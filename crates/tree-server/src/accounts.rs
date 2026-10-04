//! Accounts and devices. No phone number or email: an account is a random id
//! with one or more device authentication keys. Further devices join
//! through a confirmed device link ([`crate::links`]) or the recovery phrase.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::auth::{parse_json, parse_public_key, read_body, AuthHeaders, NoBody, Signed};
use crate::error::{ApiError, ApiResult};
use crate::features::{is_applied, SIGNUPS};
use crate::util::{check_id, new_id, today};
use crate::AppState;

/// Domain separation tag for the signup proof-of-work.
pub const POW_CONTEXT: &[u8] = b"tree-signup-v1";

/// SHA-256("tree-signup-v1" || auth_pub || nonce as 8 bytes big-endian).
pub fn pow_hash(auth_pub: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(POW_CONTEXT);
    h.update(auth_pub);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

pub fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut n = 0;
    for &b in hash {
        if b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

pub fn pow_ok(auth_pub: &[u8; 32], nonce: u64, bits: u32) -> bool {
    leading_zero_bits(&pow_hash(auth_pub, nonce)) >= bits
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(|d| d.is_unique_violation())
}

fn already_registered() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "ALREADY_EXISTS",
        "this key is already registered",
    )
}

#[derive(Deserialize)]
pub struct SignupReq {
    pub auth_pub: String,
    pub pow_nonce: u64,
}

#[derive(Serialize)]
pub struct SignupResp {
    pub account_id: String,
    pub device_id: String,
}

/// `POST /v1/accounts`
pub async fn signup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> ApiResult<(StatusCode, Json<SignupResp>)> {
    if !is_applied(&state.db, SIGNUPS).await? {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "LOCKED_BY_SERVER",
            "new signups are released by the operator",
        ));
    }
    let ip = state.client_ip(req.headers(), peer);
    state.rate_signup(ip)?;

    let auth = AuthHeaders::parse(req.headers(), false)?;
    if auth.device.is_some() {
        return Err(ApiError::bad_request("signup must not carry a device id"));
    }
    let (parts, bytes) = read_body(req, 1024).await?;
    let body: SignupReq = parse_json(&bytes)?;
    let (key, raw) = parse_public_key(&body.auth_pub)?;

    if !pow_ok(&raw, body.pow_nonce, state.cfg.pow_bits) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "POW_INVALID",
            format!(
                "proof-of-work needs {} leading zero bits",
                state.cfg.pow_bits
            ),
        ));
    }
    auth.verify(&state, &key, &parts.method, &parts.uri, &bytes)?;

    let account_id = new_id();
    let device_id = new_id();
    let day = today();
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("INSERT INTO accounts (id, created_day) VALUES (?, ?)")
        .bind(&account_id)
        .bind(day)
        .execute(&mut *tx)
        .await?;
    let inserted = sqlx::query(
        "INSERT INTO devices (id, account_id, auth_pub, created_day) VALUES (?, ?, ?, ?)",
    )
    .bind(&device_id)
    .bind(&account_id)
    .bind(&raw[..])
    .bind(day)
    .execute(&mut *tx)
    .await;
    match inserted {
        Err(e) if is_unique_violation(&e) => return Err(already_registered()),
        r => {
            r?;
        }
    }
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(SignupResp {
            account_id,
            device_id,
        }),
    ))
}

#[derive(Serialize)]
pub struct DevicesResp {
    pub account_id: String,
    pub devices: Vec<String>,
}

/// `GET /v1/devices` — the caller's own devices.
pub async fn list_devices(
    State(state): State<AppState>,
    req: Signed<NoBody>,
) -> ApiResult<Json<DevicesResp>> {
    let devices = sqlx::query("SELECT id FROM devices WHERE account_id = ? ORDER BY id")
        .bind(&req.device.account_id)
        .fetch_all(&state.db)
        .await?
        .iter()
        .map(|r| r.try_get("id"))
        .collect::<Result<Vec<String>, _>>()?;
    Ok(Json(DevicesResp {
        account_id: req.device.account_id,
        devices,
    }))
}

/// `DELETE /v1/devices/{device_id}` — removes one of the caller's devices with
/// its key packages and mailbox. Removing the last device removes the account.
pub async fn remove_device(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    req: Signed<NoBody>,
) -> ApiResult<Json<serde_json::Value>> {
    check_id(&device_id, "device_id")?;
    let account_id = &req.device.account_id;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let removed = sqlx::query("DELETE FROM devices WHERE id = ? AND account_id = ?")
        .bind(&device_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(ApiError::not_found("no such device on this account"));
    }
    sqlx::query(
        "DELETE FROM accounts WHERE id = ? AND NOT EXISTS (SELECT 1 FROM devices WHERE account_id = accounts.id)",
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM blobs WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.blob_id = blobs.id)")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.wake(&device_id);
    Ok(Json(serde_json::json!({ "removed": device_id })))
}

/// `DELETE /v1/accounts` — deletes the caller's account: every device with
/// its mailbox and key packages, the username, the recovery key, push
/// endpoints and invite links (all by cascade). Required by the app stores.
pub async fn delete_account(State(state): State<AppState>, req: Signed<NoBody>) -> ApiResult<Json<serde_json::Value>> {
    let account_id = &req.device.account_id;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let devices: Vec<String> = sqlx::query("DELETE FROM devices WHERE account_id = ? RETURNING id")
        .bind(account_id)
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(|r| r.try_get("id"))
        .collect::<Result<_, _>>()?;
    sqlx::query("DELETE FROM accounts WHERE id = ?").bind(account_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM blobs WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.blob_id = blobs.id)")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    for d in &devices {
        state.wake(d);
    }
    Ok(Json(serde_json::json!({ "deleted": true, "devices": devices.len() })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_bits_counted() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x0f, 0xff]), 20);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
    }

    #[test]
    fn pow_found_and_checked() {
        let key = [3u8; 32];
        let nonce = (0u64..).find(|&n| pow_ok(&key, n, 8)).unwrap();
        assert!(pow_ok(&key, nonce, 8));
        assert!(leading_zero_bits(&pow_hash(&key, nonce)) >= 8);
    }
}
