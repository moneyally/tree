//! Account recovery with the recovery phrase (docs/PROTOCOL.md 8.6).
//!
//! The device derives an Ed25519 recovery key from the phrase and registers
//! only its public key. A new device that knows the phrase signs
//! `"tree-recover-v1" || its request key || revoke_others` and is added to
//! the account; with `revoke_others` every other device of the account is
//! removed (a lost or stolen phone). Nothing of MLS is restored: contacts
//! see the new device as a key change.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::Json;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::accounts::pow_ok;
use crate::auth::{parse_json, parse_public_key, read_body, AuthHeaders, Signed};
use crate::error::{ApiError, ApiResult};
use crate::util::{new_id, today, unb64};
use crate::{json_body, AppState};

pub const RECOVER_CONTEXT: &[u8] = b"tree-recover-v1";

/// `"tree-recover-v1" || auth_pub || revoke_others (1 byte)`.
pub fn recovery_message(auth_pub: &[u8; 32], revoke_others: bool) -> Vec<u8> {
    let mut m = RECOVER_CONTEXT.to_vec();
    m.extend_from_slice(auth_pub);
    m.push(u8::from(revoke_others));
    m
}

fn recovery_pub(b64: &str) -> ApiResult<[u8; 32]> {
    let (_, raw) = parse_public_key(b64).map_err(|_| ApiError::bad_request("recovery_pub must be an Ed25519 public key"))?;
    Ok(raw)
}

#[derive(Deserialize)]
pub struct ApplyReq {
    pub recovery_pub: String,
}
json_body!(ApplyReq, |_cfg| 256);

/// `POST /v1/recovery/apply` — set or replace my account's recovery key.
pub async fn apply(State(state): State<AppState>, req: Signed<ApplyReq>) -> ApiResult<Json<Value>> {
    let raw = recovery_pub(&req.body.recovery_pub)?;
    let r = sqlx::query(
        "INSERT INTO account_recovery (account_id, recovery_pub, set_day) VALUES (?1, ?2, ?3) \
         ON CONFLICT (account_id) DO UPDATE SET recovery_pub = ?2, set_day = ?3",
    )
    .bind(&req.device.account_id)
    .bind(&raw[..])
    .bind(today())
    .execute(&state.db)
    .await;
    match r {
        Err(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()) => {
            Err(ApiError::new(StatusCode::CONFLICT, "ALREADY_EXISTS", "this recovery key is registered elsewhere"))
        }
        r => {
            r?;
            Ok(Json(json!({ "state": "applied" })))
        }
    }
}

/// `POST /v1/recovery/release` — my account can no longer be recovered.
pub async fn release(State(state): State<AppState>, req: Signed<crate::auth::NoBody>) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM account_recovery WHERE account_id = ?")
        .bind(&req.device.account_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "state": "released" })))
}

#[derive(Deserialize)]
pub struct RecoverReq {
    pub recovery_pub: String,
    /// The new device's request key; the request itself is signed with it.
    pub auth_pub: String,
    pub pow_nonce: u64,
    /// Recovery key signature over [`recovery_message`].
    pub signature: String,
    #[serde(default)]
    pub revoke_others: bool,
}

/// `POST /v1/recovery/recover` — a new device joins the account that holds
/// this recovery key. Unauthenticated like signup (proof of work, per-IP
/// limit), signed by the new key, authorised by the recovery signature.
pub async fn recover(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let ip = state.client_ip(req.headers(), peer);
    state.rate_signup(ip)?;
    let auth = AuthHeaders::parse(req.headers(), false)?;
    if auth.device.is_some() {
        return Err(ApiError::bad_request("recovery must not carry a device id"));
    }
    let (parts, bytes) = read_body(req, 1024).await?;
    let body: RecoverReq = parse_json(&bytes)?;
    let (key, raw) = parse_public_key(&body.auth_pub)?;
    if !pow_ok(&raw, body.pow_nonce, state.cfg.pow_bits) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "POW_INVALID", "proof-of-work too weak"));
    }
    auth.verify(&state, &key, &parts.method, &parts.uri, &bytes)?;
    let rpub = recovery_pub(&body.recovery_pub)?;
    let sig: [u8; 64] = unb64(&body.signature, "signature")?
        .try_into()
        .map_err(|_| ApiError::bad_request("signature must be 64 bytes"))?;
    let rkey = VerifyingKey::from_bytes(&rpub).map_err(|_| ApiError::bad_request("recovery_pub is not a valid key"))?;
    let refused = || ApiError::forbidden("RECOVERY_REFUSED", "no account with this recovery key, or a wrong signature");
    rkey.verify_strict(&recovery_message(&raw, body.revoke_others), &Signature::from_bytes(&sig))
        .map_err(|_| refused())?;

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let account_id: String = sqlx::query("SELECT account_id FROM account_recovery WHERE recovery_pub = ?")
        .bind(&rpub[..])
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(refused)?
        .try_get("account_id")?;
    // Checked before any device is revoked, so a refused request changes nothing.
    let known = sqlx::query("SELECT 1 FROM devices WHERE auth_pub = ?").bind(&raw[..]).fetch_optional(&mut *tx).await?;
    if known.is_some() {
        return Err(ApiError::new(StatusCode::CONFLICT, "ALREADY_EXISTS", "this key is already registered"));
    }
    let mut revoked = Vec::new();
    if body.revoke_others {
        revoked = sqlx::query("DELETE FROM devices WHERE account_id = ? RETURNING id")
            .bind(&account_id)
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(|r| r.try_get("id"))
            .collect::<Result<Vec<String>, _>>()?;
        sqlx::query("DELETE FROM blobs WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.blob_id = blobs.id)")
            .execute(&mut *tx)
            .await?;
    }
    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM devices WHERE account_id = ?")
        .bind(&account_id)
        .fetch_one(&mut *tx)
        .await?
        .try_get("n")?;
    if count >= state.cfg.max_devices_per_account as i64 {
        return Err(ApiError::limit_exceeded("device limit reached; recover with revoke_others"));
    }
    let device_id = new_id();
    let inserted = sqlx::query("INSERT INTO devices (id, account_id, auth_pub, created_day) VALUES (?, ?, ?, ?)")
        .bind(&device_id)
        .bind(&account_id)
        .bind(&raw[..])
        .bind(today())
        .execute(&mut *tx)
        .await;
    match inserted {
        Err(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()) => {
            return Err(ApiError::new(StatusCode::CONFLICT, "ALREADY_EXISTS", "this key is already registered"));
        }
        r => {
            r?;
        }
    }
    tx.commit().await?;
    for d in &revoked {
        state.wake(d);
    }
    Ok((StatusCode::CREATED, Json(json!({ "account_id": account_id, "device_id": device_id, "revoked": revoked.len() }))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_layout() {
        let m = recovery_message(&[7; 32], true);
        assert_eq!(&m[..15], b"tree-recover-v1");
        assert_eq!(&m[15..47], &[7; 32]);
        assert_eq!(m[47], 1);
        assert_eq!(recovery_message(&[7; 32], false)[47], 0);
        assert_eq!(m.len(), 48);
    }
}
