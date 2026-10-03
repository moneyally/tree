//! Server side account recovery.
//!
//! The server stores only the recovery public key. A recovered device proves
//! possession of the recovery phrase by deriving the same Ed25519 key locally
//! and signing a one-time, timestamped recovery request.
//!
//! Recovery creates a new device identity. It never reconstructs MLS state,
//! past group secrets, or a previous device's private keys.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::Json;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::auth::{parse_json, parse_public_key, read_body, Signed};
use crate::error::{ApiError, ApiResult};
use crate::util::{check_id, new_id, now_secs, today, unb64};
use crate::{json_body, AppState};

const RECOVERY_CONTEXT: &str = "tree-recovery-v1";

#[derive(Deserialize)]
pub struct SetupRecoveryReq {
    pub recovery_pub: String,
}
json_body!(SetupRecoveryReq, |_cfg| 512);

#[derive(Serialize)]
pub struct SetupRecoveryResp {
    pub recovery_pub: String,
}

/// POST /v1/recovery/setup
pub async fn setup(
    State(state): State<AppState>,
    req: Signed<SetupRecoveryReq>,
) -> ApiResult<Json<SetupRecoveryResp>> {
    let (key, raw) = parse_public_key(&req.body.recovery_pub)?;
    let _ = key;

    sqlx::query(
        "INSERT INTO recovery_keys(account_id, recovery_pub, created_at)
         VALUES (?, ?, ?)
         ON CONFLICT(account_id)
         DO UPDATE SET recovery_pub = excluded.recovery_pub, created_at = excluded.created_at",
    )
    .bind(&req.device.account_id)
    .bind(&raw[..])
    .bind(now_secs())
    .execute(&state.db)
    .await?;

    Ok(Json(SetupRecoveryResp {
        recovery_pub: crate::util::b64(&raw),
    }))
}

fn recovery_message(
    account_id: &str,
    timestamp: i64,
    nonce: &str,
    new_auth_pub: &[u8; 32],
) -> Vec<u8> {
    let mut msg = format!("{RECOVERY_CONTEXT}\n{account_id}\n{timestamp}\n{nonce}\n").into_bytes();
    msg.extend_from_slice(new_auth_pub);
    msg
}

#[derive(Deserialize)]
struct RecoverReq {
    account_id: String,
    recovery_pub: String,
    new_auth_pub: String,
    timestamp: i64,
    nonce: String,
    proof: String,
}

#[derive(Serialize)]
pub struct RecoverResp {
    pub account_id: String,
    pub device_id: String,
    pub warning: &'static str,
}

/// POST /v1/recovery
///
/// This is intentionally not an authenticated-device request. Authentication
/// is the signature under the public recovery key previously registered for
/// the account.
pub async fn recover(
    State(state): State<AppState>,
    req: Request,
) -> ApiResult<(StatusCode, Json<RecoverResp>)> {
    let (parts, bytes) = read_body(req, 4096).await?;
    let body: RecoverReq = parse_json(&bytes)?;

    check_id(&body.account_id, "account_id")?;
    if body.nonce.len() < 16
        || body.nonce.len() > 64
        || !body
            .nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ApiError::bad_request("invalid recovery nonce"));
    }

    let now = now_secs();
    let skew = state.cfg.clock_skew_secs as i64;
    if (body.timestamp - now).abs() > skew {
        return Err(ApiError::unauthorized(
            "recovery timestamp outside allowed skew",
        ));
    }

    let recovery_pub = unb64(&body.recovery_pub, "recovery_pub")?;
    let recovery_pub: [u8; 32] = recovery_pub
        .try_into()
        .map_err(|_| ApiError::bad_request("recovery_pub must be 32 bytes"))?;
    let new_auth_pub = unb64(&body.new_auth_pub, "new_auth_pub")?;
    let new_auth_pub: [u8; 32] = new_auth_pub
        .try_into()
        .map_err(|_| ApiError::bad_request("new_auth_pub must be 32 bytes"))?;
    let proof = unb64(&body.proof, "proof")?;
    let proof: [u8; 64] = proof
        .try_into()
        .map_err(|_| ApiError::bad_request("proof must be 64 bytes"))?;

    state
        .recovery_limiter
        .take(&body.account_id, 1.0)
        .map_err(ApiError::rate_limited)?;

    let stored = sqlx::query(
        "SELECT 1 FROM recovery_keys
         WHERE account_id = ? AND recovery_pub = ?",
    )
    .bind(&body.account_id)
    .bind(&recovery_pub[..])
    .fetch_optional(&state.db)
    .await?
    .is_some();
    if !stored {
        return Err(ApiError::unauthorized("recovery authentication failed"));
    }

    let key = VerifyingKey::from_bytes(&recovery_pub).map_err(|_| ApiError::internal())?;
    key.verify_strict(
        &recovery_message(&body.account_id, body.timestamp, &body.nonce, &new_auth_pub),
        &Signature::from_bytes(&proof),
    )
    .map_err(|_| ApiError::unauthorized("recovery authentication failed"))?;

    if !state.replay.insert(proof, body.timestamp + skew, now) {
        return Err(ApiError::unauthorized("replayed recovery request"));
    }

    let account_exists = sqlx::query("SELECT 1 FROM accounts WHERE id = ?")
        .bind(&body.account_id)
        .fetch_optional(&state.db)
        .await?
        .is_some();
    if !account_exists {
        return Err(ApiError::not_found("unknown account"));
    }

    let duplicate = sqlx::query("SELECT 1 FROM devices WHERE auth_pub = ?")
        .bind(&new_auth_pub[..])
        .fetch_optional(&state.db)
        .await?
        .is_some();
    if duplicate {
        return Err(ApiError::conflict(
            "ALREADY_EXISTS",
            "this authentication key is already registered",
        ));
    }

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM devices WHERE account_id = ?")
        .bind(&body.account_id)
        .fetch_one(&mut *tx)
        .await?
        .try_get("n")?;
    if count >= state.cfg.max_devices_per_account as i64 {
        return Err(ApiError::limit_exceeded(
            "device limit reached for this account",
        ));
    }

    let device_id = new_id();
    sqlx::query(
        "INSERT INTO devices (id, account_id, auth_pub, created_day)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&device_id)
    .bind(&body.account_id)
    .bind(&new_auth_pub[..])
    .bind(today())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(RecoverResp {
            account_id: body.account_id,
            device_id,
            warning: "recovery creates a new device; previous MLS group state is not restored",
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_message_binds_all_fields() {
        let a = recovery_message("a", 1, "nonce", &[1; 32]);
        let b = recovery_message("a", 2, "nonce", &[1; 32]);
        assert_ne!(a, b);
    }
}
