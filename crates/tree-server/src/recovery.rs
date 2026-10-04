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
use sqlx::Row as _;

use crate::accounts::pow_ok;
use crate::auth::{parse_json, parse_public_key, read_body, AuthHeaders, Signed};
use crate::error::{ApiError, ApiResult};
use crate::auth::NoBody;
use crate::util::{new_id, now_secs, today, unb64};
use crate::{json_body, AppState};

pub const RECOVER_CONTEXT: &[u8] = b"tree-recover-v1";
/// Proof that the device holds the new key.
pub const SET_CONTEXT: &[u8] = b"tree-recovery-set-v1";
/// The current key agrees to a replacement or release.
pub const CHANGE_CONTEXT: &[u8] = b"tree-recovery-change-v1";
/// A change not signed by the current key takes effect after this long;
/// until then the current phrase still recovers (and cancels the change).
pub const CHANGE_DELAY: i64 = 7 * 86400;

/// `"tree-recover-v1" || auth_pub || revoke_others (1 byte) || ts (8 bytes BE)`.
pub fn recovery_message(auth_pub: &[u8; 32], revoke_others: bool, ts: i64) -> Vec<u8> {
    let mut m = RECOVER_CONTEXT.to_vec();
    m.extend_from_slice(auth_pub);
    m.push(u8::from(revoke_others));
    m.extend_from_slice(&ts.to_be_bytes());
    m
}

/// `context || u32(len(account)) || account || key` (`key` all zero for a release).
pub fn change_message(context: &[u8], account: &str, key: &[u8; 32]) -> Vec<u8> {
    let mut m = context.to_vec();
    m.extend_from_slice(&(account.len() as u32).to_be_bytes());
    m.extend_from_slice(account.as_bytes());
    m.extend_from_slice(key);
    m
}

fn recovery_pub(b64: &str) -> ApiResult<[u8; 32]> {
    let (_, raw) = parse_public_key(b64).map_err(|_| ApiError::bad_request("recovery_pub must be an Ed25519 public key"))?;
    Ok(raw)
}

fn sig(b64: &str, what: &'static str) -> ApiResult<Signature> {
    let b: [u8; 64] = unb64(b64, what)?.try_into().map_err(|_| ApiError::bad_request(format!("{what} must be 64 bytes")))?;
    Ok(Signature::from_bytes(&b))
}

fn verify(key: &[u8; 32], msg: &[u8], s: &Signature) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|k| k.verify_strict(msg, s).is_ok())
}

/// The account's recovery row, with a due pending change applied first.
async fn current(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, account: &str) -> ApiResult<Option<Recovery>> {
    let r = sqlx::query("SELECT recovery_pub, pending_action, pending_pub, pending_since FROM account_recovery WHERE account_id = ?")
        .bind(account)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(r) = r else { return Ok(None) };
    let mut row = Recovery {
        key: r.try_get::<Option<Vec<u8>>, _>("recovery_pub")?.and_then(|v| v.try_into().ok()),
        pending: r.try_get("pending_action")?,
        pending_pub: r.try_get::<Option<Vec<u8>>, _>("pending_pub")?.and_then(|v| v.try_into().ok()),
        since: r.try_get::<Option<i64>, _>("pending_since")?.unwrap_or(0),
    };
    if row.pending.is_some() && now_secs() >= row.since + CHANGE_DELAY {
        let key = if row.pending.as_deref() == Some("replace") { row.pending_pub } else { None };
        set(tx, account, key).await?;
        row = Recovery { key, pending: None, pending_pub: None, since: 0 };
    }
    Ok(Some(row))
}

struct Recovery {
    key: Option<[u8; 32]>,
    pending: Option<String>,
    pending_pub: Option<[u8; 32]>,
    since: i64,
}

/// Sets the active key (or none), clearing any pending change.
async fn set(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, account: &str, key: Option<[u8; 32]>) -> ApiResult<()> {
    let r = sqlx::query(
        "INSERT INTO account_recovery (account_id, recovery_pub, set_day) VALUES (?1, ?2, ?3) \
         ON CONFLICT (account_id) DO UPDATE SET recovery_pub = ?2, set_day = ?3, \
         pending_action = NULL, pending_pub = NULL, pending_since = NULL",
    )
    .bind(account)
    .bind(key.as_ref().map(|k| k.to_vec()))
    .bind(today())
    .execute(&mut **tx)
    .await;
    match r {
        Err(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()) => {
            Err(ApiError::new(StatusCode::CONFLICT, "ALREADY_EXISTS", "this recovery key is registered elsewhere"))
        }
        r => {
            r?;
            Ok(())
        }
    }
}

fn status(row: &Option<Recovery>) -> Value {
    match row {
        None => json!({ "state": "released", "pending": null }),
        Some(r) => json!({
            "state": if r.key.is_some() { "applied" } else { "released" },
            "pending": r.pending.as_ref().map(|a| json!({ "action": a, "effective_at": r.since + CHANGE_DELAY })),
        }),
    }
}

#[derive(Deserialize)]
pub struct ApplyReq {
    pub recovery_pub: String,
    /// New key over `change_message(SET_CONTEXT, account, new key)`.
    pub proof: String,
    /// Current key over `change_message(CHANGE_CONTEXT, account, new key)`.
    pub current_signature: Option<String>,
}
json_body!(ApplyReq, |_cfg| 512);

/// `POST /v1/recovery/apply` — set my account's recovery key. A replacement
/// signed by the current key (or the first key) is immediate; otherwise it
/// is pending for [`CHANGE_DELAY`].
pub async fn apply(State(state): State<AppState>, req: Signed<ApplyReq>) -> ApiResult<Json<Value>> {
    let account = &req.device.account_id;
    let new = recovery_pub(&req.body.recovery_pub)?;
    if !verify(&new, &change_message(SET_CONTEXT, account, &new), &sig(&req.body.proof, "proof")?) {
        return Err(ApiError::bad_request("proof does not verify with recovery_pub"));
    }
    let current_sig = req.body.current_signature.as_deref().map(|s| sig(s, "current_signature")).transpose()?;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let row = current(&mut tx, account).await?;
    // Active or pending elsewhere: refused for an immediate change too, or the
    // other account's pending change could never take effect.
    let taken = sqlx::query("SELECT 1 FROM account_recovery WHERE (recovery_pub = ?1 OR pending_pub = ?1) AND account_id != ?2")
        .bind(&new[..])
        .bind(account)
        .fetch_optional(&mut *tx)
        .await?;
    if taken.is_some() {
        return Err(ApiError::new(StatusCode::CONFLICT, "ALREADY_EXISTS", "this recovery key is registered elsewhere"));
    }
    match row.as_ref().and_then(|r| r.key) {
        None => set(&mut tx, account, Some(new)).await?,
        Some(old) => match current_sig {
            Some(s) if verify(&old, &change_message(CHANGE_CONTEXT, account, &new), &s) => set(&mut tx, account, Some(new)).await?,
            Some(_) => return Err(ApiError::forbidden("RECOVERY_REFUSED", "current_signature does not verify")),
            None => pend(&mut tx, account, "replace", Some(new)).await?,
        },
    }
    let row = current(&mut tx, account).await?;
    tx.commit().await?;
    Ok(Json(status(&row)))
}

async fn pend(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, account: &str, action: &str, key: Option<[u8; 32]>) -> ApiResult<()> {
    sqlx::query("UPDATE account_recovery SET pending_action = ?, pending_pub = ?, pending_since = ? WHERE account_id = ?")
        .bind(action)
        .bind(key.as_ref().map(|k| k.to_vec()))
        .bind(now_secs())
        .bind(account)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[derive(Deserialize, Default)]
pub struct ReleaseReq {
    /// Current key over `change_message(CHANGE_CONTEXT, account, [0; 32])`.
    pub current_signature: Option<String>,
}
json_body!(ReleaseReq, |_cfg| 256);

/// `POST /v1/recovery/release` — no recovery for my account: immediate with
/// the current key's signature, otherwise after [`CHANGE_DELAY`].
pub async fn release(State(state): State<AppState>, req: Signed<ReleaseReq>) -> ApiResult<Json<Value>> {
    let account = &req.device.account_id;
    let current_sig = req.body.current_signature.as_deref().map(|s| sig(s, "current_signature")).transpose()?;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let row = current(&mut tx, account).await?;
    if let Some(old) = row.as_ref().and_then(|r| r.key) {
        match current_sig {
            Some(s) if verify(&old, &change_message(CHANGE_CONTEXT, account, &[0; 32]), &s) => set(&mut tx, account, None).await?,
            Some(_) => return Err(ApiError::forbidden("RECOVERY_REFUSED", "current_signature does not verify")),
            None => pend(&mut tx, account, "release", None).await?,
        }
    }
    let row = current(&mut tx, account).await?;
    tx.commit().await?;
    Ok(Json(status(&row)))
}

/// `GET /v1/recovery` — my account's recovery state and any pending change
/// (apps warn: "if this was not you, recover now").
pub async fn get(State(state): State<AppState>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let row = current(&mut tx, &req.device.account_id).await?;
    tx.commit().await?;
    Ok(Json(status(&row)))
}

#[derive(Deserialize)]
pub struct RecoverReq {
    pub recovery_pub: String,
    /// The new device's request key; the request itself is signed with it.
    pub auth_pub: String,
    pub pow_nonce: u64,
    /// Recovery key signature over [`recovery_message`] with `ts`.
    pub signature: String,
    /// Unix seconds; must be within the clock-skew window.
    pub ts: i64,
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
    let s = sig(&body.signature, "signature")?;
    if (now_secs() - body.ts).unsigned_abs() > state.cfg.clock_skew_secs {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "TIMESTAMP_SKEW", "ts is too far from server time"));
    }
    let refused = || ApiError::forbidden("RECOVERY_REFUSED", "no account with this recovery key, or a wrong signature");
    if !verify(&rpub, &recovery_message(&raw, body.revoke_others, body.ts), &s) {
        return Err(refused());
    }

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    // A due pending change of that account may retire this key first.
    let account_id: String = sqlx::query("SELECT account_id FROM account_recovery WHERE recovery_pub = ? OR pending_pub = ?")
        .bind(&rpub[..])
        .bind(&rpub[..])
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(refused)?
        .try_get("account_id")?;
    if current(&mut tx, &account_id).await?.and_then(|r| r.key) != Some(rpub) {
        return Err(refused());
    }
    // The phrase was proven: any pending change (by a possibly stolen
    // device) is cancelled.
    set(&mut tx, &account_id, Some(rpub)).await?;
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
    fn message_layouts() {
        let m = recovery_message(&[7; 32], true, 0x0102030405060708);
        assert_eq!(&m[..15], b"tree-recover-v1");
        assert_eq!(&m[15..47], &[7; 32]);
        assert_eq!(m[47], 1);
        assert_eq!(&m[48..], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(recovery_message(&[7; 32], false, 0)[47], 0);
        let c = change_message(CHANGE_CONTEXT, "acc", &[9; 32]);
        assert_eq!(&c[..23], b"tree-recovery-change-v1");
        assert_eq!(&c[23..27], &[0, 0, 0, 3]);
        assert_eq!(&c[27..30], b"acc");
        assert_eq!(&c[30..], &[9; 32]);
    }
}
