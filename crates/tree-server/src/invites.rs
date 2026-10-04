//! Group invite links (docs/PROTOCOL.md 8.7).
//!
//! A link carries a random secret. The admin device that made it registers
//! only `SHA-256("tree/invite/v1" || secret)` with an expiry and a use
//! limit. Whoever opens the link sends the secret; the server checks the
//! limits and queues a join request for the owner's device, which adds the
//! requester to the group through the normal MLS path (it alone knows which
//! group the link is for). The server learns that this account asked to
//! join something of the owner's, which it would learn anyway from the key
//! package claim and the welcome that follow.
//!
//! Version 2 links (F-025): the joiner sends `proof = HKDF(secret, ...)`
//! (32 bytes) instead of the secret, so the server never holds the secret,
//! and its nonce sealed to the link's owner (44 bytes), which the server
//! relays without being able to read it. Version 1 links (a 16-byte secret,
//! a 16-byte nonce in the clear from older clients) still work.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::auth::{NoBody, Signed};
use crate::error::{ApiError, ApiResult};
use crate::util::{b64, check_id, new_id, now_secs, unb64};
use crate::{json_body, AppState};

pub const LABEL: &[u8] = b"tree/invite/v1";
/// Longest allowed link lifetime (30 days) and use limit.
pub const MAX_LIFETIME: i64 = 30 * 86400;
pub const MAX_USES: i64 = 10_000;
/// Open links per device.
pub const MAX_PER_DEVICE: i64 = 100;
/// An expired link is kept this long so requests made before it expired are
/// still handled.
pub const KEEP_EXPIRED: i64 = 7 * 86400;
/// A version 1 secret, or a version 2 proof.
const TOKEN_LENS: [usize; 2] = [16, 32];
/// A version 1 nonce (older clients, in the clear), or a version 2 sealed
/// nonce (AES-256-GCM: 12-byte nonce, 16 bytes, 16-byte tag).
const NONCE_LENS: [usize; 2] = [16, 12 + 16 + 16];

/// Deletes links that expired more than [`KEEP_EXPIRED`] ago.
pub async fn purge(db: &sqlx::SqlitePool, now: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM invites WHERE expires_at < ?").bind(now - KEEP_EXPIRED).execute(db).await?.rows_affected())
}

pub fn token_hash(token: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update(token);
    h.finalize().into()
}

fn hash_arg(s: &str) -> ApiResult<[u8; 32]> {
    unb64(s, "token_hash")?.try_into().map_err(|_| ApiError::bad_request("token_hash must be 32 bytes"))
}

#[derive(Deserialize)]
pub struct CreateReq {
    pub token_hash: String,
    /// Seconds from now.
    pub lifetime: i64,
    pub max_uses: i64,
}
json_body!(CreateReq, |_cfg| 512);

/// `POST /v1/invites` — register a link this device made.
pub async fn create(State(state): State<AppState>, req: Signed<CreateReq>) -> ApiResult<(StatusCode, Json<Value>)> {
    let h = hash_arg(&req.body.token_hash)?;
    if !(60..=MAX_LIFETIME).contains(&req.body.lifetime) || !(1..=MAX_USES).contains(&req.body.max_uses) {
        return Err(ApiError::bad_request(format!("lifetime 60..{MAX_LIFETIME} s, max_uses 1..{MAX_USES}")));
    }
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let n: i64 = sqlx::query("SELECT COUNT(*) AS n FROM invites WHERE owner_device = ? AND expires_at > ?")
        .bind(&req.device.device_id)
        .bind(now_secs())
        .fetch_one(&mut *tx)
        .await?
        .try_get("n")?;
    if n >= MAX_PER_DEVICE {
        return Err(ApiError::limit_exceeded("too many open invite links on this device"));
    }
    let expires_at = now_secs() + req.body.lifetime;
    let r = sqlx::query("INSERT INTO invites (token_hash, owner_account, owner_device, expires_at, max_uses) VALUES (?, ?, ?, ?, ?)")
        .bind(&h[..])
        .bind(&req.device.account_id)
        .bind(&req.device.device_id)
        .bind(expires_at)
        .bind(req.body.max_uses)
        .execute(&mut *tx)
        .await;
    match r {
        Err(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()) => {
            return Err(ApiError::new(StatusCode::CONFLICT, "ALREADY_EXISTS", "this link is already registered"));
        }
        r => {
            r?;
        }
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "expires_at": expires_at }))))
}

/// `DELETE /v1/invites/{token_hash}` — revoke (base64url hash). Idempotent.
pub async fn revoke(State(state): State<AppState>, Path(hash): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    let h: [u8; 32] = crate::util::unb64_url(&hash, "token_hash")?
        .try_into()
        .map_err(|_| ApiError::bad_request("token_hash must be 32 bytes"))?;
    sqlx::query("DELETE FROM invites WHERE token_hash = ? AND owner_device = ?")
        .bind(&h[..])
        .bind(&req.device.device_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "state": "released" })))
}

#[derive(Deserialize)]
pub struct JoinReq {
    /// The link secret (version 1) or the proof derived from it (version 2).
    pub token: String,
    /// From the joining device, handed only to the link owner's device with
    /// the request (it names the nonce in its roster). Version 2: sealed to
    /// the link's owner, opaque here.
    #[serde(default)]
    pub nonce: Option<String>,
}
json_body!(JoinReq, |_cfg| 512);

/// `POST /v1/invites/join` — use a link. `202 {"owner_account"}`.
pub async fn join(State(state): State<AppState>, req: Signed<JoinReq>) -> ApiResult<(StatusCode, Json<Value>)> {
    let token = unb64(&req.body.token, "token")?;
    if !TOKEN_LENS.contains(&token.len()) {
        return Err(ApiError::bad_request("token must be 16 or 32 bytes"));
    }
    let nonce = req.body.nonce.as_deref().map(|n| unb64(n, "nonce")).transpose()?;
    if nonce.as_ref().is_some_and(|n| !NONCE_LENS.contains(&n.len())) {
        return Err(ApiError::bad_request("nonce must be 16 or 44 bytes"));
    }
    // Guessing links is pointless at 128 bits, but each try still costs.
    req.device.charge_outreach(&state, 5.0)?;
    let h = token_hash(&token);
    let gone = || ApiError::not_found("this invite link is invalid, expired or used up");
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let row = sqlx::query("SELECT owner_account, owner_device, expires_at, max_uses, uses FROM invites WHERE token_hash = ?")
        .bind(&h[..])
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(gone)?;
    let owner_account: String = row.try_get("owner_account")?;
    let owner_device: String = row.try_get("owner_device")?;
    if row.try_get::<i64, _>("expires_at")? <= now_secs() || row.try_get::<i64, _>("uses")? >= row.try_get::<i64, _>("max_uses")? {
        return Err(gone());
    }
    if owner_account == req.device.account_id {
        return Err(ApiError::bad_request("this is your own link"));
    }
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO invite_requests (id, token_hash, account_id, created_at, nonce) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(new_id())
    .bind(&h[..])
    .bind(&req.device.account_id)
    .bind(crate::util::round_to_minute(now_secs()))
    .bind(nonce.as_deref())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    // A repeated request by the same account uses the link once; the
    // newest nonce is the one the joining device now waits for.
    if inserted == 1 {
        sqlx::query("UPDATE invites SET uses = uses + 1 WHERE token_hash = ?").bind(&h[..]).execute(&mut *tx).await?;
    } else {
        sqlx::query("UPDATE invite_requests SET nonce = ? WHERE token_hash = ? AND account_id = ?")
            .bind(nonce.as_deref())
            .bind(&h[..])
            .bind(&req.device.account_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    state.wake(&owner_device);
    Ok((StatusCode::ACCEPTED, Json(json!({ "owner_account": owner_account }))))
}

/// `GET /v1/invites/requests` — join requests for this device's links.
pub async fn requests(State(state): State<AppState>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    let rows = sqlx::query(
        "SELECT r.id, r.token_hash, r.account_id, r.nonce FROM invite_requests r JOIN invites i ON i.token_hash = r.token_hash \
         WHERE i.owner_device = ? ORDER BY r.created_at, r.rowid LIMIT 100",
    )
    .bind(&req.device.device_id)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::new();
    for r in rows {
        out.push(json!({
            "id": r.try_get::<String, _>("id")?,
            "token_hash": b64(&r.try_get::<Vec<u8>, _>("token_hash")?),
            "account_id": r.try_get::<String, _>("account_id")?,
            "nonce": r.try_get::<Option<Vec<u8>>, _>("nonce")?.map(|n| b64(&n)),
        }));
    }
    Ok(Json(json!({ "requests": out })))
}

#[derive(Deserialize)]
pub struct AckReq {
    pub ids: Vec<String>,
}
json_body!(AckReq, |_cfg| 100 * 32 + 64);

/// `POST /v1/invites/requests/ack` — handled; deleted.
pub async fn ack(State(state): State<AppState>, req: Signed<AckReq>) -> ApiResult<Json<Value>> {
    if req.body.ids.len() > 100 {
        return Err(ApiError::too_large("at most 100 ids"));
    }
    let mut n = 0;
    for id in &req.body.ids {
        check_id(id, "request id")?;
        n += sqlx::query(
            "DELETE FROM invite_requests WHERE id = ? AND token_hash IN (SELECT token_hash FROM invites WHERE owner_device = ?)",
        )
        .bind(id)
        .bind(&req.device.device_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    }
    Ok(Json(json!({ "deleted": n })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_labelled() {
        let t = [1u8; 16];
        let mut h = Sha256::new();
        h.update(b"tree/invite/v1");
        h.update(t);
        assert_eq!(token_hash(&t), <[u8; 32]>::from(h.finalize()));
        assert_ne!(token_hash(&t), token_hash(&[2u8; 16]));
    }
}
