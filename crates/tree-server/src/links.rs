//! Device linking with a two-sided confirmation code (docs/PROTOCOL.md 8.11).
//!
//! The server keeps a short-lived link session and relays three opaque
//! messages: the existing device's offer, the new device's reveal and the
//! sealed account data. It adds the new device only when the new device
//! signed a transcript hash ([`confirm_message`]) and the existing device
//! signed its authorisation over the same hash ([`authorise_message`]).
//! It never sees the transcript itself in a form it could check, and it
//! never computes or chooses the code: both devices do that themselves.
//!
//! A session lives 10 minutes, is used once (linked or cancelled, never
//! again), and an account may have only a few of them.

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::Json;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use subtle::ConstantTimeEq;

use crate::auth::{parse_json, parse_public_key, read_body, AuthHeaders, NoBody, Signed};
use crate::error::{ApiError, ApiResult};
use crate::util::{b64, check_id, new_id, now_secs, today, unb64};
use crate::{json_body, AppState};

/// A session expires this long after the existing device opened it.
pub const LIFETIME: i64 = 600;
/// Expired sessions are kept this long (they count against the hourly limit).
pub const KEEP_EXPIRED: i64 = 3600;
/// Open sessions per account, and sessions an account may open per hour.
pub const MAX_OPEN: i64 = 2;
pub const MAX_PER_HOUR: i64 = 10;
/// Size limits of the relayed messages (bytes, decoded).
pub const MAX_OFFER: usize = 1024;
pub const MAX_REVEAL: usize = 64 * 1024;
pub const MAX_SEALED: usize = 256 * 1024;

pub const CONFIRM_CONTEXT: &[u8] = b"tree/link/confirm/v1";
pub const AUTHORISE_CONTEXT: &[u8] = b"tree/link/authorise/v1";

/// Each part preceded by its length as 4 bytes big-endian.
pub fn lp(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// What the new device signs: `lp("tree/link/confirm/v1", link_id, hash)`.
pub fn confirm_message(link_id: &[u8], hash: &[u8]) -> Vec<u8> {
    lp(&[CONFIRM_CONTEXT, link_id, hash])
}

/// What the existing device signs:
/// `lp("tree/link/authorise/v1", link_id, account_id, new_auth_pub, hash)`.
pub fn authorise_message(link_id: &[u8], account_id: &str, new_auth_pub: &[u8], hash: &[u8]) -> Vec<u8> {
    lp(&[AUTHORISE_CONTEXT, link_id, account_id.as_bytes(), new_auth_pub, hash])
}

/// Deletes sessions that expired more than [`KEEP_EXPIRED`] ago, and the
/// relayed data of every session that has expired.
pub async fn purge(db: &sqlx::SqlitePool, now: i64) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE link_sessions SET offer = x'', reveal = NULL, sealed = NULL WHERE expires_at <= ? AND (length(offer) > 0 OR reveal IS NOT NULL OR sealed IS NOT NULL)")
        .bind(now)
        .execute(db)
        .await?;
    Ok(sqlx::query("DELETE FROM link_sessions WHERE expires_at < ?").bind(now - KEEP_EXPIRED).execute(db).await?.rows_affected())
}

fn raw_link_id(id: &str) -> ApiResult<Vec<u8>> {
    check_id(id, "link_id")?;
    crate::util::unb64_url(id, "link_id")
}

fn decode_limited(s: &str, max: usize, what: &'static str) -> ApiResult<Vec<u8>> {
    if crate::util::b64_exceeds(s, max) {
        return Err(ApiError::too_large(format!("{what} too large")));
    }
    let v = unb64(s, what)?;
    if v.is_empty() {
        return Err(ApiError::bad_request(format!("{what} is empty")));
    }
    if v.len() > max {
        return Err(ApiError::too_large(format!("{what} too large")));
    }
    Ok(v)
}

fn signature(s: &str) -> ApiResult<Signature> {
    let b: [u8; 64] = unb64(s, "signature")?.try_into().map_err(|_| ApiError::bad_request("signature must be 64 bytes"))?;
    Ok(Signature::from_bytes(&b))
}

fn hash32(s: &str) -> ApiResult<[u8; 32]> {
    unb64(s, "transcript_hash")?.try_into().map_err(|_| ApiError::bad_request("transcript_hash must be 32 bytes"))
}

fn gone() -> ApiError {
    ApiError::new(StatusCode::GONE, "LINK_GONE", "this device link expired, was cancelled or was already used")
}

fn wrong_state(state: &str) -> ApiError {
    ApiError::conflict("LINK_STATE", format!("the link is {state}"))
}

/// One session row.
struct Session {
    account_id: String,
    owner_device: String,
    new_auth_pub: Vec<u8>,
    expires_at: i64,
    state: String,
    offer: Vec<u8>,
    reveal: Option<Vec<u8>>,
    transcript_hash: Option<Vec<u8>>,
    new_signature: Option<Vec<u8>>,
    sealed: Option<Vec<u8>>,
    new_device_id: Option<String>,
}

impl Session {
    fn open(&self) -> bool {
        !matches!(self.state.as_str(), "linked" | "cancelled")
    }
}

async fn load(db: impl sqlx::SqliteExecutor<'_>, link_id: &str) -> ApiResult<Option<Session>> {
    let Some(r) = sqlx::query("SELECT * FROM link_sessions WHERE link_id = ?").bind(link_id).fetch_optional(db).await? else {
        return Ok(None);
    };
    Ok(Some(Session {
        account_id: r.try_get("account_id")?,
        owner_device: r.try_get("owner_device")?,
        new_auth_pub: r.try_get("new_auth_pub")?,
        expires_at: r.try_get("expires_at")?,
        state: r.try_get("state")?,
        offer: r.try_get("offer")?,
        reveal: r.try_get("reveal")?,
        transcript_hash: r.try_get("transcript_hash")?,
        new_signature: r.try_get("new_signature")?,
        sealed: r.try_get("sealed")?,
        new_device_id: r.try_get("new_device_id")?,
    }))
}

/// The caller's own session, still usable.
async fn owned(db: impl sqlx::SqliteExecutor<'_>, link_id: &str, device: &str) -> ApiResult<Session> {
    let s = load(db, link_id).await?.filter(|s| s.owner_device == device).ok_or_else(|| ApiError::not_found("no such device link"))?;
    Ok(s)
}

#[derive(Deserialize)]
pub struct CreateReq {
    pub link_id: String,
    /// The new device's request key, from its invitation.
    pub new_auth_pub: String,
    /// The offer for the new device (opaque to the server).
    pub offer: String,
}
json_body!(CreateReq, |_cfg| MAX_OFFER * 2 + 256);

/// `POST /v1/links` — the existing device opens a session for a scanned
/// invitation.
pub async fn create(State(state): State<AppState>, req: Signed<CreateReq>) -> ApiResult<(StatusCode, Json<Value>)> {
    raw_link_id(&req.body.link_id)?;
    let (_, raw) = parse_public_key(&req.body.new_auth_pub)?;
    let offer = decode_limited(&req.body.offer, MAX_OFFER, "offer")?;
    let now = now_secs();
    let account = &req.device.account_id;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let r = sqlx::query(
        "SELECT COUNT(*) AS recent, COALESCE(SUM(state NOT IN ('linked', 'cancelled') AND expires_at > ?2), 0) AS open \
         FROM link_sessions WHERE account_id = ?1 AND created_at > ?3",
    )
    .bind(account)
    .bind(now)
    .bind(now - 3600)
    .fetch_one(&mut *tx)
    .await?;
    if r.try_get::<i64, _>("open")? >= MAX_OPEN || r.try_get::<i64, _>("recent")? >= MAX_PER_HOUR {
        return Err(ApiError::rate_limited(60).with("reason", json!("too many device links for this account")));
    }
    let registered: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM devices WHERE auth_pub = ?").bind(&raw[..]).fetch_optional(&mut *tx).await?;
    if registered.is_some() {
        return Err(ApiError::conflict("ALREADY_EXISTS", "this key is already registered"));
    }
    let ins = sqlx::query(
        "INSERT INTO link_sessions (link_id, account_id, owner_device, new_auth_pub, created_at, expires_at, state, offer) \
         VALUES (?, ?, ?, ?, ?, ?, 'offered', ?)",
    )
    .bind(&req.body.link_id)
    .bind(account)
    .bind(&req.device.device_id)
    .bind(&raw[..])
    .bind(now)
    .bind(now + LIFETIME)
    .bind(&offer)
    .execute(&mut *tx)
    .await;
    match ins {
        Err(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()) => {
            return Err(ApiError::conflict("ALREADY_EXISTS", "this device link was already used"));
        }
        r => {
            r?;
        }
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "expires_at": now + LIFETIME }))))
}

/// `GET /v1/links/{link_id}` — the existing device polls its session.
pub async fn status(State(state): State<AppState>, Path(link_id): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    raw_link_id(&link_id)?;
    let s = owned(&state.db, &link_id, &req.device.device_id).await?;
    let expired = s.open() && s.expires_at <= now_secs();
    Ok(Json(json!({
        "state": if expired { "expired" } else { s.state.as_str() },
        "expires_at": s.expires_at,
        "reveal": s.reveal.filter(|_| !expired).map(|r| b64(&r)),
        "transcript_hash": s.transcript_hash.map(|h| b64(&h)),
        "new_signature": s.new_signature.map(|h| b64(&h)),
        "device_id": s.new_device_id,
    })))
}

#[derive(Deserialize)]
pub struct CompleteReq {
    pub transcript_hash: String,
    /// The caller's request key over [`authorise_message`].
    pub signature: String,
    /// Account data for the new device (opaque, HPKE-sealed).
    pub sealed: String,
}
json_body!(CompleteReq, |_cfg| MAX_SEALED.div_ceil(3) * 4 + 1024);

/// `POST /v1/links/{link_id}/complete` — both people confirmed: the new
/// device is added to the caller's account.
pub async fn complete(State(state): State<AppState>, Path(link_id): Path<String>, req: Signed<CompleteReq>) -> ApiResult<(StatusCode, Json<Value>)> {
    let raw_id = raw_link_id(&link_id)?;
    let hash = hash32(&req.body.transcript_hash)?;
    let sig = signature(&req.body.signature)?;
    let sealed = decode_limited(&req.body.sealed, MAX_SEALED, "sealed")?;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let s = owned(&mut *tx, &link_id, &req.device.device_id).await?;
    if !s.open() || s.expires_at <= now_secs() {
        return Err(gone());
    }
    if s.state != "confirmed" {
        return Err(wrong_state("not confirmed by the new device yet"));
    }
    // Both devices must have signed the same transcript hash.
    let confirmed = s.transcript_hash.as_deref().unwrap_or_default();
    if !bool::from(confirmed.ct_eq(&hash[..])) {
        return Err(ApiError::forbidden("TRANSCRIPT_MISMATCH", "the two devices saw different link transcripts: nothing was linked"));
    }
    let owner_pub: Vec<u8> = sqlx::query("SELECT auth_pub FROM devices WHERE id = ?")
        .bind(&req.device.device_id)
        .fetch_one(&mut *tx)
        .await?
        .try_get("auth_pub")?;
    let owner_key = <[u8; 32]>::try_from(owner_pub.as_slice()).ok().and_then(|k| VerifyingKey::from_bytes(&k).ok()).ok_or_else(ApiError::internal)?;
    owner_key
        .verify_strict(&authorise_message(&raw_id, &s.account_id, &s.new_auth_pub, &hash), &sig)
        .map_err(|_| ApiError::forbidden("LINK_SIGNATURE", "the authorisation signature does not verify"))?;

    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM devices WHERE account_id = ?")
        .bind(&s.account_id)
        .fetch_one(&mut *tx)
        .await?
        .try_get("n")?;
    if count >= state.cfg.max_devices_per_account as i64 {
        return Err(ApiError::limit_exceeded("device limit reached for this account"));
    }
    let device_id = new_id();
    let ins = sqlx::query("INSERT INTO devices (id, account_id, auth_pub, created_day) VALUES (?, ?, ?, ?)")
        .bind(&device_id)
        .bind(&s.account_id)
        .bind(&s.new_auth_pub)
        .bind(today())
        .execute(&mut *tx)
        .await;
    match ins {
        Err(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()) => {
            return Err(ApiError::conflict("ALREADY_EXISTS", "this key is already registered"));
        }
        r => {
            r?;
        }
    }
    sqlx::query("UPDATE link_sessions SET state = 'linked', sealed = ?, new_device_id = ?, reveal = NULL WHERE link_id = ?")
        .bind(&sealed)
        .bind(&device_id)
        .bind(&link_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "device_id": device_id }))))
}

/// `POST /v1/links/{link_id}/cancel` — the existing device's person said no.
pub async fn cancel(State(state): State<AppState>, Path(link_id): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    raw_link_id(&link_id)?;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let s = owned(&mut *tx, &link_id, &req.device.device_id).await?;
    if s.state == "linked" {
        return Err(wrong_state("already linked"));
    }
    set_cancelled(&mut tx, &link_id).await?;
    tx.commit().await?;
    Ok(Json(json!({ "state": "cancelled" })))
}

async fn set_cancelled(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, link_id: &str) -> ApiResult<()> {
    sqlx::query("UPDATE link_sessions SET state = 'cancelled', offer = x'', reveal = NULL, sealed = NULL WHERE link_id = ?")
        .bind(link_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Authenticates a request of the new device: no device id yet, signed by
/// the key named in the session. Returns the session and the body.
async fn new_device(state: &AppState, link_id: &str, req: Request, limit: usize) -> ApiResult<(Session, Vec<u8>)> {
    raw_link_id(link_id)?;
    let auth = AuthHeaders::parse(req.headers(), false)?;
    if auth.device.is_some() {
        return Err(ApiError::bad_request("the new device has no device id yet"));
    }
    // Polling and guessing both cost; ids are 128-bit random anyway.
    state.rate_device(&format!("link/{link_id}"), 1.0)?;
    let (parts, bytes) = read_body(req, limit).await?;
    let s = load(&state.db, link_id).await?.ok_or_else(|| ApiError::not_found("no such device link (yet)"))?;
    let key = <[u8; 32]>::try_from(s.new_auth_pub.as_slice()).ok().and_then(|k| VerifyingKey::from_bytes(&k).ok()).ok_or_else(ApiError::internal)?;
    auth.verify(state, &key, &parts.method, &parts.uri, &bytes)?;
    Ok((s, bytes))
}

/// `GET /v1/links/{link_id}/new` — the new device polls (signed with its
/// own key, no device id).
pub async fn new_status(State(state): State<AppState>, Path(link_id): Path<String>, req: Request) -> ApiResult<Json<Value>> {
    let (s, bytes) = new_device(&state, &link_id, req, 0).await?;
    if !bytes.is_empty() {
        return Err(ApiError::bad_request("this request takes no body"));
    }
    if s.open() && s.expires_at <= now_secs() {
        return Err(gone());
    }
    Ok(Json(json!({
        "state": s.state,
        "expires_at": s.expires_at,
        "offer": (!s.offer.is_empty()).then(|| b64(&s.offer)),
        "sealed": s.sealed.map(|x| b64(&x)),
        "device_id": s.new_device_id,
    })))
}

#[derive(Deserialize)]
pub struct NewReq {
    /// `reveal`, `confirm`, `cancel` or `done`.
    pub action: String,
    pub reveal: Option<String>,
    pub transcript_hash: Option<String>,
    pub signature: Option<String>,
}

/// `POST /v1/links/{link_id}/new` — the new device's steps.
pub async fn new_step(State(state): State<AppState>, Path(link_id): Path<String>, req: Request) -> ApiResult<Json<Value>> {
    let (_, bytes) = new_device(&state, &link_id, req, MAX_REVEAL.div_ceil(3) * 4 + 1024).await?;
    let body: NewReq = parse_json(&bytes)?;
    let raw_id = raw_link_id(&link_id)?;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let s = load(&mut *tx, &link_id).await?.ok_or_else(|| ApiError::not_found("no such device link"))?;
    let expired = s.expires_at <= now_secs();
    let next = match body.action.as_str() {
        "reveal" => {
            if !s.open() || expired {
                return Err(gone());
            }
            if s.state != "offered" {
                return Err(wrong_state("already revealed"));
            }
            let reveal = decode_limited(body.reveal.as_deref().unwrap_or(""), MAX_REVEAL, "reveal")?;
            sqlx::query("UPDATE link_sessions SET state = 'revealed', reveal = ? WHERE link_id = ?").bind(&reveal).bind(&link_id).execute(&mut *tx).await?;
            "revealed"
        }
        "confirm" => {
            if !s.open() || expired {
                return Err(gone());
            }
            if s.state != "revealed" {
                return Err(wrong_state("not revealed, or already confirmed"));
            }
            let hash = hash32(body.transcript_hash.as_deref().unwrap_or(""))?;
            let sig = signature(body.signature.as_deref().unwrap_or(""))?;
            let key = VerifyingKey::from_bytes(&s.new_auth_pub.as_slice().try_into().map_err(|_| ApiError::internal())?).map_err(|_| ApiError::internal())?;
            key.verify_strict(&confirm_message(&raw_id, &hash), &sig)
                .map_err(|_| ApiError::forbidden("LINK_SIGNATURE", "the confirmation signature does not verify"))?;
            sqlx::query("UPDATE link_sessions SET state = 'confirmed', transcript_hash = ?, new_signature = ? WHERE link_id = ?")
                .bind(&hash[..])
                .bind(&sig.to_bytes()[..])
                .bind(&link_id)
                .execute(&mut *tx)
                .await?;
            "confirmed"
        }
        "cancel" => {
            if s.state == "linked" {
                return Err(wrong_state("already linked"));
            }
            set_cancelled(&mut tx, &link_id).await?;
            "cancelled"
        }
        "done" => {
            if s.state != "linked" {
                return Err(wrong_state("not linked"));
            }
            sqlx::query("UPDATE link_sessions SET sealed = NULL, offer = x'' WHERE link_id = ?").bind(&link_id).execute(&mut *tx).await?;
            "linked"
        }
        _ => return Err(ApiError::bad_request("action must be reveal, confirm, cancel or done")),
    };
    tx.commit().await?;
    state.wake(&s.owner_device);
    Ok(Json(json!({ "state": next })))
}

/// `POST /v1/devices` used to add a device with a signature of an existing
/// device alone. Devices are now added only through a confirmed link
/// (`user.device_link_code` is permanently applied) or the recovery phrase.
pub async fn add_device_refused() -> ApiError {
    ApiError::new(StatusCode::GONE, "LINK_REQUIRED", "devices are added with a confirmed device link (POST /v1/links)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_length_prefixed_and_labelled() {
        let c = confirm_message(&[1; 16], &[2; 32]);
        assert_eq!(&c[..4], &[0, 0, 0, 20]);
        assert_eq!(&c[4..24], b"tree/link/confirm/v1");
        let a = authorise_message(&[1; 16], "acc", &[3; 32], &[2; 32]);
        assert_ne!(a, authorise_message(&[1; 16], "acd", &[3; 32], &[2; 32]));
        assert_ne!(a[..], c[..]);
        assert_eq!(lp(&[b"ab", b"c"]), vec![0, 0, 0, 2, b'a', b'b', 0, 0, 0, 1, b'c']);
    }
}
