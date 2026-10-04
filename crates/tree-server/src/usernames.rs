//! @usernames and username links (docs/PROTOCOL.md 8.4).
//!
//! Clients send `SHA-256("tree/username/v1" || normalised name)`; the server
//! never sees the name itself. Names are short and guessable, so the hash
//! only keeps them out of plain view: lookups are rate limited (each costs
//! [`LOOKUP_COST`] tokens of the device's budget) and an account can hide its
//! name from lookups (`user.discoverable` released).

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::auth::Signed;
use crate::error::{ApiError, ApiResult};
use crate::util::{today, unb64};
use crate::{json_body, AppState};

/// Rate-limit tokens one lookup costs (a normal request costs 1).
pub const LOOKUP_COST: f64 = 10.0;

#[derive(Deserialize)]
pub struct ApplyReq {
    pub hash: String,
    #[serde(default = "yes")]
    pub discoverable: bool,
}
fn yes() -> bool {
    true
}
json_body!(ApplyReq, |_cfg| 512);

#[derive(Deserialize)]
pub struct LookupReq {
    pub hash: String,
}
json_body!(LookupReq, |_cfg| 512);

fn hash32(s: &str) -> ApiResult<Vec<u8>> {
    let h = unb64(s, "hash")?;
    if h.len() != 32 {
        return Err(ApiError::bad_request("hash must be 32 bytes"));
    }
    Ok(h)
}

/// `POST /v1/usernames/apply` — register (or change) my name, idempotent.
pub async fn apply(State(state): State<AppState>, req: Signed<ApplyReq>) -> ApiResult<Json<Value>> {
    // A bot's username is set when it is created (PROTOCOL.md 8.16).
    req.device.refuse_bot()?;
    let hash = hash32(&req.body.hash)?;
    let account = &req.device.account_id;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    // People and bots share one namespace of names.
    if sqlx::query("SELECT 1 FROM bots WHERE username_hash = ?").bind(&hash).fetch_optional(&mut *tx).await?.is_some() {
        return Err(ApiError::new(StatusCode::CONFLICT, "USERNAME_TAKEN", "this name belongs to a bot"));
    }
    let owner: Option<String> = sqlx::query("SELECT account_id FROM usernames WHERE hash = ?")
        .bind(&hash)
        .fetch_optional(&mut *tx)
        .await?
        .map(|r| r.try_get("account_id"))
        .transpose()?;
    if owner.as_ref().is_some_and(|o| o != account) {
        return Err(ApiError::new(StatusCode::CONFLICT, "USERNAME_TAKEN", "this name belongs to another account"));
    }
    sqlx::query("DELETE FROM usernames WHERE account_id = ?").bind(account).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO usernames (hash, account_id, discoverable, created_day) VALUES (?, ?, ?, ?)")
        .bind(&hash)
        .bind(account)
        .bind(req.body.discoverable)
        .bind(today())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "state": "applied", "discoverable": req.body.discoverable })))
}

/// `POST /v1/usernames/release` — drop my name (and its link), idempotent.
pub async fn release(State(state): State<AppState>, req: Signed<crate::auth::NoBody>) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    for q in ["DELETE FROM usernames WHERE account_id = ?", "DELETE FROM username_links WHERE account_id = ?"] {
        sqlx::query(q).bind(&req.device.account_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "state": "released" })))
}

/// `POST /v1/usernames/link/apply` — set (or replace: reset) my link's
/// hash. Needs a registered name. The old link stops working.
pub async fn link_apply(State(state): State<AppState>, req: Signed<LookupReq>) -> ApiResult<Json<Value>> {
    req.device.refuse_bot()?;
    let hash = hash32(&req.body.hash)?;
    let account = &req.device.account_id;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let named = sqlx::query("SELECT 1 FROM usernames WHERE account_id = ?").bind(account).fetch_optional(&mut *tx).await?.is_some();
    if !named {
        return Err(ApiError::new(StatusCode::CONFLICT, "NO_USERNAME", "register a username first"));
    }
    let r = sqlx::query(
        "INSERT INTO username_links (account_id, hash, created_day) VALUES (?, ?, ?) \
         ON CONFLICT(account_id) DO UPDATE SET hash = excluded.hash, created_day = excluded.created_day",
    )
    .bind(account)
    .bind(&hash)
    .bind(today())
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
    Ok(Json(json!({ "state": "applied" })))
}

/// `POST /v1/usernames/link/release` — delete my link, idempotent.
pub async fn link_release(State(state): State<AppState>, req: Signed<crate::auth::NoBody>) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM username_links WHERE account_id = ?").bind(&req.device.account_id).execute(&state.db).await?;
    Ok(Json(json!({ "state": "released" })))
}

/// `POST /v1/usernames/link/lookup` — account id behind a link's hash,
/// only while its name is registered and discoverable (the same `404`
/// otherwise). Costs as much as a name lookup.
pub async fn link_lookup(State(state): State<AppState>, req: Signed<LookupReq>) -> ApiResult<Json<Value>> {
    let hash = hash32(&req.body.hash)?;
    req.device.charge_outreach(&state, LOOKUP_COST - 1.0)?;
    let account: Option<String> = sqlx::query(
        "SELECT l.account_id FROM username_links l JOIN usernames u ON u.account_id = l.account_id \
         WHERE l.hash = ? AND u.discoverable = 1",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await?
    .map(|r| r.try_get("account_id"))
    .transpose()?;
    match account {
        Some(a) => Ok(Json(json!({ "account_id": a }))),
        None => Err(ApiError::not_found("no such link")),
    }
}

/// `POST /v1/usernames/lookup` — account id behind a name, if discoverable.
pub async fn lookup(State(state): State<AppState>, req: Signed<LookupReq>) -> ApiResult<Json<Value>> {
    let hash = hash32(&req.body.hash)?;
    req.device.charge_outreach(&state, LOOKUP_COST - 1.0)?;
    let account: Option<String> = sqlx::query("SELECT account_id FROM usernames WHERE hash = ? AND discoverable = 1")
        .bind(&hash)
        .fetch_optional(&state.db)
        .await?
        .map(|r| r.try_get("account_id"))
        .transpose()?;
    match account {
        Some(a) => Ok(Json(json!({ "account_id": a }))),
        None => Err(ApiError::not_found("no such name")),
    }
}
