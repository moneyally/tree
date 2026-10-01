//! @usernames (docs/PROTOCOL.md 8.4).
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
    let hash = hash32(&req.body.hash)?;
    let account = &req.device.account_id;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
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

/// `POST /v1/usernames/release` — drop my name, idempotent.
pub async fn release(State(state): State<AppState>, req: Signed<crate::auth::NoBody>) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM usernames WHERE account_id = ?")
        .bind(&req.device.account_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "state": "released" })))
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
