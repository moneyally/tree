//! Reporting with message franking, and account suspension
//! (docs/PROTOCOL.md 8.5).
//!
//! End-to-end encryption means the server never sees messages. A report is
//! a user's device handing over messages it decrypted, by the user's choice.
//! Franking lets the server check that a reported message is genuine and
//! really came from the reported account, without the server storing
//! anything per message:
//!
//! 1. The sender picks a fresh key `k` for each message and computes
//!    `com = HMAC-SHA-256(k, "tree/franking/v1" || group_id || payload)`.
//! 2. It asks the server for a tag (`POST /v1/franking`):
//!    `tag = HMAC-SHA-256(server_key, "tree/franking-tag/v1" || com || account || minute)`.
//!    The server learns `com` (random to it) and nothing else, and keeps
//!    nothing.
//! 3. `k`, `tag` and `minute` travel inside the end-to-end encrypted message.
//! 4. A report carries the payload, `k`, `tag`, `minute`, group id and the
//!    reported account; the server recomputes both MACs. A valid tag proves
//!    the reported account's device asked for a tag on exactly this content.
//!
//! HMAC-SHA-256 is used as a commitment and as a MAC as in the published
//! franking constructions; nothing new is built here.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::Row;
use subtle::ConstantTimeEq;

use crate::auth::{check_admin, parse_json, Signed};
use crate::error::{ApiError, ApiResult};
use crate::util::{check_id, new_id, now_secs, random_bytes, round_to_minute, today, unb64};
use crate::{json_body, AppState};

type HmacSha256 = Hmac<Sha256>;

pub const COMMIT_LABEL: &[u8] = b"tree/franking/v1";
pub const TAG_LABEL: &[u8] = b"tree/franking-tag/v1";
/// Messages per report, and size limits.
pub const MAX_MESSAGES: usize = 20;
pub const MAX_PAYLOAD: usize = 64 * 1024;
pub const MAX_REASON: usize = 500;

/// The server's franking key, created on first start and kept in the database.
pub async fn franking_key(db: &sqlx::SqlitePool) -> Result<[u8; 32], sqlx::Error> {
    if let Some(r) = sqlx::query("SELECT value FROM server_secrets WHERE name = 'franking'").fetch_optional(db).await? {
        let v: Vec<u8> = r.try_get("value")?;
        if let Ok(k) = <[u8; 32]>::try_from(v.as_slice()) {
            return Ok(k);
        }
    }
    let k: [u8; 32] = random_bytes();
    sqlx::query("INSERT OR IGNORE INTO server_secrets (name, value) VALUES ('franking', ?)").bind(k.as_slice()).execute(db).await?;
    // Another process may have won the insert: read back what is stored.
    let r = sqlx::query("SELECT value FROM server_secrets WHERE name = 'franking'").fetch_one(db).await?;
    let v: Vec<u8> = r.try_get("value")?;
    Ok(v.as_slice().try_into().unwrap_or(k))
}

fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// `com` for a payload (what the sender computes).
pub fn commitment(k: &[u8], group_id: &[u8], payload: &[u8]) -> [u8; 32] {
    mac(k, &[COMMIT_LABEL, &(group_id.len() as u32).to_be_bytes(), group_id, payload])
}

/// The server's tag over a commitment, an account and a minute.
pub fn tag(server_key: &[u8; 32], com: &[u8; 32], account: &str, minute: i64) -> [u8; 32] {
    mac(server_key, &[TAG_LABEL, com, &(account.len() as u32).to_be_bytes(), account.as_bytes(), &minute.to_be_bytes()])
}

#[derive(Deserialize)]
pub struct FrankReq {
    pub com: String,
}
json_body!(FrankReq, |_cfg| 256);

/// `POST /v1/franking` — tag for a commitment, bound to the caller's account.
pub async fn frank(State(state): State<AppState>, req: Signed<FrankReq>) -> ApiResult<Json<Value>> {
    let com: [u8; 32] = unb64(&req.body.com, "com")?.try_into().map_err(|_| ApiError::bad_request("com must be 32 bytes"))?;
    let minute = round_to_minute(now_secs());
    let t = tag(&state.franking_key().await?, &com, &req.device.account_id, minute);
    Ok(Json(json!({ "tag": crate::util::b64(&t), "minute": minute })))
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ReportedMessage {
    /// The application payload exactly as received (UTF-8 JSON text).
    pub payload: String,
    /// Base64: franking key `k` (32), tag (32); MLS group id.
    pub key: String,
    pub tag: String,
    pub minute: i64,
    pub group_id: String,
}

#[derive(Deserialize)]
pub struct ReportReq {
    pub reported_account: String,
    pub reason: String,
    pub messages: Vec<ReportedMessage>,
}
json_body!(ReportReq, |_cfg| MAX_MESSAGES * (MAX_PAYLOAD * 2 + 512) + 2048);

/// Checks one reported message against the reported account.
fn verify(key: &[u8; 32], account: &str, m: &ReportedMessage) -> bool {
    let (Ok(k), Ok(t), Ok(g)) = (unb64(&m.key, "key"), unb64(&m.tag, "tag"), unb64(&m.group_id, "group_id")) else {
        return false;
    };
    if k.len() != 32 || t.len() != 32 {
        return false;
    }
    let com = commitment(&k, &g, m.payload.as_bytes());
    bool::from(tag(key, &com, account, m.minute).ct_eq(&t[..]))
}

/// `POST /v1/reports` — a user reports messages. `201 {"id", "verified"}`.
pub async fn report(State(state): State<AppState>, req: Signed<ReportReq>) -> ApiResult<(StatusCode, Json<Value>)> {
    let r = req.body;
    check_id(&r.reported_account, "reported_account")?;
    if r.messages.is_empty() || r.messages.len() > MAX_MESSAGES {
        return Err(ApiError::bad_request(format!("1 to {MAX_MESSAGES} messages per report")));
    }
    if r.reason.chars().count() > MAX_REASON || r.messages.iter().any(|m| m.payload.len() > MAX_PAYLOAD) {
        return Err(ApiError::too_large("report too large"));
    }
    state.rate_device(&req.device.device_id, 10.0)?;
    let key = state.franking_key().await?;
    let checked: Vec<Value> = r
        .messages
        .iter()
        .map(|m| json!({ "payload": m.payload, "verified": verify(&key, &r.reported_account, m) }))
        .collect();
    let verified = checked.iter().all(|c| c["verified"] == true);
    let id = new_id();
    sqlx::query(
        "INSERT INTO reports (id, reported_account, reporter_account, reason, messages, verified, created_day) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&r.reported_account)
    .bind(&req.device.account_id)
    .bind(&r.reason)
    .bind(Value::Array(checked).to_string())
    .bind(verified)
    .bind(today())
    .execute(&state.db)
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id, "verified": verified }))))
}

/// `GET /v1/reports` — operator: open reports, oldest first.
pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    check_admin(&state.cfg, &headers)?;
    let rows = sqlx::query(
        "SELECT id, reported_account, reporter_account, reason, messages, verified, created_day \
         FROM reports WHERE resolved = 0 ORDER BY created_day, id LIMIT 100",
    )
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::new();
    for r in rows {
        let messages: String = r.try_get("messages")?;
        out.push(json!({
            "id": r.try_get::<String, _>("id")?,
            "reported_account": r.try_get::<String, _>("reported_account")?,
            "reporter_account": r.try_get::<String, _>("reporter_account")?,
            "reason": r.try_get::<String, _>("reason")?,
            "messages": serde_json::from_str::<Value>(&messages).unwrap_or(Value::Null),
            "verified": r.try_get::<bool, _>("verified")?,
            "created_day": r.try_get::<i64, _>("created_day")?,
        }));
    }
    Ok(Json(json!({ "reports": out })))
}

#[derive(Deserialize, Default)]
pub struct ResolveReq {
    pub resolution: Option<String>,
}

/// `POST /v1/reports/{id}/resolve` — operator closes a report.
pub async fn resolve(State(state): State<AppState>, Path(id): Path<String>, headers: HeaderMap, body: axum::body::Bytes) -> ApiResult<Json<Value>> {
    check_admin(&state.cfg, &headers)?;
    check_id(&id, "report id")?;
    let req: ResolveReq = if body.is_empty() { ResolveReq::default() } else { parse_json(&body)? };
    let n = sqlx::query("UPDATE reports SET resolved = 1, resolution = ? WHERE id = ?")
        .bind(req.resolution)
        .bind(&id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found("no such report"));
    }
    Ok(Json(json!({ "id": id, "resolved": true })))
}

/// `POST /v1/accounts/{id}/suspend/apply|release` — operator suspends or
/// restores an account (idempotent).
pub async fn suspend(
    State(state): State<AppState>,
    Path((account, action)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<Json<Value>> {
    check_admin(&state.cfg, &headers)?;
    check_id(&account, "account id")?;
    let req: ResolveReq = if body.is_empty() { ResolveReq::default() } else { parse_json(&body)? };
    match action.as_str() {
        "apply" => {
            sqlx::query("INSERT OR IGNORE INTO suspensions (account_id, since_day, reason) VALUES (?, ?, ?)")
                .bind(&account)
                .bind(today())
                .bind(req.resolution)
                .execute(&state.db)
                .await?;
        }
        "release" => {
            sqlx::query("DELETE FROM suspensions WHERE account_id = ?").bind(&account).execute(&state.db).await?;
        }
        _ => return Err(ApiError::not_found("no such endpoint")),
    }
    let suspended = is_suspended(&state.db, &account).await?;
    Ok(Json(json!({ "account_id": account, "state": if suspended { "applied" } else { "released" } })))
}

pub async fn is_suspended(db: &sqlx::SqlitePool, account: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM suspensions WHERE account_id = ?").bind(account).fetch_optional(db).await?.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_bind_content_group_account_and_minute() {
        let sk = [7u8; 32];
        let k = [1u8; 32];
        let com = commitment(&k, b"g", b"{\"t\":\"text\"}");
        let t = tag(&sk, &com, "acc", 60);
        let m = |payload: &str, g: &[u8], key: &[u8; 32], tg: &[u8; 32], minute: i64| ReportedMessage {
            payload: payload.into(),
            key: crate::util::b64(key),
            tag: crate::util::b64(tg),
            minute,
            group_id: crate::util::b64(g),
        };
        assert!(verify(&sk, "acc", &m("{\"t\":\"text\"}", b"g", &k, &t, 60)));
        assert!(!verify(&sk, "other", &m("{\"t\":\"text\"}", b"g", &k, &t, 60)), "framing another account");
        assert!(!verify(&sk, "acc", &m("{\"t\":\"texT\"}", b"g", &k, &t, 60)), "changed content");
        assert!(!verify(&sk, "acc", &m("{\"t\":\"text\"}", b"h", &k, &t, 60)), "other group");
        assert!(!verify(&sk, "acc", &m("{\"t\":\"text\"}", b"g", &[2; 32], &t, 60)), "other key");
        assert!(!verify(&sk, "acc", &m("{\"t\":\"text\"}", b"g", &k, &t, 120)), "other minute");
        assert!(!verify(&[8; 32], "acc", &m("{\"t\":\"text\"}", b"g", &k, &t, 60)), "other server");
        let mut bad = m("{\"t\":\"text\"}", b"g", &k, &t, 60);
        bad.key = "!!".into();
        assert!(!verify(&sk, "acc", &bad));
    }
}
