//! Operator feature flags (server scope). Every flag has apply and release;
//! both are idempotent and return the current state.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

use crate::auth::{check_admin, parse_json};
use crate::error::{ApiError, ApiResult};
use crate::util::now_secs;
use crate::AppState;

pub const SIGNUPS: &str = "server.signups";
pub const BOT_PLATFORM: &str = "server.bot_platform";
pub const CALLS: &str = "server.calls";
pub const PUBLIC_SPACES: &str = "server.public_spaces";
pub const NEW_ACCOUNT_LIMITS: &str = "server.new_account_limits";
pub const REPORT_LIMITS: &str = "server.report_limits";

/// Server flags known to this build. All start applied.
pub const SERVER_FLAGS: &[&str] = &[SIGNUPS, BOT_PLATFORM, CALLS, PUBLIC_SPACES, NEW_ACCOUNT_LIMITS, REPORT_LIMITS];

const APPLIED: &str = "applied";
const RELEASED: &str = "released";
const MAX_REASON_CHARS: usize = 500;

/// Inserts missing flags with their default state. Existing state is kept.
pub async fn seed(db: &SqlitePool) -> Result<(), sqlx::Error> {
    let now = now_secs();
    for key in SERVER_FLAGS {
        sqlx::query("INSERT OR IGNORE INTO features (key, state, changed_at) VALUES (?, ?, ?)")
            .bind(key)
            .bind(APPLIED)
            .bind(now)
            .execute(db)
            .await?;
    }
    Ok(())
}

/// Sets a flag directly (for tests and tooling; operators use the API).
pub async fn set_applied(db: &SqlitePool, key: &str, applied: bool) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE features SET state = ?, changed_at = ? WHERE key = ?")
        .bind(if applied { APPLIED } else { RELEASED })
        .bind(now_secs())
        .bind(key)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn is_applied(db: &SqlitePool, key: &str) -> Result<bool, sqlx::Error> {
    let state: Option<String> = sqlx::query("SELECT state FROM features WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await?
        .map(|r| r.try_get("state"))
        .transpose()?;
    Ok(state.as_deref() != Some(RELEASED))
}

#[derive(Serialize)]
pub struct FeatureStatus {
    pub key: String,
    /// `applied` or `released`.
    pub state: String,
    /// Unix seconds of the last change.
    pub changed_at: i64,
}

#[derive(Serialize)]
pub struct FeatureList {
    pub features: Vec<FeatureStatus>,
}

fn status_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<FeatureStatus, sqlx::Error> {
    Ok(FeatureStatus {
        key: r.try_get("key")?,
        state: r.try_get("state")?,
        changed_at: r.try_get("changed_at")?,
    })
}

/// `GET /v1/features` — public.
pub async fn list(State(state): State<AppState>) -> ApiResult<Json<FeatureList>> {
    let rows = sqlx::query("SELECT key, state, changed_at FROM features ORDER BY key")
        .fetch_all(&state.db)
        .await?;
    let features = rows
        .iter()
        .map(status_from_row)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|f| SERVER_FLAGS.contains(&f.key.as_str()))
        .collect();
    Ok(Json(FeatureList { features }))
}

#[derive(Deserialize, Default)]
struct ChangeReq {
    reason: Option<String>,
}

async fn set(
    state: &AppState,
    headers: &HeaderMap,
    key: &str,
    target: &'static str,
    body: &[u8],
) -> ApiResult<Json<FeatureStatus>> {
    check_admin(&state.cfg, headers)?;
    if !SERVER_FLAGS.contains(&key) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "UNKNOWN_FEATURE",
            "unknown feature key",
        ));
    }
    if body.len() > 4096 {
        return Err(ApiError::too_large("request body too large"));
    }
    let req: ChangeReq = if body.is_empty() {
        ChangeReq::default()
    } else {
        parse_json(body)?
    };
    if req
        .reason
        .as_ref()
        .is_some_and(|r| r.chars().count() > MAX_REASON_CHARS)
    {
        return Err(ApiError::bad_request(format!(
            "reason is limited to {MAX_REASON_CHARS} characters"
        )));
    }

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let current = sqlx::query("SELECT key, state, changed_at FROM features WHERE key = ?")
        .bind(key)
        .fetch_one(&mut *tx)
        .await?;
    let current = status_from_row(&current)?;
    if current.state == target {
        tx.rollback().await?;
        return Ok(Json(current));
    }
    let now = now_secs();
    sqlx::query("UPDATE features SET state = ?, changed_at = ? WHERE key = ?")
        .bind(target)
        .bind(now)
        .bind(key)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO feature_audit (key, state, at, reason) VALUES (?, ?, ?, ?)")
        .bind(key)
        .bind(target)
        .bind(now)
        .bind(req.reason)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(target: "tree_server::features", key, state = target, "operator changed flag");
    Ok(Json(FeatureStatus {
        key: key.to_string(),
        state: target.to_string(),
        changed_at: now,
    }))
}

/// `POST /v1/features/{key}/apply` — operator only.
pub async fn apply(
    State(state): State<AppState>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<FeatureStatus>> {
    set(&state, &headers, &key, APPLIED, &body).await
}

/// `POST /v1/features/{key}/release` — operator only.
pub async fn release(
    State(state): State<AppState>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<FeatureStatus>> {
    set(&state, &headers, &key, RELEASED, &body).await
}
