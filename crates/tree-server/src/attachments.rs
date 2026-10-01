//! Encrypted attachments (docs/PROTOCOL.md 6.12).
//!
//! Clients upload ciphertext only; the key is inside an end-to-end encrypted
//! message. The server stores the blob under a random id, keeps its size and
//! upload minute (not who uploaded it), serves it to any registered device
//! that knows the id, and deletes it after `MESSAGE_TTL_SECS`.

use std::path::PathBuf;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Json;
use serde_json::{json, Value};
use sqlx::Row;

use crate::auth::{NoBody, Signed, SignedBody};
use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::util::{check_id, new_id, now_secs, round_to_minute};
use crate::AppState;

/// Raw request body (the ciphertext).
pub struct RawBody(pub Vec<u8>);

impl SignedBody for RawBody {
    fn max_len(cfg: &Config) -> usize {
        cfg.max_attachment_bytes
    }
    fn parse(bytes: &[u8]) -> ApiResult<Self> {
        Ok(RawBody(bytes.to_vec()))
    }
}

fn path_of(cfg: &Config, id: &str) -> PathBuf {
    cfg.attachment_dir.join(id)
}

/// `POST /v1/attachments` — body: ciphertext. `201 {"id": "..."}`.
pub async fn upload(State(state): State<AppState>, req: Signed<RawBody>) -> ApiResult<(StatusCode, Json<Value>)> {
    let bytes = req.body.0;
    if bytes.is_empty() {
        return Err(ApiError::bad_request("empty attachment"));
    }
    // One extra token per MiB.
    state.rate_device(&req.device.device_id, (bytes.len() / (1024 * 1024)) as f64)?;
    let id = new_id();
    let dir = state.cfg.attachment_dir.clone();
    let final_path = path_of(&state.cfg, &id);
    let tmp = dir.join(format!(".{id}.part"));
    tokio::fs::create_dir_all(&dir).await.map_err(io)?;
    tokio::fs::write(&tmp, &bytes).await.map_err(io)?;
    tokio::fs::rename(&tmp, &final_path).await.map_err(io)?;
    sqlx::query("INSERT INTO attachments (id, size, created_at) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(bytes.len() as i64)
        .bind(round_to_minute(now_secs()))
        .execute(&state.db)
        .await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id, "size": bytes.len() }))))
}

/// `GET /v1/attachments/{id}` — the ciphertext.
pub async fn download(State(state): State<AppState>, Path(id): Path<String>, _req: Signed<NoBody>) -> ApiResult<Response> {
    check_id(&id, "attachment id")?;
    let known = sqlx::query("SELECT size FROM attachments WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?
        .map(|r| r.try_get::<i64, _>("size"))
        .transpose()?;
    if known.is_none() {
        return Err(ApiError::not_found("no such attachment"));
    }
    let bytes = tokio::fs::read(path_of(&state.cfg, &id)).await.map_err(|_| ApiError::not_found("no such attachment"))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(bytes))
        .map_err(|_| ApiError::internal())
}

/// Deletes attachments older than `cutoff` (unix seconds). Returns how many.
pub async fn purge(state: &AppState, cutoff: i64) -> Result<u64, sqlx::Error> {
    let ids: Vec<String> = sqlx::query("DELETE FROM attachments WHERE created_at < ? RETURNING id")
        .bind(cutoff)
        .fetch_all(&state.db)
        .await?
        .iter()
        .filter_map(|r| r.try_get("id").ok())
        .collect();
    for id in &ids {
        let _ = tokio::fs::remove_file(path_of(&state.cfg, id)).await;
    }
    Ok(ids.len() as u64)
}

fn io(e: std::io::Error) -> ApiError {
    tracing::error!(error = %e, "attachment storage");
    ApiError::internal()
}
