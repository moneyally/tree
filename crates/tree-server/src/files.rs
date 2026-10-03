//! Opaque encrypted media object storage.
//!
//! The body is a Tree EncryptedFile envelope produced on the client. The
//! server does not decrypt it. Access is capability-based: a random bearer
//! token is returned on upload, and only its SHA-256 digest is stored.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::auth::Signed;
use crate::error::{ApiError, ApiResult};
use crate::util::{b64, b64_exceeds, new_id, now_secs, unb64};
use crate::{json_body, AppState};

const CAP_BYTES: usize = 32;
const MAX_META: usize = 256;

#[derive(Deserialize)]
pub struct UploadFileReq {
    pub ciphertext: String,
}
json_body!(UploadFileReq, |cfg| cfg.max_file_bytes.div_ceil(3) * 4 + MAX_META);

#[derive(Serialize)]
pub struct UploadFileResp {
    pub file_id: String,
    pub capability: String,
    pub size_bytes: usize,
    pub sha256: String,
    pub expires_at: i64,
}

/// POST /v1/files
pub async fn upload(
    State(state): State<AppState>,
    req: Signed<UploadFileReq>,
) -> ApiResult<Json<UploadFileResp>> {
    let encoded = req.body.ciphertext;
    if b64_exceeds(&encoded, state.cfg.max_file_bytes) {
        return Err(ApiError::too_large("encrypted file too large"));
    }
    let body = unb64(&encoded, "ciphertext")?;
    if body.is_empty() {
        return Err(ApiError::bad_request("encrypted file is empty"));
    }
    if body.len() > state.cfg.max_file_bytes {
        return Err(ApiError::too_large("encrypted file too large"));
    }

    let mut capability_raw = [0u8; CAP_BYTES];
    getrandom::getrandom(&mut capability_raw).map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            format!("OS randomness unavailable: {e}"),
        )
    })?;
    let capability = b64(&capability_raw);
    let capability_hash: [u8; 32] = Sha256::digest(&capability_raw).into();
    let body_hash: [u8; 32] = Sha256::digest(&body).into();
    let size_bytes = body.len();
    let now = now_secs();
    let expires_at = now + state.cfg.file_ttl_secs as i64;
    let file_id = new_id();

    sqlx::query(
        "INSERT INTO files
         (id, owner_device_id, body, size_bytes, body_sha256, capability_hash, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&file_id)
    .bind(&req.device.device_id)
    .bind(&body)
    .bind(size_bytes as i64)
    .bind(&body_hash[..])
    .bind(&capability_hash[..])
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    Ok(Json(UploadFileResp {
        file_id,
        capability,
        size_bytes,
        sha256: hex::encode(body_hash),
        expires_at,
    }))
}

#[derive(Deserialize)]
pub struct FileQuery {
    pub capability: String,
}

#[derive(Serialize)]
pub struct FileResp {
    pub file_id: String,
    pub ciphertext: String,
    pub size_bytes: usize,
    pub sha256: String,
    pub expires_at: i64,
}

/// GET /v1/files/{file_id}?capability=<bearer>
pub async fn download(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    Query(query): Query<FileQuery>,
    _req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<FileResp>> {
    if file_id.len() != 22 || query.capability.len() > 128 {
        return Err(ApiError::bad_request(
            "invalid file identifier or capability",
        ));
    }
    let cap = unb64(&query.capability, "capability")?;
    if cap.len() != CAP_BYTES {
        return Err(ApiError::unauthorized("invalid file capability"));
    }
    let cap_hash: [u8; 32] = Sha256::digest(&cap).into();
    let row = sqlx::query(
        "SELECT body, size_bytes, body_sha256, expires_at FROM files
         WHERE id = ? AND capability_hash = ?",
    )
    .bind(&file_id)
    .bind(&cap_hash[..])
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("file not found"))?;

    let expires_at: i64 = row.try_get("expires_at")?;
    if expires_at <= now_secs() {
        return Err(ApiError::not_found("file not found"));
    }
    let body: Vec<u8> = row.try_get("body")?;
    let size_bytes: i64 = row.try_get("size_bytes")?;
    let hash: Vec<u8> = row.try_get("body_sha256")?;
    let hash: [u8; 32] = hash.try_into().map_err(|_| ApiError::internal())?;

    Ok(Json(FileResp {
        file_id,
        ciphertext: b64(&body),
        size_bytes: size_bytes as usize,
        sha256: hex::encode(hash),
        expires_at,
    }))
}
