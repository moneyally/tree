//! Resumable opaque media storage.
//!
//! The server never receives a media key and never decrypts a manifest. It
//! validates only transport-level invariants (sizes, hashes, chunk indexes)
//! and stores ciphertext until the configured retention deadline.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::auth::Signed;
use crate::error::{ApiError, ApiResult};
use crate::util::{b64, b64_exceeds, new_id, now_secs, unb64};
use crate::{json_body, AppState};

const CAP_BYTES: usize = 32;
const MAX_MANIFEST: usize = 16 * 1024;
const MAX_CHUNKS: usize = 65_535;
pub const CAPABILITY_HEADER: &str = "x-tree-media-capability";

#[derive(Deserialize)]
pub struct InitReq {
    pub manifest: String,
    pub key_commitment: String,
    pub plaintext_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
}

json_body!(InitReq, |cfg| MAX_MANIFEST * 2 + 512);

#[derive(Serialize)]
pub struct InitResp {
    pub media_id: String,
    pub capability: String,
    pub expires_at: i64,
    pub already_finalized: bool,
}

pub async fn init(
    State(state): State<AppState>,
    req: Signed<InitReq>,
) -> ApiResult<Json<InitResp>> {
    if req.body.plaintext_size == 0
        || req.body.chunk_size == 0
        || req.body.chunk_size as usize > state.cfg.max_media_chunk_bytes
        || req.body.chunk_count == 0
        || req.body.chunk_count as usize > MAX_CHUNKS
    {
        return Err(ApiError::bad_request("invalid media geometry"));
    }
    let expected = req
        .body
        .plaintext_size
        .div_ceil(req.body.chunk_size as u64);
    if expected != req.body.chunk_count as u64 {
        return Err(ApiError::bad_request("chunk count does not match plaintext size"));
    }
    if req.body.plaintext_size > state.cfg.max_file_bytes as u64 {
        return Err(ApiError::too_large("media is too large"));
    }
    let manifest = unb64(&req.body.manifest, "manifest")?;
    if manifest.is_empty() || manifest.len() > MAX_MANIFEST {
        return Err(ApiError::bad_request("invalid media manifest"));
    }
    let key_commitment = unb64(&req.body.key_commitment, "key_commitment")?;
    if key_commitment.len() != 32 {
        return Err(ApiError::bad_request("key commitment must be 32 bytes"));
    }

    let mut cap_raw = [0u8; CAP_BYTES];
    getrandom::getrandom(&mut cap_raw).map_err(|_| ApiError::internal())?;
    let cap_hash: [u8; 32] = Sha256::digest(cap_raw).into();
    let manifest_hash: [u8; 32] = Sha256::digest(&manifest).into();
    let now = now_secs();
    let expires_at = now + state.cfg.file_ttl_secs as i64;
    let media_id = new_id();

    sqlx::query(
        "INSERT INTO media_objects
         (id, owner_device_id, capability_hash, manifest, manifest_sha256, key_commitment,
          plaintext_size, chunk_size, chunk_count, finalized, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
    )
    .bind(&media_id)
    .bind(&req.device.device_id)
    .bind(&cap_hash[..])
    .bind(&manifest)
    .bind(&manifest_hash[..])
    .bind(&key_commitment)
    .bind(req.body.plaintext_size as i64)
    .bind(req.body.chunk_size as i64)
    .bind(req.body.chunk_count as i64)
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    Ok(Json(InitResp {
        media_id,
        capability: b64(&cap_raw),
        expires_at,
        already_finalized: false,
    }))
}

#[derive(Deserialize)]
pub struct ChunkReq {
    pub index: u32,
    pub ciphertext: String,
    pub sha256: String,
}
json_body!(ChunkReq, |cfg| (cfg.max_media_chunk_bytes + 16) * 4 / 3 + 512);

pub async fn put_chunk(
    State(state): State<AppState>,
    Path(media_id): Path<String>,
    headers: HeaderMap,
    req: Signed<ChunkReq>,
) -> ApiResult<Json<serde_json::Value>> {
    let cap = capability(&headers)?;
    let row = sqlx::query(
        "SELECT capability_hash, owner_device_id, chunk_size, chunk_count, plaintext_size, finalized, expires_at
         FROM media_objects WHERE id = ?",
    )
    .bind(&media_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("media not found"))?;

    let cap_hash: [u8; 32] = Sha256::digest(&cap).into();
    let stored_cap: Vec<u8> = row.try_get("capability_hash")?;
    if stored_cap.as_slice() != cap_hash.as_slice() {
        return Err(ApiError::unauthorized("invalid media capability"));
    }
    let owner: String = row.try_get("owner_device_id")?;
    if owner != req.device.device_id {
        return Err(ApiError::forbidden("MEDIA_OWNER_MISMATCH", "media belongs to another device"));
    }
    let expires_at: i64 = row.try_get("expires_at")?;
    if expires_at <= now_secs() {
        return Err(ApiError::not_found("media not found"));
    }
    let finalized: i64 = row.try_get("finalized")?;
    if finalized != 0 {
        return Err(ApiError::conflict("MEDIA_FINALIZED", "media is already finalized"));
    }

    let chunk_size: usize = row.try_get::<i64, _>("chunk_size")? as usize;
    let chunk_count: u32 = row.try_get::<i64, _>("chunk_count")? as u32;
    if req.body.index >= chunk_count {
        return Err(ApiError::bad_request("chunk index out of range"));
    }
    let ciphertext = unb64(&req.body.ciphertext, "ciphertext")?;
    let plaintext_size: u64 = row.try_get::<i64, _>("plaintext_size")? as u64;
    let offset = req.body.index as u64 * chunk_size as u64;
    let remaining = plaintext_size.saturating_sub(offset);
    let expected_ciphertext = remaining.min(chunk_size as u64) as usize + 16;
    if ciphertext.len() != expected_ciphertext {
        return Err(ApiError::bad_request("encrypted chunk size does not match manifest"));
    }
    let expected_hash = Sha256::digest(&ciphertext);
    let claimed = hex::decode(&req.body.sha256)
        .map_err(|_| ApiError::bad_request("invalid chunk hash"))?;
    if claimed.len() != 32 || claimed.as_slice() != expected_hash.as_slice() {
        return Err(ApiError::bad_request("chunk hash mismatch"));
    }

    sqlx::query(
        "INSERT INTO media_chunks (media_id, chunk_index, ciphertext, sha256)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(media_id, chunk_index) DO UPDATE SET
           ciphertext = excluded.ciphertext, sha256 = excluded.sha256",
    )
    .bind(&media_id)
    .bind(req.body.index as i64)
    .bind(&ciphertext)
    .bind(&expected_hash[..])
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({
        "media_id": media_id,
        "index": req.body.index,
        "sha256": hex::encode(expected_hash),
    })))
}

fn capability(headers: &HeaderMap) -> ApiResult<Vec<u8>> {
    let value = headers
        .get(CAPABILITY_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("media capability required"))?;
    let cap = unb64(value, "capability")?;
    if cap.len() != CAP_BYTES {
        return Err(ApiError::unauthorized("invalid media capability"));
    }
    Ok(cap)
}

async fn authorize(
    state: &AppState,
    media_id: &str,
    cap: &[u8],
) -> ApiResult<sqlx::sqlite::SqliteRow> {
    let cap_hash: [u8; 32] = Sha256::digest(cap).into();
    sqlx::query(
        "SELECT manifest, manifest_sha256, key_commitment, plaintext_size, chunk_size,
                chunk_count, finalized, expires_at
         FROM media_objects WHERE id = ? AND capability_hash = ?",
    )
    .bind(media_id)
    .bind(&cap_hash[..])
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("media not found"))
}

pub async fn manifest(
    State(state): State<AppState>,
    Path(media_id): Path<String>,
    headers: HeaderMap,
    _req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let cap = capability(&headers)?;
    let row = authorize(&state, &media_id, &cap).await?;
    let expires_at: i64 = row.try_get("expires_at")?;
    if expires_at <= now_secs() {
        return Err(ApiError::not_found("media not found"));
    }
    let manifest: Vec<u8> = row.try_get("manifest")?;
    let hash: Vec<u8> = row.try_get("manifest_sha256")?;
    let key_commitment: Vec<u8> = row.try_get("key_commitment")?;
    Ok(Json(serde_json::json!({
        "media_id": media_id,
        "manifest": b64(&manifest),
        "manifest_sha256": hex::encode(hash),
        "key_commitment": hex::encode(key_commitment),
        "plaintext_size": row.try_get::<i64, _>("plaintext_size")?,
        "chunk_size": row.try_get::<i64, _>("chunk_size")?,
        "chunk_count": row.try_get::<i64, _>("chunk_count")?,
        "finalized": row.try_get::<i64, _>("finalized")? != 0,
        "expires_at": expires_at,
    })))
}

pub async fn get_chunk(
    State(state): State<AppState>,
    Path((media_id, index)): Path<(String, u32)>,
    headers: HeaderMap,
    _req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let cap = capability(&headers)?;
    let row = authorize(&state, &media_id, &cap).await?;
    let expires_at: i64 = row.try_get("expires_at")?;
    if expires_at <= now_secs() {
        return Err(ApiError::not_found("media not found"));
    }
    let chunk_count: u32 = row.try_get::<i64, _>("chunk_count")? as u32;
    if index >= chunk_count {
        return Err(ApiError::bad_request("chunk index out of range"));
    }
    let chunk = sqlx::query(
        "SELECT ciphertext, sha256 FROM media_chunks
         WHERE media_id = ? AND chunk_index = ?",
    )
    .bind(&media_id)
    .bind(index as i64)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("chunk not uploaded"))?;
    let body: Vec<u8> = chunk.try_get("ciphertext")?;
    let hash: Vec<u8> = chunk.try_get("sha256")?;
    Ok(Json(serde_json::json!({
        "media_id": media_id,
        "index": index,
        "ciphertext": b64(&body),
        "sha256": hex::encode(hash),
    })))
}

pub async fn finalize(
    State(state): State<AppState>,
    Path(media_id): Path<String>,
    headers: HeaderMap,
    _req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let cap = capability(&headers)?;
    let row = authorize(&state, &media_id, &cap).await?;
    let expires_at: i64 = row.try_get("expires_at")?;
    if expires_at <= now_secs() {
        return Err(ApiError::not_found("media not found"));
    }
    let finalized: i64 = row.try_get("finalized")?;
    if finalized != 0 {
        return Ok(Json(serde_json::json!({"media_id": media_id, "finalized": true})));
    }
    let expected: u32 = row.try_get::<i64, _>("chunk_count")? as u32;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM media_chunks WHERE media_id = ?",
    )
    .bind(&media_id)
    .fetch_one(&state.db)
    .await?;
    if count != expected as i64 {
        return Err(ApiError::conflict("MEDIA_INCOMPLETE", "not all media chunks are uploaded"));
    }
    let distinct_bad: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM media_chunks WHERE media_id = ? AND length(sha256) != 32",
    )
    .bind(&media_id)
    .fetch_one(&state.db)
    .await?;
    if distinct_bad != 0 {
        return Err(ApiError::internal());
    }
    sqlx::query("UPDATE media_objects SET finalized = 1 WHERE id = ?")
        .bind(&media_id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({"media_id": media_id, "finalized": true})))
}
