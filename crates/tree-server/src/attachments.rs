//! Encrypted attachments (docs/PROTOCOL.md 6.12), uploaded in parts.
//!
//! Clients upload ciphertext only; the key is inside an end-to-end
//! encrypted message, and the size the server sees is already padded to a
//! bucket by the client.
//!
//! * `POST /v1/uploads` starts an upload of a declared size (checked against
//!   `MAX_ATTACHMENT_BYTES` and the account's daily quota) and returns its
//!   id and the part size.
//! * `PUT /v1/uploads/{id}/{index}` adds part `index`, in order, from the
//!   device that started the upload; a part already received is accepted
//!   again without effect (a lost answer). After the last part the blob is
//!   an attachment with the same id; the upload record (the only link to
//!   the uploading device) is deleted.
//! * `GET /v1/uploads/{id}` tells the uploader where to resume.
//! * `GET /v1/attachments/{id}?offset=N` serves one part-sized range to any
//!   registered device that knows the id.
//!
//! Stored per attachment: id, size and upload minute (not the uploader).
//! Attachments are deleted after `MESSAGE_TTL_SECS`; unfinished uploads
//! after [`UPLOAD_TTL_SECS`].

use std::io::SeekFrom;
use std::path::PathBuf;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::auth::{NoBody, Signed, SignedBody};
use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::util::{check_id, new_id, now_secs, round_to_minute, today};
use crate::AppState;

/// Unfinished uploads are deleted this long after they started.
pub const UPLOAD_TTL_SECS: i64 = 24 * 3600;
/// Response header with the attachment's total size.
pub const H_TOTAL: &str = "x-tree-total";

const MIB: usize = 1024 * 1024;

/// One part (raw ciphertext bytes).
pub struct RawPart(pub Vec<u8>);

impl SignedBody for RawPart {
    fn max_len(cfg: &Config) -> usize {
        cfg.upload_chunk_bytes
    }
    fn parse(bytes: &[u8]) -> ApiResult<Self> {
        Ok(RawPart(bytes.to_vec()))
    }
}

#[derive(Deserialize)]
pub struct NewUpload {
    size: u64,
}
crate::json_body!(NewUpload, |_c| 1024);

fn path_of(cfg: &Config, id: &str) -> PathBuf {
    cfg.attachment_dir.join(id)
}

fn part_path(cfg: &Config, id: &str) -> PathBuf {
    cfg.attachment_dir.join(format!(".{id}.part"))
}

fn chunks_of(size: u64, cs: usize) -> u64 {
    size.div_ceil(cs as u64)
}

/// Expected length of part `index` of an upload of `size` bytes.
fn part_len(size: u64, cs: usize, index: u64) -> u64 {
    (size - index * cs as u64).min(cs as u64)
}

struct Upload {
    device_id: String,
    size: u64,
    received: u64,
}

async fn load(state: &AppState, id: &str) -> ApiResult<Option<Upload>> {
    let row = sqlx::query("SELECT device_id, size, received FROM uploads WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    Ok(match row {
        Some(r) => Some(Upload {
            device_id: r.try_get("device_id")?,
            size: r.try_get::<i64, _>("size")? as u64,
            received: r.try_get::<i64, _>("received")? as u64,
        }),
        None => None,
    })
}

async fn is_attachment(state: &AppState, id: &str) -> ApiResult<Option<u64>> {
    Ok(sqlx::query("SELECT size FROM attachments WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .map(|r| r.try_get::<i64, _>("size"))
        .transpose()?
        .map(|s| s as u64))
}

fn status_json(state: &AppState, id: &str, size: u64, received: u64, complete: bool) -> Value {
    let cs = state.cfg.upload_chunk_bytes;
    json!({
        "id": id, "size": size, "chunk_size": cs, "chunks": chunks_of(size, cs),
        "received": received, "complete": complete,
    })
}

/// `POST /v1/uploads` — `{"size": N}` (the padded ciphertext size).
/// `201 {"id", "size", "chunk_size", "chunks", "received": 0, "complete": false}`.
pub async fn create(State(state): State<AppState>, req: Signed<NewUpload>) -> ApiResult<(StatusCode, Json<Value>)> {
    let size = req.body.size;
    if size == 0 {
        return Err(ApiError::bad_request("empty attachment"));
    }
    if size > state.cfg.max_attachment_bytes {
        return Err(ApiError::too_large("attachment larger than this server allows")
            .with("max_bytes", state.cfg.max_attachment_bytes.into()));
    }
    let quota = state.cfg.upload_quota_bytes_per_day;
    let over = || ApiError::forbidden("QUOTA_EXCEEDED", "daily upload quota used up; try again tomorrow (UTC)");
    if size > quota {
        return Err(over());
    }
    let mut tx = state.db.begin().await?;
    let counted = sqlx::query(
        "INSERT INTO upload_quota (account_id, day, bytes) VALUES (?1, ?2, ?3) \
         ON CONFLICT (account_id, day) DO UPDATE SET bytes = bytes + excluded.bytes WHERE bytes + excluded.bytes <= ?4",
    )
    .bind(&req.device.account_id)
    .bind(today())
    .bind(size as i64)
    .bind(quota as i64)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if counted == 0 {
        return Err(over());
    }
    let id = new_id();
    sqlx::query("INSERT INTO uploads (id, device_id, size, received, created_at) VALUES (?, ?, ?, 0, ?)")
        .bind(&id)
        .bind(&req.device.device_id)
        .bind(size as i64)
        .bind(round_to_minute(now_secs()))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(status_json(&state, &id, size, 0, false))))
}

/// `GET /v1/uploads/{id}` — where to resume. The uploading device sees its
/// unfinished upload; once complete, anyone gets `complete: true`.
pub async fn status(State(state): State<AppState>, Path(id): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    check_id(&id, "upload id")?;
    match load(&state, &id).await? {
        Some(u) if u.device_id == req.device.device_id => Ok(Json(status_json(&state, &id, u.size, u.received, false))),
        Some(_) => Err(ApiError::not_found("no such upload")),
        None => match is_attachment(&state, &id).await? {
            Some(size) => {
                let n = chunks_of(size, state.cfg.upload_chunk_bytes);
                Ok(Json(status_json(&state, &id, size, n, true)))
            }
            None => Err(ApiError::not_found("no such upload")),
        },
    }
}

/// `PUT /v1/uploads/{id}/{index}` — body: part `index` (raw bytes, exactly
/// `chunk_size` except the last). `200 {"received", "complete", ...}`.
/// Parts go in order: a later one is `409 OUT_OF_ORDER` with `received`.
pub async fn put_part(
    State(state): State<AppState>,
    Path((id, index)): Path<(String, u64)>,
    req: Signed<RawPart>,
) -> ApiResult<Json<Value>> {
    check_id(&id, "upload id")?;
    let bytes = req.body.0;
    // One extra token per whole MiB, as for every upload.
    state.rate_device(&req.device.device_id, (bytes.len() / MIB) as f64)?;
    let cs = state.cfg.upload_chunk_bytes;
    let u = match load(&state, &id).await? {
        Some(u) if u.device_id == req.device.device_id => u,
        Some(_) => return Err(ApiError::not_found("no such upload")),
        None => {
            // Finished already (the answer to the last part was lost).
            return match is_attachment(&state, &id).await? {
                Some(size) => {
                    let n = chunks_of(size, cs);
                    Ok(Json(status_json(&state, &id, size, n, true)))
                }
                None => Err(ApiError::not_found("no such upload")),
            };
        }
    };
    let chunks = chunks_of(u.size, cs);
    if index >= chunks {
        return Err(ApiError::bad_request("part index beyond the upload"));
    }
    if bytes.len() as u64 != part_len(u.size, cs, index) {
        return Err(ApiError::bad_request("part has the wrong length"));
    }
    if index > u.received {
        return Err(ApiError::conflict("OUT_OF_ORDER", "parts go in order").with("received", u.received.into()));
    }
    let mut received = u.received;
    if index == u.received {
        write_part(&state.cfg, &id, index * cs as u64, &bytes).await?;
        let moved = sqlx::query("UPDATE uploads SET received = received + 1 WHERE id = ? AND received = ?")
            .bind(&id)
            .bind(index as i64)
            .execute(&state.db)
            .await?
            .rows_affected();
        received = if moved == 1 {
            index + 1
        } else {
            // Another request moved it on, or the purge removed it.
            match load(&state, &id).await? {
                Some(u) => u.received,
                None => return Err(ApiError::not_found("no such upload")),
            }
        };
    }
    let complete = received == chunks;
    if complete {
        finish(&state, &id, u.size).await?;
    }
    Ok(Json(status_json(&state, &id, u.size, received, complete)))
}

/// Writes one part at its offset, dropping anything after it (a part cut
/// off by a crash).
async fn write_part(cfg: &Config, id: &str, offset: u64, bytes: &[u8]) -> ApiResult<()> {
    tokio::fs::create_dir_all(&cfg.attachment_dir).await.map_err(io)?;
    let mut f = tokio::fs::OpenOptions::new().create(true).write(true).truncate(false).open(part_path(cfg, id)).await.map_err(io)?;
    f.set_len(offset).await.map_err(io)?;
    f.seek(SeekFrom::Start(offset)).await.map_err(io)?;
    f.write_all(bytes).await.map_err(io)?;
    f.sync_data().await.map_err(io)?;
    Ok(())
}

/// The last part arrived: the blob becomes an attachment (same id, no
/// uploader). Safe to run again.
async fn finish(state: &AppState, id: &str, size: u64) -> ApiResult<()> {
    let part = part_path(&state.cfg, id);
    if tokio::fs::try_exists(&part).await.map_err(io)? {
        tokio::fs::rename(&part, path_of(&state.cfg, id)).await.map_err(io)?;
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM uploads WHERE id = ?").bind(id).execute(&mut *tx).await?;
    sqlx::query("INSERT OR IGNORE INTO attachments (id, size, created_at) VALUES (?, ?, ?)")
        .bind(id)
        .bind(size as i64)
        .bind(round_to_minute(now_secs()))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// `DELETE /v1/uploads/{id}` — the uploader gives up; the partial file goes.
/// The quota it used is not given back.
pub async fn cancel(State(state): State<AppState>, Path(id): Path<String>, req: Signed<NoBody>) -> ApiResult<StatusCode> {
    check_id(&id, "upload id")?;
    let gone = sqlx::query("DELETE FROM uploads WHERE id = ? AND device_id = ?")
        .bind(&id)
        .bind(&req.device.device_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if gone == 0 {
        return Err(ApiError::not_found("no such upload"));
    }
    let _ = tokio::fs::remove_file(part_path(&state.cfg, &id)).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct Range {
    #[serde(default)]
    offset: u64,
}

/// `GET /v1/attachments/{id}?offset=N` — at most `UPLOAD_CHUNK_BYTES` of the
/// ciphertext from byte `N` (default 0); header `X-Tree-Total` = its size.
pub async fn download(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(range): Query<Range>,
    _req: Signed<NoBody>,
) -> ApiResult<Response> {
    check_id(&id, "attachment id")?;
    let Some(size) = is_attachment(&state, &id).await? else {
        return Err(ApiError::not_found("no such attachment"));
    };
    if range.offset > size {
        return Err(ApiError::bad_request("offset beyond the attachment"));
    }
    let len = (size - range.offset).min(state.cfg.upload_chunk_bytes as u64) as usize;
    let mut f = tokio::fs::File::open(path_of(&state.cfg, &id)).await.map_err(|_| ApiError::not_found("no such attachment"))?;
    f.seek(SeekFrom::Start(range.offset)).await.map_err(io)?;
    let mut bytes = vec![0u8; len];
    f.read_exact(&mut bytes).await.map_err(io)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(H_TOTAL, size.to_string())
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

/// Deletes uploads unfinished [`UPLOAD_TTL_SECS`] after they started, their
/// partial files, partial files without an upload (device deleted), and
/// quota counters of past days. Returns how many uploads were dropped.
pub async fn purge_uploads(state: &AppState, now: i64) -> Result<u64, sqlx::Error> {
    let ids: Vec<String> = sqlx::query("DELETE FROM uploads WHERE created_at < ? RETURNING id")
        .bind(now - UPLOAD_TTL_SECS)
        .fetch_all(&state.db)
        .await?
        .iter()
        .filter_map(|r| r.try_get("id").ok())
        .collect();
    for id in &ids {
        let _ = tokio::fs::remove_file(part_path(&state.cfg, id)).await;
    }
    sqlx::query("DELETE FROM upload_quota WHERE day < ?").bind(now.div_euclid(86_400)).execute(&state.db).await?;
    if let Ok(mut dir) = tokio::fs::read_dir(&state.cfg.attachment_dir).await {
        while let Ok(Some(e)) = dir.next_entry().await {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_prefix('.').and_then(|n| n.strip_suffix(".part")) else { continue };
            let known = sqlx::query("SELECT 1 FROM uploads WHERE id = ?").bind(id).fetch_optional(&state.db).await?;
            if known.is_none() {
                let _ = tokio::fs::remove_file(e.path()).await;
            }
        }
    }
    Ok(ids.len() as u64)
}

fn io(e: std::io::Error) -> ApiError {
    tracing::error!(error = %e, "attachment storage");
    ApiError::internal()
}
