//! Encrypted attachments (docs/PROTOCOL.md 6.12), uploaded in parts.
//!
//! Clients upload ciphertext only; the key is inside an end-to-end
//! encrypted message, and the size the server sees is already padded to a
//! bucket by the client.
//!
//! * `POST /v1/uploads` starts an upload of a declared size and returns its
//!   id and the part size. The size must be one a Tree client can produce
//!   (an attachment of a padded bucket, PROTOCOL.md 6.12, at least 1072
//!   bytes), within `MAX_ATTACHMENT_BYTES`, the account's daily quota and its
//!   cap on bytes held (`MAX_LIVE_BYTES_PER_ACCOUNT`), and the disk must keep
//!   `MIN_FREE_DISK_BYTES` free (`507` otherwise; F-026).
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

// The attachment format's sizes (PROTOCOL.md 6.12; the same numbers as
// `tree_core::attachment`, checked against it in the tests).
const FMT_CHUNK: u64 = 1 << 20;
const FMT_TAG: u64 = 16;
const FMT_HEADER: u64 = 32;
const FMT_MIN_PADDED: u64 = 1024;

/// Is `p` a padded size the attachment format produces: 1024, a power of
/// two up to 1 MiB, or a Padme bucket above?
fn is_bucket(p: u64) -> bool {
    if p <= FMT_MIN_PADDED {
        return p == FMT_MIN_PADDED;
    }
    if p <= FMT_CHUNK {
        return p.is_power_of_two();
    }
    let e = 63 - u64::from(p.leading_zeros());
    let s = 64 - u64::from(e.leading_zeros());
    p & ((1u64 << (e - s)) - 1) == 0
}

/// Is `size` the length of an attachment some plaintext size gives:
/// `32 + padded + 16 * ceil(padded / 1 MiB)` with `padded` a bucket? The
/// smallest is 1072 bytes (an empty file).
pub fn valid_size(size: u64) -> bool {
    let Some(body) = size.checked_sub(FMT_HEADER) else { return false };
    let k = body.div_ceil(FMT_CHUNK + FMT_TAG).max(1);
    (k.saturating_sub(1)..=k + 1).filter(|k| *k >= 1).any(|k| {
        body.checked_sub(k * FMT_TAG).is_some_and(|p| p >= FMT_MIN_PADDED && p.div_ceil(FMT_CHUNK).max(1) == k && is_bucket(p))
    })
}

/// Bytes free for unprivileged use on the file system holding `dir`.
#[cfg(unix)]
fn free_disk_bytes(dir: &std::path::Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c` is a valid NUL-terminated path and `st` is written by
    // statvfs before it is read (only when it returns 0).
    let st = unsafe {
        if libc::statvfs(c.as_ptr(), st.as_mut_ptr()) != 0 {
            return None;
        }
        st.assume_init()
    };
    #[allow(clippy::unnecessary_cast)]
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

#[cfg(not(unix))]
fn free_disk_bytes(_dir: &std::path::Path) -> Option<u64> {
    None
}

/// Bytes declared by unfinished uploads and not yet written.
async fn outstanding(tx: &mut sqlx::SqliteConnection, cs: usize) -> Result<u64, sqlx::Error> {
    let n: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(size - MIN(size, received * ?)), 0) FROM uploads")
        .bind(cs as i64)
        .fetch_one(tx)
        .await?;
    Ok(n.max(0) as u64)
}

/// One lock per upload id while a part is written (F-031): a slow retry of
/// part `i` must not truncate the file after part `i + 1` was written.
#[derive(Default)]
pub struct UploadLocks(std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>);

impl UploadLocks {
    async fn lock(&self, id: &str) -> UploadGuard<'_> {
        let m = {
            let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
            map.entry(id.to_string()).or_default().clone()
        };
        let guard = m.clone().lock_owned().await;
        UploadGuard { locks: self, id: id.to_string(), _guard: guard, _m: m }
    }
}

struct UploadGuard<'a> {
    locks: &'a UploadLocks,
    id: String,
    _guard: tokio::sync::OwnedMutexGuard<()>,
    _m: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl Drop for UploadGuard<'_> {
    fn drop(&mut self) {
        let mut map = self.locks.0.lock().unwrap_or_else(|e| e.into_inner());
        // Ours, the guard's and the map's: nobody else waits for it.
        if map.get(&self.id).is_some_and(|m| std::sync::Arc::strong_count(m) <= 3) {
            map.remove(&self.id);
        }
    }
}

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
    if size > state.cfg.max_attachment_bytes {
        return Err(ApiError::too_large("attachment larger than this server allows")
            .with("max_bytes", state.cfg.max_attachment_bytes.into()));
    }
    // Only sizes the attachment format produces: no tiny blobs that cost a
    // row and a file each, no odd sizes that could tell files apart.
    if !valid_size(size) {
        return Err(ApiError::bad_request("not a padded attachment size (PROTOCOL.md 6.12)"));
    }
    let quota = state.cfg.upload_quota_bytes_per_day;
    let over = || ApiError::forbidden("QUOTA_EXCEEDED", "daily upload quota used up; try again tomorrow (UTC)");
    if size > quota {
        return Err(over());
    }
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    // What the account may hold: everything it started uploading within the
    // attachment lifetime (an upper bound on what is still stored).
    let ttl_days = state.cfg.message_ttl_secs.div_ceil(86_400) as i64;
    let held: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(bytes), 0) FROM upload_quota WHERE account_id = ? AND day > ?")
        .bind(&req.device.account_id)
        .bind(today() - ttl_days - 1)
        .fetch_one(&mut *tx)
        .await?;
    if held.max(0) as u64 + size > state.cfg.max_live_bytes_per_account {
        return Err(ApiError::forbidden("STORAGE_LIMIT", "this account holds as many attachment bytes as it may; older ones expire")
            .with("max_bytes", state.cfg.max_live_bytes_per_account.into()));
    }
    // The server's disk: keep `MIN_FREE_DISK_BYTES` free after this and the
    // unfinished uploads, or stay under `MAX_TOTAL_ATTACHMENT_BYTES`.
    let pending = outstanding(&mut tx, state.cfg.upload_chunk_bytes).await? + size;
    if state.cfg.min_free_disk_bytes > 0 {
        let _ = tokio::fs::create_dir_all(&state.cfg.attachment_dir).await;
        if let Some(free) = free_disk_bytes(&state.cfg.attachment_dir) {
            if free < pending.saturating_add(state.cfg.min_free_disk_bytes) {
                return Err(ApiError::insufficient_storage("the server is short of disk space; try again later"));
            }
        }
    }
    if state.cfg.max_total_attachment_bytes > 0 {
        let stored: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(size), 0) FROM attachments").fetch_one(&mut *tx).await?;
        if (stored.max(0) as u64).saturating_add(pending) > state.cfg.max_total_attachment_bytes {
            return Err(ApiError::insufficient_storage("the server holds as many attachment bytes as it may; try again later"));
        }
    }
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
    // Parts of one upload are handled one at a time, from reading where the
    // upload stands to counting the part (F-031).
    let _lock = state.upload_locks.lock(&id).await;
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

/// Writes one part at its offset. Nothing after it is cut off (F-031): a
/// late retry of an earlier part rewrites only its own bytes, never the
/// parts already written after it. A part cut off by a crash is rewritten
/// whole by its retry; [`finish`] fixes the length.
async fn write_part(cfg: &Config, id: &str, offset: u64, bytes: &[u8]) -> ApiResult<()> {
    tokio::fs::create_dir_all(&cfg.attachment_dir).await.map_err(io)?;
    let mut f = tokio::fs::OpenOptions::new().create(true).write(true).truncate(false).open(part_path(cfg, id)).await.map_err(io)?;
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
        let f = tokio::fs::OpenOptions::new().write(true).open(&part).await.map_err(io)?;
        f.set_len(size).await.map_err(io)?;
        f.sync_data().await.map_err(io)?;
        drop(f);
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
    // Counters stay for the attachment lifetime: they bound what an account
    // holds (MAX_LIVE_BYTES_PER_ACCOUNT).
    let ttl_days = state.cfg.message_ttl_secs.div_ceil(86_400) as i64;
    sqlx::query("DELETE FROM upload_quota WHERE day <= ?").bind(now.div_euclid(86_400) - ttl_days - 1).execute(&state.db).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tree_core::attachment as fmt;

    /// F-031: a late retry of part 0, written after part 1, leaves part 1
    /// in place (before, it cut the file back to part 0's end).
    #[tokio::test]
    async fn a_late_retry_of_an_earlier_part_cuts_nothing() {
        let dir = std::env::temp_dir().join(format!("tree-putpart-{}", std::process::id()));
        let cfg = Config { attachment_dir: dir.clone(), ..Config::default() };
        let (p0, p1) = (vec![1u8; 4096], vec![2u8; 100]);
        write_part(&cfg, "u", 0, &p0).await.unwrap();
        write_part(&cfg, "u", 4096, &p1).await.unwrap();
        write_part(&cfg, "u", 0, &p0).await.unwrap(); // the stale retry
        let got = std::fs::read(part_path(&cfg, "u")).unwrap();
        assert_eq!(got, [p0, p1].concat());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The server's copy of the format's sizes matches the client's.
    #[test]
    fn valid_sizes_are_exactly_the_formats() {
        assert_eq!((FMT_CHUNK, FMT_TAG, FMT_HEADER, FMT_MIN_PADDED), (fmt::CHUNK as u64, fmt::TAG as u64, fmt::HEADER as u64, fmt::MIN_PADDED));
        let mut sizes: Vec<u64> = (0..5000u64).chain((0..3000).map(|i| i * 7919 + 1)).chain((0..400).map(|i| i << 22 | 12345)).collect();
        sizes.push(fmt::MAX_FILE);
        let mut good = std::collections::BTreeSet::new();
        for n in sizes {
            let c = fmt::ciphertext_len(n);
            assert!(valid_size(c), "plaintext {n} gives {c}");
            good.insert(c);
        }
        assert_eq!(*good.iter().next().unwrap(), 1072);
        // Every size in between that no plaintext gives is refused (checked
        // densely below 2 MiB and around each bucket above).
        for s in 0..(2u64 << 20) {
            assert_eq!(valid_size(s), good.contains(&s), "{s}");
        }
        for &g in good.iter().filter(|g| **g > 2 << 20) {
            for s in [g - 16, g - 1, g + 1, g + 16] {
                assert!(!valid_size(s) || good.contains(&s), "{s}");
            }
        }
    }
}
