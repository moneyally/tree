//! Per-device mailboxes.
//!
//! A send stores the ciphertext once and adds one mailbox entry per recipient
//! device. The sender is never stored with the message. Arrival time is kept
//! to the minute.
//! A body is deleted as soon as every recipient has acknowledged it, or after
//! the TTL by the purge task.
//!
//! A send may carry an idempotency key (PROTOCOL.md 8.10): a retry of the
//! same request with the same key gets the first answer and delivers
//! nothing again; the same key with another request is refused. The record
//! holds an HMAC of the request under a key that exists only in this
//! process's memory and is forgotten after a day, so a copy of the database
//! cannot match a record to a stored body (F-023).

use std::collections::HashSet;
use std::time::Duration;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::Row;
use tokio::time::Instant;

use crate::auth::{NoBody, Signed};
use crate::error::{ApiError, ApiResult};
use crate::util::{b64, b64_exceeds, check_id, new_id, now_secs, round_to_minute, today, unb64, ID_LEN};
use crate::{json_body, wire, AppState};

/// At most this many ids per acknowledgement.
pub const MAX_ACK_IDS: usize = 1000;
/// Decoded length of an idempotency key.
pub const IDEMPOTENCY_KEY_MIN: usize = 16;
pub const IDEMPOTENCY_KEY_MAX: usize = 64;
/// Domain label of the request tag stored with an idempotency key.
const REQUEST_TAG_LABEL: &[u8] = b"tree/send-request/v2";
/// Length of a tag key id; a stored record is `key id || tag`.
const TAG_KEY_ID: usize = 8;

/// The keys of the request tags (PROTOCOL.md 8.10): 32 random bytes per
/// UTC day, made on first use, held only in memory (never in the database
/// or logs), and forgotten once the day after has passed. Records made
/// under a forgotten key are purged with it ([`purge_idempotency`]).
#[derive(Default)]
pub struct RequestTagKeys(std::sync::Mutex<Vec<TagKey>>);

struct TagKey {
    day: i64,
    id: [u8; TAG_KEY_ID],
    key: [u8; 32],
}

impl RequestTagKeys {
    fn keep_window(keys: &mut Vec<TagKey>, today: i64) {
        keys.retain(|k| k.day >= today - 1 && k.day <= today);
    }

    /// Today's key and its id.
    fn current(&self, today: i64) -> ([u8; TAG_KEY_ID], [u8; 32]) {
        let mut keys = self.0.lock().expect("tag keys lock");
        Self::keep_window(&mut keys, today);
        if let Some(k) = keys.iter().find(|k| k.day == today) {
            return (k.id, k.key);
        }
        let mut k = TagKey { day: today, id: [0; TAG_KEY_ID], key: [0; 32] };
        getrandom::getrandom(&mut k.id).expect("operating system random number generator failed");
        getrandom::getrandom(&mut k.key).expect("operating system random number generator failed");
        let out = (k.id, k.key);
        keys.push(k);
        out
    }

    /// The key with this id, if it is still held (today's or yesterday's).
    fn by_id(&self, id: &[u8], today: i64) -> Option<[u8; 32]> {
        let mut keys = self.0.lock().expect("tag keys lock");
        Self::keep_window(&mut keys, today);
        keys.iter().find(|k| k.id == id).map(|k| k.key)
    }
}

#[derive(Deserialize)]
pub struct SendReq {
    pub recipients: Vec<String>,
    pub body: String,
    /// Base64, 16 to 64 bytes, chosen by the sending device per message.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}
json_body!(SendReq, |cfg| cfg.max_message_bytes.div_ceil(3) * 4
    + cfg.max_recipients * (ID_LEN + 4)
    + 1024);

#[derive(Serialize)]
pub struct SendResp {
    /// Mailboxes the message was put into.
    pub delivered: usize,
    /// Recipient ids that are not registered devices.
    pub unknown_devices: Vec<String>,
    /// Recipient devices whose mailbox is full.
    pub full_devices: Vec<String>,
    /// This is the stored answer to an earlier request with the same
    /// idempotency key; nothing was delivered now. The device lists are not
    /// stored (they would link the sender to its recipients) and are empty.
    pub replayed: bool,
}

/// HMAC-SHA-256 under `key` over the label, the body and the sorted,
/// de-duplicated recipients, each length-prefixed (u32 big-endian), so two
/// different requests cannot have the same encoding. Without the key (which
/// never leaves memory) the tag cannot be recomputed from a stored body.
pub fn request_tag(key: &[u8; 32], body: &[u8], recipients: &[String]) -> [u8; 32] {
    let mut sorted: Vec<&String> = recipients.iter().collect();
    sorted.sort();
    sorted.dedup();
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    h.update(&(REQUEST_TAG_LABEL.len() as u32).to_be_bytes());
    h.update(REQUEST_TAG_LABEL);
    h.update(&(body.len() as u32).to_be_bytes());
    h.update(body);
    h.update(&(sorted.len() as u32).to_be_bytes());
    for r in sorted {
        h.update(&(r.len() as u32).to_be_bytes());
        h.update(r.as_bytes());
    }
    h.finalize().into_bytes().into()
}

fn parse_key(k: &str) -> ApiResult<Vec<u8>> {
    if b64_exceeds(k, IDEMPOTENCY_KEY_MAX) {
        return Err(ApiError::bad_request("idempotency_key too long"));
    }
    let key = unb64(k, "idempotency_key")?;
    if !(IDEMPOTENCY_KEY_MIN..=IDEMPOTENCY_KEY_MAX).contains(&key.len()) {
        return Err(ApiError::bad_request(format!(
            "idempotency_key must be {IDEMPOTENCY_KEY_MIN} to {IDEMPOTENCY_KEY_MAX} bytes"
        )));
    }
    Ok(key)
}

/// `POST /v1/messages`
pub async fn send(
    State(state): State<AppState>,
    req: Signed<SendReq>,
) -> ApiResult<Json<SendResp>> {
    let cfg = &state.cfg;
    let SendReq { recipients, body, idempotency_key } = req.body;
    let key = idempotency_key.as_deref().map(parse_key).transpose()?;
    if recipients.is_empty() {
        return Err(ApiError::bad_request("recipients is empty"));
    }
    if recipients.len() > req.device.max_fanout && req.device.max_fanout < cfg.max_recipients {
        return Err(ApiError::forbidden("LIMITED", format!("this account may send to at most {} devices at once for now", req.device.max_fanout)));
    }
    if recipients.len() > cfg.max_recipients {
        return Err(ApiError::too_large(format!(
            "at most {} recipients",
            cfg.max_recipients
        )));
    }
    let mut seen = HashSet::with_capacity(recipients.len());
    let mut unique = Vec::with_capacity(recipients.len());
    for r in recipients {
        check_id(&r, "recipient")?;
        if seen.insert(r.clone()) {
            unique.push(r);
        }
    }
    if b64_exceeds(&body, cfg.max_message_bytes) {
        return Err(ApiError::too_large("message body too large"));
    }
    let bytes = unb64(&body, "body")?;
    drop(body);
    if bytes.is_empty() {
        return Err(ApiError::bad_request("message body is empty"));
    }
    if bytes.len() > cfg.max_message_bytes {
        return Err(ApiError::too_large("message body too large"));
    }
    // Only application messages travel here: commits go through
    // /v1/commits, welcomes only with their commit, proposals not at all.
    match wire::envelope_header(&bytes) {
        Ok(h) if h.content_type == wire::APPLICATION => {}
        Ok(h) if h.content_type == wire::COMMIT => {
            return Err(ApiError::bad_request("commits must be sent to /v1/commits"))
        }
        Ok(_) => return Err(ApiError::bad_request("proposals are not accepted")),
        Err(_) if wire::is_welcome(&bytes) => {
            return Err(ApiError::bad_request("welcomes travel only with their commit"))
        }
        Err(why) => return Err(ApiError::bad_request(format!("body: {why}"))),
    }
    let day = today();
    let record = key.as_ref().map(|_| {
        let (id, k) = state.request_tags.current(day);
        let mut r = id.to_vec();
        r.extend_from_slice(&request_tag(&k, &bytes, &unique));
        r
    });
    let sender = req.device.device_id.as_str();

    // The lookup, the delivery and the record are one transaction, so two
    // concurrent requests with the same key deliver once.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    if let Some(key) = &key {
        let seen = sqlx::query("SELECT request_hash, delivered FROM idempotency_keys WHERE device_id = ? AND key = ?")
            .bind(sender)
            .bind(key.as_slice())
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(row) = seen {
            let stored: Vec<u8> = row.try_get("request_hash")?;
            // Recompute under the key the record was made with. If that key
            // is gone (the server restarted), the request cannot be compared
            // and is taken as the retry it almost surely is: the client's
            // key already hashes the body (PROTOCOL.md 6.13).
            let differs = stored.len() == TAG_KEY_ID + 32
                && state.request_tags.by_id(&stored[..TAG_KEY_ID], day).is_some_and(|k| {
                    !bool::from(subtle::ConstantTimeEq::ct_eq(&request_tag(&k, &bytes, &unique)[..], &stored[TAG_KEY_ID..]))
                });
            if differs {
                return Err(ApiError::conflict(
                    "IDEMPOTENCY_KEY_REUSE",
                    "this idempotency key was used for another request",
                ));
            }
            let delivered: i64 = row.try_get("delivered")?;
            return Ok(Json(SendResp {
                delivered: delivered as usize,
                unknown_devices: vec![],
                full_devices: vec![],
                replayed: true,
            }));
        }
    }
    // Fan-out to many mailboxes costs more (not charged again for a replay).
    req.device.charge_outreach(&state, (unique.len() / 100) as f64)?;

    let d = deliver(&mut tx, cfg, &bytes, unique).await?;
    if let (Some(key), Some(record)) = (&key, &record) {
        sqlx::query(
            "INSERT INTO idempotency_keys (device_id, key, request_hash, delivered, created_day) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(sender)
        .bind(key.as_slice())
        .bind(record.as_slice())
        .bind(d.delivered.len() as i64)
        .bind(day)
        .execute(&mut *tx)
        .await?;
        // At most MAX_IDEMPOTENCY_KEYS per device: the oldest go first.
        sqlx::query(
            "DELETE FROM idempotency_keys WHERE device_id = ?1 AND seq <= \
             (SELECT seq FROM idempotency_keys WHERE device_id = ?1 ORDER BY seq DESC LIMIT 1 OFFSET ?2)",
        )
        .bind(sender)
        .bind(cfg.max_idempotency_keys as i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    for id in &d.delivered {
        state.wake(id);
    }
    Ok(Json(SendResp {
        delivered: d.delivered.len(),
        unknown_devices: d.unknown_devices,
        full_devices: d.full_devices,
        replayed: false,
    }))
}

/// Removes idempotency records whose tag key is forgotten: those of days
/// before yesterday (`now` in unix seconds), so a record lives one to two
/// days. Also removes records in the old format (a plain SHA-256 of the
/// request, which anyone holding the stored body could recompute).
/// Returns how many.
pub async fn purge_idempotency(db: &sqlx::SqlitePool, now: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM idempotency_keys WHERE created_day < ? OR length(request_hash) <> ?")
        .bind(now.div_euclid(86_400) - 1)
        .bind((TAG_KEY_ID + 32) as i64)
        .execute(db)
        .await?
        .rows_affected())
}

/// Outcome of putting one body into several mailboxes.
pub struct Delivery {
    pub delivered: Vec<String>,
    pub unknown_devices: Vec<String>,
    pub full_devices: Vec<String>,
}

/// Stores `bytes` once and adds a mailbox entry for every known device whose
/// mailbox is not full, inside the caller's transaction. The caller notifies
/// the waiters after committing.
pub async fn deliver(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    cfg: &crate::Config,
    bytes: &[u8],
    devices: Vec<String>,
) -> ApiResult<Delivery> {
    let mut delivered = Vec::new();
    let mut unknown_devices = Vec::new();
    let mut full_devices = Vec::new();
    let blob_id: i64 =
        sqlx::query("INSERT INTO blobs (body, received_at) VALUES (?, ?) RETURNING id")
            .bind(bytes)
            .bind(round_to_minute(now_secs()))
            .fetch_one(&mut **tx)
            .await?
            .try_get("id")?;
    for device_id in devices {
        let row = sqlx::query(
            "SELECT EXISTS (SELECT 1 FROM devices WHERE id = ?1) AS known, \
             (SELECT COUNT(*) FROM (SELECT 1 FROM deliveries WHERE device_id = ?1 LIMIT ?2)) AS pending",
        )
        .bind(&device_id)
        .bind(cfg.max_mailbox_messages as i64)
        .fetch_one(&mut **tx)
        .await?;
        let known: bool = row.try_get("known")?;
        let pending: i64 = row.try_get("pending")?;
        if !known {
            unknown_devices.push(device_id);
        } else if pending >= cfg.max_mailbox_messages as i64 {
            full_devices.push(device_id);
        } else {
            sqlx::query("INSERT INTO deliveries (id, device_id, blob_id) VALUES (?, ?, ?)")
                .bind(new_id())
                .bind(&device_id)
                .bind(blob_id)
                .execute(&mut **tx)
                .await?;
            delivered.push(device_id);
        }
    }
    if delivered.is_empty() {
        sqlx::query("DELETE FROM blobs WHERE id = ?")
            .bind(blob_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(Delivery { delivered, unknown_devices, full_devices })
}

#[derive(Deserialize)]
pub struct FetchQuery {
    /// Seconds to wait for a message if the mailbox is empty (long-poll).
    pub wait: Option<u64>,
}

#[derive(Serialize)]
pub struct Message {
    pub id: String,
    pub body: String,
    /// Unix seconds, rounded down to the minute.
    pub received_at: i64,
}

#[derive(Serialize)]
pub struct FetchResp {
    pub messages: Vec<Message>,
    /// More messages are waiting beyond this page.
    pub more: bool,
}

async fn load(state: &AppState, device_id: &str) -> ApiResult<FetchResp> {
    let limit = state.cfg.fetch_limit as i64;
    let rows = sqlx::query(
        "SELECT d.id AS id, b.body AS body, b.received_at AS received_at \
         FROM deliveries d JOIN blobs b ON b.id = d.blob_id \
         WHERE d.device_id = ? ORDER BY d.seq LIMIT ?",
    )
    .bind(device_id)
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await?;
    let more = rows.len() as i64 > limit;
    let mut messages = Vec::with_capacity(rows.len());
    for r in rows.iter().take(limit as usize) {
        let body: Vec<u8> = r.try_get("body")?;
        messages.push(Message {
            id: r.try_get("id")?,
            body: b64(&body),
            received_at: r.try_get("received_at")?,
        });
    }
    Ok(FetchResp { messages, more })
}

/// Removes a long-poll subscription however the request ends.
struct Subscription<'a> {
    state: &'a AppState,
    device_id: &'a str,
    notify: Option<std::sync::Arc<tokio::sync::Notify>>,
}

impl Drop for Subscription<'_> {
    fn drop(&mut self) {
        if let Some(n) = self.notify.take() {
            self.state.waiters.unsubscribe(self.device_id, n);
        }
    }
}

/// `GET /v1/messages?wait=N`
pub async fn fetch(
    State(state): State<AppState>,
    query: Result<Query<FetchQuery>, QueryRejection>,
    req: Signed<NoBody>,
) -> ApiResult<Json<FetchResp>> {
    let Query(q) =
        query.map_err(|_| ApiError::bad_request("wait must be a non-negative integer"))?;
    let wait = q.wait.unwrap_or(0).min(state.cfg.long_poll_max_secs);
    let device_id = req.device.device_id.as_str();
    if wait == 0 {
        return Ok(Json(load(&state, device_id).await?));
    }

    let sub = Subscription {
        state: &state,
        device_id,
        notify: Some(state.waiters.subscribe(device_id)),
    };
    let notify = sub.notify.as_deref().ok_or_else(ApiError::internal)?;
    let deadline = Instant::now() + Duration::from_secs(wait);
    let resp = loop {
        // Register before reading, so a send between the read and the wait is not missed.
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let resp = load(&state, device_id).await?;
        if !resp.messages.is_empty() || Instant::now() >= deadline {
            break resp;
        }
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            break load(&state, device_id).await?;
        }
    };
    drop(sub);
    Ok(Json(resp))
}

#[derive(Deserialize)]
pub struct AckReq {
    pub ids: Vec<String>,
}
json_body!(AckReq, |_cfg| MAX_ACK_IDS * (ID_LEN + 4) + 256);

/// `POST /v1/messages/ack` — deletes the caller's own messages. Ids that are
/// not in the caller's mailbox are ignored.
pub async fn ack(
    State(state): State<AppState>,
    req: Signed<AckReq>,
) -> ApiResult<Json<serde_json::Value>> {
    let ids = &req.body.ids;
    if ids.len() > MAX_ACK_IDS {
        return Err(ApiError::too_large(format!(
            "at most {MAX_ACK_IDS} ids per acknowledgement"
        )));
    }
    for id in ids {
        check_id(id, "message id")?;
    }
    if ids.is_empty() {
        return Ok(Json(serde_json::json!({ "deleted": 0 })));
    }
    let ids_json = serde_json::to_string(ids).map_err(|_| ApiError::internal())?;

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let blob_ids: Vec<i64> = sqlx::query(
        "DELETE FROM deliveries WHERE device_id = ? AND id IN (SELECT value FROM json_each(?)) \
         RETURNING blob_id",
    )
    .bind(&req.device.device_id)
    .bind(&ids_json)
    .fetch_all(&mut *tx)
    .await?
    .iter()
    .map(|r| r.try_get("blob_id"))
    .collect::<Result<_, _>>()?;
    if !blob_ids.is_empty() {
        let blobs_json = serde_json::to_string(&blob_ids).map_err(|_| ApiError::internal())?;
        sqlx::query(
            "DELETE FROM blobs WHERE id IN (SELECT value FROM json_each(?)) \
             AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.blob_id = blobs.id)",
        )
        .bind(&blobs_json)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Json(serde_json::json!({ "deleted": blob_ids.len() })))
}
