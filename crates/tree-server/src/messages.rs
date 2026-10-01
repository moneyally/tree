//! Per-device mailboxes.
//!
//! A send stores the ciphertext once and adds one mailbox entry per recipient
//! device. The sender is never stored. Arrival time is kept to the minute.
//! A body is deleted as soon as every recipient has acknowledged it, or after
//! the TTL by the purge task.

use std::collections::HashSet;
use std::time::Duration;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tokio::time::Instant;

use crate::auth::{NoBody, Signed};
use crate::error::{ApiError, ApiResult};
use crate::util::{b64, b64_exceeds, check_id, new_id, now_secs, round_to_minute, unb64, ID_LEN};
use crate::{json_body, wire, AppState};

/// At most this many ids per acknowledgement.
pub const MAX_ACK_IDS: usize = 1000;

#[derive(Deserialize)]
pub struct SendReq {
    pub recipients: Vec<String>,
    pub body: String,
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
}

/// `POST /v1/messages`
pub async fn send(
    State(state): State<AppState>,
    req: Signed<SendReq>,
) -> ApiResult<Json<SendResp>> {
    let cfg = &state.cfg;
    let SendReq { recipients, body } = req.body;
    if recipients.is_empty() {
        return Err(ApiError::bad_request("recipients is empty"));
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
    // Fan-out to many mailboxes costs more.
    state.rate_device(&req.device.device_id, (unique.len() / 100) as f64)?;

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let d = deliver(&mut tx, cfg, &bytes, unique).await?;
    tx.commit().await?;

    for id in &d.delivered {
        state.wake(id);
    }
    Ok(Json(SendResp {
        delivered: d.delivered.len(),
        unknown_devices: d.unknown_devices,
        full_devices: d.full_devices,
    }))
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
