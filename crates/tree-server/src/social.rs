//! Stage-1 identity and social controls.
//!
//! Usernames are looked up by a client-computed hash; the clear username never
//! crosses this API. Blocks and message requests are account relationships.
//! Reports contain opaque Tree/MLS evidence only.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::HashMap;

use crate::auth::{NoBody, Signed};
use crate::error::{ApiError, ApiResult};
use crate::util::{b64, check_id, now_secs, unb64, ID_LEN};
use crate::{json_body, wire, AppState};

const USERNAME_HASH_LEN: usize = 32;
const REPORT_MAX_BYTES: usize = 256 * 1024;

fn decode_username_hash(value: &str) -> ApiResult<Vec<u8>> {
    let bytes = hex::decode(value).map_err(|_| ApiError::bad_request("username hash must be hex"))?;
    if bytes.len() != USERNAME_HASH_LEN {
        return Err(ApiError::bad_request("username hash must be 32 bytes"));
    }
    Ok(bytes)
}

fn validate_category(category: &str) -> ApiResult<()> {
    if category.is_empty() || category.len() > 64 || !category.is_ascii() {
        return Err(ApiError::bad_request(
            "report category must be 1..=64 ASCII bytes",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct SetUsernameReq {
    pub username_hash: String,
}
json_body!(SetUsernameReq, |_cfg| 256);

#[derive(Serialize)]
pub struct UsernameResp {
    pub username_hash: String,
}

/// PUT /v1/username
pub async fn set_username(
    State(state): State<AppState>,
    req: Signed<SetUsernameReq>,
) -> ApiResult<Json<UsernameResp>> {
    let hash = decode_username_hash(&req.body.username_hash)?;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    let existing = sqlx::query(
        "SELECT account_id FROM usernames WHERE username_hash = ? AND account_id <> ?",
    )
    .bind(&hash)
    .bind(&req.device.account_id)
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        return Err(ApiError::conflict(
            "ALREADY_EXISTS",
            "username is already registered",
        ));
    }

    sqlx::query(
        "INSERT INTO usernames(account_id, username_hash) VALUES (?, ?)
         ON CONFLICT(account_id) DO UPDATE SET username_hash = excluded.username_hash",
    )
    .bind(&req.device.account_id)
    .bind(&hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(UsernameResp {
        username_hash: hex::encode(hash),
    }))
}

/// GET /v1/username/{username_hash}
pub async fn lookup_username(
    State(state): State<AppState>,
    Path(username_hash): Path<String>,
    req: Signed<NoBody>,
) -> ApiResult<Json<HashMap<&'static str, String>>> {
    let hash = decode_username_hash(&username_hash)?;
    state.rate_device(&req.device.device_id, 1.0)?;

    let account: Option<String> = sqlx::query(
        "SELECT account_id FROM usernames WHERE username_hash = ?",
    )
    .bind(hash)
    .fetch_optional(&state.db)
    .await?
    .map(|r| r.try_get("account_id"))
    .transpose()?;

    let account = account.ok_or_else(|| ApiError::not_found("no account for this username"))?;
    Ok(Json(HashMap::from([("account_id", account)])))
}

/// DELETE /v1/username
pub async fn delete_username(
    State(state): State<AppState>,
    req: Signed<NoBody>,
) -> ApiResult<Json<HashMap<&'static str, bool>>> {
    sqlx::query("DELETE FROM usernames WHERE account_id = ?")
        .bind(&req.device.account_id)
        .execute(&state.db)
        .await?;
    Ok(Json(HashMap::from([("removed", true)])))
}

#[derive(Deserialize)]
pub struct MessageRequestReq {
    pub target_account_id: String,
}
json_body!(MessageRequestReq, |_cfg| 256);

#[derive(Serialize)]
pub struct MessageRequest {
    pub account_id: String,
    pub state: String,
    pub updated_at: i64,
}

#[derive(Serialize)]
pub struct MessageRequestsResp {
    pub incoming: Vec<MessageRequest>,
    pub outgoing: Vec<MessageRequest>,
}

/// POST /v1/message-requests
pub async fn create_message_request(
    State(state): State<AppState>,
    req: Signed<MessageRequestReq>,
) -> ApiResult<Json<MessageRequest>> {
    let target = req.body.target_account_id;
    check_id(&target, "target_account_id")?;
    if target == req.device.account_id {
        return Err(ApiError::bad_request("cannot request yourself"));
    }
    let target_exists = sqlx::query("SELECT 1 FROM accounts WHERE id = ?")
        .bind(&target)
        .fetch_optional(&state.db)
        .await?
        .is_some();
    if !target_exists {
        return Err(ApiError::not_found("unknown target account"));
    }

    state.rate_device(&req.device.device_id, 1.0)?;
    if is_blocked_pair(&state, &req.device.account_id, &target).await? {
        return Err(ApiError::forbidden(
            "BLOCKED",
            "message request blocked by account policy",
        ));
    }

    let now = now_secs();
    sqlx::query(
        "INSERT INTO message_requests(requester_account_id, target_account_id, state, updated_at)
         VALUES (?, ?, 'pending', ?)
         ON CONFLICT(requester_account_id, target_account_id)
         DO UPDATE SET state = 'pending', updated_at = excluded.updated_at",
    )
    .bind(&req.device.account_id)
    .bind(&target)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok(Json(MessageRequest {
        account_id: target,
        state: "pending".into(),
        updated_at: now,
    }))
}

/// GET /v1/message-requests
pub async fn list_message_requests(
    State(state): State<AppState>,
    req: Signed<NoBody>,
) -> ApiResult<Json<MessageRequestsResp>> {
    let mut incoming = Vec::new();
    let mut outgoing = Vec::new();

    let in_rows = sqlx::query(
        "SELECT requester_account_id, state, updated_at
         FROM message_requests
         WHERE target_account_id = ? ORDER BY updated_at DESC, requester_account_id",
    )
    .bind(&req.device.account_id)
    .fetch_all(&state.db)
    .await?;
    for row in in_rows {
        incoming.push(MessageRequest {
            account_id: row.try_get("requester_account_id")?,
            state: row.try_get("state")?,
            updated_at: row.try_get("updated_at")?,
        });
    }

    let out_rows = sqlx::query(
        "SELECT target_account_id, state, updated_at
         FROM message_requests
         WHERE requester_account_id = ? ORDER BY updated_at DESC, target_account_id",
    )
    .bind(&req.device.account_id)
    .fetch_all(&state.db)
    .await?;
    for row in out_rows {
        outgoing.push(MessageRequest {
            account_id: row.try_get("target_account_id")?,
            state: row.try_get("state")?,
            updated_at: row.try_get("updated_at")?,
        });
    }

    Ok(Json(MessageRequestsResp { incoming, outgoing }))
}

/// POST /v1/message-requests/{requester_account_id}/accept
pub async fn accept_message_request(
    State(state): State<AppState>,
    Path(requester): Path<String>,
    req: Signed<NoBody>,
) -> ApiResult<Json<MessageRequest>> {
    check_id(&requester, "requester_account_id")?;
    let updated = now_secs();
    let result = sqlx::query(
        "UPDATE message_requests
         SET state = 'accepted', updated_at = ?
         WHERE requester_account_id = ? AND target_account_id = ? AND state = 'pending'",
    )
    .bind(updated)
    .bind(&requester)
    .bind(&req.device.account_id)
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("no pending message request"));
    }
    if is_blocked_pair(&state, &requester, &req.device.account_id).await? {
        return Err(ApiError::forbidden(
            "BLOCKED",
            "message request is blocked by account policy",
        ));
    }
    Ok(Json(MessageRequest {
        account_id: requester,
        state: "accepted".into(),
        updated_at: updated,
    }))
}

/// POST /v1/message-requests/{requester_account_id}/reject
pub async fn reject_message_request(
    State(state): State<AppState>,
    Path(requester): Path<String>,
    req: Signed<NoBody>,
) -> ApiResult<Json<MessageRequest>> {
    check_id(&requester, "requester_account_id")?;
    let updated = now_secs();
    let result = sqlx::query(
        "UPDATE message_requests
         SET state = 'rejected', updated_at = ?
         WHERE requester_account_id = ? AND target_account_id = ? AND state = 'pending'",
    )
    .bind(updated)
    .bind(&requester)
    .bind(&req.device.account_id)
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("no pending message request"));
    }
    Ok(Json(MessageRequest {
        account_id: requester,
        state: "rejected".into(),
        updated_at: updated,
    }))
}

#[derive(Serialize)]
pub struct BlocksResp {
    pub accounts: Vec<String>,
}

/// POST /v1/blocks/{account_id}
pub async fn block_account(
    State(state): State<AppState>,
    Path(target): Path<String>,
    req: Signed<NoBody>,
) -> ApiResult<Json<serde_json::Value>> {
    check_id(&target, "account_id")?;
    if target == req.device.account_id {
        return Err(ApiError::bad_request("cannot block yourself"));
    }
    let exists = sqlx::query("SELECT 1 FROM accounts WHERE id = ?")
        .bind(&target)
        .fetch_optional(&state.db)
        .await?
        .is_some();
    if !exists {
        return Err(ApiError::not_found("unknown account"));
    }

    let now = now_secs();
    sqlx::query(
        "INSERT OR IGNORE INTO blocks(blocker_account_id, blocked_account_id, created_at)
         VALUES (?, ?, ?)",
    )
    .bind(&req.device.account_id)
    .bind(&target)
    .bind(now)
    .execute(&state.db)
    .await?;

    // A newly blocked target must not retain an outstanding incoming request.
    sqlx::query(
        "UPDATE message_requests SET state = 'rejected', updated_at = ?
         WHERE requester_account_id = ? AND target_account_id = ? AND state = 'pending'",
    )
    .bind(now)
    .bind(&target)
    .bind(&req.device.account_id)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({"blocked": target})))
}

/// DELETE /v1/blocks/{account_id}
pub async fn unblock_account(
    State(state): State<AppState>,
    Path(target): Path<String>,
    req: Signed<NoBody>,
) -> ApiResult<Json<serde_json::Value>> {
    check_id(&target, "account_id")?;
    sqlx::query(
        "DELETE FROM blocks WHERE blocker_account_id = ? AND blocked_account_id = ?",
    )
    .bind(&req.device.account_id)
    .bind(&target)
    .execute(&state.db)
    .await?;
    Ok(Json(serde_json::json!({"unblocked": target})))
}

/// GET /v1/blocks
pub async fn list_blocks(
    State(state): State<AppState>,
    req: Signed<NoBody>,
) -> ApiResult<Json<BlocksResp>> {
    let rows = sqlx::query(
        "SELECT blocked_account_id FROM blocks
         WHERE blocker_account_id = ? ORDER BY blocked_account_id",
    )
    .bind(&req.device.account_id)
    .fetch_all(&state.db)
    .await?;

    let accounts = rows
        .iter()
        .map(|row| row.try_get("blocked_account_id"))
        .collect::<Result<Vec<String>, _>>()?;
    Ok(Json(BlocksResp { accounts }))
}

async fn is_blocked_pair(
    state: &AppState,
    a: &str,
    b: &str,
) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query(
        "SELECT 1 FROM blocks
         WHERE (blocker_account_id = ? AND blocked_account_id = ?)
            OR (blocker_account_id = ? AND blocked_account_id = ?)
         LIMIT 1",
    )
    .bind(a)
    .bind(b)
    .bind(b)
    .bind(a)
    .fetch_optional(&state.db)
    .await?
    .is_some();
    Ok(exists)
}

#[derive(Deserialize)]
pub struct ReportReq {
    pub group_id: String,
    pub evidence: String,
    pub category: String,
}
json_body!(ReportReq, |cfg| cfg.max_message_bytes.div_ceil(3) * 4 + 512);

#[derive(Serialize)]
pub struct ReportResp {
    pub id: String,
    pub evidence_sha256: String,
}

/// POST /v1/reports
///
/// The evidence must be an opaque Tree envelope carrying an MLS application
/// message. The server stores it without attempting decryption.
pub async fn report(
    State(state): State<AppState>,
    req: Signed<ReportReq>,
) -> ApiResult<Json<ReportResp>> {
    check_id(&req.device.device_id, "device_id")?;
    validate_category(&req.body.category)?;

    let group_id = hex::decode(&req.body.group_id)
        .map_err(|_| ApiError::bad_request("group_id must be hex"))?;
    if group_id.is_empty() || group_id.len() > 255 {
        return Err(ApiError::bad_request("group_id has a wrong length"));
    }

    if crate::util::b64_exceeds(&req.body.evidence, REPORT_MAX_BYTES) {
        return Err(ApiError::too_large("report evidence too large"));
    }
    let evidence = unb64(&req.body.evidence, "evidence")?;
    if evidence.is_empty() || evidence.len() > REPORT_MAX_BYTES {
        return Err(ApiError::too_large("report evidence too large"));
    }

    let header = wire::envelope_header(&evidence)
        .map_err(|why| ApiError::bad_request(format!("evidence: {why}")))?;
    if header.content_type != wire::APPLICATION {
        return Err(ApiError::bad_request(
            "report evidence must contain an application message",
        ));
    }
    if header.group_id != group_id.as_slice() {
        return Err(ApiError::bad_request("group_id does not match evidence"));
    }

    let id = crate::util::new_id();
    let evidence_hash: [u8; 32] = Sha256::digest(&evidence).into();

    sqlx::query(
        "INSERT INTO reports(id, reporter_device_id, group_id, ciphertext, ciphertext_sha256, category, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.device.device_id)
    .bind(&group_id)
    .bind(&evidence)
    .bind(evidence_hash.as_slice())
    .bind(&req.body.category)
    .bind(now_secs())
    .execute(&state.db)
    .await?;

    Ok(Json(ReportResp {
        id,
        evidence_sha256: hex::encode(evidence_hash),
    }))
}
