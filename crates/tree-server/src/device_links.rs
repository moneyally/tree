//! Two-sided device linking with human verification.
//!
//! QR is only a transport for the short-lived session id + challenge. A new
//! device is not registered until both sides confirm the same six-digit code.
//! The server stores the challenge and public keys, never the numeric code as
//! a standalone secret.

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::Json;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::auth::{parse_json, parse_public_key, read_body, Signed};
use crate::error::{ApiError, ApiResult};
use crate::util::{b64, new_id, now_secs, unb64, random_bytes};
use crate::{json_body, AppState};

const LINK_TTL_SECS: i64 = 5 * 60;
const LINK_CODE_DIGITS: u32 = 1_000_000;
const JOIN_CONTEXT: &str = "tree-device-link-join-v1";
const CONFIRM_CONTEXT: &str = "tree-device-link-confirm-v1";

#[derive(Serialize)]
pub struct InitiateResp {
    pub link_id: String,
    pub challenge: String,
    /// Absent until a joiner key has been attached.
    pub verification_code: Option<String>,
    pub expires_at: i64,
}

/// POST /v1/device-links
pub async fn initiate(
    State(state): State<AppState>,
    req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<InitiateResp>> {
    let id = new_id();
    let challenge = random_bytes::<32>();
    let now = now_secs();
    let expires_at = now + LINK_TTL_SECS;

    sqlx::query(
        "INSERT INTO device_link_sessions
         (id, initiator_device_id, challenge, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.device.device_id)
    .bind(&challenge[..])
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    Ok(Json(InitiateResp {
        link_id: id,
        challenge: b64(&challenge),
        verification_code: None,
        expires_at,
    }))
}

#[derive(Serialize)]
pub struct LinkStatusResp {
    pub link_id: String,
    pub challenge: String,
    pub joiner_auth_pub: Option<String>,
    pub verification_code: Option<String>,
    pub initiator_confirmed: bool,
    pub joiner_confirmed: bool,
    pub expires_at: i64,
}

fn session_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<(Vec<u8>, Option<Vec<u8>>, bool, bool, i64), sqlx::Error> {
    Ok((
        row.try_get("challenge")?,
        row.try_get("joiner_auth_pub")?,
        row.try_get::<i64, _>("initiator_confirmed")? != 0,
        row.try_get::<i64, _>("joiner_confirmed")? != 0,
        row.try_get("expires_at")?,
    ))
}

fn verification_code(challenge: &[u8], initiator_pub: &[u8], joiner_pub: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"tree-device-link-code-v1");
    h.update(challenge);
    h.update(initiator_pub);
    h.update(joiner_pub);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % LINK_CODE_DIGITS;
    format!("{n:06}")
}

async fn load_session(
    state: &AppState,
    id: &str,
) -> ApiResult<(String, Vec<u8>, Option<Vec<u8>>, bool, bool, i64)> {
    let row = sqlx::query(
        "SELECT initiator_device_id, challenge, joiner_auth_pub,
                initiator_confirmed, joiner_confirmed, expires_at
         FROM device_link_sessions WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("device link session not found"))?;

    let (challenge, joiner, init_ok, join_ok, expires_at) = session_row(&row)?;
    if expires_at <= now_secs() {
        return Err(ApiError::not_found("device link session expired"));
    }
    Ok((
        row.try_get("initiator_device_id")?,
        challenge,
        joiner,
        init_ok,
        join_ok,
        expires_at,
    ))
}

async fn initiator_public_key(state: &AppState, device_id: &str) -> ApiResult<[u8; 32]> {
    let raw: Vec<u8> = sqlx::query("SELECT auth_pub FROM devices WHERE id = ?")
        .bind(device_id)
        .fetch_one(&state.db)
        .await?
        .try_get("auth_pub")?;
    raw.try_into().map_err(|_| ApiError::internal())
}

/// GET /v1/device-links/{link_id}
pub async fn status(
    State(state): State<AppState>,
    Path(link_id): Path<String>,
    req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<LinkStatusResp>> {
    let (initiator, challenge, joiner, init_ok, join_ok, expires_at) =
        load_session(&state, &link_id).await?;
    if initiator != req.device.device_id {
        return Err(ApiError::forbidden(
            "NOT_INITIATOR",
            "only the initiating device may inspect this link",
        ));
    }
    let joiner_auth_pub = joiner.as_deref().map(b64);
    let code = match joiner.as_deref() {
        Some(joiner) => {
            let init_pub = initiator_public_key(&state, &initiator).await?;
            Some(verification_code(&challenge, &init_pub, joiner))
        }
        None => None,
    };
    Ok(Json(LinkStatusResp {
        link_id,
        challenge: b64(&challenge),
        joiner_auth_pub,
        verification_code: code,
        initiator_confirmed: init_ok,
        joiner_confirmed: join_ok,
        expires_at,
    }))
}

#[derive(Deserialize)]
pub struct JoinReq {
    pub auth_pub: String,
    pub proof: String,
}
json_body!(JoinReq, |_cfg| 2048);

fn join_message(link_id: &str, challenge: &[u8], auth_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = format!("{JOIN_CONTEXT}\n{link_id}\n").into_bytes();
    out.extend_from_slice(challenge);
    out.push(b'\n');
    out.extend_from_slice(auth_pub);
    out
}

/// POST /v1/device-links/{link_id}/join
///
/// No existing account authentication is possible yet; possession of the new
/// auth private key is proven by the signature over the session challenge.
pub async fn join(
    State(state): State<AppState>,
    Path(link_id): Path<String>,
    req: Request,
) -> ApiResult<Json<LinkStatusResp>> {
    let (_parts, body) = read_body(req, 2048).await?;
    let body: JoinReq = parse_json(&body)?;
    let (key, new_pub) = parse_public_key(&body.auth_pub)?;
    let proof: [u8; 64] = unb64(&body.proof, "proof")?
        .try_into()
        .map_err(|_| ApiError::bad_request("proof must be 64 bytes"))?;

    let (initiator, challenge, current_joiner, init_ok, join_ok, expires_at) =
        load_session(&state, &link_id).await?;
    if current_joiner.is_some() && current_joiner.as_deref() != Some(&new_pub[..]) {
        return Err(ApiError::conflict(
            "ALREADY_EXISTS",
            "this device link already has a different joiner",
        ));
    }

    key.verify_strict(
        &join_message(&link_id, &challenge, &new_pub),
        &Signature::from_bytes(&proof),
    )
    .map_err(|_| ApiError::unauthorized("device-link proof failed"))?;

    let init_pub = initiator_public_key(&state, &initiator).await?;
    let code = verification_code(&challenge, &init_pub, &new_pub);

    sqlx::query(
        "UPDATE device_link_sessions
         SET joiner_auth_pub = ?
         WHERE id = ? AND joiner_auth_pub IS NULL",
    )
    .bind(&new_pub[..])
    .bind(&link_id)
    .execute(&state.db)
    .await?;

    Ok(Json(LinkStatusResp {
        link_id,
        challenge: b64(&challenge),
        joiner_auth_pub: Some(b64(&new_pub)),
        verification_code: Some(code),
        initiator_confirmed: init_ok,
        joiner_confirmed: join_ok,
        expires_at,
    }))
}

#[derive(Deserialize)]
pub struct InitiatorConfirmReq {
    pub code: String,
}
json_body!(InitiatorConfirmReq, |_cfg| 256);

fn confirm_message(link_id: &str, code: &str) -> Vec<u8> {
    format!("{CONFIRM_CONTEXT}\n{link_id}\n{code}\n").into_bytes()
}

fn validate_code(code: &str) -> ApiResult<()> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::bad_request("verification code must be six digits"));
    }
    Ok(())
}

/// POST /v1/device-links/{link_id}/confirm
pub async fn confirm_initiator(
    State(state): State<AppState>,
    Path(link_id): Path<String>,
    req: Signed<InitiatorConfirmReq>,
) -> ApiResult<Json<LinkStatusResp>> {
    validate_code(&req.body.code)?;
    let (initiator, challenge, joiner, _init_ok, _join_ok, _expires_at) =
        load_session(&state, &link_id).await?;
    if initiator != req.device.device_id {
        return Err(ApiError::forbidden(
            "NOT_INITIATOR",
            "only the initiating device may confirm",
        ));
    }
    let joiner = joiner.ok_or_else(|| ApiError::conflict(
        "JOINER_MISSING",
        "no second device has joined the link",
    ))?;
    let init_pub = initiator_public_key(&state, &initiator).await?;
    let expected = verification_code(&challenge, &init_pub, &joiner);
    if req.body.code != expected {
        return Err(ApiError::bad_request("verification code does not match"));
    }

    sqlx::query(
        "UPDATE device_link_sessions
         SET initiator_confirmed = 1
         WHERE id = ?",
    )
    .bind(&link_id)
    .execute(&state.db)
    .await?;

    finalize_if_ready(&state, &link_id).await?;
    let (_, _, joiner, init_ok, join_ok, expires_at) = load_session(&state, &link_id).await?;
    Ok(Json(LinkStatusResp {
        link_id,
        challenge: b64(&challenge),
        joiner_auth_pub: joiner.as_deref().map(b64),
        verification_code: joiner.as_deref().map(|j| verification_code(&challenge, &init_pub, j)),
        initiator_confirmed: init_ok,
        joiner_confirmed: join_ok,
        expires_at,
    }))
}

#[derive(Deserialize)]
pub struct JoinerConfirmReq {
    pub link_id: String,
    pub code: String,
    pub auth_pub: String,
    pub proof: String,
}
json_body!(JoinerConfirmReq, |_cfg| 4096);

fn joiner_confirm_message(link_id: &str, code: &str, auth_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = format!("{CONFIRM_CONTEXT}\n{link_id}\n{code}\n").into_bytes();
    out.extend_from_slice(auth_pub);
    out
}

/// POST /v1/device-links/confirm-join
///
/// The request is unauthenticated because this key does not exist in devices
/// until both sides have confirmed.
pub async fn confirm_join(
    State(state): State<AppState>,
    Path(link_id): Path<String>,
    req: Request,
) -> ApiResult<(StatusCode, Json<LinkStatusResp>)> {
    let (_parts, body) = read_body(req, 4096).await?;
    let body: JoinerConfirmReq = parse_json(&body)?;
    if body.link_id != link_id {
        return Err(ApiError::bad_request("link_id mismatch"));
    }
    validate_code(&body.code)?;
    let (key, new_pub) = parse_public_key(&body.auth_pub)?;
    let proof: [u8; 64] = unb64(&body.proof, "proof")?
        .try_into()
        .map_err(|_| ApiError::bad_request("proof must be 64 bytes"))?;

    let (initiator, challenge, joiner, _init_ok, _join_ok, _expires_at) =
        load_session(&state, &link_id).await?;
    if joiner.as_deref() != Some(&new_pub[..]) {
        return Err(ApiError::unauthorized("device-link joiner key mismatch"));
    }

    let init_pub = initiator_public_key(&state, &initiator).await?;
    let expected = verification_code(&challenge, &init_pub, &new_pub);
    if body.code != expected {
        return Err(ApiError::bad_request("verification code does not match"));
    }
    key.verify_strict(
        &joiner_confirm_message(&link_id, &body.code, &new_pub),
        &Signature::from_bytes(&proof),
    )
    .map_err(|_| ApiError::unauthorized("device-link confirmation failed"))?;

    sqlx::query(
        "UPDATE device_link_sessions
         SET joiner_confirmed = 1
         WHERE id = ?",
    )
    .bind(&link_id)
    .execute(&state.db)
    .await?;

    let (created, _device_id) = finalize_if_ready(&state, &link_id).await?;
    let (_, _, joiner, init_ok, join_ok, expires_at) = load_session(&state, &link_id).await?;
    Ok((
        if created { StatusCode::CREATED } else { StatusCode::OK },
        Json(LinkStatusResp {
            link_id,
            challenge: b64(&challenge),
            joiner_auth_pub: joiner.as_deref().map(b64),
            verification_code: joiner.as_deref().map(|j| verification_code(&challenge, &init_pub, j)),
            initiator_confirmed: init_ok,
            joiner_confirmed: join_ok,
            expires_at,
        }),
    ))
}

async fn finalize_if_ready(state: &AppState, link_id: &str) -> ApiResult<(bool, String)> {
    let (initiator, _challenge, joiner, init_ok, join_ok, _expires_at) =
        load_session(state, link_id).await?;
    let used: i64 = sqlx::query("SELECT used FROM device_link_sessions WHERE id = ?")
        .bind(link_id)
        .fetch_one(&state.db)
        .await?
        .try_get("used")?;
    if used != 0 {
        let joiner = joiner.ok_or_else(|| ApiError::conflict(
            "JOINER_MISSING",
            "used device-link session has no joiner",
        ))?;
        let existing: Option<String> = sqlx::query("SELECT id FROM devices WHERE auth_pub = ?")
            .bind(&joiner[..])
            .fetch_optional(&state.db)
            .await?
            .map(|row| row.try_get("id"))
            .transpose()?;
        return Ok((false, existing.unwrap_or_default()));
    }
    if !init_ok || !join_ok {
        return Ok((false, String::new()));
    }
    let joiner = joiner.ok_or_else(|| ApiError::conflict(
        "JOINER_MISSING",
        "joiner disappeared before confirmation",
    ))?;

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    let exists: Option<i64> = sqlx::query(
        "SELECT 1 FROM devices WHERE auth_pub = ?",
    )
    .bind(&joiner[..])
    .fetch_optional(&mut *tx)
    .await?
    .map(|row| row.try_get(0))
    .transpose()?;
    if exists.is_some() {
        return Err(ApiError::conflict(
            "ALREADY_EXISTS",
            "this authentication key is already registered",
        ));
    }

    let count: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM devices d
         JOIN devices i ON i.account_id = d.account_id
         WHERE i.id = ?",
    )
    .bind(&initiator)
    .fetch_one(&mut *tx)
    .await?
    .try_get("n")?;
    // Resolve the account through the initiator so the new device joins the
    // same account, not an attacker-controlled account.
    let account_id: String = sqlx::query("SELECT account_id FROM devices WHERE id = ?")
        .bind(&initiator)
        .fetch_one(&mut *tx)
        .await?
        .try_get("account_id")?;
    if count >= state.cfg.max_devices_per_account as i64 {
        return Err(ApiError::limit_exceeded("device limit reached"));
    }

    let device_id = new_id();
    sqlx::query(
        "INSERT INTO devices (id, account_id, auth_pub, created_day)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&device_id)
    .bind(&account_id)
    .bind(&joiner[..])
    .bind(crate::util::today())
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE device_link_sessions SET used = 1 WHERE id = ?",
    )
    .bind(link_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok((true, device_id))
}
