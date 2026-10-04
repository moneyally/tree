//! MLS key packages. Opaque to the server. One-time key packages are handed
//! out once; a device's single last-resort key package is handed out only
//! when it has none of those left, and is kept.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::auth::{NoBody, Signed};
use crate::error::{ApiError, ApiResult};
use crate::util::{b64, b64_exceeds, check_id, unb64};
use crate::{json_body, AppState};

/// Claims cost this many rate-limit tokens on top of the request itself,
/// so one device cannot quickly drain another account's key packages.
const CLAIM_EXTRA_COST: f64 = 4.0;

#[derive(Deserialize)]
pub struct UploadReq {
    pub key_packages: Vec<String>,
}
json_body!(UploadReq, |cfg| cfg.max_key_packages_per_upload
    * (cfg.max_key_package_bytes.div_ceil(3) * 4 + 8)
    + 1024);

#[derive(Serialize)]
pub struct UploadResp {
    pub stored: usize,
    pub count: i64,
}

async fn count_for(db: impl sqlx::SqliteExecutor<'_>, device_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query("SELECT COUNT(*) AS n FROM key_packages WHERE device_id = ?")
        .bind(device_id)
        .fetch_one(db)
        .await?
        .try_get("n")
}

fn decode(cfg: &crate::config::Config, kp: &str) -> ApiResult<Vec<u8>> {
    if b64_exceeds(kp, cfg.max_key_package_bytes) {
        return Err(ApiError::too_large("key package too large"));
    }
    let bytes = unb64(kp, "key package")?;
    if bytes.is_empty() {
        return Err(ApiError::bad_request("empty key package"));
    }
    if bytes.len() > cfg.max_key_package_bytes {
        return Err(ApiError::too_large("key package too large"));
    }
    Ok(bytes)
}

/// `POST /v1/keypackages`
pub async fn upload(
    State(state): State<AppState>,
    req: Signed<UploadReq>,
) -> ApiResult<Json<UploadResp>> {
    let cfg = &state.cfg;
    let list = &req.body.key_packages;
    if list.is_empty() {
        return Err(ApiError::bad_request("key_packages is empty"));
    }
    if list.len() > cfg.max_key_packages_per_upload {
        return Err(ApiError::too_large(format!(
            "at most {} key packages per upload",
            cfg.max_key_packages_per_upload
        )));
    }
    let decoded = list.iter().map(|kp| decode(cfg, kp)).collect::<ApiResult<Vec<_>>>()?;

    let device_id = &req.device.device_id;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let have = count_for(&mut *tx, device_id).await?;
    if have + decoded.len() as i64 > cfg.max_key_packages_per_device as i64 {
        return Err(ApiError::limit_exceeded(format!(
            "a device may store at most {} key packages",
            cfg.max_key_packages_per_device
        )));
    }
    for bytes in &decoded {
        sqlx::query("INSERT INTO key_packages (device_id, data) VALUES (?, ?)")
            .bind(device_id)
            .bind(bytes)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(UploadResp {
        stored: decoded.len(),
        count: have + decoded.len() as i64,
    }))
}

#[derive(Deserialize)]
pub struct ClaimReq {
    pub account_id: String,
}
json_body!(ClaimReq, |_cfg| 256);

#[derive(Serialize)]
pub struct ClaimedPackage {
    pub device_id: String,
    pub key_package: String,
    /// The device's last-resort key package (it had no one-time one left).
    pub last_resort: bool,
}

#[derive(Serialize)]
pub struct ClaimResp {
    pub key_packages: Vec<ClaimedPackage>,
    /// Devices of the account that have no key package left, not even a
    /// last-resort one.
    pub exhausted: Vec<String>,
    /// The account is a bot (PROTOCOL.md 8.16).
    pub bot: bool,
}

/// `POST /v1/keypackages/claim` — one key package per device of the account,
/// each deleted in the same statement that reads it; the last-resort key
/// package of a device without one-time ones, which stays.
pub async fn claim(
    State(state): State<AppState>,
    req: Signed<ClaimReq>,
) -> ApiResult<Json<ClaimResp>> {
    check_id(&req.body.account_id, "account_id")?;
    req.device.charge_outreach(&state, CLAIM_EXTRA_COST)?;

    let devices: Vec<String> =
        sqlx::query("SELECT id FROM devices WHERE account_id = ? ORDER BY id")
            .bind(&req.body.account_id)
            .fetch_all(&state.db)
            .await?
            .iter()
            .map(|r| r.try_get("id"))
            .collect::<Result<_, _>>()?;
    if devices.is_empty() {
        return Err(ApiError::not_found("unknown account"));
    }
    // Bots (PROTOCOL.md 8.16): a bot claims only people who contacted it;
    // a person claiming a bot's key packages contacts it.
    let target_bot = crate::bots::is_bot(&state.db, &req.body.account_id).await?;
    match &req.device.bot {
        Some(bot) => {
            if !crate::bots::has_contact(&state.db, bot, &req.body.account_id).await? {
                return Err(ApiError::forbidden("BOT_NO_CONTACT", "a bot can only start a chat with someone who contacted it"));
            }
        }
        None if target_bot => {
            crate::bots::platform_on(&state).await?;
            crate::bots::note_contact(&state.db, &req.body.account_id, &req.device.account_id).await?;
        }
        None => {}
    }

    let mut key_packages = Vec::new();
    let mut exhausted = Vec::new();
    for device_id in devices {
        // A single DELETE ... RETURNING: the row is chosen and removed under the
        // database write lock, so two concurrent claims can never get the same one.
        let row = sqlx::query(
            "DELETE FROM key_packages WHERE id = \
             (SELECT id FROM key_packages WHERE device_id = ? ORDER BY id LIMIT 1) \
             RETURNING data",
        )
        .bind(&device_id)
        .fetch_optional(&state.db)
        .await?;
        let (row, last_resort) = match row {
            Some(r) => (Some(r), false),
            None => {
                let r = sqlx::query("SELECT data FROM last_resort_key_packages WHERE device_id = ?")
                    .bind(&device_id)
                    .fetch_optional(&state.db)
                    .await?;
                (r, true)
            }
        };
        match row {
            Some(r) => {
                let data: Vec<u8> = r.try_get("data")?;
                key_packages.push(ClaimedPackage {
                    device_id,
                    key_package: b64(&data),
                    last_resort,
                });
            }
            None => exhausted.push(device_id),
        }
    }
    Ok(Json(ClaimResp {
        key_packages,
        exhausted,
        bot: target_bot,
    }))
}

/// `GET /v1/keypackages/count` — the caller's remaining one-time key
/// packages, and whether it has a last-resort one.
pub async fn count(
    State(state): State<AppState>,
    req: Signed<NoBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let n = count_for(&state.db, &req.device.device_id).await?;
    let lr: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM last_resort_key_packages WHERE device_id = ?")
        .bind(&req.device.device_id)
        .fetch_optional(&state.db)
        .await?;
    Ok(Json(serde_json::json!({ "count": n, "last_resort": lr.is_some() })))
}

#[derive(Deserialize)]
pub struct LastResortReq {
    pub key_package: String,
}
json_body!(LastResortReq, |cfg| cfg.max_key_package_bytes.div_ceil(3) * 4 + 64);

/// `PUT /v1/keypackages/last-resort` — sets or replaces the caller's
/// last-resort key package.
pub async fn set_last_resort(
    State(state): State<AppState>,
    req: Signed<LastResortReq>,
) -> ApiResult<Json<serde_json::Value>> {
    let bytes = decode(&state.cfg, &req.body.key_package)?;
    sqlx::query(
        "INSERT INTO last_resort_key_packages (device_id, data) VALUES (?, ?) \
         ON CONFLICT(device_id) DO UPDATE SET data = excluded.data",
    )
    .bind(&req.device.device_id)
    .bind(&bytes)
    .execute(&state.db)
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
