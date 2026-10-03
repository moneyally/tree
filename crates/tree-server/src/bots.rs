//! BotFather-compatible registry and token authentication.
//!
//! Bot code does not execute inside Tree. This service only manages bot
//! identity, metadata, token lifecycle and safe feature switches. A separate
//! developer-run gateway later consumes the bot token and joins MLS bot lanes.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::Row;

use crate::auth::Signed;
use crate::error::{ApiError, ApiResult};
use crate::util::{b64, check_id, new_id, now_secs, unb64};
use crate::{json_body, AppState};

type BotHmac = Hmac<Sha256>;

const TOKEN_PREFIX: &str = "tb_";
const BOT_TOKEN_SECRET_LABEL: &[u8] = b"tree-bot-token-v1";
const MAX_NAME: usize = 64;
const MAX_DESCRIPTION: usize = 1024;
const MAX_COMMANDS: usize = 100;
const MAX_COMMAND_NAME: usize = 32;
const MAX_COMMAND_DESC: usize = 256;

#[derive(Serialize)]
pub struct BotSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub privacy_mode: bool,
    pub join_groups: bool,
    pub inline_mode: bool,
    pub directory_listed: bool,
    pub directory_review: String,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct BotCreateResp {
    #[serde(flatten)]
    pub bot: BotSummary,
    pub token: String,
}

#[derive(Serialize)]
pub struct TokenResp {
    pub bot_id: String,
    pub token: String,
    pub issued_at: i64,
}

#[derive(Deserialize)]
pub struct CreateBotReq {
    pub name: String,
    #[serde(default)]
    pub description: String,
}
json_body!(CreateBotReq, |_cfg| 8 * 1024);

#[derive(Deserialize)]
pub struct MetadataReq {
    pub name: Option<String>,
    pub description: Option<String>,
}
json_body!(MetadataReq, |_cfg| 8 * 1024);

#[derive(Deserialize)]
pub struct FeatureReq {
    pub state: bool,
}
json_body!(FeatureReq, |_cfg| 512);

#[derive(Serialize)]
pub struct FeatureResp {
    pub bot_id: String,
    pub feature: String,
    pub state: bool,
}

#[derive(Deserialize)]
pub struct CommandsReq {
    pub commands: Vec<CommandSpec>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct CommandSpec {
    pub command: String,
    pub description: String,
}
json_body!(CommandsReq, |_cfg| 32 * 1024);

#[derive(Serialize)]
pub struct CommandsResp {
    pub commands: Vec<CommandSpec>,
}

fn require_bot_secret(state: &AppState) -> ApiResult<[u8; 32]> {
    state.cfg.bot_token_hmac_secret.ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "BOT_PLATFORM_DISABLED",
            "bot token secret is not configured",
        )
    })
}

fn validate_name(name: &str) -> ApiResult<()> {
    let n = name.trim();
    if n.is_empty() || n.len() > MAX_NAME || n.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "bot name must be 1..=64 UTF-8 bytes without control characters",
        ));
    }
    Ok(())
}

fn validate_description(description: &str) -> ApiResult<()> {
    if description.len() > MAX_DESCRIPTION || description.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "bot description is too long or contains control characters",
        ));
    }
    Ok(())
}

fn new_token(bot_id: &str, secret: &[u8; 32]) -> ApiResult<(String, Vec<u8>)> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)
        .map_err(|_| ApiError::internal())?;
    let suffix = URL_SAFE_NO_PAD.encode(raw);
    let token = format!("{TOKEN_PREFIX}{bot_id}_{suffix}");
    let hash = token_hmac(secret, token.as_bytes())?;
    Ok((token, hash))
}

fn token_hmac(secret: &[u8; 32], token: &[u8]) -> ApiResult<Vec<u8>> {
    let mut mac = BotHmac::new_from_slice(secret)
        .map_err(|_| ApiError::internal())?;
    mac.update(BOT_TOKEN_SECRET_LABEL);
    mac.update(token);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn row_to_summary(row: &sqlx::sqlite::SqliteRow) -> Result<BotSummary, sqlx::Error> {
    Ok(BotSummary {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        privacy_mode: row.try_get::<i64, _>("privacy_mode")? != 0,
        join_groups: row.try_get::<i64, _>("join_groups")? != 0,
        inline_mode: row.try_get::<i64, _>("inline_mode")? != 0,
        directory_listed: row.try_get::<i64, _>("directory_listed")? != 0,
        directory_review: row.try_get("directory_review")?,
        created_at: row.try_get("created_at")?,
    })
}

async fn owner_bot(
    state: &AppState,
    owner_account_id: &str,
    bot_id: &str,
) -> ApiResult<sqlx::sqlite::SqliteRow> {
    check_id(bot_id, "bot_id")?;
    sqlx::query(
        "SELECT id, owner_account_id, name, description, privacy_mode, join_groups,
                inline_mode, directory_listed, directory_review, created_at
         FROM bots WHERE id = ? AND owner_account_id = ?",
    )
    .bind(bot_id)
    .bind(owner_account_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("bot not found"))
}

/// POST /v1/bots
pub async fn create(
    State(state): State<AppState>,
    req: Signed<CreateBotReq>,
) -> ApiResult<(StatusCode, Json<BotCreateResp>)> {
    let secret = require_bot_secret(&state)?;
    validate_name(&req.body.name)?;
    validate_description(&req.body.description)?;
    state.rate_device(&req.device.device_id, 3.0)?;

    let id = new_id();
    let bot_account_id = new_id();
    let (token, token_hmac) = new_token(&id, &secret)?;
    let now = now_secs();

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("INSERT INTO accounts (id, created_day) VALUES (?, ?)")
        .bind(&bot_account_id)
        .bind(crate::util::today())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO bots
         (id, owner_account_id, name, description, token_hmac, token_issued_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.device.account_id)
    .bind(req.body.name.trim())
    .bind(req.body.description.trim())
    .bind(&token_hmac[..])
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO bot_identities (bot_id, account_id, created_at)
         VALUES (?, ?, ?)",
    )
    .bind(&id)
    .bind(&bot_account_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let row = sqlx::query(
        "SELECT id, owner_account_id, name, description, privacy_mode, join_groups,
                inline_mode, directory_listed, directory_review, created_at
         FROM bots WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(BotCreateResp {
            bot: row_to_summary(&row)?,
            token,
        }),
    ))
}

/// GET /v1/bots — owner's bots.
pub async fn list(
    State(state): State<AppState>,
    req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<Vec<BotSummary>>> {
    let rows = sqlx::query(
        "SELECT id, owner_account_id, name, description, privacy_mode, join_groups,
                inline_mode, directory_listed, directory_review, created_at
         FROM bots WHERE owner_account_id = ? ORDER BY created_at DESC, id",
    )
    .bind(&req.device.account_id)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(row_to_summary(&row)?);
    }
    Ok(Json(out))
}

/// POST /v1/bots/{bot_id}/token — revoke old token and issue a new one.
pub async fn issue_token(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
    req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<TokenResp>> {
    let secret = require_bot_secret(&state)?;
    state.rate_device(&req.device.device_id, 2.0)?;
    let _ = owner_bot(&state, &req.device.account_id, &bot_id).await?;

    let (token, token_hmac) = new_token(&bot_id, &secret)?;
    let now = now_secs();
    sqlx::query(
        "UPDATE bots
         SET token_hmac = ?, token_issued_at = ?, token_revoked_at = NULL
         WHERE id = ? AND owner_account_id = ?",
    )
    .bind(&token_hmac[..])
    .bind(now)
    .bind(&bot_id)
    .bind(&req.device.account_id)
    .execute(&state.db)
    .await?;

    Ok(Json(TokenResp {
        bot_id,
        token,
        issued_at: now,
    }))
}

/// POST /v1/bots/{bot_id}/revoke — immediately invalidate token.
pub async fn revoke_token(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
    req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = owner_bot(&state, &req.device.account_id, &bot_id).await?;
    let now = now_secs();
    sqlx::query(
        "UPDATE bots
         SET token_hmac = NULL, token_revoked_at = ?
         WHERE id = ? AND owner_account_id = ?",
    )
    .bind(now)
    .bind(&bot_id)
    .bind(&req.device.account_id)
    .execute(&state.db)
    .await?;
    Ok(Json(serde_json::json!({"revoked": true, "bot_id": bot_id})))
}

/// DELETE /v1/bots/{bot_id}
pub async fn delete(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
    req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = owner_bot(&state, &req.device.account_id, &bot_id).await?;
    let bot_account_id: String = sqlx::query(
        "SELECT account_id FROM bot_identities WHERE bot_id = ?",
    )
    .bind(&bot_id)
    .fetch_one(&state.db)
    .await?
    .try_get("account_id")?;

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("DELETE FROM bots WHERE id = ? AND owner_account_id = ?")
        .bind(&bot_id)
        .bind(&req.device.account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM accounts WHERE id = ?")
        .bind(&bot_account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({"deleted": true, "bot_id": bot_id})))
}

/// PATCH /v1/bots/{bot_id}
pub async fn update_metadata(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
    req: Signed<MetadataReq>,
) -> ApiResult<Json<BotSummary>> {
    let _ = owner_bot(&state, &req.device.account_id, &bot_id).await?;
    if let Some(name) = &req.body.name {
        validate_name(name)?;
    }
    if let Some(description) = &req.body.description {
        validate_description(description)?;
    }
    let row = owner_bot(&state, &req.device.account_id, &bot_id).await?;
    let current_name: String = row.try_get("name")?;
    let current_description: String = row.try_get("description")?;
    let name = req.body.name.as_deref().unwrap_or(&current_name).trim();
    let description = req.body.description.as_deref().unwrap_or(&current_description).trim();

    sqlx::query(
        "UPDATE bots SET name = ?, description = ?
         WHERE id = ? AND owner_account_id = ?",
    )
    .bind(name)
    .bind(description)
    .bind(&bot_id)
    .bind(&req.device.account_id)
    .execute(&state.db)
    .await?;

    let row = owner_bot(&state, &req.device.account_id, &bot_id).await?;
    Ok(Json(row_to_summary(&row)?))
}

fn feature_column(feature: &str) -> Option<&'static str> {
    match feature {
        "bot.privacy_mode" => Some("privacy_mode"),
        "bot.join_groups" => Some("join_groups"),
        "bot.inline" => Some("inline_mode"),
        "bot.directory" => Some("directory_listed"),
        "bot.payments" => None,
        "bot.tips" => None,
        _ => None,
    }
}

/// Common bot feature state mutation.
async fn set_feature(
    state: &AppState,
    account_id: &str,
    bot_id: &str,
    feature: &str,
    value: bool,
) -> ApiResult<Json<FeatureResp>> {
    let _ = owner_bot(state, account_id, bot_id).await?;
    let column = match feature_column(feature) {
        Some(c) => c,
        None if feature == "bot.payments" || feature == "bot.tips" => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "NOT_AVAILABLE",
                "payments and tips are reserved for a later release stage",
            ))
        }
        None => return Err(ApiError::not_found("unknown bot feature")),
    };

    if feature == "bot.directory" && value {
        let reviewed: String = sqlx::query("SELECT directory_review FROM bots WHERE id = ?")
            .bind(bot_id)
            .fetch_one(&state.db)
            .await?
            .try_get("directory_review")?;
        if reviewed != "approved" {
            return Err(ApiError::conflict(
                "DIRECTORY_REVIEW_REQUIRED",
                "bot directory listing requires operator approval",
            ));
        }
    }

    let sql = match column {
        "privacy_mode" => "UPDATE bots SET privacy_mode = ? WHERE id = ? AND owner_account_id = ?",
        "join_groups" => "UPDATE bots SET join_groups = ? WHERE id = ? AND owner_account_id = ?",
        "inline_mode" => "UPDATE bots SET inline_mode = ? WHERE id = ? AND owner_account_id = ?",
        "directory_listed" => "UPDATE bots SET directory_listed = ? WHERE id = ? AND owner_account_id = ?",
        _ => return Err(ApiError::not_found("unknown bot feature")),
    };
    sqlx::query(sql)
        .bind(i64::from(value))
        .bind(bot_id)
        .bind(account_id)
        .execute(&state.db)
        .await?;

    Ok(Json(FeatureResp {
        bot_id: bot_id.to_owned(),
        feature: feature.to_owned(),
        state: value,
    }))
}

#[derive(Deserialize)]
pub struct GatewayDeviceReq {
    pub auth_pub: String,
}
json_body!(GatewayDeviceReq, |_cfg| 1024);

#[derive(Serialize)]
pub struct GatewayDeviceResp {
    pub bot_id: String,
    pub account_id: String,
    pub device_id: String,
}

/// POST /v1/bot/register-device
///
/// The bot token authenticates the gateway. A fresh Ed25519 public key becomes
/// the bot's gateway device; the private key remains only with the developer's
/// gateway.
pub async fn register_gateway_device(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> ApiResult<(StatusCode, Json<GatewayDeviceResp>)> {
    let headers = req.headers().clone();
    let identity = authenticate_token(&state, &headers).await?;
    let bytes = crate::auth::read_body(req, 2048).await?.1;
    let body: GatewayDeviceReq = crate::auth::parse_json(&bytes)?;
    let (_key, raw) = crate::auth::parse_public_key(&body.auth_pub)?;

    if let Some(existing) = &identity.gateway_device_id {
        return Ok((
            StatusCode::OK,
            Json(GatewayDeviceResp {
                bot_id: identity.id,
                account_id: identity.account_id,
                device_id: existing.clone(),
            }),
        ));
    }

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    if let Some(existing): Option<String> = sqlx::query_scalar(
        "SELECT gateway_device_id FROM bot_identities WHERE bot_id = ?",
    )
    .bind(&identity.id)
    .fetch_one(&mut *tx)
    .await? {
        return Ok((
            StatusCode::OK,
            Json(GatewayDeviceResp {
                bot_id: identity.id,
                account_id: identity.account_id,
                device_id: existing,
            }),
        ));
    }
    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM devices WHERE account_id = ?")
        .bind(&identity.account_id)
        .fetch_one(&mut *tx)
        .await?
        .try_get("n")?;
    if count >= state.cfg.max_devices_per_account as i64 {
        return Err(ApiError::limit_exceeded("device limit reached"));
    }
    let account = identity.account_id.clone();
    let device_id = crate::util::new_id();
    sqlx::query(
        "INSERT INTO devices (id, account_id, auth_pub, created_day)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&device_id)
    .bind(&account)
    .bind(&raw[..])
    .bind(crate::util::today())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE bot_identities SET gateway_device_id = ? WHERE bot_id = ?",
    )
    .bind(&device_id)
    .bind(&identity.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(GatewayDeviceResp {
            bot_id: identity.id,
            account_id: account,
            device_id,
        }),
    ))
}

/// POST /v1/bot/getMe
pub async fn get_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<BotSummary>> {
    let identity = authenticate_token(&state, &headers).await?;
    let row = sqlx::query(
        "SELECT id, owner_account_id, name, description, privacy_mode, join_groups,
                inline_mode, directory_listed, directory_review, created_at
         FROM bots WHERE id = ?",
    )
    .bind(&identity.id)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(row_to_summary(&row)?))
}

/// GET /v1/bot/commands
pub async fn bot_commands(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<CommandsResp>> {
    let identity = authenticate_token(&state, &headers).await?;
    let row = sqlx::query("SELECT commands_json FROM bot_commands WHERE bot_id = ?")
        .bind(&identity.id)
        .fetch_optional(&state.db)
        .await?;
    let commands = match row {
        None => Vec::new(),
        Some(row) => {
            let encoded: String = row.try_get("commands_json")?;
            serde_json::from_str(&encoded).map_err(|_| ApiError::internal())?
        }
    };
    Ok(Json(CommandsResp { commands }))
}

/// POST /v1/bots/{bot_id}/features/{feature}/apply
pub async fn feature_apply(
    State(state): State<AppState>,
    Path((bot_id, feature)): Path<(String, String)>,
    req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<FeatureResp>> {
    set_feature(&state, &req.device.account_id, &bot_id, &feature, true).await
}

/// POST /v1/bots/{bot_id}/features/{feature}/release
pub async fn feature_release(
    State(state): State<AppState>,
    Path((bot_id, feature)): Path<(String, String)>,
    req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<FeatureResp>> {
    set_feature(&state, &req.device.account_id, &bot_id, &feature, false).await
}

/// PUT /v1/bots/{bot_id}/commands
pub async fn set_commands(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
    req: Signed<CommandsReq>,
) -> ApiResult<Json<CommandsResp>> {
    let _ = owner_bot(&state, &req.device.account_id, &bot_id).await?;
    if req.body.commands.len() > MAX_COMMANDS {
        return Err(ApiError::too_large("too many bot commands"));
    }
    for cmd in &req.body.commands {
        if cmd.command.is_empty()
            || cmd.command.len() > MAX_COMMAND_NAME
            || !cmd
                .command
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(ApiError::bad_request("invalid bot command name"));
        }
        if cmd.description.len() > MAX_COMMAND_DESC
            || cmd.description.chars().any(char::is_control)
        {
            return Err(ApiError::bad_request("invalid bot command description"));
        }
    }
    let encoded = serde_json::to_string(&req.body.commands).map_err(|_| ApiError::internal())?;

    sqlx::query(
        "INSERT INTO bot_commands(bot_id, commands_json) VALUES (?, ?)
         ON CONFLICT(bot_id) DO UPDATE SET commands_json = excluded.commands_json",
    )
    .bind(&bot_id)
    .bind(encoded)
    .execute(&state.db)
    .await?;

    Ok(Json(CommandsResp {
        commands: req.body.commands,
    }))
}

/// GET /v1/bots/{bot_id}/commands
pub async fn get_commands(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
    req: Signed<crate::auth::NoBody>,
) -> ApiResult<Json<CommandsResp>> {
    let _ = owner_bot(&state, &req.device.account_id, &bot_id).await?;
    let row = sqlx::query("SELECT commands_json FROM bot_commands WHERE bot_id = ?")
        .bind(&bot_id)
        .fetch_optional(&state.db)
        .await?;
    let commands = match row {
        None => Vec::new(),
        Some(row) => {
            let encoded: String = row.try_get("commands_json")?;
            serde_json::from_str(&encoded).map_err(|_| ApiError::internal())?
        }
    };
    Ok(Json(CommandsResp { commands }))
}

/// Authenticate a bot gateway request. Tokens are accepted only via
/// Authorization: Bot <token>; URL paths must never contain token material.
pub async fn authenticate_token(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<BotIdentity> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("bot token required"))?;
    let token = auth
        .strip_prefix("Bot ")
        .ok_or_else(|| ApiError::unauthorized("bot authorization must use Bot scheme"))?;
    let secret = require_bot_secret(state)?;
    let prefix = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| ApiError::unauthorized("invalid bot token"))?;
    let (bot_id, suffix) = prefix
        .split_once('_')
        .ok_or_else(|| ApiError::unauthorized("invalid bot token"))?;
    check_id(bot_id, "bot id")?;
    let raw_suffix = URL_SAFE_NO_PAD
        .decode(suffix)
        .map_err(|_| ApiError::unauthorized("invalid bot token"))?;
    if raw_suffix.len() != 32 {
        return Err(ApiError::unauthorized("invalid bot token"));
    }
    let row = sqlx::query(
        "SELECT b.token_hmac, bi.account_id, bi.gateway_device_id
         FROM bots b JOIN bot_identities bi ON bi.bot_id = b.id
         WHERE b.id = ?",
    )
    .bind(bot_id)
    .fetch_optional(&state.db)
    .await?;
    let row = row.ok_or_else(|| ApiError::unauthorized("invalid bot token"))?;
    let stored: Option<Vec<u8>> = row.try_get("token_hmac")?;
    let account_id: String = row.try_get("account_id")?;
    let gateway_device_id: Option<String> = row.try_get("gateway_device_id")?;
    let stored = stored.ok_or_else(|| ApiError::unauthorized("invalid bot token"))?;
    let expected = token_hmac(&secret, token.as_bytes())?;
    if expected.len() != stored.len() || subtle::ConstantTimeEq::ct_eq(expected.as_slice(), stored.as_slice()).unwrap_u8() != 1 {
        return Err(ApiError::unauthorized("invalid bot token"));
    }
    Ok(BotIdentity {
        id: bot_id.to_owned(),
        account_id,
        gateway_device_id,
    })
}

#[derive(Clone, Debug)]
pub struct BotIdentity {
    pub id: String,
    pub account_id: String,
    pub gateway_device_id: Option<String>,
}
