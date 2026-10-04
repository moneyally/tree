//! Bot platform (PROTOCOL.md 8.16): the server's part of the bot factory.
//!
//! Tree does not run bots. A person (an existing human account, the owner)
//! creates a bot account here, gets its token once, and runs a bot gateway
//! on their own server. The gateway registers one device for the bot with
//! the token and a proof that it holds the device key; from then on that
//! device is an ordinary device of the bot account (MLS member, mailbox,
//! signed requests), so groups with bots stay end-to-end encrypted.
//!
//! * Creating a bot costs what a human signup costs: the same proof of
//!   work (bits, under its own label so a signup's proof cannot be reused),
//!   the same per-address signup budget, `server.signups` must be applied,
//!   and new or reported accounts are refused. An owner has at most
//!   `MAX_BOTS_PER_OWNER` bots.
//! * The token is `<bot account id>:<32 random bytes, base64url>`. It is
//!   shown once; the server keeps only `HMAC-SHA-256(key, label || bot id ||
//!   secret)` under the bot token key (`BOT_TOKEN_KEY`, or a random key kept
//!   in the database). Checks are constant time.
//! * Rotating or revoking the token takes effect at once: the token
//!   generation moves on, every gateway device registered under the old
//!   one stops authenticating (its open long-poll is woken and answered
//!   `401`), and its key packages are deleted so nobody can add it any more.
//!   The gateway registers again with the new token and the same device key
//!   (same device id, its mailbox kept); a device somebody registered with a
//!   stolen token is deleted then.
//! * One gateway device per bot: a registration removes every other device
//!   of the bot. Somebody with a stolen token can take the bot over until
//!   the owner rotates the token, but not silently: the owner's gateway is
//!   cut off at once.
//! * A bot reaches only people who contacted it (claimed its key packages,
//!   that is started a chat with it or added it to a group) and the devices
//!   of groups it is in: it cannot claim anyone else's key packages, and
//!   its sends to other devices are refused (`refused_devices`).
//! * Messages sent by a bot's device carry the bot's account id in the
//!   mailbox (`bot`), so every receiver labels the sender as a bot whatever
//!   it claims inside the group. People's messages never carry a sender.
//! * Bots have no recovery key, device links, @username of the person kind
//!   or account deletion of their own (`NOT_FOR_BOTS`); never a phone number
//!   (Tree has none).
//! * `server.bot_platform` released (the default): every endpoint here, the
//!   requests of every bot device and claims of bots' key packages are
//!   refused with `LOCKED_BY_SERVER`.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Mutex;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::Signature;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use subtle::ConstantTimeEq;

use crate::auth::{parse_json, parse_public_key, NoBody, Signed};
use crate::error::{ApiError, ApiResult};
use crate::features::{is_applied, BOT_PLATFORM, SIGNUPS};
use crate::util::{b64, check_id, is_valid_id, new_id, now_secs, random_bytes, today, unb64};
use crate::{json_body, AppState};

/// Label of the token HMAC.
pub const TOKEN_LABEL: &[u8] = b"tree/bot-token/v1";
/// Label of the gateway's proof of possession.
pub const GATEWAY_LABEL: &[u8] = b"tree/bot-gateway/v1";
/// Label of the proof of work for a new bot (the signup's, relabelled).
pub const POW_CONTEXT: &[u8] = b"tree-bot-signup-v1";
/// A registration challenge is good this long, once.
pub const CHALLENGE_SECS: i64 = 120;
const MAX_CHALLENGES: usize = 10_000;
pub const MAX_DESCRIPTION: usize = 512;
pub const MAX_COMMANDS: usize = 100;
pub const MAX_COMMAND: usize = 32;
pub const MAX_COMMAND_DESCRIPTION: usize = 256;
pub const MAX_LOOKUP_ACCOUNTS: usize = 256;
const DIRECTORY_MAX: i64 = 50;

/// Bot features the server keeps, with their default, and the money
/// features that are permanently released (the same table as
/// `tree_core::features`, checked by a test).
pub const BOT_FEATURES: &[(&str, bool, Option<&str>)] = &[
    ("bot.privacy_mode", true, None),
    ("bot.join_groups", true, None),
    ("bot.inline", false, None),
    ("bot.directory", false, None),
    ("bot.pay_out_points", false, Some("bots can receive points but never pay them out")),
    ("bot.payments", false, Some("bot payments wait for stage 4: identity verification and legal review")),
    ("bot.tips", false, Some("tips to bots wait for stage 4: identity verification and legal review")),
];

type HmacSha256 = Hmac<Sha256>;

/// Open registration challenges: challenge -> (bot account, expiry). Memory
/// only; a restart simply asks the gateway for a new one.
#[derive(Default)]
pub struct Challenges(Mutex<HashMap<[u8; 32], (String, i64)>>);

impl Challenges {
    fn issue(&self, bot: &str, now: i64) -> ApiResult<[u8; 32]> {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= MAX_CHALLENGES {
            m.retain(|_, (_, exp)| *exp >= now);
            if m.len() >= MAX_CHALLENGES {
                return Err(ApiError::rate_limited(CHALLENGE_SECS as u64));
            }
        }
        let c: [u8; 32] = random_bytes();
        m.insert(c, (bot.to_string(), now + CHALLENGE_SECS));
        Ok(c)
    }

    /// Takes the challenge if it was issued to `bot` and is still good.
    fn take(&self, c: &[u8; 32], bot: &str, now: i64) -> bool {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match m.remove(c) {
            Some((b, exp)) => b == bot && exp >= now,
            None => false,
        }
    }

    pub fn prune(&self, now: i64) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, (_, exp)| *exp >= now);
    }
}

/// `403 LOCKED_BY_SERVER` unless the operator applied `server.bot_platform`.
pub async fn platform_on(state: &AppState) -> ApiResult<()> {
    if is_applied(&state.db, BOT_PLATFORM).await? {
        Ok(())
    } else {
        Err(ApiError::forbidden("LOCKED_BY_SERVER", "the bot platform is released by the operator"))
    }
}

/// SHA-256(POW_CONTEXT || key || nonce, 8 bytes big-endian).
pub fn pow_hash(key: &[u8; 32], nonce: u64) -> [u8; 32] {
    Sha256::new().chain_update(POW_CONTEXT).chain_update(key).chain_update(nonce.to_be_bytes()).finalize().into()
}

pub fn pow_ok(key: &[u8; 32], nonce: u64, bits: u32) -> bool {
    crate::accounts::leading_zero_bits(&pow_hash(key, nonce)) >= bits
}

/// A bot's @username: as a person's (a-z, 0-9, _, starting with a letter),
/// 5 to 32 characters, ending in `bot`. Returns it normalised.
pub fn normalise_username(name: &str) -> Result<String, &'static str> {
    let n = name.trim().trim_start_matches('@').to_ascii_lowercase();
    if !(5..=32).contains(&n.len()) {
        return Err("a bot's username has 5 to 32 characters");
    }
    if !n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return Err("a bot's username uses only letters a-z, digits and _");
    }
    if !n.as_bytes()[0].is_ascii_lowercase() {
        return Err("a bot's username starts with a letter");
    }
    if !n.ends_with("bot") {
        return Err("a bot's username ends with bot");
    }
    Ok(n)
}

/// The hash people's @usernames are stored under (PROTOCOL.md 8.4).
pub fn username_hash(n: &str) -> [u8; 32] {
    Sha256::new().chain_update(b"tree/username/v1").chain_update(n.as_bytes()).finalize().into()
}

/// The HMAC kept for a token.
pub fn token_mac(key: &[u8; 32], bot: &str, secret: &[u8; 32]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(TOKEN_LABEL);
    m.update(&(bot.len() as u32).to_be_bytes());
    m.update(bot.as_bytes());
    m.update(secret);
    m.finalize().into_bytes().into()
}

/// `<bot id>:<secret>`, or `None` if it is not one.
pub fn parse_token(t: &str) -> Option<(String, [u8; 32])> {
    let (bot, secret) = t.trim().split_once(':')?;
    if !is_valid_id(bot) || secret.len() != 43 {
        return None;
    }
    let s: [u8; 32] = URL_SAFE_NO_PAD.decode(secret).ok()?.try_into().ok()?;
    Some((bot.to_string(), s))
}

fn new_token(bot: &str) -> (String, [u8; 32]) {
    let secret: [u8; 32] = random_bytes();
    (format!("{bot}:{}", URL_SAFE_NO_PAD.encode(secret)), secret)
}

/// The bot token key: configured, or created in the database on first use.
async fn token_key(state: &AppState) -> ApiResult<[u8; 32]> {
    if let Some(k) = &state.cfg.bot_token_key {
        return Ok(k.0);
    }
    Ok(*state.bot_key.get_or_try_init(|| stored_key(&state.db)).await?)
}

async fn stored_key(db: &SqlitePool) -> Result<[u8; 32], sqlx::Error> {
    let k: [u8; 32] = random_bytes();
    sqlx::query("INSERT OR IGNORE INTO server_secrets (name, value) VALUES ('bot_token', ?)").bind(k.as_slice()).execute(db).await?;
    let v: Vec<u8> = sqlx::query("SELECT value FROM server_secrets WHERE name = 'bot_token'").fetch_one(db).await?.try_get("value")?;
    v.as_slice().try_into().map_err(|_| sqlx::Error::Protocol("the stored bot token key is damaged".into()))
}

/// One bot as stored.
#[derive(Debug, Clone)]
pub struct Bot {
    pub account: String,
    pub owner: String,
    pub username: String,
    pub description: String,
    pub commands: Value,
    pub token_mac: Option<Vec<u8>>,
    pub token_gen: i64,
    pub privacy_mode: bool,
    pub join_groups: bool,
    pub inline: bool,
    pub directory: bool,
    pub created_day: i64,
}

const BOT_COLS: &str = "account_id, owner_account, username, description, commands, token_mac, token_gen, privacy_mode, join_groups, inline, directory, created_day";

fn bot_of(r: &sqlx::sqlite::SqliteRow) -> Result<Bot, sqlx::Error> {
    let commands: String = r.try_get("commands")?;
    Ok(Bot {
        account: r.try_get("account_id")?,
        owner: r.try_get("owner_account")?,
        username: r.try_get("username")?,
        description: r.try_get("description")?,
        commands: serde_json::from_str(&commands).unwrap_or(json!([])),
        token_mac: r.try_get("token_mac")?,
        token_gen: r.try_get("token_gen")?,
        privacy_mode: r.try_get("privacy_mode")?,
        join_groups: r.try_get("join_groups")?,
        inline: r.try_get("inline")?,
        directory: r.try_get("directory")?,
        created_day: r.try_get("created_day")?,
    })
}

pub async fn load(db: impl sqlx::SqliteExecutor<'_>, account: &str) -> Result<Option<Bot>, sqlx::Error> {
    let q = sqlx::AssertSqlSafe(format!("SELECT {BOT_COLS} FROM bots WHERE account_id = ?"));
    sqlx::query(q).bind(account).fetch_optional(db).await?.as_ref().map(bot_of).transpose()
}

/// Whether `account` is a bot.
pub async fn is_bot(db: &SqlitePool, account: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM bots WHERE account_id = ?").bind(account).fetch_optional(db).await?.is_some())
}

/// Whether a gateway device is still registered under its bot's token.
pub async fn device_active(db: &SqlitePool, device: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 FROM bot_devices bd JOIN bots b ON b.account_id = bd.bot_account \
         WHERE bd.device_id = ? AND bd.token_gen = b.token_gen AND b.token_mac IS NOT NULL",
    )
    .bind(device)
    .fetch_optional(db)
    .await?
    .is_some())
}

fn feature_states(b: &Bot) -> Vec<Value> {
    BOT_FEATURES
        .iter()
        .map(|(key, _, lock)| {
            let applied = match *key {
                "bot.privacy_mode" => b.privacy_mode,
                "bot.join_groups" => b.join_groups,
                "bot.inline" => b.inline,
                "bot.directory" => b.directory,
                _ => false,
            };
            json!({ "key": key, "state": if applied { "applied" } else { "released" }, "locked": lock })
        })
        .collect()
}

/// What anyone may know about a bot (never its owner or token).
pub fn public_json(b: &Bot) -> Value {
    json!({
        "account": b.account,
        "username": b.username,
        "is_bot": true,
        "description": b.description,
        "commands": b.commands,
        "privacy_mode": b.privacy_mode,
        "join_groups": b.join_groups,
        "inline": b.inline,
        "directory": b.directory,
    })
}

/// The owner's view: also the token state, the gateway device, the number
/// of people who contacted it, and open reports about it.
async fn owner_json(state: &AppState, b: &Bot) -> ApiResult<Value> {
    let devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bot_devices bd WHERE bd.bot_account = ? AND bd.token_gen = ?")
        .bind(&b.account)
        .bind(b.token_gen)
        .fetch_one(&state.db)
        .await?;
    let contacts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bot_contacts WHERE bot_account = ?").bind(&b.account).fetch_one(&state.db).await?;
    let reports: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports WHERE reported_account = ? AND resolved = 0")
        .bind(&b.account)
        .fetch_one(&state.db)
        .await?;
    let mut v = public_json(b);
    v["owner"] = json!(b.owner);
    v["token_active"] = json!(b.token_mac.is_some());
    v["gateway_devices"] = json!(if b.token_mac.is_some() { devices } else { 0 });
    v["contacts"] = json!(contacts);
    v["reports_open"] = json!(reports);
    v["features"] = json!(feature_states(b));
    v["created_day"] = json!(b.created_day);
    Ok(v)
}

/// The caller's own bot `id`, or `404`.
async fn owned(state: &AppState, id: &str, account: &str) -> ApiResult<Bot> {
    check_id(id, "bot id")?;
    match load(&state.db, id).await? {
        Some(b) if b.owner == account => Ok(b),
        _ => Err(ApiError::not_found("no such bot of yours")),
    }
}

// ---------------------------------------------------------------------------
// The factory (the owner's requests)

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReq {
    pub username: String,
    /// 32 random bytes (base64) the proof of work is over; used once.
    pub pow_key: String,
    pub pow_nonce: u64,
}
json_body!(CreateReq, |_cfg| 1024);

/// `POST /v1/bots` — a person creates a bot. `201 {bot, token}`; the token
/// is in this answer only.
pub async fn create(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    req: Signed<CreateReq>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    platform_on(&state).await?;
    req.device.refuse_bot()?;
    if !is_applied(&state.db, SIGNUPS).await? {
        return Err(ApiError::forbidden("LOCKED_BY_SERVER", "new signups are released by the operator"));
    }
    // New or reported accounts (anti-spam limits) do not create bots.
    if req.device.max_fanout < state.cfg.max_recipients {
        return Err(ApiError::forbidden("LIMITED", "this account cannot create bots for now"));
    }
    // The same per-address budget as a signup.
    state.rate_signup(state.client_ip(&headers, peer))?;
    let r = &req.body;
    let username = normalise_username(&r.username).map_err(ApiError::bad_request)?;
    let key: [u8; 32] = unb64(&r.pow_key, "pow_key")?.try_into().map_err(|_| ApiError::bad_request("pow_key must be 32 bytes"))?;
    if !pow_ok(&key, r.pow_nonce, state.cfg.pow_bits) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "POW_INVALID",
            format!("proof-of-work needs {} leading zero bits", state.cfg.pow_bits),
        ));
    }
    let owner = &req.device.account_id;
    let account = new_id();
    let (token, secret) = new_token(&account);
    let mac = token_mac(&token_key(&state).await?, &account, &secret);
    let hash = username_hash(&username);
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bots WHERE owner_account = ?").bind(owner).fetch_one(&mut *tx).await?;
    if n >= state.cfg.max_bots_per_owner as i64 {
        return Err(ApiError::limit_exceeded(format!("an account owns at most {} bots", state.cfg.max_bots_per_owner)));
    }
    let person = sqlx::query("SELECT 1 FROM usernames WHERE hash = ?").bind(hash.as_slice()).fetch_optional(&mut *tx).await?;
    if person.is_some() {
        return Err(ApiError::conflict("USERNAME_TAKEN", "this username is taken"));
    }
    let used = sqlx::query("INSERT INTO bot_pow (key, day) VALUES (?, ?)").bind(key.as_slice()).bind(today()).execute(&mut *tx).await;
    if let Err(e) = used {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "POW_INVALID", "this proof of work was used already"));
        }
        return Err(e.into());
    }
    sqlx::query("INSERT INTO accounts (id, created_day) VALUES (?, ?)").bind(&account).bind(today()).execute(&mut *tx).await?;
    let ins = sqlx::query(
        "INSERT INTO bots (account_id, owner_account, username, username_hash, token_mac, created_day) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&account)
    .bind(owner)
    .bind(&username)
    .bind(hash.as_slice())
    .bind(mac.as_slice())
    .bind(today())
    .execute(&mut *tx)
    .await;
    match ins {
        Err(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()) => {
            return Err(ApiError::conflict("USERNAME_TAKEN", "this username is taken"));
        }
        r => {
            r?;
        }
    }
    tx.commit().await?;
    let b = load(&state.db, &account).await?.ok_or_else(ApiError::internal)?;
    Ok((StatusCode::CREATED, Json(json!({ "bot": owner_json(&state, &b).await?, "token": token }))))
}

/// `GET /v1/bots` — the caller's bots.
pub async fn mine(State(state): State<AppState>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    platform_on(&state).await?;
    req.device.refuse_bot()?;
    let q = sqlx::AssertSqlSafe(format!("SELECT {BOT_COLS} FROM bots WHERE owner_account = ? ORDER BY username"));
    let rows = sqlx::query(q).bind(&req.device.account_id).fetch_all(&state.db).await?;
    let mut out = Vec::new();
    for r in &rows {
        out.push(owner_json(&state, &bot_of(r)?).await?);
    }
    Ok(Json(json!({ "bots": out })))
}

/// `GET /v1/bots/{id}` — the owner's view for the owner, the public view
/// for everyone else.
pub async fn get(State(state): State<AppState>, Path(id): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    platform_on(&state).await?;
    check_id(&id, "bot id")?;
    let b = load(&state.db, &id).await?.ok_or_else(|| ApiError::not_found("no such bot"))?;
    if b.owner == req.device.account_id {
        return Ok(Json(owner_json(&state, &b).await?));
    }
    Ok(Json(public_json(&b)))
}

/// `DELETE /v1/bots/{id}` — the owner deletes the bot: its account, gateway
/// device, mailbox and contacts.
pub async fn delete(State(state): State<AppState>, Path(id): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    platform_on(&state).await?;
    let b = owned(&state, &id, &req.device.account_id).await?;
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let devices: Vec<String> = sqlx::query_scalar("SELECT id FROM devices WHERE account_id = ?").bind(&b.account).fetch_all(&mut *tx).await?;
    sqlx::query("DELETE FROM accounts WHERE id = ?").bind(&b.account).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM blobs WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.blob_id = blobs.id)").execute(&mut *tx).await?;
    tx.commit().await?;
    for d in &devices {
        state.wake(d);
    }
    Ok(Json(json!({ "deleted": b.account })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub command: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileReq {
    pub description: Option<String>,
    pub commands: Option<Vec<Command>>,
}
json_body!(ProfileReq, |_cfg| 64 * 1024);

fn printable(s: &str, max: usize, lines: bool) -> bool {
    s.chars().count() <= max && !s.chars().any(|c| c.is_control() && !(lines && c == '\n'))
}

/// `PUT /v1/bots/{id}/profile` — description and command list (shown to
/// everyone, plaintext).
pub async fn profile(State(state): State<AppState>, Path(id): Path<String>, req: Signed<ProfileReq>) -> ApiResult<Json<Value>> {
    platform_on(&state).await?;
    let b = owned(&state, &id, &req.device.account_id).await?;
    if let Some(d) = &req.body.description {
        if !printable(d, MAX_DESCRIPTION, true) {
            return Err(ApiError::bad_request(format!("a description has at most {MAX_DESCRIPTION} characters")));
        }
        sqlx::query("UPDATE bots SET description = ? WHERE account_id = ?").bind(d.trim()).bind(&b.account).execute(&state.db).await?;
    }
    if let Some(cs) = &req.body.commands {
        if cs.len() > MAX_COMMANDS {
            return Err(ApiError::bad_request(format!("at most {MAX_COMMANDS} commands")));
        }
        let mut list = Vec::new();
        for c in cs {
            let name = c.command.trim().trim_start_matches('/').to_ascii_lowercase();
            let ok = (1..=MAX_COMMAND).contains(&name.len()) && name.bytes().all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || x == b'_');
            if !ok || !printable(&c.description, MAX_COMMAND_DESCRIPTION, false) {
                return Err(ApiError::bad_request(format!(
                    "a command is 1 to {MAX_COMMAND} of a-z, 0-9, _ with a description of at most {MAX_COMMAND_DESCRIPTION} characters"
                )));
            }
            list.push(json!({ "command": name, "description": c.description.trim() }));
        }
        sqlx::query("UPDATE bots SET commands = ? WHERE account_id = ?")
            .bind(Value::Array(list).to_string())
            .bind(&b.account)
            .execute(&state.db)
            .await?;
    }
    let b = load(&state.db, &b.account).await?.ok_or_else(ApiError::internal)?;
    Ok(Json(owner_json(&state, &b).await?))
}

/// `POST /v1/bots/{id}/features/{key}/apply|release` — the owner sets a bot
/// feature. Idempotent; returns the bot. The money features can never be
/// applied (`RELEASED_ALWAYS`).
pub async fn feature(
    State(state): State<AppState>,
    Path((id, key, action)): Path<(String, String, String)>,
    req: Signed<NoBody>,
) -> ApiResult<Json<Value>> {
    platform_on(&state).await?;
    let apply = match action.as_str() {
        "apply" => true,
        "release" => false,
        _ => return Err(ApiError::not_found("no such endpoint")),
    };
    let b = owned(&state, &id, &req.device.account_id).await?;
    let Some((_, _, lock)) = BOT_FEATURES.iter().find(|(k, _, _)| *k == key) else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "UNKNOWN_FEATURE", "unknown bot feature").with("key", json!(key)));
    };
    if let Some(reason) = lock {
        if apply {
            return Err(ApiError::forbidden("RELEASED_ALWAYS", *reason));
        }
        return Ok(Json(owner_json(&state, &b).await?));
    }
    let q = match key.as_str() {
        "bot.privacy_mode" => "UPDATE bots SET privacy_mode = ? WHERE account_id = ?",
        "bot.join_groups" => "UPDATE bots SET join_groups = ? WHERE account_id = ?",
        "bot.inline" => "UPDATE bots SET inline = ? WHERE account_id = ?",
        _ => "UPDATE bots SET directory = ? WHERE account_id = ?",
    };
    sqlx::query(q).bind(apply).bind(&b.account).execute(&state.db).await?;
    let b = load(&state.db, &b.account).await?.ok_or_else(ApiError::internal)?;
    Ok(Json(owner_json(&state, &b).await?))
}

/// `POST /v1/bots/{id}/token/rotate|revoke` — a new token (shown once), or
/// none. Either way the old token and every gateway device registered with
/// it stop working now.
pub async fn token(State(state): State<AppState>, Path((id, action)): Path<(String, String)>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    platform_on(&state).await?;
    let rotate = match action.as_str() {
        "rotate" => true,
        "revoke" => false,
        _ => return Err(ApiError::not_found("no such endpoint")),
    };
    let b = owned(&state, &id, &req.device.account_id).await?;
    let new = if rotate { Some(new_token(&b.account)) } else { None };
    let mac = match &new {
        Some((_, secret)) => Some(token_mac(&token_key(&state).await?, &b.account, secret).to_vec()),
        None => None,
    };
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("UPDATE bots SET token_mac = ?, token_gen = token_gen + 1 WHERE account_id = ?")
        .bind(mac)
        .bind(&b.account)
        .execute(&mut *tx)
        .await?;
    // A cut-off device must not be added to anything any more.
    sqlx::query("DELETE FROM key_packages WHERE device_id IN (SELECT id FROM devices WHERE account_id = ?)").bind(&b.account).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM last_resort_key_packages WHERE device_id IN (SELECT id FROM devices WHERE account_id = ?)")
        .bind(&b.account)
        .execute(&mut *tx)
        .await?;
    let devices: Vec<String> = sqlx::query_scalar("SELECT id FROM devices WHERE account_id = ?").bind(&b.account).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    // Open long-polls end now and are answered 401.
    for d in &devices {
        state.wake(d);
    }
    let b = load(&state.db, &b.account).await?.ok_or_else(ApiError::internal)?;
    let mut v = json!({ "bot": owner_json(&state, &b).await? });
    if let Some((t, _)) = new {
        v["token"] = json!(t);
    }
    Ok(Json(v))
}

/// `POST /v1/bots/{id}/stop` — the caller stops the bot: it can no longer
/// reach the caller outside the groups they share (the apps call this when
/// a person blocks a bot).
pub async fn stop(State(state): State<AppState>, Path(id): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    platform_on(&state).await?;
    check_id(&id, "bot id")?;
    let n = sqlx::query("DELETE FROM bot_contacts WHERE bot_account = ? AND account_id = ?")
        .bind(&id)
        .bind(&req.device.account_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    Ok(Json(json!({ "stopped": n > 0 })))
}

// ---------------------------------------------------------------------------
// Finding bots

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupReq {
    #[serde(default)]
    pub accounts: Vec<String>,
    #[serde(default)]
    pub devices: Vec<String>,
}
json_body!(LookupReq, |cfg| (MAX_LOOKUP_ACCOUNTS + cfg.max_recipients) * 32 + 1024);

/// `POST /v1/bots/lookup` — which of these accounts are bots, and which of
/// these devices are bots' gateway devices. Only bots are named: nothing is
/// said about people's accounts or devices.
pub async fn lookup(State(state): State<AppState>, req: Signed<LookupReq>) -> ApiResult<Json<Value>> {
    platform_on(&state).await?;
    let r = &req.body;
    if r.accounts.len() > MAX_LOOKUP_ACCOUNTS || r.devices.len() > state.cfg.max_recipients {
        return Err(ApiError::too_large("too many ids"));
    }
    for a in r.accounts.iter().chain(&r.devices) {
        check_id(a, "id")?;
    }
    req.device.charge_outreach(&state, ((r.accounts.len() + r.devices.len()) / 100) as f64)?;
    let devices = sqlx::query(
        "SELECT d.id AS device, d.account_id AS bot FROM devices d JOIN bots b ON b.account_id = d.account_id \
         WHERE d.id IN (SELECT value FROM json_each(?))",
    )
    .bind(serde_json::to_string(&r.devices).map_err(|_| ApiError::internal())?)
    .fetch_all(&state.db)
    .await?;
    let mut by_device = BTreeMap::new();
    let mut accounts: Vec<String> = r.accounts.clone();
    for d in &devices {
        let bot: String = d.try_get("bot")?;
        by_device.insert(d.try_get::<String, _>("device")?, bot.clone());
        accounts.push(bot);
    }
    accounts.sort();
    accounts.dedup();
    let q = sqlx::AssertSqlSafe(format!("SELECT {BOT_COLS} FROM bots WHERE account_id IN (SELECT value FROM json_each(?)) ORDER BY account_id"));
    let rows = sqlx::query(q)
        .bind(serde_json::to_string(&accounts).map_err(|_| ApiError::internal())?)
        .fetch_all(&state.db)
        .await?;
    let bots = rows.iter().map(|r| bot_of(r).map(|b| public_json(&b))).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({ "bots": bots, "devices": by_device })))
}

#[derive(Deserialize)]
pub struct DirectoryQuery {
    #[serde(default)]
    pub q: String,
}

/// `GET /v1/bots/directory?q=` — bots whose owners applied `bot.directory`,
/// by username prefix or a word of the description.
pub async fn directory(State(state): State<AppState>, Query(q): Query<DirectoryQuery>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    platform_on(&state).await?;
    req.device.charge_outreach(&state, 4.0)?;
    let needle = q.q.trim().trim_start_matches('@');
    if needle.chars().count() > 64 {
        return Err(ApiError::bad_request("search text too long"));
    }
    let e: String = needle.chars().flat_map(|c| if matches!(c, '%' | '_' | '\\') { vec!['\\', c] } else { vec![c] }).collect();
    let q = sqlx::AssertSqlSafe(format!(
        "SELECT {BOT_COLS} FROM bots WHERE directory = 1 AND token_mac IS NOT NULL \
         AND (username LIKE ?1 ESCAPE '\\' OR description LIKE ?2 ESCAPE '\\') ORDER BY username LIMIT ?3"
    ));
    let rows = sqlx::query(q)
        .bind(format!("{}%", e.to_ascii_lowercase()))
        .bind(format!("%{e}%"))
        .bind(DIRECTORY_MAX)
        .fetch_all(&state.db)
        .await?;
    let bots = rows.iter().map(|r| bot_of(r).map(|b| public_json(&b))).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({ "bots": bots })))
}

/// `GET /v1/bots/by-username/{name}` — a bot by its exact username (listed
/// in the directory or not: a username is like a link).
pub async fn by_username(State(state): State<AppState>, Path(name): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    platform_on(&state).await?;
    req.device.charge_outreach(&state, crate::usernames::LOOKUP_COST)?;
    let n = normalise_username(&name).map_err(ApiError::bad_request)?;
    let q = sqlx::AssertSqlSafe(format!("SELECT {BOT_COLS} FROM bots WHERE username = ?"));
    let row = sqlx::query(q).bind(&n).fetch_optional(&state.db).await?.ok_or_else(|| ApiError::not_found("no such bot"))?;
    Ok(Json(public_json(&bot_of(&row)?)))
}

// ---------------------------------------------------------------------------
// The gateway (bot token)

/// Checks `Authorization: Bearer <token>` and returns the bot (`401
/// BAD_TOKEN` otherwise). Every token check is constant time and charges
/// the bot's rate limit.
async fn bearer(state: &AppState, headers: &HeaderMap) -> ApiResult<Bot> {
    platform_on(state).await?;
    let bad = || ApiError::new(StatusCode::UNAUTHORIZED, "BAD_TOKEN", "the bot token is not valid");
    let t = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(bad)?;
    let (id, secret) = parse_token(t).ok_or_else(bad)?;
    let b = load(&state.db, &id).await?.ok_or_else(bad)?;
    let want = token_mac(&token_key(state).await?, &id, &secret);
    let ok = b.token_mac.as_deref().is_some_and(|m| bool::from(m.ct_eq(&want[..])));
    if !ok {
        return Err(bad());
    }
    state.rate_bot(&b.account, 1.0)?;
    Ok(b)
}

/// Length-prefixed parts (4 bytes big-endian each), as the device link uses.
pub fn lp(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// What the gateway signs with its device key to register:
/// `lp(label, bot account id, challenge, device public key)`.
pub fn gateway_message(bot: &str, challenge: &[u8], auth_pub: &[u8; 32]) -> Vec<u8> {
    lp(&[GATEWAY_LABEL, bot.as_bytes(), challenge, auth_pub])
}

/// `POST /v1/bots/gateway/challenge` (bot token) — a fresh challenge for
/// one registration, good for two minutes.
pub async fn gateway_challenge(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let b = bearer(&state, &headers).await?;
    let now = now_secs();
    let c = state.bot_challenges.issue(&b.account, now)?;
    Ok(Json(json!({ "challenge": b64(&c), "expires_at": now + CHALLENGE_SECS, "account_id": b.account })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterReq {
    auth_pub: String,
    challenge: String,
    /// The device key's signature over [`gateway_message`].
    signature: String,
}

/// `POST /v1/bots/gateway/register` (bot token) — registers the gateway's
/// device, with proof that the gateway holds its key. The same key as
/// before keeps its device id (after a token rotation); any other device of
/// the bot is removed. `201 {account_id, device_id, username}`.
pub async fn gateway_register(State(state): State<AppState>, headers: HeaderMap, body: axum::body::Bytes) -> ApiResult<(StatusCode, Json<Value>)> {
    let b = bearer(&state, &headers).await?;
    if body.len() > 1024 {
        return Err(ApiError::too_large("request body too large"));
    }
    let r: RegisterReq = parse_json(&body)?;
    let challenge: [u8; 32] = unb64(&r.challenge, "challenge")?.try_into().map_err(|_| ApiError::bad_request("challenge must be 32 bytes"))?;
    if !state.bot_challenges.take(&challenge, &b.account, now_secs()) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "CHALLENGE_INVALID", "unknown, used or expired challenge"));
    }
    let (key, raw) = parse_public_key(&r.auth_pub)?;
    let sig: [u8; 64] = unb64(&r.signature, "signature")?.try_into().map_err(|_| ApiError::bad_request("signature must be 64 bytes"))?;
    key.verify_strict(&gateway_message(&b.account, &challenge, &raw), &Signature::from_bytes(&sig))
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "PROOF_INVALID", "the signature does not prove the device key"))?;

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    // The token may have changed since it was checked: check it again under
    // the write lock, and register under the generation it belongs to.
    let now = load(&mut *tx, &b.account).await?.ok_or_else(ApiError::internal)?;
    if now.token_mac != b.token_mac {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "BAD_TOKEN", "the bot token is not valid"));
    }
    let existing: Option<(String, String)> = sqlx::query("SELECT id, account_id FROM devices WHERE auth_pub = ?")
        .bind(&raw[..])
        .fetch_optional(&mut *tx)
        .await?
        .map(|r| Ok::<_, sqlx::Error>((r.try_get("id")?, r.try_get("account_id")?)))
        .transpose()?;
    let device = match existing {
        Some((id, acc)) if acc == b.account => id,
        Some(_) => return Err(ApiError::conflict("ALREADY_EXISTS", "this key is already registered")),
        None => {
            let id = new_id();
            sqlx::query("INSERT INTO devices (id, account_id, auth_pub, created_day) VALUES (?, ?, ?, ?)")
                .bind(&id)
                .bind(&b.account)
                .bind(&raw[..])
                .bind(today())
                .execute(&mut *tx)
                .await?;
            id
        }
    };
    sqlx::query(
        "INSERT INTO bot_devices (device_id, bot_account, token_gen) VALUES (?1, ?2, ?3) \
         ON CONFLICT (device_id) DO UPDATE SET token_gen = ?3",
    )
    .bind(&device)
    .bind(&b.account)
    .bind(now.token_gen)
    .execute(&mut *tx)
    .await?;
    // One gateway device per bot.
    let removed: Vec<String> = sqlx::query_scalar("DELETE FROM devices WHERE account_id = ? AND id <> ? RETURNING id")
        .bind(&b.account)
        .bind(&device)
        .fetch_all(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM blobs WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.blob_id = blobs.id)").execute(&mut *tx).await?;
    tx.commit().await?;
    for d in &removed {
        state.wake(d);
    }
    tracing::info!(target: "tree_server::bots", "gateway device registered");
    Ok((StatusCode::CREATED, Json(json!({ "account_id": b.account, "device_id": device, "username": b.username }))))
}

/// `GET /v1/bots/gateway/me` (bot token) — the bot's public view.
pub async fn gateway_me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let b = bearer(&state, &headers).await?;
    Ok(Json(public_json(&b)))
}

// ---------------------------------------------------------------------------
// Whom a bot may reach

/// Splits `devices` into those the bot may reach and those it may not. A
/// bot reaches its own devices, the devices of people who contacted it, and
/// the devices of groups its device is in (as the server knows them from
/// commits, PROTOCOL.md 7.4).
pub async fn may_reach(db: &SqlitePool, bot: &str, bot_device: &str, devices: &[String]) -> ApiResult<(Vec<String>, Vec<String>)> {
    let mut ok = Vec::new();
    let mut refused = Vec::new();
    for d in devices {
        let allowed: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM devices x WHERE x.id = ?1 AND (x.account_id = ?2 OR x.account_id IN \
               (SELECT account_id FROM bot_contacts WHERE bot_account = ?2))) \
             OR EXISTS (SELECT 1 FROM group_devices a JOIN group_devices b ON a.group_id = b.group_id \
               WHERE a.device_id = ?3 AND b.device_id = ?1)",
        )
        .bind(d)
        .bind(bot)
        .bind(bot_device)
        .fetch_one(db)
        .await?;
        if allowed {
            ok.push(d.clone());
        } else {
            refused.push(d.clone());
        }
    }
    Ok((ok, refused))
}

/// May the bot claim key packages of `account` (start a chat with it, add
/// it to a group)? Only if that person contacted the bot.
pub async fn has_contact(db: &SqlitePool, bot: &str, account: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM bot_contacts WHERE bot_account = ? AND account_id = ?")
        .bind(bot)
        .bind(account)
        .fetch_optional(db)
        .await?
        .is_some())
}

/// A person claimed the bot's key packages: from now on the bot may reach them.
pub async fn note_contact(db: &SqlitePool, bot: &str, account: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO bot_contacts (bot_account, account_id, since_day) VALUES (?, ?, ?)")
        .bind(bot)
        .bind(account)
        .bind(today())
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_end_in_bot() {
        assert_eq!(normalise_username(" @Weather_Bot "), Ok("weather_bot".into()));
        for bad in ["bot", "abot", "weather", "9lifebot", "we-ather_bot", &format!("{}bot", "a".repeat(30))] {
            assert!(normalise_username(bad).is_err(), "{bad}");
        }
        assert_eq!(username_hash("alice"), <[u8; 32]>::from(Sha256::digest(b"tree/username/v1alice")));
    }

    #[test]
    fn tokens_parse_and_bind_the_bot() {
        let bot = new_id();
        let (t, secret) = new_token(&bot);
        assert_eq!(parse_token(&t), Some((bot.clone(), secret)));
        for bad in ["", "x:y", &format!("{bot}:"), &format!("{bot}:{}", "A".repeat(42)), &t.replace(':', "")] {
            assert_eq!(parse_token(bad), None, "{bad}");
        }
        let k = [9u8; 32];
        assert_ne!(token_mac(&k, &bot, &secret), token_mac(&k, &new_id(), &secret), "bound to the bot");
        assert_ne!(token_mac(&k, &bot, &secret), token_mac(&[8; 32], &bot, &secret), "bound to the key");
    }

    #[test]
    fn challenges_are_single_use_and_bound() {
        let c = Challenges::default();
        let x = c.issue("bot1", 100).unwrap();
        assert!(!c.take(&x, "bot2", 100), "another bot's");
        let y = c.issue("bot1", 100).unwrap();
        assert!(c.take(&y, "bot1", 100 + CHALLENGE_SECS));
        assert!(!c.take(&y, "bot1", 100), "used");
        let z = c.issue("bot1", 100).unwrap();
        assert!(!c.take(&z, "bot1", 101 + CHALLENGE_SECS), "expired");
    }

    #[test]
    fn bot_pow_is_not_the_signup_pow() {
        let key = [3u8; 32];
        let n = (0u64..).find(|&n| pow_ok(&key, n, 8)).unwrap();
        assert_ne!(pow_hash(&key, n), crate::accounts::pow_hash(&key, n));
    }
}
