//! Public spaces: public groups and public channels (PROTOCOL.md 8.15).
//!
//! **Not end-to-end encrypted.** A public group (any number of members,
//! everyone posts) or a public channel (admins post, subscribers read and,
//! while `channel.comments` is applied, comment) is stored on the server in
//! plaintext: names, @handles, descriptions, posts, comments, who is
//! subscribed and who posted. The apps label every public space "Public".
//!
//! It is a separate data path. Nothing here touches MLS groups, mailboxes,
//! deliveries or commits, and nothing takes a private group's id: a private
//! group can never become public (`chat.private_to_public` is permanently
//! released, and this API has no way to say "from group X").
//!
//! The whole API is behind the operator flag `server.public_spaces`
//! (released: every endpoint answers `403 LOCKED_BY_SERVER`).
//!
//! Space settings are feature keys with apply and release
//! (`POST /v1/public/spaces/{id}/features/{key}/apply|release`):
//!
//! | Key | Default | Effect |
//! | --- | --- | --- |
//! | `chat.public_listing` | released | the space is in the directory and in search; released: found only by its exact @handle |
//! | `channel.comments` | released | channels: subscribers may comment on posts |
//! | `channel.signatures` | released | channels: the posting admin's account and name are shown with each post |
//! | `chat.slow_mode` | released; option = 10 s to 1 h (default `30s`) | members who are not admins post at most once per interval |
//!
//! New subscribers are woken without content (`push.rs`) at most once per
//! [`crate::Config::public_push_interval_secs`] per space, and only if they
//! applied notifications for that space ([`PublicWakes`]).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::sqlite::SqliteRow;
use sqlx::Row;

use crate::auth::{NoBody, Signed};
use crate::error::{ApiError, ApiResult};
use crate::features::{is_applied, PUBLIC_SPACES};
use crate::util::{check_id, new_id, now_secs, today};
use crate::{json_body, AppState};

/// Longest space name, in characters.
pub const MAX_NAME: usize = 64;
/// Longest description, in characters.
pub const MAX_DESCRIPTION: usize = 1000;
/// Longest post or comment, in characters.
pub const MAX_TEXT: usize = 4096;
/// Longest published author name, in characters.
pub const MAX_AUTHOR_NAME: usize = 64;
/// Longest avatar / attachment reference (opaque to the server), in bytes.
pub const MAX_REF: usize = 512;
/// Spaces one account may own.
pub const MAX_OWNED: i64 = 10;
/// Spaces one account may be subscribed to.
pub const MAX_JOINED: i64 = 1000;
/// Admins per space (the owner included).
pub const MAX_ADMINS: i64 = 50;
/// Posts per page.
pub const PAGE_DEFAULT: i64 = 50;
pub const PAGE_MAX: i64 = 200;
/// Rate-limit tokens (on top of the request's own one, times the account's
/// anti-spam factor).
pub const CREATE_COST: f64 = 20.0;
pub const POST_COST: f64 = 2.0;
pub const SEARCH_COST: f64 = 4.0;
pub const JOIN_COST: f64 = 1.0;

pub const LISTING: &str = "chat.public_listing";
pub const COMMENTS: &str = "channel.comments";
pub const SIGNATURES: &str = "channel.signatures";
pub const SLOW_MODE: &str = "chat.slow_mode";
/// Slow mode bounds and default, as `chat.slow_mode` in the feature registry.
pub const SLOW_MIN: i64 = 10;
pub const SLOW_MAX: i64 = 3600;
pub const SLOW_DEFAULT: i64 = 30;

/// SQL put together from this module's constants only (column lists,
/// fixed filters); every value is a bound parameter.
fn safe(sql: String) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(sql)
}

/// Every endpoint first: the operator flag.
async fn on(state: &AppState) -> ApiResult<()> {
    if !is_applied(&state.db, PUBLIC_SPACES).await? {
        return Err(ApiError::forbidden("LOCKED_BY_SERVER", "public spaces are released by the operator"));
    }
    Ok(())
}

/// Normalises an @handle: trim, drop a leading `@`, ASCII lower case; 5 to
/// 32 characters of `a-z`, `0-9`, `_`, starting with a letter.
pub fn normalise_handle(s: &str) -> Result<String, &'static str> {
    let h = s.trim().trim_start_matches('@').to_ascii_lowercase();
    if !(5..=32).contains(&h.len()) {
        return Err("a handle is 5 to 32 characters");
    }
    if !h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return Err("a handle uses a-z, 0-9 and _ only");
    }
    if !h.as_bytes()[0].is_ascii_lowercase() {
        return Err("a handle starts with a letter");
    }
    Ok(h)
}

/// A text of `1..=max` characters without control characters (line breaks
/// allowed where `lines`).
fn check_text(s: &str, max: usize, lines: bool, what: &str) -> ApiResult<()> {
    let n = s.chars().count();
    if n == 0 || n > max || s.chars().any(|c| c.is_control() && !(lines && c == '\n')) {
        return Err(ApiError::bad_request(format!("{what}: 1 to {max} characters, no control characters")));
    }
    Ok(())
}

fn check_ref(s: &str, what: &str) -> ApiResult<()> {
    if s.is_empty() || s.len() > MAX_REF || s.chars().any(char::is_control) {
        return Err(ApiError::bad_request(format!("{what}: 1 to {MAX_REF} bytes")));
    }
    Ok(())
}

/// Seconds of a slow-mode option (`90`, `30s`, `5m`, `1h`), within bounds.
pub fn slow_seconds(option: Option<&str>) -> Result<i64, &'static str> {
    let Some(o) = option.map(str::trim) else { return Ok(SLOW_DEFAULT) };
    let (num, mul) = match o.chars().last() {
        Some('s') => (&o[..o.len() - 1], 1),
        Some('m') => (&o[..o.len() - 1], 60),
        Some('h') => (&o[..o.len() - 1], 3600),
        _ => (o, 1),
    };
    let ok = !num.is_empty() && num.len() <= 6 && num.bytes().all(|b| b.is_ascii_digit());
    match num.parse::<i64>() {
        Ok(n) if ok && (SLOW_MIN..=SLOW_MAX).contains(&(n * mul)) => Ok(n * mul),
        _ => Err("chat.slow_mode: a duration from 10 to 3600 seconds, e.g. 30s, 5m, 1h"),
    }
}

// ---------------------------------------------------------------------------
// Rows

#[derive(Debug, Clone)]
struct Space {
    id: String,
    kind: String,
    handle: String,
    name: String,
    description: String,
    avatar: Option<String>,
    listed: bool,
    comments: bool,
    signatures: bool,
    slow_mode: i64,
    members: i64,
}

impl Space {
    fn channel(&self) -> bool {
        self.kind == "channel"
    }
}

const SPACE_COLS: &str = "s.id, s.kind, s.handle, s.name, s.description, s.avatar, s.listed, s.comments, s.signatures, s.slow_mode, \
     (SELECT COUNT(*) FROM public_members m WHERE m.space_id = s.id) AS members";

fn space_of(r: &SqliteRow) -> Result<Space, sqlx::Error> {
    Ok(Space {
        id: r.try_get("id")?,
        kind: r.try_get("kind")?,
        handle: r.try_get("handle")?,
        name: r.try_get("name")?,
        description: r.try_get("description")?,
        avatar: r.try_get("avatar")?,
        listed: r.try_get("listed")?,
        comments: r.try_get("comments")?,
        signatures: r.try_get("signatures")?,
        slow_mode: r.try_get("slow_mode")?,
        members: r.try_get("members")?,
    })
}

async fn load(state: &AppState, id: &str) -> ApiResult<Space> {
    check_id(id, "space id")?;
    let r = sqlx::query(safe(format!("SELECT {SPACE_COLS} FROM public_spaces s WHERE s.id = ?")))
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("no such public space"))?;
    Ok(space_of(&r)?)
}

/// The caller's membership: role and notify, if subscribed.
async fn membership(state: &AppState, space: &str, account: &str) -> ApiResult<Option<(String, bool)>> {
    Ok(sqlx::query("SELECT role, notify FROM public_members WHERE space_id = ? AND account_id = ?")
        .bind(space)
        .bind(account)
        .fetch_optional(&state.db)
        .await?
        .map(|r| -> Result<_, sqlx::Error> { Ok((r.try_get("role")?, r.try_get("notify")?)) })
        .transpose()?)
}

async fn banned(state: &AppState, space: &str, account: &str) -> ApiResult<bool> {
    Ok(sqlx::query("SELECT 1 FROM public_bans WHERE space_id = ? AND account_id = ?")
        .bind(space)
        .bind(account)
        .fetch_optional(&state.db)
        .await?
        .is_some())
}

fn is_admin_role(role: &str) -> bool {
    role == "owner" || role == "admin"
}

async fn require_admin(state: &AppState, space: &str, account: &str) -> ApiResult<String> {
    match membership(state, space, account).await? {
        Some((role, _)) if is_admin_role(&role) => Ok(role),
        _ => Err(ApiError::forbidden("NOT_ADMIN", "only an admin of this space may do this")),
    }
}

/// What a caller sees of a space. Admin accounts only for admins.
async fn space_json(state: &AppState, s: &Space, account: &str) -> ApiResult<Value> {
    let me = membership(state, &s.id, account).await?;
    let admin = me.as_ref().is_some_and(|(r, _)| is_admin_role(r));
    let rev: Option<i64> = sqlx::query_scalar("SELECT MAX(rev) FROM public_posts WHERE space_id = ?")
        .bind(&s.id)
        .fetch_one(&state.db)
        .await?;
    let mut v = json!({
        "id": s.id,
        "is_public": true,
        "kind": s.kind,
        "handle": s.handle,
        "name": s.name,
        "description": s.description,
        "avatar": s.avatar,
        "members": s.members,
        "features": {
            LISTING: s.listed,
            COMMENTS: s.channel() && s.comments,
            SIGNATURES: s.channel() && s.signatures,
            SLOW_MODE: (s.slow_mode > 0).then_some(s.slow_mode),
        },
        "role": me.as_ref().map(|(r, _)| r.clone()),
        "notify": me.as_ref().is_some_and(|(_, n)| *n),
        "banned": banned(state, &s.id, account).await?,
        "last_rev": rev.unwrap_or(0),
    });
    if admin {
        let admins: Vec<String> =
            sqlx::query_scalar("SELECT account_id FROM public_members WHERE space_id = ? AND role IN ('owner', 'admin') ORDER BY account_id")
                .bind(&s.id)
                .fetch_all(&state.db)
                .await?;
        v["admins"] = json!(admins);
        let bans: Vec<String> = sqlx::query_scalar("SELECT account_id FROM public_bans WHERE space_id = ? ORDER BY account_id")
            .bind(&s.id)
            .fetch_all(&state.db)
            .await?;
        v["bans"] = json!(bans);
    }
    Ok(v)
}

/// A post as `viewer` sees it. In a channel the author of a post (not of a
/// comment) is shown only while `channel.signatures` is applied, or to the
/// channel's admins.
fn post_json(r: &SqliteRow, s: &Space, viewer: &str, viewer_admin: bool) -> Result<Value, sqlx::Error> {
    let author: String = r.try_get("author_account")?;
    let reply_to: Option<String> = r.try_get("reply_to")?;
    let deleted: bool = r.try_get("deleted")?;
    let hide = s.channel() && reply_to.is_none() && !s.signatures && !viewer_admin;
    let mut v = json!({
        "id": r.try_get::<String, _>("id")?,
        "space": s.id,
        "is_public": true,
        "seq": r.try_get::<i64, _>("seq")?,
        "rev": r.try_get::<i64, _>("rev")?,
        "reply_to": reply_to,
        "created_at": r.try_get::<i64, _>("created_at")?,
        "edited_at": r.try_get::<Option<i64>, _>("edited_at")?,
        "deleted": deleted,
        "mine": author == viewer,
        "author": if hide { None } else { Some(author.clone()) },
        "author_name": if hide { None } else { r.try_get::<Option<String>, _>("author_name")? },
    });
    if !deleted {
        v["text"] = json!(r.try_get::<String, _>("text")?);
        v["attachment"] = json!(r.try_get::<Option<String>, _>("attachment")?);
    }
    if s.channel() && v["reply_to"].is_null() {
        v["comments"] = json!(r.try_get::<i64, _>("comments")?);
    }
    Ok(v)
}

const POST_COLS: &str = "p.seq, p.id, p.author_account, p.author_name, p.reply_to, p.text, p.attachment, p.created_at, p.edited_at, p.deleted, p.rev, \
     (SELECT COUNT(*) FROM public_posts c WHERE c.reply_to = p.id AND c.deleted = 0) AS comments";

// ---------------------------------------------------------------------------
// Spaces

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReq {
    /// `group` or `channel`.
    pub kind: String,
    pub name: String,
    pub handle: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub avatar: Option<String>,
}
json_body!(CreateReq, |_cfg| 8 * 1024);

/// `POST /v1/public/spaces` — create a public group or channel; the caller's
/// account owns it. `201` with the space.
pub async fn create(State(state): State<AppState>, req: Signed<CreateReq>) -> ApiResult<(StatusCode, Json<Value>)> {
    on(&state).await?;
    req.device.refuse_bot()?;
    let r = &req.body;
    if r.kind != "group" && r.kind != "channel" {
        return Err(ApiError::bad_request("kind is group or channel"));
    }
    check_text(r.name.trim(), MAX_NAME, false, "name")?;
    if !r.description.is_empty() {
        check_text(&r.description, MAX_DESCRIPTION, true, "description")?;
    }
    if let Some(a) = &r.avatar {
        check_ref(a, "avatar")?;
    }
    let handle = normalise_handle(&r.handle).map_err(ApiError::bad_request)?;
    // New or reported accounts (anti-spam limits) do not open broadcast spaces.
    if req.device.max_fanout < state.cfg.max_recipients {
        return Err(ApiError::forbidden("LIMITED", "this account cannot create public spaces for now"));
    }
    req.device.charge_outreach(&state, CREATE_COST)?;
    let account = &req.device.account_id;
    let id = new_id();
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let owned: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM public_spaces WHERE owner_account = ?")
        .bind(account)
        .fetch_one(&mut *tx)
        .await?;
    if owned >= MAX_OWNED {
        return Err(ApiError::limit_exceeded(format!("an account owns at most {MAX_OWNED} public spaces")));
    }
    let ins = sqlx::query(
        "INSERT INTO public_spaces (id, kind, handle, name, description, avatar, owner_account, created_day) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&r.kind)
    .bind(&handle)
    .bind(r.name.trim())
    .bind(&r.description)
    .bind(&r.avatar)
    .bind(account)
    .bind(today())
    .execute(&mut *tx)
    .await;
    match ins {
        Err(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()) => {
            return Err(ApiError::conflict("HANDLE_TAKEN", "this handle belongs to another public space"));
        }
        r => {
            r?;
        }
    }
    sqlx::query("INSERT INTO public_members (space_id, account_id, role, notify) VALUES (?, ?, 'owner', 0)")
        .bind(&id)
        .bind(account)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let s = load(&state, &id).await?;
    Ok((StatusCode::CREATED, Json(space_json(&state, &s, account).await?)))
}

/// `GET /v1/public/spaces/{id}` — anyone signed in (public content).
pub async fn get(State(state): State<AppState>, Path(id): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    let s = load(&state, &id).await?;
    Ok(Json(space_json(&state, &s, &req.device.account_id).await?))
}

/// `GET /v1/public/handles/{handle}` — a space by its exact @handle, listed
/// or not (a handle is like a link).
pub async fn by_handle(State(state): State<AppState>, Path(handle): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    let h = normalise_handle(&handle).map_err(ApiError::bad_request)?;
    let r = sqlx::query(safe(format!("SELECT {SPACE_COLS} FROM public_spaces s WHERE s.handle = ?")))
        .bind(&h)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("no such public space"))?;
    Ok(Json(space_json(&state, &space_of(&r)?, &req.device.account_id).await?))
}

#[derive(Deserialize)]
pub struct DirectoryQuery {
    #[serde(default)]
    pub q: String,
    pub limit: Option<i64>,
}

fn like_escape(s: &str) -> String {
    s.chars().flat_map(|c| if matches!(c, '%' | '_' | '\\') { vec!['\\', c] } else { vec![c] }).collect()
}

/// `GET /v1/public/directory?q=&limit=` — listed spaces (`chat.public_listing`
/// applied) whose handle starts with, or whose name contains, `q`; the
/// largest first. Unlisted spaces never appear.
pub async fn directory(State(state): State<AppState>, Query(q): Query<DirectoryQuery>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    req.device.charge_outreach(&state, SEARCH_COST)?;
    let needle = q.q.trim().trim_start_matches('@');
    if needle.chars().count() > MAX_NAME {
        return Err(ApiError::bad_request("search text too long"));
    }
    let limit = q.limit.unwrap_or(PAGE_DEFAULT).clamp(1, PAGE_MAX);
    let e = like_escape(needle);
    let rows = sqlx::query(safe(format!(
        "SELECT {SPACE_COLS} FROM public_spaces s WHERE s.listed = 1 \
         AND (s.handle LIKE ?1 ESCAPE '\\' OR s.name LIKE ?2 ESCAPE '\\') ORDER BY members DESC, s.handle LIMIT ?3"
    )))
    .bind(format!("{}%", e.to_ascii_lowercase()))
    .bind(format!("%{e}%"))
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::new();
    for r in rows {
        out.push(space_json(&state, &space_of(&r)?, &req.device.account_id).await?);
    }
    Ok(Json(json!({ "spaces": out })))
}

/// `GET /v1/public/subscriptions` — the caller's spaces (for its other devices).
pub async fn subscriptions(State(state): State<AppState>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    let rows = sqlx::query(safe(format!(
        "SELECT {SPACE_COLS} FROM public_spaces s JOIN public_members me ON me.space_id = s.id WHERE me.account_id = ? ORDER BY s.handle"
    )))
    .bind(&req.device.account_id)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::new();
    for r in rows {
        out.push(space_json(&state, &space_of(&r)?, &req.device.account_id).await?);
    }
    Ok(Json(json!({ "spaces": out })))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProfileReq {
    pub name: Option<String>,
    pub description: Option<String>,
    /// Empty string: no avatar.
    pub avatar: Option<String>,
}
json_body!(ProfileReq, |_cfg| 8 * 1024);

/// `POST /v1/public/spaces/{id}/profile` — an admin changes name,
/// description or avatar.
pub async fn profile(State(state): State<AppState>, Path(id): Path<String>, req: Signed<ProfileReq>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    let s = load(&state, &id).await?;
    require_admin(&state, &s.id, &req.device.account_id).await?;
    let r = &req.body;
    if let Some(n) = &r.name {
        check_text(n.trim(), MAX_NAME, false, "name")?;
    }
    if let Some(d) = r.description.as_ref().filter(|d| !d.is_empty()) {
        check_text(d, MAX_DESCRIPTION, true, "description")?;
    }
    if let Some(a) = r.avatar.as_ref().filter(|a| !a.is_empty()) {
        check_ref(a, "avatar")?;
    }
    sqlx::query(
        "UPDATE public_spaces SET name = COALESCE(?, name), description = COALESCE(?, description), \
         avatar = CASE WHEN ? IS NULL THEN avatar WHEN ? = '' THEN NULL ELSE ? END WHERE id = ?",
    )
    .bind(r.name.as_deref().map(str::trim))
    .bind(&r.description)
    .bind(&r.avatar)
    .bind(&r.avatar)
    .bind(&r.avatar)
    .bind(&s.id)
    .execute(&state.db)
    .await?;
    let s = load(&state, &id).await?;
    Ok(Json(space_json(&state, &s, &req.device.account_id).await?))
}

/// `DELETE /v1/public/spaces/{id}` — the owner deletes the space with all
/// its posts.
pub async fn delete_space(State(state): State<AppState>, Path(id): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    let s = load(&state, &id).await?;
    if membership(&state, &s.id, &req.device.account_id).await?.map(|m| m.0).as_deref() != Some("owner") {
        return Err(ApiError::forbidden("NOT_OWNER", "only the owner deletes a public space"));
    }
    sqlx::query("DELETE FROM public_spaces WHERE id = ?").bind(&s.id).execute(&state.db).await?;
    Ok(Json(json!({ "id": s.id, "deleted": true })))
}

#[derive(Deserialize, Default)]
pub struct OptionReq {
    pub option: Option<String>,
}
impl crate::auth::SignedBody for OptionReq {
    fn max_len(_: &crate::config::Config) -> usize {
        512
    }
    fn parse(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.is_empty() {
            Ok(Self::default())
        } else {
            crate::auth::parse_json(bytes)
        }
    }
}

/// `POST /v1/public/spaces/{id}/features/{key}/apply|release` — an admin
/// applies or releases a space setting (module table). Idempotent; returns
/// the space.
pub async fn feature(
    State(state): State<AppState>,
    Path((id, key, action)): Path<(String, String, String)>,
    req: Signed<OptionReq>,
) -> ApiResult<Json<Value>> {
    on(&state).await?;
    let apply = match action.as_str() {
        "apply" => true,
        "release" => false,
        _ => return Err(ApiError::not_found("no such endpoint")),
    };
    let s = load(&state, &id).await?;
    require_admin(&state, &s.id, &req.device.account_id).await?;
    let opt = req.body.option.as_deref();
    let (col, value): (&str, i64) = match key.as_str() {
        LISTING => ("listed", apply as i64),
        COMMENTS | SIGNATURES if !s.channel() => {
            return Err(ApiError::bad_request(format!("{key} is for channels")));
        }
        COMMENTS => ("comments", apply as i64),
        SIGNATURES => ("signatures", apply as i64),
        SLOW_MODE if apply => ("slow_mode", slow_seconds(opt).map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "INVALID_OPTION", e))?),
        SLOW_MODE => ("slow_mode", 0),
        _ => return Err(ApiError::new(StatusCode::NOT_FOUND, "UNKNOWN_FEATURE", "unknown public space setting").with("key", json!(key))),
    };
    if opt.is_some() && key != SLOW_MODE {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "INVALID_OPTION", format!("{key}: takes no option")));
    }
    sqlx::query(safe(format!("UPDATE public_spaces SET {col} = ? WHERE id = ?")))
        .bind(value)
        .bind(&s.id)
        .execute(&state.db)
        .await?;
    let s = load(&state, &id).await?;
    Ok(Json(space_json(&state, &s, &req.device.account_id).await?))
}

// ---------------------------------------------------------------------------
// Membership

/// `POST /v1/public/spaces/{id}/join` — subscribe (idempotent). Banned
/// accounts are refused.
pub async fn join(State(state): State<AppState>, Path(id): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    let s = load(&state, &id).await?;
    let account = &req.device.account_id;
    if banned(&state, &s.id, account).await? {
        return Err(ApiError::forbidden("BANNED", "this account is banned from this space"));
    }
    req.device.charge_outreach(&state, JOIN_COST)?;
    let joined: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM public_members WHERE account_id = ?")
        .bind(account)
        .fetch_one(&state.db)
        .await?;
    if joined >= MAX_JOINED && membership(&state, &s.id, account).await?.is_none() {
        return Err(ApiError::limit_exceeded(format!("at most {MAX_JOINED} public spaces per account")));
    }
    sqlx::query("INSERT OR IGNORE INTO public_members (space_id, account_id, role) VALUES (?, ?, 'member')")
        .bind(&s.id)
        .bind(account)
        .execute(&state.db)
        .await?;
    let s = load(&state, &id).await?;
    Ok(Json(space_json(&state, &s, account).await?))
}

/// `POST /v1/public/spaces/{id}/leave` — unsubscribe (idempotent). The owner
/// cannot leave; it deletes the space instead.
pub async fn leave(State(state): State<AppState>, Path(id): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    let s = load(&state, &id).await?;
    let account = &req.device.account_id;
    if membership(&state, &s.id, account).await?.map(|m| m.0).as_deref() == Some("owner") {
        return Err(ApiError::conflict("OWNER_CANNOT_LEAVE", "the owner deletes the space instead"));
    }
    sqlx::query("DELETE FROM public_members WHERE space_id = ? AND account_id = ?")
        .bind(&s.id)
        .bind(account)
        .execute(&state.db)
        .await?;
    let s = load(&state, &id).await?;
    Ok(Json(space_json(&state, &s, account).await?))
}

/// `POST /v1/public/spaces/{id}/notify/apply|release` — content-free
/// wake-ups for new posts in this space (members only).
pub async fn notify(State(state): State<AppState>, Path((id, action)): Path<(String, String)>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    let on_ = match action.as_str() {
        "apply" => true,
        "release" => false,
        _ => return Err(ApiError::not_found("no such endpoint")),
    };
    let s = load(&state, &id).await?;
    let n = sqlx::query("UPDATE public_members SET notify = ? WHERE space_id = ? AND account_id = ?")
        .bind(on_)
        .bind(&s.id)
        .bind(&req.device.account_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::forbidden("NOT_MEMBER", "subscribe first"));
    }
    Ok(Json(space_json(&state, &s, &req.device.account_id).await?))
}

/// `POST /v1/public/spaces/{id}/admins/{account}/apply|release` — admins
/// appoint admins; an admin is dropped by any admin, the owner never.
pub async fn admin(
    State(state): State<AppState>,
    Path((id, target, action)): Path<(String, String, String)>,
    req: Signed<NoBody>,
) -> ApiResult<Json<Value>> {
    on(&state).await?;
    check_id(&target, "account id")?;
    let s = load(&state, &id).await?;
    require_admin(&state, &s.id, &req.device.account_id).await?;
    let current = membership(&state, &s.id, &target).await?.map(|m| m.0);
    match (action.as_str(), current.as_deref()) {
        (_, Some("owner")) => return Err(ApiError::forbidden("OWNER", "the owner's role does not change")),
        (_, None) => return Err(ApiError::forbidden("NOT_MEMBER", "only a subscriber can be an admin")),
        ("apply", _) => {
            let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM public_members WHERE space_id = ? AND role IN ('owner', 'admin')")
                .bind(&s.id)
                .fetch_one(&state.db)
                .await?;
            if n >= MAX_ADMINS && current.as_deref() != Some("admin") {
                return Err(ApiError::limit_exceeded(format!("at most {MAX_ADMINS} admins")));
            }
            sqlx::query("UPDATE public_members SET role = 'admin' WHERE space_id = ? AND account_id = ?")
                .bind(&s.id)
                .bind(&target)
                .execute(&state.db)
                .await?;
        }
        ("release", _) => {
            sqlx::query("UPDATE public_members SET role = 'member' WHERE space_id = ? AND account_id = ?")
                .bind(&s.id)
                .bind(&target)
                .execute(&state.db)
                .await?;
        }
        _ => return Err(ApiError::not_found("no such endpoint")),
    }
    Ok(Json(space_json(&state, &s, &req.device.account_id).await?))
}

/// `POST /v1/public/spaces/{id}/bans/{account}/apply|release` — an admin
/// bans a member (it is unsubscribed and may not join or post) or lifts
/// the ban. Admins cannot be banned.
pub async fn ban(
    State(state): State<AppState>,
    Path((id, target, action)): Path<(String, String, String)>,
    req: Signed<NoBody>,
) -> ApiResult<Json<Value>> {
    on(&state).await?;
    check_id(&target, "account id")?;
    let s = load(&state, &id).await?;
    require_admin(&state, &s.id, &req.device.account_id).await?;
    match action.as_str() {
        "apply" => {
            if membership(&state, &s.id, &target).await?.is_some_and(|(r, _)| is_admin_role(&r)) {
                return Err(ApiError::forbidden("ADMIN", "drop the admin role first"));
            }
            let known = sqlx::query("SELECT 1 FROM accounts WHERE id = ?").bind(&target).fetch_optional(&state.db).await?;
            if known.is_none() {
                return Err(ApiError::not_found("no such account"));
            }
            let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
            sqlx::query("INSERT OR IGNORE INTO public_bans (space_id, account_id) VALUES (?, ?)")
                .bind(&s.id)
                .bind(&target)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM public_members WHERE space_id = ? AND account_id = ?")
                .bind(&s.id)
                .bind(&target)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        "release" => {
            sqlx::query("DELETE FROM public_bans WHERE space_id = ? AND account_id = ?")
                .bind(&s.id)
                .bind(&target)
                .execute(&state.db)
                .await?;
        }
        _ => return Err(ApiError::not_found("no such endpoint")),
    }
    let s = load(&state, &id).await?;
    Ok(Json(space_json(&state, &s, &req.device.account_id).await?))
}

// ---------------------------------------------------------------------------
// Posts

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostReq {
    /// Chosen by the client (16 random bytes, base64url): a retry with the
    /// same id and content is answered with the stored post.
    pub id: String,
    pub text: String,
    #[serde(default)]
    pub reply_to: Option<String>,
    #[serde(default)]
    pub attachment: Option<String>,
    /// The display name the author publishes with this post.
    #[serde(default)]
    pub author_name: Option<String>,
}
json_body!(PostReq, |_cfg| MAX_TEXT * 4 + MAX_REF + 1024);

async fn next_rev(tx: &mut sqlx::SqliteConnection) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COALESCE(MAX(rev), 0) + 1 FROM public_posts").fetch_one(tx).await
}

async fn post_row(state: &AppState, id: &str) -> ApiResult<Option<SqliteRow>> {
    Ok(sqlx::query(safe(format!("SELECT {POST_COLS}, p.space_id FROM public_posts p WHERE p.id = ?")))
        .bind(id)
        .fetch_optional(&state.db)
        .await?)
}

/// `POST /v1/public/spaces/{id}/posts` — a post (or, with `reply_to`, a
/// comment). Public groups: members. Channels: admins post; members comment
/// while `channel.comments` is applied. Banned accounts never. Slow mode
/// for non-admins. `201` with the post (`200` with `"replayed": true` for a
/// retry).
pub async fn post(State(state): State<AppState>, Path(id): Path<String>, req: Signed<PostReq>) -> ApiResult<(StatusCode, Json<Value>)> {
    on(&state).await?;
    let s = load(&state, &id).await?;
    let account = req.device.account_id.clone();
    let r = &req.body;
    check_id(&r.id, "post id")?;
    if !(r.text.is_empty() && r.attachment.is_some()) {
        check_text(&r.text, MAX_TEXT, true, "text")?;
    }
    if let Some(a) = &r.attachment {
        check_ref(a, "attachment")?;
    }
    if let Some(n) = &r.author_name {
        check_text(n, MAX_AUTHOR_NAME, false, "author_name")?;
    }
    if banned(&state, &s.id, &account).await? {
        return Err(ApiError::forbidden("BANNED", "this account is banned from this space"));
    }
    let role = membership(&state, &s.id, &account)
        .await?
        .map(|m| m.0)
        .ok_or_else(|| ApiError::forbidden("NOT_MEMBER", "subscribe first"))?;
    let admin = is_admin_role(&role);
    if s.channel() && r.reply_to.is_none() && !admin {
        return Err(ApiError::forbidden("NOT_ADMIN", "only admins post in a channel"));
    }
    if let Some(parent) = &r.reply_to {
        if s.channel() && !s.comments {
            return Err(ApiError::forbidden("LOCKED_BY_CHAT", "comments are released in this channel (channel.comments)"));
        }
        check_id(parent, "reply_to")?;
        let ok = sqlx::query("SELECT reply_to FROM public_posts WHERE id = ? AND space_id = ? AND deleted = 0")
            .bind(parent)
            .bind(&s.id)
            .fetch_optional(&state.db)
            .await?
            .map(|row| row.try_get::<Option<String>, _>("reply_to"))
            .transpose()?;
        // A channel comment answers a post, not another comment.
        match ok {
            None => return Err(ApiError::not_found("no such post in this space")),
            Some(Some(_)) if s.channel() => return Err(ApiError::bad_request("comments answer posts, not comments")),
            Some(_) => {}
        }
    }
    req.device.charge_outreach(&state, POST_COST)?;

    let now = now_secs();
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    // A retry of the same post: the stored one, nothing new.
    if let Some(old) = sqlx::query("SELECT space_id, author_account, text, reply_to FROM public_posts WHERE id = ?")
        .bind(&r.id)
        .fetch_optional(&mut *tx)
        .await?
    {
        let same = old.try_get::<String, _>("space_id")? == s.id
            && old.try_get::<String, _>("author_account")? == account
            && old.try_get::<String, _>("text")? == r.text
            && old.try_get::<Option<String>, _>("reply_to")? == r.reply_to;
        tx.rollback().await?;
        if !same {
            return Err(ApiError::conflict("IDEMPOTENCY_KEY_REUSE", "this post id was used for another post"));
        }
        let row = post_row(&state, &r.id).await?.ok_or_else(ApiError::internal)?;
        let mut v = post_json(&row, &s, &account, admin)?;
        v["replayed"] = json!(true);
        return Ok((StatusCode::OK, Json(v)));
    }
    if !admin && s.slow_mode > 0 {
        let last: i64 = sqlx::query_scalar("SELECT last_post_at FROM public_members WHERE space_id = ? AND account_id = ?")
            .bind(&s.id)
            .bind(&account)
            .fetch_one(&mut *tx)
            .await?;
        let wait = last + s.slow_mode - now;
        if wait > 0 {
            return Err(ApiError { retry_after: Some(wait as u64), ..ApiError::new(StatusCode::TOO_MANY_REQUESTS, "SLOW_MODE", "slow mode: wait before posting again") });
        }
    }
    let rev = next_rev(&mut tx).await?;
    sqlx::query(
        "INSERT INTO public_posts (id, space_id, author_account, author_name, reply_to, text, attachment, created_at, rev) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&r.id)
    .bind(&s.id)
    .bind(&account)
    .bind(&r.author_name)
    .bind(&r.reply_to)
    .bind(&r.text)
    .bind(&r.attachment)
    .bind(now)
    .bind(rev)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE public_members SET last_post_at = ? WHERE space_id = ? AND account_id = ?")
        .bind(now)
        .bind(&s.id)
        .bind(&account)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.public_wakes.mark(&s.id, &account);
    let row = post_row(&state, &r.id).await?.ok_or_else(ApiError::internal)?;
    Ok((StatusCode::CREATED, Json(post_json(&row, &s, &account, admin)?)))
}

#[derive(Deserialize)]
pub struct PostsQuery {
    /// Newest first, older than this `seq`.
    pub before: Option<i64>,
    /// Everything changed after this `rev`, oldest change first (also
    /// edits and deletions), for keeping a cache up to date.
    pub after_rev: Option<i64>,
    /// Only the comments of this post.
    pub reply_to: Option<String>,
    pub limit: Option<i64>,
}

/// `GET /v1/public/spaces/{id}/posts?before=&after_rev=&reply_to=&limit=` —
/// anyone signed in may read (public content). Without `after_rev`: newest
/// first, not deleted; in a channel only posts unless `reply_to` names one.
pub async fn posts(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<PostsQuery>,
    req: Signed<NoBody>,
) -> ApiResult<Json<Value>> {
    on(&state).await?;
    let s = load(&state, &id).await?;
    let account = &req.device.account_id;
    let admin = membership(&state, &s.id, account).await?.is_some_and(|(r, _)| is_admin_role(&r));
    let limit = q.limit.unwrap_or(PAGE_DEFAULT).clamp(1, PAGE_MAX);
    let rows = if let Some(after) = q.after_rev {
        sqlx::query(safe(format!("SELECT {POST_COLS} FROM public_posts p WHERE p.space_id = ? AND p.rev > ? ORDER BY p.rev LIMIT ?")))
            .bind(&s.id)
            .bind(after)
            .bind(limit)
            .fetch_all(&state.db)
            .await?
    } else {
        let before = q.before.unwrap_or(i64::MAX);
        let filter = match (&q.reply_to, s.channel()) {
            (Some(_), _) => "AND p.reply_to = ?",
            (None, true) => "AND p.reply_to IS NULL AND ? IS NULL",
            (None, false) => "AND ? IS NULL",
        };
        sqlx::query(safe(format!(
            "SELECT {POST_COLS} FROM public_posts p WHERE p.space_id = ? AND p.seq < ? AND p.deleted = 0 {filter} ORDER BY p.seq DESC LIMIT ?"
        )))
        .bind(&s.id)
        .bind(before)
        .bind(&q.reply_to)
        .bind(limit)
        .fetch_all(&state.db)
        .await?
    };
    let posts = rows.iter().map(|r| post_json(r, &s, account, admin)).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({ "posts": posts })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditReq {
    pub text: String,
}
json_body!(EditReq, |_cfg| MAX_TEXT * 4 + 256);

/// `PUT /v1/public/posts/{post}` — the author edits its own post.
pub async fn edit(State(state): State<AppState>, Path(post): Path<String>, req: Signed<EditReq>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    check_id(&post, "post id")?;
    check_text(&req.body.text, MAX_TEXT, true, "text")?;
    let row = post_row(&state, &post).await?.ok_or_else(|| ApiError::not_found("no such post"))?;
    let account = &req.device.account_id;
    if row.try_get::<String, _>("author_account")? != *account || row.try_get::<bool, _>("deleted")? {
        return Err(ApiError::forbidden("NOT_AUTHOR", "only the author edits a post"));
    }
    let space: String = row.try_get("space_id")?;
    if banned(&state, &space, account).await? {
        return Err(ApiError::forbidden("BANNED", "this account is banned from this space"));
    }
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let rev = next_rev(&mut tx).await?;
    sqlx::query("UPDATE public_posts SET text = ?, edited_at = ?, rev = ? WHERE id = ?")
        .bind(&req.body.text)
        .bind(now_secs())
        .bind(rev)
        .bind(&post)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let s = load(&state, &space).await?;
    let admin = membership(&state, &space, account).await?.is_some_and(|(r, _)| is_admin_role(&r));
    let row = post_row(&state, &post).await?.ok_or_else(ApiError::internal)?;
    Ok(Json(post_json(&row, &s, account, admin)?))
}

/// `DELETE /v1/public/posts/{post}` — the author, or an admin of the space,
/// deletes a post. The text is erased; a tombstone stays so caches learn it.
pub async fn delete_post(State(state): State<AppState>, Path(post): Path<String>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    on(&state).await?;
    check_id(&post, "post id")?;
    let row = post_row(&state, &post).await?.ok_or_else(|| ApiError::not_found("no such post"))?;
    let account = &req.device.account_id;
    let space: String = row.try_get("space_id")?;
    let admin = membership(&state, &space, account).await?.is_some_and(|(r, _)| is_admin_role(&r));
    if row.try_get::<String, _>("author_account")? != *account && !admin {
        return Err(ApiError::forbidden("NOT_ADMIN", "only the author or an admin deletes a post"));
    }
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let rev = next_rev(&mut tx).await?;
    sqlx::query("UPDATE public_posts SET text = '', attachment = NULL, author_name = NULL, deleted = 1, edited_at = ?, rev = ? WHERE id = ?")
        .bind(now_secs())
        .bind(rev)
        .bind(&post)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "id": post, "deleted": true, "rev": rev })))
}

// ---------------------------------------------------------------------------
// Reports

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportReq {
    pub post: String,
    pub reason: String,
}
json_body!(ReportReq, |_cfg| 4096);

/// `POST /v1/public/reports` — report a public post. The server holds the
/// post, so the report names it and the operator sees the stored text;
/// no franking is needed. Goes into the same queue and daily limit as
/// reports of private messages (`reports.rs`).
pub async fn report(State(state): State<AppState>, req: Signed<ReportReq>) -> ApiResult<(StatusCode, Json<Value>)> {
    on(&state).await?;
    use crate::reports::{MAX_PER_DAY, MAX_REASON};
    check_id(&req.body.post, "post id")?;
    if req.body.reason.chars().count() > MAX_REASON {
        return Err(ApiError::too_large("report too large"));
    }
    state.rate_device(&req.device.device_id, 10.0)?;
    let row = post_row(&state, &req.body.post).await?.ok_or_else(|| ApiError::not_found("no such post"))?;
    if row.try_get::<bool, _>("deleted")? {
        return Err(ApiError::not_found("the post was deleted"));
    }
    let author: String = row.try_get("author_account")?;
    let account = &req.device.account_id;
    if author == *account {
        return Err(ApiError::bad_request("your own post"));
    }
    let filed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports WHERE reporter_account = ? AND created_day = ?")
        .bind(account)
        .bind(today())
        .fetch_one(&state.db)
        .await?;
    if filed >= MAX_PER_DAY {
        return Err(ApiError::limit_exceeded("too many reports from this account today"));
    }
    let messages = json!([{
        "payload": row.try_get::<String, _>("text")?,
        "attachment": row.try_get::<Option<String>, _>("attachment")?,
        "verified": true,
        "public_post": req.body.post,
        "public_space": row.try_get::<String, _>("space_id")?,
    }]);
    let id = new_id();
    sqlx::query(
        "INSERT INTO reports (id, reported_account, reporter_account, reason, messages, verified, created_day) VALUES (?, ?, ?, ?, ?, 1, ?)",
    )
    .bind(&id)
    .bind(&author)
    .bind(account)
    .bind(&req.body.reason)
    .bind(messages.to_string())
    .bind(today())
    .execute(&state.db)
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id, "verified": true }))))
}

/// Deletes tombstones of posts deleted before `cutoff` (unix seconds).
pub async fn purge(db: &sqlx::SqlitePool, cutoff: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM public_posts WHERE deleted = 1 AND edited_at < ?")
        .bind(cutoff)
        .execute(db)
        .await?
        .rows_affected())
}

// ---------------------------------------------------------------------------
// Notifications

/// Spaces with new posts, woken at most once per interval each. In memory
/// only: which spaces had posts recently, and who posted last (not woken).
#[derive(Default)]
pub struct PublicWakes {
    inner: Mutex<WakeState>,
}

#[derive(Default)]
struct WakeState {
    /// Space -> the author of its latest unannounced post.
    dirty: HashMap<String, String>,
    last: HashMap<String, Instant>,
}

impl PublicWakes {
    /// A new post in `space` by `author`.
    pub fn mark(&self, space: &str, author: &str) {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.dirty.insert(space.to_string(), author.to_string());
    }

    /// Spaces due for a wake-up at `now` (each at most once per `interval`),
    /// with the author to leave out. They are taken off the list.
    pub fn due(&self, now: Instant, interval: Duration) -> Vec<(String, String)> {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.last.retain(|_, t| now.duration_since(*t) < interval);
        let due: Vec<String> = s.dirty.keys().filter(|k| !s.last.contains_key(*k)).cloned().collect();
        let mut out = Vec::new();
        for k in due {
            if let Some(a) = s.dirty.remove(&k) {
                s.last.insert(k.clone(), now);
                out.push((k, a));
            }
        }
        out
    }

    pub fn pending(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).dirty.len()
    }
}

/// Devices to wake for a post in `space`: devices with a push endpoint of
/// members who applied notifications, except the author's account.
pub async fn devices_to_wake(db: &sqlx::SqlitePool, space: &str, author: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT d.id FROM public_members m JOIN devices d ON d.account_id = m.account_id \
         JOIN push_endpoints e ON e.device_id = d.id \
         WHERE m.space_id = ? AND m.notify = 1 AND m.account_id != ?",
    )
    .bind(space)
    .bind(author)
    .fetch_all(db)
    .await
}

/// The task that turns [`PublicWakes`] into push wake-ups (`push.rs`
/// coalesces per device as well).
pub fn spawn_wakes(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_secs(state.cfg.public_push_interval_secs);
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tick.tick().await;
            for (space, author) in state.public_wakes.due(Instant::now(), interval) {
                match devices_to_wake(&state.db, &space, &author).await {
                    Ok(devices) => {
                        if let Some(p) = &state.push {
                            for d in devices {
                                let _ = p.try_send(d);
                            }
                        }
                    }
                    Err(e) => tracing::error!(target: "tree_server::public", error = %e),
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles() {
        assert_eq!(normalise_handle(" @Tree_News "), Ok("tree_news".into()));
        assert!(normalise_handle("abcd").is_err(), "too short");
        assert!(normalise_handle(&"a".repeat(33)).is_err(), "too long");
        assert!(normalise_handle("1news").is_err(), "starts with a letter");
        assert!(normalise_handle("news-x").is_err());
        assert!(normalise_handle("뉴스채널입니다").is_err());
        assert_eq!(normalise_handle(&"a".repeat(32)).map(|h| h.len()), Ok(32));
    }

    #[test]
    fn slow_mode_options() {
        assert_eq!(slow_seconds(None), Ok(30));
        assert_eq!(slow_seconds(Some("10")), Ok(10));
        assert_eq!(slow_seconds(Some("5m")), Ok(300));
        assert_eq!(slow_seconds(Some("1h")), Ok(3600));
        assert_eq!(slow_seconds(Some("45s")), Ok(45));
        for bad in ["9", "2h", "", "m", "-5", "1d", "1.5m"] {
            assert!(slow_seconds(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn wakes_once_per_interval_per_space() {
        let w = PublicWakes::default();
        let t0 = Instant::now();
        let i = Duration::from_secs(60);
        w.mark("s1", "a");
        w.mark("s1", "b");
        w.mark("s2", "a");
        let mut d = w.due(t0, i);
        d.sort();
        assert_eq!(d, vec![("s1".to_string(), "b".to_string()), ("s2".to_string(), "a".to_string())]);
        w.mark("s1", "c");
        assert!(w.due(t0 + Duration::from_secs(30), i).is_empty(), "within the minute");
        assert_eq!(w.pending(), 1, "kept for later");
        assert_eq!(w.due(t0 + Duration::from_secs(61), i), vec![("s1".to_string(), "c".to_string())]);
        assert!(w.due(t0 + Duration::from_secs(200), i).is_empty(), "nothing new");
    }

    #[test]
    fn like_wildcards_are_escaped() {
        assert_eq!(like_escape("a%b_c\\"), "a\\%b\\_c\\\\");
    }
}
