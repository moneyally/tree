//! Tree bot gateway (PROTOCOL.md 8.16, docs/BOT_GATEWAY.md).
//!
//! Tree runs no bots. A bot's developer runs this gateway on their own
//! server. It is the bot's device: it holds the bot's MLS keys and device
//! key in an encrypted profile (a [`tree_client::Session`]), receives and
//! decrypts what members send to the bot, and offers the bot's own code a
//! small HTTP API in a widely used bot HTTP API style: long-poll
//! `getUpdates` (or a webhook), `sendMessage` with inline buttons,
//! `answerCallbackQuery`, `getMe`, `leaveChat`.
//!
//! **What the gateway's operator sees.** Everything the bot is sent, in
//! plaintext: that is what a bot is. With `bot.privacy_mode` applied (the
//! default) members' devices send a bot in a group only what is addressed
//! to it (commands, mentions, replies to it, presses of its buttons) plus
//! the member list and names; in a 1:1 chat everything. Never people's
//! phone numbers (Tree has none) or recovery data (bots have none).
//!
//! **Security of the local API.** It listens on a loopback address unless
//! told otherwise (`allow_remote`), and every call carries the bot token
//! (`Authorization: Bearer <token>`, or the path `/bot<token>/<method>`),
//! compared in constant time with the SHA-256 the profile keeps. The token
//! itself is never written to disk by the gateway.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tree_client::{BotInfo, Button, Error, Event, GroupStatus, MemberId, Session, TextOptions};

/// Longest `getUpdates` wait (seconds).
pub const MAX_TIMEOUT: u64 = 50;
/// Updates kept at most; the oldest go first.
pub const MAX_QUEUE: usize = 10_000;

/// How the gateway runs.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where the local API listens (default `127.0.0.1:8081`).
    pub listen: SocketAddr,
    /// Listen on a non-loopback address too (then put it behind TLS and a
    /// firewall: the token is the only protection).
    pub allow_remote: bool,
    /// How long one wait for new messages at the server lasts (seconds).
    pub poll_secs: u64,
    /// How often the bot's settings are read again from the server.
    pub settings_every: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self { listen: "127.0.0.1:8081".parse().expect("address"), allow_remote: false, poll_secs: 20, settings_every: Duration::from_secs(300) }
    }
}

/// Why the gateway did not start.
#[derive(Debug)]
pub struct StartError(pub String);

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StartError {}

struct Shared {
    session: Mutex<Session>,
    /// SHA-256 of the bot token (memory only; the token is not kept).
    token_hash: Vec<u8>,
    /// Bumped whenever updates are queued.
    signal: Mutex<u64>,
    ready: Condvar,
    stop: AtomicBool,
    me: Mutex<Option<BotInfo>>,
    /// The last error of the receive loop (shown by `getWebhookInfo`).
    last_error: Mutex<Option<String>>,
}

impl Shared {
    fn s(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn notify(&self) {
        *self.signal.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.ready.notify_all();
    }

    fn token_ok(&self, token: &str) -> bool {
        !self.token_hash.is_empty() && bool::from(Sha256::digest(token.trim().as_bytes()).as_slice().ct_eq(&self.token_hash))
    }
}

/// A running gateway.
pub struct Gateway {
    /// Where the local API listens.
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    receiver: Option<std::thread::JoinHandle<()>>,
    http: Option<std::thread::JoinHandle<()>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Gateway {
    /// Starts the receive loop and the local API for a bot's device
    /// ([`Session::create_bot_device`]).
    pub fn start(session: Session, cfg: Config) -> Result<Gateway, StartError> {
        if !cfg.allow_remote && !cfg.listen.ip().is_loopback() {
            return Err(StartError(format!("{} is not a loopback address; allow remote access explicitly", cfg.listen)));
        }
        if session.bot_self().map_err(|e| StartError(e.to_string()))?.is_none() {
            return Err(StartError("this profile is not a bot's device (create it with the bot token)".into()));
        }
        let token_hash = session.bot_token_sha256().map_err(|e| StartError(e.to_string()))?.unwrap_or_default();
        let me = session.bot_info_fresh().ok();
        if let Some(info) = &me {
            session.apply_bot_settings(info).map_err(|e| StartError(e.to_string()))?;
        }
        let shared = Arc::new(Shared {
            session: Mutex::new(session),
            token_hash,
            signal: Mutex::new(0),
            ready: Condvar::new(),
            stop: AtomicBool::new(false),
            me: Mutex::new(me),
            last_error: Mutex::new(None),
        });
        let listener = std::net::TcpListener::bind(cfg.listen).map_err(|e| StartError(format!("{}: {e}", cfg.listen)))?;
        listener.set_nonblocking(true).map_err(|e| StartError(e.to_string()))?;
        let addr = listener.local_addr().map_err(|e| StartError(e.to_string()))?;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let app = router(shared.clone());
        let http = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("listener");
                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = rx.await;
                    })
                    .await;
            });
        });
        let receiver = {
            let shared = shared.clone();
            std::thread::spawn(move || receive_loop(shared, cfg))
        };
        Ok(Gateway { addr, shared, receiver: Some(receiver), http: Some(http), shutdown: Some(tx) })
    }

    /// Stops both loops and gives the session back.
    pub fn stop(mut self) -> Session {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.notify();
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.http.take() {
            let _ = h.join();
        }
        if let Some(h) = self.receiver.take() {
            let _ = h.join();
        }
        // A request still finishing holds the state a moment longer.
        let mut shared = self.shared;
        loop {
            match Arc::try_unwrap(shared) {
                Ok(s) => return s.session.into_inner().unwrap_or_else(|e| e.into_inner()),
                Err(again) => {
                    shared = again;
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    /// The receive loop's last error, if any (e.g. the token was rotated:
    /// register again).
    pub fn last_error(&self) -> Option<String> {
        self.shared.last_error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

fn set_error(shared: &Shared, e: Option<String>) {
    *shared.last_error.lock().unwrap_or_else(|x| x.into_inner()) = e;
}

/// Waits at the server, syncs, turns events into updates, delivers a
/// webhook, and reads the bot's settings again now and then.
fn receive_loop(shared: Arc<Shared>, cfg: Config) {
    let mut settings_at = Instant::now();
    while !shared.stop.load(Ordering::SeqCst) {
        let (api, creds) = shared.s().waiter();
        if let Err(e) = api.wait_pending(&creds, cfg.poll_secs) {
            set_error(&shared, Some(e.to_string()));
            pause(&shared, Duration::from_secs(1));
            continue;
        }
        if shared.stop.load(Ordering::SeqCst) {
            break;
        }
        let r = {
            let mut s = shared.s();
            s.sync(0).and_then(|events| queue_events(&mut s, events))
        };
        match r {
            Ok(n) => {
                set_error(&shared, None);
                if n > 0 {
                    shared.notify();
                }
            }
            Err(e) => {
                set_error(&shared, Some(e.to_string()));
                pause(&shared, Duration::from_secs(1));
            }
        }
        if settings_at.elapsed() >= cfg.settings_every {
            settings_at = Instant::now();
            let s = shared.s();
            if let Ok(info) = s.bot_info_fresh() {
                let _ = s.apply_bot_settings(&info);
                *shared.me.lock().unwrap_or_else(|e| e.into_inner()) = Some(info);
            }
        }
        deliver_webhook(&shared);
    }
}

fn pause(shared: &Shared, d: Duration) {
    let g = shared.signal.lock().unwrap_or_else(|e| e.into_inner());
    let _ = shared.ready.wait_timeout_while(g, d, |_| !shared.stop.load(Ordering::SeqCst));
}

// ---------------------------------------------------------------------------
// The update queue (in the encrypted profile, under `gw/`)

fn update_key(id: u64) -> String {
    format!("u/{id:020}")
}

fn next_id(s: &Session) -> Result<u64, Error> {
    Ok(s.gateway_get("next")?.and_then(|v| String::from_utf8(v).ok()).and_then(|v| v.parse().ok()).unwrap_or(1))
}

fn push_update(s: &Session, mut u: Value) -> Result<(), Error> {
    let id = next_id(s)?;
    u["update_id"] = json!(id);
    s.gateway_set(&update_key(id), Some(&serde_json::to_vec(&u).expect("JSON")))?;
    s.gateway_set("next", Some((id + 1).to_string().as_bytes()))?;
    let keys = s.gateway_keys("u/")?;
    if keys.len() > MAX_QUEUE {
        for k in &keys[..keys.len() - MAX_QUEUE] {
            s.gateway_set(k, None)?;
        }
    }
    Ok(())
}

fn user_json(s: &mut Session, gid: &[u8], m: &MemberId) -> Result<Value, Error> {
    let members = s.members(gid)?;
    let info = members.iter().find(|x| x.id == *m);
    Ok(json!({
        "id": m.to_hex(),
        "is_bot": info.is_some_and(|i| i.bot.is_some()),
        "first_name": info.and_then(|i| i.name.clone()).unwrap_or_else(|| "member".into()),
        // The member's account as the group's roster names it (a claim).
        "account": info.and_then(|i| i.account.clone()),
    }))
}

fn chat_json(s: &mut Session, gid: &[u8]) -> Result<Value, Error> {
    let direct = s.members(gid)?.len() <= 2;
    let title = s.group_settings(gid)?.name;
    Ok(json!({ "id": hex::encode(gid), "type": if direct { "private" } else { "group" }, "title": title }))
}

/// Turns what the bot received into updates. Only chats the bot's device
/// accepted; never its own messages.
fn queue_events(s: &mut Session, events: Vec<Event>) -> Result<usize, Error> {
    let me = s.member_id();
    let mut n = 0;
    for e in events {
        match e {
            Event::Text { group, id, from, text, .. } if from != me => {
                if s.group_status(&group)? != GroupStatus::Accepted {
                    continue;
                }
                let stored = s.history(&group, 200)?.into_iter().find(|m| m.id == id);
                let date = stored.as_ref().map(|m| m.received_at).unwrap_or(0);
                let reply = stored.as_ref().and_then(tree_client::channel::message_re);
                let mut msg = json!({ "message_id": id, "from": user_json(s, &group, &from)?, "chat": chat_json(s, &group)?, "date": date, "text": text });
                if let Some(r) = reply {
                    msg["reply_to_message"] = json!({ "message_id": r });
                }
                push_update(s, json!({ "message": msg }))?;
                n += 1;
            }
            Event::CallbackQuery { group, id, from, msg, data } => {
                if s.group_status(&group)? != GroupStatus::Accepted {
                    continue;
                }
                s.gateway_set(&format!("q/{id}"), Some(hex::encode(&group).as_bytes()))?;
                let q = json!({
                    "id": id,
                    "from": user_json(s, &group, &from)?,
                    "message": { "message_id": msg, "chat": chat_json(s, &group)? },
                    "data": data,
                });
                push_update(s, json!({ "callback_query": q }))?;
                n += 1;
            }
            _ => {}
        }
    }
    Ok(n)
}

/// Drops updates before `offset`; returns up to `limit` from it on.
fn take_updates(s: &Session, offset: Option<u64>, limit: usize) -> Result<Vec<Value>, Error> {
    let mut out = Vec::new();
    for k in s.gateway_keys("u/")? {
        let id: u64 = k[2..].parse().unwrap_or(0);
        if offset.is_some_and(|o| id < o) {
            s.gateway_set(&k, None)?;
            continue;
        }
        if out.len() < limit {
            if let Some(v) = s.gateway_get(&k)? {
                out.push(serde_json::from_slice(&v).unwrap_or(Value::Null));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Webhook mode

fn webhook(s: &Session) -> Result<Option<(String, Option<String>)>, Error> {
    Ok(s.gateway_get("webhook")?.and_then(|v| serde_json::from_slice::<(String, Option<String>)>(&v).ok()))
}

/// Only `https://`, or `http://` to this machine.
fn webhook_url_ok(u: &str) -> bool {
    if u.len() > 2048 {
        return false;
    }
    if u.starts_with("https://") {
        return true;
    }
    let Some(rest) = u.strip_prefix("http://") else { return false };
    let host = rest.split(['/', '?']).next().unwrap_or("");
    let host = host.rsplit_once(':').map_or(host, |(h, p)| if p.bytes().all(|b| b.is_ascii_digit()) { h } else { host });
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

/// Posts waiting updates to the webhook, oldest first; one that fails
/// stays and is tried again next time.
fn deliver_webhook(shared: &Shared) {
    let (hook, updates) = {
        let s = shared.s();
        match webhook(&s) {
            Ok(Some(h)) => (h, take_updates(&s, None, 100).unwrap_or_default()),
            _ => return,
        }
    };
    let Ok(http) = reqwest::blocking::Client::builder().timeout(Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none()).build() else {
        return;
    };
    for u in updates {
        let mut rb = http.post(&hook.0).json(&u);
        if let Some(secret) = &hook.1 {
            rb = rb.header("X-Tree-Bot-Api-Secret-Token", secret);
        }
        match rb.send() {
            Ok(r) if r.status().is_success() => {
                let id = u["update_id"].as_u64().unwrap_or(0);
                let _ = shared.s().gateway_set(&update_key(id), None);
            }
            Ok(r) => {
                set_error(shared, Some(format!("webhook answered {}", r.status())));
                return;
            }
            Err(e) => {
                set_error(shared, Some(format!("webhook: {e}")));
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The local HTTP API

fn router(shared: Arc<Shared>) -> Router {
    Router::new().route("/{scope}/{method}", post(call).get(call)).with_state(shared)
}

struct ApiError(u16, String);

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        match e {
            Error::Server { status, code } => ApiError(if status == 0 { 500 } else { status }, code),
            Error::Usage(r) => ApiError(400, r),
            Error::Feature(c) => ApiError(403, c),
            Error::NoSuchGroup => ApiError(400, "chat not found".into()),
            other => ApiError(500, other.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let st = StatusCode::from_u16(self.0).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (st, Json(json!({ "ok": false, "error_code": self.0, "description": self.1 }))).into_response()
    }
}

fn ok(v: Value) -> Response {
    Json(json!({ "ok": true, "result": v })).into_response()
}

fn bad(why: &str) -> ApiError {
    ApiError(400, why.to_string())
}

/// `/bot<token>/<method>` or `/v1/<method>` with `Authorization: Bearer`.
async fn call(
    State(shared): State<Arc<Shared>>,
    Path((scope, method)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let token = match scope.strip_prefix("bot") {
        Some(t) => t.to_string(),
        None if scope == "v1" => headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("")
            .to_string(),
        None => return ApiError(404, "Not Found".into()).into_response(),
    };
    if !shared.token_ok(&token) {
        return ApiError(401, "Unauthorized".into()).into_response();
    }
    let mut params = serde_json::Map::new();
    for (k, v) in query {
        params.insert(k, Value::String(v));
    }
    if !body.is_empty() {
        match serde_json::from_slice::<Value>(&body) {
            Ok(Value::Object(m)) => params.extend(m),
            _ => return bad("the body must be a JSON object").into_response(),
        }
    }
    let params = Value::Object(params);
    if method == "getUpdates" {
        return get_updates(shared, params).await.unwrap_or_else(IntoResponse::into_response);
    }
    match tokio::task::spawn_blocking(move || dispatch(&shared, &method, &params)).await {
        Ok(Ok(v)) => ok(v),
        Ok(Err(e)) => e.into_response(),
        Err(_) => ApiError(500, "internal error".into()).into_response(),
    }
}

fn str_param<'a>(p: &'a Value, k: &str) -> Option<&'a str> {
    p.get(k).and_then(Value::as_str)
}

fn u64_param(p: &Value, k: &str) -> Option<u64> {
    match p.get(k) {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

fn bool_param(p: &Value, k: &str) -> bool {
    match p.get(k) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    }
}

/// A chat the bot's device is in and accepted.
fn chat(s: &mut Session, p: &Value) -> Result<Vec<u8>, ApiError> {
    let id = str_param(p, "chat_id").ok_or_else(|| bad("chat_id is required"))?;
    let gid = hex::decode(id).map_err(|_| bad("chat not found"))?;
    if !s.group_ids()?.contains(&gid) || s.group_status(&gid)? != GroupStatus::Accepted {
        return Err(bad("chat not found"));
    }
    Ok(gid)
}

/// `reply_markup.inline_keyboard`: rows of `{text, callback_data}`.
fn keyboard(p: &Value) -> Result<Vec<Vec<Button>>, ApiError> {
    let markup = match p.get("reply_markup") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::String(s)) => serde_json::from_str::<Value>(s).map_err(|_| bad("reply_markup is not JSON"))?,
        Some(v) => v.clone(),
    };
    let rows = markup["inline_keyboard"].as_array().ok_or_else(|| bad("reply_markup needs inline_keyboard"))?;
    let mut out = Vec::new();
    for r in rows {
        let mut row = Vec::new();
        for b in r.as_array().ok_or_else(|| bad("inline_keyboard is rows of buttons"))? {
            let text = b["text"].as_str().ok_or_else(|| bad("a button needs text"))?;
            let data = b["callback_data"].as_str().ok_or_else(|| bad("a button needs callback_data"))?;
            row.push(Button { text: text.into(), data: data.into() });
        }
        out.push(row);
    }
    Ok(out)
}

fn dispatch(shared: &Shared, method: &str, p: &Value) -> Result<Value, ApiError> {
    match method {
        "getMe" => {
            let cached = shared.me.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let info = match cached {
                Some(i) => i,
                None => shared.s().bot_info_fresh()?,
            };
            Ok(json!({
                "id": info.account,
                "is_bot": true,
                "first_name": info.username,
                "username": info.username,
                "can_join_groups": info.join_groups,
                "can_read_all_group_messages": !info.privacy_mode,
                "supports_inline_queries": info.inline,
            }))
        }
        "sendMessage" => {
            let mut s = shared.s();
            let gid = chat(&mut s, p)?;
            let text = str_param(p, "text").filter(|t| !t.is_empty()).ok_or_else(|| bad("text is required"))?;
            let reply = str_param(p, "reply_to_message_id").map(str::to_string);
            let kb = keyboard(p)?;
            let id = if kb.is_empty() {
                s.send_text_with(&gid, text, &TextOptions { reply_to: reply, ..Default::default() })?
            } else {
                s.send_buttons(&gid, text, kb.clone(), reply.as_deref())?
            };
            let mut v = json!({ "message_id": id, "chat": chat_json(&mut s, &gid)?, "date": now(), "text": text });
            if !kb.is_empty() {
                v["reply_markup"] = json!({ "inline_keyboard": kb.iter().map(|r| r.iter().map(|b| json!({ "text": b.text, "callback_data": b.data })).collect::<Vec<_>>()).collect::<Vec<_>>() });
            }
            Ok(v)
        }
        "answerCallbackQuery" => {
            let s = shared.s();
            let id = str_param(p, "callback_query_id").ok_or_else(|| bad("callback_query_id is required"))?.to_string();
            let gid = s.gateway_get(&format!("q/{id}"))?.and_then(|v| hex::decode(v).ok()).ok_or_else(|| bad("query not found"))?;
            drop(s);
            let mut s = shared.s();
            s.answer_callback(&gid, &id, str_param(p, "text"), bool_param(p, "show_alert"))?;
            s.gateway_set(&format!("q/{id}"), None)?;
            Ok(json!(true))
        }
        "leaveChat" => {
            let mut s = shared.s();
            let gid = chat(&mut s, p)?;
            s.leave(&gid)?;
            Ok(json!(true))
        }
        "setWebhook" => {
            let url = str_param(p, "url").unwrap_or("");
            let s = shared.s();
            if url.is_empty() {
                s.gateway_set("webhook", None)?;
                return Ok(json!(true));
            }
            if !webhook_url_ok(url) {
                return Err(bad("the webhook must be https://, or http:// to this machine"));
            }
            let secret = str_param(p, "secret_token").map(str::to_string);
            if secret.as_ref().is_some_and(|t| t.is_empty() || t.len() > 256 || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')) {
                return Err(bad("secret_token: 1 to 256 of A-Z, a-z, 0-9, _ and -"));
            }
            s.gateway_set("webhook", Some(&serde_json::to_vec(&(url, secret)).expect("JSON")))?;
            Ok(json!(true))
        }
        "deleteWebhook" => {
            shared.s().gateway_set("webhook", None)?;
            Ok(json!(true))
        }
        "getWebhookInfo" => {
            let s = shared.s();
            let pending = s.gateway_keys("u/")?.len();
            let url = webhook(&s)?.map(|h| h.0).unwrap_or_default();
            let err = shared.last_error.lock().unwrap_or_else(|e| e.into_inner()).clone();
            Ok(json!({ "url": url, "pending_update_count": pending, "last_error_message": err }))
        }
        _ => Err(ApiError(404, "Not Found: no such method".into())),
    }
}

/// `getUpdates {offset, limit, timeout}`: long-poll for updates.
async fn get_updates(shared: Arc<Shared>, p: Value) -> Result<Response, ApiError> {
    let offset = u64_param(&p, "offset");
    let limit = u64_param(&p, "limit").unwrap_or(100).clamp(1, 100) as usize;
    let timeout = u64_param(&p, "timeout").unwrap_or(0).min(MAX_TIMEOUT);
    let r = tokio::task::spawn_blocking(move || -> Result<Vec<Value>, ApiError> {
        if webhook(&shared.s())?.is_some() {
            return Err(ApiError(409, "Conflict: a webhook is set; delete it to use getUpdates".into()));
        }
        let deadline = Instant::now() + Duration::from_secs(timeout);
        loop {
            let seen = *shared.signal.lock().unwrap_or_else(|e| e.into_inner());
            let got = take_updates(&shared.s(), offset, limit)?;
            let now = Instant::now();
            if !got.is_empty() || now >= deadline || shared.stop.load(Ordering::SeqCst) {
                return Ok(got);
            }
            let g = shared.signal.lock().unwrap_or_else(|e| e.into_inner());
            let _ = shared.ready.wait_timeout_while(g, deadline - now, |n| *n == seen && !shared.stop.load(Ordering::SeqCst));
        }
    })
    .await
    .map_err(|_| ApiError(500, "internal error".into()))??;
    Ok(ok(Value::Array(r)))
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhooks_go_to_https_or_this_machine() {
        assert!(webhook_url_ok("https://bot.example/hook"));
        assert!(webhook_url_ok("http://127.0.0.1:9000/hook"));
        assert!(webhook_url_ok("http://localhost/hook"));
        assert!(webhook_url_ok("http://[::1]:80/x"));
        assert!(!webhook_url_ok("http://10.0.0.5/hook"));
        assert!(!webhook_url_ok("http://localhost.example/hook"));
        assert!(!webhook_url_ok("ftp://x"));
        assert!(!webhook_url_ok(&format!("https://x/{}", "a".repeat(3000))));
    }

    #[test]
    fn keyboards_parse() {
        let p = json!({ "reply_markup": { "inline_keyboard": [[{ "text": "Yes", "callback_data": "y" }, { "text": "No", "callback_data": "n" }]] } });
        assert_eq!(keyboard(&p).ok().unwrap(), vec![vec![Button { text: "Yes".into(), data: "y".into() }, Button { text: "No".into(), data: "n".into() }]]);
        let s = json!({ "reply_markup": "{\"inline_keyboard\":[[{\"text\":\"A\",\"callback_data\":\"a\"}]]}" });
        assert_eq!(keyboard(&s).ok().unwrap().len(), 1);
        assert!(keyboard(&json!({})).ok().unwrap().is_empty());
        assert!(keyboard(&json!({ "reply_markup": { "inline_keyboard": [[{ "text": "x" }]] } })).is_err());
    }
}
