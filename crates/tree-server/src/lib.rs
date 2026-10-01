//! Tree server.
//!
//! Stores and forwards ciphertext. It never sees plaintext or MLS keys:
//! messages and key packages are opaque byte strings.
//!
//! * [`accounts`] — signup with proof-of-work, extra devices
//! * [`keypackages`] — one-time MLS key packages
//! * [`messages`] — per-device mailboxes with long-poll
//! * [`commits`] — commit ordering: first commit per group and epoch wins
//! * [`invites`] — group invite links (hash of the secret, expiry, use limit)
//! * [`push`] — content-free wake-ups to allowed push gateways
//! * [`recovery`] — a new device joins its account with the recovery phrase
//! * [`usernames`] — @usernames, stored as hashes only
//! * [`attachments`] — encrypted attachments (ciphertext blobs)
//! * [`reports`] — reports with message franking, account suspension
//! * [`features`] — operator flags with apply/release
//!
//! Privacy: no IP addresses, message bodies or key packages are logged. Logs
//! carry method, route template, status and latency only. The sender of a
//! message is known only while its request is processed and is never stored.

pub mod accounts;
pub mod attachments;
pub mod auth;
pub mod commits;
pub mod config;
pub mod error;
pub mod features;
pub mod invites;
pub mod keypackages;
pub mod limits;
pub mod messages;
pub mod push;
pub mod recovery;
pub mod reports;
pub mod usernames;
pub mod util;
pub mod wire;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::json;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Notify};
use tokio::task::JoinHandle;

pub use config::Config;
use error::{ApiError, ApiResult};
use limits::{ip_key, RateLimiter, ReplayCache};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Shared server state.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub db: SqlitePool,
    pub cfg: Config,
    pub replay: ReplayCache,
    pub device_limiter: RateLimiter<String>,
    pub signup_limiter: RateLimiter<[u8; 16]>,
    pub waiters: Waiters,
    pub franking: tokio::sync::OnceCell<[u8; 32]>,
    /// Devices to wake through their push endpoint (see [`push`]).
    pub push: Option<tokio::sync::mpsc::UnboundedSender<String>>,
}

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(db: SqlitePool, cfg: Config) -> Self {
        Self::with_push(db, cfg, None)
    }

    pub fn with_push(db: SqlitePool, cfg: Config, push: Option<tokio::sync::mpsc::UnboundedSender<String>>) -> Self {
        Self(Arc::new(Inner {
            device_limiter: RateLimiter::new(cfg.rate_per_sec, cfg.rate_burst),
            signup_limiter: RateLimiter::new(cfg.signup_per_hour / 3600.0, cfg.signup_burst),
            replay: ReplayCache::new(),
            waiters: Waiters::default(),
            franking: tokio::sync::OnceCell::new(),
            push,
            db,
            cfg,
        }))
    }

    /// Takes `cost` tokens from the device's bucket.
    pub fn rate_device(&self, device_id: &str, cost: f64) -> ApiResult<()> {
        self.device_limiter
            .take(&device_id.to_string(), cost)
            .map_err(ApiError::rate_limited)
    }

    /// Something arrived for `device_id`: wake its long-poll and, if it has
    /// a push endpoint, the app.
    pub fn wake(&self, device_id: &str) {
        self.waiters.notify(device_id);
        if let Some(p) = &self.push {
            let _ = p.send(device_id.to_string());
        }
    }

    /// The server's franking key (created in the database on first use).
    pub async fn franking_key(&self) -> ApiResult<[u8; 32]> {
        Ok(*self.franking.get_or_try_init(|| reports::franking_key(&self.db)).await?)
    }

    /// Client address for the signup limit. Used only in memory.
    pub fn client_ip(&self, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
        if self.cfg.trust_forwarded_for {
            let forwarded = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|v| IpAddr::from_str(v.trim()).ok());
            if let Some(ip) = forwarded {
                return ip;
            }
        }
        peer.ip()
    }

    pub fn rate_signup(&self, ip: IpAddr) -> ApiResult<()> {
        self.signup_limiter
            .take(&ip_key(ip), 1.0)
            .map_err(ApiError::rate_limited)
    }
}

/// Wake-up signals for long-polling devices.
#[derive(Default)]
pub struct Waiters {
    map: Mutex<HashMap<String, Arc<Notify>>>,
}

impl Waiters {
    pub fn subscribe(&self, device_id: &str) -> Arc<Notify> {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(device_id.to_string()).or_default().clone()
    }

    pub fn notify(&self, device_id: &str) {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get(device_id) {
            n.notify_waiters();
        }
    }

    /// Drops a subscription; removes the entry once nobody waits on it.
    pub fn unsubscribe(&self, device_id: &str, n: Arc<Notify>) {
        drop(n);
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if map
            .get(device_id)
            .is_some_and(|e| Arc::strong_count(e) == 1)
        {
            map.remove(device_id);
        }
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Opens the database and applies the embedded migrations.
pub async fn open_db(url: &str) -> Result<SqlitePool, BoxError> {
    let opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(10))
        // Deleted ciphertext is overwritten in the database file, not just unlinked.
        .pragma("secure_delete", "ON");
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    features::seed(&pool).await?;
    Ok(pool)
}

/// The HTTP API.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/accounts", post(accounts::signup))
        .route(
            "/v1/devices",
            post(accounts::add_device).get(accounts::list_devices),
        )
        .route("/v1/devices/{device_id}", delete(accounts::remove_device))
        .route("/v1/keypackages", post(keypackages::upload))
        .route("/v1/keypackages/claim", post(keypackages::claim))
        .route("/v1/keypackages/count", get(keypackages::count))
        .route("/v1/messages", post(messages::send).get(messages::fetch))
        .route("/v1/messages/ack", post(messages::ack))
        .route("/v1/commits", post(commits::submit))
        .route("/v1/attachments", post(attachments::upload))
        .route("/v1/attachments/{id}", get(attachments::download))
        .route("/v1/usernames/apply", post(usernames::apply))
        .route("/v1/usernames/release", post(usernames::release))
        .route("/v1/usernames/lookup", post(usernames::lookup))
        .route("/v1/invites", post(invites::create))
        .route("/v1/invites/{token_hash}", delete(invites::revoke))
        .route("/v1/invites/join", post(invites::join))
        .route("/v1/invites/requests", get(invites::requests))
        .route("/v1/invites/requests/ack", post(invites::ack))
        .route("/v1/recovery/apply", post(recovery::apply))
        .route("/v1/recovery/release", post(recovery::release))
        .route("/v1/recovery/recover", post(recovery::recover))
        .route("/v1/push", post(push::set).delete(push::clear))
        .route("/v1/franking", post(reports::frank))
        .route("/v1/reports", post(reports::report).get(reports::list))
        .route("/v1/reports/{id}/resolve", post(reports::resolve))
        .route("/v1/accounts/{id}/suspend/{action}", post(reports::suspend))
        .route("/v1/features", get(features::list))
        .route("/v1/features/{key}/apply", post(features::apply))
        .route("/v1/features/{key}/release", post(features::release))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn(log_requests))
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    sqlx::query("SELECT 1").execute(&state.db).await?;
    Ok(Json(json!({ "status": "ok" })))
}

async fn not_found() -> ApiError {
    ApiError::not_found("no such endpoint")
}

async fn method_not_allowed() -> ApiError {
    ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "METHOD_NOT_ALLOWED",
        "method not allowed",
    )
}

/// Logs method, route template, status and latency. Never addresses, bodies or ids.
async fn log_requests(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "-".to_owned());
    let start = Instant::now();
    let resp = next.run(req).await;
    tracing::info!(
        target: "tree_server::http",
        method = %method,
        route = %route,
        status = resp.status().as_u16(),
        ms = start.elapsed().as_millis() as u64,
    );
    resp
}

/// Deletes undelivered messages older than the TTL and any orphaned bodies,
/// and the ordering record of groups none of whose devices exist any more.
/// Returns the number of bodies removed.
pub async fn purge_expired(state: &AppState, now: i64) -> Result<u64, sqlx::Error> {
    let cutoff = now - state.cfg.message_ttl_secs as i64;
    let expired = sqlx::query("DELETE FROM blobs WHERE received_at < ?")
        .bind(cutoff)
        .execute(&state.db)
        .await?
        .rows_affected();
    let orphans = sqlx::query(
        "DELETE FROM blobs WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.blob_id = blobs.id)",
    )
    .execute(&state.db)
    .await?
    .rows_affected();
    sqlx::query(
        "DELETE FROM groups WHERE NOT EXISTS (SELECT 1 FROM group_devices g WHERE g.group_id = groups.group_id)",
    )
    .execute(&state.db)
    .await?;
    let files = attachments::purge(state, cutoff).await?;
    let invites = invites::purge(&state.db, now).await?;
    Ok(expired + orphans + files + invites)
}

/// A running server.
pub struct Server {
    pub addr: SocketAddr,
    pub state: AppState,
    shutdown: Option<oneshot::Sender<()>>,
    http: JoinHandle<std::io::Result<()>>,
    background: Vec<JoinHandle<()>>,
}

/// Opens the database, binds `cfg.bind_addr` and serves until [`Server::shutdown`].
pub async fn start(cfg: Config) -> Result<Server, BoxError> {
    cfg.validate()?;
    let db = open_db(&cfg.database_url).await?;
    let listener = TcpListener::bind(cfg.bind_addr).await?;
    let addr = listener.local_addr()?;
    let (push_tx, push_rx) = tokio::sync::mpsc::unbounded_channel();
    let push_on = !cfg.push_allowed_hosts.is_empty();
    let state = AppState::with_push(db, cfg, push_on.then_some(push_tx));

    let mut background = Vec::new();
    if push_on {
        background.push(push::spawn(state.clone(), push_rx));
    }
    {
        let state = state.clone();
        background.push(tokio::spawn(async move {
            let mut tick =
                tokio::time::interval(Duration::from_secs(state.cfg.purge_interval_secs));
            loop {
                tick.tick().await;
                match purge_expired(&state, util::now_secs()).await {
                    Ok(n) => tracing::info!(target: "tree_server::purge", removed = n),
                    Err(e) => tracing::error!(target: "tree_server::purge", error = %e),
                }
            }
        }));
    }
    {
        let state = state.clone();
        background.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                state.replay.prune(util::now_secs());
                state.device_limiter.prune();
                state.signup_limiter.prune();
            }
        }));
    }

    let (tx, rx) = oneshot::channel::<()>();
    let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let http = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
    });
    tracing::info!(target: "tree_server", %addr, "listening");
    Ok(Server {
        addr,
        state,
        shutdown: Some(tx),
        http,
        background,
    })
}

impl Server {
    /// Stops accepting connections, lets in-flight requests finish and stops background tasks.
    pub async fn shutdown(mut self) -> std::io::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        for t in &self.background {
            t.abort();
        }
        let result = (&mut self.http).await.unwrap_or(Ok(()));
        self.state.db.close().await;
        result
    }
}
