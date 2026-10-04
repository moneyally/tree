//! Relays for GIF search and map tiles (docs/PROTOCOL.md 8.12).
//!
//! The server fetches on the device's behalf, so the GIF provider and the
//! tile server see the Tree server's address, never the user's. Both are
//! off unless the operator applies the flag (`server.gif_relay`,
//! `server.map_relay`) **and** configures an upstream (`GIF_PROVIDER_URL`,
//! `MAP_TILE_URL`); otherwise every relay endpoint answers
//! `503 RELAY_UNAVAILABLE` and the apps hide the GIF button / show plain
//! coordinates.
//!
//! What the server learns (and never stores or logs): the search words of a
//! GIF search, which GIF media a device fetched, and which map tiles (so
//! roughly which area at which zoom) a device looked at, together with the
//! authenticated device id of each request. The upstream learns the search
//! words and tile coordinates, from the server's address, with no device,
//! account, client address or forwarding header.
//!
//! Only URLs the provider itself returned are fetched (by an opaque id kept
//! in memory for an hour), redirects are not followed, answers are limited
//! to `RELAY_MAX_BYTES` and must be images or videos, so a device cannot
//! make the server fetch anything else.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{NoBody, Signed};
use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::{features, json_body, AppState};

pub const GIF_RELAY: &str = "server.gif_relay";
pub const MAP_RELAY: &str = "server.map_relay";
/// Search words per query (characters).
pub const MAX_QUERY: usize = 100;
/// Results per search.
pub const MAX_RESULTS: usize = 50;
/// How long a media id from a search can be fetched.
pub const MEDIA_TTL: Duration = Duration::from_secs(3600);
/// Media ids kept at most (memory only).
pub const MAX_MEDIA_IDS: usize = 50_000;
/// Highest map zoom level relayed.
pub const MAX_ZOOM: u32 = 19;
/// Upstream timeout.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The relay's memory: media ids handed out by searches, and the HTTP
/// client used for upstream requests (no redirects, no cookies, a fixed
/// user agent and nothing from the device's request).
pub struct Relay {
    media: Mutex<HashMap<String, (String, Instant)>>,
    http: reqwest::Client,
}

impl Default for Relay {
    fn default() -> Self {
        Self::new()
    }
}

impl Relay {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .user_agent("tree-relay/1")
            .build()
            .expect("HTTP client");
        Self { media: Mutex::new(HashMap::new()), http }
    }

    /// An opaque id for an upstream URL the provider returned.
    fn remember(&self, url: String) -> String {
        let id = crate::util::new_id();
        let mut m = self.media.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= MAX_MEDIA_IDS {
            let now = Instant::now();
            m.retain(|_, (_, at)| now.duration_since(*at) < MEDIA_TTL);
            if m.len() >= MAX_MEDIA_IDS {
                m.clear();
            }
        }
        m.insert(id.clone(), (url, Instant::now()));
        id
    }

    fn url_of(&self, id: &str) -> Option<String> {
        let m = self.media.lock().unwrap_or_else(|e| e.into_inner());
        m.get(id).filter(|(_, at)| at.elapsed() < MEDIA_TTL).map(|(u, _)| u.clone())
    }
}

fn unavailable(what: &str) -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "RELAY_UNAVAILABLE", format!("this server offers no {what} relay"))
}

fn upstream_error() -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, "RELAY_UPSTREAM", "the upstream did not answer usefully")
}

async fn gif_on(state: &AppState) -> ApiResult<bool> {
    Ok(state.cfg.gif_provider_url.is_some() && features::is_applied(&state.db, GIF_RELAY).await?)
}

async fn map_on(state: &AppState) -> ApiResult<bool> {
    Ok(state.cfg.map_tile_url.is_some() && features::is_applied(&state.db, MAP_RELAY).await?)
}

/// A URL the relay may fetch: https (http only with `RELAY_ALLOW_HTTP`, for
/// tests), no credentials, and outside tests no IP literal or localhost.
pub fn check_upstream(cfg: &Config, url: &str) -> Option<reqwest::Url> {
    let u = reqwest::Url::parse(url).ok()?;
    let ok_scheme = u.scheme() == "https" || (cfg.relay_allow_http && u.scheme() == "http");
    if !ok_scheme || !u.username().is_empty() || u.password().is_some() {
        return None;
    }
    let host = u.host_str()?.to_ascii_lowercase();
    let ip_literal = host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().is_ok();
    if !cfg.relay_allow_http && (host == "localhost" || host.ends_with(".localhost") || ip_literal) {
        return None;
    }
    Some(u)
}

/// Fetches `url` and returns its bytes and type if it is an image or a
/// video of at most `RELAY_MAX_BYTES`.
async fn fetch_media(state: &AppState, url: reqwest::Url) -> ApiResult<(Vec<u8>, String)> {
    let mut resp = state.relay.http.get(url).send().await.map_err(|_| upstream_error())?;
    if !resp.status().is_success() {
        return Err(upstream_error());
    }
    let mime = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .unwrap_or_default();
    if !(mime.starts_with("image/") || mime.starts_with("video/")) {
        return Err(upstream_error());
    }
    let max = state.cfg.relay_max_bytes;
    if resp.content_length().is_some_and(|n| n as usize > max) {
        return Err(upstream_error());
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| upstream_error())? {
        if out.len() + chunk.len() > max {
            return Err(upstream_error());
        }
        out.extend_from_slice(&chunk);
    }
    Ok((out, mime))
}

fn bytes_response(bytes: Vec<u8>, mime: &str) -> ApiResult<Response> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
        .map_err(|_| upstream_error())
}

/// `GET /v1/relay` — public: which relays this server offers.
pub async fn status(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "gif": gif_on(&state).await?, "map": map_on(&state).await? })))
}

#[derive(Deserialize)]
pub struct SearchReq {
    pub q: String,
    #[serde(default)]
    pub limit: Option<usize>,
}
json_body!(SearchReq, |_cfg| 4 * MAX_QUERY + 64);

/// One result as the provider describes it (the provider contract,
/// SERVER_API.md "Relays").
#[derive(Deserialize)]
struct ProviderResult {
    #[serde(default)]
    title: String,
    url: String,
    #[serde(default)]
    preview: Option<String>,
    #[serde(default)]
    width: Option<u32>,
    #[serde(default)]
    height: Option<u32>,
}

#[derive(Deserialize)]
struct ProviderReply {
    #[serde(default)]
    results: Vec<ProviderResult>,
}

/// `POST /v1/relay/gif/search` — `{"q": words, "limit": n}`. The server
/// asks the provider `GET <GIF_PROVIDER_URL>?q=<words>&limit=<n>` and
/// answers with titles, sizes and opaque media ids.
pub async fn gif_search(State(state): State<AppState>, req: Signed<SearchReq>) -> ApiResult<Json<Value>> {
    if !gif_on(&state).await? {
        return Err(unavailable("GIF"));
    }
    state.rate_device(&req.device.device_id, 1.0)?;
    let q = req.body.q.trim();
    if q.is_empty() || q.chars().count() > MAX_QUERY {
        return Err(ApiError::bad_request(format!("a search is 1 to {MAX_QUERY} characters")));
    }
    let limit = req.body.limit.unwrap_or(20).clamp(1, MAX_RESULTS);
    let base = state.cfg.gif_provider_url.as_deref().unwrap_or_default();
    let mut url = check_upstream(&state.cfg, base).ok_or_else(|| unavailable("GIF"))?;
    url.query_pairs_mut().append_pair("q", q).append_pair("limit", &limit.to_string());
    let mut r = state.relay.http.get(url).header(header::ACCEPT, "application/json");
    if let Some(k) = &state.cfg.gif_provider_key {
        r = r.bearer_auth(&k.0);
    }
    let resp = r.send().await.map_err(|_| upstream_error())?;
    if !resp.status().is_success() {
        return Err(upstream_error());
    }
    let body = resp.bytes().await.map_err(|_| upstream_error())?;
    if body.len() > state.cfg.relay_max_bytes {
        return Err(upstream_error());
    }
    let reply: ProviderReply = serde_json::from_slice(&body).map_err(|_| upstream_error())?;
    let results: Vec<Value> = reply
        .results
        .into_iter()
        .filter(|r| check_upstream(&state.cfg, &r.url).is_some())
        .take(limit)
        .map(|r| {
            let preview = r.preview.filter(|p| check_upstream(&state.cfg, p).is_some()).map(|p| state.relay.remember(p));
            json!({
                "media": state.relay.remember(r.url),
                "preview": preview,
                "title": r.title.chars().take(200).collect::<String>(),
                "width": r.width,
                "height": r.height,
            })
        })
        .collect();
    Ok(Json(json!({ "results": results })))
}

/// `GET /v1/relay/gif/media/{id}` — the GIF (or its preview) behind a
/// media id from a search, fetched now and passed through, not stored.
pub async fn gif_media(State(state): State<AppState>, Path(id): Path<String>, req: Signed<NoBody>) -> ApiResult<Response> {
    if !gif_on(&state).await? {
        return Err(unavailable("GIF"));
    }
    state.rate_device(&req.device.device_id, 1.0)?;
    let url = state.relay.url_of(&id).ok_or_else(|| ApiError::not_found("unknown or expired media id"))?;
    let url = check_upstream(&state.cfg, &url).ok_or_else(upstream_error)?;
    let (bytes, mime) = fetch_media(&state, url).await?;
    bytes_response(bytes, &mime)
}

/// The tile URL for `z/x/y` from the `MAP_TILE_URL` template, if the
/// coordinates exist at that zoom.
pub fn tile_url(template: &str, z: u32, x: u32, y: u32) -> Option<String> {
    if z > MAX_ZOOM || x >= (1u32 << z) || y >= (1u32 << z) {
        return None;
    }
    Some(template.replace("{z}", &z.to_string()).replace("{x}", &x.to_string()).replace("{y}", &y.to_string()))
}

/// `GET /v1/relay/map/{z}/{x}/{y}` — one map tile through the relay.
pub async fn map_tile(State(state): State<AppState>, Path((z, x, y)): Path<(u32, u32, u32)>, req: Signed<NoBody>) -> ApiResult<Response> {
    if !map_on(&state).await? {
        return Err(unavailable("map"));
    }
    state.rate_device(&req.device.device_id, 0.25)?;
    let template = state.cfg.map_tile_url.as_deref().unwrap_or_default();
    let url = tile_url(template, z, x, y).ok_or_else(|| ApiError::bad_request("no such tile"))?;
    let url = check_upstream(&state.cfg, &url).ok_or_else(|| unavailable("map"))?;
    let (bytes, mime) = fetch_media(&state, url).await?;
    if !mime.starts_with("image/") {
        return Err(upstream_error());
    }
    bytes_response(bytes, &mime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiles_and_upstreams_are_checked() {
        let t = "https://tiles.example/{z}/{x}/{y}.png";
        assert_eq!(tile_url(t, 2, 3, 1).as_deref(), Some("https://tiles.example/2/3/1.png"));
        assert_eq!(tile_url(t, 0, 0, 0).as_deref(), Some("https://tiles.example/0/0/0.png"));
        assert!(tile_url(t, 2, 4, 0).is_none() && tile_url(t, 2, 0, 4).is_none());
        assert!(tile_url(t, MAX_ZOOM + 1, 0, 0).is_none());
        let mut cfg = Config::default();
        assert!(check_upstream(&cfg, "https://media.example/a.gif").is_some());
        for bad in ["http://media.example/a.gif", "https://u:p@media.example/a", "https://127.0.0.1/a", "https://[::1]/a", "https://localhost/a", "file:///etc/passwd", "nonsense"] {
            assert!(check_upstream(&cfg, bad).is_none(), "{bad}");
        }
        cfg.relay_allow_http = true;
        assert!(check_upstream(&cfg, "http://127.0.0.1:9/a").is_some());
    }

    #[test]
    fn media_ids_are_opaque_and_expire() {
        let r = Relay::new();
        let id = r.remember("https://media.example/x.gif".into());
        assert!(!id.contains("media.example"));
        assert_eq!(r.url_of(&id).as_deref(), Some("https://media.example/x.gif"));
        assert_eq!(r.url_of("unknown"), None);
        r.media.lock().unwrap().get_mut(&id).unwrap().1 = Instant::now() - MEDIA_TTL - Duration::from_secs(1);
        assert_eq!(r.url_of(&id), None);
    }
}
