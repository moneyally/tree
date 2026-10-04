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
//!
//! Every upstream host name is resolved by the relay itself and only public
//! addresses are kept (no loopback, private, link-local and metadata,
//! carrier-grade NAT, unique-local, multicast, documentation or reserved
//! ranges, also when wrapped in IPv4-mapped, NAT64 or 6to4 IPv6); the
//! connection goes to exactly the checked addresses (no second lookup, no
//! proxy), so a provider result naming an internal host, or DNS rebinding,
//! reaches nothing inside (F-027).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
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
/// Media ids kept per device: a device's newest ones push out only its own
/// oldest, never other devices' (F-032).
pub const MAX_MEDIA_IDS_PER_DEVICE: usize = 1_000;
/// Highest map zoom level relayed.
pub const MAX_ZOOM: u32 = 19;
/// Upstream timeout.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// Is `ip` an address of the public internet? Everything a relay must not
/// reach is refused: this host, private networks, link-local (cloud
/// metadata services live there), carrier-grade NAT, unique-local,
/// multicast, documentation, benchmarking and reserved ranges, and IPv6
/// forms that carry an IPv4 address (mapped, compatible, NAT64, 6to4) are
/// judged by that address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 carrier-grade NAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || o[0] >= 240) // reserved
}

fn public_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    let embedded = |hi: usize| Ipv4Addr::new((s[hi] >> 8) as u8, s[hi] as u8, (s[hi + 1] >> 8) as u8, s[hi + 1] as u8);
    if let Some(v4) = a.to_ipv4_mapped() {
        return public_v4(v4);
    }
    if s[..6] == [0; 6] {
        // ::/96 (IPv4-compatible), :: and ::1 included.
        return !(a.is_unspecified() || a.is_loopback()) && public_v4(embedded(6));
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        return public_v4(embedded(6)); // NAT64 64:ff9b::/96
    }
    if s[0] == 0x2002 {
        return public_v4(embedded(1)); // 6to4
    }
    !((s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local
        || (s[0] & 0xff00) == 0xff00 // multicast
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x0100 && s[1..4] == [0; 3])) // 100::/64 discard
}

/// Resolves upstream host names itself and keeps only public addresses;
/// reqwest connects to exactly these (F-027).
struct PublicOnly {
    allow_private: bool,
}

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow = self.allow_private;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.filter(|a| allow || is_public(a.ip())).collect();
            if addrs.is_empty() {
                return Err("the upstream host has no public address".into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[derive(Default)]
struct MediaIds {
    /// id -> (upstream URL, when made, device it was made for).
    urls: HashMap<String, (String, Instant, String)>,
    /// Ids per device, oldest first; and every id in the order made (both
    /// may still name ids already dropped, which are skipped).
    by_device: HashMap<String, VecDeque<String>>,
    order: VecDeque<String>,
}

/// The relay's memory: media ids handed out by searches, and the HTTP
/// client used for upstream requests (no redirects, no cookies, no proxy, a
/// fixed user agent, nothing from the device's request, public addresses
/// only).
pub struct Relay {
    media: Mutex<MediaIds>,
    http: reqwest::Client,
}

impl Default for Relay {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Relay {
    /// `allow_private`: also reach private and loopback addresses (only with
    /// `RELAY_ALLOW_HTTP`, for tests against a local upstream).
    pub fn new(allow_private: bool) -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(PublicOnly { allow_private }))
            .timeout(TIMEOUT)
            .user_agent("tree-relay/1")
            .build()
            .expect("HTTP client");
        Self { media: Mutex::new(MediaIds::default()), http }
    }

    /// An opaque id for an upstream URL the provider returned to `device`.
    /// Beyond [`MAX_MEDIA_IDS_PER_DEVICE`] that device's oldest id goes;
    /// beyond [`MAX_MEDIA_IDS`] expired ids go, then the oldest of all.
    fn remember(&self, device: &str, url: String) -> String {
        let id = crate::util::new_id();
        let now = Instant::now();
        let mut m = self.media.lock().unwrap_or_else(|e| e.into_inner());
        let MediaIds { urls, by_device, order } = &mut *m;
        let mine = by_device.entry(device.to_string()).or_default();
        mine.retain(|i| urls.contains_key(i));
        while mine.len() >= MAX_MEDIA_IDS_PER_DEVICE {
            if let Some(old) = mine.pop_front() {
                urls.remove(&old);
            }
        }
        mine.push_back(id.clone());
        // Oldest first: drop ids already gone, expired ones, and while full.
        while let Some(front) = order.front() {
            let drop = match urls.get(front) {
                None => true,
                Some((_, at, _)) => urls.len() >= MAX_MEDIA_IDS || now.duration_since(*at) >= MEDIA_TTL,
            };
            if !drop {
                break;
            }
            let old = order.pop_front().expect("front exists");
            if let Some((_, _, dev)) = urls.remove(&old) {
                if let Some(ids) = by_device.get_mut(&dev) {
                    ids.retain(|i| *i != old);
                    if ids.is_empty() {
                        by_device.remove(&dev);
                    }
                }
            }
        }
        urls.insert(id.clone(), (url, now, device.to_string()));
        order.push_back(id.clone());
        id
    }

    fn url_of(&self, id: &str) -> Option<String> {
        let m = self.media.lock().unwrap_or_else(|e| e.into_inner());
        m.urls.get(id).filter(|(_, at, _)| at.elapsed() < MEDIA_TTL).map(|(u, _, _)| u.clone())
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
            let dev = req.device.device_id.as_str();
            let preview = r.preview.filter(|p| check_upstream(&state.cfg, p).is_some()).map(|p| state.relay.remember(dev, p));
            json!({
                "media": state.relay.remember(dev, r.url),
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
        let r = Relay::new(false);
        let id = r.remember("dev", "https://media.example/x.gif".into());
        assert!(!id.contains("media.example"));
        assert_eq!(r.url_of(&id).as_deref(), Some("https://media.example/x.gif"));
        assert_eq!(r.url_of("unknown"), None);
        r.media.lock().unwrap().urls.get_mut(&id).unwrap().1 = Instant::now() - MEDIA_TTL - Duration::from_secs(1);
        assert_eq!(r.url_of(&id), None);
    }

    /// F-032: one device asking for many ids pushes out only its own oldest
    /// ones; before, the whole map was cleared for everyone.
    #[test]
    fn one_device_cannot_flush_everyone_elses_media_ids() {
        let r = Relay::new(false);
        // Globally full (many devices): the oldest go one by one, the newest
        // stay; nothing is cleared at once.
        let first = r.remember("early", "https://media.example/first.gif".into());
        let second = r.remember("early", "https://media.example/second.gif".into());
        let mut last = String::new();
        for i in 0..(MAX_MEDIA_IDS - 1) {
            last = r.remember(&format!("dev{}", i % 100), format!("https://media.example/f{i}.gif"));
        }
        assert!(r.url_of(&first).is_none(), "the oldest went");
        assert!(r.url_of(&second).is_some(), "only one went");
        assert!(r.url_of(&last).is_some());
        assert_eq!(r.media.lock().unwrap().urls.len(), MAX_MEDIA_IDS);
        // Per device: at most MAX_MEDIA_IDS_PER_DEVICE kept, its newest.
        let one = Relay::new(false);
        let keep = one.remember("victim", "https://media.example/keep.gif".into());
        let flood: Vec<String> = (0..(MAX_MEDIA_IDS_PER_DEVICE + 100)).map(|i| one.remember("flood", format!("https://media.example/{i}.gif"))).collect();
        assert_eq!(one.url_of(&keep).as_deref(), Some("https://media.example/keep.gif"), "the victim's id survives");
        assert!(one.url_of(&flood[0]).is_none(), "the flooder's oldest went");
        assert!(one.url_of(flood.last().unwrap()).is_some());
        let m = one.media.lock().unwrap();
        assert_eq!(m.urls.len(), MAX_MEDIA_IDS_PER_DEVICE + 1);
    }

    /// F-027: only public addresses are reached, also through IPv6 forms
    /// that carry an IPv4 address.
    #[test]
    fn only_public_addresses() {
        for bad in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "255.255.255.255",
            "224.0.0.1", "192.0.2.1", "198.18.0.1", "240.0.0.1", "192.0.0.8", "::1", "::", "fc00::1", "fd12::1", "fe80::1", "ff02::1",
            "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::127.0.0.1", "64:ff9b::a00:1", "2002:a00:1::1",
            "2001:db8::1", "fec0::1",
        ] {
            assert!(!is_public(bad.parse().unwrap()), "{bad}");
        }
        for good in ["93.184.216.34", "1.1.1.1", "2606:4700::1111", "::ffff:93.184.216.34", "64:ff9b::5db8:d822", "2002:5db8:d822::1"] {
            assert!(is_public(good.parse().unwrap()), "{good}");
        }
    }

    /// F-027: a host name that resolves to this machine is not fetched,
    /// though the URL passed the name checks; the address is checked at
    /// connection time by the relay's own resolver.
    #[tokio::test]
    async fn a_name_resolving_inside_is_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://localhost:{port}/x.gif");
        let strict = Relay::new(false);
        let e = strict.http.get(&url).send().await.unwrap_err();
        let mut chain = String::new();
        let mut src: Option<&dyn std::error::Error> = Some(&e);
        while let Some(s) = src {
            chain.push_str(&s.to_string());
            chain.push('|');
            src = s.source();
        }
        assert!(chain.contains("no public address"), "{chain}");
        // Control: the same request is made when private addresses are allowed (tests).
        let open = Relay::new(true);
        let fetch = tokio::spawn(async move { open.http.get(&url).timeout(Duration::from_secs(2)).send().await });
        let (conn, _) = listener.accept().await.unwrap();
        drop(conn);
        let _ = fetch.await;
    }
}
