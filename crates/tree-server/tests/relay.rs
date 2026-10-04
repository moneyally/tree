//! GIF and map relays (PROTOCOL.md 8.12) against a fake upstream over HTTP:
//! off without a provider or while the operator flag is released (503),
//! nothing of the device reaches the upstream, only URLs the provider
//! returned are fetched, and answers are limited to images and videos.

mod common;

use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use common::*;
use reqwest::{Method, StatusCode};
use serde_json::json;

/// (path, headers) of every request the upstream got.
type Seen = Arc<Mutex<Vec<(String, HeaderMap)>>>;

#[derive(Clone)]
struct Upstream {
    seen: Seen,
    base: Arc<Mutex<String>>,
}

async fn search(State(u): State<Upstream>, Query(q): Query<Vec<(String, String)>>, h: HeaderMap) -> impl IntoResponse {
    u.seen.lock().unwrap().push((format!("/search?{}", q.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")), h));
    let b = u.base.lock().unwrap().clone();
    axum::Json(json!({ "results": [
        { "title": "dog", "url": format!("{b}/media/dog.gif"), "preview": format!("{b}/media/dog-small.gif"), "width": 320, "height": 240 },
        { "title": "html", "url": format!("{b}/media/page.html") },
        { "title": "huge", "url": format!("{b}/media/huge.gif") },
        { "title": "creds", "url": "http://user:pw@127.0.0.1:1/x.gif" },
    ]}))
}

async fn media(State(u): State<Upstream>, Path(name): Path<String>, h: HeaderMap) -> impl IntoResponse {
    u.seen.lock().unwrap().push((format!("/media/{name}"), h));
    match name.as_str() {
        "page.html" => ([(header::CONTENT_TYPE, "text/html")], b"<html>".to_vec()),
        "huge.gif" => ([(header::CONTENT_TYPE, "image/gif")], vec![7u8; 5000]),
        _ => ([(header::CONTENT_TYPE, "image/gif")], format!("GIF89a {name}").into_bytes()),
    }
}

async fn tile(State(u): State<Upstream>, Path((z, x, y)): Path<(u32, u32, String)>, h: HeaderMap) -> impl IntoResponse {
    u.seen.lock().unwrap().push((format!("/tiles/{z}/{x}/{y}"), h));
    ([(header::CONTENT_TYPE, "image/png")], format!("PNG {z}/{x}/{y}").into_bytes())
}

async fn upstream() -> (Upstream, String) {
    let u = Upstream { seen: Arc::default(), base: Arc::default() };
    let app = Router::new()
        .route("/search", get(search))
        .route("/media/{name}", get(media))
        .route("/tiles/{z}/{x}/{y}", get(tile))
        .with_state(u.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    *u.base.lock().unwrap() = base.clone();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (u, base)
}

/// A signed GET answered with bytes.
async fn get_bytes(api: &Api, dev: &Device, path: &str) -> (StatusCode, Vec<u8>, String) {
    let s = Signed::new(Method::GET, path, Some(&dev.device_id), None);
    let resp = api
        .http
        .get(api.url(path))
        .header("X-Tree-Device", &dev.device_id)
        .header("X-Tree-Timestamp", s.ts.to_string())
        .header("X-Tree-Nonce", &s.nonce)
        .header("X-Tree-Signature", s.signature(&dev.key))
        // A client address the relay must never pass on.
        .header("X-Forwarded-For", "203.0.113.7")
        .send()
        .await
        .unwrap();
    let st = resp.status();
    let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    (st, resp.bytes().await.unwrap().to_vec(), ct)
}

async fn search_as(api: &Api, dev: &Device, q: &str) -> (StatusCode, serde_json::Value) {
    api.call(dev, Method::POST, "/v1/relay/gif/search", Some(json!({ "q": q, "limit": 10 }))).await
}

#[tokio::test]
async fn no_provider_means_503() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let dev = api.signup().await;
    // Applied, but nothing configured: still unavailable.
    for key in ["server.gif_relay", "server.map_relay"] {
        assert_eq!(api.admin(Some(ADMIN_TOKEN), key, "apply").await.0, StatusCode::OK);
    }
    let (st, v) = decode(api.http.get(api.url("/v1/relay")).send().await.unwrap()).await;
    assert_eq!((st, v), (StatusCode::OK, json!({ "gif": false, "map": false })));
    let (st, v) = search_as(api, &dev, "cat").await;
    assert_eq!((st, v["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("RELAY_UNAVAILABLE")));
    assert_eq!(get_bytes(api, &dev, "/v1/relay/gif/media/abc").await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(get_bytes(api, &dev, "/v1/relay/map/1/0/0").await.0, StatusCode::SERVICE_UNAVAILABLE);
    ts.stop().await;
}

#[tokio::test]
async fn relays_pass_nothing_of_the_device_upstream() {
    let (up, base) = upstream().await;
    let ts = boot(|c| {
        c.gif_provider_url = Some(format!("{base}/search"));
        c.gif_provider_key = Some(tree_server::config::Secret("test-provider-key".into()));
        c.map_tile_url = Some(format!("{base}/tiles/{{z}}/{{x}}/{{y}}"));
        c.relay_allow_http = true;
        c.relay_max_bytes = 1000;
    })
    .await;
    let api = &ts.api;
    let dev = api.signup().await;

    // Configured, but the flags start released.
    let (_, v) = decode(api.http.get(api.url("/v1/relay")).send().await.unwrap()).await;
    assert_eq!(v, json!({ "gif": false, "map": false }));
    assert_eq!(search_as(api, &dev, "dog").await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(up.seen.lock().unwrap().is_empty());
    for key in ["server.gif_relay", "server.map_relay"] {
        assert_eq!(api.admin(Some(ADMIN_TOKEN), key, "apply").await.0, StatusCode::OK);
    }
    let (_, v) = decode(api.http.get(api.url("/v1/relay")).send().await.unwrap()).await;
    assert_eq!(v, json!({ "gif": true, "map": true }));

    // Unsigned requests are refused; bad queries too.
    let (st, _) = decode(api.http.post(api.url("/v1/relay/gif/search")).body(r#"{"q":"dog"}"#).send().await.unwrap()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(search_as(api, &dev, "").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(search_as(api, &dev, &"x".repeat(101)).await.0, StatusCode::BAD_REQUEST);

    // A search: results with opaque media ids; a URL with credentials is left out.
    let (st, v) = search_as(api, &dev, "dog").await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let results = v["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert!(!v.to_string().contains("127.0.0.1"), "no upstream URL reaches the device: {v}");
    let id = |t: &str| results.iter().find(|r| r["title"] == t).unwrap()["media"].as_str().unwrap().to_string();
    assert_eq!(results[0]["width"], 320);

    let (st, body, ct) = get_bytes(api, &dev, &format!("/v1/relay/gif/media/{}", id("dog"))).await;
    assert_eq!((st, body.as_slice(), ct.as_str()), (StatusCode::OK, &b"GIF89a dog.gif"[..], "image/gif"));
    let preview = results[0]["preview"].as_str().unwrap();
    assert_eq!(get_bytes(api, &dev, &format!("/v1/relay/gif/media/{preview}")).await.0, StatusCode::OK);
    // Not an image or video, or larger than allowed: refused.
    assert_eq!(get_bytes(api, &dev, &format!("/v1/relay/gif/media/{}", id("html"))).await.0, StatusCode::BAD_GATEWAY);
    assert_eq!(get_bytes(api, &dev, &format!("/v1/relay/gif/media/{}", id("huge"))).await.0, StatusCode::BAD_GATEWAY);
    // Only ids the provider returned: nothing else can be fetched.
    assert_eq!(get_bytes(api, &dev, "/v1/relay/gif/media/not-an-id").await.0, StatusCode::NOT_FOUND);

    // Map tiles.
    let (st, body, _) = get_bytes(api, &dev, "/v1/relay/map/2/3/1").await;
    assert_eq!((st, body.as_slice()), (StatusCode::OK, &b"PNG 2/3/1"[..]));
    assert_eq!(get_bytes(api, &dev, "/v1/relay/map/2/4/1").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(get_bytes(api, &dev, "/v1/relay/map/20/0/0").await.0, StatusCode::BAD_REQUEST);

    // What the upstream saw: no client address, no device, no Tree headers;
    // the provider's own key only on searches.
    let seen = up.seen.lock().unwrap().clone();
    assert!(seen.iter().any(|(p, _)| p == "/search?q=dog&limit=10"), "{:?}", seen.iter().map(|s| &s.0).collect::<Vec<_>>());
    for (path, h) in &seen {
        for name in ["x-forwarded-for", "forwarded", "x-real-ip", "via", "cookie"] {
            assert!(h.get(name).is_none(), "{path}: {name}");
        }
        assert!(h.keys().all(|k| !k.as_str().starts_with("x-tree")), "{path}: {h:?}");
        for v in h.values() {
            let v = v.to_str().unwrap_or("");
            assert!(!v.contains("203.0.113.7") && !v.contains(&dev.device_id) && !v.contains(&dev.account_id), "{path}: {v}");
        }
        assert_eq!(h.get("user-agent").and_then(|v| v.to_str().ok()), Some("tree-relay/1"));
        let auth = h.get("authorization").and_then(|v| v.to_str().ok());
        if path.starts_with("/search") {
            assert_eq!(auth, Some("Bearer test-provider-key"));
        } else {
            assert_eq!(auth, None, "{path}: the key goes to searches only");
        }
    }

    // Released again: unavailable, the upstream is not asked.
    let n = up.seen.lock().unwrap().len();
    assert_eq!(api.admin(Some(ADMIN_TOKEN), "server.gif_relay", "release").await.0, StatusCode::OK);
    assert_eq!(search_as(api, &dev, "dog").await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(get_bytes(api, &dev, &format!("/v1/relay/gif/media/{}", id("dog"))).await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(api.admin(Some(ADMIN_TOKEN), "server.map_relay", "release").await.0, StatusCode::OK);
    assert_eq!(get_bytes(api, &dev, "/v1/relay/map/2/3/1").await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(up.seen.lock().unwrap().len(), n);
    ts.stop().await;
}
