//! Push wake-ups (PROTOCOL.md 8.8) against a fake gateway over HTTP.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode as AxStatus;
use axum::routing::post;
use axum::Router;
use common::*;
use reqwest::{Method, StatusCode};
use serde_json::json;

/// (endpoint id, body) of every POST the gateway received.
type Received = Vec<(String, Vec<u8>)>;

#[derive(Clone, Default)]
struct Gateway {
    got: Arc<Mutex<Received>>,
}

async fn receive(State(g): State<Gateway>, Path(id): Path<String>, body: axum::body::Bytes) -> AxStatus {
    g.got.lock().unwrap().push((id.clone(), body.to_vec()));
    if id == "gone" { AxStatus::GONE } else { AxStatus::OK }
}

async fn gateway() -> (Gateway, String) {
    let g = Gateway::default();
    let app = Router::new().route("/up/{id}", post(receive)).with_state(g.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (g, format!("http://127.0.0.1:{}", addr.port()))
}

fn count(g: &Gateway, id: &str) -> usize {
    g.got.lock().unwrap().iter().filter(|(i, _)| i == id).count()
}

/// Waits (up to 10 s) until the gateway got `n` wake-ups for `id`.
async fn wait_for(g: &Gateway, id: &str, n: usize) {
    for _ in 0..200 {
        if count(g, id) >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("gateway got {} wake-ups for {id}, wanted {n}", count(g, id));
}

async fn set(api: &Api, dev: &Device, url: String) -> (StatusCode, serde_json::Value) {
    api.call(dev, Method::POST, "/v1/push", Some(json!({ "endpoint": url }))).await
}

#[tokio::test]
async fn wakeups_are_contentless_coalesced_and_only_to_allowed_hosts() {
    let (gw, base) = gateway().await;
    let ts = boot(|c| {
        c.push_allowed_hosts = vec![base.trim_start_matches("http://").to_string()];
        c.push_allow_http = true;
        c.push_interval_secs = 1;
    })
    .await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);

    // Only allowed hosts.
    assert_eq!(set(api, &b, "http://localhost:1/up/x".into()).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(set(api, &b, "http://127.0.0.1:1/up/x".into()).await.0, StatusCode::BAD_REQUEST, "same host, other port");
    assert_eq!(set(api, &b, "http://10.0.0.1/up/x".into()).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(set(api, &b, format!("{base}/up/bob")).await.0, StatusCode::OK);

    // One message: one wake-up with the fixed body.
    api.send_raw(&a, &[&b.device_id], &app(b"secret text")).await;
    wait_for(&gw, "bob", 1).await;
    assert_eq!(gw.got.lock().unwrap()[0].1, b"wake");

    // A burst within the interval: at most one more, later.
    for _ in 0..5 {
        api.send_raw(&a, &[&b.device_id], &app(b"x")).await;
    }
    wait_for(&gw, "bob", 2).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(count(&gw, "bob"), 2, "coalesced");
    // Nothing that is not 'wake' ever went out.
    assert!(gw.got.lock().unwrap().iter().all(|(_, b)| b == b"wake"));

    // Cleared: no more.
    assert_eq!(api.call(&b, Method::DELETE, "/v1/push", None).await.0, StatusCode::OK);
    api.send_raw(&a, &[&b.device_id], &app(b"x")).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(count(&gw, "bob"), 2);

    // A gateway answering 410 Gone makes the server forget the endpoint.
    assert_eq!(set(api, &b, format!("{base}/up/gone")).await.0, StatusCode::OK);
    api.send_raw(&a, &[&b.device_id], &app(b"x")).await;
    wait_for(&gw, "gone", 1).await;
    let mut left = 1;
    for _ in 0..100 {
        let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM push_endpoints").fetch_one(&ts.server.state.db).await.unwrap();
        left = n.0;
        if left == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(left, 0);
    ts.stop().await;
}

#[tokio::test]
async fn push_is_off_unless_configured() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let (st, v) = api.call(&a, Method::POST, "/v1/push", Some(json!({ "endpoint": "https://push.example/x" }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    ts.stop().await;
}
