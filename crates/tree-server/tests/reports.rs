//! Reports with message franking, and account suspension (PROTOCOL.md 8.5).

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use tree_server::reports::commitment;

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

async fn op(api: &Api, token: Option<&str>, method: Method, path: &str) -> (StatusCode, Value) {
    let mut rb = api.http.request(method, api.url(path));
    if let Some(t) = token {
        rb = rb.header("X-Tree-Admin", t);
    }
    decode(rb.send().await.unwrap()).await
}

/// What a sender's device does for one message: commit, get a tag.
async fn frank(api: &Api, dev: &Device, group: &[u8], payload: &str) -> Value {
    let k = [9u8; 32];
    let com = commitment(&k, group, payload.as_bytes());
    let (st, v) = api.call(dev, Method::POST, "/v1/franking", Some(json!({ "com": b64(&com) }))).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    json!({ "payload": payload, "key": b64(&k), "tag": v["tag"], "minute": v["minute"], "group_id": b64(group) })
}

#[tokio::test]
async fn report_review_suspend() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (alice, bob, carol) = (api.signup().await, api.signup().await, api.signup().await);
    let msg = r#"{"t":"text","id":"00","text":"bad words"}"#;
    let franked = frank(api, &alice, b"group-1", msg).await;

    // Genuine message, right sender: verified.
    let report = |who: &str, messages: Vec<Value>| json!({ "reported_account": who, "reason": "abuse", "messages": messages });
    let (st, v) = api.call(&bob, Method::POST, "/v1/reports", Some(report(&alice.account_id, vec![franked.clone()]))).await;
    assert_eq!((st, v["verified"].as_bool()), (StatusCode::CREATED, Some(true)), "{v}");

    // Bob cannot frame carol with alice's message, nor alter the text.
    let (_, v) = api.call(&bob, Method::POST, "/v1/reports", Some(report(&carol.account_id, vec![franked.clone()]))).await;
    assert_eq!(v["verified"], false);
    let mut altered = franked.clone();
    altered["payload"] = json!(r#"{"t":"text","id":"00","text":"worse words"}"#);
    let (_, v) = api.call(&bob, Method::POST, "/v1/reports", Some(report(&alice.account_id, vec![franked.clone(), altered]))).await;
    assert_eq!(v["verified"], false, "one bad message makes the report unverified");

    // Limits.
    let (st, _) = api.call(&bob, Method::POST, "/v1/reports", Some(report(&alice.account_id, vec![]))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = api.call(&bob, Method::POST, "/v1/reports", Some(report(&alice.account_id, vec![franked.clone(); 21]))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = api.call(&bob, Method::POST, "/v1/reports", Some(json!({ "reported_account": alice.account_id, "reason": "x".repeat(501), "messages": [franked] }))).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    let (st, _) = api.call(&bob, Method::POST, "/v1/reports", Some(report("not an id", vec![frank(api, &alice, b"g", "{}").await]))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Unknown accounts cannot be reported.
    let (st, _) = api.call(&bob, Method::POST, "/v1/reports", Some(report(&"A".repeat(22), vec![franked.clone()]))).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Operator review: needs the token.
    assert_eq!(op(api, None, Method::GET, "/v1/reports").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(op(api, Some("wrong"), Method::GET, "/v1/reports").await.0, StatusCode::UNAUTHORIZED);
    let (st, v) = op(api, Some(ADMIN_TOKEN), Method::GET, "/v1/reports").await;
    assert_eq!(st, StatusCode::OK);
    let reports = v["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 3);
    let first = reports.iter().find(|r| r["verified"] == true).unwrap();
    assert_eq!(first["reporter_account"], bob.account_id.as_str());
    assert_eq!(first["messages"][0]["payload"], msg);
    let id = first["id"].as_str().unwrap();

    // Suspend alice: everything she signs is refused, until released.
    let path = format!("/v1/accounts/{}/suspend/apply", alice.account_id);
    assert_eq!(op(api, None, Method::POST, &path).await.0, StatusCode::UNAUTHORIZED);
    let (st, v) = op(api, Some(ADMIN_TOKEN), Method::POST, &path).await;
    assert_eq!((st, v["state"].as_str()), (StatusCode::OK, Some("applied")));
    assert_eq!(op(api, Some(ADMIN_TOKEN), Method::POST, &path).await.1["state"], "applied", "idempotent");
    let (st, v) = api.call(&alice, Method::POST, "/v1/franking", Some(json!({ "com": b64(&[0; 32]) }))).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "SUSPENDED"));
    let (st, v) = api.send_raw(&alice, &[&bob.device_id], &app(b"hi")).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "SUSPENDED"));
    assert_eq!(api.send_raw(&bob, &[&alice.device_id], &app(b"hi")).await.0, StatusCode::OK, "others are unaffected");
    let (st, v) = op(api, Some(ADMIN_TOKEN), Method::POST, &format!("/v1/accounts/{}/suspend/release", alice.account_id)).await;
    assert_eq!((st, v["state"].as_str()), (StatusCode::OK, Some("released")));
    assert_eq!(api.send_raw(&alice, &[&bob.device_id], &app(b"hi")).await.0, StatusCode::OK);
    assert_eq!(op(api, Some(ADMIN_TOKEN), Method::POST, &format!("/v1/accounts/{}/suspend/other", alice.account_id)).await.0, StatusCode::NOT_FOUND);

    // Resolve.
    assert_eq!(op(api, None, Method::POST, &format!("/v1/reports/{id}/resolve")).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(op(api, Some(ADMIN_TOKEN), Method::POST, &format!("/v1/reports/{id}/resolve")).await.0, StatusCode::OK);
    assert_eq!(op(api, Some(ADMIN_TOKEN), Method::POST, &format!("/v1/reports/{}/resolve", "A".repeat(22))).await.0, StatusCode::NOT_FOUND);
    let (_, v) = op(api, Some(ADMIN_TOKEN), Method::GET, "/v1/reports").await;
    assert_eq!(v["reports"].as_array().unwrap().len(), 2);
    ts.stop().await;
}

#[tokio::test]
async fn franking_key_survives_restart_and_tags_need_32_bytes() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let (st, _) = api.call(&a, Method::POST, "/v1/franking", Some(json!({ "com": b64(&[0; 31]) }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let k1 = tree_server::reports::franking_key(&tree_server::open_db(&format!("sqlite://{}/tree.db", ts.dir.display())).await.unwrap()).await.unwrap();
    let k2 = tree_server::reports::franking_key(&tree_server::open_db(&format!("sqlite://{}/tree.db", ts.dir.display())).await.unwrap()).await.unwrap();
    assert_eq!(k1, k2);
    // The running server uses the same key: its tag checks against k1.
    let com = commitment(&[1; 32], b"g", b"p");
    let (_, v) = api.call(&a, Method::POST, "/v1/franking", Some(json!({ "com": b64(&com) }))).await;
    let want = tree_server::reports::tag(&k1, &com, &a.account_id, v["minute"].as_i64().unwrap());
    assert_eq!(unb64(v["tag"].as_str().unwrap()), want);
    ts.stop().await;
}

#[tokio::test]
async fn reports_per_day_are_limited_and_resolved_ones_purged() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let m = frank(api, &a, b"g", "{}").await;
    let body = json!({ "reported_account": a.account_id, "reason": "x", "messages": [m] });
    for _ in 0..tree_server::reports::MAX_PER_DAY {
        assert_eq!(api.call(&b, Method::POST, "/v1/reports", Some(body.clone())).await.0, StatusCode::CREATED);
    }
    let (st, v) = api.call(&b, Method::POST, "/v1/reports", Some(body.clone())).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "LIMIT_EXCEEDED"));
    // Large payloads are refused.
    let mut big = frank(api, &a, b"g", "{}").await;
    big["payload"] = json!("x".repeat(16 * 1024 + 1));
    let (st, _) = api.call(&a, Method::POST, "/v1/reports", Some(json!({ "reported_account": b.account_id, "reason": "x", "messages": [big] }))).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);

    // Resolved reports are deleted 30 days after resolution; open ones stay.
    let (_, v) = op(api, Some(ADMIN_TOKEN), Method::GET, "/v1/reports").await;
    let id = v["reports"][0]["id"].as_str().unwrap().to_string();
    op(api, Some(ADMIN_TOKEN), Method::POST, &format!("/v1/reports/{id}/resolve")).await;
    let today = tree_server::util::today();
    let db = &ts.server.state.db;
    assert_eq!(tree_server::reports::purge(db, today + 30).await.unwrap(), 0);
    assert_eq!(tree_server::reports::purge(db, today + 31).await.unwrap(), 1);
    let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM reports").fetch_one(db).await.unwrap();
    assert_eq!(n.0, tree_server::reports::MAX_PER_DAY - 1);
    ts.stop().await;
}

#[tokio::test]
async fn a_damaged_franking_key_is_an_error_not_a_new_key() {
    let ts = boot(|_| {}).await;
    let db = &ts.server.state.db;
    tree_server::reports::franking_key(db).await.unwrap();
    sqlx::query("UPDATE server_secrets SET value = x'0102' WHERE name = 'franking'").execute(db).await.unwrap();
    assert!(tree_server::reports::franking_key(db).await.is_err());
    ts.stop().await;
}

#[tokio::test]
async fn report_limits_are_exact() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let m = frank(api, &a, b"g", "{}").await;
    let send = |messages: Vec<Value>, reason: String| {
        let body = json!({ "reported_account": a.account_id, "reason": reason, "messages": messages });
        api.call(&b, Method::POST, "/v1/reports", Some(body))
    };
    assert_eq!(send(vec![m.clone(); 20], "x".into()).await.0, StatusCode::CREATED, "20 messages");
    assert_eq!(send(vec![m.clone()], "가".repeat(500)).await.0, StatusCode::CREATED, "500 characters");
    let mut big = m.clone();
    big["payload"] = json!("x".repeat(16 * 1024));
    assert_eq!(send(vec![big], "x".into()).await.0, StatusCode::CREATED, "exactly 16 KiB");
    ts.stop().await;
}

/// The franking key is 32 random bytes per server, and only a 32-byte
/// franking key is accepted in a report (HMAC would treat a shorter key
/// padded with zeros as the same key).
#[tokio::test]
async fn franking_keys_are_random_and_exact() {
    let ts1 = boot(|_| {}).await;
    let ts2 = boot(|_| {}).await;
    let k1 = tree_server::reports::franking_key(&ts1.server.state.db).await.unwrap();
    let k2 = tree_server::reports::franking_key(&ts2.server.state.db).await.unwrap();
    assert_ne!(k1, k2);
    assert!(k1 != [0; 32] && k1 != [1; 32]);

    let api = &ts1.api;
    let (a, b) = (api.signup().await, api.signup().await);
    // A franking key ending in a zero byte: the same HMAC key as its first
    // 31 bytes.
    let mut k = [7u8; 32];
    k[31] = 0;
    let com = commitment(&k, b"g", b"{}");
    let (_, v) = api.call(&a, Method::POST, "/v1/franking", Some(json!({ "com": b64(&com) }))).await;
    let msg = |key: &[u8]| json!({ "payload": "{}", "key": b64(key), "tag": v["tag"], "minute": v["minute"], "group_id": b64(b"g") });
    let report = |key: &[u8]| json!({ "reported_account": a.account_id, "reason": "x", "messages": [msg(key)] });
    assert_eq!(api.call(&b, Method::POST, "/v1/reports", Some(report(&k))).await.1["verified"], true);
    assert_eq!(api.call(&b, Method::POST, "/v1/reports", Some(report(&k[..31]))).await.1["verified"], false);
    ts1.stop().await;
    ts2.stop().await;
}
