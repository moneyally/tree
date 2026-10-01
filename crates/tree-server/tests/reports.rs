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
