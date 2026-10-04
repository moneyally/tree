//! Group invite links (PROTOCOL.md 8.7).

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use tree_server::invites::token_hash;

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

async fn create(api: &Api, dev: &Device, token: &[u8; 16], lifetime: i64, max_uses: i64) -> (StatusCode, Value) {
    let body = json!({ "token_hash": b64(&token_hash(token)), "lifetime": lifetime, "max_uses": max_uses });
    api.call(dev, Method::POST, "/v1/invites", Some(body)).await
}

async fn join(api: &Api, dev: &Device, token: &[u8]) -> (StatusCode, Value) {
    api.call(dev, Method::POST, "/v1/invites/join", Some(json!({ "token": b64(token) }))).await
}

#[tokio::test]
async fn links_limits_requests() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (owner, a, b, c) = (api.signup().await, api.signup().await, api.signup().await, api.signup().await);
    let other_owner_device = api.add_device(&owner).await;
    let t = [7u8; 16];

    for (life, uses) in [(59, 1), (30 * 86400 + 1, 1), (3600, 0), (3600, 10_001)] {
        assert_eq!(create(api, &owner, &t, life, uses).await.0, StatusCode::BAD_REQUEST, "{life} {uses}");
    }
    assert_eq!(create(api, &owner, &[6u8; 16], 30 * 86400, 10_000).await.0, StatusCode::CREATED, "the limits themselves");
    assert_eq!(create(api, &owner, &t, 3600, 2).await.0, StatusCode::CREATED);
    let (st, v) = create(api, &a, &t, 3600, 2).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"));

    // Wrong or malformed tokens; the owner's own account.
    assert_eq!(join(api, &a, &[8u8; 16]).await.0, StatusCode::NOT_FOUND);
    assert_eq!(join(api, &a, &[7u8; 15]).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(join(api, &other_owner_device, &t).await.0, StatusCode::BAD_REQUEST);

    // Two uses: a (twice: counts once) and b; c finds it used up.
    let (st, v) = join(api, &a, &t).await;
    assert_eq!((st, v["owner_account"].as_str()), (StatusCode::ACCEPTED, Some(owner.account_id.as_str())));
    assert_eq!(join(api, &a, &t).await.0, StatusCode::ACCEPTED);
    assert_eq!(join(api, &b, &t).await.0, StatusCode::ACCEPTED);
    assert_eq!(join(api, &c, &t).await.0, StatusCode::NOT_FOUND);

    // Only the owner's device sees the requests.
    let (_, v) = api.call(&other_owner_device, Method::GET, "/v1/invites/requests", None).await;
    assert_eq!(v["requests"], json!([]));
    let (_, v) = api.call(&owner, Method::GET, "/v1/invites/requests", None).await;
    let reqs = v["requests"].as_array().unwrap();
    let accounts: Vec<&str> = reqs.iter().map(|r| r["account_id"].as_str().unwrap()).collect();
    assert_eq!(accounts, vec![a.account_id.as_str(), b.account_id.as_str()]);
    assert_eq!(reqs[0]["token_hash"], b64(&token_hash(&t)));
    let ids: Vec<&str> = reqs.iter().map(|r| r["id"].as_str().unwrap()).collect();
    // Another device cannot acknowledge them.
    let (_, v) = api.call(&a, Method::POST, "/v1/invites/requests/ack", Some(json!({ "ids": ids }))).await;
    assert_eq!(v["deleted"], 0);
    let (_, v) = api.call(&owner, Method::POST, "/v1/invites/requests/ack", Some(json!({ "ids": ids }))).await;
    assert_eq!(v["deleted"], 2);
    let (_, v) = api.call(&owner, Method::GET, "/v1/invites/requests", None).await;
    assert_eq!(v["requests"], json!([]));
    let many: Vec<String> = (0..101).map(|_| "A".repeat(22)).collect();
    let (st, _) = api.call(&owner, Method::POST, "/v1/invites/requests/ack", Some(json!({ "ids": many }))).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);

    // Revoke: only the owner device; then the link is gone.
    let t2 = [9u8; 16];
    assert_eq!(create(api, &owner, &t2, 3600, 5).await.0, StatusCode::CREATED);
    let path = format!("/v1/invites/{}", URL_SAFE_NO_PAD.encode(token_hash(&t2)));
    assert_eq!(api.call(&a, Method::DELETE, &path, None).await.0, StatusCode::OK);
    assert_eq!(join(api, &c, &t2).await.0, StatusCode::ACCEPTED, "a stranger's revoke changes nothing");
    assert_eq!(api.call(&owner, Method::DELETE, &path, None).await.0, StatusCode::OK);
    assert_eq!(join(api, &b, &t2).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.call(&owner, Method::DELETE, "/v1/invites/!!", None).await.0, StatusCode::BAD_REQUEST);

    // Expiry: an expired link refuses joins; purged a week later.
    let t3 = [3u8; 16];
    assert_eq!(create(api, &owner, &t3, 60, 5).await.0, StatusCode::CREATED);
    sqlx::query("UPDATE invites SET expires_at = expires_at - 61").execute(&ts.server.state.db).await.unwrap();
    assert_eq!(join(api, &a, &t3).await.0, StatusCode::NOT_FOUND);
    let now = tree_server::util::now_secs();
    tree_server::invites::purge(&ts.server.state.db, now).await.unwrap();
    let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invites").fetch_one(&ts.server.state.db).await.unwrap();
    assert_eq!(n.0, 3, "kept for a week after expiry");
    assert_eq!(tree_server::invites::purge(&ts.server.state.db, now + 6 * 86400).await.unwrap(), 0);
    assert_eq!(tree_server::invites::purge(&ts.server.state.db, now + 8 * 86400).await.unwrap(), 2, "the 30-day link stays");
    ts.stop().await;
}

#[tokio::test]
async fn open_links_per_device_are_limited() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let o = api.signup().await;
    for i in 0..100u8 {
        assert_eq!(create(api, &o, &[i; 16], 3600, 1).await.0, StatusCode::CREATED);
    }
    let (st, v) = create(api, &o, &[200; 16], 3600, 1).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "LIMIT_EXCEEDED"));
    // Expired ones do not count.
    sqlx::query("UPDATE invites SET expires_at = 0 WHERE token_hash = ?").bind(&token_hash(&[0; 16])[..]).execute(&ts.server.state.db).await.unwrap();
    assert_eq!(create(api, &o, &[200; 16], 3600, 1).await.0, StatusCode::CREATED);
    ts.stop().await;
}

#[tokio::test]
async fn ack_takes_up_to_100_ids() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let o = api.signup().await;
    let ids: Vec<String> = (0..100).map(|_| "A".repeat(22)).collect();
    let (st, v) = api.call(&o, Method::POST, "/v1/invites/requests/ack", Some(json!({ "ids": ids }))).await;
    assert_eq!((st, &v["deleted"]), (StatusCode::OK, &json!(0)), "{v}");
    ts.stop().await;
}

#[tokio::test]
async fn a_database_failure_is_not_reported_as_a_duplicate() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let o = api.signup().await;
    sqlx::raw_sql("CREATE TRIGGER fail_invite BEFORE INSERT ON invites BEGIN SELECT RAISE(ABORT, 'injected'); END")
        .execute(&ts.server.state.db)
        .await
        .unwrap();
    let (st, v) = create(api, &o, &[1; 16], 3600, 1).await;
    assert_eq!((st, code(&v)), (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL"), "{v}");
    sqlx::raw_sql("DROP TRIGGER fail_invite").execute(&ts.server.state.db).await.unwrap();
    assert_eq!(create(api, &o, &[1; 16], 3600, 1).await.0, StatusCode::CREATED);
    ts.stop().await;
}
