//! @usernames: hash only, one per account, lookups limited and hideable.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

#[tokio::test]
async fn register_lookup_release() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let h1 = b64(&[1u8; 32]);
    let h2 = b64(&[2u8; 32]);

    let (st, v) = api.call(&a, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": h1 }))).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": h1 }))).await.0, StatusCode::OK, "idempotent");
    let (st, v) = api.call(&b, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": h1 }))).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "USERNAME_TAKEN"));

    let (st, v) = api.call(&b, Method::POST, "/v1/usernames/lookup", Some(json!({ "hash": h1 }))).await;
    assert_eq!((st, v["account_id"].as_str()), (StatusCode::OK, Some(a.account_id.as_str())));
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/lookup", Some(json!({ "hash": h2 }))).await.0, StatusCode::NOT_FOUND);

    // Changing the name frees the old one; one name per account.
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": h2 }))).await.0, StatusCode::OK);
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/lookup", Some(json!({ "hash": h1 }))).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": h1 }))).await.0, StatusCode::OK);

    // Hidden from lookups.
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": h2, "discoverable": false }))).await.0, StatusCode::OK);
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/lookup", Some(json!({ "hash": h2 }))).await.0, StatusCode::NOT_FOUND);
    // ...but still taken.
    let (st, v) = api.call(&b, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": h2 }))).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "USERNAME_TAKEN"));

    // Release, twice.
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/release", None).await.0, StatusCode::OK);
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/release", None).await.0, StatusCode::OK);
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/lookup", Some(json!({ "hash": h2 }))).await.0, StatusCode::NOT_FOUND);

    // Malformed hashes.
    for bad in [json!({ "hash": b64(&[1u8; 31]) }), json!({ "hash": "!!" }), json!({})] {
        assert_eq!(api.call(&a, Method::POST, "/v1/usernames/apply", Some(bad.clone())).await.0, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(api.call(&a, Method::POST, "/v1/usernames/lookup", Some(bad)).await.0, StatusCode::BAD_REQUEST);
    }

    // Only the hash is stored.
    let cols: Vec<(String,)> = sqlx::query_as("SELECT name FROM pragma_table_info('usernames')")
        .fetch_all(&ts.server.state.db)
        .await
        .unwrap();
    let cols: Vec<&str> = cols.iter().map(|c| c.0.as_str()).collect();
    assert_eq!(cols, vec!["hash", "account_id", "discoverable", "created_day"]);
    ts.stop().await;
}

/// Lookups cost 10 tokens: guessing names is slow.
#[tokio::test]
async fn lookups_are_rate_limited() {
    let ts = boot(|c| {
        c.rate_burst = 35.0;
        c.rate_per_sec = 0.001;
    })
    .await;
    let api = &ts.api;
    let a = api.signup().await;
    let mut limited = None;
    for i in 0..10 {
        let (st, _) = api.call(&a, Method::POST, "/v1/usernames/lookup", Some(json!({ "hash": b64(&[i as u8; 32]) }))).await;
        if st == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(i);
            break;
        }
    }
    assert_eq!(limited, Some(3), "35 tokens allow 3 lookups of 10");
    ts.stop().await;
}

/// The name goes away with the account.
#[tokio::test]
async fn deleted_with_the_account() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let h = b64(&[7u8; 32]);
    api.call(&a, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": h }))).await;
    let (st, _) = api.call(&a, Method::DELETE, &format!("/v1/devices/{}", a.device_id), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/lookup", Some(json!({ "hash": h }))).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": h }))).await.0, StatusCode::OK);
    ts.stop().await;
}
