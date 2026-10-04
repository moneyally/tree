//! Username links: hash only, one per account, reset replaces it, found
//! only while the name is registered and discoverable, gone with the name.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

#[tokio::test]
async fn username_links() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let name = b64(&[9u8; 32]);
    let (l1, l2) = (b64(&[10u8; 32]), b64(&[11u8; 32]));
    let link = |h: &str| Some(json!({ "hash": h }));

    // A link needs a name.
    let (st, v) = api.call(&a, Method::POST, "/v1/usernames/link/apply", link(&l1)).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "NO_USERNAME"));
    api.call(&a, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": name }))).await;
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/link/apply", link(&l1)).await.0, StatusCode::OK);
    let (st, v) = api.call(&b, Method::POST, "/v1/usernames/link/lookup", link(&l1)).await;
    assert_eq!((st, v["account_id"].as_str()), (StatusCode::OK, Some(a.account_id.as_str())));
    // Another account cannot take the same hash.
    api.call(&b, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": b64(&[12u8; 32]) }))).await;
    let (st, v) = api.call(&b, Method::POST, "/v1/usernames/link/apply", link(&l1)).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"));

    // Reset: the old link stops working, the new one works, the name stays.
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/link/apply", link(&l2)).await.0, StatusCode::OK);
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/link/lookup", link(&l1)).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/link/lookup", link(&l2)).await.0, StatusCode::OK);
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/lookup", Some(json!({ "hash": name }))).await.0, StatusCode::OK);

    // Hidden name: the link answers like an unknown one.
    api.call(&a, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": name, "discoverable": false }))).await;
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/link/lookup", link(&l2)).await.0, StatusCode::NOT_FOUND);
    api.call(&a, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": name }))).await;
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/link/lookup", link(&l2)).await.0, StatusCode::OK, "kept across re-registration");

    // Release the link, twice; a new link goes with a released name.
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/link/release", None).await.0, StatusCode::OK);
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/link/release", None).await.0, StatusCode::OK);
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/link/lookup", link(&l2)).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/link/apply", link(&l1)).await.0, StatusCode::OK);
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/release", None).await.0, StatusCode::OK);
    assert_eq!(api.call(&b, Method::POST, "/v1/usernames/link/lookup", link(&l1)).await.0, StatusCode::NOT_FOUND);
    let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM username_links WHERE account_id = ?")
        .bind(&a.account_id)
        .fetch_one(&ts.server.state.db)
        .await
        .unwrap();
    assert_eq!(n.0, 0, "the link went with the name");

    for bad in [json!({ "hash": b64(&[1u8; 31]) }), json!({ "hash": "!!" }), json!({})] {
        assert_eq!(api.call(&a, Method::POST, "/v1/usernames/link/apply", Some(bad.clone())).await.0, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(api.call(&a, Method::POST, "/v1/usernames/link/lookup", Some(bad)).await.0, StatusCode::BAD_REQUEST);
    }
    // Only the hash is stored.
    let cols: Vec<(String,)> = sqlx::query_as("SELECT name FROM pragma_table_info('username_links')")
        .fetch_all(&ts.server.state.db)
        .await
        .unwrap();
    let cols: Vec<&str> = cols.iter().map(|c| c.0.as_str()).collect();
    assert_eq!(cols, vec!["account_id", "hash", "created_day"]);
    ts.stop().await;
}

/// Deleting the account deletes its link.
#[tokio::test]
async fn link_deleted_with_the_account() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    api.call(&a, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": b64(&[4u8; 32]) }))).await;
    api.call(&a, Method::POST, "/v1/usernames/link/apply", Some(json!({ "hash": b64(&[5u8; 32]) }))).await;
    assert_eq!(api.call(&a, Method::DELETE, "/v1/accounts", None).await.0, StatusCode::OK);
    let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM username_links").fetch_one(&ts.server.state.db).await.unwrap();
    assert_eq!(n.0, 0);
    ts.stop().await;
}

/// A link lookup costs as much as a name lookup (10 tokens).
#[tokio::test]
async fn link_lookup_cost_is_ten_tokens() {
    let ts = boot(|c| {
        c.rate_per_sec = 0.001;
        c.rate_burst = 20.0;
    })
    .await;
    let api = &ts.api;
    let a = api.signup().await;
    let body = || Some(json!({ "hash": b64(&[3u8; 32]) }));
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/link/lookup", body()).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/link/lookup", body()).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.call(&a, Method::POST, "/v1/usernames/link/lookup", body()).await.0, StatusCode::TOO_MANY_REQUESTS);
    ts.stop().await;
}
