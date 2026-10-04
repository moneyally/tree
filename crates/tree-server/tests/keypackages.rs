//! Integration tests for key-package claim policy.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::json;
use tree_core::Client;

#[tokio::test]
async fn blocked_account_cannot_claim_one_time_key_packages() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let bob = api.signup().await;

    let alice_core = Client::new("alice").unwrap();
    let package = alice_core.key_package().unwrap();
    let (st, body) = api
        .call(
            &alice,
            Method::POST,
            "/v1/keypackages",
            Some(json!({"key_packages": [b64(&package)]})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");

    let (st, body) = api
        .call(
            &alice,
            Method::POST,
            &format!("/v1/blocks/{}", bob.account_id),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");

    let (st, body) = api
        .call(
            &bob,
            Method::POST,
            "/v1/keypackages/claim",
            Some(json!({"account_id": alice.account_id})),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"].as_str(), Some("BLOCKED"));

    let (st, body) = api
        .call(&alice, Method::GET, "/v1/keypackages/count", None)
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["count"].as_i64(), Some(1));

    ts.stop().await;
}


#[tokio::test]
async fn device_can_revoke_all_unused_key_packages_after_compromise() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let alice_core = Client::new("alice").unwrap();

    let packages = (0..3)
        .map(|_| b64(&alice_core.key_package().unwrap()))
        .collect::<Vec<_>>();
    let (st, body) = api
        .call(
            &alice,
            Method::POST,
            "/v1/keypackages",
            Some(json!({"key_packages": packages})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["count"].as_i64(), Some(3));

    let (st, body) = api
        .call(&alice, Method::DELETE, "/v1/keypackages", None)
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["revoked"].as_u64(), Some(3));

    let (st, body) = api
        .call(&alice, Method::GET, "/v1/keypackages/count", None)
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["count"].as_i64(), Some(0));

    ts.stop().await;
}
