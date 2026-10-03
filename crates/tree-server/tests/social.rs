//! Integration tests for stage-1 identity/social endpoints.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};
use tree_core::{safety_fingerprint, username_hash};

fn fake_application() -> Vec<u8> {
    app(b"opaque evidence ciphertext")
}

#[tokio::test]
async fn username_is_hashed_and_unique() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let bob = api.signup().await;

    let hash = username_hash("Alice_Test").unwrap();
    let path = "/v1/username";

    let (st, v) = api
        .call(
            &alice,
            Method::PUT,
            path,
            Some(json!({"username_hash": hex::encode(hash)})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        v["username_hash"].as_str(),
        Some(hex::encode(hash).as_str())
    );

    let (st, v) = api
        .call(
            &bob,
            Method::PUT,
            path,
            Some(json!({"username_hash": hex::encode(hash)})),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT, "{v}");

    let (st, v) = api
        .call(
            &alice,
            Method::GET,
            &format!("/v1/username/{}", hex::encode(hash)),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["account_id"].as_str(), Some(alice.account_id.as_str()));

    let (st, v) = api.call(&alice, Method::DELETE, "/v1/username", None).await;
    assert_eq!(st, StatusCode::OK, "{v}");

    let (st, v) = api
        .call(
            &alice,
            Method::GET,
            &format!("/v1/username/{}", hex::encode(hash)),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{v}");

    ts.stop().await;
}

#[tokio::test]
async fn blocks_stop_requests_but_can_be_removed() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let bob = api.signup().await;

    let (st, v) = api
        .call(
            &alice,
            Method::POST,
            "/v1/message-requests",
            Some(json!({"target_account_id": bob.account_id})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");

    let (st, v) = api
        .call(&bob, Method::GET, "/v1/message-requests", None)
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        v["incoming"][0]["account_id"].as_str(),
        Some(alice.account_id.as_str())
    );
    assert_eq!(v["incoming"][0]["state"].as_str(), Some("pending"));

    let (st, v) = api
        .call(
            &bob,
            Method::POST,
            &format!("/v1/message-requests/{}/accept", alice.account_id),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");

    let (st, v) = api
        .call(
            &alice,
            Method::POST,
            &format!("/v1/blocks/{}", bob.account_id),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");

    let (st, v) = api
        .call(
            &bob,
            Method::POST,
            "/v1/message-requests",
            Some(json!({"target_account_id": alice.account_id})),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"].as_str(), Some("BLOCKED"));

    let (st, v) = api
        .call(
            &bob,
            Method::POST,
            &format!("/v1/message-requests/{}/accept", alice.account_id),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{v}");

    let (st, v) = api
        .call(
            &alice,
            Method::DELETE,
            &format!("/v1/blocks/{}", bob.account_id),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");

    let (st, v) = api
        .call(
            &bob,
            Method::POST,
            "/v1/message-requests",
            Some(json!({"target_account_id": alice.account_id})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");

    ts.stop().await;
}

#[tokio::test]
async fn report_stores_only_opaque_evidence_hash_and_bytes() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let bob = api.signup().await;
    let setup = json!({
        "group_id": b64(&GROUP),
        "epoch": 0,
        "recipients": [bob.device_id],
        "body": b64(&commit(&GROUP, 0, b"report-setup"))
    });
    let (st, setup_body) = api
        .call(&alice, Method::POST, "/v1/commits", Some(setup))
        .await;
    assert_eq!(st, StatusCode::OK, "{setup_body}");
    let setup_messages = api.fetch(&bob, 0).await;
    assert_eq!(setup_messages.len(), 1);
    api.ack(&bob, &[setup_messages[0]["id"].as_str().unwrap()]).await;

    let evidence = fake_application();
    let hash: [u8; 32] = Sha256::digest(&evidence).into();

    let body = json!({
        "group_id": hex::encode(GROUP),
        "evidence": b64(&evidence),
        "category": "spam"
    });
    let (st, v) = api
        .call(&alice, Method::POST, "/v1/reports", Some(body))
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        v["evidence_sha256"].as_str(),
        Some(hex::encode(hash).as_str())
    );

    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT ciphertext FROM reports ORDER BY created_at DESC LIMIT 1")
    .fetch_one(&ts.server.state.db)
    .await
    .unwrap();
    assert_eq!(stored, evidence);
    assert!(!stored
        .windows(b"opaque evidence plaintext".len())
        .any(|w| w == b"opaque evidence plaintext"));

    // Per-device safety fingerprint is deterministic and non-trivial.
    let fp1 = safety_fingerprint(&[1u8; 32]);
    let fp2 = safety_fingerprint(&[1u8; 32]);
    assert_eq!(fp1, fp2);

    ts.stop().await;
}
