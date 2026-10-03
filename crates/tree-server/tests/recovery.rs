//! Integration tests for recovery setup and new-device issuance.

mod common;

use common::*;
use ed25519_dalek::Signer;
use reqwest::Method;
use serde_json::json;
use tree_core::RecoveryPhrase;

#[tokio::test]
async fn recovery_adds_a_new_device_and_rejects_replay() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;

    let phrase = RecoveryPhrase::generate().unwrap();
    let (st, v) = api
        .call(
            &alice,
            Method::POST,
            "/v1/recovery/setup",
            Some(json!({"recovery_pub": b64(&phrase.recovery_public_key())})),
        )
        .await;
    assert_eq!(st, reqwest::StatusCode::OK, "{v}");

    let new_auth = new_key();
    let timestamp = now();
    let nonce = fresh_nonce();
    let mut proof_message =
        format!("tree-recovery-v1\n{}\n{}\n{}\n", alice.account_id, timestamp, nonce).into_bytes();
    proof_message.extend_from_slice(new_auth.verifying_key().as_bytes());
    let proof = phrase.recovery_signing_key().sign(&proof_message).to_bytes();

    let request = json!({
        "account_id": alice.account_id,
        "recovery_pub": b64(&phrase.recovery_public_key()),
        "new_auth_pub": b64(new_auth.verifying_key().as_bytes()),
        "timestamp": timestamp,
        "nonce": nonce,
        "proof": b64(&proof)
    });

    let first = api
        .http
        .post(api.url("/v1/recovery"))
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .unwrap();
    let (st, first_body) = decode(first).await;
    assert_eq!(st, reqwest::StatusCode::CREATED, "{first_body}");
    assert_eq!(
        first_body["account_id"].as_str(),
        Some(alice.account_id.as_str())
    );
    let recovered_device_id = first_body["device_id"].as_str().unwrap().to_string();

    let second = api
        .http
        .post(api.url("/v1/recovery"))
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .unwrap();
    let (st, v) = decode(second).await;
    assert_eq!(st, reqwest::StatusCode::UNAUTHORIZED, "{v}");

    let new_device_id = v["device_id"].as_str().unwrap_or_default();
    assert_ne!(new_device_id, alice.device_id);

    let devices = api
        .call(&alice, Method::GET, "/v1/devices", None)
        .await;
    assert_eq!(devices.0, reqwest::StatusCode::OK, "{:?}", devices.1);
    assert_eq!(devices.1["devices"].as_array().unwrap().len(), 2);

    ts.stop().await;
}
