//! Integration tests for human-verified two-sided device linking.

mod common;

use common::*;
use ed25519_dalek::Signer;
use reqwest::{Method, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};

fn link_join_message(link_id: &str, challenge: &[u8], auth_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = format!("tree-device-link-join-v1\n{link_id}\n").into_bytes();
    out.extend_from_slice(challenge);
    out.push(b'\n');
    out.extend_from_slice(auth_pub);
    out
}

fn link_confirm_message(link_id: &str, code: &str, auth_pub: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = format!("tree-device-link-confirm-v1\n{link_id}\n{code}\n").into_bytes();
    if let Some(pubkey) = auth_pub {
        out.extend_from_slice(pubkey);
    }
    out
}

fn verification_code(challenge: &[u8], initiator_pub: &[u8; 32], joiner_pub: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"tree-device-link-code-v1");
    h.update(challenge);
    h.update(initiator_pub);
    h.update(joiner_pub);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{n:06}")
}

#[tokio::test]
async fn device_link_requires_both_sides_and_is_idempotent() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;

    let (st, created) = api.call(&alice, Method::POST, "/v1/device-links", None).await;
    assert_eq!(st, StatusCode::OK, "{created}");

    let link_id = created["link_id"].as_str().unwrap().to_string();
    let challenge = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        created["challenge"].as_str().unwrap(),
    )
    .unwrap();
    let new_key = new_key();
    let join_proof = new_key
        .sign(&link_join_message(
            &link_id,
            &challenge,
            new_key.verifying_key().as_bytes(),
        ))
        .to_bytes();

    let join = api
        .http
        .post(api.url(&format!("/v1/device-links/{link_id}/join")))
        .json(&json!({
            "auth_pub": b64(new_key.verifying_key().as_bytes()),
            "proof": b64(&join_proof),
        }))
        .send()
        .await
        .unwrap();
    let (st, joined) = decode(join).await;
    assert_eq!(st, StatusCode::OK, "{joined}");

    let code = joined["verification_code"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|b| b.is_ascii_digit()));

    let wrong = api
        .call(
            &alice,
            Method::POST,
            &format!("/v1/device-links/{link_id}/confirm"),
            Some(json!({"code": "000000"})),
        )
        .await;
    if code != "000000" {
        assert_eq!(wrong.0, StatusCode::BAD_REQUEST, "{:?}", wrong.1);
    }

    let join_confirm_proof = new_key
        .sign(&link_confirm_message(
            &link_id,
            &code,
            Some(new_key.verifying_key().as_bytes()),
        ))
        .to_bytes();
    let join_confirm = api
        .http
        .post(api.url(&format!("/v1/device-links/{link_id}/confirm-join")))
        .json(&json!({
            "link_id": link_id,
            "code": code,
            "auth_pub": b64(new_key.verifying_key().as_bytes()),
            "proof": b64(&join_confirm_proof),
        }))
        .send()
        .await
        .unwrap();
    let (st, _) = decode(join_confirm).await;
    assert_eq!(st, StatusCode::OK);

    // The new device must not exist until the existing device also confirms.
    let devices = api
        .call(&alice, Method::GET, "/v1/devices", None)
        .await;
    assert_eq!(devices.0, StatusCode::OK, "{:?}", devices.1);
    assert_eq!(devices.1["devices"].as_array().unwrap().len(), 1);

    let init_confirm = api
        .call(
            &alice,
            Method::POST,
            &format!("/v1/device-links/{link_id}/confirm"),
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(init_confirm.0, StatusCode::OK, "{:?}", init_confirm.1);

    let devices = api
        .call(&alice, Method::GET, "/v1/devices", None)
        .await;
    assert_eq!(devices.0, StatusCode::OK, "{:?}", devices.1);
    assert_eq!(devices.1["devices"].as_array().unwrap().len(), 2);

    // Confirming again is a no-op, not a second device.
    let again = api
        .call(
            &alice,
            Method::POST,
            &format!("/v1/device-links/{link_id}/confirm"),
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(again.0, StatusCode::OK, "{again:?}");

    let devices = api
        .call(&alice, Method::GET, "/v1/devices", None)
        .await;
    assert_eq!(devices.1["devices"].as_array().unwrap().len(), 2);

    ts.stop().await;
}

#[tokio::test]
async fn device_link_rejects_a_different_joiner_after_first_join() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;

    let (st, created) = api.call(&alice, Method::POST, "/v1/device-links", None).await;
    assert_eq!(st, StatusCode::OK, "{created}");
    let link_id = created["link_id"].as_str().unwrap().to_string();
    let challenge = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        created["challenge"].as_str().unwrap(),
    )
    .unwrap();

    let key1 = new_key();
    let proof1 = key1
        .sign(&link_join_message(&link_id, &challenge, key1.verifying_key().as_bytes()))
        .to_bytes();
    let first = api
        .http
        .post(api.url(&format!("/v1/device-links/{link_id}/join")))
        .json(&json!({
            "auth_pub": b64(key1.verifying_key().as_bytes()),
            "proof": b64(&proof1),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(decode(first).await.0, StatusCode::OK);

    let key2 = new_key();
    let proof2 = key2
        .sign(&link_join_message(&link_id, &challenge, key2.verifying_key().as_bytes()))
        .to_bytes();
    let second = api
        .http
        .post(api.url(&format!("/v1/device-links/{link_id}/join")))
        .json(&json!({
            "auth_pub": b64(key2.verifying_key().as_bytes()),
            "proof": b64(&proof2),
        }))
        .send()
        .await
        .unwrap();
    let (st, _) = decode(second).await;
    assert_eq!(st, StatusCode::CONFLICT);

    ts.stop().await;
}

#[tokio::test]
async fn device_link_code_binds_both_public_keys() {
    let challenge = [9u8; 32];
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    assert_ne!(verification_code(&challenge, &a, &b), verification_code(&challenge, &a, &c));
}
