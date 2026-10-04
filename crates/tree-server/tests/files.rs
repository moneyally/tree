//! Integration tests for opaque encrypted media storage.

mod common;

use common::*;
use reqwest::{header::HeaderMap, Method, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};
use tree_core::{encrypt_file, FileKey};

#[tokio::test]
async fn encrypted_file_capability_controls_download() {
    let ts = boot(|cfg| cfg.file_ttl_secs = 3600).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let encrypted = encrypt_file(
        &FileKey::generate().unwrap(),
        b"group=abc;message=7",
        b"secret-media-bytes",
    )
    .unwrap();
    let wire = encrypted.encode().unwrap();
    let digest: [u8; 32] = Sha256::digest(&wire).into();

    let (st, v) = api
        .call(
            &alice,
            Method::POST,
            "/v1/files",
            Some(json!({
                "ciphertext": b64(&wire)
            })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["size_bytes"].as_u64(), Some(wire.len() as u64));
    assert_eq!(v["sha256"].as_str(), Some(hex::encode(digest).as_str()));

    let file_id = v["file_id"].as_str().unwrap().to_string();
    let cap = v["capability"].as_str().unwrap().to_string();

    let path = format!("/v1/files/{file_id}");
    let mut headers = HeaderMap::new();
    headers.insert(
        tree_server::files::FILE_CAPABILITY_HEADER,
        cap.parse().unwrap(),
    );
    let signed = Signed::new(Method::GET, &path, Some(&alice.device_id), None);
    let (st, downloaded) = api.send_with_headers(&signed, &alice.key, headers).await;
    assert_eq!(st, StatusCode::OK, "{downloaded}");
    let returned = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        downloaded["ciphertext"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(returned, wire);
    assert_eq!(
        downloaded["sha256"].as_str(),
        Some(hex::encode(digest).as_str())
    );

    let path = format!("/v1/files/{file_id}");
    let mut bad_headers = HeaderMap::new();
    bad_headers.insert(
        tree_server::files::FILE_CAPABILITY_HEADER,
        b64(&[7u8; 32]).parse().unwrap(),
    );
    let signed = Signed::new(Method::GET, &path, Some(&alice.device_id), None);
    let (st, _) = api
        .send_with_headers(&signed, &alice.key, bad_headers)
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _) = api
        .call(
            &alice,
            Method::POST,
            "/v1/files",
            Some(json!({"ciphertext": b64(&[1u8; 3])})),
        )
        .await;
    assert_eq!(st, StatusCode::OK);

    ts.stop().await;
}

#[tokio::test]
async fn encrypted_file_expires_and_server_purge_removes_it() {
    let ts = boot(|cfg| cfg.file_ttl_secs = 1).await;
    let api = &ts.api;
    let alice = api.signup().await;

    let (st, v) = api
        .call(
            &alice,
            Method::POST,
            "/v1/files",
            Some(json!({"ciphertext": b64(b"opaque-file")})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let file_id = v["file_id"].as_str().unwrap();
    let cap = v["capability"].as_str().unwrap().to_string();
    let path = format!("/v1/files/{file_id}");

    sqlx::query("UPDATE files SET expires_at = 0 WHERE id = ?")
        .bind(file_id)
        .execute(&ts.server.state.db)
        .await
        .unwrap();

    let removed = tree_server::purge_expired(&ts.server.state, 100)
        .await
        .unwrap();
    assert!(removed >= 1);

    let mut headers = HeaderMap::new();
    headers.insert(
        tree_server::files::FILE_CAPABILITY_HEADER,
        cap.parse().unwrap(),
    );
    let signed = Signed::new(Method::GET, &path, Some(&alice.device_id), None);
    let (st, _) = api.send_with_headers(&signed, &alice.key, headers).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    ts.stop().await;
}
