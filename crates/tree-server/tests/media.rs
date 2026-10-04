use axum::http::{HeaderMap, Method, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};
use tree_core::media::{
    decrypt_manifest, encrypt_manifest, EncryptedChunk, MediaEnvelope, MediaManifest, PreviewMode,
    ViewPolicy,
};
use tree_core::MessageId;

mod common;
use common::{b64, boot, Device, Signed};

async fn signed_with_media_cap(
    ts: &common::TestServer,
    dev: &Device,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
    capability: &str,
) -> (StatusCode, serde_json::Value) {
    let req = Signed::new(method, path, Some(&dev.device_id), body.as_ref());
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-tree-media-capability",
        capability.parse().expect("valid capability header"),
    );
    ts.api.send_with_headers(&req, &dev.key, headers).await
}

#[tokio::test]
async fn encrypted_media_can_resume_finalize_and_download_without_plaintext() {
    let ts = boot(|c| c.file_ttl_secs = 3600).await;
    let dev = ts.api.signup().await;

    let (manifest, key) = MediaManifest::generate(
        MessageId([9; 16]),
        b"group-1",
        7,
        "image",
        "photo.jpg",
        "image/jpeg",
        5,
        ViewPolicy::Persistent,
        PreviewMode::Blurred,
    )
    .unwrap();
    let commitment = manifest.key_commitment(&key).unwrap();
    let body = json!({
        "manifest": b64(&encrypt_manifest(&key, &manifest).unwrap()),
        "key_commitment": b64(&commitment),
        "plaintext_size": 5,
        "chunk_size": manifest.chunk_size,
        "chunk_count": manifest.chunk_count,
    });
    let (status, value) = ts
        .api
        .call(&dev, Method::POST, "/v1/media", Some(body))
        .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let media_id = value["media_id"].as_str().unwrap().to_string();
    let capability = value["capability"].as_str().unwrap().to_string();

    let chunk = EncryptedChunk::encrypt(&key, &manifest, 0, b"hello").unwrap();
    let chunk_body = json!({
        "index": 0,
        "ciphertext": b64(&chunk.ciphertext),
        "sha256": hex::encode(Sha256::digest(&chunk.ciphertext)),
    });
    let (status, _) = signed_with_media_cap(
        &ts,
        &dev,
        Method::POST,
        &format!("/v1/media/{media_id}/chunks"),
        Some(chunk_body),
        &capability,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, value) = signed_with_media_cap(
        &ts,
        &dev,
        Method::POST,
        &format!("/v1/media/{media_id}"),
        None,
        &capability,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["finalized"], true);

    let (status, value) = signed_with_media_cap(
        &ts,
        &dev,
        Method::GET,
        &format!("/v1/media/{media_id}"),
        None,
        &capability,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["finalized"], true);
    assert_eq!(
        decrypt_manifest(&key, &common::unb64(value["manifest"].as_str().unwrap())).unwrap(),
        manifest
    );

    let (status, value) = signed_with_media_cap(
        &ts,
        &dev,
        Method::GET,
        &format!("/v1/media/{media_id}/chunks/0"),
        None,
        &capability,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        value["ciphertext"].as_str().unwrap(),
        b64(&chunk.ciphertext)
    );

    let wrong = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let (status, _) = signed_with_media_cap(
        &ts,
        &dev,
        Method::GET,
        &format!("/v1/media/{media_id}"),
        None,
        wrong,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    ts.stop().await;
}

#[tokio::test]
async fn media_envelope_keeps_key_off_server_and_binds_it_to_message_epoch() {
    let (manifest, key) = MediaManifest::generate(
        MessageId([1; 16]),
        b"group",
        12,
        "image",
        "a.png",
        "image/png",
        5,
        ViewPolicy::ViewOnce,
        PreviewMode::Blurred,
    )
    .unwrap();
    let envelope = MediaEnvelope::new(
        "media123".into(),
        [8; 32],
        manifest.clone(),
        key.clone(),
        None,
    )
    .unwrap()
    .encode()
    .unwrap();
    let decoded = MediaEnvelope::decode(&envelope).unwrap();
    assert_eq!(decoded.manifest.epoch, 12);
    assert_eq!(decoded.file_key.as_bytes(), key.as_bytes());

    let mut tampered = envelope.clone();
    let pos = tampered
        .windows(32)
        .position(|w| w == manifest.key_commitment(&key).unwrap().as_slice())
        .unwrap();
    tampered[pos] ^= 1;
    assert!(MediaEnvelope::decode(&tampered).is_err());
}
