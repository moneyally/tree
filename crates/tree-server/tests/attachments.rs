//! Encrypted attachments: opaque upload, download by id, size limit, purge.

mod common;

use common::*;
use reqwest::{Method, StatusCode};

async fn upload(api: &Api, dev: &Device, bytes: &[u8]) -> (StatusCode, serde_json::Value) {
    let mut s = Signed::new(Method::POST, "/v1/attachments", Some(&dev.device_id), None);
    s.body = bytes.to_vec();
    api.send(&s, &dev.key).await
}

async fn download(api: &Api, dev: &Device, id: &str) -> (StatusCode, Vec<u8>) {
    let path = format!("/v1/attachments/{id}");
    let s = Signed::new(Method::GET, &path, Some(&dev.device_id), None);
    let resp = api
        .http
        .get(api.url(&path))
        .header("X-Tree-Device", &dev.device_id)
        .header("X-Tree-Timestamp", s.ts.to_string())
        .header("X-Tree-Nonce", &s.nonce)
        .header("X-Tree-Signature", s.signature(&dev.key))
        .send()
        .await
        .unwrap();
    let st = resp.status();
    (st, resp.bytes().await.unwrap().to_vec())
}

#[tokio::test]
async fn upload_download_limits_purge() {
    let ts = boot(|c| c.max_attachment_bytes = 1000).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let blob: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let (st, v) = upload(api, &a, &blob).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["size"], 1000);

    // Any registered device that knows the id may fetch it; bytes unchanged.
    assert_eq!(download(api, &b, &id).await, (StatusCode::OK, blob.clone()));
    assert_eq!(download(api, &b, "AAAAAAAAAAAAAAAAAAAAAA").await.0, StatusCode::NOT_FOUND);
    assert_eq!(download(api, &b, "bad").await.0, StatusCode::BAD_REQUEST);

    // Limits.
    assert_eq!(upload(api, &a, &[0u8; 1001]).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(upload(api, &a, &[]).await.0, StatusCode::BAD_REQUEST);

    // Only id, size and minute are stored; no uploader.
    let cols: Vec<(String,)> = sqlx::query_as("SELECT name FROM pragma_table_info('attachments')")
        .fetch_all(&ts.server.state.db)
        .await
        .unwrap();
    assert_eq!(cols.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(), vec!["id", "size", "created_at"]);
    let file = ts.dir.join("attachments").join(&id);
    assert!(file.exists());

    // Purged after the message TTL, file included.
    let ttl = ts.server.state.cfg.message_ttl_secs as i64;
    tree_server::purge_expired(&ts.server.state, now() + ttl + 120).await.unwrap();
    assert!(!file.exists());
    assert_eq!(download(api, &b, &id).await.0, StatusCode::NOT_FOUND);
    ts.stop().await;
}
