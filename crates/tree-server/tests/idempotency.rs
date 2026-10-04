//! Idempotent sends (PROTOCOL.md 8.10): `POST /v1/messages` with an
//! idempotency key delivers once however often it is retried, refuses the
//! key for another request, keeps keys apart per device, bounds the records
//! per device and purges them with the message TTL.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

async fn send_keyed(api: &Api, dev: &Device, recipients: &[&str], body: &[u8], key: &[u8]) -> (StatusCode, Value) {
    api.call(
        dev,
        Method::POST,
        "/v1/messages",
        Some(json!({ "recipients": recipients, "body": b64(body), "idempotency_key": b64(key) })),
    )
    .await
}

async fn count(ts: &TestServer, q: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(q.to_string())).fetch_one(&ts.server.state.db).await.unwrap()
}

#[tokio::test]
async fn same_key_same_request_delivers_once() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let b = api.signup().await;
    let c = api.signup().await;
    let body = app(b"hello once");
    let key = [1u8; 16];

    let (st, v) = send_keyed(api, &a, &[&b.device_id, &c.device_id, &b.device_id], &body, &key).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!((v["delivered"].as_i64(), v["replayed"].as_bool()), (Some(2), Some(false)), "duplicates collapse");
    // A retry, recipients in another order and repeated: the same request.
    for recipients in [vec![&c.device_id, &b.device_id], vec![&b.device_id, &c.device_id, &c.device_id]] {
        let r: Vec<&str> = recipients.iter().map(|s| s.as_str()).collect();
        let (st, v) = send_keyed(api, &a, &r, &body, &key).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_eq!((v["delivered"].as_i64(), v["replayed"].as_bool()), (Some(2), Some(true)));
        assert_eq!(v["unknown_devices"], json!([]));
    }
    assert_eq!(api.fetch(&b, 0).await.len(), 1, "delivered once");
    assert_eq!(api.fetch(&c, 0).await.len(), 1);
    assert_eq!(count(&ts, "SELECT COUNT(*) FROM blobs").await, 1);
    assert_eq!(count(&ts, "SELECT COUNT(*) FROM idempotency_keys").await, 1);

    // Control: without a key every request delivers.
    api.send_raw(&a, &[&b.device_id], &body).await;
    api.send_raw(&a, &[&b.device_id], &body).await;
    assert_eq!(api.fetch(&b, 0).await.len(), 3);
    ts.stop().await;
}

#[tokio::test]
async fn same_key_other_request_is_refused() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let b = api.signup().await;
    let c = api.signup().await;
    let key = [2u8; 32];
    let (st, _) = send_keyed(api, &a, &[&b.device_id], &app(b"first"), &key).await;
    assert_eq!(st, StatusCode::OK);
    for (recipients, body) in [
        (vec![b.device_id.as_str()], app(b"second")),
        (vec![b.device_id.as_str(), c.device_id.as_str()], app(b"first")),
        (vec![c.device_id.as_str()], app(b"first")),
    ] {
        let (st, v) = send_keyed(api, &a, &recipients, &body, &key).await;
        assert_eq!((st, v["code"].as_str()), (StatusCode::CONFLICT, Some("IDEMPOTENCY_KEY_REUSE")), "{v}");
    }
    assert_eq!(api.fetch(&b, 0).await.len(), 1);
    assert!(api.fetch(&c, 0).await.is_empty(), "nothing delivered by a refused request");

    // Malformed keys.
    for bad in [vec![0u8; 15], vec![0u8; 65]] {
        let (st, v) = send_keyed(api, &a, &[&b.device_id], &app(b"x"), &bad).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    }
    let (st, _) = api
        .call(&a, Method::POST, "/v1/messages", Some(json!({ "recipients": [&b.device_id], "body": b64(&app(b"x")), "idempotency_key": "%%%" })))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    ts.stop().await;
}

/// Keys are per sending device: another device using the same bytes is
/// a different record, so items of different senders never collide.
#[tokio::test]
async fn keys_are_per_device() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a1 = api.signup().await;
    let a2 = api.add_device(&a1).await;
    let other = api.signup().await;
    let b = api.signup().await;
    let key = [3u8; 16];
    for (i, dev) in [&a1, &a2, &other].into_iter().enumerate() {
        let (st, v) = send_keyed(api, dev, &[&b.device_id], &app(format!("from {i}").as_bytes()), &key).await;
        assert_eq!((st, v["replayed"].as_bool()), (StatusCode::OK, Some(false)), "{v}");
    }
    assert_eq!(api.fetch(&b, 0).await.len(), 3);
    assert_eq!(count(&ts, "SELECT COUNT(*) FROM idempotency_keys").await, 3);
    // A device's records go with it.
    let (st, _) = api.call(&a1, Method::DELETE, &format!("/v1/devices/{}", a2.device_id), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(count(&ts, "SELECT COUNT(*) FROM idempotency_keys").await, 2);
    ts.stop().await;
}

/// Many copies of one keyed request at the same time: one delivery.
#[tokio::test]
async fn concurrent_retries_deliver_once() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let b = api.signup().await;
    let body = app(b"raced");
    let key = [4u8; 16];
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (api, a, to, body) = (api.clone(), a.clone(), b.device_id.clone(), body.clone());
        tasks.push(tokio::spawn(async move { send_keyed(&api, &a, &[&to], &body, &key).await }));
    }
    let mut fresh = 0;
    for t in tasks {
        let (st, v) = t.await.unwrap();
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_eq!(v["delivered"], 1);
        fresh += usize::from(v["replayed"] == false);
    }
    assert_eq!(fresh, 1, "exactly one request delivered");
    assert_eq!(api.fetch(&b, 0).await.len(), 1);
    ts.stop().await;
}

/// At most MAX_IDEMPOTENCY_KEYS records per device (the oldest go), and
/// the purge removes records older than the message TTL.
#[tokio::test]
async fn records_are_bounded_and_purged() {
    let ts = boot(|c| c.max_idempotency_keys = 3).await;
    let api = &ts.api;
    let a = api.signup().await;
    let b = api.signup().await;
    for i in 0..5u8 {
        let (st, _) = send_keyed(api, &a, &[&b.device_id], &app(&[i]), &[i + 10; 16]).await;
        assert_eq!(st, StatusCode::OK);
    }
    assert_eq!(count(&ts, "SELECT COUNT(*) FROM idempotency_keys").await, 3);
    // The newest are kept: a retry of the last one is still answered.
    let (_, v) = send_keyed(api, &a, &[&b.device_id], &app(&[4]), &[14; 16]).await;
    assert_eq!(v["replayed"], true);
    // The oldest was dropped: its key is free again (the cap bounds storage;
    // a client retries within minutes, far below the cap).
    let (_, v) = send_keyed(api, &a, &[&b.device_id], &app(&[0]), &[10; 16]).await;
    assert_eq!(v["replayed"], false);

    // Only the day is stored.
    let day = count(&ts, "SELECT MAX(created_day) FROM idempotency_keys").await;
    assert_eq!(day, now() / 86_400);
    // Young records survive a purge; after the TTL they are gone.
    tree_server::purge_expired(&ts.server.state, now()).await.unwrap();
    assert_eq!(count(&ts, "SELECT COUNT(*) FROM idempotency_keys").await, 3);
    let ttl = ts.server.state.cfg.message_ttl_secs as i64;
    tree_server::purge_expired(&ts.server.state, now() + ttl + 86_400).await.unwrap();
    assert_eq!(count(&ts, "SELECT COUNT(*) FROM idempotency_keys").await, 0);
    // After the purge the key is new again (and the message long expired).
    let (_, v) = send_keyed(api, &a, &[&b.device_id], &app(&[4]), &[14; 16]).await;
    assert_eq!(v["replayed"], false);

    // The table holds no recipient, body or message id.
    let cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('idempotency_keys')")
        .fetch_all(&ts.server.state.db)
        .await
        .unwrap();
    assert_eq!(cols, ["seq", "device_id", "key", "request_hash", "delivered", "created_day"]);
    ts.stop().await;
}

/// Commits need no key: a retry of the same commit is already answered from
/// the stored winner hash (PROTOCOL.md 7.4) and delivers nothing again.
#[tokio::test]
async fn commit_retries_are_idempotent_by_hash() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let b = api.signup().await;
    let commit = envelope(&GROUP, 0, 3, b"commit bytes");
    let req = json!({ "group_id": b64(&GROUP), "epoch": 0, "recipients": [&b.device_id], "body": b64(&commit) });
    let (st, first) = api.call(&a, Method::POST, "/v1/commits", Some(req.clone())).await;
    assert_eq!(st, StatusCode::OK, "{first}");
    let (st, again) = api.call(&a, Method::POST, "/v1/commits", Some(req)).await;
    assert_eq!(st, StatusCode::OK, "{again}");
    assert_eq!((again["id"].clone(), again["delivered"].as_i64()), (first["id"].clone(), Some(0)));
    assert_eq!(api.fetch(&b, 0).await.len(), 1);
    ts.stop().await;
}
