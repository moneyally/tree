//! Device-link sessions (PROTOCOL.md 8.11): the server relays, limits and
//! adds a device only with both devices' signatures over one hash.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

struct Link {
    raw: [u8; 16],
    id: String,
    new: SigningKey,
}

impl Link {
    fn new() -> Self {
        let raw = random::<16>();
        Self { raw, id: URL_SAFE_NO_PAD.encode(raw), new: new_key() }
    }
    fn pubkey(&self) -> [u8; 32] {
        self.new.verifying_key().to_bytes()
    }
    fn path(&self, tail: &str) -> String {
        format!("/v1/links/{}{tail}", self.id)
    }
}

async fn open(api: &Api, dev: &Device, l: &Link, offer: &[u8]) -> (StatusCode, Value) {
    api.call(dev, Method::POST, "/v1/links", Some(json!({ "link_id": l.id, "new_auth_pub": b64(&l.pubkey()), "offer": b64(offer) }))).await
}

async fn step(api: &Api, l: &Link, body: Value) -> (StatusCode, Value) {
    api.new_device(&l.new, Method::POST, &l.path("/new"), Some(body)).await
}

async fn confirm(api: &Api, l: &Link, hash: &[u8; 32]) -> (StatusCode, Value) {
    let sig = l.new.sign(&link_lp(&[b"tree/link/confirm/v1", &l.raw, hash])).to_bytes();
    step(api, l, json!({ "action": "confirm", "transcript_hash": b64(hash), "signature": b64(&sig) })).await
}

async fn complete(api: &Api, dev: &Device, l: &Link, hash: &[u8; 32], signer: &SigningKey) -> (StatusCode, Value) {
    let sig = signer.sign(&link_lp(&[b"tree/link/authorise/v1", &l.raw, dev.account_id.as_bytes(), &l.pubkey(), hash])).to_bytes();
    api.call(dev, Method::POST, &l.path("/complete"), Some(json!({ "transcript_hash": b64(hash), "signature": b64(&sig), "sealed": b64(b"sealed") }))).await
}

async fn devices(api: &Api, dev: &Device) -> usize {
    api.call(dev, Method::GET, "/v1/devices", None).await.1["devices"].as_array().unwrap().len()
}

#[tokio::test]
async fn a_session_relays_and_adds_only_with_both_signatures() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let a2 = api.add_device(&a).await;
    let b = api.signup().await;
    let l = Link::new();

    // The new device can see nothing before the existing device opened it.
    assert_eq!(api.new_device(&l.new, Method::GET, &l.path("/new"), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(open(api, &a, &l, b"offer").await.0, StatusCode::CREATED);
    // Only the key named in the session reads and writes as the new device.
    let (st, v) = api.new_device(&l.new, Method::GET, &l.path("/new"), None).await;
    assert_eq!((st, v["state"].as_str(), v["offer"].as_str()), (StatusCode::OK, Some("offered"), Some(b64(b"offer").as_str())));
    assert_eq!(api.new_device(&new_key(), Method::GET, &l.path("/new"), None).await.0, StatusCode::UNAUTHORIZED);
    // The session belongs to the device that opened it.
    assert_eq!(api.call(&a2, Method::GET, &l.path(""), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.call(&b, Method::GET, &l.path(""), None).await.0, StatusCode::NOT_FOUND);

    let hash = random::<32>();
    // Order is enforced: no confirmation before the reveal, no completion
    // before the confirmation.
    assert_eq!(confirm(api, &l, &hash).await.0, StatusCode::CONFLICT);
    assert_eq!(step(api, &l, json!({ "action": "reveal", "reveal": b64(b"reveal") })).await.0, StatusCode::OK);
    assert_eq!(step(api, &l, json!({ "action": "reveal", "reveal": b64(b"again") })).await.0, StatusCode::CONFLICT);
    let (st, v) = api.call(&a, Method::GET, &l.path(""), None).await;
    assert_eq!((st, v["state"].as_str(), v["reveal"].as_str()), (StatusCode::OK, Some("revealed"), Some(b64(b"reveal").as_str())));
    let (st, v) = complete(api, &a, &l, &hash, &a.key).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "LINK_STATE"));
    // A confirmation signed by another key is refused.
    let wrong = new_key().sign(&link_lp(&[b"tree/link/confirm/v1", &l.raw, &hash])).to_bytes();
    let (st, v) = step(api, &l, json!({ "action": "confirm", "transcript_hash": b64(&hash), "signature": b64(&wrong) })).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LINK_SIGNATURE"));
    assert_eq!(confirm(api, &l, &hash).await.0, StatusCode::OK);

    // Completion: the same hash, signed by the opening device's own key.
    let (st, v) = complete(api, &a, &l, &[9; 32], &a.key).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "TRANSCRIPT_MISMATCH"));
    let (st, v) = complete(api, &a, &l, &hash, &a2.key).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LINK_SIGNATURE"), "another device's key is not this device's authorisation");
    let (st, v) = complete(api, &a, &l, &hash, &l.new).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LINK_SIGNATURE"));
    assert_eq!(devices(api, &a).await, 2);
    let (st, v) = complete(api, &a, &l, &hash, &a.key).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let new_id = v["device_id"].as_str().unwrap().to_string();
    assert_eq!(devices(api, &a).await, 3);

    // The new device picks up its id and the sealed data, then clears it.
    let (_, v) = api.new_device(&l.new, Method::GET, &l.path("/new"), None).await;
    assert_eq!((v["state"].as_str(), v["device_id"].as_str(), v["sealed"].as_str()), (Some("linked"), Some(new_id.as_str()), Some(b64(b"sealed").as_str())));
    assert_eq!(step(api, &l, json!({ "action": "done" })).await.0, StatusCode::OK);
    let (_, v) = api.new_device(&l.new, Method::GET, &l.path("/new"), None).await;
    assert!(v["sealed"].is_null() && v["offer"].is_null());
    let dev = Device { key: l.new.clone(), account_id: a.account_id.clone(), device_id: new_id };
    assert_eq!(api.call(&dev, Method::GET, "/v1/keypackages/count", None).await.0, StatusCode::OK);

    // Used once: no second completion, no reuse of the link id.
    let (st, _) = complete(api, &a, &l, &hash, &a.key).await;
    assert_eq!(st, StatusCode::GONE);
    let (st, v) = open(api, &a, &l, b"offer").await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"));
    assert_eq!(step(api, &l, json!({ "action": "cancel" })).await.0, StatusCode::CONFLICT, "linked stays linked");

    // A registered key cannot be offered again.
    let mut l2 = Link::new();
    l2.new = a2.key.clone();
    let (st, v) = open(api, &a, &l2, b"offer").await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"));
    // The old way is gone.
    let (st, v) = api.call(&a, Method::POST, "/v1/devices", Some(json!({ "auth_pub": b64(&l2.pubkey()), "proof": b64(&[0u8; 64]) }))).await;
    assert_eq!((st, code(&v)), (StatusCode::GONE, "LINK_REQUIRED"));
    ts.stop().await;
}

#[tokio::test]
async fn cancel_expiry_limits_and_purge() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let db = &ts.server.state.db;

    // Cancelled by the new device: nothing more happens on it.
    let l = Link::new();
    open(api, &a, &l, b"o").await;
    step(api, &l, json!({ "action": "reveal", "reveal": b64(b"r") })).await;
    assert_eq!(step(api, &l, json!({ "action": "cancel" })).await.0, StatusCode::OK);
    let (_, v) = api.call(&a, Method::GET, &l.path(""), None).await;
    assert_eq!(v["state"], "cancelled");
    assert!(v["reveal"].is_null(), "relayed data is dropped");
    assert_eq!(confirm(api, &l, &[1; 32]).await.0, StatusCode::GONE);

    // Cancelled by the existing device after the new one confirmed.
    let l = Link::new();
    open(api, &a, &l, b"o").await;
    step(api, &l, json!({ "action": "reveal", "reveal": b64(b"r") })).await;
    confirm(api, &l, &[1; 32]).await;
    assert_eq!(api.call(&a, Method::POST, &l.path("/cancel"), None).await.0, StatusCode::OK);
    assert_eq!(complete(api, &a, &l, &[1; 32], &a.key).await.0, StatusCode::GONE);
    let (_, v) = api.new_device(&l.new, Method::GET, &l.path("/new"), None).await;
    assert_eq!(v["state"], "cancelled");

    // Expired: nothing works any more.
    let l = Link::new();
    open(api, &a, &l, b"o").await;
    step(api, &l, json!({ "action": "reveal", "reveal": b64(b"r") })).await;
    confirm(api, &l, &[1; 32]).await;
    sqlx::query("UPDATE link_sessions SET expires_at = 1 WHERE link_id = ?").bind(&l.id).execute(db).await.unwrap();
    assert_eq!(complete(api, &a, &l, &[1; 32], &a.key).await.0, StatusCode::GONE);
    assert_eq!(api.new_device(&l.new, Method::GET, &l.path("/new"), None).await.0, StatusCode::GONE);
    assert_eq!(api.call(&a, Method::GET, &l.path(""), None).await.1["state"], "expired");
    assert_eq!(devices(api, &a).await, 1);

    // Limits: two open sessions per account at a time; ten per hour.
    let (x, y) = (Link::new(), Link::new());
    assert_eq!(open(api, &a, &x, b"o").await.0, StatusCode::CREATED);
    assert_eq!(open(api, &a, &y, b"o").await.0, StatusCode::CREATED);
    let (st, v) = open(api, &a, &Link::new(), b"o").await;
    assert_eq!((st, code(&v)), (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"));
    api.call(&a, Method::POST, &x.path("/cancel"), None).await;
    api.call(&a, Method::POST, &y.path("/cancel"), None).await;
    for _ in 0..5 {
        let l = Link::new();
        assert_eq!(open(api, &a, &l, b"o").await.0, StatusCode::CREATED);
        api.call(&a, Method::POST, &l.path("/cancel"), None).await;
    }
    let (st, _) = open(api, &a, &Link::new(), b"o").await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "ten sessions in the last hour");
    // Size limits.
    let b = api.signup().await;
    let (st, _) = open(api, &b, &Link::new(), &vec![0u8; tree_server::links::MAX_OFFER + 1]).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    let l = Link::new();
    open(api, &b, &l, b"o").await;
    let (st, _) = step(api, &l, json!({ "action": "reveal", "reveal": b64(&vec![0u8; tree_server::links::MAX_REVEAL + 1]) })).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);

    // Purge: relayed data of expired sessions at once, rows after an hour.
    let now = now();
    tree_server::purge_expired(&ts.server.state, now + tree_server::links::LIFETIME + 1).await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM link_sessions WHERE length(offer) > 0 OR reveal IS NOT NULL").fetch_one(db).await.unwrap();
    assert_eq!(left, 0);
    tree_server::purge_expired(&ts.server.state, now + tree_server::links::LIFETIME + tree_server::links::KEEP_EXPIRED + 1).await.unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM link_sessions").fetch_one(db).await.unwrap();
    assert_eq!(rows, 0);
    ts.stop().await;
}
