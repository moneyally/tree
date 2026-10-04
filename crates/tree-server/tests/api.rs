//! End-to-end API tests: real server on a random port, real HTTP, real Ed25519.

mod common;

use std::collections::HashSet;
use std::time::{Duration, Instant};

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

async fn blob_count(ts: &TestServer) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM blobs")
        .fetch_one(&ts.server.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn healthz_and_unknown_routes() {
    let ts = boot(|_| {}).await;
    let (st, v) = decode(
        ts.api
            .http
            .get(ts.api.url("/healthz"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["status"], "ok");
    let (st, v) = decode(
        ts.api
            .http
            .get(ts.api.url("/v1/nope"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((st, code(&v)), (StatusCode::NOT_FOUND, "NOT_FOUND"));
    let (st, v) = decode(
        ts.api
            .http
            .delete(ts.api.url("/v1/features"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED")
    );
    ts.stop().await;
}

#[tokio::test]
async fn signup_with_valid_and_invalid_pow() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;

    // Valid proof-of-work.
    let dev = api.signup().await;
    assert_eq!(dev.account_id.len(), 22);
    assert_eq!(dev.device_id.len(), 22);
    assert_ne!(dev.account_id, dev.device_id);

    // Invalid proof-of-work.
    let key = new_key();
    let bad = bad_pow(key.verifying_key().as_bytes(), POW_BITS);
    let (st, v) = api.signup_raw(&key, bad).await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::BAD_REQUEST, "POW_INVALID"),
        "{v}"
    );

    // Same key twice.
    let nonce = solve_pow(key.verifying_key().as_bytes(), POW_BITS);
    let (st, _) = api.signup_raw(&key, nonce).await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, v) = api.signup_raw(&key, nonce).await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::CONFLICT, "ALREADY_EXISTS"),
        "{v}"
    );

    // Signup signed by a key other than auth_pub (no proof of possession).
    let victim = new_key();
    let nonce = solve_pow(victim.verifying_key().as_bytes(), POW_BITS);
    let body = json!({ "auth_pub": b64(victim.verifying_key().as_bytes()), "pow_nonce": nonce });
    let s = Signed::new(Method::POST, "/v1/accounts", None, Some(&body));
    let (st, v) = api.send(&s, &new_key()).await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
        "{v}"
    );

    // Malformed key.
    let s = Signed::new(
        Method::POST,
        "/v1/accounts",
        None,
        Some(&json!({ "auth_pub": "AAAA", "pow_nonce": 1 })),
    );
    let (st, v) = api.send(&s, &key).await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
        "{v}"
    );
    ts.stop().await;
}

#[tokio::test]
async fn pow_difficulty_is_enforced_at_default_strength() {
    // With 20 bits a random nonce is accepted with probability 2^-20.
    let ts = boot(|c| c.pow_bits = 20).await;
    let key = new_key();
    let nonce = bad_pow(key.verifying_key().as_bytes(), 20);
    let (st, v) = ts.api.signup_raw(&key, nonce).await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "POW_INVALID"));
    let nonce = solve_pow(key.verifying_key().as_bytes(), 20);
    let (st, v) = ts.api.signup_raw(&key, nonce).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    ts.stop().await;
}

#[tokio::test]
async fn flags_require_operator_and_lock_signups() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;

    let (st, v) = decode(api.http.get(api.url("/v1/features")).send().await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    let keys: Vec<&str> = v["features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["key"].as_str().unwrap())
        .collect();
    assert_eq!(
        keys,
        [
            "server.bot_platform",
            "server.calls",
            "server.public_spaces",
            "server.signups"
        ]
    );
    assert!(v["features"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["state"] == "applied"));

    // Operator token required.
    let (st, v) = api.admin(None, "server.signups", "release").await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"));
    let (st, v) = api.admin(Some("wrong"), "server.signups", "release").await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"));
    let (st, v) = api.admin(Some(ADMIN_TOKEN), "server.nope", "apply").await;
    assert_eq!((st, code(&v)), (StatusCode::NOT_FOUND, "UNKNOWN_FEATURE"));

    // Release, idempotently.
    let (st, first) = api
        .admin(Some(ADMIN_TOKEN), "server.signups", "release")
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(first["state"], "released");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (st, again) = api
        .admin(Some(ADMIN_TOKEN), "server.signups", "release")
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(again, first, "repeating a release changes nothing");

    // Signups are locked.
    let key = new_key();
    let nonce = solve_pow(key.verifying_key().as_bytes(), POW_BITS);
    let (st, v) = api.signup_raw(&key, nonce).await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::FORBIDDEN, "LOCKED_BY_SERVER"),
        "{v}"
    );

    // Apply again: signups work.
    let (st, v) = api
        .admin(Some(ADMIN_TOKEN), "server.signups", "apply")
        .await;
    assert_eq!((st, v["state"].as_str()), (StatusCode::OK, Some("applied")));
    let (st, v) = api.signup_raw(&key, nonce).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");

    // Changes are in the operator audit trail.
    let n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM feature_audit WHERE key = 'server.signups'")
            .fetch_one(&ts.server.state.db)
            .await
            .unwrap();
    assert_eq!(n, 2);
    ts.stop().await;

    // Without a configured token the operator endpoints are closed.
    let ts = boot(|c| c.admin_token_sha256 = None).await;
    let (st, v) = ts
        .api
        .admin(Some(ADMIN_TOKEN), "server.signups", "release")
        .await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"));
    ts.stop().await;
}

#[tokio::test]
async fn authentication_failures() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let dev = api.signup().await;
    let other = api.signup().await;
    api.seed_fake_group(&dev, &[&other.device_id]).await;
    let path = "/v1/keypackages/count";

    // Baseline works.
    let (st, _) = api.call(&dev, Method::GET, path, None).await;
    assert_eq!(st, StatusCode::OK);

    // Signed by another device's key.
    let s = Signed::new(Method::GET, path, Some(&dev.device_id), None);
    let (st, v) = api.send(&s, &other.key).await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"));

    // Garbage signature.
    let s = Signed::new(Method::GET, path, Some(&dev.device_id), None);
    let (st, _) = api.send_with_sig(&s, &b64(&[0u8; 64])).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Signature over a different path.
    let mut s = Signed::new(Method::GET, path, Some(&dev.device_id), None);
    s.sign_path = Some("/v1/messages".into());
    let (st, _) = api.send(&s, &dev.key).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Body changed after signing.
    let body = json!({ "recipients": [other.device_id], "body": b64(&app(b"hello")) });
    let mut s = Signed::new(
        Method::POST,
        "/v1/messages",
        Some(&dev.device_id),
        Some(&body),
    );
    s.sign_body = Some(
        serde_json::to_vec(
            &json!({ "recipients": [other.device_id], "body": b64(&app(b"HELLO")) }),
        )
        .unwrap(),
    );
    let (st, _) = api.send(&s, &dev.key).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert!(api.fetch(&other, 0).await.is_empty());

    // Stale and future timestamps.
    for offset in [-400, 400] {
        let mut s = Signed::new(Method::GET, path, Some(&dev.device_id), None);
        s.ts = now() + offset;
        let (st, v) = api.send(&s, &dev.key).await;
        assert_eq!(
            (st, code(&v)),
            (StatusCode::UNAUTHORIZED, "TIMESTAMP_SKEW"),
            "offset {offset}"
        );
    }
    // Inside the window is fine.
    let mut s = Signed::new(Method::GET, path, Some(&dev.device_id), None);
    s.ts = now() - 200;
    assert_eq!(api.send(&s, &dev.key).await.0, StatusCode::OK);

    // Replay: the exact same signed request twice.
    let s = Signed::new(
        Method::POST,
        "/v1/messages",
        Some(&dev.device_id),
        Some(&body),
    );
    let sig = s.signature(&dev.key);
    let (st, v) = api.send_with_sig(&s, &sig).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let (st, v) = api.send_with_sig(&s, &sig).await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"));
    assert_eq!(v["message"], "replayed request");
    assert_eq!(
        api.fetch(&other, 0).await.len(),
        1,
        "the replay was not delivered"
    );

    // Unknown device, missing headers, bad nonce.
    let ghost = Device {
        key: new_key(),
        account_id: dev.account_id.clone(),
        device_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    assert_eq!(
        api.call(&ghost, Method::GET, path, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (st, v) = decode(api.http.get(api.url(path)).send().await.unwrap()).await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"));
    let mut s = Signed::new(Method::GET, path, Some(&dev.device_id), None);
    s.nonce = "short".into();
    assert_eq!(api.send(&s, &dev.key).await.0, StatusCode::UNAUTHORIZED);

    // Signup replay is rejected too.
    let key = new_key();
    let nonce = solve_pow(key.verifying_key().as_bytes(), POW_BITS);
    let body = json!({ "auth_pub": b64(key.verifying_key().as_bytes()), "pow_nonce": nonce });
    let s = Signed::new(Method::POST, "/v1/accounts", None, Some(&body));
    let sig = s.signature(&key);
    assert_eq!(api.send_with_sig(&s, &sig).await.0, StatusCode::CREATED);
    let (st, v) = api.send_with_sig(&s, &sig).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{v}");
    ts.stop().await;
}

#[tokio::test]
async fn devices_add_list_remove() {
    let ts = boot(|c| c.max_devices_per_account = 3).await;
    let api = &ts.api;
    let a1 = api.signup().await;
    let a2 = api.add_device(&a1).await;
    assert_eq!(a2.account_id, a1.account_id);
    assert_eq!(
        api.call(&a2, Method::GET, "/v1/keypackages/count", None)
            .await
            .0,
        StatusCode::OK
    );

    // Proof by the wrong key.
    let (st, v) = api.add_device_raw(&a1, &new_key(), &new_key()).await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
        "{v}"
    );
    // Re-registering an existing key.
    let (st, v) = api.add_device_raw(&a1, &a2.key, &a2.key).await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::CONFLICT, "ALREADY_EXISTS"),
        "{v}"
    );

    let _a3 = api.add_device(&a1).await;
    let (st, v) = api.add_device_raw(&a1, &new_key(), &new_key()).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    let k = new_key();
    let (st, v) = api.add_device_raw(&a1, &k, &k).await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::CONFLICT, "LIMIT_EXCEEDED"),
        "{v}"
    );

    let (st, v) = api.call(&a1, Method::GET, "/v1/devices", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["devices"].as_array().unwrap().len(), 3);

    // Another account cannot remove my device.
    let b = api.signup().await;
    let (st, v) = api
        .call(
            &b,
            Method::DELETE,
            &format!("/v1/devices/{}", a2.device_id),
            None,
        )
        .await;
    assert_eq!((st, code(&v)), (StatusCode::NOT_FOUND, "NOT_FOUND"));

    // Removing a device drops its mailbox; the device can no longer authenticate.
    api.send_msg(&b, &[&a2.device_id], b"for a2").await;
    let (st, _) = api
        .call(
            &a1,
            Method::DELETE,
            &format!("/v1/devices/{}", a2.device_id),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        api.call(&a2, Method::GET, "/v1/messages", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(blob_count(&ts).await, 0);

    // Removing the last device removes the account.
    let (st, _) = api
        .call(
            &b,
            Method::DELETE,
            &format!("/v1/devices/{}", b.device_id),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let (st, v) = api.claim(&a1, &b.account_id).await;
    assert_eq!((st, code(&v)), (StatusCode::NOT_FOUND, "NOT_FOUND"));
    ts.stop().await;
}

#[tokio::test]
async fn key_packages_are_one_time() {
    let ts = boot(|c| {
        c.max_key_packages_per_upload = 5;
        c.max_key_packages_per_device = 8;
        c.max_key_package_bytes = 3000;
    })
    .await;
    let api = &ts.api;
    let alice = api.signup().await;
    let alice2 = api.add_device(&alice).await;
    let bob = api.signup().await;

    let kp = |tag: &str, i: usize| format!("{tag}-key-package-{i}").into_bytes();
    let (st, v) = api
        .upload(&alice, &(0..3).map(|i| kp("a1", i)).collect::<Vec<_>>())
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        (v["stored"].as_i64(), v["count"].as_i64()),
        (Some(3), Some(3))
    );
    api.upload(&alice2, &[kp("a2", 0)]).await;
    assert_eq!(api.kp_count(&alice).await, 3);
    assert_eq!(api.kp_count(&alice2).await, 1);

    // One package per device of the account.
    let (st, v) = api.claim(&bob, &alice.account_id).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let got = v["key_packages"].as_array().unwrap();
    assert_eq!(got.len(), 2);
    let mut seen = HashSet::new();
    for p in got {
        let dev = p["device_id"].as_str().unwrap();
        assert!(dev == alice.device_id || dev == alice2.device_id);
        assert!(seen.insert(unb64(p["key_package"].as_str().unwrap())));
    }
    assert!(seen.contains(&kp("a2", 0)));
    assert!(seen.contains(&kp("a1", 0)), "oldest first");
    assert_eq!(api.kp_count(&alice).await, 2);
    assert_eq!(api.kp_count(&alice2).await, 0);

    // alice2 is exhausted now.
    let (_, v) = api.claim(&bob, &alice.account_id).await;
    assert_eq!(v["key_packages"].as_array().unwrap().len(), 1);
    assert_eq!(v["exhausted"], json!([alice2.device_id]));
    let (_, v) = api.claim(&bob, &alice.account_id).await;
    assert_eq!(
        unb64(v["key_packages"][0]["key_package"].as_str().unwrap()),
        kp("a1", 2)
    );
    let (st, v) = api.claim(&bob, &alice.account_id).await;
    assert_eq!(st, StatusCode::OK);
    assert!(v["key_packages"].as_array().unwrap().is_empty());
    assert_eq!(v["exhausted"].as_array().unwrap().len(), 2);

    // Limits.
    let (st, v) = api
        .upload(&bob, &(0..6).map(|i| kp("b", i)).collect::<Vec<_>>())
        .await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE"),
        "batch count"
    );
    let (st, v) = api.upload(&bob, &[vec![7u8; 3001]]).await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE"),
        "package size"
    );
    assert_eq!(api.upload(&bob, &[vec![7u8; 3000]]).await.0, StatusCode::OK);
    assert_eq!(
        api.upload(&bob, &(0..5).map(|i| kp("b", i)).collect::<Vec<_>>())
            .await
            .0,
        StatusCode::OK
    );
    let (st, v) = api
        .upload(&bob, &(5..8).map(|i| kp("b", i)).collect::<Vec<_>>())
        .await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::CONFLICT, "LIMIT_EXCEEDED"),
        "per-device total"
    );
    assert_eq!(api.kp_count(&bob).await, 6);
    let (st, v) = api.upload(&bob, &[]).await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "BAD_REQUEST"));
    let (st, v) = api.claim(&bob, "AAAAAAAAAAAAAAAAAAAAAA").await;
    assert_eq!((st, code(&v)), (StatusCode::NOT_FOUND, "NOT_FOUND"));
    let (st, v) = api.claim(&bob, "not-an-id").await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "BAD_REQUEST"));
    ts.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_claims_never_share_a_package() {
    const PACKAGES: usize = 20;
    const CLAIMERS: usize = 24;
    let ts = boot(|c| c.max_key_packages_per_upload = 50).await;
    let api = std::sync::Arc::new(Api {
        http: reqwest::Client::new(),
        base: ts.api.base.clone(),
    });
    let owner = api.signup().await;
    let packages: Vec<Vec<u8>> = (0..PACKAGES)
        .map(|i| format!("kp-{i:02}").into_bytes())
        .collect();
    assert_eq!(api.upload(&owner, &packages).await.0, StatusCode::OK);

    let mut claimers = Vec::new();
    for _ in 0..4 {
        claimers.push(api.signup().await);
    }
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(CLAIMERS));
    let mut tasks = Vec::new();
    for i in 0..CLAIMERS {
        let api = api.clone();
        let claimer = claimers[i % claimers.len()].clone();
        let account = owner.account_id.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            api.claim(&claimer, &account).await
        }));
    }
    let mut got = Vec::new();
    let mut exhausted = 0;
    for t in tasks {
        let (st, v) = t.await.unwrap();
        assert_eq!(st, StatusCode::OK, "{v}");
        match v["key_packages"].as_array().unwrap().first() {
            Some(p) => got.push(unb64(p["key_package"].as_str().unwrap())),
            None => exhausted += 1,
        }
    }
    let unique: HashSet<_> = got.iter().cloned().collect();
    assert_eq!(got.len(), PACKAGES, "every package handed out");
    assert_eq!(unique.len(), PACKAGES, "no package handed out twice");
    assert_eq!(exhausted, CLAIMERS - PACKAGES);
    assert_eq!(api.kp_count(&owner).await, 0);
    ts.stop().await;
}

#[tokio::test]
async fn mailbox_fan_out_fetch_and_ack() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let bob1 = api.signup().await;
    let bob2 = api.add_device(&bob1).await;
    let carol = api.signup().await;
    api.seed_fake_group(
        &alice,
        &[&bob1.device_id, &bob2.device_id, &carol.device_id],
    )
    .await;

    let body = b"opaque ciphertext \x00\x01\x02";
    let (st, v) = api
        .send_msg(
            &alice,
            &[
                &bob1.device_id,
                &bob2.device_id,
                &carol.device_id,
                &bob1.device_id,
                "AAAAAAAAAAAAAAAAAAAAAA",
            ],
            body,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["delivered"], 3, "duplicates collapse");
    assert_eq!(v["unknown_devices"], json!(["AAAAAAAAAAAAAAAAAAAAAA"]));
    assert_eq!(blob_count(&ts).await, 1, "one stored copy of the body");

    // The sender is not stored anywhere next to the message.
    let row: (String,) = sqlx::query_as("SELECT sql FROM sqlite_master WHERE name = 'deliveries'")
        .fetch_one(&ts.server.state.db)
        .await
        .unwrap();
    assert!(!row.0.contains("sender"));

    let b1 = api.fetch(&bob1, 0).await;
    let b2 = api.fetch(&bob2, 0).await;
    let c = api.fetch(&carol, 0).await;
    assert_eq!((b1.len(), b2.len(), c.len()), (1, 1, 1));
    assert!(api.fetch(&alice, 0).await.is_empty());
    for m in [&b1[0], &b2[0], &c[0]] {
        assert_eq!(unb64(m["body"].as_str().unwrap()), app(body));
        let t = m["received_at"].as_i64().unwrap();
        assert_eq!(t % 60, 0, "rounded to the minute");
        assert!((now() - t) < 120);
    }
    let b1_id = b1[0]["id"].as_str().unwrap();
    let b2_id = b2[0]["id"].as_str().unwrap();
    let c_id = c[0]["id"].as_str().unwrap();
    assert_ne!(b1_id, b2_id);

    // Nobody else can ack bob1's message (other account, or bob's other device).
    let (st, v) = api.ack(&carol, &[b1_id]).await;
    assert_eq!((st, v["deleted"].as_i64()), (StatusCode::OK, Some(0)));
    let (_, v) = api.ack(&bob2, &[b1_id]).await;
    assert_eq!(v["deleted"], 0);
    assert_eq!(api.fetch(&bob1, 0).await.len(), 1, "still there");

    // Own acks delete; the body goes when the last recipient acks.
    let (_, v) = api.ack(&bob1, &[b1_id, b1_id]).await;
    assert_eq!(v["deleted"], 1);
    assert!(api.fetch(&bob1, 0).await.is_empty());
    assert_eq!(api.ack(&bob2, &[b2_id]).await.1["deleted"], 1);
    assert_eq!(blob_count(&ts).await, 1);
    assert_eq!(api.ack(&carol, &[c_id]).await.1["deleted"], 1);
    assert_eq!(blob_count(&ts).await, 0, "body deleted after the last ack");
    let (st, v) = api.ack(&carol, &["bad id"]).await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "BAD_REQUEST"));

    // Order and paging.
    for i in 0..5 {
        api.send_msg(&alice, &[&carol.device_id], format!("m{i}").as_bytes())
            .await;
    }
    let msgs = api.fetch(&carol, 0).await;
    let bodies: Vec<Vec<u8>> = msgs
        .iter()
        .map(|m| unb64(m["body"].as_str().unwrap()))
        .collect();
    assert_eq!(
        bodies,
        (0..5)
            .map(|i| app(format!("m{i}").as_bytes()))
            .collect::<Vec<_>>()
    );
    ts.stop().await;
}

#[tokio::test]
async fn fetch_pages_with_more_flag() {
    let ts = boot(|c| c.fetch_limit = 2).await;
    let api = &ts.api;
    let a = api.signup().await;
    let b = api.signup().await;
    api.seed_fake_group(&a, &[&b.device_id]).await;
    for i in 0..3 {
        api.send_msg(&a, &[&b.device_id], &[i]).await;
    }
    let (_, v) = api.call(&b, Method::GET, "/v1/messages", None).await;
    assert_eq!(v["messages"].as_array().unwrap().len(), 2);
    assert_eq!(v["more"], true);
    let ids: Vec<&str> = v["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    api.ack(&b, &ids).await;
    let (_, v) = api.call(&b, Method::GET, "/v1/messages", None).await;
    assert_eq!(v["messages"].as_array().unwrap().len(), 1);
    assert_eq!(v["more"], false);
    ts.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_poll_wakes_on_new_message() {
    let ts = boot(|_| {}).await;
    let api = std::sync::Arc::new(Api {
        http: reqwest::Client::new(),
        base: ts.api.base.clone(),
    });
    let a = api.signup().await;
    let b = api.signup().await;
    api.seed_fake_group(&a, &[&b.device_id]).await;

    // Empty mailbox: returns after the wait with nothing.
    let t = Instant::now();
    assert!(api.fetch(&b, 1).await.is_empty());
    assert!(t.elapsed() >= Duration::from_millis(900), "waited");

    // A message arriving during the wait ends it early.
    let waiter = {
        let api = api.clone();
        let b = b.clone();
        tokio::spawn(async move {
            let t = Instant::now();
            let msgs = api.fetch(&b, 20).await;
            (msgs, t.elapsed())
        })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    api.send_msg(&a, &[&b.device_id], b"wake up").await;
    let (msgs, took) = waiter.await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(unb64(msgs[0]["body"].as_str().unwrap()), app(b"wake up"));
    assert!(took < Duration::from_secs(5), "woke early: {took:?}");
    assert_eq!(
        ts.server.state.waiters.len(),
        0,
        "no subscriptions left behind"
    );

    // Pending message: returns immediately even with a wait.
    let t = Instant::now();
    assert_eq!(api.fetch(&b, 20).await.len(), 1);
    assert!(t.elapsed() < Duration::from_secs(2));

    // A malformed wait is rejected.
    let (st, _) = api
        .call(&b, Method::GET, "/v1/messages?wait=abc", None)
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    ts.stop().await;
}

#[tokio::test]
async fn message_size_recipient_and_mailbox_limits() {
    let ts = boot(|c| {
        c.max_mailbox_messages = 3;
        c.max_recipients = 1000;
    })
    .await;
    let api = &ts.api;
    let a = api.signup().await;
    let b = api.signup().await;
    api.seed_fake_group(&a, &[&b.device_id]).await;

    // Body size: exactly 256 KiB is accepted, one byte more is not.
    let max = 256 * 1024;
    let (st, v) = api.send_raw(&a, &[&b.device_id], &app_sized(max)).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let (st, v) = api.send_raw(&a, &[&b.device_id], &app_sized(max + 1)).await;
    assert_eq!((st, code(&v)), (StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE"));
    let (st, v) = api.send_msg(&a, &[&b.device_id], b"").await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "BAD_REQUEST"));

    // Recipients: 1000 is accepted (unknown ones reported), 1001 is not.
    let ids: Vec<String> = (0..1000u32).map(|i| format!("{:0>21}A", i)).collect();
    let mut refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    refs[0] = &b.device_id;
    let (st, v) = api.send_msg(&a, &refs, b"x").await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["delivered"], 1);
    assert_eq!(v["unknown_devices"].as_array().unwrap().len(), 999);
    let ids: Vec<String> = (0..1001u32).map(|i| format!("{:0>21}A", i)).collect();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let (st, v) = api.send_msg(&a, &refs, b"x").await;
    assert_eq!((st, code(&v)), (StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE"));
    let (st, v) = api.send_msg(&a, &[], b"x").await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "BAD_REQUEST"));
    let (st, v) = api.send_msg(&a, &["../../etc"], b"x").await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "BAD_REQUEST"));

    // Mailbox quota: b holds 2 messages; the 3rd fits, the 4th is refused for b.
    assert_eq!(
        api.send_msg(&a, &[&b.device_id], b"3").await.1["delivered"],
        1
    );
    let (st, v) = api.send_msg(&a, &[&b.device_id], b"4").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["delivered"], 0);
    assert_eq!(v["full_devices"], json!([b.device_id]));
    assert_eq!(
        blob_count(&ts).await,
        3,
        "nothing stored for an undelivered send"
    );

    // Oversized raw body is refused before parsing.
    let s = Signed::new(
        Method::POST,
        "/v1/messages",
        Some(&a.device_id),
        Some(&json!({ "x": "y".repeat(1 << 20) })),
    );
    let (st, v) = api.send(&s, &a.key).await;
    assert_eq!((st, code(&v)), (StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE"));
    ts.stop().await;
}

#[tokio::test]
async fn old_messages_are_purged() {
    // TTL of 1 second, purge task every second. Arrival times are rounded down
    // to the minute, so a message is "older than 1s" by the next purge.
    let ts = boot(|c| {
        c.message_ttl_secs = 1;
        c.purge_interval_secs = 1;
    })
    .await;
    let api = &ts.api;
    let a = api.signup().await;
    let b = api.signup().await;
    api.seed_fake_group(&a, &[&b.device_id]).await;
    api.send_msg(&a, &[&b.device_id], b"old").await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while blob_count(&ts).await > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(blob_count(&ts).await, 0, "purged by the background task");
    assert!(api.fetch(&b, 0).await.is_empty());
    ts.stop().await;

    // Direct check with the default 30-day TTL: young messages stay, old ones go.
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let b = api.signup().await;
    api.send_msg(&a, &[&b.device_id], b"young").await;
    let removed = tree_server::purge_expired(&ts.server.state, now())
        .await
        .unwrap();
    assert_eq!(removed, 0);
    assert_eq!(api.fetch(&b, 0).await.len(), 1);
    let removed = tree_server::purge_expired(&ts.server.state, now() + 30 * 86_400 + 120)
        .await
        .unwrap();
    assert_eq!(removed, 1);
    assert!(api.fetch(&b, 0).await.is_empty());
    ts.stop().await;
}

#[tokio::test]
async fn rate_limits() {
    let ts = boot(|c| {
        c.rate_per_sec = 0.01;
        c.rate_burst = 5.0;
        c.signup_per_hour = 1.0;
        c.signup_burst = 3.0;
    })
    .await;
    let api = &ts.api;
    let a = api.signup().await;
    let _b = api.signup().await;
    let _c = api.signup().await;

    // Per-address signup limit (address kept in memory only).
    let key = new_key();
    let nonce = solve_pow(key.verifying_key().as_bytes(), POW_BITS);
    let resp = api
        .http
        .post(api.url("/v1/accounts"))
        .json(&json!({ "auth_pub": b64(key.verifying_key().as_bytes()), "pow_nonce": nonce }))
        .send()
        .await
        .unwrap();
    assert!(resp.headers().contains_key("retry-after"));
    let (st, v) = decode(resp).await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
    );

    // Per-device bucket.
    for _ in 0..5 {
        assert_eq!(
            api.call(&a, Method::GET, "/v1/keypackages/count", None)
                .await
                .0,
            StatusCode::OK
        );
    }
    let (st, v) = api
        .call(&a, Method::GET, "/v1/keypackages/count", None)
        .await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
    );

    // A forged request for a device does not drain that device's bucket.
    let ts2 = boot(|c| {
        c.rate_per_sec = 0.01;
        c.rate_burst = 2.0;
    })
    .await;
    let victim = ts2.api.signup().await;
    for _ in 0..5 {
        let s = Signed::new(
            Method::GET,
            "/v1/keypackages/count",
            Some(&victim.device_id),
            None,
        );
        assert_eq!(
            ts2.api.send(&s, &new_key()).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        ts2.api
            .call(&victim, Method::GET, "/v1/keypackages/count", None)
            .await
            .0,
        StatusCode::OK
    );
    ts2.stop().await;
    ts.stop().await;
}
