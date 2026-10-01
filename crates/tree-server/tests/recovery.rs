//! Account recovery with the recovery key (PROTOCOL.md 8.6).

mod common;

use common::*;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use tree_server::recovery::{change_message, recovery_message, CHANGE_CONTEXT, CHANGE_DELAY, SET_CONTEXT};

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

fn pk(k: &SigningKey) -> [u8; 32] {
    *k.verifying_key().as_bytes()
}

/// A recovery request by a new device key, signed by `rk`, then tweaked.
async fn recover(api: &Api, rk: &SigningKey, new: &SigningKey, revoke: bool, tweak: impl FnOnce(&mut Value)) -> (StatusCode, Value) {
    let auth_pub = pk(new);
    let ts = now();
    let mut body = json!({
        "recovery_pub": b64(&pk(rk)),
        "auth_pub": b64(&auth_pub),
        "pow_nonce": solve_pow(&auth_pub, POW_BITS),
        "signature": b64(&rk.sign(&recovery_message(&auth_pub, revoke, ts)).to_bytes()),
        "ts": ts,
        "revoke_others": revoke,
    });
    tweak(&mut body);
    api.send(&Signed::new(Method::POST, "/v1/recovery/recover", None, Some(&body)), new).await
}

/// Registers `key` for `dev`'s account; `current` signs the change.
async fn apply(api: &Api, dev: &Device, key: &SigningKey, current: Option<&SigningKey>) -> (StatusCode, Value) {
    let body = json!({
        "recovery_pub": b64(&pk(key)),
        "proof": b64(&key.sign(&change_message(SET_CONTEXT, &dev.account_id, &pk(key))).to_bytes()),
        "current_signature": current.map(|c| b64(&c.sign(&change_message(CHANGE_CONTEXT, &dev.account_id, &pk(key))).to_bytes())),
    });
    api.call(dev, Method::POST, "/v1/recovery/apply", Some(body)).await
}

async fn release(api: &Api, dev: &Device, current: Option<&SigningKey>) -> (StatusCode, Value) {
    let body = json!({
        "current_signature": current.map(|c| b64(&c.sign(&change_message(CHANGE_CONTEXT, &dev.account_id, &[0; 32])).to_bytes())),
    });
    api.call(dev, Method::POST, "/v1/recovery/release", Some(body)).await
}

async fn age_pending(ts: &TestServer) {
    sqlx::query("UPDATE account_recovery SET pending_since = pending_since - ?")
        .bind(CHANGE_DELAY)
        .execute(&ts.server.state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn recovery_rules() {
    let ts = boot(|c| c.max_devices_per_account = 3).await;
    let api = &ts.api;
    let a = api.signup().await;
    let a2 = api.add_device(&a).await;
    let rk = new_key();

    // Unregistered key: refused.
    let (st, v) = recover(api, &rk, &new_key(), false, |_| {}).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "RECOVERY_REFUSED"), "{v}");

    // A key needs its proof of possession.
    let other = new_key();
    let mut body = json!({ "recovery_pub": b64(&pk(&rk)), "proof": b64(&other.sign(&change_message(SET_CONTEXT, &a.account_id, &pk(&rk))).to_bytes()) });
    assert_eq!(api.call(&a, Method::POST, "/v1/recovery/apply", Some(body.clone())).await.0, StatusCode::BAD_REQUEST);
    body["proof"] = json!(b64(&rk.sign(&change_message(SET_CONTEXT, "another account", &pk(&rk))).to_bytes()));
    assert_eq!(api.call(&a, Method::POST, "/v1/recovery/apply", Some(body)).await.0, StatusCode::BAD_REQUEST, "bound to the account");

    let (st, v) = apply(api, &a, &rk, None).await;
    assert_eq!((st, v["state"].as_str(), &v["pending"]), (StatusCode::OK, Some("applied"), &Value::Null), "first key: immediate");
    let b = api.signup().await;
    let (st, v) = apply(api, &b, &rk, None).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"), "one key, one account");

    // Signature checks: wrong signer, flag, new key, time, length, proof of work.
    let (st, _) = recover(api, &new_key(), &new_key(), false, |b| b["recovery_pub"] = json!(b64(&pk(&rk)))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = recover(api, &rk, &new_key(), false, |b| b["revoke_others"] = json!(true)).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "flag is signed");
    let (st, _) = recover(api, &rk, &new_key(), false, |b| b["ts"] = json!(b["ts"].as_i64().unwrap() + 1)).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "time is signed");
    let stale = new_key();
    let old_ts = now() - 3600;
    let stale_sig = b64(&rk.sign(&recovery_message(&pk(&stale), false, old_ts)).to_bytes());
    let (st, v) = recover(api, &rk, &stale, false, |b| { b["ts"] = json!(old_ts); b["signature"] = json!(stale_sig); }).await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "TIMESTAMP_SKEW"), "an old signature cannot be replayed");
    let n = new_key();
    let sig_for_other = b64(&rk.sign(&recovery_message(&pk(&other), false, now())).to_bytes());
    let (st, _) = recover(api, &rk, &n, false, |b| b["signature"] = json!(sig_for_other)).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "signature binds the new key");
    let weak = new_key();
    let weak_nonce = bad_pow(&pk(&weak), POW_BITS);
    let (st, v) = recover(api, &rk, &weak, false, |b| b["pow_nonce"] = json!(weak_nonce)).await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "POW_INVALID"));
    let (st, _) = recover(api, &rk, &new_key(), false, |b| b["signature"] = json!(b64(&[0; 63]))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Joins the account; the device limit counts; a known key is refused
    // before anything is revoked.
    let n1 = new_key();
    let (st, v) = recover(api, &rk, &n1, false, |_| {}).await;
    assert_eq!((st, v["account_id"].as_str(), v["revoked"].as_u64()), (StatusCode::CREATED, Some(a.account_id.as_str()), Some(0)), "{v}");
    let (st, v) = recover(api, &rk, &new_key(), false, |_| {}).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "LIMIT_EXCEEDED"));
    let (st, v) = recover(api, &rk, &n1, true, |_| {}).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"));
    assert_eq!(api.call(&a, Method::GET, "/v1/devices", None).await.1["devices"].as_array().unwrap().len(), 3);

    // A stolen device (a2) replaces the key without the phrase: pending for
    // 7 days. The owner's phrase still recovers, cancels the change and
    // revokes the thief.
    let thief_key = new_key();
    let (st, v) = apply(api, &a2, &thief_key, None).await;
    assert_eq!((st, v["state"].as_str(), v["pending"]["action"].as_str()), (StatusCode::OK, Some("applied"), Some("replace")), "{v}");
    let (_, v) = api.call(&a, Method::GET, "/v1/recovery", None).await;
    assert_eq!(v["pending"]["action"], "replace", "every device sees it");
    let (st, _) = recover(api, &thief_key, &new_key(), true, |_| {}).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a pending key does not recover yet");
    let owner = new_key();
    let (st, v) = recover(api, &rk, &owner, true, |_| {}).await;
    assert_eq!((st, v["revoked"].as_u64()), (StatusCode::CREATED, Some(3)), "{v}");
    let d = Device { key: owner, account_id: a.account_id.clone(), device_id: v["device_id"].as_str().unwrap().into() };
    assert_eq!(api.call(&a2, Method::GET, "/v1/devices", None).await.0, StatusCode::UNAUTHORIZED, "thief cut off");
    let (_, v) = api.call(&d, Method::GET, "/v1/recovery", None).await;
    assert_eq!(v["pending"], Value::Null, "the thief's change was cancelled");

    // Without anyone stopping it, a pending change takes effect after 7 days.
    let k2 = new_key();
    apply(api, &d, &k2, None).await;
    age_pending(&ts).await;
    let (_, v) = api.call(&d, Method::GET, "/v1/recovery", None).await;
    assert_eq!((v["state"].as_str(), &v["pending"]), (Some("applied"), &Value::Null));
    assert_eq!(recover(api, &rk, &new_key(), false, |_| {}).await.0, StatusCode::FORBIDDEN, "old key retired");
    assert_eq!(recover(api, &k2, &new_key(), false, |_| {}).await.0, StatusCode::CREATED);

    // With the current key's signature a change is immediate; a wrong one is refused.
    let k3 = new_key();
    let (st, v) = apply(api, &d, &k3, Some(&new_key())).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "RECOVERY_REFUSED"));
    let (st, v) = apply(api, &d, &k3, Some(&k2)).await;
    assert_eq!((st, &v["pending"]), (StatusCode::OK, &Value::Null));
    assert_eq!(recover(api, &k2, &new_key(), false, |_| {}).await.0, StatusCode::FORBIDDEN);

    // Release: pending without the phrase, immediate with it.
    let (_, v) = release(api, &d, None).await;
    assert_eq!((v["state"].as_str(), v["pending"]["action"].as_str()), (Some("applied"), Some("release")));
    let (_, v) = release(api, &d, Some(&k3)).await;
    assert_eq!((v["state"].as_str(), &v["pending"]), (Some("released"), &Value::Null));
    assert_eq!(recover(api, &k3, &new_key(), false, |_| {}).await.0, StatusCode::FORBIDDEN);
    // Another account may now use that key.
    assert_eq!(apply(api, &b, &k3, None).await.0, StatusCode::OK);
    ts.stop().await;
}
