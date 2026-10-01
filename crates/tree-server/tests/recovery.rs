//! Account recovery with the recovery key (PROTOCOL.md 8.6).

mod common;

use common::*;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use tree_server::recovery::recovery_message;

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

/// A recovery request by a new device key, signed by `rk` (or with a
/// tweaked body), with a valid proof of work unless `nonce` is given.
async fn recover(api: &Api, rk: &SigningKey, new: &SigningKey, revoke: bool, tweak: impl FnOnce(&mut Value)) -> (StatusCode, Value) {
    let auth_pub = *new.verifying_key().as_bytes();
    let mut body = json!({
        "recovery_pub": b64(rk.verifying_key().as_bytes()),
        "auth_pub": b64(&auth_pub),
        "pow_nonce": solve_pow(&auth_pub, POW_BITS),
        "signature": b64(&rk.sign(&recovery_message(&auth_pub, revoke)).to_bytes()),
        "revoke_others": revoke,
    });
    tweak(&mut body);
    api.send(&Signed::new(Method::POST, "/v1/recovery/recover", None, Some(&body)), new).await
}

async fn apply(api: &Api, dev: &Device, key: &SigningKey) -> (StatusCode, Value) {
    let body = json!({ "recovery_pub": b64(key.verifying_key().as_bytes()) });
    api.call(dev, Method::POST, "/v1/recovery/apply", Some(body)).await
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

    assert_eq!(apply(api, &a, &rk).await.0, StatusCode::OK);
    assert_eq!(apply(api, &a, &rk).await.0, StatusCode::OK, "idempotent");
    let b = api.signup().await;
    let (st, v) = apply(api, &b, &rk).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"), "one key, one account");
    let (st, _) = api.call(&a, Method::POST, "/v1/recovery/apply", Some(json!({ "recovery_pub": b64(&[0; 31]) }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Wrong signer, signature for another key or flag, weak proof of work, a device header.
    let (st, v) = recover(api, &new_key(), &new_key(), false, |b| b["recovery_pub"] = json!(b64(rk.verifying_key().as_bytes()))).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "RECOVERY_REFUSED"));
    let (st, _) = recover(api, &rk, &new_key(), false, |b| b["revoke_others"] = json!(true)).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "flag is signed");
    let other = new_key();
    let sig_for_other = b64(&rk.sign(&recovery_message(other.verifying_key().as_bytes(), false)).to_bytes());
    let (st, _) = recover(api, &rk, &new_key(), false, |b| b["signature"] = json!(sig_for_other)).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "signature binds the new key");
    let weak = new_key();
    let weak_nonce = bad_pow(weak.verifying_key().as_bytes(), POW_BITS);
    let (st, v) = recover(api, &rk, &weak, false, |b| b["pow_nonce"] = json!(weak_nonce)).await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "POW_INVALID"));
    let (st, _) = recover(api, &rk, &new_key(), false, |b| b["signature"] = json!(b64(&[0; 63]))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Joins the account; the device limit counts.
    let n1 = new_key();
    let (st, v) = recover(api, &rk, &n1, false, |_| {}).await;
    assert_eq!((st, v["account_id"].as_str(), v["revoked"].as_u64()), (StatusCode::CREATED, Some(a.account_id.as_str()), Some(0)), "{v}");
    let (st, v) = recover(api, &rk, &new_key(), false, |_| {}).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "LIMIT_EXCEEDED"), "3 devices already");
    // The same new key again: already registered.
    let (st, v) = recover(api, &rk, &n1, true, |_| {}).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"));
    // ...and the failed request removed nothing (one transaction).
    assert_eq!(api.call(&a, Method::GET, "/v1/devices", None).await.1["devices"].as_array().unwrap().len(), 3);

    // Lost phone: revoke the others.
    let n2 = new_key();
    let (st, v) = recover(api, &rk, &n2, true, |_| {}).await;
    assert_eq!((st, v["revoked"].as_u64()), (StatusCode::CREATED, Some(3)), "{v}");
    let d2 = Device { key: n2, account_id: a.account_id.clone(), device_id: v["device_id"].as_str().unwrap().into() };
    assert_eq!(api.call(&a, Method::GET, "/v1/devices", None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(api.call(&a2, Method::GET, "/v1/devices", None).await.0, StatusCode::UNAUTHORIZED);
    let (_, v) = api.call(&d2, Method::GET, "/v1/devices", None).await;
    assert_eq!(v["devices"], json!([d2.device_id]));

    // Release: no more recovery.
    assert_eq!(api.call(&d2, Method::POST, "/v1/recovery/release", None).await.0, StatusCode::OK);
    let (st, _) = recover(api, &rk, &new_key(), false, |_| {}).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // Another account may now use that key.
    assert_eq!(apply(api, &b, &rk).await.0, StatusCode::OK);
    ts.stop().await;
}
