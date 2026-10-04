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

/// Runs `sql` on the server's database (fault injection with triggers).
async fn exec(ts: &TestServer, sql: &str) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_string())).execute(&ts.server.state.db).await.unwrap();
}

#[tokio::test]
async fn a_wrong_signature_releases_nothing() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let rk = new_key();
    assert_eq!(apply(api, &a, &rk, None).await.0, StatusCode::OK);

    // Another key, and the right key over another message: both refused.
    let (st, v) = release(api, &a, Some(&new_key())).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "RECOVERY_REFUSED"), "{v}");
    let other_msg = b64(&rk.sign(&change_message(CHANGE_CONTEXT, &a.account_id, &[1; 32])).to_bytes());
    let (st, v) = api.call(&a, Method::POST, "/v1/recovery/release", Some(json!({ "current_signature": other_msg }))).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "RECOVERY_REFUSED"), "{v}");

    // Nothing changed: still applied, nothing pending, the key still recovers.
    let (_, v) = api.call(&a, Method::GET, "/v1/recovery", None).await;
    assert_eq!((v["state"].as_str(), &v["pending"]), (Some("applied"), &Value::Null), "{v}");
    assert_eq!(recover(api, &rk, &new_key(), false, |_| {}).await.0, StatusCode::CREATED);
    ts.stop().await;
}

#[tokio::test]
async fn a_change_waits_seven_days() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let (rk, k2) = (new_key(), new_key());
    apply(api, &a, &rk, None).await;
    let (_, v) = apply(api, &a, &k2, None).await;
    let left = v["pending"]["effective_at"].as_i64().unwrap() - now();
    assert!((7 * 86400 - 10..=7 * 86400).contains(&left), "{left}");
    // Six days later it is still pending: the old key recovers, the new does not.
    sqlx::query("UPDATE account_recovery SET pending_since = pending_since - ?").bind(6 * 86400).execute(&ts.server.state.db).await.unwrap();
    let (_, v) = api.call(&a, Method::GET, "/v1/recovery", None).await;
    assert_eq!(v["pending"]["action"], "replace", "{v}");
    assert_eq!(recover(api, &k2, &new_key(), false, |_| {}).await.0, StatusCode::FORBIDDEN);
    assert_eq!(recover(api, &rk, &new_key(), false, |_| {}).await.0, StatusCode::CREATED);
    ts.stop().await;
}

#[tokio::test]
async fn a_key_pending_elsewhere_cannot_be_applied() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let a2 = api.add_device(&a).await;
    let b = api.signup().await;
    let (rk, k) = (new_key(), new_key());
    apply(api, &a, &rk, None).await;
    // a2 starts an unsigned replacement to k; another account cannot take k
    // meanwhile, neither as its first key nor signed by its current key.
    assert_eq!(apply(api, &a2, &k, None).await.1["pending"]["action"], "replace");
    let (st, v) = apply(api, &b, &k, None).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"), "{v}");
    let bk = new_key();
    assert_eq!(apply(api, &b, &bk, None).await.0, StatusCode::OK);
    let (st, v) = apply(api, &b, &k, Some(&bk)).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"), "{v}");
    // So the change takes effect after the delay.
    age_pending(&ts).await;
    let (st, v) = api.call(&a, Method::GET, "/v1/recovery", None).await;
    assert_eq!((st, v["state"].as_str(), &v["pending"]), (StatusCode::OK, Some("applied"), &Value::Null), "{v}");
    assert_eq!(recover(api, &k, &new_key(), false, |_| {}).await.0, StatusCode::CREATED);
    ts.stop().await;
}

#[tokio::test]
async fn the_time_window_includes_its_edge() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let rk = new_key();
    apply(api, &a, &rk, None).await;
    let skew = ts.server.state.cfg.clock_skew_secs as i64;
    // Exactly `skew` seconds old is accepted. Sent right after a second
    // starts so the server reads the same second; retried if it did not.
    let mut accepted = false;
    for _ in 0..5 {
        let into = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_millis();
        tokio::time::sleep(std::time::Duration::from_millis(u64::from(1010 - into))).await;
        let n = new_key();
        let t = now() - skew;
        let s = b64(&rk.sign(&recovery_message(&pk(&n), false, t)).to_bytes());
        let (st, v) = recover(api, &rk, &n, false, |b| { b["ts"] = json!(t); b["signature"] = json!(s); }).await;
        if st == StatusCode::CREATED {
            accepted = true;
            break;
        }
        assert_eq!(code(&v), "TIMESTAMP_SKEW", "{v}");
    }
    assert!(accepted, "a request exactly at the edge of the window was never accepted");
    ts.stop().await;
}

#[tokio::test]
async fn database_failures_are_not_reported_as_duplicates() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let rk = new_key();

    // Setting the key fails for another reason than a duplicate: 500, not 409.
    exec(&ts, "CREATE TRIGGER fail_recovery BEFORE INSERT ON account_recovery BEGIN SELECT RAISE(ABORT, 'injected'); END").await;
    let (st, v) = apply(api, &a, &rk, None).await;
    assert_eq!((st, code(&v)), (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL"), "{v}");
    exec(&ts, "DROP TRIGGER fail_recovery").await;
    // A key registered elsewhere by a concurrent request (simulated by a
    // trigger) is the duplicate: 409.
    let b = api.signup().await;
    exec(&ts, &format!(
        "CREATE TRIGGER race_recovery BEFORE INSERT ON account_recovery BEGIN \
         INSERT INTO account_recovery (account_id, recovery_pub, set_day) VALUES ('{}', NEW.recovery_pub, 0); END",
        b.account_id
    ))
    .await;
    let (st, v) = apply(api, &a, &rk, None).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"), "{v}");
    exec(&ts, "DROP TRIGGER race_recovery").await;
    assert_eq!(apply(api, &a, &rk, None).await.0, StatusCode::OK, "nothing of the failed attempts stayed");

    // Adding the recovered device fails for another reason: 500, not 409.
    exec(&ts, "CREATE TRIGGER fail_device BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT, 'injected'); END").await;
    let (st, v) = recover(api, &rk, &new_key(), false, |_| {}).await;
    assert_eq!((st, code(&v)), (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL"), "{v}");
    exec(&ts, "DROP TRIGGER fail_device").await;
    // The same device key registered by a concurrent request between the
    // check and the insert (simulated by a trigger): 409, nothing revoked.
    exec(&ts, "CREATE TRIGGER race_device BEFORE INSERT ON devices BEGIN \
               INSERT INTO devices (id, account_id, auth_pub, created_day) VALUES ('racer', NEW.account_id, NEW.auth_pub, 0); END")
        .await;
    let (st, v) = recover(api, &rk, &new_key(), true, |_| {}).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"), "{v}");
    exec(&ts, "DROP TRIGGER race_device").await;
    assert_eq!(api.call(&a, Method::GET, "/v1/devices", None).await.0, StatusCode::OK, "nothing revoked");
    ts.stop().await;
}
