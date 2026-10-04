//! Bot platform (PROTOCOL.md 8.16): the factory, tokens, gateway devices,
//! whom a bot may reach, the directory and the operator flag. The proof of
//! work, the token MAC and the gateway proof are written here from the
//! documentation, independently of the server code.

mod common;

use common::*;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

/// Proof of work for a new bot: SHA-256("tree-bot-signup-v1" || key || nonce).
fn bot_pow(key: &[u8; 32], bits: u32) -> u64 {
    (0u64..)
        .find(|n| {
            let h: [u8; 32] = Sha256::new().chain_update(b"tree-bot-signup-v1").chain_update(key).chain_update(n.to_be_bytes()).finalize().into();
            let z = h.iter().position(|b| *b != 0).map_or(256, |i| i as u32 * 8 + h[i].leading_zeros());
            z >= bits
        })
        .unwrap()
}

async fn create_raw(api: &Api, owner: &Device, username: &str, key: [u8; 32], nonce: u64) -> (StatusCode, Value) {
    api.call(owner, Method::POST, "/v1/bots", Some(json!({ "username": username, "pow_key": b64(&key), "pow_nonce": nonce }))).await
}

/// Creates a bot; returns (bot account, token).
async fn create(api: &Api, owner: &Device, username: &str) -> (String, String) {
    let key = random::<32>();
    let (st, v) = create_raw(api, owner, username, key, bot_pow(&key, POW_BITS)).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    (v["bot"]["account"].as_str().unwrap().to_string(), v["token"].as_str().unwrap().to_string())
}

async fn bearer(api: &Api, method: Method, path: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
    let mut rb = api.http.request(method, api.url(path)).header("Authorization", format!("Bearer {token}"));
    if let Some(b) = body {
        rb = rb.json(&b);
    }
    decode(rb.send().await.unwrap()).await
}

fn lp(parts: &[&[u8]]) -> Vec<u8> {
    link_lp(parts)
}

/// Registers `key` as the bot's gateway device with `token`, signing the
/// challenge with `prover`.
async fn register_with(api: &Api, token: &str, key: &SigningKey, prover: &SigningKey) -> (StatusCode, Value) {
    let (st, v) = bearer(api, Method::POST, "/v1/bots/gateway/challenge", token, None).await;
    if st != StatusCode::OK {
        return (st, v);
    }
    let bot = v["account_id"].as_str().unwrap().to_string();
    let challenge = unb64(v["challenge"].as_str().unwrap());
    let public = key.verifying_key().to_bytes();
    let sig = prover.sign(&lp(&[b"tree/bot-gateway/v1", bot.as_bytes(), &challenge, &public]));
    bearer(
        api,
        Method::POST,
        "/v1/bots/gateway/register",
        token,
        Some(json!({ "auth_pub": b64(&public), "challenge": b64(&challenge), "signature": b64(&sig.to_bytes()) })),
    )
    .await
}

async fn register(api: &Api, token: &str, key: &SigningKey) -> Device {
    let (st, v) = register_with(api, token, key, key).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    Device { key: key.clone(), account_id: v["account_id"].as_str().unwrap().into(), device_id: v["device_id"].as_str().unwrap().into() }
}

async fn platform(ts: &TestServer, on: bool) {
    tree_server::features::set_applied(&ts.server.state.db, "server.bot_platform", on).await.unwrap();
}

async fn boot_bots(tweak: impl FnOnce(&mut tree_server::Config)) -> TestServer {
    let ts = boot(tweak).await;
    platform(&ts, true).await;
    ts
}

/// `server.bot_platform` starts released: every bot endpoint refuses, and
/// so do the requests of bots' devices and claims of bots' key packages.
#[tokio::test]
async fn the_platform_flag_refuses_every_bot_endpoint_while_released() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let owner = api.signup().await;
    let key = random::<32>();
    let (st, v) = create_raw(api, &owner, "helper_bot", key, bot_pow(&key, POW_BITS)).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LOCKED_BY_SERVER"));
    for (m, p) in [(Method::GET, "/v1/bots"), (Method::GET, "/v1/bots/directory?q=x"), (Method::GET, "/v1/bots/by-username/helper_bot")] {
        let (st, v) = api.call(&owner, m, p, None).await;
        assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LOCKED_BY_SERVER"), "{p}");
    }
    let (st, v) = api.call(&owner, Method::POST, "/v1/bots/lookup", Some(json!({ "accounts": [owner.account_id] }))).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LOCKED_BY_SERVER"));

    // Applied: a bot is made and its gateway registers.
    platform(&ts, true).await;
    let (bot, token) = create(api, &owner, "helper_bot").await;
    let dev = register(api, &token, &new_key()).await;
    assert_eq!(dev.account_id, bot);
    let up = api.upload(&dev, &[b"kp".to_vec()]).await;
    assert_eq!(up.0, StatusCode::OK, "{}", up.1);

    // Released again: the gateway, its device and claims of the bot stop.
    platform(&ts, false).await;
    let (st, v) = bearer(api, Method::POST, "/v1/bots/gateway/challenge", &token, None).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LOCKED_BY_SERVER"));
    let (st, v) = api.call(&dev, Method::GET, "/v1/messages", None).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LOCKED_BY_SERVER"));
    let (st, v) = api.claim(&owner, &bot).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LOCKED_BY_SERVER"));
    // Nothing is kept for the bot meanwhile, to be read once it is back.
    let (st, v) = api.send_msg(&owner, &[&dev.device_id], b"while off").await;
    assert_eq!((st, v["delivered"].as_u64(), v["refused_devices"].clone()), (StatusCode::OK, Some(0), json!([dev.device_id])));
    platform(&ts, true).await;
    assert!(api.fetch(&dev, 0).await.is_empty());
    ts.stop().await;
}

/// The token is in the creation answer only; the server keeps an HMAC of
/// it under its bot token key, and nothing else of it.
#[tokio::test]
async fn the_token_is_shown_once_and_stored_as_an_hmac() {
    let ts = boot_bots(|_| {}).await;
    let api = &ts.api;
    let owner = api.signup().await;
    let (bot, token) = create(api, &owner, "weather_bot").await;
    let (id, secret) = token.split_once(':').unwrap();
    assert_eq!(id, bot);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, secret).unwrap();
    assert_eq!(raw.len(), 32);

    // No later answer carries it.
    for p in ["/v1/bots".to_string(), format!("/v1/bots/{bot}")] {
        let (st, v) = api.call(&owner, Method::GET, &p, None).await;
        assert_eq!(st, StatusCode::OK);
        assert!(!v.to_string().contains(secret) && v.to_string().contains("weather_bot"), "{v}");
    }
    // Stored: HMAC-SHA-256(key, label || len(bot) || bot || secret).
    let db = &ts.server.state.db;
    let key: Vec<u8> = sqlx::query_scalar("SELECT value FROM server_secrets WHERE name = 'bot_token'").fetch_one(db).await.unwrap();
    let mac: Vec<u8> = sqlx::query_scalar("SELECT token_mac FROM bots WHERE account_id = ?").bind(&bot).fetch_one(db).await.unwrap();
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
    m.update(b"tree/bot-token/v1");
    m.update(&(bot.len() as u32).to_be_bytes());
    m.update(bot.as_bytes());
    m.update(&raw);
    assert_eq!(mac, m.finalize().into_bytes().to_vec());
    // Neither the token nor its secret is anywhere in the database files.
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(db).await.unwrap();
    for f in ["tree.db", "tree.db-wal"] {
        let bytes = std::fs::read(ts.dir.join(f)).unwrap_or_default();
        let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(!has(secret.as_bytes()) && !has(&raw), "{f} holds the token");
    }
    // A configured key (BOT_TOKEN_KEY) is used instead of a stored one.
    let ts2 = boot_bots(|c| c.bot_token_key = Some(tree_server::config::SecretKey([7; 32]))).await;
    let o2 = ts2.api.signup().await;
    let (b2, t2) = create(&ts2.api, &o2, "other_bot").await;
    let raw2 = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, t2.split_once(':').unwrap().1).unwrap();
    let mac2: Vec<u8> = sqlx::query_scalar("SELECT token_mac FROM bots").fetch_one(&ts2.server.state.db).await.unwrap();
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&[7; 32]).unwrap();
    m.update(b"tree/bot-token/v1");
    m.update(&(b2.len() as u32).to_be_bytes());
    m.update(b2.as_bytes());
    m.update(&raw2);
    assert_eq!(mac2, m.finalize().into_bytes().to_vec());
    assert!(sqlx::query("SELECT 1 FROM server_secrets WHERE name = 'bot_token'").fetch_optional(&ts2.server.state.db).await.unwrap().is_none());
    ts2.stop().await;
    ts.stop().await;
}

/// A gateway device needs the token and a signature over a fresh server
/// challenge by the device key it registers.
#[tokio::test]
async fn gateway_registration_needs_the_token_and_proof_of_the_device_key() {
    let ts = boot_bots(|_| {}).await;
    let api = &ts.api;
    let owner = api.signup().await;
    let (bot, token) = create(api, &owner, "echo_bot").await;
    let (_, token2) = create(api, &owner, "other_bot").await;
    let key = new_key();

    // No token, a malformed one, a wrong secret.
    let (st, v) = decode(api.http.post(api.url("/v1/bots/gateway/challenge")).send().await.unwrap()).await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "BAD_TOKEN"));
    let wrong = format!("{bot}:{}", base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, random::<32>()));
    for t in ["nonsense", wrong.as_str()] {
        let (st, v) = register_with(api, t, &key, &key).await;
        assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "BAD_TOKEN"), "{t}");
    }
    // The token, but no proof of the key: signed by another key.
    let (st, v) = register_with(api, &token, &key, &new_key()).await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "PROOF_INVALID"));
    // A challenge is used once and only by the bot it was issued to.
    let (_, c) = bearer(api, Method::POST, "/v1/bots/gateway/challenge", &token2, None).await;
    let challenge = unb64(c["challenge"].as_str().unwrap());
    let public = key.verifying_key().to_bytes();
    let body = json!({
        "auth_pub": b64(&public), "challenge": b64(&challenge),
        "signature": b64(&key.sign(&lp(&[b"tree/bot-gateway/v1", bot.as_bytes(), &challenge, &public])).to_bytes()),
    });
    let (st, v) = bearer(api, Method::POST, "/v1/bots/gateway/register", &token, Some(body)).await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "CHALLENGE_INVALID"));
    // A human account's key cannot be taken over as a bot device.
    let (st, v) = register_with(api, &token, &owner.key, &owner.key).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "ALREADY_EXISTS"));
    // Done properly: a device of the bot account.
    let dev = register(api, &token, &key).await;
    assert_eq!(dev.account_id, bot);
    let (st, v) = api.call(&dev, Method::GET, "/v1/keypackages/count", None).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let (st, v) = bearer(api, Method::GET, "/v1/bots/gateway/me", &token, None).await;
    assert_eq!((st, v["username"].as_str(), v["is_bot"].as_bool()), (StatusCode::OK, Some("echo_bot"), Some(true)));
    assert!(v.get("owner").is_none(), "the owner is never shown");
    ts.stop().await;
}

/// Rotating or revoking the token cuts the old token and every gateway
/// device registered with it off at once, including one a thief
/// registered with the stolen token, and an open long-poll.
#[tokio::test]
async fn rotate_and_revoke_cut_off_the_old_token_and_its_devices_at_once() {
    let ts = boot_bots(|_| {}).await;
    let api = &ts.api;
    let owner = api.signup().await;
    let alice = api.signup().await;
    let (bot, token) = create(api, &owner, "shop_bot").await;
    let legit = new_key();
    let dev = register(api, &token, &legit).await;
    // alice contacts the bot (claims its key packages).
    api.upload(&dev, &[b"kp1".to_vec(), b"kp2".to_vec()]).await;
    assert_eq!(api.claim(&alice, &bot).await.0, StatusCode::OK);

    // A thief with the stolen token registers its own device: the owner's
    // gateway device is removed at once (one device per bot), so the
    // takeover is noticed.
    let thief_key = new_key();
    let thief = register(api, &token, &thief_key).await;
    let (st, _) = api.call(&dev, Method::GET, "/v1/messages", None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "the owner's gateway is cut off");
    api.upload(&thief, &[b"thief-kp".to_vec()]).await;
    assert_eq!(api.send_msg(&alice, &[&thief.device_id], b"to the bot").await.0, StatusCode::OK);

    // The thief reads its mailbox, then long-polls; the owner rotates the
    // token: the open poll ends at once with 401.
    let first = api.fetch(&thief, 0).await;
    assert_eq!(first.len(), 1);
    let ids: Vec<&str> = first.iter().map(|m| m["id"].as_str().unwrap()).collect();
    api.ack(&thief, &ids).await;
    let waiting = {
        let (api, thief) = (api.clone(), thief.clone());
        tokio::spawn(async move {
            let t = std::time::Instant::now();
            let r = api.call(&thief, Method::GET, "/v1/messages?wait=20", None).await;
            (r, t.elapsed())
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let (st, v) = api.call(&owner, Method::POST, &format!("/v1/bots/{bot}/token/rotate"), None).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let new_token = v["token"].as_str().unwrap().to_string();
    assert_ne!(new_token, token);
    let ((st, v), took) = waiting.await.unwrap();
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "BOT_DEVICE_DISABLED"));
    assert!(took < std::time::Duration::from_secs(10), "{took:?}");
    // Every request of the thief's device fails now.
    let (st, v) = api.call(&thief, Method::GET, "/v1/keypackages/count", None).await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "BOT_DEVICE_DISABLED"));
    // Its key packages are gone: nobody can add it any more.
    let (st, v) = api.claim(&alice, &bot).await;
    assert_eq!(st, StatusCode::OK);
    assert!(v["key_packages"].as_array().unwrap().is_empty(), "{v}");
    // The old token is dead.
    let (st, v) = register_with(api, &token, &thief_key, &thief_key).await;
    assert_eq!((st, code(&v)), (StatusCode::UNAUTHORIZED, "BAD_TOKEN"));

    // The owner's gateway registers again with the new token (its key):
    // the thief's device is deleted.
    let again = register(api, &new_token, &legit).await;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE account_id = ?").bind(&bot).fetch_one(&ts.server.state.db).await.unwrap();
    assert_eq!(n, 1);
    assert!(sqlx::query("SELECT 1 FROM devices WHERE id = ?").bind(&thief.device_id).fetch_optional(&ts.server.state.db).await.unwrap().is_none());
    assert_eq!(api.call(&again, Method::GET, "/v1/messages", None).await.0, StatusCode::OK);

    // A rotation with the same device key keeps the device id and its
    // mailbox (the gateway catches up).
    assert_eq!(api.send_msg(&alice, &[&again.device_id], b"while rotating").await.0, StatusCode::OK);
    let (_, v) = api.call(&owner, Method::POST, &format!("/v1/bots/{bot}/token/rotate"), None).await;
    let t3 = v["token"].as_str().unwrap().to_string();
    assert_eq!(api.call(&again, Method::GET, "/v1/messages", None).await.0, StatusCode::UNAUTHORIZED);
    let back = register(api, &t3, &legit).await;
    assert_eq!(back.device_id, again.device_id);
    let got = api.fetch(&back, 0).await;
    assert_eq!(got.len(), 1);

    // Revoke: no token works, the device stops; a rotation issues a new one.
    let (st, v) = api.call(&owner, Method::POST, &format!("/v1/bots/{bot}/token/revoke"), None).await;
    assert_eq!((st, v.get("token")), (StatusCode::OK, None));
    assert_eq!(v["bot"]["token_active"], json!(false));
    assert_eq!(api.call(&back, Method::GET, "/v1/messages", None).await.0, StatusCode::UNAUTHORIZED);
    let (st, _) = bearer(api, Method::POST, "/v1/bots/gateway/challenge", &t3, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (_, v) = api.call(&owner, Method::POST, &format!("/v1/bots/{bot}/token/rotate"), None).await;
    let t4 = v["token"].as_str().unwrap().to_string();
    assert_eq!(register(api, &t4, &legit).await.device_id, back.device_id);
    // Only the owner rotates.
    let (st, _) = api.call(&alice, Method::POST, &format!("/v1/bots/{bot}/token/rotate"), None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    ts.stop().await;
}

/// A bot costs a signup's proof of work and budget, needs signups open,
/// and an owner has at most `MAX_BOTS_PER_OWNER`.
#[tokio::test]
async fn creating_a_bot_costs_a_signup_and_is_capped_per_owner() {
    let ts = boot_bots(|c| c.max_bots_per_owner = 2).await;
    let api = &ts.api;
    let owner = api.signup().await;
    let key = random::<32>();
    let bad = (0u64..).find(|n| {
        let h: [u8; 32] = Sha256::new().chain_update(b"tree-bot-signup-v1").chain_update(key).chain_update(n.to_be_bytes()).finalize().into();
        h[0] != 0
    });
    let (st, v) = create_raw(api, &owner, "first_bot", key, bad.unwrap()).await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "POW_INVALID"));
    // A signup's proof (another label) does not count.
    let zeros = |label: &[u8], n: u64| {
        let h: [u8; 32] = Sha256::new().chain_update(label).chain_update(key).chain_update(n.to_be_bytes()).finalize().into();
        h.iter().position(|b| *b != 0).map_or(256, |i| i as u32 * 8 + h[i].leading_zeros())
    };
    let signup_only = (0u64..).find(|n| zeros(b"tree-signup-v1", *n) >= POW_BITS && zeros(b"tree-bot-signup-v1", *n) < POW_BITS).unwrap();
    let (st, v) = create_raw(api, &owner, "first_bot", key, signup_only).await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "POW_INVALID"));
    let nonce = bot_pow(&key, POW_BITS);
    assert_eq!(create_raw(api, &owner, "first_bot", key, nonce).await.0, StatusCode::CREATED);
    // The same proof again is refused.
    let (st, v) = create_raw(api, &owner, "second_bot", key, nonce).await;
    assert_eq!((st, code(&v)), (StatusCode::BAD_REQUEST, "POW_INVALID"));
    // Names: taken, malformed.
    let k2 = random::<32>();
    let (st, v) = create_raw(api, &owner, "first_bot", k2, bot_pow(&k2, POW_BITS)).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "USERNAME_TAKEN"));
    for name in ["helper", "bot", "9_bot"] {
        let k = random::<32>();
        let (st, _) = create_raw(api, &owner, name, k, bot_pow(&k, POW_BITS)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{name}");
    }
    // A person's @username cannot be a bot's, nor the other way round.
    let h: [u8; 32] = Sha256::new().chain_update(b"tree/username/v1").chain_update(b"taken_bot").finalize().into();
    let other = api.signup().await;
    let (st, v) = api.call(&other, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": b64(&h) }))).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let k3 = random::<32>();
    let (st, v) = create_raw(api, &owner, "taken_bot", k3, bot_pow(&k3, POW_BITS)).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "USERNAME_TAKEN"));
    let h1: [u8; 32] = Sha256::new().chain_update(b"tree/username/v1").chain_update(b"first_bot").finalize().into();
    let (st, v) = api.call(&other, Method::POST, "/v1/usernames/apply", Some(json!({ "hash": b64(&h1) }))).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "USERNAME_TAKEN"));
    // The cap.
    create(api, &owner, "second_bot").await;
    let k4 = random::<32>();
    let (st, v) = create_raw(api, &owner, "third_bot", k4, bot_pow(&k4, POW_BITS)).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "LIMIT_EXCEEDED"));
    // Signups released: no bots either.
    tree_server::features::set_applied(&ts.server.state.db, "server.signups", false).await.unwrap();
    let (st, v) = create_raw(api, &other, "fourth_bot", k4, bot_pow(&k4, POW_BITS)).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LOCKED_BY_SERVER"));
    ts.stop().await;

    // The per-address signup budget: one signup and two bots use it up.
    let ts = boot_bots(|c| {
        c.signup_burst = 3.0;
        c.signup_per_hour = 1.0;
    })
    .await;
    let api = &ts.api;
    let owner = api.signup().await;
    create(api, &owner, "one_bot").await;
    create(api, &owner, "two_bot").await;
    let k = random::<32>();
    let (st, v) = create_raw(api, &owner, "three_bot", k, bot_pow(&k, POW_BITS)).await;
    assert_eq!((st, code(&v)), (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"));
    ts.stop().await;
}

/// The directory lists a bot only while its owner applies `bot.directory`;
/// the money features can never be applied.
#[tokio::test]
async fn directory_only_when_applied_and_money_features_locked() {
    let ts = boot_bots(|_| {}).await;
    let api = &ts.api;
    let owner = api.signup().await;
    let user = api.signup().await;
    let (bot, _) = create(api, &owner, "quiz_bot").await;
    let found = |v: &Value| v["bots"].as_array().unwrap().iter().any(|b| b["account"] == json!(bot));
    let (st, v) = api.call(&user, Method::GET, "/v1/bots/directory?q=quiz", None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(!found(&v), "not listed by default");
    let path = |k: &str, a: &str| format!("/v1/bots/{bot}/features/{k}/{a}");
    // Only the owner sets features.
    assert_eq!(api.call(&user, Method::POST, &path("bot.directory", "apply"), None).await.0, StatusCode::NOT_FOUND);
    let (st, v) = api.call(&owner, Method::POST, &path("bot.directory", "apply"), None).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["directory"], json!(true));
    let (_, v) = api.call(&user, Method::GET, "/v1/bots/directory?q=quiz", None).await;
    assert!(found(&v), "{v}");
    assert!(v["bots"][0].get("owner").is_none());
    api.call(&owner, Method::PUT, &format!("/v1/bots/{bot}/profile"), Some(json!({ "description": "daily trivia", "commands": [{ "command": "/start", "description": "begin" }] }))).await;
    let (_, v) = api.call(&user, Method::GET, "/v1/bots/directory?q=trivia", None).await;
    assert!(found(&v));
    assert_eq!(v["bots"][0]["commands"], json!([{ "command": "start", "description": "begin" }]));
    api.call(&owner, Method::POST, &path("bot.directory", "release"), None).await;
    let (_, v) = api.call(&user, Method::GET, "/v1/bots/directory?q=quiz", None).await;
    assert!(!found(&v), "released: gone");
    // The exact username still finds it (like a link).
    let (st, v) = api.call(&user, Method::GET, "/v1/bots/by-username/@Quiz_Bot", None).await;
    assert_eq!((st, v["account"].as_str()), (StatusCode::OK, Some(bot.as_str())));
    // Money: locked off (releasing is a no-op), unknown keys refused.
    for k in ["bot.payments", "bot.tips", "bot.pay_out_points"] {
        let (st, v) = api.call(&owner, Method::POST, &path(k, "apply"), None).await;
        assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "RELEASED_ALWAYS"), "{k}");
        assert_eq!(api.call(&owner, Method::POST, &path(k, "release"), None).await.0, StatusCode::OK);
    }
    let (st, v) = api.call(&owner, Method::POST, &path("bot.nope", "apply"), None).await;
    assert_eq!((st, code(&v)), (StatusCode::NOT_FOUND, "UNKNOWN_FEATURE"));
    // Every bot feature toggles both ways.
    for k in ["bot.privacy_mode", "bot.join_groups", "bot.inline", "bot.directory"] {
        let field = k.trim_start_matches("bot.");
        let (_, v) = api.call(&owner, Method::POST, &path(k, "release"), None).await;
        assert_eq!(v[field], json!(false), "{k}");
        let (_, v) = api.call(&owner, Method::POST, &path(k, "apply"), None).await;
        assert_eq!(v[field], json!(true), "{k}");
    }
    ts.stop().await;
}

/// The server's bot feature table is the core registry's.
#[test]
fn bot_features_match_the_registry() {
    use tree_core::features::{standard_features, Lock, Scope, State};
    let mut core: Vec<(String, bool, bool)> = standard_features()
        .into_iter()
        .filter(|f| f.scope == Scope::Bot)
        .map(|f| (f.key.to_string(), f.default == State::Applied, matches!(f.lock, Lock::AlwaysOff(_))))
        .collect();
    let mut server: Vec<(String, bool, bool)> = tree_server::bots::BOT_FEATURES.iter().map(|(k, d, l)| (k.to_string(), *d, l.is_some())).collect();
    core.sort();
    server.sort();
    assert_eq!(core, server);
}

/// A bot reaches only people who contacted it and the devices of its
/// groups; what it sends carries its account id; people's sends never do.
#[tokio::test]
async fn a_bot_reaches_only_contacts_and_its_groups() {
    let ts = boot_bots(|_| {}).await;
    let api = &ts.api;
    let owner = api.signup().await;
    let (alice, bob, carol) = (api.signup().await, api.signup().await, api.signup().await);
    let (bot, token) = create(api, &owner, "news_bot").await;
    let dev = register(api, &token, &new_key()).await;
    api.upload(&alice, &[b"a".to_vec()]).await;
    api.upload(&carol, &[b"c".to_vec()]).await;
    api.upload(&dev, &[b"b1".to_vec(), b"b2".to_vec()]).await;

    // Cold: no claim, no message.
    let (st, v) = api.claim(&dev, &alice.account_id).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "BOT_NO_CONTACT"));
    let (st, v) = api.send_msg(&dev, &[&alice.device_id], b"buy now").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!((v["delivered"].as_u64(), v["refused_devices"].clone()), (Some(0), json!([alice.device_id])));
    assert!(api.fetch(&alice, 0).await.is_empty());

    // alice contacts it: now it may.
    let (st, v) = api.claim(&alice, &bot).await;
    assert_eq!((st, v["bot"].as_bool()), (StatusCode::OK, Some(true)));
    let (_, v) = api.claim(&bob, &alice.account_id).await;
    assert_eq!(v["bot"], json!(false));
    assert_eq!(api.claim(&dev, &alice.account_id).await.0, StatusCode::OK);
    let (_, v) = api.send_msg(&dev, &[&alice.device_id, &carol.device_id], b"hello").await;
    assert_eq!((v["delivered"].as_u64(), v["refused_devices"].clone()), (Some(1), json!([carol.device_id])));
    let got = api.fetch(&alice, 0).await;
    assert_eq!(got[0]["bot"], json!(bot), "labelled by the server");
    api.send_msg(&bob, &[&alice.device_id], b"from bob").await;
    let got = api.fetch(&alice, 0).await;
    assert!(got.iter().any(|m| m.get("bot").is_none()), "a person's message names no sender: {got:?}");

    // A group alice made with the bot and carol: the bot reaches carol
    // there, but still cannot claim her.
    let g = [0x55u8; 16];
    let r = json!({
        "group_id": b64(&g), "epoch": 0, "recipients": [], "body": b64(&commit(&g, 0, b"add")),
        "added": [dev.device_id, carol.device_id], "welcome": b64(&welcome(b"w")),
    });
    assert_eq!(api.call(&alice, Method::POST, "/v1/commits", Some(r)).await.0, StatusCode::OK);
    let (_, v) = api.send_msg(&dev, &[&carol.device_id], b"in the group").await;
    assert_eq!(v["delivered"].as_u64(), Some(1), "{v}");
    assert_eq!(api.claim(&dev, &carol.account_id).await.1["code"], json!("BOT_NO_CONTACT"));
    // A commit by the bot may not reach outsiders.
    let r = json!({ "group_id": b64(&g), "epoch": 1, "recipients": [alice.device_id, bob.device_id], "body": b64(&commit(&g, 1, b"x")) });
    let (st, v) = api.call(&dev, Method::POST, "/v1/commits", Some(r)).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "BOT_NO_CONTACT"));
    // Stopping the bot ends the contact.
    let (st, v) = api.call(&alice, Method::POST, &format!("/v1/bots/{bot}/stop"), None).await;
    assert_eq!((st, v["stopped"].as_bool()), (StatusCode::OK, Some(true)));
    assert_eq!(api.claim(&dev, &alice.account_id).await.1["code"], json!("BOT_NO_CONTACT"));

    // Lookups name bots only.
    let (_, v) = api
        .call(&bob, Method::POST, "/v1/bots/lookup", Some(json!({ "accounts": [alice.account_id, bot], "devices": [dev.device_id, alice.device_id] })))
        .await;
    assert_eq!(v["bots"].as_array().unwrap().len(), 1);
    assert_eq!(v["bots"][0]["account"], json!(bot));
    assert_eq!(v["devices"], json!({ dev.device_id.clone(): bot }));
    ts.stop().await;
}

/// Bots have no recovery, device links, @usernames of people or account
/// deletion of their own; they never own bots. The owner's account takes
/// its bots with it.
#[tokio::test]
async fn person_only_requests_and_owner_deletion() {
    let ts = boot_bots(|_| {}).await;
    let api = &ts.api;
    let owner = api.signup().await;
    let (bot, token) = create(api, &owner, "safe_bot").await;
    let dev = register(api, &token, &new_key()).await;
    let h = [1u8; 32];
    for (m, p, b) in [
        (Method::GET, "/v1/recovery", None),
        (Method::POST, "/v1/usernames/apply", Some(json!({ "hash": b64(&h) }))),
        (Method::DELETE, "/v1/accounts", None),
        (Method::GET, "/v1/bots", None),
    ] {
        let (st, v) = api.call(&dev, m, p, b).await;
        assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "NOT_FOR_BOTS"), "{p}");
    }
    let key = random::<32>();
    let (st, v) = create_raw(api, &dev, "child_bot", key, bot_pow(&key, POW_BITS)).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "NOT_FOR_BOTS"));
    let (st, v) = api.call(&dev, Method::POST, "/v1/links", Some(json!({ "link_id": "x", "new_auth_pub": b64(&[0; 32]), "offer": b64(b"o") }))).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "NOT_FOR_BOTS"), "{v}");

    // The owner deletes their account: the bot and its device go too.
    assert_eq!(api.call(&owner, Method::DELETE, "/v1/accounts", None).await.0, StatusCode::OK);
    let db = &ts.server.state.db;
    for q in ["SELECT 1 FROM accounts WHERE id = ?", "SELECT 1 FROM bots WHERE account_id = ?", "SELECT 1 FROM devices WHERE account_id = ?"] {
        assert!(sqlx::query(q).bind(&bot).fetch_optional(db).await.unwrap().is_none(), "{q}");
    }
    ts.stop().await;
}

/// One bucket per bot over all its requests; reports about a bot reach the
/// operator with its owner, and the owner sees the count.
#[tokio::test]
async fn per_bot_rate_limit_and_reports() {
    let ts = boot_bots(|c| {
        c.bot_rate_burst = 6.0;
        c.bot_rate_per_sec = 0.01;
    })
    .await;
    let api = &ts.api;
    let owner = api.signup().await;
    let (bot, token) = create(api, &owner, "busy_bot").await;
    // challenge + register: 2 of 6.
    let dev = register(api, &token, &new_key()).await;
    let mut codes = Vec::new();
    for _ in 0..6 {
        codes.push(api.call(&dev, Method::GET, "/v1/keypackages/count", None).await.0);
    }
    assert_eq!(codes.iter().filter(|s| **s == StatusCode::OK).count(), 4, "{codes:?}");
    assert!(codes[4..].iter().all(|s| *s == StatusCode::TOO_MANY_REQUESTS));

    let user = api.signup().await;
    let r = json!({ "reported_account": bot, "reason": "spam", "messages": [{ "payload": "{}", "key": b64(&[0; 32]), "tag": b64(&[0; 32]), "minute": 0, "group_id": b64(b"g") }] });
    assert_eq!(api.call(&user, Method::POST, "/v1/reports", Some(r)).await.0, StatusCode::CREATED);
    let (_, v) = decode(api.http.get(api.url("/v1/reports")).header("X-Tree-Admin", ADMIN_TOKEN).send().await.unwrap()).await;
    assert_eq!(v["reports"][0]["reported_bot_owner"], json!(owner.account_id));
    let (_, v) = api.call(&owner, Method::GET, &format!("/v1/bots/{bot}"), None).await;
    assert_eq!(v["reports_open"], json!(1));
    ts.stop().await;
}
