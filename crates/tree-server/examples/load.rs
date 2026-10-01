//! Load test: many devices send to each other through an in-process server
//! and fetch/acknowledge, measuring throughput and latency.
//!
//!   cargo run --release -p tree-server --example load -- [devices] [messages-per-device] [recipients]
//!
//! Bodies are 1 KiB fake application envelopes (the server reads only the
//! cleartext header). Rate limits are lifted so the numbers show the
//! server's own capacity on this machine with SQLite.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tree_server::Config;

struct Dev {
    key: SigningKey,
    id: String,
}

fn rand<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).unwrap();
    b
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

async fn call(http: &reqwest::Client, base: &str, key: &SigningKey, dev: &str, method: reqwest::Method, path: &str, body: Option<&Value>) -> (u16, Value) {
    let bytes = body.map(|b| serde_json::to_vec(b).unwrap()).unwrap_or_default();
    let ts = now().to_string();
    let nonce = URL_SAFE_NO_PAD.encode(rand::<16>());
    let msg = format!("tree-auth-v1\n{}\n{path}\n{ts}\n{nonce}\n{dev}\n{}", method.as_str(), hex::encode(Sha256::digest(&bytes)));
    let mut rb = http
        .request(method, format!("{base}{path}"))
        .header("X-Tree-Timestamp", ts)
        .header("X-Tree-Nonce", nonce)
        .header("X-Tree-Signature", STANDARD.encode(key.sign(msg.as_bytes()).to_bytes()));
    if !dev.is_empty() {
        rb = rb.header("X-Tree-Device", dev);
    }
    if !bytes.is_empty() {
        rb = rb.header("Content-Type", "application/json").body(bytes);
    }
    let r = rb.send().await.unwrap();
    let st = r.status().as_u16();
    (st, r.json().await.unwrap_or(Value::Null))
}

/// A 1 KiB application envelope: 0x01 || tag || MLS PrivateMessage header || filler.
fn envelope() -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&[0xaa; 32]);
    v.extend_from_slice(&[0, 1, 0, 2, 16]);
    v.extend_from_slice(&[7u8; 16]);
    v.extend_from_slice(&1u64.to_be_bytes());
    v.push(1);
    v.resize(1024, 0x55);
    v
}

fn percentile(v: &mut [Duration], p: f64) -> Duration {
    v.sort();
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

#[tokio::main]
async fn main() {
    let args: Vec<usize> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let (n, per, k) = (args.first().copied().unwrap_or(100), args.get(1).copied().unwrap_or(50), args.get(2).copied().unwrap_or(5));
    let dir = std::env::temp_dir().join(format!("tree-load-{}", hex::encode(rand::<6>())));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = Config {
        database_url: format!("sqlite://{}/tree.db", dir.display()),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        pow_bits: 4,
        rate_per_sec: 1e9,
        rate_burst: 1e9,
        signup_per_hour: 1e9,
        signup_burst: 1e9,
        attachment_dir: dir.join("att"),
        ..Config::default()
    };
    let server = tree_server::start(cfg).await.unwrap();
    tree_server::features::set_applied(&server.state.db, tree_server::features::NEW_ACCOUNT_LIMITS, false).await.unwrap();
    let base = format!("http://{}", server.addr);
    let http = reqwest::Client::new();

    // Sign-up.
    let t = Instant::now();
    let mut devs = Vec::new();
    for _ in 0..n {
        let key = SigningKey::from_bytes(&rand::<32>());
        let public = key.verifying_key().to_bytes();
        let nonce = (0u64..)
            .find(|x| {
                let h = Sha256::new().chain_update(b"tree-signup-v1").chain_update(public).chain_update(x.to_be_bytes()).finalize();
                h[0] >> 4 == 0
            })
            .unwrap();
        let (st, v) = call(&http, &base, &key, "", reqwest::Method::POST, "/v1/accounts", Some(&json!({ "auth_pub": STANDARD.encode(public), "pow_nonce": nonce }))).await;
        assert_eq!(st, 201, "{v}");
        devs.push(Dev { key, id: v["device_id"].as_str().unwrap().to_string() });
    }
    println!("signup: {n} devices in {:.2?} ({:.0}/s)", t.elapsed(), n as f64 / t.elapsed().as_secs_f64());

    // Every device sends `per` messages to `k` others, all devices at once.
    let devs = Arc::new(devs);
    let body = STANDARD.encode(envelope());
    let t = Instant::now();
    let mut tasks = Vec::new();
    for i in 0..n {
        let (devs, http, base, body) = (devs.clone(), http.clone(), base.clone(), body.clone());
        tasks.push(tokio::spawn(async move {
            let mut lat = Vec::with_capacity(per);
            for m in 0..per {
                let to: Vec<String> = (1..=k).map(|j| devs[(i + j + m) % n].id.clone()).collect();
                let s = Instant::now();
                let (st, v) = call(&http, &base, &devs[i].key, &devs[i].id, reqwest::Method::POST, "/v1/messages", Some(&json!({ "recipients": to, "body": body }))).await;
                assert_eq!(st, 200, "{v}");
                lat.push(s.elapsed());
            }
            lat
        }));
    }
    let mut lat = Vec::new();
    for t in tasks {
        lat.extend(t.await.unwrap());
    }
    let sent = n * per;
    let el = t.elapsed();
    println!(
        "send: {sent} messages x {k} recipients in {el:.2?} ({:.0} msg/s, {:.0} deliveries/s); latency p50 {:.1?} p99 {:.1?}",
        sent as f64 / el.as_secs_f64(),
        (sent * k) as f64 / el.as_secs_f64(),
        percentile(&mut lat, 0.5),
        percentile(&mut lat, 0.99)
    );

    // Every device fetches and acknowledges its mailbox.
    let t = Instant::now();
    let mut tasks = Vec::new();
    for i in 0..n {
        let (devs, http, base) = (devs.clone(), http.clone(), base.clone());
        tasks.push(tokio::spawn(async move {
            let mut got = 0;
            loop {
                let (st, v) = call(&http, &base, &devs[i].key, &devs[i].id, reqwest::Method::GET, "/v1/messages", None).await;
                assert_eq!(st, 200);
                let ids: Vec<String> = v["messages"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap().to_string()).collect();
                if ids.is_empty() {
                    break got;
                }
                got += ids.len();
                let (st, _) = call(&http, &base, &devs[i].key, &devs[i].id, reqwest::Method::POST, "/v1/messages/ack", Some(&json!({ "ids": ids }))).await;
                assert_eq!(st, 200);
            }
        }));
    }
    let mut got = 0;
    for t in tasks {
        got += t.await.unwrap();
    }
    let el = t.elapsed();
    println!("fetch+ack: {got} deliveries in {el:.2?} ({:.0}/s)", got as f64 / el.as_secs_f64());
    assert_eq!(got, sent * k, "every delivery arrived exactly once");
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
