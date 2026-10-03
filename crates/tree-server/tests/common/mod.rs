//! Test client: boots the server in-process on a random port and talks to it
//! over real HTTP with real Ed25519 signatures. The request signing below is
//! written from the documented format, independently of the server code.

#![allow(dead_code)]

use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{header::HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tree_server::{Config, Server};

pub const ADMIN_TOKEN: &str = "test-operator-token";
pub const POW_BITS: u32 = 6;

pub struct TestServer {
    pub server: Server,
    pub api: Api,
    pub dir: PathBuf,
}

impl TestServer {
    pub async fn stop(self) {
        self.server.shutdown().await.expect("clean shutdown");
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).unwrap();
    b
}

pub async fn boot(tweak: impl FnOnce(&mut Config)) -> TestServer {
    let dir = std::env::temp_dir().join(format!("tree-server-test-{}", hex::encode(random::<8>())));
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = Config {
        database_url: format!("sqlite://{}/tree.db", dir.display()),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_token_sha256: Some(Sha256::digest(ADMIN_TOKEN.as_bytes()).into()),
        pow_bits: POW_BITS,
        rate_per_sec: 10_000.0,
        rate_burst: 10_000.0,
        signup_per_hour: 1_000_000.0,
        signup_burst: 10_000.0,
        ..Config::default()
    };
    tweak(&mut cfg);
    let server = tree_server::start(cfg).await.expect("server starts");
    let api = Api {
        http: reqwest::Client::new(),
        base: format!("http://{}", server.addr),
    };
    TestServer { server, api, dir }
}

pub fn new_key() -> SigningKey {
    SigningKey::from_bytes(&random::<32>())
}

pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

pub fn unb64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}

fn leading_zeros(h: &[u8]) -> u32 {
    let mut n = 0;
    for &b in h {
        if b == 0 {
            n += 8
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

fn pow_bits_of(pubkey: &[u8; 32], nonce: u64) -> u32 {
    let mut h = Sha256::new();
    h.update(b"tree-signup-v1");
    h.update(pubkey);
    h.update(nonce.to_be_bytes());
    leading_zeros(&h.finalize())
}

pub fn solve_pow(pubkey: &[u8; 32], bits: u32) -> u64 {
    (0u64..).find(|&n| pow_bits_of(pubkey, n) >= bits).unwrap()
}

/// A nonce that does NOT satisfy the proof-of-work.
pub fn bad_pow(pubkey: &[u8; 32], bits: u32) -> u64 {
    (0u64..).find(|&n| pow_bits_of(pubkey, n) < bits).unwrap()
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn fresh_nonce() -> String {
    hex::encode(random::<16>())
}

/// The documented signing string.
pub fn signing_message(
    method: &str,
    pq: &str,
    ts: &str,
    nonce: &str,
    device: &str,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "tree-auth-v1\n{method}\n{pq}\n{ts}\n{nonce}\n{device}\n{}",
        hex::encode(Sha256::digest(body))
    )
    .into_bytes()
}

#[derive(Clone)]
pub struct Device {
    pub key: SigningKey,
    pub account_id: String,
    pub device_id: String,
}

/// Everything that goes into one signed request; tests tweak fields to break it.
pub struct Signed {
    pub method: Method,
    pub path: String,
    pub device_id: Option<String>,
    pub ts: i64,
    pub nonce: String,
    pub body: Vec<u8>,
    /// Signature computed over these (defaults to the fields above).
    pub sign_path: Option<String>,
    pub sign_body: Option<Vec<u8>>,
}

impl Signed {
    pub fn new(method: Method, path: &str, device_id: Option<&str>, body: Option<&Value>) -> Self {
        Self {
            method,
            path: path.to_string(),
            device_id: device_id.map(str::to_string),
            ts: now(),
            nonce: fresh_nonce(),
            body: body
                .map(|b| serde_json::to_vec(b).unwrap())
                .unwrap_or_default(),
            sign_path: None,
            sign_body: None,
        }
    }

    pub fn signature(&self, key: &SigningKey) -> String {
        let msg = signing_message(
            self.method.as_str(),
            self.sign_path.as_deref().unwrap_or(&self.path),
            &self.ts.to_string(),
            &self.nonce,
            self.device_id.as_deref().unwrap_or(""),
            self.sign_body.as_deref().unwrap_or(&self.body),
        );
        b64(&key.sign(&msg).to_bytes())
    }
}

#[derive(Clone)]
pub struct Api {
    pub http: reqwest::Client,
    pub base: String,
}

pub async fn decode(resp: reqwest::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let text = resp.text().await.unwrap();
    let v = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    (status, v)
}

impl Api {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Sends a signed request with an explicit signature header value.
    pub async fn send_with_sig(&self, s: &Signed, sig: &str) -> (StatusCode, Value) {
        self.send_with_sig_and_headers(s, sig, HeaderMap::new())
            .await
    }

    pub async fn send_with_sig_and_headers(
        &self,
        s: &Signed,
        sig: &str,
        headers: HeaderMap,
    ) -> (StatusCode, Value) {
        let mut rb = self
            .http
            .request(s.method.clone(), self.url(&s.path))
            .headers(headers)
            .header("X-Tree-Timestamp", s.ts.to_string())
            .header("X-Tree-Nonce", &s.nonce)
            .header("X-Tree-Signature", sig);
        if let Some(d) = &s.device_id {
            rb = rb.header("X-Tree-Device", d);
        }
        if !s.body.is_empty() {
            rb = rb
                .header("Content-Type", "application/json")
                .body(s.body.clone());
        }
        decode(rb.send().await.unwrap()).await
    }

    pub async fn send(&self, s: &Signed, key: &SigningKey) -> (StatusCode, Value) {
        self.send_with_sig_and_headers(s, &s.signature(key), HeaderMap::new())
            .await
    }

    pub async fn send_with_headers(
        &self,
        s: &Signed,
        key: &SigningKey,
        headers: HeaderMap,
    ) -> (StatusCode, Value) {
        self.send_with_sig_and_headers(s, &s.signature(key), headers)
            .await
    }

    /// Authenticated call as `dev`.
    pub async fn call(
        &self,
        dev: &Device,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let s = Signed::new(method, path, Some(&dev.device_id), body.as_ref());
        self.send(&s, &dev.key).await
    }

    pub async fn signup_raw(&self, key: &SigningKey, nonce: u64) -> (StatusCode, Value) {
        let body = json!({ "auth_pub": b64(key.verifying_key().as_bytes()), "pow_nonce": nonce });
        let s = Signed::new(Method::POST, "/v1/accounts", None, Some(&body));
        self.send(&s, key).await
    }

    pub async fn signup(&self) -> Device {
        let key = new_key();
        let nonce = solve_pow(key.verifying_key().as_bytes(), POW_BITS);
        let (st, v) = self.signup_raw(&key, nonce).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        Device {
            key,
            account_id: v["account_id"].as_str().unwrap().to_string(),
            device_id: v["device_id"].as_str().unwrap().to_string(),
        }
    }

    /// Adds a second device to `dev`'s account.
    pub async fn add_device(&self, dev: &Device) -> Device {
        let key = new_key();
        let (st, v) = self.add_device_raw(dev, &key, &key).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        Device {
            key,
            account_id: dev.account_id.clone(),
            device_id: v["device_id"].as_str().unwrap().to_string(),
        }
    }

    pub async fn add_device_raw(
        &self,
        dev: &Device,
        new: &SigningKey,
        prover: &SigningKey,
    ) -> (StatusCode, Value) {
        let pubkey = new.verifying_key().to_bytes();
        let mut msg = format!("tree-add-device-v1\n{}\n", dev.account_id).into_bytes();
        msg.extend_from_slice(&pubkey);
        let proof = prover.sign(&msg).to_bytes();
        self.call(
            dev,
            Method::POST,
            "/v1/devices",
            Some(json!({ "auth_pub": b64(&pubkey), "proof": b64(&proof) })),
        )
        .await
    }

    pub async fn admin(&self, token: Option<&str>, key: &str, action: &str) -> (StatusCode, Value) {
        let mut rb = self
            .http
            .post(self.url(&format!("/v1/features/{key}/{action}")));
        if let Some(t) = token {
            rb = rb.header("X-Tree-Admin", t);
        }
        decode(rb.send().await.unwrap()).await
    }

    pub async fn upload(&self, dev: &Device, packages: &[Vec<u8>]) -> (StatusCode, Value) {
        let list: Vec<String> = packages.iter().map(|p| b64(p)).collect();
        self.call(
            dev,
            Method::POST,
            "/v1/keypackages",
            Some(json!({ "key_packages": list })),
        )
        .await
    }

    pub async fn claim(&self, dev: &Device, account_id: &str) -> (StatusCode, Value) {
        self.call(
            dev,
            Method::POST,
            "/v1/keypackages/claim",
            Some(json!({ "account_id": account_id })),
        )
        .await
    }

    pub async fn kp_count(&self, dev: &Device) -> i64 {
        let (st, v) = self
            .call(dev, Method::GET, "/v1/keypackages/count", None)
            .await;
        assert_eq!(st, StatusCode::OK, "{v}");
        v["count"].as_i64().unwrap()
    }

    /// Sends `payload` wrapped as an application-message envelope (see
    /// [`app`]); an empty payload is sent as an empty body.
    pub async fn send_msg(
        &self,
        dev: &Device,
        recipients: &[&str],
        payload: &[u8],
    ) -> (StatusCode, Value) {
        let body = if payload.is_empty() { vec![] } else { app(payload) };
        self.send_raw(dev, recipients, &body).await
    }

    /// Sends exactly `body`.
    pub async fn send_raw(&self, dev: &Device, recipients: &[&str], body: &[u8]) -> (StatusCode, Value) {
        self.call(
            dev,
            Method::POST,
            "/v1/messages",
            Some(json!({ "recipients": recipients, "body": b64(body) })),
        )
        .await
    }

    pub async fn fetch(&self, dev: &Device, wait: u64) -> Vec<Value> {
        let path = if wait > 0 {
            format!("/v1/messages?wait={wait}")
        } else {
            "/v1/messages".into()
        };
        let (st, v) = self.call(dev, Method::GET, &path, None).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        v["messages"].as_array().unwrap().clone()
    }

    pub async fn ack(&self, dev: &Device, ids: &[&str]) -> (StatusCode, Value) {
        self.call(
            dev,
            Method::POST,
            "/v1/messages/ack",
            Some(json!({ "ids": ids })),
        )
        .await
    }
}

/// Group id used by the fake envelopes below.
pub const GROUP: [u8; 16] = [0x47; 16];

/// A Tree envelope header (PROTOCOL.md 4.1) for `group` / `epoch` /
/// `content_type`, followed by `rest`. The tag is fake: the server cannot
/// check it.
pub fn envelope(group: &[u8], epoch: u64, content_type: u8, rest: &[u8]) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&[0xee; 32]);
    v.extend_from_slice(&[0, 1, 0, 2]);
    assert!(group.len() < 64);
    v.push(group.len() as u8);
    v.extend_from_slice(group);
    v.extend_from_slice(&epoch.to_be_bytes());
    v.push(content_type);
    v.extend_from_slice(rest);
    v
}

/// An application message carrying `payload` (tests compare whole bodies).
pub fn app(payload: &[u8]) -> Vec<u8> {
    envelope(&GROUP, 1, 1, payload)
}

/// An application message of exactly `n` bytes.
pub fn app_sized(n: usize) -> Vec<u8> {
    let head = app(b"").len();
    app(&vec![1u8; n - head])
}

/// A commit for `group` / `epoch`; `tag` makes different commits differ.
pub fn commit(group: &[u8], epoch: u64, tag: &[u8]) -> Vec<u8> {
    envelope(group, epoch, 3, tag)
}

/// A bare MLS welcome (first bytes only matter to the server).
pub fn welcome(tag: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 1, 0, 3];
    v.extend_from_slice(tag);
    v
}
