//! HTTP client for the Tree server API (docs/SERVER_API.md).
//!
//! Every authenticated request is signed with the device's Ed25519
//! authentication key over the signing string of PROTOCOL.md 8.1. That key
//! is separate from the device's MLS keys.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::blocking::Client as Http;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::Error;

/// A registered device: its ids and its request-signing key.
pub struct Creds {
    pub account_id: String,
    pub device_id: String,
    pub key: SigningKey,
}

/// The server's answer to a request: status and JSON body.
#[derive(Debug)]
pub struct Reply {
    pub status: StatusCode,
    pub body: Value,
}

impl Reply {
    pub fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or("")
    }

    fn ok(self) -> Result<Value, Error> {
        if self.status.is_success() {
            Ok(self.body)
        } else {
            Err(Error::Server { status: self.status.as_u16(), code: self.code().to_string() })
        }
    }
}

/// One server.
pub struct Api {
    base: String,
    http: Http,
}

pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, Error> {
    STANDARD.decode(s).map_err(|_| Error::Protocol("bad base64 from server".into()))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("operating system random number generator failed");
    b
}

/// Proof of work for signup (PROTOCOL.md 8.2).
pub fn solve_pow(auth_pub: &[u8; 32], bits: u32) -> u64 {
    (0u64..)
        .find(|n| {
            let h = Sha256::new()
                .chain_update(b"tree-signup-v1")
                .chain_update(auth_pub)
                .chain_update(n.to_be_bytes())
                .finalize();
            leading_zero_bits(&h) >= bits
        })
        .expect("a nonce exists")
}

fn leading_zero_bits(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

impl Api {
    pub fn new(base: &str) -> Result<Self, Error> {
        let http = Http::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Network(e.to_string()))?;
        Ok(Self { base: base.trim_end_matches('/').to_string(), http })
    }

    /// Sends a request signed by `key`; `device_id` is empty only for signup.
    pub fn request(
        &self,
        key: &SigningKey,
        device_id: &str,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Reply, Error> {
        let body = body.map(|b| serde_json::to_vec(b).expect("JSON value")).unwrap_or_default();
        let ts = now().to_string();
        let nonce = URL_SAFE_NO_PAD.encode(random::<16>());
        let signing = format!(
            "tree-auth-v1\n{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            path,
            ts,
            nonce,
            device_id,
            hex::encode(Sha256::digest(&body))
        );
        let sig = key.sign(signing.as_bytes());
        let mut req = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .header("X-Tree-Timestamp", ts)
            .header("X-Tree-Nonce", nonce)
            .header("X-Tree-Signature", b64(&sig.to_bytes()));
        if !device_id.is_empty() {
            req = req.header("X-Tree-Device", device_id);
        }
        if !body.is_empty() {
            req = req.header("Content-Type", "application/json").body(body);
        }
        let resp = req.send().map_err(|e| Error::Network(e.to_string()))?;
        let status = resp.status();
        let text = resp.text().map_err(|e| Error::Network(e.to_string()))?;
        let body = if text.is_empty() { Value::Null } else { serde_json::from_str(&text).unwrap_or(Value::Null) };
        Ok(Reply { status, body })
    }

    fn call(&self, c: &Creds, method: Method, path: &str, body: Option<&Value>) -> Result<Reply, Error> {
        self.request(&c.key, &c.device_id, method, path, body)
    }

    /// Registers a new account with one device. Solves the proof of work.
    pub fn signup(&self, key: &SigningKey, pow_bits: u32) -> Result<Creds, Error> {
        let public = key.verifying_key().to_bytes();
        let nonce = solve_pow(&public, pow_bits);
        let body = json!({ "auth_pub": b64(&public), "pow_nonce": nonce });
        let v = self.request(key, "", Method::POST, "/v1/accounts", Some(&body))?.ok()?;
        Ok(Creds {
            account_id: field(&v, "account_id")?,
            device_id: field(&v, "device_id")?,
            key: key.clone(),
        })
    }

    pub fn upload_key_packages(&self, c: &Creds, kps: &[Vec<u8>]) -> Result<u64, Error> {
        let body = json!({ "key_packages": kps.iter().map(|k| b64(k)).collect::<Vec<_>>() });
        let v = self.call(c, Method::POST, "/v1/keypackages", Some(&body))?.ok()?;
        Ok(v["count"].as_u64().unwrap_or(0))
    }

    pub fn key_package_count(&self, c: &Creds) -> Result<u64, Error> {
        let v = self.call(c, Method::GET, "/v1/keypackages/count", None)?.ok()?;
        Ok(v["count"].as_u64().unwrap_or(0))
    }

    /// One key package per device of `account_id`: (device id, key package).
    pub fn claim(&self, c: &Creds, account_id: &str) -> Result<Vec<(String, Vec<u8>)>, Error> {
        let v = self
            .call(c, Method::POST, "/v1/keypackages/claim", Some(&json!({ "account_id": account_id })))?
            .ok()?;
        let mut out = Vec::new();
        for kp in v["key_packages"].as_array().into_iter().flatten() {
            out.push((field(kp, "device_id")?, unb64(kp["key_package"].as_str().unwrap_or(""))?));
        }
        Ok(out)
    }

    /// Uploads an encrypted attachment; returns its id.
    pub fn upload(&self, c: &Creds, ciphertext: &[u8]) -> Result<String, Error> {
        let reply = self.request_raw(&c.key, &c.device_id, Method::POST, "/v1/attachments", ciphertext.to_vec())?;
        let status = reply.status();
        let v: Value = reply.json().unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(Error::Server { status: status.as_u16(), code: v["code"].as_str().unwrap_or("").into() });
        }
        field(&v, "id")
    }

    pub fn download(&self, c: &Creds, id: &str) -> Result<Vec<u8>, Error> {
        let path = format!("/v1/attachments/{id}");
        let reply = self.request_raw(&c.key, &c.device_id, Method::GET, &path, vec![])?;
        let status = reply.status();
        if !status.is_success() {
            return Err(Error::Server { status: status.as_u16(), code: "DOWNLOAD_FAILED".into() });
        }
        Ok(reply.bytes().map_err(|e| Error::Network(e.to_string()))?.to_vec())
    }

    /// A signed request with a raw (non-JSON) body; returns the response.
    fn request_raw(&self, key: &SigningKey, device_id: &str, method: Method, path: &str, body: Vec<u8>) -> Result<reqwest::blocking::Response, Error> {
        let ts = now().to_string();
        let nonce = URL_SAFE_NO_PAD.encode(random::<16>());
        let signing = format!(
            "tree-auth-v1\n{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            path,
            ts,
            nonce,
            device_id,
            hex::encode(Sha256::digest(&body))
        );
        let sig = key.sign(signing.as_bytes());
        let mut req = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .header("X-Tree-Device", device_id)
            .header("X-Tree-Timestamp", ts)
            .header("X-Tree-Nonce", nonce)
            .header("X-Tree-Signature", b64(&sig.to_bytes()));
        if !body.is_empty() {
            req = req.header("Content-Type", "application/octet-stream").body(body);
        }
        req.send().map_err(|e| Error::Network(e.to_string()))
    }

    /// `POST /v1/usernames/{action}` (apply, release, lookup).
    pub fn username(&self, c: &Creds, action: &str, body: Option<&Value>) -> Result<Value, Error> {
        self.call(c, Method::POST, &format!("/v1/usernames/{action}"), body)?.ok()
    }

    /// A franking tag for a commitment: (tag base64, minute).
    pub fn frank(&self, c: &Creds, com: &[u8; 32]) -> Result<(String, i64), Error> {
        let v = self.call(c, Method::POST, "/v1/franking", Some(&json!({ "com": b64(com) })))?.ok()?;
        Ok((v["tag"].as_str().unwrap_or_default().to_string(), v["minute"].as_i64().unwrap_or(0)))
    }

    /// Files a report (PROTOCOL.md 8.5).
    pub fn report(&self, c: &Creds, req: &Value) -> Result<Value, Error> {
        self.call(c, Method::POST, "/v1/reports", Some(req))?.ok()
    }

    pub fn send(&self, c: &Creds, recipients: &[String], body: &[u8]) -> Result<Value, Error> {
        let req = json!({ "recipients": recipients, "body": b64(body) });
        self.call(c, Method::POST, "/v1/messages", Some(&req))?.ok()
    }

    /// Submits a commit; the caller interprets the reply (200 / 409 / 403).
    pub fn commit(&self, c: &Creds, req: &Value) -> Result<Reply, Error> {
        self.call(c, Method::POST, "/v1/commits", Some(req))
    }

    /// Pending mailbox entries: (id, body). Waits up to `wait` seconds.
    pub fn fetch(&self, c: &Creds, wait: u64) -> Result<Vec<(String, Vec<u8>)>, Error> {
        let path = if wait > 0 { format!("/v1/messages?wait={wait}") } else { "/v1/messages".into() };
        let v = self.call(c, Method::GET, &path, None)?.ok()?;
        let mut out = Vec::new();
        for m in v["messages"].as_array().into_iter().flatten() {
            out.push((field(m, "id")?, unb64(m["body"].as_str().unwrap_or(""))?));
        }
        Ok(out)
    }

    pub fn ack(&self, c: &Creds, ids: &[String]) -> Result<(), Error> {
        if ids.is_empty() {
            return Ok(());
        }
        self.call(c, Method::POST, "/v1/messages/ack", Some(&json!({ "ids": ids })))?.ok()?;
        Ok(())
    }
}

fn field(v: &Value, name: &str) -> Result<String, Error> {
    v[name].as_str().map(str::to_string).ok_or_else(|| Error::Protocol(format!("server reply lacks {name}")))
}
