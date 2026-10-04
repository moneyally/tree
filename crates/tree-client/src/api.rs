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
#[derive(Clone)]
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

/// An upload as the server has it (`POST /v1/uploads` and friends).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadStatus {
    pub id: String,
    pub size: u64,
    pub chunk_size: u64,
    pub chunks: u64,
    pub received: u64,
    pub complete: bool,
}

impl UploadStatus {
    fn from_json(v: &Value) -> Result<Self, Error> {
        let n = |k: &str| v[k].as_u64().ok_or_else(|| Error::Protocol(format!("server reply lacks {k}")));
        let s = UploadStatus {
            id: field(v, "id")?,
            size: n("size")?,
            chunk_size: n("chunk_size")?,
            chunks: n("chunks")?,
            received: n("received")?,
            complete: v["complete"].as_bool().unwrap_or(false),
        };
        if s.chunk_size == 0 || s.chunks != s.size.div_ceil(s.chunk_size) || s.received > s.chunks {
            return Err(Error::Protocol("inconsistent upload status".into()));
        }
        Ok(s)
    }
}

/// One server.
#[derive(Clone)]
pub struct Api {
    base: String,
    http: Http,
}

/// Someone used one of this device's invite links.
pub struct InviteRequest {
    pub id: String,
    pub hash: Vec<u8>,
    pub account: String,
    /// The joining device's nonce (none from older clients).
    pub nonce: Option<Vec<u8>>,
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

    /// Joins the account that holds `recovery_pub` as a new device
    /// (PROTOCOL.md 8.6). `signature` is the recovery key's signature over
    /// the recovery message for this key.
    pub fn recover(
        &self,
        key: &SigningKey,
        recovery_pub: &[u8; 32],
        signature: &[u8; 64],
        ts: i64,
        revoke_others: bool,
        pow_bits: u32,
    ) -> Result<Creds, Error> {
        let public = key.verifying_key().to_bytes();
        let nonce = solve_pow(&public, pow_bits);
        let body = json!({
            "recovery_pub": b64(recovery_pub), "auth_pub": b64(&public), "pow_nonce": nonce,
            "signature": b64(signature), "ts": ts, "revoke_others": revoke_others,
        });
        let v = self.request(key, "", Method::POST, "/v1/recovery/recover", Some(&body))?.ok()?;
        Ok(Creds { account_id: field(&v, "account_id")?, device_id: field(&v, "device_id")?, key: key.clone() })
    }

    /// Deletes the whole account on the server.
    pub fn delete_account(&self, c: &Creds) -> Result<(), Error> {
        self.call(c, Method::DELETE, "/v1/accounts", None)?.ok()?;
        Ok(())
    }

    /// Sets (`Some`) or clears (`None`) this device's push endpoint
    /// (PROTOCOL.md 8.8).
    pub fn set_push(&self, c: &Creds, endpoint: Option<&str>) -> Result<(), Error> {
        match endpoint {
            Some(e) => self.call(c, Method::POST, "/v1/push", Some(&json!({ "endpoint": e })))?.ok()?,
            None => self.call(c, Method::DELETE, "/v1/push", None)?.ok()?,
        };
        Ok(())
    }

    /// Registers an invite link's hash (PROTOCOL.md 8.7).
    pub fn invite_create(&self, c: &Creds, hash: &[u8; 32], lifetime: i64, max_uses: u32) -> Result<Value, Error> {
        let body = json!({ "token_hash": b64(hash), "lifetime": lifetime, "max_uses": max_uses });
        self.call(c, Method::POST, "/v1/invites", Some(&body))?.ok()
    }

    pub fn invite_revoke(&self, c: &Creds, hash: &[u8]) -> Result<(), Error> {
        let path = format!("/v1/invites/{}", URL_SAFE_NO_PAD.encode(hash));
        self.call(c, Method::DELETE, &path, None)?.ok()?;
        Ok(())
    }

    /// Uses a link; returns the owner's account id. `nonce` goes only to
    /// the owner's device, with the request.
    pub fn invite_join(&self, c: &Creds, token_b64: &str, nonce: &[u8; 16]) -> Result<String, Error> {
        let body = json!({ "token": token_b64, "nonce": b64(nonce) });
        let v = self.call(c, Method::POST, "/v1/invites/join", Some(&body))?.ok()?;
        field(&v, "owner_account")
    }

    /// Join requests for this device's links: (id, token hash, account,
    /// the joiner's nonce if it sent one).
    pub fn invite_requests(&self, c: &Creds) -> Result<Vec<InviteRequest>, Error> {
        let v = self.call(c, Method::GET, "/v1/invites/requests", None)?.ok()?;
        let mut out = Vec::new();
        for r in v["requests"].as_array().cloned().unwrap_or_default() {
            let nonce = r["nonce"].as_str().map(unb64).transpose()?;
            out.push(InviteRequest {
                id: field(&r, "id")?,
                hash: unb64(&field(&r, "token_hash")?)?,
                account: field(&r, "account_id")?,
                nonce,
            });
        }
        Ok(out)
    }

    pub fn invite_ack(&self, c: &Creds, ids: &[String]) -> Result<(), Error> {
        self.call(c, Method::POST, "/v1/invites/requests/ack", Some(&json!({ "ids": ids })))?.ok()?;
        Ok(())
    }

    /// Registers a recovery key (`proof`: by the new key; `current`: by the
    /// current key, or the change waits 7 days). Returns the state.
    pub fn recovery_apply(&self, c: &Creds, recovery_pub: &[u8; 32], proof: &[u8; 64], current: Option<&[u8; 64]>) -> Result<Value, Error> {
        let body = json!({ "recovery_pub": b64(recovery_pub), "proof": b64(proof), "current_signature": current.map(|s| b64(s)) });
        self.call(c, Method::POST, "/v1/recovery/apply", Some(&body))?.ok()
    }

    pub fn recovery_release(&self, c: &Creds, current: Option<&[u8; 64]>) -> Result<Value, Error> {
        let body = json!({ "current_signature": current.map(|s| b64(s)) });
        self.call(c, Method::POST, "/v1/recovery/release", Some(&body))?.ok()
    }

    pub fn recovery_status(&self, c: &Creds) -> Result<Value, Error> {
        self.call(c, Method::GET, "/v1/recovery", None)?.ok()
    }

    pub fn upload_key_packages(&self, c: &Creds, kps: &[Vec<u8>]) -> Result<u64, Error> {
        let body = json!({ "key_packages": kps.iter().map(|k| b64(k)).collect::<Vec<_>>() });
        let v = self.call(c, Method::POST, "/v1/keypackages", Some(&body))?.ok()?;
        Ok(v["count"].as_u64().unwrap_or(0))
    }

    pub fn key_package_count(&self, c: &Creds) -> Result<u64, Error> {
        Ok(self.key_package_status(c)?.0)
    }

    /// One-time key packages left on the server, and whether a last-resort
    /// one is there.
    pub fn key_package_status(&self, c: &Creds) -> Result<(u64, bool), Error> {
        let v = self.call(c, Method::GET, "/v1/keypackages/count", None)?.ok()?;
        Ok((v["count"].as_u64().unwrap_or(0), v["last_resort"].as_bool().unwrap_or(false)))
    }

    /// Sets or replaces this device's last-resort key package.
    pub fn set_last_resort(&self, c: &Creds, kp: &[u8]) -> Result<(), Error> {
        self.call(c, Method::PUT, "/v1/keypackages/last-resort", Some(&json!({ "key_package": b64(kp) })))?.ok()?;
        Ok(())
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

    /// Starts an upload of `size` ciphertext bytes (PROTOCOL.md 6.12).
    pub fn upload_create(&self, c: &Creds, size: u64) -> Result<UploadStatus, Error> {
        UploadStatus::from_json(&self.call(c, Method::POST, "/v1/uploads", Some(&json!({ "size": size })))?.ok()?)
    }

    /// Where an upload stands (`404` once purged).
    pub fn upload_status(&self, c: &Creds, id: &str) -> Result<UploadStatus, Error> {
        UploadStatus::from_json(&self.call(c, Method::GET, &format!("/v1/uploads/{id}"), None)?.ok()?)
    }

    /// Sends part `index` of an upload.
    pub fn upload_part(&self, c: &Creds, id: &str, index: u64, bytes: &[u8]) -> Result<UploadStatus, Error> {
        let path = format!("/v1/uploads/{id}/{index}");
        let reply = self.request_raw(&c.key, &c.device_id, Method::PUT, &path, bytes.to_vec())?;
        let status = reply.status();
        let v: Value = reply.json().unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(Error::Server { status: status.as_u16(), code: v["code"].as_str().unwrap_or("").into() });
        }
        UploadStatus::from_json(&v)
    }

    /// Gives up an unfinished upload.
    pub fn upload_cancel(&self, c: &Creds, id: &str) -> Result<(), Error> {
        self.call(c, Method::DELETE, &format!("/v1/uploads/{id}"), None)?.ok()?;
        Ok(())
    }

    /// One range of an attachment from byte `offset`: (bytes, total size).
    pub fn download_range(&self, c: &Creds, id: &str, offset: u64) -> Result<(Vec<u8>, u64), Error> {
        let path = format!("/v1/attachments/{id}?offset={offset}");
        let reply = self.request_raw(&c.key, &c.device_id, Method::GET, &path, vec![])?;
        let status = reply.status();
        if !status.is_success() {
            return Err(Error::Server { status: status.as_u16(), code: "DOWNLOAD_FAILED".into() });
        }
        let total = reply
            .headers()
            .get("x-tree-total")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| Error::Protocol("server reply lacks the attachment size".into()))?;
        Ok((reply.bytes().map_err(|e| Error::Network(e.to_string()))?.to_vec(), total))
    }

    /// A signed GET that answers with bytes (relays): the bytes and their
    /// type, or the server's error code.
    pub fn get_bytes(&self, c: &Creds, path: &str) -> Result<(Vec<u8>, String), Error> {
        let reply = self.request_raw(&c.key, &c.device_id, Method::GET, path, vec![])?;
        let status = reply.status();
        let mime = reply
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let bytes = reply.bytes().map_err(|e| Error::Network(e.to_string()))?.to_vec();
        if !status.is_success() {
            let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            return Err(Error::Server { status: status.as_u16(), code: v["code"].as_str().unwrap_or("").into() });
        }
        Ok((bytes, mime))
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

    /// [`Api::send`] with an idempotency key (PROTOCOL.md 8.10): a retry
    /// with the same key and request is answered without a second delivery.
    pub fn send_keyed(&self, c: &Creds, recipients: &[String], body: &[u8], key: &[u8]) -> Result<Value, Error> {
        let req = json!({ "recipients": recipients, "body": b64(body), "idempotency_key": b64(key) });
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

    /// Waits up to `wait` seconds for the mailbox to be non-empty, without
    /// taking anything (the caller then syncs). Lets an app long-poll while
    /// other calls on its session proceed.
    pub fn wait_pending(&self, c: &Creds, wait: u64) -> Result<bool, Error> {
        Ok(!self.fetch(c, wait)?.is_empty())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_of_work_bits() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x0f, 0xff]), 20);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0x01]), 7);
        assert_eq!(leading_zero_bits(&[0, 0x40]), 9);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
        let key = [5u8; 32];
        let n = solve_pow(&key, 10);
        assert!(leading_zero_bits(&Sha256::digest([&b"tree-signup-v1"[..], &key[..], &n.to_be_bytes()[..]].concat())) >= 10);
    }
}
