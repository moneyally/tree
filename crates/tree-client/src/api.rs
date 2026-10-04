use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::blocking::Client as Http;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{b64, Error as ClientError};

#[derive(Clone)]
pub struct Creds {
    pub account_id: String,
    pub device_id: String,
    pub key: SigningKey,
}

#[derive(Debug)]
pub struct Reply {
    pub status: StatusCode,
    pub body: Value,
}

impl Reply {
    pub fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or("")
    }

    fn ok(self) -> Result<Value, ClientError> {
        if self.status.is_success() {
            Ok(self.body)
        } else {
            Err(ClientError::Server {
                status: self.status.as_u16(),
                code: self.code().to_string(),
            })
        }
    }
}

#[derive(Clone)]
pub struct Api {
    base: String,
    http: Http,
}

impl Api {
    pub fn new(base: &str) -> Result<Self, ClientError> {
        let http = Http::builder()
            .timeout(std::time::Duration::from_secs(35))
            .build()
            .map_err(|e| ClientError::Usage(format!("HTTP client: {e}")))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http,
        })
    }

    pub fn signup(&self, key: &SigningKey, pow_bits: u32) -> Result<Creds, ClientError> {
        let public = key.verifying_key().to_bytes();
        let nonce = solve_pow(&public, pow_bits);
        let body = json!({
            "auth_pub": b64(&public),
            "pow_nonce": nonce,
        });
        let value = self
            .request(key, "", Method::POST, "/v1/accounts", Some(&body))?
            .ok()?;
        Ok(Creds {
            account_id: field(&value, "account_id")?,
            device_id: field(&value, "device_id")?,
            key: key.clone(),
        })
    }

    pub fn key_package_count(&self, c: &Creds) -> Result<u64, ClientError> {
        let value = self
            .call(c, Method::GET, "/v1/keypackages/count", None)?
            .ok()?;
        value["count"].as_u64().ok_or_else(|| {
            ClientError::Usage("server returned an invalid key-package count".into())
        })
    }

    pub fn upload_key_packages(
        &self,
        c: &Creds,
        packages: &[Vec<u8>],
    ) -> Result<u64, ClientError> {
        let body = json!({
            "key_packages": packages.iter().map(|p| b64(p)).collect::<Vec<_>>(),
        });
        let value = self
            .call(c, Method::POST, "/v1/keypackages", Some(&body))?
            .ok()?;
        value["count"].as_u64().ok_or_else(|| {
            ClientError::Usage("server returned an invalid key-package count".into())
        })
    }

    pub fn revoke_key_packages(&self, c: &Creds) -> Result<u64, ClientError> {
        let value = self
            .call(c, Method::DELETE, "/v1/keypackages", None)?
            .ok()?;
        value["revoked"]
            .as_u64()
            .ok_or_else(|| ClientError::Usage("server returned an invalid revoke count".into()))
    }

    pub fn claim(
        &self,
        c: &Creds,
        account_id: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, ClientError> {
        let body = json!({ "account_id": account_id });
        let value = self
            .call(c, Method::POST, "/v1/keypackages/claim", Some(&body))?
            .ok()?;
        let mut out = Vec::new();
        for item in value["key_packages"].as_array().into_iter().flatten() {
            let device = field(item, "device_id")?;
            let package = unb64(item["key_package"].as_str().unwrap_or(""))?;
            out.push((device, package));
        }
        Ok(out)
    }

    pub fn commit(&self, c: &Creds, request: &Value) -> Result<Reply, ClientError> {
        self.call(c, Method::POST, "/v1/commits", Some(request))
    }

    pub fn send(
        &self,
        c: &Creds,
        recipients: &[String],
        body: &[u8],
    ) -> Result<Reply, ClientError> {
        let request = json!({
            "recipients": recipients,
            "body": b64(body),
        });
        self.call(c, Method::POST, "/v1/messages", Some(&request))
    }

    pub fn fetch(&self, c: &Creds, wait: u64) -> Result<Vec<(String, Vec<u8>)>, ClientError> {
        let path = if wait == 0 {
            "/v1/messages".to_string()
        } else {
            format!("/v1/messages?wait={wait}")
        };
        let value = self.call(c, Method::GET, &path, None)?.ok()?;
        let mut out = Vec::new();
        for item in value["messages"].as_array().into_iter().flatten() {
            out.push((
                field(item, "id")?,
                unb64(item["body"].as_str().unwrap_or(""))?,
            ));
        }
        Ok(out)
    }

    pub fn ack(&self, c: &Creds, ids: &[String]) -> Result<(), ClientError> {
        if ids.is_empty() {
            return Ok(());
        }
        self.call(
            c,
            Method::POST,
            "/v1/messages/ack",
            Some(&json!({ "ids": ids })),
        )?
        .ok()?;
        Ok(())
    }

    fn call(
        &self,
        c: &Creds,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Reply, ClientError> {
        self.request(&c.key, &c.device_id, method, path, body)
    }

    fn request(
        &self,
        key: &SigningKey,
        device_id: &str,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Reply, ClientError> {
        let body = body
            .map(|value| {
                serde_json::to_vec(value)
                    .map_err(|e| ClientError::Usage(format!("JSON encode: {e}")))
            })
            .transpose()?
            .unwrap_or_default();
        let timestamp = now().to_string();
        let nonce = URL_SAFE_NO_PAD.encode(random::<16>());
        let signing = format!(
            "tree-auth-v1\n{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            path,
            timestamp,
            nonce,
            device_id,
            hex::encode(Sha256::digest(&body)),
        );
        let signature = key.sign(signing.as_bytes());

        let mut request = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .header("X-Tree-Timestamp", timestamp)
            .header("X-Tree-Nonce", nonce)
            .header("X-Tree-Signature", b64(&signature.to_bytes()));

        if !device_id.is_empty() {
            request = request.header("X-Tree-Device", device_id);
        }
        if !body.is_empty() {
            request = request
                .header("Content-Type", "application/json")
                .body(body);
        }

        let response = request
            .send()
            .map_err(|e| ClientError::Usage(format!("HTTP request: {e}")))?;
        let status = response.status();
        let text = response
            .text()
            .map_err(|e| ClientError::Usage(format!("HTTP response: {e}")))?;
        let body = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        };
        Ok(Reply { status, body })
    }
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn unb64(value: &str) -> Result<Vec<u8>, ClientError> {
    STANDARD
        .decode(value)
        .map_err(|_| ClientError::Usage("invalid base64 from server".into()))
}

fn field(value: &Value, name: &str) -> Result<String, ClientError> {
    value[name]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| ClientError::Usage(format!("server reply lacks {name}")))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes)
        .expect("operating system random number generator failed");
    bytes
}

fn solve_pow(auth_pub: &[u8; 32], bits: u32) -> u64 {
    (0u64..)
        .find(|nonce| {
            let hash = Sha256::digest(
                [&b"tree-signup-v1"[..], auth_pub, &nonce.to_be_bytes()[..]].concat(),
            );
            leading_zero_bits(&hash) >= bits
        })
        .expect("proof-of-work search exhausted")
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total = 0;
    for byte in bytes {
        if *byte == 0 {
            total += 8;
        } else {
            total += byte.leading_zeros();
            break;
        }
    }
    total
}
