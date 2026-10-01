//! Request authentication.
//!
//! Every authenticated request carries:
//!
//! * `X-Tree-Device`: device id
//! * `X-Tree-Timestamp`: unix seconds, decimal
//! * `X-Tree-Nonce`: 16 to 64 characters of `[A-Za-z0-9_-]`, fresh per request
//! * `X-Tree-Signature`: base64 Ed25519 signature over [`signing_message`]
//!
//! The signature covers the method, path and query, timestamp, nonce, device id
//! and the SHA-256 of the body. Requests outside the clock-skew window are
//! rejected, and a signature is accepted only once within that window.

use axum::body::to_bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use sqlx::Row;
use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::util::{is_valid_id, now_secs, unb64};
use crate::AppState;

pub const H_DEVICE: &str = "x-tree-device";
pub const H_TIMESTAMP: &str = "x-tree-timestamp";
pub const H_NONCE: &str = "x-tree-nonce";
pub const H_SIGNATURE: &str = "x-tree-signature";
pub const H_ADMIN: &str = "x-tree-admin";

/// Domain separation tag for request signatures.
pub const AUTH_CONTEXT: &str = "tree-auth-v1";

/// The exact bytes a client signs.
///
/// ```text
/// tree-auth-v1 \n METHOD \n PATH_AND_QUERY \n TIMESTAMP \n NONCE \n DEVICE_ID \n hex(SHA-256(body))
/// ```
///
/// `DEVICE_ID` is empty for signup, where the device does not exist yet.
pub fn signing_message(
    method: &str,
    path_and_query: &str,
    timestamp: &str,
    nonce: &str,
    device_id: &str,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = hex::encode(Sha256::digest(body));
    format!("{AUTH_CONTEXT}\n{method}\n{path_and_query}\n{timestamp}\n{nonce}\n{device_id}\n{body_hash}")
        .into_bytes()
}

/// Parsed authentication headers.
pub struct AuthHeaders {
    pub device: Option<String>,
    timestamp_raw: String,
    timestamp: i64,
    nonce: String,
    signature: [u8; 64],
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn valid_nonce(n: &str) -> bool {
    (16..=64).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl AuthHeaders {
    pub fn parse(h: &HeaderMap, need_device: bool) -> ApiResult<Self> {
        let missing = || ApiError::unauthorized("missing or malformed authentication headers");
        let device = match header(h, H_DEVICE) {
            Some(d) if is_valid_id(d) => Some(d.to_string()),
            Some(_) => return Err(missing()),
            None if need_device => return Err(missing()),
            None => None,
        };
        let ts = header(h, H_TIMESTAMP).ok_or_else(missing)?;
        if ts.is_empty() || ts.len() > 12 || !ts.bytes().all(|b| b.is_ascii_digit()) {
            return Err(missing());
        }
        let timestamp: i64 = ts.parse().map_err(|_| missing())?;
        let nonce = header(h, H_NONCE)
            .filter(|n| valid_nonce(n))
            .ok_or_else(missing)?;
        let sig = header(h, H_SIGNATURE).ok_or_else(missing)?;
        let signature: [u8; 64] = unb64(sig, "signature")
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(missing)?;
        Ok(Self {
            device,
            timestamp_raw: ts.to_string(),
            timestamp,
            nonce: nonce.to_string(),
            signature,
        })
    }

    /// Checks time window, signature and replay. On success the signature is
    /// remembered until it leaves the window.
    pub fn verify(
        &self,
        state: &AppState,
        key: &VerifyingKey,
        method: &Method,
        uri: &Uri,
        body: &[u8],
    ) -> ApiResult<()> {
        let now = now_secs();
        let skew = state.cfg.clock_skew_secs as i64;
        if (self.timestamp - now).abs() > skew {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "TIMESTAMP_SKEW",
                "timestamp outside the accepted window; see the Date response header",
            ));
        }
        let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let msg = signing_message(
            method.as_str(),
            pq,
            &self.timestamp_raw,
            &self.nonce,
            self.device.as_deref().unwrap_or(""),
            body,
        );
        key.verify_strict(&msg, &Signature::from_bytes(&self.signature))
            .map_err(|_| ApiError::unauthorized("authentication failed"))?;
        if !state
            .replay
            .insert(self.signature, self.timestamp + skew, now)
        {
            return Err(ApiError::unauthorized("replayed request"));
        }
        Ok(())
    }
}

/// Parses and validates an Ed25519 public key sent by a client.
pub fn parse_public_key(b64: &str) -> ApiResult<(VerifyingKey, [u8; 32])> {
    let raw: [u8; 32] = unb64(b64, "auth_pub")?
        .try_into()
        .map_err(|_| ApiError::bad_request("auth_pub must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&raw)
        .map_err(|_| ApiError::bad_request("auth_pub is not a valid Ed25519 key"))?;
    if key.is_weak() {
        return Err(ApiError::bad_request("auth_pub is a weak key"));
    }
    Ok((key, raw))
}

/// Reads the body up to `limit` bytes.
pub async fn read_body(
    req: Request,
    limit: usize,
) -> ApiResult<(axum::http::request::Parts, Vec<u8>)> {
    let (parts, body) = req.into_parts();
    if let Some(len) = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if len > limit as u64 {
            return Err(ApiError::too_large("request body too large"));
        }
    }
    let bytes = to_bytes(body, limit)
        .await
        .map_err(|_| ApiError::too_large("request body too large"))?;
    Ok((parts, bytes.to_vec()))
}

pub fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(bytes)
        .map_err(|e| ApiError::bad_request(format!("invalid JSON body: {e}")))
}

/// A request body type for [`Signed`].
pub trait SignedBody: Sized {
    fn max_len(cfg: &Config) -> usize;
    fn parse(bytes: &[u8]) -> ApiResult<Self>;
}

/// Body of a request that must not have one (GET, DELETE).
pub struct NoBody;

impl SignedBody for NoBody {
    fn max_len(_: &Config) -> usize {
        0
    }
    fn parse(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.is_empty() {
            Ok(NoBody)
        } else {
            Err(ApiError::bad_request("this request takes no body"))
        }
    }
}

/// Implements [`SignedBody`] for a JSON request type with a size limit.
#[macro_export]
macro_rules! json_body {
    ($t:ty, |$cfg:ident| $limit:expr) => {
        impl $crate::auth::SignedBody for $t {
            fn max_len($cfg: &$crate::config::Config) -> usize {
                $limit
            }
            fn parse(bytes: &[u8]) -> $crate::error::ApiResult<Self> {
                $crate::auth::parse_json(bytes)
            }
        }
    };
}

/// The authenticated device behind a request.
#[derive(Debug, Clone)]
pub struct DeviceCtx {
    pub device_id: String,
    pub account_id: String,
}

/// Extractor: verifies the request signature, applies the per-device rate
/// limit (one token) and parses the body.
pub struct Signed<T> {
    pub device: DeviceCtx,
    pub body: T,
}

impl<T: SignedBody + Send> FromRequest<AppState> for Signed<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth = AuthHeaders::parse(req.headers(), true)?;
        let (parts, bytes) = read_body(req, T::max_len(&state.cfg)).await?;
        let device_id = auth.device.clone().unwrap_or_default();

        let row = sqlx::query("SELECT account_id, auth_pub FROM devices WHERE id = ?")
            .bind(&device_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::unauthorized("authentication failed"))?;
        let account_id: String = row.try_get("account_id")?;
        let auth_pub: Vec<u8> = row.try_get("auth_pub")?;
        let raw: [u8; 32] = auth_pub.try_into().map_err(|_| ApiError::internal())?;
        let key = VerifyingKey::from_bytes(&raw).map_err(|_| ApiError::internal())?;

        auth.verify(state, &key, &parts.method, &parts.uri, &bytes)?;
        state.rate_device(&device_id, 1.0)?;

        let body = T::parse(&bytes)?;
        Ok(Signed {
            device: DeviceCtx {
                device_id,
                account_id,
            },
            body,
        })
    }
}

/// Checks `X-Tree-Admin` against the configured SHA-256, in constant time.
pub fn check_admin(cfg: &Config, headers: &HeaderMap) -> ApiResult<()> {
    let Some(expected) = cfg.admin_token_sha256 else {
        return Err(ApiError::unauthorized(
            "operator endpoints are disabled on this server",
        ));
    };
    let token = headers
        .get(H_ADMIN)
        .map(|v| v.as_bytes())
        .unwrap_or_default();
    let got = Sha256::digest(token);
    if token.is_empty() || !bool::from(got.as_slice().ct_eq(&expected)) {
        return Err(ApiError::unauthorized("operator token required"));
    }
    Ok(())
}
