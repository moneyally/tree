//! Small helpers: time, random identifiers, base64.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::error::ApiError;

/// Unix time in seconds.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Days since the Unix epoch (the only granularity stored for creation dates).
pub fn today() -> i64 {
    now_secs() / 86_400
}

/// Rounds a timestamp down to the minute.
pub fn round_to_minute(t: i64) -> i64 {
    t - t.rem_euclid(60)
}

/// Fills `buf` from the operating system's CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("operating system random number generator failed");
    buf
}

/// Length of an encoded identifier: 16 random bytes, base64url without padding.
pub const ID_LEN: usize = 22;

/// New random identifier (account, device or message).
pub fn new_id() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<16>())
}

/// Checks the shape of an identifier supplied by a client.
pub fn is_valid_id(s: &str) -> bool {
    s.len() == ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && URL_SAFE_NO_PAD
            .decode(s)
            .map(|v| v.len() == 16)
            .unwrap_or(false)
}

pub fn check_id(s: &str, what: &'static str) -> Result<(), ApiError> {
    if is_valid_id(s) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "{what} is not a valid identifier"
        )))
    }
}

/// Standard base64 (RFC 4648 section 4, with padding).
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn unb64(s: &str, what: &'static str) -> Result<Vec<u8>, ApiError> {
    STANDARD
        .decode(s)
        .map_err(|_| ApiError::bad_request(format!("{what} is not valid base64")))
}

pub fn unb64_url(s: &str, what: &'static str) -> Result<Vec<u8>, ApiError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| ApiError::bad_request(format!("{what} is not valid base64url")))
}

/// True if `s` certainly decodes to more than `max` bytes (checked before decoding).
/// Padding removes at most 2 bytes from `len / 4 * 3`.
pub fn b64_exceeds(s: &str, max: usize) -> bool {
    (s.len() / 4 * 3).saturating_sub(2) > max
}
