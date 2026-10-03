//! Identity helpers that do not require the UI.
//!
//! Usernames are intentionally restricted to a small ASCII alphabet so the
//! normalization is deterministic across clients without pulling Unicode
//! normalization into the security boundary. The server stores only the hash.
//!
//! Safety fingerprints are per-device values derived from the MLS signing
//! public key. A multi-device "person" fingerprint is an app-level view over
//! these device fingerprints; Tree v1 deliberately does not invent a new
//! multi-device combiner.

use sha2::{Digest, Sha256};

use crate::error::TreeError;

const USERNAME_LABEL: &[u8] = b"tree/username/v1";
const SAFETY_LABEL: &[u8] = b"tree/safety-number/v1";

/// Canonical Tree username.
///
/// v1 accepts 3..=32 ASCII bytes from [a-z0-9_], lowercases ASCII letters,
/// and requires the first byte to be an ASCII letter. This avoids ambiguous
/// Unicode case/normalization rules before the app UI exists.
pub fn normalize_username(input: &str) -> Result<String, TreeError> {
    let raw = input.trim();
    if !(3..=32).contains(&raw.len()) {
        return Err(TreeError::Identity(
            "username must be 3..=32 ASCII bytes".into(),
        ));
    }

    let mut out = String::with_capacity(raw.len());
    for (i, b) in raw.bytes().enumerate() {
        let b = match b {
            b'A'..=b'Z' => b + (b'a' - b'A'),
            b'a'..=b'z' | b'0'..=b'9' | b'_' => b,
            _ => {
                return Err(TreeError::Identity(
                    "username may use only ASCII letters, digits and '_'".into(),
                ))
            }
        };
        if i == 0 && !b.is_ascii_lowercase() {
            return Err(TreeError::Identity(
                "username must start with an ASCII letter".into(),
            ));
        }
        out.push(b as char);
    }
    Ok(out)
}

/// Hashes a canonical username. Only this digest belongs on the server.
pub fn username_hash(username: &str) -> Result<[u8; 32], TreeError> {
    let canonical = normalize_username(username)?;
    let mut h = Sha256::new();
    h.update(USERNAME_LABEL);
    h.update(canonical.as_bytes());
    Ok(h.finalize().into())
}

/// Returns a stable per-device safety fingerprint.
pub fn safety_fingerprint(signature_public_key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SAFETY_LABEL);
    h.update(signature_public_key);
    h.finalize().into()
}

/// Lowercase hex representation used by the non-UI CLI and future QR payloads.
pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    hex::encode(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_normalization_is_canonical() {
        assert_eq!(normalize_username("Alice_01").unwrap(), "alice_01");
        assert_eq!(username_hash("Alice").unwrap(), username_hash("alice").unwrap());
        assert!(normalize_username("ab").is_err());
        assert!(normalize_username("1alice").is_err());
        assert!(normalize_username("alice-01").is_err());
    }

    #[test]
    fn safety_fingerprint_is_domain_separated() {
        let fp = safety_fingerprint(&[7u8; 32]);
        assert_eq!(fp.len(), 32);
        assert_ne!(fp, Sha256::digest([7u8; 32]).into());
    }
}
