//! Group invite links, version 2 (PROTOCOL.md 8.7, F-025): what is derived
//! from a link's secret so the server neither learns the secret nor reads
//! the joiner's nonce.
//!
//! From the 16-byte link secret `T` (HKDF-SHA-256, RFC 5869, no salt,
//! `T` as input key material, one label per output):
//!
//! - `proof = HKDF(T, "tree/invite/proof/v2")` (32 bytes): what the joiner
//!   sends to the server instead of `T`. The server keeps only
//!   `SHA-256("tree/invite/v1" || proof)`, so a copy of its database does not
//!   let anyone use the link, and the server never holds `T`.
//! - `nonce_key = HKDF(T, "tree/invite/nonce-key/v2")` (32 bytes): the
//!   joiner seals its 16-byte nonce with AES-256-GCM under this key, a fresh
//!   random 12-byte AEAD nonce, and `lp("tree/invite/nonce/v2", joiner
//!   account id)` as associated data. Only someone who holds the link (its
//!   owner's device) can open it; the server relays it opaque.
//!
//! The two outputs are independent: knowing `proof` (the server) gives
//! nothing about `nonce_key`.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::TreeError;
use crate::link::lp;

const LABEL_PROOF: &[u8] = b"tree/invite/proof/v2";
const LABEL_NONCE_KEY: &[u8] = b"tree/invite/nonce-key/v2";
const LABEL_NONCE_AAD: &[u8] = b"tree/invite/nonce/v2";
/// Length of a sealed nonce: AEAD nonce, 16-byte nonce, 16-byte tag.
pub const SEALED_NONCE_LEN: usize = 12 + 16 + 16;

fn derive(token: &[u8; 16], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, token).expand(label, &mut out[..]).expect("32 bytes is a valid HKDF-SHA-256 length");
    out
}

/// What the joiner sends to the server in place of the link secret.
pub fn proof(token: &[u8; 16]) -> [u8; 32] {
    *derive(token, LABEL_PROOF)
}

/// The key that seals the joiner's nonce for the link's owner.
pub fn nonce_key(token: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    derive(token, LABEL_NONCE_KEY)
}

fn aad(joiner_account: &str) -> Vec<u8> {
    lp(&[LABEL_NONCE_AAD, joiner_account.as_bytes()])
}

/// Seals the joiner's `nonce` for the owner of the link `token`.
pub fn seal_nonce(token: &[u8; 16], joiner_account: &str, nonce: &[u8; 16]) -> Vec<u8> {
    let key = nonce_key(token);
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).expect("operating system random number generator failed");
    let ct = Aes256Gcm::new_from_slice(&key[..])
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(&iv), Payload { msg: nonce, aad: &aad(joiner_account) })
        .expect("AES-GCM encryption of 16 bytes does not fail");
    let mut out = iv.to_vec();
    out.extend_from_slice(&ct);
    out
}

/// Opens a sealed nonce with the link's `nonce_key`; fails if it was made
/// for another link or another joining account, or was changed.
pub fn open_nonce(key: &[u8; 32], joiner_account: &str, sealed: &[u8]) -> Result<[u8; 16], TreeError> {
    if sealed.len() != SEALED_NONCE_LEN {
        return Err(TreeError::Malformed("sealed invite nonce has the wrong length".into()));
    }
    let pt = Aes256Gcm::new_from_slice(key)
        .expect("32-byte key")
        .decrypt(Nonce::from_slice(&sealed[..12]), Payload { msg: &sealed[12..], aad: &aad(joiner_account) })
        .map_err(|_| TreeError::Rejected("sealed invite nonce does not open".into()))?;
    pt.try_into().map_err(|_| TreeError::Malformed("invite nonce must be 16 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_round_trip_and_binding() {
        let t = [7u8; 16];
        let n = [9u8; 16];
        let sealed = seal_nonce(&t, "joiner", &n);
        assert_eq!(sealed.len(), SEALED_NONCE_LEN);
        assert!(!sealed.windows(16).any(|w| w == n), "the nonce is not in the clear");
        assert_eq!(open_nonce(&nonce_key(&t), "joiner", &sealed).unwrap(), n);
        assert!(open_nonce(&nonce_key(&[8u8; 16]), "joiner", &sealed).is_err(), "another link");
        assert!(open_nonce(&nonce_key(&t), "someone else", &sealed).is_err(), "another joiner");
        let mut bad = sealed.clone();
        bad[20] ^= 1;
        assert!(open_nonce(&nonce_key(&t), "joiner", &bad).is_err());
        assert!(open_nonce(&nonce_key(&t), "joiner", &sealed[..40]).is_err());
        assert_ne!(seal_nonce(&t, "joiner", &n), sealed, "fresh AEAD nonce each time");
    }

    #[test]
    fn derivations_are_separate() {
        let t = [1u8; 16];
        assert_ne!(proof(&t), *nonce_key(&t));
        assert_ne!(proof(&t), proof(&[2u8; 16]));
        // RFC 5869 HKDF-SHA-256 with no salt, as documented.
        let mut want = [0u8; 32];
        Hkdf::<Sha256>::new(None, &t).expand(b"tree/invite/proof/v2", &mut want).unwrap();
        assert_eq!(proof(&t), want);
    }
}
