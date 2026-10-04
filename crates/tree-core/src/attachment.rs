//! Attachments (PROTOCOL.md 6.12): each file is encrypted with its own random
//! key and uploaded as an opaque blob; the key travels inside the end-to-end
//! encrypted message that refers to the file.
//!
//! * Cipher: AES-256-GCM in the STREAM construction (Hoang, Reyhanitabar,
//!   Rogaway, Vizar, CRYPTO 2015) as implemented by the RustCrypto `aead`
//!   crate (`StreamBE32`): 64 KiB plaintext chunks, nonce = 7-byte random
//!   prefix || 32-bit chunk counter || last-chunk flag. Chunks cannot be
//!   reordered, dropped or truncated without detection.
//! * Commitment: the message carries SHA-256 of the ciphertext and of the
//!   plaintext. The receiver checks the ciphertext hash before decrypting and
//!   the plaintext hash after, so a file cannot open to different content for
//!   different holders of different keys (GCM alone is not key-committing).
//!
//! Nothing here is new cryptography: AES-GCM, STREAM and SHA-256 are used as
//! published, from audited library code.

use aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::{Aes256Gcm, KeyInit};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::TreeError;

/// Plaintext bytes per chunk.
pub const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;
const PREFIX: usize = 7;

/// Everything a recipient needs to fetch-and-open a file, except where it
/// is stored. Sent only inside end-to-end encrypted messages.
#[derive(Clone, PartialEq, Eq)]
pub struct FileKey {
    pub key: Zeroizing<[u8; 32]>,
    pub nonce_prefix: [u8; PREFIX],
    /// Plaintext length in bytes.
    pub size: u64,
    pub ciphertext_sha256: [u8; 32],
    pub plaintext_sha256: [u8; 32],
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKey").field("size", &self.size).finish_non_exhaustive()
    }
}

/// Length of the ciphertext for `size` plaintext bytes.
pub fn ciphertext_len(size: u64) -> u64 {
    let chunks = size.div_ceil(CHUNK as u64).max(1);
    size + chunks * TAG as u64
}

fn random<const N: usize>() -> Result<[u8; N], TreeError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| TreeError::Identity(format!("random: {e}")))?;
    Ok(b)
}

/// Encrypts a file with a fresh key.
pub fn encrypt(plaintext: &[u8]) -> Result<(Vec<u8>, FileKey), TreeError> {
    let key = Zeroizing::new(random::<32>()?);
    let nonce_prefix = random::<PREFIX>()?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| TreeError::Malformed("key".into()))?;
    let mut enc = EncryptorBE32::from_aead(cipher, (&nonce_prefix).into());
    let mut out = Vec::with_capacity(ciphertext_len(plaintext.len() as u64) as usize);
    let failed = |_| TreeError::Malformed("encrypt".into());
    // An empty file is one empty last chunk.
    let mut chunks = plaintext.chunks(CHUNK).peekable();
    loop {
        let c = chunks.next().unwrap_or_default();
        if chunks.peek().is_none() {
            out.extend(enc.encrypt_last(c).map_err(failed)?);
            break;
        }
        out.extend(enc.encrypt_next(c).map_err(failed)?);
    }
    let fk = FileKey {
        key,
        nonce_prefix,
        size: plaintext.len() as u64,
        ciphertext_sha256: Sha256::digest(&out).into(),
        plaintext_sha256: Sha256::digest(plaintext).into(),
    };
    Ok((out, fk))
}

/// Checks and decrypts a downloaded file. Any change to the ciphertext, a
/// wrong key, or content that does not match the committed hashes is an error.
pub fn decrypt(ciphertext: &[u8], fk: &FileKey) -> Result<Vec<u8>, TreeError> {
    let bad = |why: &str| TreeError::Rejected(format!("attachment: {why}"));
    if ciphertext.len() as u64 != ciphertext_len(fk.size) {
        return Err(bad("wrong length"));
    }
    let h: [u8; 32] = Sha256::digest(ciphertext).into();
    if !bool::from(h.ct_eq(&fk.ciphertext_sha256)) {
        return Err(bad("ciphertext does not match the message"));
    }
    let cipher = Aes256Gcm::new_from_slice(&fk.key[..]).map_err(|_| bad("key"))?;
    let mut dec = DecryptorBE32::from_aead(cipher, (&fk.nonce_prefix).into());
    let mut out = Vec::with_capacity(fk.size as usize);
    let mut chunks = ciphertext.chunks(CHUNK + TAG).peekable();
    while let Some(c) = chunks.next() {
        if chunks.peek().is_some() {
            out.extend(dec.decrypt_next(c).map_err(|_| bad("decryption failed"))?);
        } else {
            out.extend(dec.decrypt_last(c).map_err(|_| bad("decryption failed"))?);
            break;
        }
    }
    let p: [u8; 32] = Sha256::digest(&out).into();
    if out.len() as u64 != fk.size || !bool::from(p.ct_eq(&fk.plaintext_sha256)) {
        return Err(bad("content does not match the message"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PROTOCOL.md 6.12: 64 KiB chunks, a 16-byte tag each; the key never
    /// shows up in logs.
    #[test]
    fn format_constants_and_debug() {
        assert_eq!(CHUNK, 65_536);
        assert_eq!(ciphertext_len(65_536), 65_536 + 16);
        assert_eq!(ciphertext_len(65_537), 65_537 + 32);
        let (_, fk) = encrypt(b"secret").unwrap();
        let d = format!("{fk:?}");
        assert!(d.starts_with("FileKey") && d.contains("size: 6"), "{d}");
        assert!(!d.contains(&format!("{:?}", &fk.key[..4])) && !d.contains("key"), "{d}");
    }

    #[test]
    fn round_trip_sizes() {
        for n in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 17] {
            let pt: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
            let (ct, fk) = encrypt(&pt).unwrap();
            assert_eq!(ct.len() as u64, ciphertext_len(n as u64), "n={n}");
            assert_eq!(decrypt(&ct, &fk).unwrap(), pt, "n={n}");
        }
    }

    #[test]
    fn fresh_key_and_nonce_each_time() {
        let (c1, k1) = encrypt(b"same").unwrap();
        let (c2, k2) = encrypt(b"same").unwrap();
        assert_ne!(c1, c2);
        assert_ne!(*k1.key, *k2.key);
        assert_ne!(k1.nonce_prefix, k2.nonce_prefix);
        assert_eq!(k1.plaintext_sha256, k2.plaintext_sha256);
        assert!(!format!("{k1:?}").contains(&format!("{:?}", &k1.key[..4])), "Debug hides the key");
    }

    #[test]
    fn tampering_detected() {
        let pt = vec![5u8; 2 * CHUNK + 10];
        let (ct, fk) = encrypt(&pt).unwrap();
        // flipped byte, truncation, extension, dropped chunk, swapped chunks
        let mut flipped = ct.clone();
        flipped[CHUNK + 3] ^= 1;
        let n = CHUNK + TAG;
        let swapped = [&ct[n..2 * n], &ct[..n], &ct[2 * n..]].concat();
        for bad in [flipped, ct[..ct.len() - 1].to_vec(), [&ct[..], &[0]].concat(), ct[n..].to_vec(), swapped] {
            assert!(decrypt(&bad, &fk).is_err());
        }
        // Even with the hashes adjusted to the tampered ciphertext, STREAM
        // still refuses reordered chunks.
        let swapped = [&ct[n..2 * n], &ct[..n], &ct[2 * n..]].concat();
        let fk2 = FileKey { ciphertext_sha256: Sha256::digest(&swapped).into(), ..fk.clone() };
        assert!(decrypt(&swapped, &fk2).is_err());
        // A truncation that ends on a chunk boundary is caught by the last flag.
        let cut = ct[..2 * n].to_vec();
        let fk3 = FileKey { size: 2 * CHUNK as u64, ciphertext_sha256: Sha256::digest(&cut).into(), ..fk.clone() };
        assert!(decrypt(&cut, &fk3).is_err());
    }

    /// The design's "not yet run" test: one file must not open to different
    /// content under two keys. Hashes in the message bind the content.
    #[test]
    fn key_commitment() {
        let (ct, fk) = encrypt(b"the real picture").unwrap();
        let wrong_key = FileKey { key: Zeroizing::new([9; 32]), ..fk.clone() };
        assert!(decrypt(&ct, &wrong_key).is_err());
        let other_content = FileKey { plaintext_sha256: Sha256::digest(b"another picture").into(), ..fk.clone() };
        assert!(decrypt(&ct, &other_content).is_err());
        let wrong_size = FileKey { size: fk.size + 1, ..fk.clone() };
        assert!(decrypt(&ct, &wrong_size).is_err());
        assert_eq!(decrypt(&ct, &fk).unwrap(), b"the real picture");
    }
}
