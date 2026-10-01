//! Recovery phrase and account recovery key (docs/RECOVERY_THREAT_MODEL.md 2.2,
//! PROTOCOL.md 8.6).
//!
//! The phrase is BIP-39: 128 to 256 bits from the system random generator,
//! encoded as 12 to 24 words with a checksum, in English or Korean (the two
//! standard word lists Tree offers). It never leaves the device that shows
//! it and is never stored by Tree.
//!
//! The only key derived from it so far is the account recovery key:
//!
//! ```text
//! seed = HKDF-SHA-256(salt = "tree/recovery/v1", ikm = BIP-39 entropy,
//!                     info = "account-recovery-key", L = 32)
//! recovery key = Ed25519 key pair from seed
//! ```
//!
//! The server keeps the public key with the account. A new device proves
//! the phrase by signing `"tree-recover-v1" || its request key || flags` with
//! the recovery key. The entropy itself (not the BIP-39 PBKDF2 seed) is the
//! HKDF input: it is already uniformly random, so a slow KDF adds nothing.
//! Recovery never restores MLS state: the new device is a new member that
//! contacts see as a key change.

use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::TreeError;

const SALT: &[u8] = b"tree/recovery/v1";
const INFO_ACCOUNT: &[u8] = b"account-recovery-key";
/// Context of the recovery signature (PROTOCOL.md 8.6).
pub const RECOVER_CONTEXT: &[u8] = b"tree-recover-v1";
/// Proof of holding a new recovery key.
pub const SET_CONTEXT: &[u8] = b"tree-recovery-set-v1";
/// The current key agrees to a replacement or release.
pub const CHANGE_CONTEXT: &[u8] = b"tree-recovery-change-v1";

/// Word list of a new phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Words {
    English,
    Korean,
}

impl Words {
    fn language(self) -> Language {
        match self {
            Words::English => Language::English,
            Words::Korean => Language::Korean,
        }
    }
}

/// A recovery phrase. Shown once to the user; never stored.
pub struct Phrase {
    text: Zeroizing<String>,
    entropy: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Phrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Phrase(..)")
    }
}

impl Phrase {
    /// A new phrase of `words` words (12, 15, 18, 21 or 24; 24 recommended).
    pub fn generate(words: usize, list: Words) -> Result<Self, TreeError> {
        if !matches!(words, 12 | 15 | 18 | 21 | 24) {
            return Err(TreeError::InvalidPhrase("12, 15, 18, 21 or 24 words".into()));
        }
        let mut entropy = Zeroizing::new(vec![0u8; words / 3 * 4]);
        getrandom::getrandom(&mut entropy).expect("operating system random number generator failed");
        let m = Mnemonic::from_entropy_in(list.language(), &entropy).map_err(|e| TreeError::InvalidPhrase(e.to_string()))?;
        Ok(Self { text: Zeroizing::new(m.to_string()), entropy })
    }

    /// Reads a phrase the user typed: English or Korean, any spacing, the
    /// checksum must match.
    pub fn parse(s: &str) -> Result<Self, TreeError> {
        let joined = Zeroizing::new(s.split_whitespace().collect::<Vec<_>>().join(" "));
        let m = Mnemonic::parse(joined.as_str()).map_err(|e| TreeError::InvalidPhrase(e.to_string()))?;
        if m.word_count() < 12 {
            return Err(TreeError::InvalidPhrase("at least 12 words".into()));
        }
        Ok(Self { text: Zeroizing::new(m.to_string()), entropy: Zeroizing::new(m.to_entropy()) })
    }

    /// The words, separated by single spaces.
    pub fn words(&self) -> &str {
        &self.text
    }

    /// The account recovery key.
    pub fn recovery_key(&self) -> RecoveryKey {
        let mut seed = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(SALT), &self.entropy)
            .expand(INFO_ACCOUNT, seed.as_mut())
            .expect("32 bytes is a valid HKDF-SHA-256 length");
        RecoveryKey(SigningKey::from_bytes(&seed))
    }
}

/// The Ed25519 key that proves the phrase to the server.
pub struct RecoveryKey(SigningKey);

impl RecoveryKey {
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs a recovery request for a new device's request key at time `ts`.
    pub fn sign_recovery(&self, auth_pub: &[u8; 32], revoke_others: bool, ts: i64) -> [u8; 64] {
        self.0.sign(&recovery_message(auth_pub, revoke_others, ts)).to_bytes()
    }

    /// Proof that this (new) key is held, for `account`.
    pub fn sign_set(&self, account: &str) -> [u8; 64] {
        self.0.sign(&change_message(SET_CONTEXT, account, &self.public_key())).to_bytes()
    }

    /// This (current) key agrees to replace it with `new`, or to release
    /// recovery (`None`).
    pub fn sign_change(&self, account: &str, new: Option<&[u8; 32]>) -> [u8; 64] {
        self.0.sign(&change_message(CHANGE_CONTEXT, account, new.unwrap_or(&[0; 32]))).to_bytes()
    }
}

/// `"tree-recover-v1" || auth_pub || revoke_others (1 byte) || ts (8 bytes BE)`.
pub fn recovery_message(auth_pub: &[u8; 32], revoke_others: bool, ts: i64) -> Vec<u8> {
    let mut m = Vec::with_capacity(RECOVER_CONTEXT.len() + 41);
    m.extend_from_slice(RECOVER_CONTEXT);
    m.extend_from_slice(auth_pub);
    m.push(u8::from(revoke_others));
    m.extend_from_slice(&ts.to_be_bytes());
    m
}

/// `context || u32(len(account)) || account || key`.
pub fn change_message(context: &[u8], account: &str, key: &[u8; 32]) -> Vec<u8> {
    let mut m = context.to_vec();
    m.extend_from_slice(&(account.len() as u32).to_be_bytes());
    m.extend_from_slice(account.as_bytes());
    m.extend_from_slice(key);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn generate_parse_and_derive() {
        for (n, list) in [(12, Words::English), (24, Words::English), (24, Words::Korean), (18, Words::Korean)] {
            let p = Phrase::generate(n, list).unwrap();
            assert_eq!(p.words().split(' ').count(), n);
            // typed back with odd spacing
            let typed = format!("  {}\n", p.words().replace(' ', "   "));
            let q = Phrase::parse(&typed).unwrap();
            assert_eq!(q.words(), p.words());
            assert_eq!(p.recovery_key().public_key(), q.recovery_key().public_key());
        }
        let a = Phrase::generate(24, Words::English).unwrap();
        let b = Phrase::generate(24, Words::English).unwrap();
        assert_ne!(a.words(), b.words());
        assert_ne!(a.recovery_key().public_key(), b.recovery_key().public_key());
        for bad in [0, 11, 13, 25, 48] {
            assert!(Phrase::generate(bad, Words::English).is_err(), "{bad}");
        }
        assert_eq!(format!("{a:?}"), "Phrase(..)", "never printed by Debug");
    }

    #[test]
    fn checksum_and_word_list_are_checked() {
        let p = Phrase::generate(12, Words::English).unwrap();
        let mut words: Vec<&str> = p.words().split(' ').collect();
        // swapping two different words breaks the checksum (almost always;
        // pick a pair that differs)
        let j = (1..12).find(|&j| words[j] != words[0]).unwrap();
        words.swap(0, j);
        let swapped = words.join(" ");
        assert!(Phrase::parse(&swapped).is_err() || Phrase::parse(&swapped).unwrap().words() != p.words());
        assert!(Phrase::parse("not a phrase at all").is_err());
        assert!(Phrase::parse("").is_err());
        // 3 words of a valid list are too short for an account
        assert!(Phrase::parse("abandon abandon about").is_err());
    }

    /// Fixed vector: the BIP-39 test phrase "abandon ... about" (entropy all
    /// zero) gives a fixed recovery key, so the derivation cannot change
    /// unnoticed.
    #[test]
    fn derivation_vector() {
        let p = Phrase::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut seed = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"tree/recovery/v1"), &[0u8; 16]).expand(b"account-recovery-key", &mut seed).unwrap();
        let want = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(p.recovery_key().public_key(), want);
        assert_eq!(hex(&want), RECOVERY_PUB_VECTOR);
    }

    /// Checked independently with Python's hmac/hashlib (HKDF) and the
    /// `cryptography` package (Ed25519).
    const RECOVERY_PUB_VECTOR: &str = "c5dda56a7105f6429ee484c58047cff5f59701f7ebb53a95d9f899597a02efed";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn signature_binds_key_and_flag() {
        let k = Phrase::generate(12, Words::English).unwrap().recovery_key();
        let auth = [7u8; 32];
        let sig = Signature::from_bytes(&k.sign_recovery(&auth, true, 100));
        let vk = VerifyingKey::from_bytes(&k.public_key()).unwrap();
        assert!(vk.verify(&recovery_message(&auth, true, 100), &sig).is_ok());
        assert!(vk.verify(&recovery_message(&auth, false, 100), &sig).is_err());
        assert!(vk.verify(&recovery_message(&auth, true, 101), &sig).is_err());
        assert!(vk.verify(&recovery_message(&[8; 32], true, 100), &sig).is_err());
        assert_eq!(&recovery_message(&auth, true, 0)[..15], b"tree-recover-v1");
        let set = Signature::from_bytes(&k.sign_set("acc"));
        assert!(vk.verify(&change_message(SET_CONTEXT, "acc", &k.public_key()), &set).is_ok());
        assert!(vk.verify(&change_message(SET_CONTEXT, "acd", &k.public_key()), &set).is_err());
        let rel = Signature::from_bytes(&k.sign_change("acc", None));
        assert!(vk.verify(&change_message(CHANGE_CONTEXT, "acc", &[0; 32]), &rel).is_ok());
        assert!(vk.verify(&change_message(SET_CONTEXT, "acc", &[0; 32]), &rel).is_err(), "contexts differ");
    }
}
