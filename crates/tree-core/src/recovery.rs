//! Account recovery primitive.
//!
//! The mnemonic is a BIP-39 encoding of 256 bits generated locally by the
//! operating system. Tree does not use BIP-39's optional passphrase for
//! security; the 256-bit entropy is the recovery secret itself.
//!
//! A recovery authentication key is derived with standard HKDF-SHA256 using
//! a Tree-specific domain label. The resulting 32 bytes are used as an
//! Ed25519 secret key seed. The server sees only the derived public key.

use bip39::Mnemonic;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::TreeError;

const RECOVERY_AUTH_INFO: &[u8] = b"tree/recovery-auth/ed25519/v1";
const ENTROPY_BYTES: usize = 32;

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryPhrase {
    entropy: [u8; ENTROPY_BYTES],
    phrase: String,
}

impl Drop for RecoveryPhrase {
    fn drop(&mut self) {
        self.entropy.zeroize();
        self.phrase.zeroize();
    }
}

impl RecoveryPhrase {
    /// Generate a new 24-word English recovery phrase from 256 bits of OS
    /// randomness.
    pub fn generate() -> Result<Self, TreeError> {
        let mut entropy = [0u8; ENTROPY_BYTES];
        getrandom::fill(&mut entropy)
            .map_err(|e| TreeError::Identity(format!("OS randomness unavailable: {e}")))?;
        Self::from_entropy_bytes(entropy)
    }

    pub fn from_phrase(phrase: &str) -> Result<Self, TreeError> {
        let mnemonic = Mnemonic::parse(phrase)
            .map_err(|_| TreeError::Identity("invalid recovery phrase".into()))?;
        if mnemonic.word_count() != 24 {
            return Err(TreeError::Identity(
                "Tree recovery phrases must contain 24 words".into(),
            ));
        }
        let entropy_vec = mnemonic.to_entropy();
        let entropy: [u8; ENTROPY_BYTES] = entropy_vec
            .try_into()
            .map_err(|_| TreeError::Identity("recovery entropy has wrong size".into()))?;
        Ok(Self {
            entropy,
            phrase: mnemonic.to_string(),
        })
    }

    pub(crate) fn from_entropy_bytes(entropy: [u8; ENTROPY_BYTES]) -> Result<Self, TreeError> {
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|_| TreeError::Identity("could not encode recovery entropy".into()))?;
        Ok(Self {
            entropy,
            phrase: mnemonic.to_string(),
        })
    }

    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    pub(crate) fn entropy_bytes(&self) -> [u8; ENTROPY_BYTES] {
        self.entropy
    }

    /// Derives the deterministic Ed25519 key used only for recovery.
    pub fn recovery_signing_key(&self) -> SigningKey {
        let hk = Hkdf::<Sha256>::new(None, &self.entropy);
        let mut seed = Zeroizing::new([0u8; 32]);
        hk.expand(RECOVERY_AUTH_INFO, seed.as_mut())
            .expect("32-byte HKDF output is always valid");
        SigningKey::from_bytes(&seed)
    }

    pub fn recovery_public_key(&self) -> [u8; 32] {
        self.recovery_signing_key().verifying_key().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_phrase_round_trips_to_the_same_recovery_key() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let parsed = RecoveryPhrase::from_phrase(phrase.phrase()).unwrap();
        assert_eq!(
            phrase.recovery_public_key(),
            parsed.recovery_public_key()
        );
        assert_eq!(phrase.phrase(), parsed.phrase());
    }

    #[test]
    fn twelve_words_are_rejected() {
        let entropy = [0u8; 16];
        let phrase = Mnemonic::from_entropy(&entropy).unwrap().to_string();
        assert!(RecoveryPhrase::from_phrase(&phrase).is_err());
    }

    #[test]
    fn invalid_checksum_is_rejected() {
        let phrase = RecoveryPhrase::from_phrase(
            &Mnemonic::from_entropy(&[1u8; 32]).unwrap().to_string()
        )
        .unwrap();
        let mut words: Vec<&str> = phrase.phrase().split_whitespace().collect();
        words[23] = "abandon";
        assert!(RecoveryPhrase::from_phrase(&words.join(" ")).is_err());
    }
}
