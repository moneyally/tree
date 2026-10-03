//! Versioned cryptographic profile negotiation.
//!
//! Tree keeps the protocol contract separate from the concrete MLS
//! ciphersuite so future PQC migrations cannot silently downgrade an existing
//! conversation. Unsupported algorithms are represented explicitly and are
//! never advertised as active.
//!
//! v5 target:
//!   bootstrap/reset: ML-KEM-768 + HQC-192 + X25519
//!   normal refresh:  ML-KEM-768 + X25519
//!   device signature: ML-DSA-65
//!   root identity: SLH-DSA
//!
//! The current production implementation remains the OpenMLS
//! ML-KEM-768 + X25519 suite with Ed25519. HQC/ML-DSA/SLH-DSA are contract
//! entries until an audited implementation and interoperability tests are
//! available.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::TreeError;

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum KemAlgorithm {
    X25519 = 0x0101,
    MlKem768 = 0x0201,
    Hqc192 = 0x0301,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum SignatureAlgorithm {
    Ed25519 = 0x0101,
    MlDsa65 = 0x0201,
    SlhDsa = 0x0301,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMode {
    Triple,
    CurrentMls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshMode {
    Double,
    CurrentMls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoProfile {
    pub version: u16,
    pub bootstrap: Vec<KemAlgorithm>,
    pub refresh: Vec<KemAlgorithm>,
    pub device_signature: SignatureAlgorithm,
    pub root_signature: SignatureAlgorithm,
}

impl CryptoProfile {
    pub fn current() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            bootstrap: vec![KemAlgorithm::MlKem768, KemAlgorithm::X25519],
            refresh: vec![KemAlgorithm::MlKem768, KemAlgorithm::X25519],
            device_signature: SignatureAlgorithm::Ed25519,
            root_signature: SignatureAlgorithm::Ed25519,
        }
    }

    pub fn v5_target() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            bootstrap: vec![
                KemAlgorithm::MlKem768,
                KemAlgorithm::Hqc192,
                KemAlgorithm::X25519,
            ],
            refresh: vec![KemAlgorithm::MlKem768, KemAlgorithm::X25519],
            device_signature: SignatureAlgorithm::MlDsa65,
            root_signature: SignatureAlgorithm::SlhDsa,
        }
    }

    pub fn bootstrap_mode(&self) -> BootstrapMode {
        if self.bootstrap == [KemAlgorithm::MlKem768, KemAlgorithm::X25519] {
            BootstrapMode::CurrentMls
        } else {
            BootstrapMode::Triple
        }
    }

    pub fn refresh_mode(&self) -> RefreshMode {
        if self.refresh == [KemAlgorithm::MlKem768, KemAlgorithm::X25519] {
            RefreshMode::Double
        } else {
            RefreshMode::CurrentMls
        }
    }

    pub fn is_supported_by_current_core(&self) -> bool {
        let current = Self::current();
        self == &current
    }

    /// Canonical bytes bound into the handshake transcript.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 2 * (self.bootstrap.len() + self.refresh.len()) + 6);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.bootstrap.len() as u8);
        for alg in &self.bootstrap {
            out.extend_from_slice(&(*alg as u16).to_be_bytes());
        }
        out.push(self.refresh.len() as u8);
        for alg in &self.refresh {
            out.extend_from_slice(&(*alg as u16).to_be_bytes());
        }
        out.extend_from_slice(&(self.device_signature as u16).to_be_bytes());
        out.extend_from_slice(&(self.root_signature as u16).to_be_bytes());
        out
    }

    pub fn profile_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"tree/crypto-profile/v1");
        h.update(self.canonical_bytes());
        h.finalize().into()
    }
}

/// Negotiates one exact profile, never a weaker subset.
///
/// The caller supplies an ordered list from strongest/preferred to weakest.
/// A target profile can only be selected if the exact profile is supported
/// locally; there is no silent downgrade from a triple profile to a double
/// profile.
pub fn negotiate(
    local: &[CryptoProfile],
    remote: &[CryptoProfile],
) -> Result<CryptoProfile, TreeError> {
    for candidate in local {
        if remote.iter().any(|p| p == candidate) && candidate.is_supported_by_current_core() {
            return Ok(candidate.clone());
        }
    }
    Err(TreeError::UnsupportedCiphersuite)
}

/// Derives one symmetric root from all supplied KEM secrets and the exact
/// profile/transcript. The returned buffer is zeroized when dropped.
///
/// This function combines already-established secrets; it does not implement
/// any KEM itself.
pub fn combine_secrets(
    profile: &CryptoProfile,
    transcript: &[u8],
    secrets: &[&[u8]],
) -> Result<Zeroizing<[u8; 32]>, TreeError> {
    if secrets.is_empty() {
        return Err(TreeError::Identity("hybrid secret set is empty".into()));
    }

    let mut ikm = Zeroizing::new(Vec::new());
    for secret in secrets {
        if secret.is_empty() {
            return Err(TreeError::Identity("hybrid secret is empty".into()));
        }
        ikm.extend_from_slice(secret);
    }

    let mut salt = Sha256::new();
    salt.update(b"tree/crypto-profile-salt/v1");
    salt.update(profile.canonical_bytes());
    salt.update(transcript);

    let hk = Hkdf::<Sha256>::new(Some(&salt.finalize()), &ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(b"tree/hybrid-root/v1", out.as_mut())
        .map_err(|_| TreeError::Identity("hybrid HKDF expansion failed".into()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v5_target_is_triple_bootstrap_and_double_refresh() {
        let p = CryptoProfile::v5_target();
        assert_eq!(p.bootstrap_mode(), BootstrapMode::Triple);
        assert_eq!(p.refresh_mode(), RefreshMode::Double);
        assert!(p.bootstrap.contains(&KemAlgorithm::Hqc192));
        assert_eq!(p.device_signature, SignatureAlgorithm::MlDsa65);
        assert_eq!(p.root_signature, SignatureAlgorithm::SlhDsa);
    }

    #[test]
    fn negotiation_rejects_downgrade_to_current_profile_when_target_is_required() {
        let target = CryptoProfile::v5_target();
        let current = CryptoProfile::current();
        assert_ne!(target, current);
        assert!(negotiate(
            std::slice::from_ref(&target),
            std::slice::from_ref(&current)
        )
        .is_err());
    }

    #[test]
    fn exact_profile_id_changes_on_any_algorithm_change() {
        let a = CryptoProfile::current();
        let mut b = a.clone();
        b.bootstrap.reverse();
        assert_ne!(a.profile_id(), b.profile_id());
    }

    #[test]
    fn combining_three_secrets_binds_profile_and_transcript() {
        let p = CryptoProfile::v5_target();
        let a = combine_secrets(&p, b"transcript-a", &[b"a", b"b", b"c"]).unwrap();
        let b = combine_secrets(&p, b"transcript-a", &[b"a", b"b", b"c"]).unwrap();
        let c = combine_secrets(&p, b"transcript-b", &[b"a", b"b", b"c"]).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn empty_secret_is_rejected() {
        assert!(combine_secrets(&CryptoProfile::current(), b"x", &[b""]).is_err());
    }
}
