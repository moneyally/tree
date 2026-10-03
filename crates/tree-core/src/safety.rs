//! Persistent peer safety-key state.
//!
//! The server does not need to know whether a user verified a peer. This
//! state lives inside the encrypted SQLCipher profile. A key change is always
//! surfaced by the core; the UI cannot disable the underlying comparison.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::TreeError;
use crate::provider::TreeProvider;

const META_SAFETY_KEYS: &str = "safety_keys_v1";
const VERSION: u8 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct StoredPeer {
    fingerprint: String,
    verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DiskState {
    version: u8,
    peers: BTreeMap<String, StoredPeer>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyObservation {
    FirstSeen {
        fingerprint: [u8; 32],
    },
    Unchanged {
        fingerprint: [u8; 32],
        verified: bool,
    },
    Changed {
        previous: [u8; 32],
        current: [u8; 32],
        was_verified: bool,
    },
}

fn fingerprint_hex(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_fingerprint(s: &str) -> Result<[u8; 32], TreeError> {
    if s.len() != 64 {
        return Err(TreeError::Storage(
            "stored safety fingerprint has wrong size".into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0]).ok_or_else(|| {
            TreeError::Storage("stored safety fingerprint is damaged".into())
        })?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| {
            TreeError::Storage("stored safety fingerprint is damaged".into())
        })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn load<P: TreeProvider>(provider: &P) -> Result<BTreeMap<String, StoredPeer>, TreeError> {
    let Some(bytes) = provider.meta_optional(META_SAFETY_KEYS)? else {
        return Ok(BTreeMap::new());
    };
    let disk: DiskState = serde_json::from_slice(&bytes)
        .map_err(|_| TreeError::Storage("safety key state is damaged".into()))?;
    if disk.version != VERSION {
        return Err(TreeError::Storage("unsupported safety key state version".into()));
    }
    Ok(disk.peers)
}

fn save<P: TreeProvider>(
    provider: &P,
    peers: &BTreeMap<String, StoredPeer>,
) -> Result<(), TreeError> {
    let disk = DiskState {
        version: VERSION,
        peers: peers.clone(),
    };
    let bytes = serde_json::to_vec(&disk)
        .map_err(|_| TreeError::Storage("could not serialize safety key state".into()))?;
    provider.put_meta(META_SAFETY_KEYS, &bytes)
}

pub fn observe<P: TreeProvider>(
    provider: &P,
    peer_id: &str,
    signature_public_key: &[u8],
) -> Result<KeyObservation, TreeError> {
    if peer_id.is_empty() || peer_id.len() > 128 {
        return Err(TreeError::Identity("invalid peer id".into()));
    }
    let fingerprint = crate::identity::safety_fingerprint(signature_public_key);
    let mut peers = load(provider)?;

    let result = match peers.get(peer_id) {
        None => KeyObservation::FirstSeen { fingerprint },
        Some(previous) => {
            let prior = parse_fingerprint(&previous.fingerprint)?;
            if prior == fingerprint {
                KeyObservation::Unchanged {
                    fingerprint,
                    verified: previous.verified,
                }
            } else {
                KeyObservation::Changed {
                    previous: prior,
                    current: fingerprint,
                    was_verified: previous.verified,
                }
            }
        }
    };

    let verified = match result {
        KeyObservation::Unchanged { verified, .. } => verified,
        _ => false,
    };

    peers.insert(
        peer_id.to_owned(),
        StoredPeer {
            fingerprint: fingerprint_hex(&fingerprint),
            verified,
        },
    );
    save(provider, &peers)?;

    Ok(result)
}

pub fn verify<P: TreeProvider>(
    provider: &P,
    peer_id: &str,
    expected: &[u8; 32],
) -> Result<(), TreeError> {
    let mut peers = load(provider)?;
    let entry = peers
        .get_mut(peer_id)
        .ok_or_else(|| TreeError::Identity("peer key has not been observed".into()))?;
    let current = parse_fingerprint(&entry.fingerprint)?;
    if &current != expected {
        return Err(TreeError::Identity("fingerprint mismatch".into()));
    }
    entry.verified = true;
    save(provider, &peers)
}

pub fn forget<P: TreeProvider>(provider: &P, peer_id: &str) -> Result<(), TreeError> {
    let mut peers = load(provider)?;
    peers.remove(peer_id);
    save(provider, &peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;

    #[test]
    fn first_seen_then_unchanged_then_changed() {
        let client = Client::new("alice").unwrap();
        let first = observe(&client.provider, "bob:device1", &[1u8; 32]).unwrap();
        assert!(matches!(first, KeyObservation::FirstSeen { .. }));

        let same = observe(&client.provider, "bob:device1", &[1u8; 32]).unwrap();
        assert!(matches!(
            same,
            KeyObservation::Unchanged { verified: false, .. }
        ));

        let fp = match same {
            KeyObservation::Unchanged { fingerprint, .. } => fingerprint,
            _ => unreachable!(),
        };
        verify(&client.provider, "bob:device1", &fp).unwrap();

        let same_verified = observe(&client.provider, "bob:device1", &[1u8; 32]).unwrap();
        assert!(matches!(
            same_verified,
            KeyObservation::Unchanged { verified: true, .. }
        ));

        let changed = observe(&client.provider, "bob:device1", &[2u8; 32]).unwrap();
        assert!(matches!(
            changed,
            KeyObservation::Changed {
                was_verified: true,
                ..
            }
        ));
    }

    #[test]
    fn verification_requires_exact_fingerprint() {
        let client = Client::new("alice").unwrap();
        observe(&client.provider, "bob:device1", &[1u8; 32]).unwrap();
        assert!(verify(&client.provider, "bob:device1", &[2u8; 32]).is_err());
    }
}
