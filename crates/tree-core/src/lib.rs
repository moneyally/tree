//! Tree messenger core.
//!
//! All application logic lives here; apps only draw screens.
//!
//! * [`client`] — a device identity: signing key, credential, key packages.
//! * [`group`]  — an end-to-end encrypted conversation (1:1 is a two-member group).
//! * [`features`] — the feature registry: every feature has apply/release.
//! * [`storage`] — the encrypted on-device database (SQLCipher) that keeps
//!   identity and groups across restarts.
//!
//! Wire formats are plain bytes so that any transport (server mailbox,
//! file, QR code) can carry them.

pub mod bot_lane;
pub mod client;
pub mod crypto_profile;
pub mod error;
pub mod features;
pub mod file;
pub mod group;
mod group_state;
pub mod identity;
pub mod message;
pub mod message_state;
pub mod provider;
pub mod recovery;
pub mod storage;
pub mod user_features;

pub use bot_lane::{BotLaneDescriptor, BotLaneEvent, BotLaneMode};
pub use client::Client;
pub use crypto_profile::{
    combine_secrets, negotiate as negotiate_crypto_profile, CryptoProfile, KemAlgorithm,
    SignatureAlgorithm,
};
pub use error::TreeError;
pub use file::{decrypt as decrypt_file, encrypt as encrypt_file, EncryptedFile, FileKey};
pub use group::{Group, Incoming, Member, MemberId, PendingCommit};
pub use identity::{fingerprint_hex, normalize_username, safety_fingerprint, username_hash};
pub use message::{MessageEvent, MessageId, MessageKind, DEFAULT_EDIT_WINDOW_SECS};
pub use provider::TreeProvider;
pub use recovery::RecoveryPhrase;
pub use storage::{KdfParams, KeySource, Passphrase, StoredProvider};

use openmls::prelude::Ciphersuite;

/// Default ciphersuite.
///
/// With the `pq` feature (default) this is the IETF draft hybrid suite
/// ML-KEM-768 + X25519 with AES-256-GCM / SHA-384 / Ed25519, so key exchange
/// stays safe as long as either ML-KEM or X25519 holds, and all symmetric
/// keys are 256-bit. The draft code point is provisional, so the suite is
/// always negotiated, never assumed.
#[cfg(feature = "pq")]
pub const TREE_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519;

/// Classical fallback when built without the `pq` feature.
#[cfg(not(feature = "pq"))]
pub const TREE_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// Crypto provider used by default (RustCrypto primitives), in memory only.
/// For state that survives restarts see [`Client::create`] / [`Client::open`].
pub type DefaultProvider = openmls_rust_crypto::OpenMlsRustCrypto;

/// Alternative provider built on formally verified libcrux primitives.
/// Supports the X-Wing hybrid suite under the `pq` feature.
pub type LibcruxProvider = openmls_libcrux_crypto::Provider;

pub mod safety;