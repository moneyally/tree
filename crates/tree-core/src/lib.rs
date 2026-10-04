//! Tree messenger core.
//!
//! All application logic lives here; apps only draw screens.

pub mod bot_lane;
pub mod client;
pub mod crypto_profile;
pub mod error;
pub mod features;
pub mod file;
pub mod group;
mod group_state;
pub mod identity;
pub mod media;
pub mod media_editor;
pub mod message;
pub mod message_state;
pub mod messenger_store;
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
pub use messenger_store::{OutboxItem, OutboxState, StoredMessage};
pub use provider::TreeProvider;
pub use recovery::RecoveryPhrase;
pub use storage::{KdfParams, KeySource, Passphrase, StoredProvider};

use openmls::prelude::Ciphersuite;

#[cfg(feature = "pq")]
pub const TREE_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519;

#[cfg(not(feature = "pq"))]
pub const TREE_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

pub type DefaultProvider = openmls_rust_crypto::OpenMlsRustCrypto;
pub type LibcruxProvider = openmls_libcrux_crypto::Provider;
pub mod safety;
