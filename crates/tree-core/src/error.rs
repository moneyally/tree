use thiserror::Error;

/// Errors surfaced by the Tree core.
///
/// Messages are kept free of key material and plaintext so they are safe to log.
#[derive(Debug, Error)]
pub enum TreeError {
    #[error("crypto provider does not support the requested ciphersuite")]
    UnsupportedCiphersuite,
    #[error("could not create identity: {0}")]
    Identity(String),
    #[error("malformed input: {0}")]
    Malformed(String),
    #[error("key package rejected: {0}")]
    InvalidKeyPackage(String),
    #[error("group operation failed: {0}")]
    Group(String),
    #[error("message rejected: {0}")]
    Rejected(String),
    #[error("no member named {0:?} in this group")]
    UnknownMember(String),
    #[error("this device is no longer a member of the group")]
    NotAMember,
    #[error("no stored group with this id")]
    NoSuchGroup,
    #[error("passphrase must not be empty")]
    EmptyPassphrase,
    /// Wrong passphrase, or the database file was damaged or modified.
    /// (The two cannot be told apart: both fail page authentication.)
    #[error("wrong passphrase, or the database is damaged")]
    WrongKey,
    #[error("local storage: {0}")]
    Storage(String),
}

pub(crate) fn group_err(e: impl std::fmt::Debug) -> TreeError {
    TreeError::Group(format!("{e:?}"))
}
