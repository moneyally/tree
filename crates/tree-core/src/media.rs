//! End-to-end media lifecycle primitives.
//!
//! This module is UI-independent. It defines the authenticated attachment
//! manifest, per-file key/manifest commitments, chunk encryption,
//! encrypted previews, and the client-side view/expiry state machine.
//!
//! UI animation consumes MediaViewState; it is never part of a security decision.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::TreeError;
use crate::message::MessageId;

pub const MEDIA_VERSION: u8 = 1;
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
pub const MAX_CHUNKS: u32 = 65_535;
const KEY_LEN: usize = 32;
const BASE_NONCE_LEN: usize = 8;
const NONCE_LEN: usize = 12;
const ATTACHMENT_ID_LEN: usize = 16;
const MAX_GROUP_ID: usize = 128;
const MAX_FILENAME: usize = 255;
const MAX_MIME: usize = 127;
const MAX_MEDIA_TYPE: usize = 32;
const MAX_MANIFEST: usize = 16 * 1024;
const MAX_PREVIEW: usize = 256 * 1024;
const DOMAIN: &[u8] = b"tree-media-v1";
const CHUNK_DOMAIN: &[u8] = b"tree-media-chunk-v1";
const PREVIEW_DOMAIN: &[u8] = b"tree-media-preview-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaKey(Zeroizing<[u8; KEY_LEN]>);

impl MediaKey {
    pub fn generate() -> Result<Self, TreeError> {
        let mut key = [0u8; KEY_LEN];
        getrandom::fill(&mut key)
            .map_err(|e| TreeError::FileCrypto(format!("OS randomness unavailable: {e}")))?;
        Ok(Self(Zeroizing::new(key)))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TreeError> {
        let key: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| TreeError::FileCrypto("media key must be 32 bytes".into()))?;
        Ok(Self(Zeroizing::new(key)))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for MediaKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewPolicy {
    Persistent,
    Timed { seconds: u32 },
    ViewOnce,
}

impl ViewPolicy {
    pub fn ttl_seconds(self) -> Option<u32> {
        match self {
            Self::Persistent => None,
            Self::Timed { seconds } => Some(seconds),
            Self::ViewOnce => Some(0),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreviewMode {
    None,
    Blurred,
    LowResolution,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaManifest {
    pub attachment_id: [u8; ATTACHMENT_ID_LEN],
    pub message_id: MessageId,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub media_type: String,
    pub filename: String,
    pub mime: String,
    pub plaintext_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub preview_mode: PreviewMode,
    pub view_policy: ViewPolicy,
    pub base_nonce: [u8; BASE_NONCE_LEN],
}

impl MediaManifest {
    pub fn generate(
        message_id: MessageId,
        group_id: &[u8],
        epoch: u64,
        media_type: &str,
        filename: &str,
        mime: &str,
        plaintext_size: u64,
        view_policy: ViewPolicy,
        preview_mode: PreviewMode,
    ) -> Result<(Self, MediaKey), TreeError> {
        if group_id.is_empty() || group_id.len() > MAX_GROUP_ID {
            return Err(TreeError::FileCrypto("group id length is invalid".into()));
        }
        if media_type.is_empty() || media_type.len() > MAX_MEDIA_TYPE || !media_type.is_ascii() {
            return Err(TreeError::FileCrypto("media type is invalid".into()));
        }
        if filename.is_empty() || filename.len() > MAX_FILENAME {
            return Err(TreeError::FileCrypto("filename length is invalid".into()));
        }
        if mime.is_empty() || mime.len() > MAX_MIME || !mime.is_ascii() {
            return Err(TreeError::FileCrypto("mime type is invalid".into()));
        }
        if plaintext_size == 0 {
            return Err(TreeError::FileCrypto("media cannot be empty".into()));
        }
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let chunk_count = u32::try_from(plaintext_size.div_ceil(chunk_size as u64))
            .map_err(|_| TreeError::FileCrypto("media has too many chunks".into()))?;
        if chunk_count == 0 || chunk_count > MAX_CHUNKS {
            return Err(TreeError::FileCrypto("media chunk count is invalid".into()));
        }
        let mut attachment_id = [0u8; ATTACHMENT_ID_LEN];
        getrandom::fill(&mut attachment_id)
            .map_err(|e| TreeError::FileCrypto(format!("OS randomness unavailable: {e}")))?;
        let mut base_nonce = [0u8; BASE_NONCE_LEN];
        getrandom::fill(&mut base_nonce)
            .map_err(|e| TreeError::FileCrypto(format!("OS randomness unavailable: {e}")))?;
        let manifest = Self {
            attachment_id,
            message_id,
            group_id: group_id.to_vec(),
            epoch,
            media_type: media_type.to_string(),
            filename: filename.to_string(),
            mime: mime.to_string(),
            plaintext_size,
            chunk_size,
            chunk_count,
            preview_mode,
            view_policy,
            base_nonce,
        };
        manifest.validate()?;
        Ok((manifest, MediaKey::generate()?))
    }

    pub fn validate(&self) -> Result<(), TreeError> {
        if self.group_id.is_empty()
            || self.group_id.len() > MAX_GROUP_ID
            || self.media_type.is_empty()
            || self.media_type.len() > MAX_MEDIA_TYPE
            || !self.media_type.is_ascii()
            || self.filename.is_empty()
            || self.filename.len() > MAX_FILENAME
            || self.mime.is_empty()
            || self.mime.len() > MAX_MIME
            || !self.mime.is_ascii()
            || self.chunk_size == 0
            || self.chunk_size > MAX_CHUNK_SIZE
            || self.chunk_count == 0
            || self.chunk_count > MAX_CHUNKS
        {
            return Err(TreeError::FileCrypto("invalid media manifest".into()));
        }
        let expected = self.plaintext_size.div_ceil(self.chunk_size as u64);
        if expected != self.chunk_count as u64 {
            return Err(TreeError::FileCrypto("chunk count does not match size".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        self.validate()?;
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(DOMAIN);
        out.push(MEDIA_VERSION);
        out.extend_from_slice(&self.attachment_id);
        out.extend_from_slice(self.message_id.as_bytes());
        put_bytes_u16(&mut out, &self.group_id)?;
        out.extend_from_slice(&self.epoch.to_be_bytes());
        put_string_u8(&mut out, &self.media_type)?;
        put_string_u16(&mut out, &self.filename)?;
        put_string_u8(&mut out, &self.mime)?;
        out.extend_from_slice(&self.plaintext_size.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.push(preview_byte(self.preview_mode));
        put_view_policy(&mut out, self.view_policy);
        out.extend_from_slice(&self.base_nonce);
        if out.len() > MAX_MANIFEST {
            return Err(TreeError::FileCrypto("media manifest is too large".into()));
        }
        Ok(out)
    }

    pub fn commitment(&self) -> Result<[u8; 32], TreeError> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    pub fn key_commitment(&self, key: &MediaKey) -> Result<[u8; 32], TreeError> {
        let manifest = self.commitment()?;
        let mut h = Sha256::new();
        h.update(b"tree-media-key-commit-v1");
        h.update(&manifest);
        h.update(key.as_bytes());
        Ok(h.finalize().into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedChunk {
    pub index: u32,
    pub ciphertext: Vec<u8>,
    pub sha256: [u8; 32],
}

impl EncryptedChunk {
    pub fn encrypt(
        key: &MediaKey,
        manifest: &MediaManifest,
        index: u32,
        plaintext: &[u8],
    ) -> Result<Self, TreeError> {
        manifest.validate()?;
        validate_index(manifest, index, plaintext.len())?;
        let nonce = chunk_nonce(&manifest.base_nonce, index);
        let aad = chunk_aad(manifest, index)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|_| TreeError::FileCrypto("invalid media key".into()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| TreeError::FileCrypto("media chunk encryption failed".into()))?;
        let sha256 = Sha256::digest(&ciphertext).into();
        Ok(Self { index, ciphertext, sha256 })
    }

    pub fn decrypt(
        key: &MediaKey,
        manifest: &MediaManifest,
        chunk: &EncryptedChunk,
    ) -> Result<Vec<u8>, TreeError> {
        manifest.validate()?;
        if chunk.index >= manifest.chunk_count {
            return Err(TreeError::FileCrypto("media chunk index is out of range".into()));
        }
        let expected: [u8; 32] = Sha256::digest(&chunk.ciphertext).into();
        if expected != chunk.sha256 {
            return Err(TreeError::FileCrypto("media chunk hash mismatch".into()));
        }
        let nonce = chunk_nonce(&manifest.base_nonce, chunk.index);
        let aad = chunk_aad(manifest, chunk.index)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|_| TreeError::FileCrypto("invalid media key".into()))?;
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &chunk.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| TreeError::FileCrypto("media chunk authentication failed".into()))
    }
}

pub fn encrypt_preview(
    key: &MediaKey,
    manifest: &MediaManifest,
    plaintext: &[u8],
) -> Result<EncryptedChunk, TreeError> {
    if plaintext.len() > MAX_PREVIEW {
        return Err(TreeError::FileCrypto("preview is too large".into()));
    }
    let preview_key = derive_preview_key(key, manifest)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| TreeError::FileCrypto(format!("OS randomness unavailable: {e}")))?;
    let aad = {
        let mut a = Vec::with_capacity(64);
        a.extend_from_slice(PREVIEW_DOMAIN);
        a.extend_from_slice(&manifest.commitment()?);
        a
    };
    let cipher = Aes256Gcm::new_from_slice(preview_key.as_bytes())
        .map_err(|_| TreeError::FileCrypto("invalid preview key".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: plaintext, aad: &aad },
        )
        .map_err(|_| TreeError::FileCrypto("preview encryption failed".into()))?;
    let mut wire = nonce.to_vec();
    wire.extend_from_slice(&ciphertext);
    Ok(EncryptedChunk {
        index: u32::MAX,
        ciphertext: wire.clone(),
        sha256: Sha256::digest(&wire).into(),
    })
}

pub fn decrypt_preview(
    key: &MediaKey,
    manifest: &MediaManifest,
    preview: &EncryptedChunk,
) -> Result<Vec<u8>, TreeError> {
    if preview.index != u32::MAX || preview.ciphertext.len() < NONCE_LEN + 16 {
        return Err(TreeError::FileCrypto("invalid encrypted preview".into()));
    }
    let expected: [u8; 32] = Sha256::digest(&preview.ciphertext).into();
    if expected != preview.sha256 {
        return Err(TreeError::FileCrypto("preview hash mismatch".into()));
    }
    let preview_key = derive_preview_key(key, manifest)?;
    let aad = {
        let mut a = Vec::with_capacity(64);
        a.extend_from_slice(PREVIEW_DOMAIN);
        a.extend_from_slice(&manifest.commitment()?);
        a
    };
    let cipher = Aes256Gcm::new_from_slice(preview_key.as_bytes())
        .map_err(|_| TreeError::FileCrypto("invalid preview key".into()))?;
    cipher
        .decrypt(
            Nonce::from_slice(&preview.ciphertext[..NONCE_LEN]),
            Payload {
                msg: &preview.ciphertext[NONCE_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| TreeError::FileCrypto("preview authentication failed".into()))
}

fn derive_preview_key(key: &MediaKey, manifest: &MediaManifest) -> Result<MediaKey, TreeError> {
    let hk = Hkdf::<Sha256>::new(Some(b"tree-media-preview-salt-v1"), key.as_bytes());
    let mut out = [0u8; KEY_LEN];
    hk.expand(&manifest.commitment()?, &mut out)
        .map_err(|_| TreeError::FileCrypto("preview key derivation failed".into()))?;
    MediaKey::from_bytes(&out)
}

fn chunk_nonce(base: &[u8; BASE_NONCE_LEN], index: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..BASE_NONCE_LEN].copy_from_slice(base);
    nonce[BASE_NONCE_LEN..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn chunk_aad(manifest: &MediaManifest, index: u32) -> Result<Vec<u8>, TreeError> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(CHUNK_DOMAIN);
    aad.extend_from_slice(&manifest.commitment()?);
    aad.extend_from_slice(&index.to_be_bytes());
    Ok(aad)
}

fn validate_index(
    manifest: &MediaManifest,
    index: u32,
    plaintext_len: usize,
) -> Result<(), TreeError> {
    if index >= manifest.chunk_count {
        return Err(TreeError::FileCrypto("media chunk index is out of range".into()));
    }
    let offset = index as u64 * manifest.chunk_size as u64;
    let remaining = manifest.plaintext_size.saturating_sub(offset);
    let expected = remaining.min(manifest.chunk_size as u64) as usize;
    if plaintext_len != expected {
        return Err(TreeError::FileCrypto("media chunk plaintext size is invalid".into()));
    }
    Ok(())
}

fn preview_byte(mode: PreviewMode) -> u8 {
    match mode {
        PreviewMode::None => 0,
        PreviewMode::Blurred => 1,
        PreviewMode::LowResolution => 2,
    }
}

fn put_view_policy(out: &mut Vec<u8>, policy: ViewPolicy) {
    match policy {
        ViewPolicy::Persistent => out.extend_from_slice(&[0, 0, 0, 0]),
        ViewPolicy::Timed { seconds } => {
            out.push(1);
            out.extend_from_slice(&seconds.to_be_bytes());
        }
        ViewPolicy::ViewOnce => out.extend_from_slice(&[2, 0, 0, 0]),
    }
}

fn put_string_u8(out: &mut Vec<u8>, s: &str) -> Result<(), TreeError> {
    if s.len() > u8::MAX as usize {
        return Err(TreeError::FileCrypto("field too long".into()));
    }
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn put_string_u16(out: &mut Vec<u8>, s: &str) -> Result<(), TreeError> {
    if s.len() > u16::MAX as usize {
        return Err(TreeError::FileCrypto("field too long".into()));
    }
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn put_bytes_u16(out: &mut Vec<u8>, b: &[u8]) -> Result<(), TreeError> {
    if b.len() > u16::MAX as usize {
        return Err(TreeError::FileCrypto("field too long".into()));
    }
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediaViewState {
    Hidden,
    Preview,
    Opening,
    Open { expires_at: Option<i64> },
    Closed,
    Consumed,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaLifecycle {
    pub policy: ViewPolicy,
    pub state: MediaViewState,
    started_at: Option<i64>,
    expires_at: Option<i64>,
}

impl MediaLifecycle {
    pub fn new(policy: ViewPolicy) -> Self {
        Self {
            policy,
            state: MediaViewState::Hidden,
            started_at: None,
            expires_at: None,
        }
    }

    pub fn show_preview(&mut self) -> Result<(), TreeError> {
        if matches!(self.state, MediaViewState::Hidden) {
            self.state = MediaViewState::Preview;
            Ok(())
        } else {
            Err(TreeError::FileCrypto("preview state transition is invalid".into()))
        }
    }

    pub fn begin_open(&mut self, now: i64) -> Result<(), TreeError> {
        self.refresh(now);
        match self.state {
            MediaViewState::Preview | MediaViewState::Closed | MediaViewState::Hidden => {
                self.state = MediaViewState::Opening;
                Ok(())
            }
            MediaViewState::Opening | MediaViewState::Open { .. } => {
                Err(TreeError::FileCrypto("media is already opening/open".into()))
            }
            MediaViewState::Consumed | MediaViewState::Expired => {
                Err(TreeError::FileCrypto(
                    "media has expired or was already consumed".into(),
                ))
            }
        }
    }

    pub fn confirm_open(&mut self, now: i64) -> Result<(), TreeError> {
        if !matches!(self.state, MediaViewState::Opening) {
            return Err(TreeError::FileCrypto("media is not opening".into()));
        }
        match self.policy {
            ViewPolicy::Persistent => {
                self.state = MediaViewState::Open { expires_at: None };
            }
            ViewPolicy::Timed { seconds } => {
                let expires_at = now
                    .checked_add(i64::from(seconds))
                    .ok_or_else(|| TreeError::FileCrypto("media timer overflow".into()))?;
                self.started_at = Some(now);
                self.expires_at = Some(expires_at);
                self.state = MediaViewState::Open {
                    expires_at: Some(expires_at),
                };
            }
            ViewPolicy::ViewOnce => {
                self.started_at = Some(now);
                self.state = MediaViewState::Consumed;
            }
        }
        Ok(())
    }

    pub fn close(&mut self, now: i64) {
        self.refresh(now);
        if matches!(self.state, MediaViewState::Open { .. }) {
            self.state = MediaViewState::Closed;
        }
    }

    pub fn refresh(&mut self, now: i64) {
        if let Some(expires_at) = self.expires_at {
            if now >= expires_at
                && matches!(
                    self.state,
                    MediaViewState::Open { .. } | MediaViewState::Closed
                )
            {
                self.state = MediaViewState::Expired;
            }
        }
    }

    pub fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    pub fn remaining_seconds(&mut self, now: i64) -> Option<u32> {
        self.refresh(now);
        self.expires_at
            .map(|e| e.saturating_sub(now).max(0) as u32)
    }

    pub fn is_reopenable(&self) -> bool {
        matches!(
            self.state,
            MediaViewState::Preview | MediaViewState::Closed
        ) && !matches!(self.policy, ViewPolicy::ViewOnce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(size: u64, policy: ViewPolicy) -> (MediaManifest, MediaKey) {
        MediaManifest::generate(
            MessageId([7; 16]),
            b"group-1",
            4,
            "image",
            "photo.jpg",
            "image/jpeg",
            size,
            policy,
            PreviewMode::Blurred,
        )
        .unwrap()
    }

    #[test]
    fn chunk_round_trip_and_tamper_detection() {
        let (manifest, key) = sample(5, ViewPolicy::Persistent);
        let chunk = EncryptedChunk::encrypt(&key, &manifest, 0, b"hello").unwrap();
        assert_eq!(
            EncryptedChunk::decrypt(&key, &manifest, &chunk).unwrap(),
            b"hello"
        );
        let mut tampered = chunk.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(EncryptedChunk::decrypt(&key, &manifest, &tampered).is_err());
    }

    #[test]
    fn wrong_manifest_context_fails() {
        let (a, key) = sample(5, ViewPolicy::Persistent);
        let (b, _) = sample(5, ViewPolicy::Persistent);
        let chunk = EncryptedChunk::encrypt(&key, &a, 0, b"hello").unwrap();
        assert!(EncryptedChunk::decrypt(&key, &b, &chunk).is_err());
    }

    #[test]
    fn preview_uses_a_separate_derived_key() {
        let (manifest, key) = sample(5, ViewPolicy::Persistent);
        let preview = encrypt_preview(&key, &manifest, b"thumb").unwrap();
        assert_eq!(
            decrypt_preview(&key, &manifest, &preview).unwrap(),
            b"thumb"
        );
        let other = MediaKey::generate().unwrap();
        assert!(decrypt_preview(&other, &manifest, &preview).is_err());
    }

    #[test]
    fn view_once_is_not_burned_on_failed_open() {
        let (manifest, _) = sample(5, ViewPolicy::ViewOnce);
        let mut life = MediaLifecycle::new(manifest.view_policy);
        life.show_preview().unwrap();
        life.begin_open(100).unwrap();
        assert_eq!(life.state, MediaViewState::Opening);
        life.state = MediaViewState::Preview;
        life.begin_open(100).unwrap();
        life.confirm_open(101).unwrap();
        assert_eq!(life.state, MediaViewState::Consumed);
        assert!(life.begin_open(102).is_err());
    }

    #[test]
    fn timer_starts_only_after_successful_open() {
        let (manifest, _) = sample(10, ViewPolicy::Timed { seconds: 10 });
        let mut life = MediaLifecycle::new(manifest.view_policy);
        life.show_preview().unwrap();
        life.begin_open(100).unwrap();
        life.confirm_open(102).unwrap();
        assert_eq!(life.expires_at(), Some(112));
        assert_eq!(life.remaining_seconds(107), Some(5));
        assert_eq!(life.remaining_seconds(112), Some(0));
        assert_eq!(life.state, MediaViewState::Expired);
    }

    #[test]
    fn manifest_binds_group_epoch_and_message() {
        let (manifest, key) = sample(5, ViewPolicy::Persistent);
        let first = manifest.key_commitment(&key).unwrap();
        let mut changed = manifest.clone();
        changed.epoch += 1;
        assert_ne!(first, changed.key_commitment(&key).unwrap());
    }
}
