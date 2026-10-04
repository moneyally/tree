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

pub const MEDIA_VERSION: u8 = 2;
const LEGACY_MEDIA_VERSION: u8 = 1;
/// Bounded, non-destructive edit recipe. The recipe never contains the
/// plaintext media; it is safe to keep locally and can be discarded after the
/// final rendered bytes are encrypted.
pub const MAX_EDIT_OPERATIONS: usize = 128;
pub const MAX_CAPTION_BYTES: usize = 4096;
pub const MAX_OVERLAY_TEXT_BYTES: usize = 1024;
pub const MAX_STROKE_POINTS: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rotation {
    Deg0,
    Deg90,
    Deg180,
    Deg270,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CropRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageAdjustments {
    pub brightness: i16,
    pub contrast: i16,
    pub saturation: i16,
    pub sharpness: u8,
    pub warmth: i16,
    pub blur: u8,
}

impl Default for ImageAdjustments {
    fn default() -> Self {
        Self {
            brightness: 0,
            contrast: 0,
            saturation: 0,
            sharpness: 0,
            warmth: 0,
            blur: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrushStyle {
    pub width: u16,
    pub opacity: u8,
    /// 0..=100: pressure/sensitivity multiplier used by the platform renderer.
    pub sensitivity: u8,
    pub smoothing: u8,
    pub rotation_deg: i16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrawPoint {
    pub x_milli: i32,
    pub y_milli: i32,
    pub pressure: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrawStroke {
    pub brush: BrushStyle,
    pub points: Vec<DrawPoint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextStyle {
    pub size: u16,
    pub opacity: u8,
    pub rotation_deg: i16,
    pub bold: bool,
    pub italic: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextOverlay {
    pub text: String,
    pub x_milli: i32,
    pub y_milli: i32,
    pub style: TextStyle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StickerTransform {
    pub x_milli: i32,
    pub y_milli: i32,
    pub scale_milli: u32,
    pub rotation_deg: i16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StickerOverlay {
    pub sticker_id: [u8; 16],
    pub transform: StickerTransform,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditOperation {
    Crop(CropRect),
    Rotate(Rotation),
    RotateBy(i16),
    FlipHorizontal,
    FlipVertical,
    Adjust(ImageAdjustments),
    Draw(DrawStroke),
    AddText(TextOverlay),
    AddSticker(StickerOverlay),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaEditPlan {
    pub source_width: u32,
    pub source_height: u32,
    pub operations: Vec<EditOperation>,
    pub caption: String,
    redo: Vec<EditOperation>,
}

impl MediaEditPlan {
    pub fn new(source_width: u32, source_height: u32) -> Result<Self, TreeError> {
        if source_width == 0 || source_height == 0 {
            return Err(TreeError::FileCrypto("media dimensions must be non-zero".into()));
        }
        Ok(Self {
            source_width,
            source_height,
            operations: Vec::new(),
            caption: String::new(),
            redo: Vec::new(),
        })
    }

    pub fn push(&mut self, op: EditOperation) -> Result<(), TreeError> {
        if self.operations.len() >= MAX_EDIT_OPERATIONS {
            return Err(TreeError::FileCrypto("too many media edit operations".into()));
        }
        validate_edit_operation(&op)?;
        self.operations.push(op);
        self.redo.clear();
        Ok(())
    }

    pub fn set_caption(&mut self, caption: &str) -> Result<(), TreeError> {
        if caption.as_bytes().len() > MAX_CAPTION_BYTES {
            return Err(TreeError::FileCrypto("media caption is too long".into()));
        }
        if caption.chars().any(|c| c == '\0') {
            return Err(TreeError::FileCrypto("media caption contains NUL".into()));
        }
        self.caption = caption.to_string();
        Ok(())
    }

    pub fn validate(&self) -> Result<(), TreeError> {
        for op in &self.operations { validate_edit_operation(op)?; }
        Ok(())
    }

    pub fn undo(&mut self) -> Option<EditOperation> {
        let op = self.operations.pop()?;
        self.redo.push(op.clone());
        Some(op)
    }

    pub fn redo(&mut self) -> Option<EditOperation> {
        let op = self.redo.pop()?;
        self.operations.push(op.clone());
        Some(op)
    }

    pub fn clear(&mut self) {
        self.operations.clear();
        self.redo.clear();
        self.caption.clear();
    }
}

fn validate_edit_operation(op: &EditOperation) -> Result<(), TreeError> {
    match op {
        EditOperation::Crop(r) => {
            if r.width == 0 || r.height == 0 || r.x.checked_add(r.width).is_none() || r.y.checked_add(r.height).is_none() {

                return Err(TreeError::FileCrypto("crop dimensions must be non-zero".into()));
            }
        }
        EditOperation::Adjust(a) => {
            if !(-100..=100).contains(&a.brightness)
                || !(-100..=100).contains(&a.contrast)
                || !(-100..=100).contains(&a.saturation)
                || !(-100..=100).contains(&a.warmth)
                || a.sharpness > 100
                || a.blur > 100
            {
                return Err(TreeError::FileCrypto("media adjustment is out of range".into()));
            }
        }
        EditOperation::Draw(s) => {
            if s.points.is_empty() || s.points.len() > MAX_STROKE_POINTS {
                return Err(TreeError::FileCrypto("draw stroke point count is invalid".into()));
            }
            if s.brush.width == 0 || s.brush.opacity == 0 || s.brush.sensitivity > 100 {
                return Err(TreeError::FileCrypto("brush settings are invalid".into()));
            }
        }
        EditOperation::AddText(t) => {
            if t.text.is_empty() || t.text.as_bytes().len() > MAX_OVERLAY_TEXT_BYTES {
                return Err(TreeError::FileCrypto("text overlay is invalid".into()));
            }
            if t.style.size == 0 || t.style.opacity == 0 {
                return Err(TreeError::FileCrypto("text style is invalid".into()));
            }
        }
        EditOperation::AddSticker(s) => {
            if s.transform.scale_milli == 0 {
                return Err(TreeError::FileCrypto("sticker scale is invalid".into()));
            }
        }
        EditOperation::Rotate(_)
        | EditOperation::FlipHorizontal
        | EditOperation::FlipVertical => {}
        EditOperation::RotateBy(deg) => {
            if !(-180..=180).contains(deg) {
                return Err(TreeError::FileCrypto("rotation angle is out of range".into()));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaSendMode {
    Original,
    Edited,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaComposerState {
    pub edit: MediaEditPlan,
    pub send_mode: MediaSendMode,
    pub view_policy: ViewPolicy,
    pub preview_mode: PreviewMode,
}

impl MediaComposerState {
    pub fn new(width: u32, height: u32) -> Result<Self, TreeError> {
        Ok(Self {
            edit: MediaEditPlan::new(width, height)?,
            send_mode: MediaSendMode::Edited,
            view_policy: ViewPolicy::Persistent,
            preview_mode: PreviewMode::LowResolution,
        })
    }

    pub fn reset_edits(&mut self) {
        self.edit.operations.clear();
    }

    pub fn set_view_once(&mut self) {
        self.view_policy = ViewPolicy::ViewOnce;
    }

    pub fn set_timer(&mut self, seconds: u32) -> Result<(), TreeError> {
        if seconds == 0 || seconds > 30 * 86_400 {
            return Err(TreeError::FileCrypto("media timer is out of range".into()));
        }
        self.view_policy = ViewPolicy::Timed { seconds };
        Ok(())
    }
}

pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
pub const MAX_CHUNKS: u32 = 65_535;
const KEY_LEN: usize = 32;
const CAP_BYTES: usize = 32;
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
    pub edit_script_hash: Option<[u8; 32]>,
    pub output_commitment: Option<[u8; 32]>,
}

impl MediaManifest {
    #[allow(clippy::too_many_arguments)]
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
            edit_script_hash: None,
            output_commitment: None,
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
        if self.edit_script_hash.is_some() != self.output_commitment.is_some() {
            return Err(TreeError::FileCrypto(
                "media edit binding must contain both hashes".into(),
            ));
        }
        let expected = self.plaintext_size.div_ceil(self.chunk_size as u64);
        if expected != self.chunk_count as u64 {
            return Err(TreeError::FileCrypto(
                "chunk count does not match size".into(),
            ));
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
        match (self.edit_script_hash, self.output_commitment) {
            (None, None) => out.push(0),
            (Some(edit), Some(output)) => {
                out.push(1);
                out.extend_from_slice(&edit);
                out.extend_from_slice(&output);
            }
            _ => unreachable!("validated edit binding is either present or absent"),
        }
        if out.len() > MAX_MANIFEST {
            return Err(TreeError::FileCrypto("media manifest is too large".into()));
        }
        Ok(out)
    }

    pub fn commitment(&self) -> Result<[u8; 32], TreeError> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        let mut r = Reader(bytes);
        if r.take(DOMAIN.len())? != DOMAIN {
            return Err(TreeError::Malformed("invalid media manifest header".into()));
        }
        let version = r.u8()?;
        if version != LEGACY_MEDIA_VERSION && version != MEDIA_VERSION {
            return Err(TreeError::Malformed("invalid media manifest header".into()));
        }
        let attachment_id = r.array::<16>()?;
        let message_id = MessageId::from_bytes(r.array::<16>()?);
        let group_id = r.bytes_u16(MAX_GROUP_ID)?;
        let epoch = r.u64()?;
        let media_type = r.string_u8()?;
        let filename = r.string_u16()?;
        let mime = r.string_u8()?;
        let plaintext_size = r.u64()?;
        let chunk_size = r.u32()?;
        let chunk_count = r.u32()?;
        let preview_mode = match r.u8()? {
            0 => PreviewMode::None,
            1 => PreviewMode::Blurred,
            2 => PreviewMode::LowResolution,
            _ => return Err(TreeError::Malformed("invalid media preview mode".into())),
        };
        let view_policy = match r.u8()? {
            0 => {
                let _ = r.take(3)?;
                ViewPolicy::Persistent
            }
            1 => ViewPolicy::Timed { seconds: r.u32()? },
            2 => {
                let _ = r.take(3)?;
                ViewPolicy::ViewOnce
            }
            _ => return Err(TreeError::Malformed("invalid media view policy".into())),
        };
        let base_nonce = r.array::<8>()?;
        let (edit_script_hash, output_commitment) = if version == LEGACY_MEDIA_VERSION {
            (None, None)
        } else {
            match r.u8()? {
                0 => (None, None),
                1 => (Some(r.array::<32>()?), Some(r.array::<32>()?)),
                _ => return Err(TreeError::Malformed("invalid media edit binding flag".into())),
            }
        };
        if !r.0.is_empty() {
            return Err(TreeError::Malformed("trailing media manifest bytes".into()));
        }
        let manifest = Self {
            attachment_id,
            message_id,
            group_id,
            epoch,
            media_type,
            filename,
            mime,
            plaintext_size,
            chunk_size,
            chunk_count,
            preview_mode,
            view_policy,
            base_nonce,
            edit_script_hash,
            output_commitment,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn with_edit_binding(
        mut self,
        edit_script_hash: [u8; 32],
        output_commitment: [u8; 32],
    ) -> Result<Self, TreeError> {
        self.edit_script_hash = Some(edit_script_hash);
        self.output_commitment = Some(output_commitment);
        self.validate()?;
        Ok(self)
    }

    pub fn key_commitment(&self, key: &MediaKey) -> Result<[u8; 32], TreeError> {
        let manifest = self.commitment()?;
        let mut h = Sha256::new();
        h.update(b"tree-media-key-commit-v1");
        h.update(manifest);
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
        Ok(Self {
            index,
            ciphertext,
            sha256,
        })
    }

    pub fn decrypt(
        key: &MediaKey,
        manifest: &MediaManifest,
        chunk: &EncryptedChunk,
    ) -> Result<Vec<u8>, TreeError> {
        manifest.validate()?;
        if chunk.index >= manifest.chunk_count {
            return Err(TreeError::FileCrypto(
                "media chunk index is out of range".into(),
            ));
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

pub fn encrypt_manifest(key: &MediaKey, manifest: &MediaManifest) -> Result<Vec<u8>, TreeError> {
    let manifest_bytes = manifest.encode()?;
    let manifest_key = derive_manifest_key_raw(key)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| TreeError::FileCrypto(format!("OS randomness unavailable: {e}")))?;
    let cipher = Aes256Gcm::new_from_slice(manifest_key.as_bytes())
        .map_err(|_| TreeError::FileCrypto("invalid manifest key".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &manifest_bytes,
                aad: b"tree-media-manifest-v1",
            },
        )
        .map_err(|_| TreeError::FileCrypto("manifest encryption failed".into()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_manifest(key: &MediaKey, manifest_blob: &[u8]) -> Result<MediaManifest, TreeError> {
    if manifest_blob.len() < NONCE_LEN + 16 {
        return Err(TreeError::FileCrypto(
            "encrypted manifest is too short".into(),
        ));
    }
    let nonce: [u8; NONCE_LEN] = manifest_blob[..NONCE_LEN]
        .try_into()
        .expect("length checked");
    let ciphertext = &manifest_blob[NONCE_LEN..];
    let manifest_key = derive_manifest_key_raw(key)?;
    let cipher = Aes256Gcm::new_from_slice(manifest_key.as_bytes())
        .map_err(|_| TreeError::FileCrypto("invalid manifest key".into()))?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: b"tree-media-manifest-v1",
            },
        )
        .map_err(|_| TreeError::FileCrypto("manifest authentication failed".into()))?;
    MediaManifest::decode(&plain)
}

fn derive_manifest_key_raw(key: &MediaKey) -> Result<MediaKey, TreeError> {
    let hk = Hkdf::<Sha256>::new(Some(b"tree-media-manifest-salt-v1"), key.as_bytes());
    let mut out = [0u8; KEY_LEN];
    hk.expand(b"manifest", &mut out)
        .map_err(|_| TreeError::FileCrypto("manifest key derivation failed".into()))?;
    MediaKey::from_bytes(&out)
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
            Payload {
                msg: plaintext,
                aad: &aad,
            },
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
        return Err(TreeError::FileCrypto(
            "media chunk plaintext size is invalid".into(),
        ));
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

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TreeError> {
        if self.0.len() < n {
            return Err(TreeError::Malformed("truncated media manifest".into()));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, TreeError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, TreeError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("length checked"),
        ))
    }

    fn u64(&mut self) -> Result<u64, TreeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("length checked"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TreeError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    fn bytes_u16(&mut self, max: usize) -> Result<Vec<u8>, TreeError> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().expect("length checked")) as usize;
        if n > max {
            return Err(TreeError::Malformed(
                "media manifest field is too large".into(),
            ));
        }
        Ok(self.take(n)?.to_vec())
    }

    fn string_u8(&mut self) -> Result<String, TreeError> {
        let n = self.u8()? as usize;
        String::from_utf8(self.take(n)?.to_vec())
            .map_err(|_| TreeError::Malformed("media manifest string is not UTF-8".into()))
    }

    fn string_u16(&mut self) -> Result<String, TreeError> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().expect("length checked")) as usize;
        String::from_utf8(self.take(n)?.to_vec())
            .map_err(|_| TreeError::Malformed("media manifest string is not UTF-8".into()))
    }
}

fn put_bytes_u16(out: &mut Vec<u8>, b: &[u8]) -> Result<(), TreeError> {
    if b.len() > u16::MAX as usize {
        return Err(TreeError::FileCrypto("field too long".into()));
    }
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

pub const MEDIA_VIEW_MAGIC: &[u8] = b"TREEMEDIAVIEW\x01";

#[derive(Debug)]
pub struct SecureMediaBytes(Zeroizing<Vec<u8>>);

impl SecureMediaBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaViewEvent {
    pub message_id: MessageId,
    pub attachment_id: [u8; ATTACHMENT_ID_LEN],
    pub consumed_at: i64,
}

impl MediaViewEvent {
    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        let mut out = Vec::with_capacity(MEDIA_VIEW_MAGIC.len() + 16 + 16 + 8);
        out.extend_from_slice(MEDIA_VIEW_MAGIC);
        out.extend_from_slice(self.message_id.as_bytes());
        out.extend_from_slice(&self.attachment_id);
        out.extend_from_slice(&self.consumed_at.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        let expected = MEDIA_VIEW_MAGIC.len() + 16 + ATTACHMENT_ID_LEN + 8;
        if bytes.len() != expected || !bytes.starts_with(MEDIA_VIEW_MAGIC) {
            return Err(TreeError::Malformed("invalid media view event".into()));
        }
        let mut p = MEDIA_VIEW_MAGIC.len();
        let message_id =
            MessageId::from_bytes(bytes[p..p + 16].try_into().expect("length checked"));
        p += 16;
        let attachment_id = bytes[p..p + ATTACHMENT_ID_LEN]
            .try_into()
            .expect("length checked");
        p += ATTACHMENT_ID_LEN;
        let consumed_at = i64::from_be_bytes(bytes[p..p + 8].try_into().expect("length checked"));
        Ok(Self {
            message_id,
            attachment_id,
            consumed_at,
        })
    }
}

pub const MEDIA_MESSAGE_MAGIC: &[u8] = b"TREEMEDIA\x01";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaEnvelope {
    pub media_id: String,
    pub capability: [u8; CAP_BYTES],
    pub manifest: MediaManifest,
    pub file_key: MediaKey,
    pub preview: Option<EncryptedChunk>,
    pub caption: String,
}

impl MediaEnvelope {
    pub fn file_key_ref(&self) -> &MediaKey {
        &self.file_key
    }

    pub fn new(
        media_id: String,
        capability: [u8; CAP_BYTES],
        manifest: MediaManifest,
        file_key: MediaKey,
        preview: Option<EncryptedChunk>,
    ) -> Result<Self, TreeError> {
        if media_id.is_empty()
            || media_id.len() > 64
            || !media_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(TreeError::FileCrypto("invalid media id".into()));
        }
        if let Some(p) = &preview {
            if p.index != u32::MAX {
                return Err(TreeError::FileCrypto(
                    "media preview has invalid index".into(),
                ));
            }
        }
        Ok(Self {
            media_id,
            capability,
            manifest,
            file_key,
            preview,
            caption: String::new(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        let manifest = self.manifest.encode()?;
        let key_commitment = self.manifest.key_commitment(&self.file_key)?;
        let mut out = Vec::with_capacity(256 + manifest.len());
        out.extend_from_slice(MEDIA_MESSAGE_MAGIC);
        put_string_u8(&mut out, &self.media_id)?;
        out.extend_from_slice(&self.capability);
        put_bytes_u16(&mut out, &manifest)?;
        out.extend_from_slice(self.file_key.as_bytes());
        out.extend_from_slice(&key_commitment);
        put_string_u16(&mut out, &self.caption)?;
        match &self.preview {
            None => out.push(0),
            Some(preview) => {
                out.push(1);
                if preview.ciphertext.len() > u32::MAX as usize {
                    return Err(TreeError::FileCrypto("preview is too large".into()));
                }
                out.extend_from_slice(&(preview.ciphertext.len() as u32).to_be_bytes());
                out.extend_from_slice(&preview.ciphertext);
                out.extend_from_slice(&preview.sha256);
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        let mut r = Reader(bytes);
        if r.take(MEDIA_MESSAGE_MAGIC.len())? != MEDIA_MESSAGE_MAGIC {
            return Err(TreeError::Malformed("not a Tree media message".into()));
        }
        let media_id = r.string_u8()?;
        let capability = r.array::<CAP_BYTES>()?;
        let manifest_bytes = r.bytes_u16(MAX_MANIFEST)?;
        let manifest = MediaManifest::decode(&manifest_bytes)?;
        let file_key = MediaKey::from_bytes(r.take(KEY_LEN)?)?;
        let expected = manifest.key_commitment(&file_key)?;
        let received = r.array::<32>()?;
        if expected != received {
            return Err(TreeError::FileCrypto(
                "media key commitment mismatch".into(),
            ));
        }
        let caption = r.string_u16()?;
        let preview = match r.u8()? {
            0 => None,
            1 => {
                let n = r.u32()? as usize;
                if n > MAX_PREVIEW + NONCE_LEN + 16 {
                    return Err(TreeError::Malformed("media preview is too large".into()));
                }
                let ciphertext = r.take(n)?.to_vec();
                let sha256 = r.array::<32>()?;
                Some(EncryptedChunk {
                    index: u32::MAX,
                    ciphertext,
                    sha256,
                })
            }
            _ => return Err(TreeError::Malformed("invalid media preview flag".into())),
        };
        if !r.0.is_empty() {
            return Err(TreeError::Malformed("trailing media message bytes".into()));
        }
        Self::new(media_id, capability, manifest, file_key, preview)
    }
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
            Err(TreeError::FileCrypto(
                "preview state transition is invalid".into(),
            ))
        }
    }

    pub fn begin_open(&mut self, now: i64) -> Result<(), TreeError> {
        self.refresh(now);
        match self.state {
            MediaViewState::Preview | MediaViewState::Closed | MediaViewState::Hidden => {
                self.state = MediaViewState::Opening;
                Ok(())
            }
            MediaViewState::Opening | MediaViewState::Open { .. } => Err(TreeError::FileCrypto(
                "media is already opening/open".into(),
            )),
            MediaViewState::Consumed | MediaViewState::Expired => Err(TreeError::FileCrypto(
                "media has expired or was already consumed".into(),
            )),
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
        self.expires_at.map(|e| e.saturating_sub(now).max(0) as u32)
    }

    pub fn apply_remote_consumed(&mut self) {
        if matches!(self.policy, ViewPolicy::ViewOnce) {
            self.state = MediaViewState::Consumed;
            self.expires_at = None;
        }
    }

    pub fn is_reopenable(&self) -> bool {
        matches!(self.state, MediaViewState::Preview | MediaViewState::Closed)
            && !matches!(self.policy, ViewPolicy::ViewOnce)
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
    fn manifest_and_media_envelope_round_trip() {
        let (manifest, key) = sample(5, ViewPolicy::ViewOnce);
        let preview = encrypt_preview(&key, &manifest, b"thumb").unwrap();
        let envelope = MediaEnvelope::new(
            "media123".into(),
            [8; CAP_BYTES],
            manifest.clone(),
            key.clone(),
            Some(preview),
        )
        .unwrap();
        let decoded = MediaEnvelope::decode(&envelope.encode().unwrap()).unwrap();
        assert_eq!(decoded.manifest, manifest);
        assert_eq!(decoded.file_key.as_bytes(), key.as_bytes());
        assert_eq!(
            decrypt_preview(
                decoded.file_key_ref(),
                &decoded.manifest,
                decoded.preview.as_ref().unwrap()
            )
            .unwrap(),
            b"thumb"
        );
    }

    #[test]
    fn manifest_is_encrypted_for_server_storage() {
        let (manifest, key) = sample(5, ViewPolicy::Persistent);
        let blob = encrypt_manifest(&key, &manifest).unwrap();
        assert_ne!(blob, manifest.encode().unwrap());
        assert_eq!(decrypt_manifest(&key, &blob).unwrap(), manifest);
        let other = MediaKey::generate().unwrap();
        assert!(decrypt_manifest(&other, &blob).is_err());
    }

    #[test]
    fn view_event_round_trips() {
        let event = MediaViewEvent {
            message_id: MessageId([3; 16]),
            attachment_id: [4; 16],
            consumed_at: 123,
        };
        assert_eq!(
            MediaViewEvent::decode(&event.encode().unwrap()).unwrap(),
            event
        );
    }

    #[test]
    fn secure_media_bytes_expose_only_a_borrowed_view() {
        let bytes = SecureMediaBytes::new(vec![1, 2, 3]);
        assert_eq!(bytes.as_slice(), &[1, 2, 3]);
        assert_eq!(bytes.len(), 3);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn edit_plan_supports_arbitrary_rotation_and_redo() {
        let mut plan = MediaEditPlan::new(1920, 1080).unwrap();
        plan.push(EditOperation::RotateBy(37)).unwrap();
        assert!(plan.undo().is_some());
        assert!(plan.redo().is_some());
        assert_eq!(plan.operations.len(), 1);
    }

    #[test]
    fn edit_plan_validates_text_drawing_adjustments_and_undo() {
        let mut plan = MediaEditPlan::new(1920, 1080).unwrap();
        plan.set_caption("설명").unwrap();
        plan.push(EditOperation::Rotate(Rotation::Deg90)).unwrap();
        plan.push(EditOperation::Adjust(ImageAdjustments {
            brightness: 20,
            contrast: -10,
            saturation: 15,
            sharpness: 30,
            warmth: 5,
            blur: 0,
        })).unwrap();
        plan.push(EditOperation::Draw(DrawStroke {
            brush: BrushStyle {
                width: 12,
                opacity: 200,
                sensitivity: 75,
                smoothing: 60,
                rotation_deg: 15,
            },
            points: vec![
                DrawPoint { x_milli: 100, y_milli: 100, pressure: 180 },
                DrawPoint { x_milli: 200, y_milli: 200, pressure: 220 },
            ],
        })).unwrap();
        plan.push(EditOperation::AddText(TextOverlay {
            text: "확인".into(),
            x_milli: 500,
            y_milli: 500,
            style: TextStyle {
                size: 48,
                opacity: 255,
                rotation_deg: -5,
                bold: true,
                italic: false,
            },
        })).unwrap();
        assert!(matches!(plan.undo(), Some(EditOperation::AddText(_))));
        assert_eq!(plan.caption, "설명");
    }

    #[test]
    fn composer_rejects_invalid_timer() {
        let mut composer = MediaComposerState::new(100, 100).unwrap();
        assert!(composer.set_timer(0).is_err());
        assert!(composer.set_timer(31 * 86_400).is_err());
        composer.set_timer(30).unwrap();
        assert_eq!(composer.view_policy, ViewPolicy::Timed { seconds: 30 });
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
