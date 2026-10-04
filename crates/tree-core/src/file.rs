//! Per-object media encryption for Tree.
//!
//! Media is encrypted on the sender device before upload. The server receives
//! only this blob. Tree v1 uses AES-256-GCM with a fresh random 96-bit nonce,
//! plus an explicit SHA-256 key-commitment field.
//!
//! This is deliberately NOT described as a "key-committing AEAD": ordinary
//! AES-GCM does not itself provide that property. The separate commitment
//! binds the file key, nonce, AAD and ciphertext.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::TreeError;

const MAGIC: &[u8] = b"TREEFILE";
const VERSION: u8 = 1;
const ALG_AES_256_GCM: u8 = 1;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const CAP_BYTES: usize = 32;
const COMMIT_LEN: usize = 32;
const MAX_AAD: usize = 4096;

const KEY_COMMIT_LABEL: &[u8] = b"tree/file-key-commit/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileKey(Zeroizing<[u8; KEY_LEN]>);

impl FileKey {
    pub fn generate() -> Result<Self, TreeError> {
        let mut key = [0u8; KEY_LEN];
        getrandom::fill(&mut key)
            .map_err(|e| TreeError::FileCrypto(format!("OS randomness unavailable: {e}")))?;
        Ok(Self(Zeroizing::new(key)))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TreeError> {
        let key: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| TreeError::FileCrypto("file key must be 32 bytes".into()))?;
        Ok(Self(Zeroizing::new(key)))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedFile {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub key_commitment: [u8; COMMIT_LEN],
}

impl EncryptedFile {
    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        let cipher_len = u64::try_from(self.ciphertext.len())
            .map_err(|_| TreeError::FileCrypto("ciphertext is too large".into()))?;
        let mut out = Vec::with_capacity(
            MAGIC.len() + 1 + 1 + NONCE_LEN + COMMIT_LEN + 8 + self.ciphertext.len(),
        );
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(ALG_AES_256_GCM);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.key_commitment);
        out.extend_from_slice(&cipher_len.to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        let min_len = MAGIC.len() + 1 + 1 + NONCE_LEN + COMMIT_LEN + 8;
        if bytes.len() < min_len {
            return Err(TreeError::Malformed(
                "encrypted file header is truncated".into(),
            ));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(TreeError::Malformed("not a Tree file envelope".into()));
        }
        let mut p = MAGIC.len();
        if bytes[p] != VERSION {
            return Err(TreeError::Malformed("unsupported Tree file version".into()));
        }
        p += 1;
        if bytes[p] != ALG_AES_256_GCM {
            return Err(TreeError::Malformed(
                "unsupported Tree file algorithm".into(),
            ));
        }
        p += 1;
        let nonce: [u8; NONCE_LEN] = bytes[p..p + NONCE_LEN]
            .try_into()
            .map_err(|_| TreeError::Malformed("bad file nonce".into()))?;
        p += NONCE_LEN;
        let key_commitment: [u8; COMMIT_LEN] = bytes[p..p + COMMIT_LEN]
            .try_into()
            .map_err(|_| TreeError::Malformed("bad file commitment".into()))?;
        p += COMMIT_LEN;
        let declared_len = u64::from_be_bytes(
            bytes[p..p + 8]
                .try_into()
                .map_err(|_| TreeError::Malformed("bad file length".into()))?,
        );
        p += 8;
        let remaining = bytes.len() - p;
        if declared_len != remaining as u64 {
            return Err(TreeError::Malformed(
                "file length does not match envelope".into(),
            ));
        }
        if remaining < 16 {
            return Err(TreeError::Malformed("file ciphertext is too short".into()));
        }
        Ok(Self {
            nonce,
            ciphertext: bytes[p..].to_vec(),
            key_commitment,
        })
    }
}

pub fn encrypt(key: &FileKey, aad: &[u8], plaintext: &[u8]) -> Result<EncryptedFile, TreeError> {
    validate_aad(aad)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| TreeError::FileCrypto(format!("OS randomness unavailable: {e}")))?;
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| TreeError::FileCrypto("invalid AES-256 key".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| TreeError::FileCrypto("file encryption failed".into()))?;
    let key_commitment = commitment(key, &nonce, aad, &ciphertext);
    Ok(EncryptedFile {
        nonce,
        ciphertext,
        key_commitment,
    })
}

pub fn decrypt(key: &FileKey, aad: &[u8], encrypted: &EncryptedFile) -> Result<Vec<u8>, TreeError> {
    validate_aad(aad)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| TreeError::FileCrypto("invalid AES-256 key".into()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            aes_gcm::aead::Payload {
                msg: &encrypted.ciphertext,
                aad,
            },
        )
        .map_err(|_| TreeError::FileCrypto("file authentication failed".into()))?;
    let expected = commitment(key, &encrypted.nonce, aad, &encrypted.ciphertext);
    if expected != encrypted.key_commitment {
        return Err(TreeError::FileCrypto(
            "file key commitment verification failed".into(),
        ));
    }
    Ok(plaintext)
}

fn commitment(
    key: &FileKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; COMMIT_LEN] {
    let mut h = Sha256::new();
    h.update(KEY_COMMIT_LABEL);
    h.update(key.as_bytes());
    h.update(nonce);
    h.update((aad.len() as u64).to_be_bytes());
    h.update(aad);
    h.update((ciphertext.len() as u64).to_be_bytes());
    h.update(ciphertext);
    h.finalize().into()
}

const SHARE_MAGIC: &[u8] = b"TREEFSHARE\x01";
const MAX_FILE_ID: usize = 64;
const MAX_FILENAME: usize = 255;
const MAX_MIME: usize = 127;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileShare {
    pub file_id: String,
    pub capability: [u8; CAP_BYTES],
    pub file_key: FileKey,
    pub ciphertext_sha256: [u8; COMMIT_LEN],
    pub plaintext_size: u64,
    pub filename: String,
    pub mime: String,
}

impl FileShare {
    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        validate_file_id(&self.file_id)?;
        if self.filename.len() > MAX_FILENAME {
            return Err(TreeError::FileCrypto("filename is too long".into()));
        }
        if self.mime.len() > MAX_MIME || !self.mime.is_ascii() {
            return Err(TreeError::FileCrypto("mime type is invalid".into()));
        }
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(SHARE_MAGIC);
        put_u8_string(&mut out, &self.file_id)?;
        out.extend_from_slice(&self.capability);
        out.extend_from_slice(self.file_key.as_bytes());
        out.extend_from_slice(&self.ciphertext_sha256);
        out.extend_from_slice(&self.plaintext_size.to_be_bytes());
        put_u16_string(&mut out, &self.filename)?;
        put_u16_string(&mut out, &self.mime)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        if !bytes.starts_with(SHARE_MAGIC) {
            return Err(TreeError::Malformed("not a Tree file share".into()));
        }
        let mut r = ShareReader(&bytes[SHARE_MAGIC.len()..]);
        let file_id = r.string()?;
        validate_file_id(&file_id)?;
        let capability: [u8; CAP_BYTES] = r
            .take(CAP_BYTES)?
            .try_into()
            .map_err(|_| TreeError::Malformed("bad file capability".into()))?;
        let key = FileKey::from_bytes(r.take(KEY_LEN)?)?;
        let ciphertext_sha256: [u8; COMMIT_LEN] = r
            .take(COMMIT_LEN)?
            .try_into()
            .map_err(|_| TreeError::Malformed("bad file hash".into()))?;
        let plaintext_size = r.u64()?;
        let filename = r.string()?;
        if filename.len() > MAX_FILENAME {
            return Err(TreeError::Malformed("filename is too long".into()));
        }
        let mime = r.string()?;
        if mime.len() > MAX_MIME || !mime.is_ascii() {
            return Err(TreeError::Malformed("mime type is invalid".into()));
        }
        if !r.0.is_empty() {
            return Err(TreeError::Malformed("trailing bytes in file share".into()));
        }
        Ok(Self {
            file_id,
            capability,
            file_key: key,
            ciphertext_sha256,
            plaintext_size,
            filename,
            mime,
        })
    }
}

fn put_u8_string(out: &mut Vec<u8>, value: &str) -> Result<(), TreeError> {
    if value.len() > u8::MAX as usize {
        return Err(TreeError::FileCrypto("string is too long".into()));
    }
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_u16_string(out: &mut Vec<u8>, value: &str) -> Result<(), TreeError> {
    if value.len() > u16::MAX as usize {
        return Err(TreeError::FileCrypto("string is too long".into()));
    }
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn validate_file_id(file_id: &str) -> Result<(), TreeError> {
    if file_id.is_empty()
        || file_id.len() > MAX_FILE_ID
        || !file_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(TreeError::Malformed("invalid file id".into()));
    }
    Ok(())
}

struct ShareReader<'a>(&'a [u8]);

impl ShareReader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], TreeError> {
        if self.0.len() < n {
            return Err(TreeError::Malformed("truncated file share".into()));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn string(&mut self) -> Result<String, TreeError> {
        let len = self.take(1)?[0] as usize;
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| TreeError::Malformed("file share string is not UTF-8".into()))
    }

    fn u64(&mut self) -> Result<u64, TreeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("length checked"),
        ))
    }
}

pub fn media_aad(group_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(b"tree-media-v1\n");
    aad.extend_from_slice(group_id);
    aad
}

fn validate_aad(aad: &[u8]) -> Result<(), TreeError> {
    if aad.len() > MAX_AAD {
        return Err(TreeError::FileCrypto("file AAD is too large".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_aad() {
        let key = FileKey::generate().unwrap();
        let aad = b"group=abc;message=42";
        let enc = encrypt(&key, aad, b"media bytes").unwrap();
        let wire = enc.encode().unwrap();
        let parsed = EncryptedFile::decode(&wire).unwrap();
        assert_eq!(decrypt(&key, aad, &parsed).unwrap(), b"media bytes");
    }

    #[test]
    fn wrong_key_and_wrong_aad_fail() {
        let key = FileKey::generate().unwrap();
        let other = FileKey::generate().unwrap();
        let enc = encrypt(&key, b"aad-a", b"secret").unwrap();
        assert!(decrypt(&other, b"aad-a", &enc).is_err());
        assert!(decrypt(&key, b"aad-b", &enc).is_err());
    }

    #[test]
    fn tamper_ciphertext_or_commitment_fails() {
        let key = FileKey::generate().unwrap();
        let mut enc = encrypt(&key, b"aad", b"secret").unwrap();
        enc.ciphertext[0] ^= 1;
        assert!(decrypt(&key, b"aad", &enc).is_err());

        let mut enc = encrypt(&key, b"aad", b"secret").unwrap();
        enc.key_commitment[0] ^= 1;
        assert!(decrypt(&key, b"aad", &enc).is_err());
    }

    #[test]
    fn file_share_round_trips() {
        let key = FileKey::generate().unwrap();
        let share = FileShare {
            file_id: "ABCDEFGHIJKLMNOPQRSTUV".into(),
            capability: [3u8; CAP_BYTES],
            file_key: key,
            ciphertext_sha256: [4u8; COMMIT_LEN],
            plaintext_size: 123,
            filename: "photo.jpg".into(),
            mime: "image/jpeg".into(),
        };
        let bytes = share.encode().unwrap();
        let decoded = FileShare::decode(&bytes).unwrap();
        assert_eq!(decoded.file_id, share.file_id);
        assert_eq!(decoded.capability, share.capability);
        assert_eq!(decoded.file_key.as_bytes(), share.file_key.as_bytes());
        assert_eq!(decoded.ciphertext_sha256, share.ciphertext_sha256);
        assert_eq!(decoded.plaintext_size, 123);
        assert_eq!(decoded.filename, "photo.jpg");
        assert_eq!(decoded.mime, "image/jpeg");
    }

    #[test]
    fn malformed_length_is_rejected() {
        let key = FileKey::generate().unwrap();
        let enc = encrypt(&key, b"", b"x").unwrap();
        let mut wire = enc.encode().unwrap();
        let i = wire.len() - 1 - 8;
        wire[i] ^= 1;
        assert!(EncryptedFile::decode(&wire).is_err());
    }
}
