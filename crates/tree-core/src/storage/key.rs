//! Where the database key comes from.
//!
//! The database is encrypted with a 256-bit key that is never stored. It is
//! rebuilt on every unlock by a [`KeySource`] from a small public
//! [`KeyHeader`] kept in a side file next to the database (`<db>.hdr`).
//!
//! Today the only source is [`Passphrase`] (Argon2id, RFC 9106). On phones the
//! key will later be wrapped by the hardware keystore: that is a second
//! [`KeySource`] implementation and needs no change to the storage code.

use std::{
    fmt,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use crate::error::TreeError;

/// Length of the database key in bytes (256 bits).
pub const KEY_LEN: usize = 32;
/// Length of the random per-database salt in bytes.
pub const SALT_LEN: usize = 32;

/// The 256-bit database key. Wiped from memory when dropped and never printed.
pub struct DbKey(Zeroizing<[u8; KEY_LEN]>);

impl DbKey {
    /// Wraps raw key bytes (for key sources other than [`Passphrase`]).
    /// The caller should wipe its own copy.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for DbKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DbKey(<redacted>)")
    }
}

/// Argon2id cost parameters. Stored in the key header so they can be raised
/// later without breaking existing databases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Number of passes over the memory.
    pub iterations: u32,
    /// Lanes. Kept at 1: the Argon2 crate computes lanes one after another,
    /// so more lanes would cost us time without costing an attacker more.
    pub parallelism: u32,
}

impl KdfParams {
    /// Default for new databases: 64 MiB, 3 passes, 1 lane.
    ///
    /// This is the memory-constrained profile of RFC 9106 (section 4) with
    /// one lane. It takes a fraction of a second on a current phone and makes
    /// every passphrase guess cost an attacker the same 64 MiB and 3 passes.
    pub const RECOMMENDED: Self = Self { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 };

    /// Weakest accepted setting (OWASP minimum for Argon2id: 19 MiB, 2 passes).
    pub const MIN: Self = Self { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };

    /// Strongest accepted setting. A header asking for more is treated as
    /// damaged, so a tampered header cannot make the app run out of memory.
    pub const MAX: Self = Self { memory_kib: 1024 * 1024, iterations: 16, parallelism: 4 };

    fn validate(&self) -> Result<(), TreeError> {
        let ok = |v: u32, lo: u32, hi: u32| (lo..=hi).contains(&v);
        if ok(self.memory_kib, Self::MIN.memory_kib, Self::MAX.memory_kib)
            && ok(self.iterations, Self::MIN.iterations, Self::MAX.iterations)
            && ok(self.parallelism, Self::MIN.parallelism, Self::MAX.parallelism)
        {
            Ok(())
        } else {
            Err(TreeError::Storage("key derivation parameters out of range".into()))
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::RECOMMENDED
    }
}

/// Public, non-secret data a [`KeySource`] needs to rebuild the database key.
///
/// File layout (54 bytes, integers little-endian):
/// `"TREEKEY\0"` | version 1 | kdf 1 = Argon2id v1.3 | memory_kib u32 |
/// iterations u32 | parallelism u32 | salt (32 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyHeader {
    pub params: KdfParams,
    pub salt: [u8; SALT_LEN],
}

impl KeyHeader {
    const MAGIC: &'static [u8; 8] = b"TREEKEY\0";
    const VERSION: u8 = 1;
    const KDF_ARGON2ID: u8 = 1;
    const LEN: usize = 8 + 1 + 1 + 4 * 3 + SALT_LEN;

    pub fn new(params: KdfParams, salt: [u8; SALT_LEN]) -> Result<Self, TreeError> {
        params.validate()?;
        Ok(Self { params, salt })
    }

    /// Path of the header file that belongs to the database at `db`.
    pub fn path_for(db: &Path) -> PathBuf {
        let mut p = db.as_os_str().to_owned();
        p.push(".hdr");
        PathBuf::from(p)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(Self::MAGIC);
        out.push(Self::VERSION);
        out.push(Self::KDF_ARGON2ID);
        out.extend_from_slice(&self.params.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.params.iterations.to_le_bytes());
        out.extend_from_slice(&self.params.parallelism.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, TreeError> {
        let bad = || TreeError::Storage("key header is damaged or not a Tree key header".into());
        if b.len() != Self::LEN || &b[..8] != Self::MAGIC {
            return Err(bad());
        }
        if b[8] != Self::VERSION || b[9] != Self::KDF_ARGON2ID {
            return Err(TreeError::Storage("unsupported key header version".into()));
        }
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let params = KdfParams { memory_kib: u32_at(10), iterations: u32_at(14), parallelism: u32_at(18) };
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&b[22..]);
        Self::new(params, salt)
    }

    pub(crate) fn read(db: &Path) -> Result<Self, TreeError> {
        let path = Self::path_for(db);
        let bytes = fs::read(&path).map_err(|e| {
            TreeError::Storage(format!("cannot read key header {}: {e}", path.display()))
        })?;
        Self::from_bytes(&bytes)
    }

    /// Writes the header file (owner-only permissions on Unix) and syncs it.
    pub(crate) fn write(&self, db: &Path) -> Result<(), TreeError> {
        let path = Self::path_for(db);
        let mut f = super::private_file(&path, true)?;
        f.write_all(&self.to_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| TreeError::Storage(format!("cannot write key header: {e}")))
    }
}

/// Produces the database key for a given header.
///
/// Implement this to plug in another key source, e.g. a key wrapped by the
/// Android Keystore or the iOS Secure Enclave. Implementations must return
/// the same key for the same header every time, and must not keep copies of
/// key material longer than needed.
pub trait KeySource {
    fn database_key(&self, header: &KeyHeader) -> Result<DbKey, TreeError>;
}

/// A user passphrase, stretched with Argon2id. Wiped from memory when dropped.
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    /// Copies the passphrase into memory that is wiped on drop. The caller
    /// should wipe or drop its own copy as soon as possible.
    pub fn new(passphrase: &str) -> Result<Self, TreeError> {
        if passphrase.is_empty() {
            return Err(TreeError::EmptyPassphrase);
        }
        Ok(Self(Zeroizing::new(passphrase.as_bytes().to_vec())))
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

impl KeySource for Passphrase {
    fn database_key(&self, header: &KeyHeader) -> Result<DbKey, TreeError> {
        header.params.validate()?;
        let p = &header.params;
        let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(KEY_LEN))
            .map_err(|e| TreeError::Storage(format!("argon2 parameters: {e}")))?;
        // Our own work memory, so it can be wiped afterwards (the crate frees
        // its internal buffer without wiping it).
        let mut memory = WorkMemory(vec![Block::new(); params.block_count()]);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(&self.0, &header.salt, out.as_mut(), memory.0.as_mut_slice())
            .map_err(|e| TreeError::Storage(format!("argon2: {e}")))?;
        Ok(DbKey(out))
    }
}

/// Argon2 work memory, wiped block by block when dropped.
pub(crate) struct WorkMemory(pub(crate) Vec<Block>);

impl Drop for WorkMemory {
    fn drop(&mut self) {
        for block in self.0.iter_mut() {
            zeroize::Zeroize::zeroize(block);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_and_validation() {
        let h = KeyHeader::new(KdfParams::RECOMMENDED, [7u8; SALT_LEN]).unwrap();
        assert_eq!(KeyHeader::from_bytes(&h.to_bytes()).unwrap(), h);

        let mut weak = h.to_bytes();
        weak[10..14].copy_from_slice(&1024u32.to_le_bytes()); // 1 MiB: too weak
        assert!(KeyHeader::from_bytes(&weak).is_err());
        let mut huge = h.to_bytes();
        huge[10..14].copy_from_slice(&u32::MAX.to_le_bytes()); // would exhaust memory
        assert!(KeyHeader::from_bytes(&huge).is_err());
        assert!(KeyHeader::from_bytes(&h.to_bytes()[..20]).is_err());
    }

    #[test]
    fn passphrase_key_depends_on_passphrase_and_salt() {
        let h1 = KeyHeader::new(KdfParams::MIN, [1u8; SALT_LEN]).unwrap();
        let h2 = KeyHeader::new(KdfParams::MIN, [2u8; SALT_LEN]).unwrap();
        let a = Passphrase::new("correct horse").unwrap();
        let b = Passphrase::new("correct horsf").unwrap();
        let k = |p: &Passphrase, h: &KeyHeader| *p.database_key(h).unwrap().as_bytes();
        assert_eq!(k(&a, &h1), k(&a, &h1));
        assert_ne!(k(&a, &h1), k(&b, &h1));
        assert_ne!(k(&a, &h1), k(&a, &h2));
        assert!(Passphrase::new("").is_err());
        assert_eq!(format!("{a:?}"), "Passphrase(<redacted>)");
    }
}
