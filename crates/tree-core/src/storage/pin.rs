//! PIN unlock: a second, opt-in way to rebuild the database key
//! (`user.app_lock` with the option `pin`; PROTOCOL.md 8.13).
//!
//! The database key never changes. Enabling a PIN derives the key from the
//! passphrase as usual, checks it against the database, and stores a copy of
//! it in the side file `<db>.pin`, encrypted with AES-256-GCM under a key
//! that Argon2id (RFC 9106) derives from the PIN and a fresh salt. The
//! passphrase keeps working, and removing the PIN file leaves the database
//! exactly as it was.
//!
//! Security level, honestly: a six-digit PIN has 10^6 possible values. To
//! anyone who copies the files off the device, the PIN file is only as strong
//! as those 10^6 Argon2id guesses (64 MiB, 3 passes each): roughly a day on
//! one desktop core, much less with many machines. The passphrase file alone
//! is as strong as the passphrase. So a PIN trades strength against an
//! offline attacker for convenience, and the app says so before enabling it.
//!
//! Two things limit the damage:
//!
//! * **The attempt limit** ([`PIN_MAX_ATTEMPTS`]). Every attempt is counted
//!   in the file *before* the key is derived (a crash or a killed app still
//!   counts). After the last failed attempt the PIN file is overwritten and
//!   deleted, and only the passphrase opens the profile. This stops guessing
//!   through the app, which is what someone holding an unlocked-then-locked
//!   phone can do. It does not stop someone who copied the file: the counter
//!   is in the file they copied. That is why the limit matters and why it is
//!   not enough on its own.
//! * **A device secret** (optional). The platform may pass a secret it keeps
//!   in hardware-backed storage (on Android: a random value encrypted by a
//!   non-exportable key of the system keystore). It enters Argon2id as the
//!   standard secret input `K`, so guessing the PIN offline also needs that
//!   secret, which a copy of the files does not contain. Where no such
//!   storage exists (desktops today), there is no device secret and the
//!   paragraph above applies in full.
//!
//! File layout (`<db>.pin`, integers little-endian):
//! `"TREEPIN\0"` | version 1 | flags (bit 0: a device secret was used) |
//! memory_kib u32 | iterations u32 | parallelism u32 | salt (32) |
//! nonce (12) | AES-256-GCM(database key) (32 + 16) | failed attempts u8.
//! Everything before the ciphertext is the associated data, so the cost
//! parameters and the salt cannot be changed without the unlock failing.
//! The failure counter is the last byte and is not authenticated: changing
//! it needs write access to the file, and with that an attacker can copy
//! the file anyway.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use super::key::{DbKey, KdfParams, KeyHeader, KeySource, Passphrase, WorkMemory, KEY_LEN, SALT_LEN};
use crate::error::TreeError;

/// Failed PIN attempts before the PIN stops working and the passphrase is
/// needed (the PIN file is wiped).
pub const PIN_MAX_ATTEMPTS: u8 = 10;
/// Shortest and longest PIN, in digits.
pub const PIN_MIN_DIGITS: usize = 6;
pub const PIN_MAX_DIGITS: usize = 16;

const MAGIC: &[u8; 8] = b"TREEPIN\0";
const VERSION: u8 = 1;
const FLAG_DEVICE_SECRET: u8 = 1;
const NONCE_LEN: usize = 12;
const CT_LEN: usize = KEY_LEN + 16;
const AAD_LEN: usize = 8 + 1 + 1 + 12 + SALT_LEN + NONCE_LEN;
const FILE_LEN: usize = AAD_LEN + CT_LEN + 1;
/// Device secrets longer than this are refused (Argon2 accepts any length;
/// a platform secret is 32 bytes).
const MAX_SECRET: usize = 64;

/// Where the PIN stands on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinState {
    /// A PIN file exists and can still be used.
    pub enabled: bool,
    /// Attempts left before the passphrase is needed (0 when not enabled).
    pub attempts_left: u8,
    /// The PIN was enabled together with a device secret.
    pub device_secret: bool,
}

/// Path of the PIN file that belongs to the database at `db`.
pub fn pin_path(db: &Path) -> PathBuf {
    let mut p = db.as_os_str().to_owned();
    p.push(".pin");
    PathBuf::from(p)
}

fn check_pin(pin: &str) -> Result<(), TreeError> {
    let n = pin.chars().count();
    if !(PIN_MIN_DIGITS..=PIN_MAX_DIGITS).contains(&n) || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(TreeError::Storage(format!("a PIN is {PIN_MIN_DIGITS} to {PIN_MAX_DIGITS} digits")));
    }
    Ok(())
}

fn check_secret(secret: Option<&[u8]>) -> Result<(), TreeError> {
    match secret {
        Some(s) if s.is_empty() || s.len() > MAX_SECRET => Err(TreeError::Storage("device secret must be 1 to 64 bytes".into())),
        _ => Ok(()),
    }
}

fn random<const N: usize>() -> Result<[u8; N], TreeError> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| TreeError::Storage(format!("random: {e}")))?;
    Ok(b)
}

/// Argon2id(PIN, salt, secret = device secret) -> 256-bit wrapping key.
fn pin_key(pin: &str, salt: &[u8; SALT_LEN], params: &KdfParams, secret: Option<&[u8]>) -> Result<Zeroizing<[u8; KEY_LEN]>, TreeError> {
    let p = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_LEN))
        .map_err(|e| TreeError::Storage(format!("argon2 parameters: {e}")))?;
    let a = match secret {
        Some(s) => Argon2::new_with_secret(s, Algorithm::Argon2id, Version::V0x13, p.clone())
            .map_err(|e| TreeError::Storage(format!("argon2: {e}")))?,
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, p.clone()),
    };
    let mut memory = WorkMemory(vec![Block::new(); p.block_count()]);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    a.hash_password_into_with_memory(pin.as_bytes(), salt, out.as_mut(), memory.0.as_mut_slice())
        .map_err(|e| TreeError::Storage(format!("argon2: {e}")))?;
    Ok(out)
}

/// The parsed PIN file.
struct PinFile {
    flags: u8,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ct: [u8; CT_LEN],
    failures: u8,
}

impl PinFile {
    fn aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AAD_LEN);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.flags);
        out.extend_from_slice(&self.params.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.params.iterations.to_le_bytes());
        out.extend_from_slice(&self.params.parallelism.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.aad();
        out.extend_from_slice(&self.ct);
        out.push(self.failures);
        out
    }

    fn from_bytes(b: &[u8]) -> Result<Self, TreeError> {
        let bad = || TreeError::Storage("PIN file is damaged".into());
        if b.len() != FILE_LEN || &b[..8] != MAGIC || b[8] != VERSION {
            return Err(bad());
        }
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let params = KdfParams { memory_kib: u32_at(10), iterations: u32_at(14), parallelism: u32_at(18) };
        // Same bounds as the passphrase header: a tampered file cannot make
        // the app run out of memory or derive with a weak setting.
        KeyHeader::new(params, [0; SALT_LEN]).map_err(|_| bad())?;
        let mut f = PinFile { flags: b[9], params, salt: [0; SALT_LEN], nonce: [0; NONCE_LEN], ct: [0; CT_LEN], failures: b[FILE_LEN - 1] };
        f.salt.copy_from_slice(&b[22..22 + SALT_LEN]);
        f.nonce.copy_from_slice(&b[22 + SALT_LEN..AAD_LEN]);
        f.ct.copy_from_slice(&b[AAD_LEN..AAD_LEN + CT_LEN]);
        Ok(f)
    }

    fn read(db: &Path) -> Result<Option<Self>, TreeError> {
        match fs::read(pin_path(db)) {
            Ok(b) => Self::from_bytes(&b).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(TreeError::Storage(format!("cannot read the PIN file: {e}"))),
        }
    }

    /// Replaces the file in one step (write a temporary file, sync, rename),
    /// so a crash leaves the old or the new counter, never a broken file.
    fn write(&self, db: &Path) -> Result<(), TreeError> {
        let path = pin_path(db);
        let mut tmp = path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let mut f = super::private_file(&tmp, true)?;
        f.write_all(&self.to_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| TreeError::Storage(format!("cannot write the PIN file: {e}")))?;
        drop(f);
        fs::rename(&tmp, &path).map_err(|e| TreeError::Storage(format!("cannot write the PIN file: {e}")))
    }
}

/// Turns PIN unlock on (or changes the PIN) for the database at `db`. The
/// passphrase is needed: it rebuilds the database key, which is checked
/// against the database before anything is written. `device_secret`: see
/// the module documentation; the same secret must be given to unlock.
pub fn enable_pin(db: &Path, passphrase: &Passphrase, pin: &str, device_secret: Option<&[u8]>) -> Result<(), TreeError> {
    enable_pin_with(db, passphrase, pin, device_secret, KdfParams::RECOMMENDED)
}

/// [`enable_pin`] with explicit Argon2id costs (tests use the minimum).
pub fn enable_pin_with(db: &Path, passphrase: &Passphrase, pin: &str, device_secret: Option<&[u8]>, params: KdfParams) -> Result<(), TreeError> {
    check_pin(pin)?;
    check_secret(device_secret)?;
    KeyHeader::new(params, [0; SALT_LEN])?;
    let db_key = verified_key(db, passphrase)?;
    let salt = random::<SALT_LEN>()?;
    let nonce = random::<NONCE_LEN>()?;
    let wrap = pin_key(pin, &salt, &params, device_secret)?;
    let flags = if device_secret.is_some() { FLAG_DEVICE_SECRET } else { 0 };
    let mut file = PinFile { flags, params, salt, nonce, ct: [0; CT_LEN], failures: 0 };
    let aad = file.aad();
    let ct = Aes256Gcm::new(wrap.as_ref().into())
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: db_key.as_bytes(), aad: &aad })
        .map_err(|_| TreeError::Storage("could not encrypt the PIN file".into()))?;
    file.ct.copy_from_slice(&ct);
    file.write(db)
}

/// The database key from the passphrase, checked against the database.
pub(crate) fn verified_key(db: &Path, passphrase: &Passphrase) -> Result<DbKey, TreeError> {
    let header = KeyHeader::read(db)?;
    let key = passphrase.database_key(&header)?;
    drop(super::open_connection(db, Some(&key))?);
    Ok(key)
}

/// Turns PIN unlock off: the PIN file is overwritten and deleted. The
/// passphrase is unaffected. Idempotent.
pub fn disable_pin(db: &Path) -> Result<(), TreeError> {
    let mut tmp = pin_path(db).into_os_string();
    tmp.push(".tmp");
    wipe(Path::new(&tmp))?;
    wipe(&pin_path(db))
}

fn wipe(path: &Path) -> Result<(), TreeError> {
    match fs::metadata(path) {
        Ok(m) => {
            // Overwrite first (on flash storage the old blocks may survive
            // elsewhere; the file only ever held ciphertext).
            if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
                let _ = f.write_all(&vec![0u8; m.len() as usize]).and_then(|_| f.sync_all());
            }
            fs::remove_file(path).map_err(|e| TreeError::Storage(format!("cannot delete the PIN file: {e}")))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(TreeError::Storage(format!("cannot read the PIN file: {e}"))),
    }
}

/// Whether PIN unlock is available for the database at `db`.
pub fn pin_state(db: &Path) -> PinState {
    match PinFile::read(db) {
        Ok(Some(f)) if f.failures < PIN_MAX_ATTEMPTS => PinState {
            enabled: true,
            attempts_left: PIN_MAX_ATTEMPTS - f.failures,
            device_secret: f.flags & FLAG_DEVICE_SECRET != 0,
        },
        _ => PinState { enabled: false, attempts_left: 0, device_secret: false },
    }
}

/// A PIN typed by the user, with the platform's device secret if any.
/// As a [`KeySource`], each use is one counted attempt.
pub struct Pin {
    pin: Zeroizing<String>,
    secret: Option<Zeroizing<Vec<u8>>>,
    db: PathBuf,
}

impl Pin {
    pub fn new(db: &Path, pin: &str, device_secret: Option<&[u8]>) -> Result<Self, TreeError> {
        check_secret(device_secret)?;
        Ok(Self { pin: Zeroizing::new(pin.to_string()), secret: device_secret.map(|s| Zeroizing::new(s.to_vec())), db: db.to_path_buf() })
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pin(<redacted>)")
    }
}

impl KeySource for Pin {
    fn database_key(&self, _header: &KeyHeader) -> Result<DbKey, TreeError> {
        let Some(mut file) = PinFile::read(&self.db)? else {
            return Err(TreeError::PinUnavailable);
        };
        if file.failures >= PIN_MAX_ATTEMPTS {
            wipe(&pin_path(&self.db))?;
            return Err(TreeError::PinUnavailable);
        }
        // Count the attempt before trying it.
        file.failures += 1;
        file.write(&self.db)?;
        let failed = |file: &PinFile| -> TreeError {
            if file.failures >= PIN_MAX_ATTEMPTS {
                let _ = wipe(&pin_path(&self.db));
                TreeError::PinUnavailable
            } else {
                TreeError::WrongPin(PIN_MAX_ATTEMPTS - file.failures)
            }
        };
        if check_pin(&self.pin).is_err() || (file.flags & FLAG_DEVICE_SECRET != 0) != self.secret.is_some() {
            return Err(failed(&file));
        }
        let wrap = pin_key(&self.pin, &file.salt, &file.params, self.secret.as_deref().map(|s| s.as_slice()))?;
        let aad = file.aad();
        let plain = Aes256Gcm::new(wrap.as_ref().into()).decrypt(Nonce::from_slice(&file.nonce), Payload { msg: &file.ct, aad: &aad });
        match plain {
            Ok(p) => {
                let p = Zeroizing::new(p);
                let mut k = [0u8; KEY_LEN];
                k.copy_from_slice(&p);
                file.failures = 0;
                file.write(&self.db)?;
                Ok(DbKey::from_bytes(k))
            }
            Err(_) => Err(failed(&file)),
        }
    }
}

impl KeySource for DbKey {
    /// A key the platform kept wrapped itself (e.g. by a biometric-bound
    /// key of the system keystore) and unwrapped for this unlock.
    fn database_key(&self, _header: &KeyHeader) -> Result<DbKey, TreeError> {
        Ok(DbKey::from_bytes(*self.as_bytes()))
    }
}

/// The database key for a platform keystore to wrap (biometric unlock):
/// rebuilt from the passphrase and checked against the database. The
/// caller must wrap it at once and wipe its copy.
pub fn key_for_platform_wrap(db: &Path, passphrase: &Passphrase) -> Result<Zeroizing<[u8; KEY_LEN]>, TreeError> {
    let k = verified_key(db, passphrase)?;
    Ok(Zeroizing::new(*k.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_roundtrip_and_tamper() {
        let f = PinFile { flags: 1, params: KdfParams::MIN, salt: [3; SALT_LEN], nonce: [4; NONCE_LEN], ct: [5; CT_LEN], failures: 2 };
        let b = f.to_bytes();
        assert_eq!(b.len(), FILE_LEN);
        let g = PinFile::from_bytes(&b).unwrap();
        assert_eq!((g.flags, g.params, g.salt, g.nonce, g.ct, g.failures), (1, KdfParams::MIN, [3; SALT_LEN], [4; NONCE_LEN], [5; CT_LEN], 2));
        let mut weak = b.clone();
        weak[10..14].copy_from_slice(&1u32.to_le_bytes());
        assert!(PinFile::from_bytes(&weak).is_err(), "too weak parameters are refused");
        assert!(PinFile::from_bytes(&b[..10]).is_err());
    }

    #[test]
    fn pin_format() {
        assert!(check_pin("123456").is_ok());
        assert!(check_pin("12345").is_err());
        assert!(check_pin("12345a").is_err());
        assert!(check_pin(&"1".repeat(17)).is_err());
    }
}
