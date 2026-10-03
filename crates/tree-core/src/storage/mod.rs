//! Encrypted local storage.
//!
//! One SQLCipher database file per device holds the identity (signing key,
//! name, credential, ciphersuite) and the full OpenMLS state of every group,
//! so everything survives a restart.
//!
//! * Encryption: SQLCipher 4 (AES-256 page encryption with HMAC-SHA512 per
//!   page). The 256-bit key is handed over in raw form, so SQLCipher's own
//!   password stretching is skipped; stretching is done by the [`KeySource`].
//! * Key: rebuilt on every unlock from the side file `<db>.hdr` by a
//!   [`KeySource`] ([`Passphrase`] = Argon2id today).
//! * OpenMLS tables: `openmls_sqlite_storage`, unchanged.
//! * Tree tables: `tree_meta` (identity), `tree_groups` (group list) and
//!   `tree_group_state` (pending commit, past envelope keys; see
//!   `group_state.rs`).
//! * Each group operation runs in one transaction ([`TreeProvider::atomically`]),
//!   so a crash leaves either the old or the new state, never half of each.

mod forward;
pub mod key;
#[cfg(test)]
mod tests;

use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::{ffi, params, Connection, OpenFlags, OptionalExtension};
use zeroize::Zeroizing;

pub use key::{DbKey, KdfParams, KeyHeader, KeySource, Passphrase};

use crate::{error::TreeError, provider::TreeProvider};

/// Version of Tree's own tables (`PRAGMA user_version`).
/// 1: `tree_meta`, `tree_groups`. 2: + `tree_group_state`.
const TREE_SCHEMA_VERSION: i64 = 2;

/// Tree tables added after version 1 (idempotent).
const TREE_TABLES_V2: &str =
    "CREATE TABLE IF NOT EXISTS tree_group_state (group_id BLOB PRIMARY KEY, state BLOB NOT NULL) WITHOUT ROWID;";

/// Serialises OpenMLS objects as JSON before they are stored (and encrypted
/// by SQLCipher). JSON is the format the OpenMLS storage crates are tested with.
#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// The OpenMLS SQLite provider borrowing our connection for one call.
pub(crate) type Sql<'a> = SqliteStorageProvider<JsonCodec, &'a Connection>;

/// OpenMLS storage on an encrypted SQLite connection.
pub struct SqlStorage {
    conn: Connection,
}

impl SqlStorage {
    fn sql(&self) -> Sql<'_> {
        SqliteStorageProvider::new(&self.conn)
    }
}

/// Crypto provider with persistent, encrypted storage: RustCrypto primitives
/// (same as [`crate::DefaultProvider`]) plus [`SqlStorage`].
pub struct StoredProvider {
    crypto: RustCrypto,
    storage: SqlStorage,
}

impl OpenMlsProvider for StoredProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqlStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl TreeProvider for StoredProvider {
    fn atomically<T>(&self, op: impl FnOnce() -> Result<T, TreeError>) -> Result<T, TreeError> {
        let conn = &self.storage.conn;
        conn.execute_batch("SAVEPOINT tree_op")
            .map_err(storage_err)?;
        let result = op();
        // Commit even when `op` failed: OpenMLS keeps its in-memory group and
        // its storage in step as it goes, so whatever it wrote matches the
        // in-memory state. Only a crash (no commit at all) rolls back.
        if let Err(e) = conn.execute_batch("RELEASE tree_op") {
            let _ = conn.execute_batch("ROLLBACK TO tree_op; RELEASE tree_op");
            return Err(TreeError::Storage(format!(
                "could not save; reload the group before continuing: {e}"
            )));
        }
        result
    }

    fn remember_group(&self, group_id: &[u8]) -> Result<(), TreeError> {
        self.storage
            .conn
            .execute(
                "INSERT OR IGNORE INTO tree_groups (group_id) VALUES (?1)",
                params![group_id],
            )
            .map(|_| ())
            .map_err(storage_err)
    }

    fn save_group_state(&self, group_id: &[u8], state: &[u8]) -> Result<(), TreeError> {
        self.storage
            .conn
            .execute(
                "INSERT OR REPLACE INTO tree_group_state (group_id, state) VALUES (?1, ?2)",
                params![group_id, state],
            )
            .map(|_| ())
            .map_err(storage_err)
    }

    fn put_meta(&self, key: &str, value: &[u8]) -> Result<(), TreeError> {
        self.storage
            .conn
            .execute(
                "INSERT OR REPLACE INTO tree_meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map(|_| ())
            .map_err(storage_err)
    }

    fn meta_optional(&self, key: &str) -> Result<Option<Vec<u8>>, TreeError> {
        self.storage
            .conn
            .query_row(
                "SELECT value FROM tree_meta WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage_err)
    }

    fn delete_meta(&self, key: &str) -> Result<(), TreeError> {
        self.storage
            .conn
            .execute("DELETE FROM tree_meta WHERE key = ?1", params![key])
            .map(|_| ())
            .map_err(storage_err)
    }
}

impl StoredProvider {
    /// Reads back what [`TreeProvider::save_group_state`] stored.
    pub(crate) fn load_group_state(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, TreeError> {
        self.storage
            .conn
            .query_row(
                "SELECT state FROM tree_group_state WHERE group_id = ?1",
                params![group_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage_err)
    }

    /// Creates a new encrypted database at `path` (which must not exist yet)
    /// and its key header next to it.
    pub(crate) fn create(
        path: &Path,
        source: &dyn KeySource,
        params: KdfParams,
    ) -> Result<Self, TreeError> {
        let header_path = KeyHeader::path_for(path);
        if path.exists() {
            return Err(TreeError::Storage(format!(
                "{} already exists",
                path.display()
            )));
        }
        if fs::symlink_metadata(&header_path).is_ok() {
            return Err(TreeError::Storage(format!(
                "{} already exists",
                header_path.display()
            )));
        }
        let crypto = RustCrypto::default();
        let salt: [u8; key::SALT_LEN] = openmls_traits::random::OpenMlsRand::random_array(&crypto)
            .map_err(|e| TreeError::Storage(format!("random: {e:?}")))?;
        let header = KeyHeader::new(params, salt)?;
        let db_key = source.database_key(&header)?;

        // Create the file ourselves (fails if it appeared meanwhile, so the
        // cleanup below can only ever delete files made here). Owner-only from
        // the start; SQLite gives its journal files the same permissions.
        drop(private_file(path, false)?);
        let build = || -> Result<Self, TreeError> {
            header.write(path)?;
            let mut conn = open_connection(path, Some(&db_key))?;
            migrate(&mut conn)?;
            conn.execute_batch(
                "BEGIN;
                 CREATE TABLE tree_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
                 CREATE TABLE tree_groups (
                     seq INTEGER PRIMARY KEY AUTOINCREMENT,
                     group_id BLOB NOT NULL UNIQUE
                 );
                 COMMIT;",
            )
            .map_err(storage_err)?;
            conn.execute_batch(TREE_TABLES_V2).map_err(storage_err)?;
            conn.pragma_update(None, "user_version", TREE_SCHEMA_VERSION)
                .map_err(storage_err)?;
            Ok(Self {
                crypto,
                storage: SqlStorage { conn },
            })
        };
        build().inspect_err(|_| {
            // Never leave a half-made identity behind.
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(&header_path);
        })
    }

    /// Opens an existing database. A wrong key gives [`TreeError::WrongKey`].
    pub(crate) fn open(path: &Path, source: &dyn KeySource) -> Result<Self, TreeError> {
        let meta = fs::symlink_metadata(path).map_err(|e| {
            TreeError::Storage(format!("cannot stat {}: {e}", path.display()))
        })?;
        if !meta.file_type().is_file() {
            return Err(TreeError::Storage(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        let header_path = KeyHeader::path_for(path);
        let header_meta = fs::symlink_metadata(&header_path).map_err(|e| {
            TreeError::Storage(format!("cannot stat {}: {e}", header_path.display()))
        })?;
        if !header_meta.file_type().is_file() {
            return Err(TreeError::Storage(format!(
                "{} is not a regular file",
                header_path.display()
            )));
        }
        let header = KeyHeader::read(path)?;
        let db_key = source.database_key(&header)?;
        let mut conn = open_connection(path, Some(&db_key))?;
        drop(db_key);
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(storage_err)?;
        if !(1..=TREE_SCHEMA_VERSION).contains(&version) {
            return Err(TreeError::Storage(format!(
                "unsupported database version {version}"
            )));
        }
        migrate(&mut conn)?;
        if version < TREE_SCHEMA_VERSION {
            conn.execute_batch(TREE_TABLES_V2).map_err(storage_err)?;
            conn.pragma_update(None, "user_version", TREE_SCHEMA_VERSION)
                .map_err(storage_err)?;
        }
        Ok(Self {
            crypto: RustCrypto::default(),
            storage: SqlStorage { conn },
        })
    }

    /// Unencrypted database, only to prove in tests that the scan for
    /// plaintext would find it.
    #[cfg(test)]
    pub(crate) fn create_unencrypted_for_test(path: &Path) -> Result<Self, TreeError> {
        let mut conn = Connection::open(path).map_err(storage_err)?;
        migrate(&mut conn)?;
        conn.execute_batch(
            "CREATE TABLE tree_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE tree_groups (seq INTEGER PRIMARY KEY AUTOINCREMENT, group_id BLOB NOT NULL UNIQUE);",
        )
        .map_err(storage_err)?;
        conn.execute_batch(TREE_TABLES_V2).map_err(storage_err)?;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage: SqlStorage { conn },
        })
    }

    pub(crate) fn put_meta(&self, key: &str, value: &[u8]) -> Result<(), TreeError> {
        self.storage
            .conn
            .execute(
                "INSERT OR REPLACE INTO tree_meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map(|_| ())
            .map_err(storage_err)
    }

    pub(crate) fn meta(&self, key: &str) -> Result<Vec<u8>, TreeError> {
        self.storage
            .conn
            .query_row(
                "SELECT value FROM tree_meta WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage_err)?
            .ok_or_else(|| TreeError::Storage(format!("identity record {key:?} missing")))
    }

    pub(crate) fn meta_optional(&self, key: &str) -> Result<Option<Vec<u8>>, TreeError> {
        self.storage
            .conn
            .query_row(
                "SELECT value FROM tree_meta WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage_err)
    }

    pub(crate) fn group_ids(&self) -> Result<Vec<Vec<u8>>, TreeError> {
        let mut stmt = self
            .storage
            .conn
            .prepare("SELECT group_id FROM tree_groups ORDER BY seq")
            .map_err(storage_err)?;
        let rows = stmt.query_map([], |r| r.get(0)).map_err(storage_err)?;
        rows.collect::<Result<Vec<Vec<u8>>, _>>()
            .map_err(storage_err)
    }
}

pub(crate) fn storage_err(e: impl std::fmt::Display) -> TreeError {
    TreeError::Storage(e.to_string())
}

/// Creates (or truncates) a file readable only by its owner on Unix.
pub(crate) fn private_file(path: &Path, truncate: bool) -> Result<File, TreeError> {
    let mut o = OpenOptions::new();
    o.write(true);
    if truncate {
        o.create(true).truncate(true);
    } else {
        o.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
        .map_err(|e| TreeError::Storage(format!("cannot create {}: {e}", path.display())))
}

/// Runs the OpenMLS storage migrations (idempotent).
fn migrate(conn: &mut Connection) -> Result<(), TreeError> {
    SqliteStorageProvider::<JsonCodec, &mut Connection>::new(conn)
        .run_migrations()
        .map_err(|e| TreeError::Storage(format!("storage migration: {e}")))
}

/// Opens an existing database file, unlocks it and checks the key.
fn open_connection(path: &Path, key: Option<&DbKey>) -> Result<Connection, TreeError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags).map_err(storage_err)?;
    // SQLCipher would otherwise write its own error log to stderr / logcat
    // (e.g. on every wrong passphrase). Errors still reach the caller.
    conn.pragma_update(None, "cipher_log_level", "NONE")
        .map_err(storage_err)?;
    if let Some(key) = key {
        apply_key(&conn, key)?;
    }

    // Refuse to run on a SQLite build without encryption: there `key` would
    // be silently ignored and everything written in the clear.
    let cipher: Option<String> = conn
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .optional()
        .map_err(storage_err)?;
    if cipher.is_none() {
        return Err(TreeError::Storage(
            "SQLite was built without SQLCipher".into(),
        ));
    }

    // Reading the schema decrypts and authenticates page 1: a wrong key or a
    // modified file fails here.
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    }) {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::NotADatabase =>
        {
            return Err(TreeError::WrongKey)
        }
        Err(e) => return Err(storage_err(e)),
    }

    // secure_delete: deleted rows (old epoch secrets, used key packages) are
    // overwritten, not left in free pages where a later key leak would expose
    // them. temp_store: temporary tables stay in memory, never on disk.
    conn.execute_batch("PRAGMA secure_delete = ON; PRAGMA temp_store = MEMORY;")
        .map_err(storage_err)?;
    Ok(conn)
}

/// Hands the raw 256-bit key to SQLCipher through `sqlite3_key`, so the key
/// never passes through SQL text. Form `x'<64 hex digits>'` = raw key.
fn apply_key(conn: &Connection, key: &DbKey) -> Result<(), TreeError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut spec = Zeroizing::new(Vec::with_capacity(3 + 2 * key::KEY_LEN));
    spec.extend_from_slice(b"x'");
    for b in key.as_bytes() {
        spec.push(HEX[(b >> 4) as usize]);
        spec.push(HEX[(b & 0x0f) as usize]);
    }
    spec.push(b'\'');
    // SAFETY: `conn.handle()` is the live database handle owned by `conn`;
    // SQLCipher copies the key bytes before returning and does not keep the
    // pointer. `spec` outlives the call.
    let rc = unsafe {
        ffi::sqlite3_key(
            conn.handle(),
            spec.as_ptr().cast(),
            spec.len() as std::os::raw::c_int,
        )
    };
    if rc != ffi::SQLITE_OK {
        return Err(TreeError::Storage(format!("sqlite3_key failed ({rc})")));
    }
    Ok(())
}
