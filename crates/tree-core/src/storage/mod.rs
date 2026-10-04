//! Encrypted local storage.
//!
//! One SQLCipher database file per device holds identity, OpenMLS state and
//! Tree messenger data. Plaintext message history never leaves this database.

mod forward;
pub mod key;
#[cfg(test)]
mod tests;

use std::{fs::{self, File, OpenOptions}, path::Path};

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::{ffi, params, Connection, OpenFlags, OptionalExtension};
use zeroize::Zeroizing;

pub use key::{DbKey, KdfParams, KeyHeader, KeySource, Passphrase};
use crate::{error::TreeError, provider::TreeProvider};

const TREE_SCHEMA_VERSION: i64 = 3;
const TREE_TABLES_V2: &str = "CREATE TABLE IF NOT EXISTS tree_group_state (group_id BLOB PRIMARY KEY, state BLOB NOT NULL) WITHOUT ROWID;";
const TREE_TABLES_V3: &str = r#"
CREATE TABLE IF NOT EXISTS tree_messages (
    group_id BLOB NOT NULL,
    message_id BLOB NOT NULL,
    sender_member_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    edited_at INTEGER,
    expires_at INTEGER,
    view_once INTEGER NOT NULL,
    deleted INTEGER NOT NULL,
    body BLOB NOT NULL,
    reply_to BLOB,
    media_manifest BLOB,
    PRIMARY KEY (group_id, message_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS tree_messages_group_seq ON tree_messages(group_id, sequence);
CREATE INDEX IF NOT EXISTS tree_messages_group_created ON tree_messages(group_id, created_at);
CREATE TABLE IF NOT EXISTS tree_message_mutations (
    group_id BLOB NOT NULL,
    mutation_id BLOB NOT NULL,
    target_message_id BLOB,
    sender_member_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    kind INTEGER NOT NULL,
    payload BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, mutation_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS tree_message_mutations_target ON tree_message_mutations(group_id, target_message_id, sequence);
CREATE TABLE IF NOT EXISTS tree_outbox (
    local_id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL,
    message_id BLOB,
    kind INTEGER NOT NULL,
    envelope BLOB NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_retry_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_error_code TEXT,
    server_id TEXT
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS tree_outbox_retry ON tree_outbox(state, next_retry_at);
CREATE TABLE IF NOT EXISTS tree_inbox_cursor (
    device_id BLOB PRIMARY KEY,
    cursor TEXT NOT NULL,
    updated_at INTEGER NOT NULL
) WITHOUT ROWID;
"#;

#[derive(Default)]
pub struct JsonCodec;
impl Codec for JsonCodec {
    type Error = serde_json::Error;
    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> { serde_json::to_vec(value) }
    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> { serde_json::from_slice(slice) }
}

pub(crate) type Sql<'a> = SqliteStorageProvider<JsonCodec, &'a Connection>;
pub struct SqlStorage { conn: Connection }
impl SqlStorage { fn sql(&self) -> Sql<'_> { SqliteStorageProvider::new(&self.conn) } }
pub struct StoredProvider { crypto: RustCrypto, storage: SqlStorage }
impl OpenMlsProvider for StoredProvider {
    type CryptoProvider = RustCrypto; type RandProvider = RustCrypto; type StorageProvider = SqlStorage;
    fn storage(&self) -> &Self::StorageProvider { &self.storage }
    fn crypto(&self) -> &Self::CryptoProvider { &self.crypto }
    fn rand(&self) -> &Self::RandProvider { &self.crypto }
}
impl TreeProvider for StoredProvider {
    fn atomically<T>(&self, op: impl FnOnce() -> Result<T, TreeError>) -> Result<T, TreeError> {
        let conn = &self.storage.conn;
        conn.execute_batch("SAVEPOINT tree_op").map_err(storage_err)?;
        match op() {
            Ok(value) => { if let Err(e)=conn.execute_batch("RELEASE tree_op") { let _=conn.execute_batch("ROLLBACK TO tree_op; RELEASE tree_op"); return Err(TreeError::Storage(format!("could not save; reload the group before continuing: {e}"))); } Ok(value) }
            Err(err) => { if let Err(e)=conn.execute_batch("ROLLBACK TO tree_op; RELEASE tree_op") { return Err(TreeError::Storage(format!("operation failed ({err}) and rollback failed: {e}"))); } Err(err) }
        }
    }
    fn remember_group(&self, group_id:&[u8])->Result<(),TreeError>{ self.storage.conn.execute("INSERT OR IGNORE INTO tree_groups (group_id) VALUES (?1)",params![group_id]).map(|_|()).map_err(storage_err) }
    fn save_group_state(&self,group_id:&[u8],state:&[u8])->Result<(),TreeError>{self.storage.conn.execute("INSERT OR REPLACE INTO tree_group_state (group_id,state) VALUES (?1,?2)",params![group_id,state]).map(|_|()).map_err(storage_err)}
    fn load_group_state(&self,group_id:&[u8])->Result<Option<Vec<u8>>,TreeError>{self.storage.conn.query_row("SELECT state FROM tree_group_state WHERE group_id=?1",params![group_id],|r|r.get(0)).optional().map_err(storage_err)}
    fn reload_group_after_error(&self)->bool{true}
    fn put_meta(&self,key:&str,value:&[u8])->Result<(),TreeError>{self.storage.conn.execute("INSERT OR REPLACE INTO tree_meta (key,value) VALUES (?1,?2)",params![key,value]).map(|_|()).map_err(storage_err)}
    fn meta_optional(&self,key:&str)->Result<Option<Vec<u8>>,TreeError>{self.storage.conn.query_row("SELECT value FROM tree_meta WHERE key=?1",params![key],|r|r.get(0)).optional().map_err(storage_err)}
    fn delete_meta(&self,key:&str)->Result<(),TreeError>{self.storage.conn.execute("DELETE FROM tree_meta WHERE key=?1",params![key]).map(|_|()).map_err(storage_err)}
}
impl StoredProvider {
    pub(crate) fn load_group_state(&self,group_id:&[u8])->Result<Option<Vec<u8>>,TreeError>{self.storage.conn.query_row("SELECT state FROM tree_group_state WHERE group_id=?1",params![group_id],|r|r.get(0)).optional().map_err(storage_err)}
    pub(crate) fn create(path:&Path,source:&dyn KeySource,params:KdfParams)->Result<Self,TreeError>{
        let header_path=KeyHeader::path_for(path); if path.exists(){return Err(TreeError::Storage(format!("{} already exists",path.display())))} if fs::symlink_metadata(&header_path).is_ok(){return Err(TreeError::Storage(format!("{} already exists",header_path.display())))}
        let crypto=RustCrypto::default(); let salt:[u8;key::SALT_LEN]=openmls_traits::random::OpenMlsRand::random_array(&crypto).map_err(|e|TreeError::Storage(format!("random: {e:?}")))?; let header=KeyHeader::new(params,salt)?; let db_key=source.database_key(&header)?; drop(private_file(path,false)?);
        let build=||->Result<Self,TreeError>{header.write(path)?; let mut conn=open_connection(path,Some(&db_key))?; migrate(&mut conn)?; conn.execute_batch("BEGIN; CREATE TABLE tree_meta (key TEXT PRIMARY KEY,value BLOB NOT NULL) WITHOUT ROWID; CREATE TABLE tree_groups (seq INTEGER PRIMARY KEY AUTOINCREMENT,group_id BLOB NOT NULL UNIQUE); COMMIT;").map_err(storage_err)?; conn.execute_batch(TREE_TABLES_V2).map_err(storage_err)?; conn.execute_batch(TREE_TABLES_V3).map_err(storage_err)?; conn.pragma_update(None,"user_version",TREE_SCHEMA_VERSION).map_err(storage_err)?; Ok(Self{crypto,storage:SqlStorage{conn}})}; build().inspect_err(|_|{let _=fs::remove_file(path);let _=fs::remove_file(&header_path);})
    }
    pub(crate) fn open(path:&Path,source:&dyn KeySource)->Result<Self,TreeError>{
        let meta=fs::symlink_metadata(path).map_err(|e|TreeError::Storage(format!("cannot stat {}: {e}",path.display())))?; if !meta.file_type().is_file(){return Err(TreeError::Storage(format!("{} is not a regular file",path.display())))}
        let header_path=KeyHeader::path_for(path); let hm=fs::symlink_metadata(&header_path).map_err(|e|TreeError::Storage(format!("cannot stat {}: {e}",header_path.display())))?; if !hm.file_type().is_file(){return Err(TreeError::Storage(format!("{} is not a regular file",header_path.display())))}
        let header=KeyHeader::read(path)?; let db_key=source.database_key(&header)?; let mut conn=open_connection(path,Some(&db_key))?; drop(db_key); let version:i64=conn.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(storage_err)?; if !(1..=TREE_SCHEMA_VERSION).contains(&version){return Err(TreeError::Storage(format!("unsupported database version {version}")))} migrate(&mut conn)?; if version<TREE_SCHEMA_VERSION {if version<2{conn.execute_batch(TREE_TABLES_V2).map_err(storage_err)?;} conn.execute_batch(TREE_TABLES_V3).map_err(storage_err)?; conn.pragma_update(None,"user_version",TREE_SCHEMA_VERSION).map_err(storage_err)?;} Ok(Self{crypto:RustCrypto::default(),storage:SqlStorage{conn}})
    }
    #[cfg(test)] pub(crate) fn create_unencrypted_for_test(path:&Path)->Result<Self,TreeError>{let mut conn=Connection::open(path).map_err(storage_err)?;migrate(&mut conn)?;conn.execute_batch("CREATE TABLE tree_meta (key TEXT PRIMARY KEY,value BLOB NOT NULL) WITHOUT ROWID; CREATE TABLE tree_groups (seq INTEGER PRIMARY KEY AUTOINCREMENT,group_id BLOB NOT NULL UNIQUE);").map_err(storage_err)?;conn.execute_batch(TREE_TABLES_V2).map_err(storage_err)?;conn.execute_batch(TREE_TABLES_V3).map_err(storage_err)?;Ok(Self{crypto:RustCrypto::default(),storage:SqlStorage{conn}})}
    pub(crate) fn put_meta(&self,key:&str,value:&[u8])->Result<(),TreeError>{self.storage.conn.execute("INSERT OR REPLACE INTO tree_meta (key,value) VALUES (?1,?2)",params![key,value]).map(|_|()).map_err(storage_err)}
    pub(crate) fn delete_meta(&self,key:&str)->Result<(),TreeError>{self.storage.conn.execute("DELETE FROM tree_meta WHERE key=?1",params![key]).map(|_|()).map_err(storage_err)}
    pub(crate) fn meta(&self,key:&str)->Result<Vec<u8>,TreeError>{self.storage.conn.query_row("SELECT value FROM tree_meta WHERE key=?1",params![key],|r|r.get(0)).optional().map_err(storage_err)?.ok_or_else(||TreeError::Storage(format!("identity record {key:?} missing")))}
    pub(crate) fn meta_optional(&self,key:&str)->Result<Option<Vec<u8>>,TreeError>{self.storage.conn.query_row("SELECT value FROM tree_meta WHERE key=?1",params![key],|r|r.get(0)).optional().map_err(storage_err)}
    pub(crate) fn meta_keys(&self,prefix:&str)->Result<Vec<String>,TreeError>{let mut stmt=self.storage.conn.prepare("SELECT key FROM tree_meta WHERE key LIKE ?1 ORDER BY key").map_err(storage_err)?;let pattern=format!("{prefix}%");let rows=stmt.query_map(params![pattern],|r|r.get(0)).map_err(storage_err)?;rows.collect::<Result<Vec<String>,_>>().map_err(storage_err)}
    pub(crate) fn group_ids(&self)->Result<Vec<Vec<u8>>,TreeError>{let mut stmt=self.storage.conn.prepare("SELECT group_id FROM tree_groups ORDER BY seq").map_err(storage_err)?;let rows=stmt.query_map([],|r|r.get(0)).map_err(storage_err)?;rows.collect::<Result<Vec<Vec<u8>>,_>>().map_err(storage_err)}
    
    pub(crate) fn insert_message_record(&self,group_id:&[u8],message_id:&[u8;16],sender:&[u8;32],seq:u64,created_at:i64,expires_at:Option<i64>,view_once:bool,deleted:bool,body:&[u8])->Result<(),TreeError>{self.storage.conn.execute("INSERT OR REPLACE INTO tree_messages (group_id,message_id,sender_member_id,sequence,created_at,expires_at,view_once,deleted,body) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![group_id,message_id.as_slice(),sender.as_slice(),seq as i64,created_at,expires_at,view_once as i64,deleted as i64,body]).map(|_|()).map_err(storage_err)}
}

pub(crate) fn storage_err(e:impl std::fmt::Display)->TreeError{TreeError::Storage(e.to_string())}
pub(crate) fn private_file(path:&Path,truncate:bool)->Result<File,TreeError>{let mut o=OpenOptions::new();o.write(true);if truncate{o.create(true).truncate(true);}else{o.create_new(true);}#[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;o.mode(0o600);}o.open(path).map_err(|e|TreeError::Storage(format!("cannot create {}: {e}",path.display())))}
fn migrate(conn:&mut Connection)->Result<(),TreeError>{SqliteStorageProvider::<JsonCodec,&mut Connection>::new(conn).run_migrations().map_err(|e|TreeError::Storage(format!("storage migration: {e}")))}
fn open_connection(path:&Path,key:Option<&DbKey>)->Result<Connection,TreeError>{let flags=OpenFlags::SQLITE_OPEN_READ_WRITE|OpenFlags::SQLITE_OPEN_NO_MUTEX;let conn=Connection::open_with_flags(path,flags).map_err(storage_err)?;conn.pragma_update(None,"cipher_log_level","NONE").map_err(storage_err)?;if let Some(key)=key{apply_key(&conn,key)?;} let cipher:Option<String>=conn.query_row("PRAGMA cipher_version",[],|r|r.get(0)).optional().map_err(storage_err)?;if cipher.is_none(){return Err(TreeError::Storage("SQLite was built without SQLCipher".into()));} match conn.query_row("SELECT count(*) FROM sqlite_master",[],|r|r.get::<_,i64>(0)){Ok(_)=>{},Err(rusqlite::Error::SqliteFailure(e,_)) if e.code==rusqlite::ErrorCode::NotADatabase=>return Err(TreeError::WrongKey),Err(e)=>return Err(storage_err(e)),} conn.execute_batch("PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY;").map_err(storage_err)?;Ok(conn)}
fn apply_key(conn:&Connection,key:&DbKey)->Result<(),TreeError>{const HEX:&[u8;16]=b"0123456789abcdef";let mut spec=Zeroizing::new(Vec::with_capacity(3+2*key::KEY_LEN));spec.extend_from_slice(b"x'");for b in key.as_bytes(){spec.push(HEX[(b>>4)as usize]);spec.push(HEX[(b&0x0f)as usize]);}spec.push(b'\'');let rc=unsafe{ffi::sqlite3_key(conn.handle(),spec.as_ptr().cast(),spec.len()as std::os::raw::c_int)};if rc!=ffi::SQLITE_OK{return Err(TreeError::Storage(format!("sqlite3_key failed ({rc})")));}Ok(())}
