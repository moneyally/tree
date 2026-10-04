//! A real Tree server in this process, and devices talking to it over HTTP.
#![allow(dead_code)]

use std::path::PathBuf;

use tree_client::Session;
use tree_server::Config;

/// Operator token of the test server.
pub const ADMIN_TOKEN: &str = "test-operator";

pub struct Env {
    pub dir: PathBuf,
    pub url: String,
    pub db: PathBuf,
    _rt: tokio::runtime::Runtime,
}

impl Env {
    pub fn new(tag: &str) -> Self {
        Self::with(tag, |_| {})
    }

    /// A server with a changed configuration (e.g. relays with a fake upstream).
    pub fn with(tag: &str, tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = std::env::temp_dir().join(format!("tree-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("server.db");
        let cfg = Config {
            database_url: format!("sqlite://{}", db.display()),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            pow_bits: 8,
            attachment_dir: dir.join("attachments"),
            admin_token_sha256: Some(sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(ADMIN_TOKEN)).into()),
            ..Config::default()
        };
        let mut cfg = cfg;
        tweak(&mut cfg);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(tree_server::start(cfg)).unwrap();
        // Test accounts are all new; the server's new-account limits are
        // tested in tree-server and switched off here.
        rt.block_on(tree_server::features::set_applied(&server.state.db, tree_server::features::NEW_ACCOUNT_LIMITS, false))
            .unwrap();
        let url = format!("http://{}", server.addr);
        std::mem::forget(server); // runs until the runtime is dropped
        Self { dir, url, db, _rt: rt }
    }

    pub fn device(&self, name: &str) -> Session {
        let p = self.profile(name);
        Session::create(&p, &format!("{name} passphrase"), name, &self.url, 8).unwrap()
    }

    /// An operator request (`X-Tree-Admin`).
    pub fn operator(&self, method: reqwest::Method, path: &str) -> (u16, serde_json::Value) {
        let r = reqwest::blocking::Client::new()
            .request(method, format!("{}{path}", self.url))
            .header("X-Tree-Admin", ADMIN_TOKEN)
            .send()
            .unwrap();
        (r.status().as_u16(), r.json().unwrap_or_default())
    }

    /// Runs one statement on the server database; rows changed.
    pub fn sql(&self, q: &'static str, arg: &str) -> u64 {
        let arg = arg.to_string();
        self._rt.block_on(async {
            let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", self.db.display())).await.unwrap();
            let n = sqlx::query(q).bind(arg).execute(&pool).await.unwrap().rows_affected();
            pool.close().await;
            n
        })
    }

    /// Reads one blob from the server database.
    pub fn sql_blob(&self, q: &'static str, arg: &str) -> Option<Vec<u8>> {
        let arg = arg.to_string();
        self._rt.block_on(async {
            let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", self.db.display())).await.unwrap();
            let r: Option<(Vec<u8>,)> = sqlx::query_as(q).bind(arg).fetch_optional(&pool).await.unwrap();
            pool.close().await;
            r.map(|r| r.0)
        })
    }

    /// Runs one statement with a blob and a text argument; rows changed.
    pub fn sql_set_blob(&self, q: &'static str, blob: &[u8], arg: &str) -> u64 {
        let (blob, arg) = (blob.to_vec(), arg.to_string());
        self._rt.block_on(async {
            let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", self.db.display())).await.unwrap();
            let n = sqlx::query(q).bind(blob).bind(arg).execute(&pool).await.unwrap().rows_affected();
            pool.close().await;
            n
        })
    }

    /// The last-resort key package the server holds for a device.
    pub fn last_resort(&self, device: &str) -> Option<Vec<u8>> {
        let device = device.to_string();
        self._rt.block_on(async {
            let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", self.db.display())).await.unwrap();
            let r: Option<(Vec<u8>,)> = sqlx::query_as("SELECT data FROM last_resort_key_packages WHERE device_id = ?")
                .bind(device)
                .fetch_optional(&pool)
                .await
                .unwrap();
            pool.close().await;
            r.map(|r| r.0)
        })
    }

    /// Puts a last-resort key package back on the server for a device.
    pub fn set_last_resort(&self, device: &str, kp: &[u8]) {
        let (device, kp) = (device.to_string(), kp.to_vec());
        self._rt.block_on(async {
            let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", self.db.display())).await.unwrap();
            sqlx::query("UPDATE last_resort_key_packages SET data = ? WHERE device_id = ?")
                .bind(kp)
                .bind(device)
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        })
    }

    pub fn profile(&self, name: &str) -> String {
        self.dir.join(format!("{name}.db")).display().to_string()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

