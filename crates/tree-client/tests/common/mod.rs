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
    pub
    fn new(tag: &str) -> Self {
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

    pub fn profile(&self, name: &str) -> String {
        self.dir.join(format!("{name}.db")).display().to_string()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

