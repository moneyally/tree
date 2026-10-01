//! A real Tree server in this process, and devices talking to it over HTTP.
#![allow(dead_code)]

use std::path::PathBuf;

use tree_client::Session;
use tree_server::Config;

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
            ..Config::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(tree_server::start(cfg)).unwrap();
        let url = format!("http://{}", server.addr);
        std::mem::forget(server); // runs until the runtime is dropped
        Self { dir, url, db, _rt: rt }
    }

    pub fn device(&self, name: &str) -> Session {
        let p = self.profile(name);
        Session::create(&p, &format!("{name} passphrase"), name, &self.url, 8).unwrap()
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

