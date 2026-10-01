//! On-disk checks that need crate internals (the signing key, and an
//! unencrypted control database that the public API cannot create).

use std::path::{Path, PathBuf};

use super::*;
use crate::{Client, Incoming, TREE_CIPHERSUITE};

pub(crate) struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "tree-unit-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Every file in `dir` (database, key header, any journal left behind).
fn all_bytes(dir: &Path) -> Vec<(String, Vec<u8>)> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            (p.file_name().unwrap().to_string_lossy().into_owned(), fs::read(&p).unwrap())
        })
        .collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// What an attacker holding the raw files would look for.
fn needles(client: &Client<StoredProvider>, name: &str, message: &str) -> Vec<(&'static str, Vec<u8>)> {
    let json = serde_json::to_value(&client.signer).unwrap();
    let private: Vec<u8> = serde_json::from_value(json["private"].clone()).unwrap();
    assert!(private.len() >= 32, "unexpected private key length");
    vec![
        ("sqlite header", b"SQLite format 3".to_vec()),
        ("client name", name.as_bytes().to_vec()),
        ("message plaintext", message.as_bytes().to_vec()),
        ("private key (raw)", private.clone()),
        ("private key (as stored)", serde_json::to_vec(&private).unwrap()),
    ]
}

/// Runs the same conversation for a client whose files are then scanned.
fn chat(client: &Client<StoredProvider>, message: &str) {
    let peer = Client::new("peer").unwrap();
    let mut g = client.create_group().unwrap();
    let added = g.add(client, &[peer.key_package().unwrap()]).unwrap();
    g.confirm_commit(client).unwrap();
    let mut p = peer.join(added.welcome.as_ref().unwrap()).unwrap();
    let m = g.send(client, message.as_bytes()).unwrap();
    assert!(matches!(p.receive(&peer, &m).unwrap(), Incoming::Message { .. }));
    let m = p.send(&peer, message.as_bytes()).unwrap();
    assert!(matches!(g.receive(client, &m).unwrap(), Incoming::Message { .. }));
    client.key_package().unwrap();
}

#[test]
fn files_on_disk_reveal_nothing() {
    let name = "alice-7f3a9c-known-name";
    let message = "known plaintext 4b1d: meet at the north gate";

    // Control: the same data in an UNENCRYPTED database must be found by the
    // scan, otherwise the scan proves nothing.
    let plain_dir = TempDir::new("plain");
    let plain_path = plain_dir.0.join("plain.db");
    {
        let provider = StoredProvider::create_unencrypted_for_test(&plain_path).unwrap();
        let c = Client::with_provider(name, provider, TREE_CIPHERSUITE).unwrap();
        c.provider.put_meta("name", name.as_bytes()).unwrap();
        chat(&c, message);
        let plain = all_bytes(&plain_dir.0);
        let found: Vec<&str> = needles(&c, name, message)
            .into_iter()
            .filter(|(_, n)| plain.iter().any(|(_, b)| contains(b, n)))
            .map(|(what, _)| what)
            .collect();
        // Messages are not stored by the core yet, so only these are expected.
        for expected in ["sqlite header", "client name", "private key (as stored)"] {
            assert!(found.contains(&expected), "control scan missed {expected}: found {found:?}");
        }
    }

    // Encrypted database: none of it may appear in any file.
    let dir = TempDir::new("enc");
    let path = dir.0.join("alice.db");
    let n = {
        let c = Client::create(&path, "pass phrase 1", name).unwrap();
        chat(&c, message);
        needles(&c, name, message)
    }; // dropped: connection closed, everything flushed
    let files = all_bytes(&dir.0);
    assert!(files.iter().any(|(f, _)| f == "alice.db"));
    assert!(files.iter().any(|(f, _)| f == "alice.db.hdr"));
    for (file, bytes) in &files {
        for (what, needle) in &n {
            assert!(!contains(bytes, needle), "{what} found in {file}");
        }
    }

    // The same database still opens and holds the identity.
    let c = Client::open(&path, "pass phrase 1").unwrap();
    assert_eq!(c.name(), name);
    assert_eq!(c.group_ids().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("perm");
    let path = dir.0.join("a.db");
    drop(Client::create(&path, "pw", "a").unwrap());
    for p in [path.clone(), KeyHeader::path_for(&path)] {
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{} has mode {mode:o}", p.display());
    }
}

/// A database of schema version 1 (before `tree_group_state`) is upgraded on
/// open; versions this code does not know are refused.
#[test]
fn schema_v1_is_upgraded() {
    let dir = TempDir::new("schema");
    let set_version = |path: &Path, version: i64, drop_table: bool| {
        let c = Client::open(path, "pw").unwrap();
        let conn = &c.provider.storage.conn;
        if drop_table {
            conn.execute_batch("DROP TABLE tree_group_state").unwrap();
        }
        conn.pragma_update(None, "user_version", version).unwrap();
    };
    let path = dir.0.join("a.db");
    drop(Client::create(&path, "pw", "a").unwrap());
    set_version(&path, 1, true);
    let c = Client::open(&path, "pw").unwrap();
    let conn = &c.provider.storage.conn;
    let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
    assert_eq!(v, TREE_SCHEMA_VERSION);
    c.provider.save_group_state(b"g", b"state").unwrap();
    assert_eq!(c.provider.load_group_state(b"g").unwrap(), Some(b"state".to_vec()));
    assert_eq!(c.provider.load_group_state(b"other").unwrap(), None);
    drop(c);
    for bad in [0, TREE_SCHEMA_VERSION + 1] {
        let path = dir.0.join(format!("v{bad}.db"));
        drop(Client::create(&path, "pw", "a").unwrap());
        set_version(&path, bad, false);
        assert!(matches!(Client::open(&path, "pw"), Err(TreeError::Storage(_))), "version {bad}");
    }
}
