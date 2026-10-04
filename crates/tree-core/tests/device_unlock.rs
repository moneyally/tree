//! PIN unlock with its attempt limit, platform-key unlock, and the
//! full-text search index inside the encrypted database.

use std::path::PathBuf;

use tree_core::storage::messages::StoredMessage;
use tree_core::storage::pin::{self, Pin, PIN_MAX_ATTEMPTS};
use tree_core::storage::{DbKey, KdfParams};
use tree_core::{Client, Passphrase, TreeError};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("tree-unlock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn db(&self) -> PathBuf {
        self.0.join("p.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn pass() -> Passphrase {
    Passphrase::new("a long passphrase").unwrap()
}

fn enable(db: &std::path::Path, pin_: &str, secret: Option<&[u8]>) {
    pin::enable_pin_with(db, &pass(), pin_, secret, KdfParams::MIN).unwrap();
}

#[test]
fn pin_opens_the_same_database_and_the_passphrase_keeps_working() {
    let d = TempDir::new("open");
    let db = d.db();
    let c = Client::create(&db, "a long passphrase", "alice").unwrap();
    let id = c.member_id();
    drop(c);
    assert!(!pin::pin_state(&db).enabled);
    // A wrong passphrase cannot set a PIN.
    assert!(matches!(pin::enable_pin_with(&db, &Passphrase::new("wrong").unwrap(), "123456", None, KdfParams::MIN), Err(TreeError::WrongKey)));
    assert!(pin::enable_pin_with(&db, &pass(), "12345", None, KdfParams::MIN).is_err(), "too short");
    enable(&db, "123456", None);
    let st = pin::pin_state(&db);
    assert!(st.enabled && st.attempts_left == PIN_MAX_ATTEMPTS && !st.device_secret);
    let c = Client::open_with_key(&db, &Pin::new(&db, "123456", None).unwrap()).unwrap();
    assert_eq!(c.member_id(), id);
    drop(c);
    let c = Client::open(&db, "a long passphrase").unwrap();
    assert_eq!(c.member_id(), id);
    drop(c);
    pin::disable_pin(&db).unwrap();
    assert!(!pin::pin_path(&db).exists(), "disabling wipes the file");
    assert!(matches!(Client::open_with_key(&db, &Pin::new(&db, "123456", None).unwrap()), Err(TreeError::PinUnavailable)));
    Client::open(&db, "a long passphrase").unwrap();
}

#[test]
fn ten_wrong_pins_wipe_the_pin_and_only_the_passphrase_opens() {
    let d = TempDir::new("limit");
    let db = d.db();
    drop(Client::create(&db, "a long passphrase", "alice").unwrap());
    enable(&db, "424242", None);
    // Wrong attempts are counted; a right one resets the count.
    for left in (PIN_MAX_ATTEMPTS - 3..PIN_MAX_ATTEMPTS).rev() {
        match Client::open_with_key(&db, &Pin::new(&db, "000000", None).unwrap()) {
            Err(TreeError::WrongPin(n)) => assert_eq!(n, left),
            other => panic!("{:?}", other.err()),
        }
    }
    assert_eq!(pin::pin_state(&db).attempts_left, PIN_MAX_ATTEMPTS - 3);
    drop(Client::open_with_key(&db, &Pin::new(&db, "424242", None).unwrap()).unwrap());
    assert_eq!(pin::pin_state(&db).attempts_left, PIN_MAX_ATTEMPTS, "a right PIN resets the count");
    // Ten wrong ones in a row: the PIN is gone.
    for i in 1..=PIN_MAX_ATTEMPTS {
        let r = Client::open_with_key(&db, &Pin::new(&db, "111111", None).unwrap());
        if i < PIN_MAX_ATTEMPTS {
            assert!(matches!(r, Err(TreeError::WrongPin(n)) if n == PIN_MAX_ATTEMPTS - i), "attempt {i}");
        } else {
            assert!(matches!(r, Err(TreeError::PinUnavailable)), "the tenth wrong PIN ends PIN unlock");
        }
    }
    assert!(!pin::pin_path(&db).exists(), "the PIN file is wiped");
    assert!(!pin::pin_state(&db).enabled);
    assert!(matches!(Client::open_with_key(&db, &Pin::new(&db, "424242", None).unwrap()), Err(TreeError::PinUnavailable)), "even the right PIN");
    Client::open(&db, "a long passphrase").expect("the passphrase still opens the profile");
}

#[test]
fn a_malformed_pin_still_counts_and_a_device_secret_is_needed() {
    let d = TempDir::new("secret");
    let db = d.db();
    drop(Client::create(&db, "a long passphrase", "alice").unwrap());
    let secret = [9u8; 32];
    enable(&db, "13572468", Some(&secret));
    assert!(pin::pin_state(&db).device_secret);
    assert!(matches!(Client::open_with_key(&db, &Pin::new(&db, "13572468", None).unwrap()), Err(TreeError::WrongPin(9))), "without the secret");
    assert!(matches!(Client::open_with_key(&db, &Pin::new(&db, "13572468", Some(&[8u8; 32])).unwrap()), Err(TreeError::WrongPin(8))), "another secret");
    assert!(matches!(Client::open_with_key(&db, &Pin::new(&db, "abc", Some(&secret)).unwrap()), Err(TreeError::WrongPin(7))), "malformed");
    drop(Client::open_with_key(&db, &Pin::new(&db, "13572468", Some(&secret)).unwrap()).unwrap());
}

#[test]
fn a_tampered_pin_file_does_not_open() {
    let d = TempDir::new("tamper");
    let db = d.db();
    drop(Client::create(&db, "a long passphrase", "alice").unwrap());
    enable(&db, "123456", None);
    let path = pin::pin_path(&db);
    let mut b = std::fs::read(&path).unwrap();
    b[30] ^= 1; // inside the salt (associated data)
    std::fs::write(&path, &b).unwrap();
    assert!(matches!(Client::open_with_key(&db, &Pin::new(&db, "123456", None).unwrap()), Err(TreeError::WrongPin(_))));
}

#[test]
fn platform_wrapped_key_opens_and_a_wrong_one_does_not() {
    let d = TempDir::new("platform");
    let db = d.db();
    let id = Client::create(&db, "a long passphrase", "alice").unwrap().member_id();
    let k = pin::key_for_platform_wrap(&db, &pass()).unwrap();
    assert!(matches!(pin::key_for_platform_wrap(&db, &Passphrase::new("nope").unwrap()), Err(TreeError::WrongKey)));
    let c = Client::open_with_key(&db, &DbKey::from_bytes(*k)).unwrap();
    assert_eq!(c.member_id(), id);
    drop(c);
    assert!(matches!(Client::open_with_key(&db, &DbKey::from_bytes([1; 32])), Err(TreeError::WrongKey)));
}

fn msg(g: &[u8], id: &str, text: &str, at: i64, expires: Option<i64>) -> StoredMessage {
    StoredMessage {
        group_id: g.to_vec(),
        id: id.into(),
        sender: "00".into(),
        received_at: at,
        kind: "text".into(),
        text: Some(text.into()),
        data: None,
        edited_at: None,
        deleted: false,
        expires_at: expires,
        reactions: Default::default(),
        franking: None,
    }
}

fn found(c: &Client<tree_core::StoredProvider>, q: &str) -> Vec<String> {
    c.search_index(q, 50).unwrap().into_iter().map(|m| m.id).collect()
}

#[test]
fn search_index_lifecycle_inside_the_encrypted_database() {
    let d = TempDir::new("search");
    let db = d.db();
    let c = Client::create(&db, "a long passphrase", "alice").unwrap();
    let g = b"group-1".to_vec();
    c.store_message(&msg(&g, "a", "사과를 먹었다", 1, None)).unwrap();
    c.store_message(&msg(&g, "b", "Trees are green", 2, Some(100))).unwrap();
    assert!(!c.has_search_index().unwrap());
    assert!(c.search_index("tree", 10).is_err(), "no index, no search");
    // Apply: built from the history that is already there.
    assert_eq!(c.build_search_index().unwrap(), 2);
    assert_eq!(found(&c, "사과"), vec!["a"], "Korean word by prefix");
    assert_eq!(found(&c, "tree GREEN"), vec!["b"], "all words, any case");
    assert!(found(&c, "ree").is_empty(), "not from the middle of a word");
    assert!(found(&c, "\" OR *").is_empty(), "query syntax does not get through");
    // Kept current by the triggers.
    c.store_message(&msg(&g, "c", "a new tree", 3, None)).unwrap();
    assert_eq!(found(&c, "tree"), vec!["c", "b"], "newest first");
    c.edit_message(&g, "c", "a new bush", 4, None).unwrap();
    assert_eq!(found(&c, "tree"), vec!["b"]);
    assert_eq!(found(&c, "bush"), vec!["c"]);
    c.delete_message(&g, "c").unwrap();
    assert!(found(&c, "bush").is_empty(), "deleted for everyone");
    c.purge_expired_messages(200).unwrap();
    assert!(found(&c, "tree").is_empty(), "expired");
    assert_eq!(c.search_index_size().unwrap(), 1);
    // Survives a restart.
    drop(c);
    let c = Client::open(&db, "a long passphrase").unwrap();
    assert_eq!(found(&c, "사과"), vec!["a"]);
    // Release: index and triggers gone; new messages are not indexed.
    c.drop_search_index().unwrap();
    assert!(!c.has_search_index().unwrap());
    assert_eq!(c.search_index_size().unwrap(), 0);
    c.store_message(&msg(&g, "d", "after release", 5, None)).unwrap();
    assert!(c.search_index("after", 10).is_err());
    // Apply again: rebuilt with everything, including what came meanwhile.
    assert_eq!(c.build_search_index().unwrap(), 2);
    assert_eq!(found(&c, "release"), vec!["d"]);
}
