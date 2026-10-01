//! Encrypted persistent storage: restarts, wrong keys, isolation.

mod common;

use common::{ids, Now};

use std::path::{Path, PathBuf};

use tree_core::{storage::KeyHeader, Client, Group, Incoming, StoredProvider, TreeError};

type Stored = Client<StoredProvider>;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "tree-it-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn db(&self, name: &str) -> PathBuf {
        self.0.join(format!("{name}.db"))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Simulates an app restart: everything in memory is dropped, the identity
/// and its only group are loaded again from disk.
fn restart(client: Stored, group: Group, path: &Path, pass: &str) -> (Stored, Group) {
    let id = group.id();
    drop(group);
    drop(client);
    let client = Client::open(path, pass).unwrap();
    assert_eq!(client.group_ids().unwrap(), vec![id.clone()]);
    let group = client.load_group(&id).unwrap();
    (client, group)
}

fn says(ev: Incoming, from: &Client<impl tree_core::TreeProvider>, text: &str) {
    assert_eq!(
        ev,
        Incoming::Message { from: from.member_id(), body: text.as_bytes().to_vec() }
    );
}

#[test]
fn conversation_survives_restarts() {
    let dir = TempDir::new("restart");
    let (pa, pb, pc) = (dir.db("alice"), dir.db("bob"), dir.db("charlie"));
    let alice = Client::create(&pa, "alice pass", "alice").unwrap();
    let bob = Client::create(&pb, "bob pass", "bob").unwrap();

    let mut a = alice.create_group().unwrap();
    let w = a.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    let mut b = bob.join(&w).unwrap();
    let m = a.send(&alice, b"before restart").unwrap();
    says(b.receive(&bob, &m).unwrap(), &alice, "before restart");

    // Both restart, then keep chatting both ways.
    let (alice, mut a) = restart(alice, a, &pa, "alice pass");
    let (bob, mut b) = restart(bob, b, &pb, "bob pass");
    assert_eq!(a.verification_code(), b.verification_code());
    let m = a.send(&alice, b"after restart 1").unwrap();
    says(b.receive(&bob, &m).unwrap(), &alice, "after restart 1");
    let m = b.send(&bob, b"after restart 2").unwrap();
    says(a.receive(&alice, &m).unwrap(), &bob, "after restart 2");

    // A message sent while the receiver restarts is still readable, and the
    // used message key stays deleted across a restart (no replay).
    let m = a.send(&alice, b"in flight").unwrap();
    let (bob, mut b) = restart(bob, b, &pb, "bob pass");
    says(b.receive(&bob, &m).unwrap(), &alice, "in flight");
    let (bob, mut b) = restart(bob, b, &pb, "bob pass");
    assert!(b.receive(&bob, &m).is_err(), "replay accepted after restart");

    // Charlie publishes a key package, restarts, and can still join with it:
    // its private part was stored.
    let charlie = Client::create(&pc, "charlie pass", "charlie").unwrap();
    let kp = charlie.key_package().unwrap();
    drop(charlie);
    let charlie = Client::open(&pc, "charlie pass").unwrap();
    assert!(charlie.group_ids().unwrap().is_empty());
    let add = a.add_now(&alice, &kp).unwrap();
    assert!(matches!(b.receive(&bob, &add.commit).unwrap(), Incoming::GroupChanged { .. }));
    let c = charlie.join(&add.welcome).unwrap();

    // Everyone restarts in the middle of the epoch.
    let (alice, mut a) = restart(alice, a, &pa, "alice pass");
    let (bob, mut b) = restart(bob, b, &pb, "bob pass");
    let (charlie, mut c2) = restart(charlie, c, &pc, "charlie pass");
    assert_eq!(a.members(), ids(&[&alice, &bob, &charlie]));
    assert_eq!(c2.members(), a.members());
    let m = c2.send(&charlie, b"hi from charlie").unwrap();
    says(a.receive(&alice, &m).unwrap(), &charlie, "hi from charlie");
    says(b.receive(&bob, &m).unwrap(), &charlie, "hi from charlie");

    // Key refresh across a restart.
    let r = b.refresh_now(&bob).unwrap();
    let (bob, mut b) = restart(bob, b, &pb, "bob pass");
    a.receive(&alice, &r).unwrap();
    c2.receive(&charlie, &r).unwrap();
    assert_eq!(a.verification_code(), b.verification_code());

    // Alice removes Bob; Bob restarts and stays removed.
    let rm = a.remove_now(&alice, &[bob.member_id()]).unwrap();
    assert!(matches!(c2.receive(&charlie, &rm).unwrap(), Incoming::GroupChanged { .. }));
    assert_eq!(b.receive(&bob, &rm).unwrap(), Incoming::RemovedFromGroup);
    let (alice, mut a) = restart(alice, a, &pa, "alice pass");
    let (charlie, mut c) = restart(charlie, c2, &pc, "charlie pass");
    let (bob, mut b) = restart(bob, b, &pb, "bob pass");
    assert!(!b.is_member());
    let m = a.send(&alice, b"without bob").unwrap();
    says(c.receive(&charlie, &m).unwrap(), &alice, "without bob");
    assert!(b.receive(&bob, &m).is_err());
    assert_eq!(a.members(), ids(&[&alice, &charlie]));

    // Add Bob back (fresh key package, after all those restarts).
    let add = a.add_now(&alice, &bob.key_package().unwrap()).unwrap();
    c.receive(&charlie, &add.commit).unwrap();
    let mut b2 = bob.join(&add.welcome).unwrap();
    assert_eq!(bob.group_ids().unwrap().len(), 1, "same group id is listed once");
    drop(b);
    let m = b2.send(&bob, b"back again").unwrap();
    says(a.receive(&alice, &m).unwrap(), &bob, "back again");
    says(c.receive(&charlie, &m).unwrap(), &bob, "back again");
}

#[test]
fn several_groups_are_listed_and_loaded() {
    let dir = TempDir::new("groups");
    let pa = dir.db("alice");
    let alice = Client::create(&pa, "pw", "alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut ids = vec![];
    let mut peers = vec![];
    for _ in 0..3 {
        let mut g = alice.create_group().unwrap();
        let w = g.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
        peers.push(bob.join(&w).unwrap());
        ids.push(g.id());
    }
    drop(alice);
    let alice = Client::open(&pa, "pw").unwrap();
    assert_eq!(alice.group_ids().unwrap(), ids);
    for (id, peer) in ids.iter().zip(peers.iter_mut()) {
        let mut g = alice.load_group(id).unwrap();
        let m = g.send(&alice, id).unwrap();
        assert_eq!(
            peer.receive(&bob, &m).unwrap(),
            Incoming::Message { from: alice.member_id(), body: id.clone() }
        );
    }
    assert!(matches!(alice.load_group(b"no such group"), Err(TreeError::NoSuchGroup)));
}

#[test]
fn wrong_passphrase_fails_cleanly() {
    let dir = TempDir::new("wrong");
    let p = dir.db("alice");
    let alice = Client::create(&p, "right horse battery", "alice").unwrap();
    let pk = alice.signature_public_key();
    drop(alice);

    assert!(matches!(Client::open(&p, "wrong horse battery"), Err(TreeError::WrongKey)));
    assert!(matches!(Client::open(&p, "right horse batterY"), Err(TreeError::WrongKey)));
    assert!(matches!(Client::open(&p, ""), Err(TreeError::EmptyPassphrase)));
    assert!(matches!(Client::create(dir.db("x"), "", "x"), Err(TreeError::EmptyPassphrase)));
    assert!(matches!(Client::open(dir.db("missing"), "pw"), Err(TreeError::Storage(_))));

    // Creating over an existing identity is refused and destroys nothing.
    assert!(matches!(Client::create(&p, "other", "mallory"), Err(TreeError::Storage(_))));

    // The right passphrase still works after all the failures.
    let alice = Client::open(&p, "right horse battery").unwrap();
    assert_eq!(alice.signature_public_key(), pk);
    assert_eq!(alice.name(), "alice");

    // Error text never contains the passphrase.
    let e = Client::open(&p, "s3cret-guess").err().unwrap().to_string();
    assert!(!e.contains("s3cret"), "{e}");
}

#[test]
fn damaged_files_fail_cleanly() {
    let dir = TempDir::new("damaged");
    let p = dir.db("alice");
    drop(Client::create(&p, "pw", "alice").unwrap());
    let hdr = KeyHeader::path_for(&p);
    let good_hdr = std::fs::read(&hdr).unwrap();
    let good_db = std::fs::read(&p).unwrap();

    // Changed salt -> different key -> refused.
    let mut h = good_hdr.clone();
    *h.last_mut().unwrap() ^= 1;
    std::fs::write(&hdr, &h).unwrap();
    assert!(matches!(Client::open(&p, "pw"), Err(TreeError::WrongKey)));
    // Truncated or missing header.
    std::fs::write(&hdr, &good_hdr[..10]).unwrap();
    assert!(matches!(Client::open(&p, "pw"), Err(TreeError::Storage(_))));
    std::fs::remove_file(&hdr).unwrap();
    assert!(matches!(Client::open(&p, "pw"), Err(TreeError::Storage(_))));
    std::fs::write(&hdr, &good_hdr).unwrap();

    // One flipped bit in the first page of the database -> refused.
    let mut d = good_db.clone();
    d[100] ^= 1;
    std::fs::write(&p, &d).unwrap();
    assert!(Client::open(&p, "pw").is_err());

    std::fs::write(&p, &good_db).unwrap();
    assert_eq!(Client::open(&p, "pw").unwrap().name(), "alice");
}

#[test]
fn two_databases_do_not_interfere() {
    let dir = TempDir::new("two");
    let (pa, pb) = (dir.db("alice"), dir.db("bob"));
    // Same passphrase on purpose: the random salt still gives different keys.
    let alice = Client::create(&pa, "same pass", "alice").unwrap();
    let bob = Client::create(&pb, "same pass", "bob").unwrap();
    assert_ne!(std::fs::read(KeyHeader::path_for(&pa)).unwrap(), std::fs::read(KeyHeader::path_for(&pb)).unwrap());

    let mut a = alice.create_group().unwrap();
    let mut a_only = alice.create_group().unwrap();
    let w = a.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    let mut b = bob.join(&w).unwrap();
    let m = a.send(&alice, b"one").unwrap();
    says(b.receive(&bob, &m).unwrap(), &alice, "one");
    let _ = a_only.send(&alice, b"just me").unwrap();

    assert_eq!(alice.group_ids().unwrap(), vec![a.id(), a_only.id()]);
    assert_eq!(bob.group_ids().unwrap(), vec![b.id()]);
    assert!(matches!(bob.load_group(&a_only.id()), Err(TreeError::NoSuchGroup)));
    let (alice_pk, bob_pk) = (alice.signature_public_key(), bob.signature_public_key());
    assert_ne!(alice_pk, bob_pk);
    drop((alice, bob, a, b, a_only));

    // Header of one database does not unlock the other.
    let hb = std::fs::read(KeyHeader::path_for(&pb)).unwrap();
    let ha = std::fs::read(KeyHeader::path_for(&pa)).unwrap();
    std::fs::write(KeyHeader::path_for(&pb), &ha).unwrap();
    assert!(matches!(Client::open(&pb, "same pass"), Err(TreeError::WrongKey)));
    std::fs::write(KeyHeader::path_for(&pb), &hb).unwrap();

    // Both open at the same time, each with its own identity and groups.
    let alice = Client::open(&pa, "same pass").unwrap();
    let bob = Client::open(&pb, "same pass").unwrap();
    assert_eq!((alice.name(), bob.name()), ("alice", "bob"));
    assert_eq!(alice.signature_public_key(), alice_pk);
    assert_eq!(bob.signature_public_key(), bob_pk);
    assert_eq!(alice.group_ids().unwrap().len(), 2);
    assert_eq!(bob.group_ids().unwrap().len(), 1);

    // And they still talk to each other after reopening.
    let mut a = alice.load_group(&alice.group_ids().unwrap()[0]).unwrap();
    let mut b = bob.load_group(&bob.group_ids().unwrap()[0]).unwrap();
    let m = b.send(&bob, b"two").unwrap();
    says(a.receive(&alice, &m).unwrap(), &bob, "two");
}

/// The persistent client can be moved to another thread (needed for the
/// app bindings, which wrap it in a lock).
#[test]
fn stored_client_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Stored>();
    assert_send::<Group>();
}

#[test]
fn persistent_and_in_memory_clients_mix() {
    let dir = TempDir::new("mix");
    let p = dir.db("alice");
    let alice = Client::create(&p, "pw", "alice").unwrap();
    let bob = Client::new("bob").unwrap(); // in memory
    let mut b = bob.create_group().unwrap();
    let w = b.add_now(&bob, &alice.key_package().unwrap()).unwrap().welcome;
    let a = alice.join(&w).unwrap();
    let (alice, mut a) = restart(alice, a, &p, "pw");
    let m = b.send(&bob, b"to disk").unwrap();
    says(a.receive(&alice, &m).unwrap(), &bob, "to disk");
    let m = a.send(&alice, b"from disk").unwrap();
    says(b.receive(&bob, &m).unwrap(), &alice, "from disk");
}

/// F-003: a pending commit is stored with the group. After a restart the
/// same bytes can be resubmitted and then confirmed (or discarded).
#[test]
fn pending_commit_survives_restart() {
    let dir = TempDir::new("pending");
    let pa = dir.db("alice");
    let alice = Client::create(&pa, "pw", "alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut a = alice.create_group().unwrap();
    let w = a.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    let mut b = bob.join(&w).unwrap();

    let p = a.refresh_keys(&alice).unwrap();
    let (alice, mut a) = restart(alice, a, &pa, "pw");
    assert_eq!(a.pending_commit(), Some(p.clone()), "same bytes after restart");
    assert!(matches!(a.refresh_keys(&alice), Err(TreeError::CommitPending)));
    a.discard_commit(&alice).unwrap();
    let (alice, mut a) = restart(alice, a, &pa, "pw");
    assert!(a.pending_commit().is_none(), "discard is stored");

    let p = a.refresh_keys(&alice).unwrap();
    let (alice, mut a) = restart(alice, a, &pa, "pw");
    assert_eq!(a.confirm_commit(&alice).unwrap(), 2);
    let (alice, mut a) = restart(alice, a, &pa, "pw");
    assert!(a.pending_commit().is_none());
    assert_eq!(a.epoch(), 2);
    b.receive(&bob, &p.commit).unwrap();
    assert_eq!(a.verification_code(), b.verification_code());
    // The own-commit echo is recognised after a restart too.
    assert_eq!(a.receive(&alice, &p.commit).unwrap(), Incoming::OwnEcho);
}

/// F-002: past-epoch envelope keys and members are stored, so a message of
/// the previous epoch is still read after a restart.
#[test]
fn past_epoch_message_after_restart() {
    let dir = TempDir::new("past");
    let pa = dir.db("alice");
    let alice = Client::create(&pa, "pw", "alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut a = alice.create_group().unwrap();
    let w = a.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    let mut b = bob.join(&w).unwrap();
    let in_flight = b.send(&bob, b"sent in epoch 1").unwrap();
    a.refresh_now(&alice).unwrap();
    let (alice, mut a) = restart(alice, a, &pa, "pw");
    says(a.receive(&alice, &in_flight).unwrap(), &bob, "sent in epoch 1");
}

/// A joined device's "refresh your key soon" flag survives a restart.
#[test]
fn should_refresh_survives_restart() {
    let dir = TempDir::new("refresh");
    let pb = dir.db("bob");
    let alice = Client::new("alice").unwrap();
    let bob = Client::create(&pb, "pw", "bob").unwrap();
    let mut a = alice.create_group().unwrap();
    let w = a.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    let b = bob.join(&w).unwrap();
    let (bob, mut b) = restart(bob, b, &pb, "pw");
    assert!(b.should_refresh_keys());
    b.refresh_now(&bob).unwrap();
    let (_bob, b) = restart(bob, b, &pb, "pw");
    assert!(!b.should_refresh_keys());
}

/// App data lives in the same encrypted database and survives a restart.
#[test]
fn app_data_round_trip() {
    let dir = TempDir::new("appdata");
    let p = dir.db("alice");
    let alice = Client::create(&p, "pw", "alice").unwrap();
    assert_eq!(alice.app_data("a/1").unwrap(), None);
    alice.set_app_data("a/1", Some(b"one")).unwrap();
    alice.set_app_data("a/2", Some(b"two")).unwrap();
    alice.set_app_data("b/1", Some(b"other")).unwrap();
    alice.set_app_data("a/1", Some(b"uno")).unwrap();
    drop(alice);
    let alice = Client::open(&p, "pw").unwrap();
    assert_eq!(alice.app_data("a/1").unwrap().as_deref(), Some(&b"uno"[..]));
    assert_eq!(alice.app_data_keys("a/").unwrap(), vec!["a/1", "a/2"]);
    alice.set_app_data("a/1", None).unwrap();
    assert_eq!(alice.app_data("a/1").unwrap(), None);
    assert_eq!(alice.app_data_keys("a/").unwrap(), vec!["a/2"]);
    assert_eq!(alice.app_data_keys("").unwrap().len(), 2);
    assert!(alice.app_data_keys("zzz").unwrap().is_empty());
}

fn msg(g: &[u8], id: &str, at: i64, text: &str) -> tree_core::storage::messages::StoredMessage {
    tree_core::storage::messages::StoredMessage {
        group_id: g.to_vec(),
        id: id.into(),
        sender: "ab".repeat(32),
        received_at: at,
        kind: "text".into(),
        text: Some(text.into()),
        data: None,
        edited_at: None,
        deleted: false,
        expires_at: None,
        reactions: Default::default(),
        franking: Some(b"fr".to_vec()),
    }
}

/// Message history: store, duplicates, edit, delete, reactions, paging,
/// search, expiry; encrypted on disk and kept across restarts.
#[test]
fn message_history() {
    let dir = TempDir::new("history");
    let p = dir.db("alice");
    let c = Client::create(&p, "pw", "alice").unwrap();
    let g = b"group-1";
    for i in 0..5 {
        assert!(c.store_message(&msg(g, &format!("m{i}"), 100 + i, &format!("hello {i} 9f1d"))).unwrap());
    }
    assert!(!c.store_message(&msg(g, "m0", 999, "replay")).unwrap(), "duplicate ignored");
    assert_eq!(c.message(g, "m0").unwrap().unwrap().text.as_deref(), Some("hello 0 9f1d"));
    c.store_message(&msg(b"group-2", "x", 50, "other group 50%_off")).unwrap();

    // paging: newest 2, then the 2 before
    let last2 = c.messages(g, 2, None).unwrap();
    assert_eq!(last2.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), vec!["m3", "m4"]);
    let prev = c.messages(g, 2, Some(103)).unwrap();
    assert_eq!(prev.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), vec!["m1", "m2"]);

    c.edit_message(g, "m1", "edited", 200, Some(b"fr2")).unwrap();
    let m1 = c.message(g, "m1").unwrap().unwrap();
    assert_eq!((m1.text.as_deref(), m1.edited_at), (Some("edited"), Some(200)));
    assert_eq!(m1.franking.as_deref(), Some(&b"fr2"[..]), "the edit's franking record replaces the original's");
    assert_eq!(c.message(g, "m0").unwrap().unwrap().franking.as_deref(), Some(&b"fr"[..]));

    c.react(g, "m2", "aa", "👍", false).unwrap();
    c.react(g, "m2", "bb", "👍", false).unwrap();
    c.react(g, "m2", "aa", "👍", false).unwrap();
    assert_eq!(c.message(g, "m2").unwrap().unwrap().reactions["👍"], vec!["bb", "aa"]);
    c.react(g, "m2", "bb", "👍", true).unwrap();
    c.react(g, "m2", "aa", "👍", true).unwrap();
    assert!(c.message(g, "m2").unwrap().unwrap().reactions.is_empty());
    c.react(g, "nope", "aa", "x", false).unwrap();

    c.delete_message(g, "m3").unwrap();
    let m3 = c.message(g, "m3").unwrap().unwrap();
    assert!(m3.deleted && m3.text.is_none() && m3.franking.is_none());
    c.edit_message(g, "m3", "back from the dead", 300, None).unwrap();
    assert!(c.message(g, "m3").unwrap().unwrap().text.is_none(), "a deleted message stays deleted");
    c.react(g, "m3", "aa", "x", false).unwrap();
    assert!(c.message(g, "m3").unwrap().unwrap().reactions.is_empty());

    // search: substring, not deleted, % and _ are literal
    let hits = c.search_messages("9F1D", 10).unwrap();
    assert_eq!(hits.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), vec!["m4", "m2", "m0"]);
    assert_eq!(c.search_messages("50%_", 10).unwrap().len(), 1);
    assert!(c.search_messages("0%o", 10).unwrap().is_empty());

    // expiry
    let mut e = msg(g, "temp", 400, "disappearing");
    e.expires_at = Some(500);
    c.store_message(&e).unwrap();
    c.set_message_data(g, "temp", Some(b"data")).unwrap();
    assert_eq!(c.message(g, "temp").unwrap().unwrap().data.as_deref(), Some(&b"data"[..]));
    assert_eq!(c.purge_expired_messages(499).unwrap(), 0);
    assert_eq!(c.purge_expired_messages(500).unwrap(), 1);
    assert!(c.message(g, "temp").unwrap().is_none());

    // restart, then nothing readable on disk
    drop(c);
    let c = Client::open(&p, "pw").unwrap();
    assert_eq!(c.messages(g, 10, None).unwrap().len(), 5);
    assert_eq!(c.forget_messages(b"group-2").unwrap(), 1);
    drop(c);
    let raw = std::fs::read(&p).unwrap();
    assert!(!raw.windows(4).any(|w| w == b"9f1d"));
}
