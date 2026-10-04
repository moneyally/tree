//! Account recovery with the recovery phrase (PROTOCOL.md 8.6), through a
//! real server.

mod common;

use common::Env;
use tree_client::{Error, Event, Session, Words};

#[test]
fn a_lost_phone_is_replaced_with_the_phrase() {
    let env = Env::new("recovery");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.confirm_contact(alice.account_id()).unwrap();
    alice.confirm_contact(bob.account_id()).unwrap();
    alice.set_username("alice_tree").unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.send_text(&g, "hi").unwrap();
    bob.sync(0).unwrap();

    // No phrase yet: nothing can recover the account.
    assert!(!alice.has_recovery().unwrap());
    let unregistered = tree_client::Phrase::generate(12, Words::English).unwrap();
    let p = env.profile("thief");
    match Session::recover(&p, "pw", "x", &env.url, unregistered.words(), false, 8) {
        Err(Error::Server { code, .. }) => assert_eq!(code, "RECOVERY_REFUSED"),
        other => panic!("{:?}", other.map(|s| s.account_id().to_string())),
    }
    assert!(!std::path::Path::new(&p).exists(), "no profile is left behind");

    let (phrase, st) = alice.new_recovery_phrase(24, Words::Korean, None).unwrap();
    assert!(st.active && st.pending.is_none());
    assert!(alice.has_recovery().unwrap());
    let words = phrase.words().to_string();
    // A typo (one word swapped for another list word) is refused locally or by the server.
    let mut typo: Vec<&str> = words.split(' ').collect();
    typo[3] = if typo[3] == "가격" { "가구" } else { "가격" };
    assert!(Session::recover(&env.profile("typo"), "pw", "x", &env.url, &typo.join(" "), false, 8).is_err());

    // A thief with alice's unlocked phone tries to swap the phrase: it only
    // becomes pending, and alice is warned.
    let (_, st) = alice.new_recovery_phrase(12, Words::English, None).unwrap();
    assert_eq!(st.pending.as_ref().map(|p| p.0.as_str()), Some("replace"));
    assert!(alice.recovery_status().unwrap().pending.is_some());

    // The phone is lost: a new device recovers the account with the real
    // phrase, removes the old one and cancels the pending swap.
    let mut alice2 = Session::recover(&env.profile("alice2"), "new pw", "alice", &env.url, &words, true, 8).unwrap();
    assert_eq!(alice2.account_id(), alice.account_id());
    assert_ne!(alice2.device_id(), alice.device_id());
    // The old device is gone from the server.
    assert!(matches!(alice.sync(0), Err(Error::Server { status: 401, .. })));
    assert!(alice2.recovery_status().unwrap().pending.is_none());
    // The username stays with the account.
    assert_eq!(bob.find("@alice_tree").unwrap().as_deref(), Some(alice.account_id()));

    // Groups are not restored: bob adds the new device and sees a key change.
    bob.invite(&g, alice2.account_id()).unwrap();
    let ev = alice2.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Joined { .. })), "{ev:?}");
    let msg = alice2.send_text(&g, "back with a new phone").unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Text { id, .. } if *id == msg)), "{ev:?}");

    // With the current phrase a new one replaces it at once; release likewise.
    let (again, st) = alice2.new_recovery_phrase(12, Words::English, Some(&words)).unwrap();
    assert!(st.pending.is_none());
    assert!(Session::recover(&env.profile("old"), "pw", "x", &env.url, &words, false, 8).is_err(), "old phrase no longer works");
    let alice3 = Session::recover(&env.profile("alice3"), "pw", "alice", &env.url, again.words(), false, 8).unwrap();
    assert_eq!(alice3.account_id(), alice2.account_id());
    assert!(alice2.apply_feature("user.recovery_phrase", None).is_err(), "only with the words shown");
    // Without the phrase a release only becomes pending, and the setting
    // says so honestly: still applied (the phrase still recovers the
    // account), with the date the server drops the key.
    use tree_core::features::State;
    let st = alice2.release_feature("user.recovery_phrase").unwrap();
    assert_eq!(st.state, State::Applied);
    assert!(alice2.has_recovery().unwrap());
    let server = alice2.recovery_status().unwrap().pending.unwrap();
    assert_eq!(server.0, "release");
    let until = alice2.release_pending("user.recovery_phrase").unwrap().expect("release pending");
    assert_eq!(until, server.1);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!(until > now + 6 * 86400, "7 days from now");
    assert!(alice2.features().unwrap().iter().any(|f| f.key == "user.recovery_phrase" && f.state == State::Applied));
    // Releasing again: still pending (the server restarts the wait).
    alice2.release_feature("user.recovery_phrase").unwrap();
    assert!(alice2.release_pending("user.recovery_phrase").unwrap().is_some_and(|t| t >= until));
    // With the phrase it is released at once; nothing is pending any more.
    let st = alice2.release_recovery(Some(again.words())).unwrap();
    assert!(!st.active && st.pending.is_none());
    assert_eq!(alice2.feature("user.recovery_phrase").unwrap().state, State::Released);
    assert_eq!(alice2.release_pending("user.recovery_phrase").unwrap(), None);
    assert!(!alice2.has_recovery().unwrap());
    assert!(Session::recover(&env.profile("late"), "pw", "x", &env.url, again.words(), false, 8).is_err());
}

/// A release without the phrase reads "applied, release pending until
/// <date>" until the server really dropped the key, then "released"; a
/// cancelled release (the phrase was used) reads applied again.
#[test]
fn a_pending_release_is_reported_until_the_server_drops_the_key() {
    use tree_core::features::State;
    let env = Env::new("recovery-pending");
    let alice = env.device("alice");
    let (phrase, _) = alice.new_recovery_phrase(12, Words::English, None).unwrap();
    assert_eq!(alice.feature("user.recovery_phrase").unwrap().state, State::Applied);
    alice.release_feature("user.recovery_phrase").unwrap();
    assert!(alice.release_pending("user.recovery_phrase").unwrap().is_some());

    // Someone with the phrase recovers: the server cancels the release.
    let _other = Session::recover(&env.profile("alice-new"), "pw", "alice", &env.url, phrase.words(), false, 8).unwrap();
    let st = alice.recovery_status().unwrap();
    assert!(st.active && st.pending.is_none());
    assert_eq!(alice.release_pending("user.recovery_phrase").unwrap(), None);
    assert_eq!(alice.feature("user.recovery_phrase").unwrap().state, State::Applied);

    // Released again, and the 7 days pass on the server.
    alice.release_feature("user.recovery_phrase").unwrap();
    assert_eq!(alice.feature("user.recovery_phrase").unwrap().state, State::Applied);
    let n = env.sql("UPDATE account_recovery SET pending_since = pending_since - 8 * 86400 WHERE account_id = ?", alice.account_id());
    assert_eq!(n, 1);
    let st = alice.recovery_status().unwrap();
    assert!(!st.active && st.pending.is_none());
    assert_eq!(alice.feature("user.recovery_phrase").unwrap().state, State::Released);
    assert_eq!(alice.release_pending("user.recovery_phrase").unwrap(), None);
    assert!(Session::recover(&env.profile("late"), "pw", "x", &env.url, phrase.words(), false, 8).is_err());
}

#[test]
fn deleting_the_account_leaves_nothing_behind() {
    let env = Env::new("delete");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.confirm_contact(alice.account_id()).unwrap();
    alice.set_username("gone_soon").unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    // bob (no admin) deletes his account: alice is asked to remove him.
    let path = env.profile("bob");
    let bob_account = bob.account_id().to_string();
    bob.delete_account(&path).unwrap();
    assert!(!std::path::Path::new(&path).exists() && !std::path::Path::new(&format!("{path}.hdr")).exists());
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::LeaveRequested { .. })), "{ev:?}");
    assert!(alice.invite(&g, &bob_account).is_err(), "no such account any more");
    // alice deletes hers; the username is free again.
    let apath = env.profile("alice");
    alice.delete_account(&apath).unwrap();
    let carol = env.device("carol");
    carol.set_username("gone_soon").unwrap();
    assert!(carol.find("@gone_soon").unwrap().is_some());
}
