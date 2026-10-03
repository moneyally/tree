//! Delivery order, epochs, echoes and commit ordering: what happens when the
//! network does not deliver messages in the ideal order.

mod common;

use common::{two_person_chat, Now};
use tree_core::{Client, Incoming, TreeError};

fn is_message(r: &Result<Incoming, TreeError>, body: &[u8]) -> bool {
    matches!(r, Ok(Incoming::Message { body: b, .. }) if b == body)
}

fn rejected_with(r: &Result<Incoming, TreeError>, what: &str) -> bool {
    matches!(r, Err(TreeError::Rejected(s)) if s.contains(what))
}

/// Out-of-order delivery inside the configured tolerance works.
#[test]
fn out_of_order_within_tolerance() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let msgs: Vec<Vec<u8>> = (0..20).map(|i| a.send(&alice, format!("m{i}").as_bytes()).unwrap()).collect();
    for (i, m) in msgs.iter().enumerate().rev() {
        assert!(is_message(&b.receive(&bob, m), format!("m{i}").as_bytes()), "m{i} lost");
    }
}

/// Tolerance boundary. After the newest message (generation 33) arrives, the
/// receiver's ratchet head is at 34, and keys up to 32 generations behind
/// the head are kept: generations 2..=32 still decrypt, 0 and 1 do not.
/// (So in practice "32" means the 31 messages before the newest one.)
#[test]
fn out_of_order_tolerance_boundary() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let msgs: Vec<Vec<u8>> = (0..34).map(|i| a.send(&alice, format!("m{i}").as_bytes()).unwrap()).collect();
    assert!(is_message(&b.receive(&bob, &msgs[33]), b"m33"));
    for (i, m) in msgs.iter().enumerate().take(33).skip(2) {
        assert!(is_message(&b.receive(&bob, m), format!("m{i}").as_bytes()), "m{i} lost");
    }
    assert!(matches!(b.receive(&bob, &msgs[1]), Err(TreeError::Rejected(_))));
    assert!(matches!(b.receive(&bob, &msgs[0]), Err(TreeError::Rejected(_))));
}

/// The receiver will not derive keys more than 1000 messages ahead.
#[test]
fn forward_distance_bounded() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let mut last = Vec::new();
    for _ in 0..1002 {
        last = a.send(&alice, b"flood").unwrap();
    }
    // Generation 1001 is 1001 steps ahead of the receiver: refused.
    assert!(matches!(b.receive(&bob, &last), Err(TreeError::Rejected(_))));
}

/// F-002 (fixed): a message sent in epoch N that arrives after the receiver
/// moved on is still read while N is one of the 2 retained past epochs, with
/// the right sender.
#[test]
fn message_from_previous_epoch_after_commit_is_read() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let in_flight = b.send(&bob, b"sent at epoch 1").unwrap();
    let c = a.refresh_now(&alice).unwrap(); // alice moves to epoch 2
    assert_eq!(a.epoch(), 2);
    assert_eq!(
        a.receive(&alice, &in_flight).unwrap(),
        Incoming::Message { from: bob.member_id(), name: "bob".into(), body: b"sent at epoch 1".to_vec() }
    );
    b.receive(&bob, &c).unwrap();
    let m = b.send(&bob, b"epoch 2").unwrap();
    assert!(is_message(&a.receive(&alice, &m), b"epoch 2"));
}

/// Past-epoch window boundary: N-1 and N-2 are read, N-3 is not (its
/// envelope key and MLS secrets are gone).
#[test]
fn past_epoch_window_is_two_epochs() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let msgs: Vec<Vec<u8>> = (0..3).map(|i| b.send(&bob, format!("e1 m{i}").as_bytes()).unwrap()).collect();
    a.refresh_now(&alice).unwrap(); // epoch 2: epoch 1 is N-1
    assert!(is_message(&a.receive(&alice, &msgs[0]), b"e1 m0"));
    a.refresh_now(&alice).unwrap(); // epoch 3: epoch 1 is N-2
    assert!(is_message(&a.receive(&alice, &msgs[1]), b"e1 m1"));
    a.refresh_now(&alice).unwrap(); // epoch 4: epoch 1 is N-3
    assert!(rejected_with(&a.receive(&alice, &msgs[2]), "seal"));
}

/// The sender of a past-epoch message is named by the members of THAT epoch,
/// even if its leaf now belongs to someone else.
#[test]
fn past_epoch_sender_is_the_member_of_that_epoch() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let eve = Client::new("eve").unwrap();
    let add = a.add_now(&alice, &eve.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut e = eve.join(&add.welcome).unwrap();
    let from_eve = e.send(&eve, b"eve, epoch 2").unwrap();
    // Eve (leaf 2) is removed, dave takes leaf 2.
    a.remove_now(&alice, &[eve.member_id()]).unwrap();
    let dave = Client::new("dave").unwrap();
    a.add_now(&alice, &dave.key_package().unwrap()).unwrap();
    assert_eq!(a.epoch(), 4);
    match a.receive(&alice, &from_eve).unwrap() {
        Incoming::Message { from, name, .. } => {
            assert_eq!(from, eve.member_id());
            assert_eq!(name, "eve");
        }
        other => panic!("{other:?}"),
    }
}

/// A message sealed in epoch N+1 delivered before the commit that creates
/// N+1 is refused (the receiver cannot verify it yet) and is NOT consumed:
/// after the commit arrives, the same bytes are readable.
#[test]
fn message_from_next_epoch_before_commit() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let c = a.refresh_now(&alice).unwrap();
    let early = a.send(&alice, b"epoch 2 message").unwrap();
    assert_eq!(
        b.receive(&bob, &early).unwrap(),
        Incoming::HeldForRetry { epoch: 2 }
    );
    assert_eq!(b.receive(&bob, &early).unwrap(), Incoming::HeldForRetry { epoch: 2 });
    b.receive(&bob, &c).unwrap();
    assert!(is_message(&b.receive(&bob, &early), b"epoch 2 message"));
}

/// A removed member's messages of the epoch before its removal stay readable
/// inside the past-epoch window: they are valid epoch-N messages. This
/// includes messages its client creates AFTER the removal if it ignores the
/// removal and keeps sending in epoch N (PROTOCOL.md 6.6, claim C11). Once
/// that epoch leaves the window, nothing from it is accepted.
#[test]
fn removed_members_old_epoch_messages() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let eve = Client::new("eve").unwrap();
    let add = a.add_now(&alice, &eve.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut e = eve.join(&add.welcome).unwrap();

    let early = e.send(&eve, b"before removal (1)").unwrap();
    let late = e.send(&eve, b"before removal (2)").unwrap();
    assert!(is_message(&b.receive(&bob, &early), b"before removal (1)"));

    let rm = a.remove_now(&alice, &[eve.member_id()]).unwrap();
    assert!(is_message(&a.receive(&alice, &late), b"before removal (2)"));
    b.receive(&bob, &rm).unwrap();
    assert!(is_message(&b.receive(&bob, &late), b"before removal (2)"));
    // Eve's client ignores the removal and keeps sending in epoch 2.
    let after = e.send(&eve, b"after removal").unwrap();
    assert!(is_message(&b.receive(&bob, &after), b"after removal"));
    // Two more epochs and epoch 2 has left the window.
    let r = a.refresh_now(&alice).unwrap();
    b.receive(&bob, &r).unwrap();
    let r = a.refresh_now(&alice).unwrap();
    b.receive(&bob, &r).unwrap();
    let much_later = e.send(&eve, b"much later").unwrap();
    assert!(b.receive(&bob, &much_later).is_err());
}

/// A commit for an old epoch delivered again (replay) is refused before MLS
/// and does not change state.
#[test]
fn commit_replay_rejected() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let c = a.refresh_now(&alice).unwrap();
    b.receive(&bob, &c).unwrap();
    let code = b.verification_code();
    assert!(rejected_with(&b.receive(&bob, &c), "past epoch"));
    assert_eq!(b.epoch(), 2);
    assert_eq!(b.verification_code(), code);
}

/// F-002: a commit made in a past epoch is never merged, even though its
/// envelope key is still known.
#[test]
fn past_epoch_commit_rejected() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let lost = b.refresh_keys(&bob).unwrap(); // made in epoch 1, never accepted
    a.refresh_now(&alice).unwrap(); // epoch 2
    assert!(rejected_with(&a.receive(&alice, &lost.commit), "past epoch"));
    assert_eq!(a.epoch(), 2);
}

/// F-004 (fixed): echoes of our own traffic are recognised. An own
/// application message and an own merged commit both come back as `OwnEcho`.
#[test]
fn own_echoes() {
    let (alice, _bob, mut a, _b) = two_person_chat();
    let m = a.send(&alice, b"mine").unwrap();
    assert_eq!(a.receive(&alice, &m).unwrap(), Incoming::OwnEcho);
    let c = a.refresh_now(&alice).unwrap();
    assert_eq!(a.receive(&alice, &c).unwrap(), Incoming::OwnEcho);
    assert_eq!(a.receive(&alice, &c).unwrap(), Incoming::OwnEcho, "every repeat");
    // The group is unaffected and an echo does not burn anything.
    assert!(a.is_member());
    assert_eq!(a.epoch(), 2);
    let m2 = a.send(&alice, b"mine again").unwrap();
    assert_eq!(a.receive(&alice, &m2).unwrap(), Incoming::OwnEcho);
}

/// Echo hashes are kept only while the epoch is in the window; an older own
/// commit is then refused like any other old commit.
#[test]
fn own_commit_echo_forgotten_with_its_epoch() {
    let (alice, _bob, mut a, _b) = two_person_chat();
    let c = a.refresh_now(&alice).unwrap(); // sealed in 1
    a.refresh_now(&alice).unwrap();
    assert_eq!(a.receive(&alice, &c).unwrap(), Incoming::OwnEcho, "epoch 1 is N-2");
    a.refresh_now(&alice).unwrap();
    assert!(a.receive(&alice, &c).is_err(), "epoch 1 is N-3");
}

// ----- two-phase commits (F-003) -------------------------------------------

/// F-003 (fixed): two members commit in the same epoch. The server accepts
/// alice's; bob receives it while his own is pending: his is discarded
/// automatically, both stay in one group state, and bob can try again.
#[test]
fn concurrent_commits_no_longer_fork() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let ca = a.refresh_keys(&alice).unwrap();
    let cb = b.refresh_keys(&bob).unwrap();
    assert_eq!((ca.epoch, cb.epoch), (1, 1));
    // server: alice first
    a.confirm_commit(&alice).unwrap();
    assert_eq!(
        b.receive(&bob, &ca.commit).unwrap(),
        Incoming::GroupChanged { added: vec![], removed: vec![], epoch: 2, own_commit_discarded: true }
    );
    assert!(b.pending_commit().is_none());
    assert_eq!(a.epoch(), b.epoch());
    assert_eq!(a.verification_code(), b.verification_code(), "no fork");
    let m = a.send(&alice, b"can you read me?").unwrap();
    assert!(is_message(&b.receive(&bob, &m), b"can you read me?"));
    // bob's discarded commit is never accepted later
    assert!(a.receive(&alice, &cb.commit).is_err());
    // bob decides again in epoch 2
    let again = b.refresh_keys(&bob).unwrap();
    assert_eq!(again.epoch, 2);
    b.confirm_commit(&bob).unwrap();
    a.receive(&alice, &again.commit).unwrap();
    assert_eq!(a.verification_code(), b.verification_code());
}

/// A pending commit changes nothing until it is confirmed.
#[test]
fn pending_commit_changes_nothing() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let carol = Client::new("carol").unwrap();
    let code = a.verification_code();
    let p = a.add(&alice, &[carol.key_package().unwrap()]).unwrap();
    assert_eq!(p.group_id, a.id());
    assert_eq!(p.epoch, 1);
    assert_eq!(p.added, vec![carol.member_id()]);
    assert!(p.removed.is_empty());
    assert!(p.welcome.is_some());
    assert_eq!(a.epoch(), 1);
    assert_eq!(a.verification_code(), code);
    assert_eq!(common::names(&a), vec!["alice", "bob"]);
    assert_eq!(a.pending_commit(), Some(p.clone()));
    // Messages still flow in epoch 1 both ways.
    let m = a.send(&alice, b"while pending").unwrap();
    assert!(is_message(&b.receive(&bob, &m), b"while pending"));
    let m = b.send(&bob, b"to a pending alice").unwrap();
    assert!(is_message(&a.receive(&alice, &m), b"to a pending alice"));
    // Confirm: now the change applies.
    assert_eq!(a.confirm_commit(&alice).unwrap(), 2);
    assert!(a.pending_commit().is_none());
    assert_eq!(common::names(&a), vec!["alice", "bob", "carol"]);
    b.receive(&bob, &p.commit).unwrap();
    let c = carol.join(p.welcome.as_ref().unwrap()).unwrap();
    assert_eq!(c.verification_code(), a.verification_code());
}

/// The pending removal lists the removed member ids.
#[test]
fn pending_removal_lists_removed() {
    let (alice, bob, mut a, _b) = two_person_chat();
    let p = a.remove(&alice, &[bob.member_id()]).unwrap();
    assert_eq!(p.removed, vec![bob.member_id()]);
    assert!(p.added.is_empty());
    assert!(p.welcome.is_none());
}

/// While a commit is pending no other commit can be made.
#[test]
fn one_pending_commit_at_a_time() {
    let (alice, bob, mut a, _b) = two_person_chat();
    let first = a.refresh_keys(&alice).unwrap();
    assert!(matches!(a.refresh_keys(&alice), Err(TreeError::CommitPending)));
    let kp = Client::new("x").unwrap().key_package().unwrap();
    assert!(matches!(a.add(&alice, &[kp]), Err(TreeError::CommitPending)));
    assert!(matches!(a.remove(&alice, &[bob.member_id()]), Err(TreeError::CommitPending)));
    assert_eq!(a.pending_commit().unwrap(), first, "the first one is untouched");
}

/// Discarding drops the commit; a new one can be made. Discard with nothing
/// pending is a no-op; confirm with nothing pending is an error.
#[test]
fn discard_and_confirm_without_pending() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    assert!(matches!(a.confirm_commit(&alice), Err(TreeError::NoPendingCommit)));
    a.discard_commit(&alice).unwrap();
    let dropped = a.refresh_keys(&alice).unwrap();
    a.discard_commit(&alice).unwrap();
    assert!(a.pending_commit().is_none());
    assert_eq!(a.epoch(), 1);
    let c = a.refresh_now(&alice).unwrap();
    assert_ne!(c, dropped.commit);
    b.receive(&bob, &c).unwrap();
    assert_eq!(a.verification_code(), b.verification_code());
}

/// PROTOCOL.md 7.1 step 6: our own pending commit arriving from the mailbox
/// means the server accepted it: it is merged.
#[test]
fn own_pending_commit_arriving_is_merged() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let p = a.refresh_keys(&alice).unwrap();
    assert_eq!(a.receive(&alice, &p.commit).unwrap(), Incoming::OwnCommitMerged { epoch: 2 });
    assert!(a.pending_commit().is_none());
    assert_eq!(a.receive(&alice, &p.commit).unwrap(), Incoming::OwnEcho);
    b.receive(&bob, &p.commit).unwrap();
    assert_eq!(a.verification_code(), b.verification_code());
}

/// The key package of a lost add can be used again for the retry (its
/// welcome was never delivered).
#[test]
fn lost_add_retried_with_same_key_package() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let carol = Client::new("carol").unwrap();
    let kp = carol.key_package().unwrap();
    let lost = a.add(&alice, &[&kp]).unwrap();
    let won = b.refresh_now(&bob).unwrap();
    assert!(matches!(
        a.receive(&alice, &won).unwrap(),
        Incoming::GroupChanged { own_commit_discarded: true, .. }
    ));
    let retry = a.add(&alice, &[&kp]).unwrap();
    assert_eq!(retry.epoch, 2);
    a.confirm_commit(&alice).unwrap();
    b.receive(&bob, &retry.commit).unwrap();
    let c = carol.join(retry.welcome.as_ref().unwrap()).unwrap();
    assert_eq!(c.verification_code(), a.verification_code());
    // The lost welcome belongs to a branch that never existed.
    assert!(carol.join(lost.welcome.as_ref().unwrap()).is_err());
}

/// A device that has joined is told to refresh its key soon; its first own
/// key refresh clears that. An add (no update path) does not.
#[test]
fn joiner_should_refresh_keys() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    assert!(!a.should_refresh_keys());
    assert!(b.should_refresh_keys());
    let carol = Client::new("carol").unwrap();
    let add = b.add_now(&bob, &carol.key_package().unwrap()).unwrap();
    assert!(b.should_refresh_keys(), "an add does not refresh the adder's key");
    a.receive(&alice, &add.commit).unwrap();
    let r = b.refresh_now(&bob).unwrap();
    assert!(!b.should_refresh_keys());
    a.receive(&alice, &r).unwrap();
    assert_eq!(a.verification_code(), b.verification_code());
}
