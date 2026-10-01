//! Delivery order, epochs and echoes: what happens when the network does
//! not deliver messages in the ideal order.

mod common;

use common::two_person_chat;
use tree_core::{Client, Incoming, TreeError};

fn is_message(r: &Result<Incoming, TreeError>, body: &[u8]) -> bool {
    matches!(r, Ok(Incoming::Message { body: b, .. }) if b == body)
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

/// A message sent in epoch N and delivered after the receiver moved to
/// epoch N+1 is not readable. KNOWN LIMITATION (F-002): no past-epoch
/// window, so messages in flight during a commit are lost.
#[test]
fn message_from_previous_epoch_after_commit_is_lost() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let in_flight = b.send(&bob, b"sent at epoch 1").unwrap();
    let c = a.refresh_keys(&alice).unwrap(); // alice moves to epoch 2
    assert_eq!(a.epoch(), 2);
    match a.receive(&alice, &in_flight) {
        Err(TreeError::Rejected(s)) => assert!(s.contains("seal"), "{s}"),
        other => panic!("old-epoch message: {other:?}"),
    }
    b.receive(&bob, &c).unwrap();
    // Messages of the new epoch flow again.
    let m = b.send(&bob, b"epoch 2").unwrap();
    assert!(is_message(&a.receive(&alice, &m), b"epoch 2"));
}

/// A message sealed in epoch N+1 delivered before the commit that creates
/// N+1 is refused (the receiver cannot verify it yet) and is NOT consumed:
/// after the commit arrives, the same bytes are readable.
#[test]
fn message_from_next_epoch_before_commit() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let c = a.refresh_keys(&alice).unwrap();
    let early = a.send(&alice, b"epoch 2 message").unwrap();
    assert!(b.receive(&bob, &early).is_err());
    b.receive(&bob, &c).unwrap();
    assert!(is_message(&b.receive(&bob, &early), b"epoch 2 message"));
}

/// A removed member's message sent BEFORE the removal: readable if it arrives
/// before the removal commit, refused after it.
#[test]
fn removed_members_old_messages() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let eve = Client::new("eve").unwrap();
    let add = a.add(&alice, &eve.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut e = eve.join(&add.welcome).unwrap();

    let early = e.send(&eve, b"before removal (1)").unwrap();
    let late = e.send(&eve, b"before removal (2)").unwrap();
    assert!(is_message(&b.receive(&bob, &early), b"before removal (1)"));

    let rm = a.remove(&alice, "eve").unwrap();
    assert!(matches!(a.receive(&alice, &late), Err(TreeError::Rejected(_))));
    b.receive(&bob, &rm).unwrap();
    assert!(matches!(b.receive(&bob, &late), Err(TreeError::Rejected(_))));
    // Messages eve creates after removal (her client ignored it) are refused too.
    let after = e.send(&eve, b"after removal").unwrap();
    assert!(b.receive(&bob, &after).is_err());
}

/// A commit for an old epoch delivered again (replay) is refused and does not
/// change state.
#[test]
fn commit_replay_rejected() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let c = a.refresh_keys(&alice).unwrap();
    b.receive(&bob, &c).unwrap();
    let code = b.verification_code();
    assert!(b.receive(&bob, &c).is_err());
    assert_eq!(b.epoch(), 2);
    assert_eq!(b.verification_code(), code);
}

/// Server echoes of our own traffic. An own application message comes back
/// as `OwnEcho`, but an own COMMIT comes back as a seal error (F-004): it was
/// sealed with the previous epoch's key and we already merged it, so the
/// app cannot tell it apart from a forged message.
#[test]
fn own_echoes() {
    let (alice, _bob, mut a, _b) = two_person_chat();
    let m = a.send(&alice, b"mine").unwrap();
    assert_eq!(a.receive(&alice, &m).unwrap(), Incoming::OwnEcho);
    let c = a.refresh_keys(&alice).unwrap();
    match a.receive(&alice, &c) {
        Err(TreeError::Rejected(s)) => assert!(s.contains("seal"), "{s}"),
        other => panic!("own commit echo: {other:?}"),
    }
    // The group is unaffected and an echo does not burn anything.
    assert!(a.is_member());
    assert_eq!(a.epoch(), 2);
    let m2 = a.send(&alice, b"mine again").unwrap();
    assert_eq!(a.receive(&alice, &m2).unwrap(), Incoming::OwnEcho);
}

/// Two members commit at the same time. Each merges its own commit at once,
/// so each rejects the other's: the group forks. KNOWN LIMITATION (F-003):
/// commits must be ordered by the server before members merge them.
#[test]
fn concurrent_commits_fork_the_group() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let ca = a.refresh_keys(&alice).unwrap();
    let cb = b.refresh_keys(&bob).unwrap();
    assert!(a.receive(&alice, &cb).is_err());
    assert!(b.receive(&bob, &ca).is_err());
    assert_eq!(a.epoch(), b.epoch());
    assert_ne!(a.verification_code(), b.verification_code(), "forked");
    let m = a.send(&alice, b"can you read me?").unwrap();
    assert!(b.receive(&bob, &m).is_err());
}
