//! Outer envelope seal (F-001): format, tag comparison and key separation.

mod common;

#[allow(unused_imports)]
use common::Now;

use common::{chat_with_insider, two_person_chat, Insider, TAG_LEN};
use tree_core::{Client, Incoming, TreeError};

fn is_message(r: &Result<Incoming, TreeError>, body: &[u8]) -> bool {
    matches!(r, Ok(Incoming::Message { body: b, .. }) if b == body)
}

/// Envelope layout: version byte 1, 32-byte tag, then the MLS bytes.
#[test]
fn envelope_layout() {
    let (alice, _bob, mut a, _b) = two_person_chat();
    let m = a.send(&alice, b"layout").unwrap();
    assert_eq!(m[0], 1, "version byte");
    assert!(m.len() > 1 + TAG_LEN + 16);
}

/// Padding: short bodies of different lengths give the same wire length.
#[test]
fn padding_hides_short_lengths() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let lens: Vec<usize> = [0usize, 1, 17, 100, 150]
        .iter()
        .map(|&n| {
            let m = a.send(&alice, &vec![b'x'; n]).unwrap();
            assert!(is_message(&b.receive(&bob, &m), &vec![b'x'; n]));
            m.len()
        })
        .collect();
    assert!(
        lens.windows(2).all(|w| w[0] == w[1]),
        "lengths differ: {lens:?}"
    );
    let long = a.send(&alice, &[b'x'; 600]).unwrap();
    assert!(long.len() > lens[0]);
}

/// Every version byte other than 1 is refused before any crypto runs, and
/// the genuine message is still readable afterwards.
#[test]
fn wrong_version_byte_rejected() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let m = a.send(&alice, b"v1 only").unwrap();
    for v in [0u8, 2, 3, 0x7f, 0x80, 0xff] {
        let mut t = m.clone();
        t[0] = v;
        let r = b.receive(&bob, &t);
        assert!(
            matches!(r, Err(TreeError::Malformed(_))),
            "version {v} accepted: {r:?}"
        );
    }
    assert!(is_message(&b.receive(&bob, &m), b"v1 only"));
}

/// Inputs shorter than version + tag are refused without panicking,
/// including the exact boundary lengths.
#[test]
fn short_envelopes_rejected_without_panic() {
    let (_alice, bob, _a, mut b) = two_person_chat();
    for len in 0..=(1 + TAG_LEN + 2) {
        for first in [0u8, 1] {
            let mut v = vec![0u8; len];
            if len > 0 {
                v[0] = first;
            }
            let r = b.receive(&bob, &v);
            assert!(r.is_err(), "len {len} accepted");
        }
    }
    // A short input with the right version byte is reported as a bad envelope,
    // not handed to the seal check.
    let mut v = vec![0u8; TAG_LEN];
    v[0] = 1;
    match b.receive(&bob, &v) {
        Err(TreeError::Malformed(s)) => assert!(s.contains("bad envelope"), "{s}"),
        other => panic!("unexpected {other:?}"),
    }
    // Exactly version + tag (empty body) is a complete envelope: the seal is
    // checked, and a wrong tag is reported as a seal failure.
    let mut v = vec![0u8; 1 + TAG_LEN];
    v[0] = 1;
    match b.receive(&bob, &v) {
        Err(TreeError::Rejected(s)) => assert!(s.contains("seal"), "{s}"),
        other => panic!("unexpected {other:?}"),
    }
}

/// An empty MLS body with a correct seal is still malformed.
#[test]
fn correctly_sealed_empty_body_rejected() {
    let (_alice, bob, _a, mut b, mut m) = chat_with_insider("mallory");
    let sealed = m.seal(&[]);
    assert_eq!(sealed.len(), 1 + TAG_LEN);
    assert!(matches!(
        b.receive(&bob, &sealed),
        Err(TreeError::Malformed(_))
    ));
}

/// Flipping any single bit of the tag is caught by the seal check
/// (reported as `Rejected`, not passed to MLS).
#[test]
fn every_tag_byte_is_checked() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let m = a.send(&alice, b"tag").unwrap();
    for i in 1..=TAG_LEN {
        for bit in [0x01u8, 0x80] {
            let mut t = m.clone();
            t[i] ^= bit;
            match b.receive(&bob, &t) {
                Err(TreeError::Rejected(s)) => assert!(s.contains("seal"), "{s}"),
                other => panic!("tag byte {i} bit {bit:#x}: {other:?}"),
            }
        }
    }
    assert!(is_message(&b.receive(&bob, &m), b"tag"));
}

/// Two compensating differences in the tag (same bit flipped in two bytes)
/// must still be rejected: the comparison ORs differences, it must not XOR
/// them together.
#[test]
fn compensating_tag_changes_rejected() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let m = a.send(&alice, b"pair").unwrap();
    for (i, j) in [(1, 2), (1, TAG_LEN), (5, 17), (TAG_LEN - 1, TAG_LEN)] {
        for bit in [0x01u8, 0x10, 0xff] {
            let mut t = m.clone();
            t[i] ^= bit;
            t[j] ^= bit;
            assert!(
                b.receive(&bob, &t).is_err(),
                "pair ({i},{j}) bit {bit:#x} accepted"
            );
        }
    }
    // Swapping two tag bytes is also caught.
    let mut t = m.clone();
    t.swap(3, 4);
    if t != m {
        assert!(b.receive(&bob, &t).is_err());
    }
    assert!(is_message(&b.receive(&bob, &m), b"pair"));
}

/// Truncated or extended envelopes are refused and do not consume the key.
#[test]
fn truncated_or_extended_rejected() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let m = a.send(&alice, b"exact length").unwrap();
    for cut in [1, 2, 16, 100, m.len() - 1 - TAG_LEN] {
        let r = b.receive(&bob, &m[..m.len() - cut]);
        assert!(r.is_err(), "truncated by {cut} accepted");
    }
    for extra in [&[0u8][..], &[0, 0, 0, 0], &[0xff; 64]] {
        let mut t = m.clone();
        t.extend_from_slice(extra);
        assert!(
            b.receive(&bob, &t).is_err(),
            "extended by {} accepted",
            extra.len()
        );
    }
    assert!(is_message(&b.receive(&bob, &m), b"exact length"));
}

/// The seal key is per group: the same two members in two groups get
/// different keys, and a body re-sealed for the wrong group is refused.
#[test]
fn sealing_key_differs_between_groups() {
    let alice = Client::new("alice").unwrap();
    let mut m = Insider::new("mallory");
    let mut m2 = Insider::new("mallory");
    let mut g1 = alice.create_group().unwrap();
    let mut g2 = alice.create_group().unwrap();
    m.join(&g1.add_now(&alice, &m.key_package()).unwrap().welcome);
    m2.join(&g2.add_now(&alice, &m2.key_package()).unwrap().welcome);
    assert_ne!(g1.id(), g2.id());
    let k1 = m.envelope_key();
    let k2 = m2.envelope_key();
    assert_ne!(k1, k2, "two groups share an envelope key");

    // A genuine message of group 2, sealed for group 2, delivered to group 1.
    let for_g2 = m2.send(b"group 2");
    assert!(matches!(
        g1.receive(&alice, &for_g2),
        Err(TreeError::Rejected(_))
    ));
    // The group-2 MLS body re-sealed with the group-1 key passes the seal but
    // MLS still refuses it (wrong group id).
    let raw_g2 = m2.raw_message(b"group 2 again");
    let resealed = m.seal(&raw_g2);
    assert!(g1.receive(&alice, &resealed).is_err());
    assert!(is_message(&g2.receive(&alice, &m2.send(b"ok")), b"ok"));
}

/// The seal key changes with every epoch.
#[test]
fn sealing_key_changes_every_epoch() {
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let k0 = m.envelope_key();
    let c = a.refresh_now(&alice).unwrap();
    b.receive(&bob, &c).unwrap();
    m.receive_commit(&c);
    let k1 = m.envelope_key();
    assert_ne!(k0, k1);
    // And the insider's sealed message from the new epoch is accepted.
    assert!(is_message(
        &b.receive(&bob, &m.send(b"new epoch")),
        b"new epoch"
    ));
}

/// A member's correctly sealed but MLS-tampered message is rejected by MLS.
/// (This also documents the residual risk of F-001: it burns that key.)
#[test]
fn insider_sealed_garbage_rejected_by_mls() {
    let (_alice, bob, _a, mut b, mut m) = chat_with_insider("mallory");
    for body in [&b"\x00"[..], b"\x00\x01", &[0xffu8; 300], b"not mls at all"] {
        let sealed = m.seal(body);
        assert!(b.receive(&bob, &sealed).is_err());
    }
    let raw = m.raw_message(b"to be tampered");
    let mut t = raw.clone();
    let i = t.len() - 3;
    t[i] ^= 1;
    let r = b.receive(&bob, &m.seal(&t));
    assert!(matches!(r, Err(TreeError::Rejected(_))), "{r:?}");
}

/// PROTOCOL.md 4.3 step 4: the MLS header must name the epoch whose envelope
/// key matched. An insider re-seals an unread message of an older epoch with
/// the current key: the seal passes, the header check refuses it. The same
/// message sealed for its own epoch is still read (past-epoch window).
#[test]
fn header_epoch_must_match_envelope_key() {
    let (alice, bob, mut a, mut b, mut m) = common::chat_with_insider("mallory");
    let old = m.raw_message(b"made in epoch 2");
    let honest = m.seal(&old); // sealed with the epoch-2 key
    let c = a.refresh_now(&alice).unwrap();
    b.receive(&bob, &c).unwrap();
    m.receive_commit(&c);
    let resealed = m.seal(&old); // same bytes, epoch-3 key
    let r = b.receive(&bob, &resealed);
    assert!(
        matches!(r, Err(TreeError::Rejected(ref s)) if s.contains("header")),
        "{r:?}"
    );
    assert!(matches!(
        b.receive(&bob, &honest),
        Ok(Incoming::Message { .. })
    ));
}
