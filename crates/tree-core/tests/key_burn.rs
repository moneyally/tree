//! Regression: a tampered copy delivered before the genuine message must not
//! "burn" the message key. Found during security testing (2026-10-01): without
//! the outer envelope seal, tampering the content area made the genuine
//! message permanently undecryptable.

use tree_core::{Client, Incoming};

#[test]
fn tampered_copy_does_not_burn_genuine_message() {
    for frac in [10, 20, 30, 40, 50, 60, 70, 80, 90, 99] {
        let alice = Client::new("alice").unwrap();
        let bob = Client::new("bob").unwrap();
        let mut a = alice.create_group().unwrap();
        let w = a.add(&alice, &bob.key_package().unwrap()).unwrap().welcome;
        let mut b = bob.join(&w).unwrap();

        let m = a.send(&alice, b"genuine").unwrap();
        let i = (m.len() * frac / 100).min(m.len() - 1);
        let mut t = m.clone();
        t[i] ^= 0x01;
        assert!(b.receive(&bob, &t).is_err(), "tampered copy accepted at byte {i}");
        assert!(
            matches!(b.receive(&bob, &m), Ok(Incoming::Message { .. })),
            "genuine message lost after tamper at byte {i}"
        );
    }
}
