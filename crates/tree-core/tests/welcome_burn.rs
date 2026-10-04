//! Regression (F-006): a damaged copy of a welcome delivered first must not
//! destroy the one-time key package, or the genuine welcome can never be
//! used and the new member cannot join.

mod common;

#[allow(unused_imports)]
use common::Now;

use tree_core::{Client, Incoming};

#[test]
fn damaged_welcome_does_not_burn_key_package() {
    for frac in [50, 75, 90, 99] {
        let alice = Client::new("alice").unwrap();
        let bob = Client::new("bob").unwrap();
        let mut a = alice.create_group().unwrap();
        let w = a
            .add_now(&alice, &bob.key_package().unwrap())
            .unwrap()
            .welcome;

        let mut t = w.clone();
        let i = (t.len() * frac / 100).min(t.len() - 1);
        t[i] ^= 0x01;
        assert!(
            bob.join(&t).is_err(),
            "damaged welcome accepted at byte {i}"
        );

        let mut b = bob
            .join(&w)
            .unwrap_or_else(|e| panic!("genuine welcome refused after damage at byte {i}: {e:?}"));
        let m = a.send(&alice, b"hi bob").unwrap();
        assert!(matches!(b.receive(&bob, &m), Ok(Incoming::Message { .. })));
        // Still one-time: the welcome cannot be used a second time.
        assert!(bob.join(&w).is_err());
    }
}
