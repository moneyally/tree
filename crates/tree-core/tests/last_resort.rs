//! Last-resort key packages (RFC 9420 section 16.8): usable for many joins,
//! unusable once forgotten; one-time key packages stay one-time.

mod common;

use common::Now;
use openmls::prelude::{tls_codec::Deserialize, KeyPackageIn, ProtocolVersion};
use openmls_traits::OpenMlsProvider;
use tree_core::{Client, DefaultProvider, Incoming};

fn is_last_resort(kp: &[u8]) -> bool {
    let p = DefaultProvider::default();
    KeyPackageIn::tls_deserialize_exact(kp)
        .unwrap()
        .validate(p.crypto(), ProtocolVersion::Mls10)
        .unwrap()
        .last_resort()
}

#[test]
fn last_resort_key_package_serves_many_joins_until_forgotten() {
    let bob = Client::new("bob").unwrap();
    let lr = bob.last_resort_key_package().unwrap();
    assert!(is_last_resort(&lr));
    assert!(!is_last_resort(&bob.key_package().unwrap()));

    // Two people add Bob with the same package, to two groups; both work.
    for name in ["alice", "carol"] {
        let adder = Client::new(name).unwrap();
        let mut g = adder.create_group().unwrap();
        let w = g.add_now(&adder, &lr).unwrap().welcome;
        let mut b = bob.join(&w).unwrap();
        let m = g.send(&adder, b"hi").unwrap();
        assert!(matches!(b.receive(&bob, &m), Ok(Incoming::Message { body, .. }) if body == b"hi"));
    }

    // Forgotten: a welcome made from it can no longer be opened.
    bob.forget_key_package(&lr).unwrap();
    let dave = Client::new("dave").unwrap();
    let mut g = dave.create_group().unwrap();
    let w = g.add_now(&dave, &lr).unwrap().welcome;
    assert!(bob.join(&w).is_err());
    assert!(bob.forget_key_package(b"junk").is_err());
}

#[test]
fn one_time_key_package_still_burns() {
    let bob = Client::new("bob").unwrap();
    let kp = bob.key_package().unwrap();
    for (i, name) in ["alice", "carol"].into_iter().enumerate() {
        let adder = Client::new(name).unwrap();
        let mut g = adder.create_group().unwrap();
        let w = g.add_now(&adder, &kp).unwrap().welcome;
        assert_eq!(bob.join(&w).is_ok(), i == 0, "{name}");
    }
}
