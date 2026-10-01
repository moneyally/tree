//! Security checks on the real core (not a model).
//!
//! Each test plays an attacker against Tree's own design and asserts it fails.

mod common;

#[allow(unused_imports)]
use common::Now;

use openmls::prelude::Ciphersuite;
use tree_core::{
    features::{Caller, FeatureError, Plan, Registry, Scope, State},
    Client, Group, Incoming, LibcruxProvider, TreeError,
};

fn two_person_chat() -> (Client, Client, Group, Group) {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut a = alice.create_group().unwrap();
    let w = a.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    let b = bob.join(&w).unwrap();
    (alice, bob, a, b)
}

/// A removed member whose client IGNORES the removal commit (malicious or
/// modified app) must still be unable to read messages from the new epoch.
#[test]
fn removed_member_cannot_decrypt_even_if_ignoring_removal() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let eve = Client::new("eve").unwrap();
    let add = a.add_now(&alice, &eve.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut e = eve.join(&add.welcome).unwrap();

    // Eve can read while she is a member.
    let m = a.send(&alice, b"hello everyone").unwrap();
    assert!(matches!(e.receive(&eve, &m).unwrap(), Incoming::Message { .. }));

    // Alice removes Eve. Eve's client never processes the removal.
    let rm = a.remove_now(&alice, &[eve.member_id()]).unwrap();
    b.receive(&bob, &rm).unwrap();
    let _ = rm; // never delivered to eve

    let secret = a.send(&alice, b"after eve left").unwrap();
    assert!(matches!(b.receive(&bob, &secret).unwrap(), Incoming::Message { .. }));
    let res = e.receive(&eve, &secret);
    assert!(
        matches!(res, Err(TreeError::Rejected(_))),
        "removed member decrypted a new-epoch message: {res:?}"
    );
}

/// Flipping any byte of a ciphertext must make it undecryptable.
#[test]
fn tampered_ciphertext_rejected() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let m = a.send(&alice, b"do not change me").unwrap();
    let mut rejected = 0;
    let positions = [m.len() / 3, m.len() / 2, m.len() - 20, m.len() - 1];
    for &i in &positions {
        let mut t = m.clone();
        t[i] ^= 0x01;
        if b.receive(&bob, &t).is_err() {
            rejected += 1;
        }
    }
    assert_eq!(rejected, positions.len());
    // The untouched original still works afterwards.
    assert!(matches!(b.receive(&bob, &m).unwrap(), Incoming::Message { .. }));
}

/// The same ciphertext delivered twice (server replay) is rejected the
/// second time: message keys are deleted after use (forward secrecy).
#[test]
fn replay_rejected() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let m = a.send(&alice, b"only once").unwrap();
    assert!(b.receive(&bob, &m).is_ok());
    assert!(b.receive(&bob, &m).is_err(), "replayed message was accepted");
}

/// A message from one group must not be accepted by another group,
/// even when the receiver is a member of both.
#[test]
fn cross_group_message_rejected() {
    let (alice, bob, mut a1, mut b1) = two_person_chat();
    let mut a2 = alice.create_group().unwrap();
    let w = a2.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    let _b2 = bob.join(&w).unwrap();

    let for_group2 = a2.send(&alice, b"meant for group 2").unwrap();
    assert!(b1.receive(&bob, &for_group2).is_err());
    let _ = &mut a1;
}

/// An outsider who forges a group with the SAME group id cannot inject
/// messages into the real group.
#[test]
fn outsider_with_same_group_id_cannot_inject() {
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;

    let (_alice, bob, a, mut b) = two_person_chat();

    let provider = tree_core::DefaultProvider::default();
    let signer = SignatureKeyPair::new(tree_core::TREE_CIPHERSUITE.signature_algorithm()).unwrap();
    signer.store(provider.storage()).unwrap();
    let cred = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(), // even impersonating the name
        signature_key: signer.to_public_vec().into(),
    };
    let cfg = MlsGroupCreateConfig::builder()
        .ciphersuite(tree_core::TREE_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut fake = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &cfg,
        GroupId::from_slice(&a.id()),
        cred,
    )
    .unwrap();
    let forged = fake
        .create_message(&provider, &signer, b"I am alice, send me money")
        .unwrap()
        .to_bytes()
        .unwrap();
    assert!(b.receive(&bob, &forged).is_err(), "outsider injected a message");
}

/// A key package whose signature was tampered with is refused.
#[test]
fn tampered_key_package_rejected() {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut kp = bob.key_package().unwrap();
    let last = kp.len() - 5;
    kp[last] ^= 0x01;
    let mut a = alice.create_group().unwrap();
    assert!(a.add_now(&alice, &kp).is_err());
}

/// A device on a different ciphersuite cannot be added silently: no
/// downgrade from the post-quantum hybrid suite to a classical one.
#[test]
fn ciphersuite_downgrade_rejected() {
    let alice = Client::new("alice").unwrap();
    let classical = Client::with_provider(
        "old",
        tree_core::DefaultProvider::default(),
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    )
    .unwrap();
    let mut a = alice.create_group().unwrap();
    let res = a.add_now(&alice, &classical.key_package().unwrap());
    assert!(res.is_err(), "classical device was added to a PQ group");
}

/// The X-Wing hybrid suite on the formally verified libcrux provider
/// works end to end as an alternative.
#[test]
fn xwing_suite_on_libcrux_works() {
    let cs = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let alice = Client::with_provider("alice", LibcruxProvider::default(), cs).unwrap();
    let bob = Client::with_provider("bob", LibcruxProvider::default(), cs).unwrap();
    let kp = bob.key_package().unwrap();
    let mut a = alice.create_group().unwrap();
    let w = a.add_now(&alice, &kp).unwrap().welcome;
    let mut b = bob.join(&w).unwrap();
    let m = a.send(&alice, b"x-wing").unwrap();
    assert_eq!(
        b.receive(&bob, &m).unwrap(),
        Incoming::Message { from: alice.member_id(), body: b"x-wing".to_vec() }
    );
    println!("x-wing key package: {} bytes", kp.len());
}

/// Feature registry rules from the design document.
#[test]
fn feature_registry_rules() {
    let mut r = Registry::standard();
    let user = Caller { plan: Plan::Free, is_admin: false };
    let admin = Caller { plan: Plan::Free, is_admin: true };

    // End-to-end encryption can never be released, even by an admin.
    assert_eq!(r.release("chat.e2e", admin).unwrap_err(), FeatureError::LockedAlways("end-to-end encryption is why Tree exists"));
    // Points can never move between people.
    assert!(matches!(r.apply("points.send_to_user", None, admin), Err(FeatureError::ReleasedAlways(_))));
    // Bots can never pay out points.
    assert!(matches!(r.apply("bot.pay_out_points", None, admin), Err(FeatureError::ReleasedAlways(_))));

    // Idempotent apply/release.
    let s1 = r.apply("user.app_lock", None, user).unwrap();
    let s2 = r.apply("user.app_lock", None, user).unwrap();
    assert_eq!(s1, s2);
    assert_eq!(r.release("user.app_lock", user).unwrap().state, State::Released);
    assert_eq!(r.release("user.app_lock", user).unwrap().state, State::Released);

    // Non-admins cannot change room settings.
    assert_eq!(r.apply("chat.disappearing", Some("1d".into()), user).unwrap_err(), FeatureError::NotAdmin);
    assert_eq!(r.apply("chat.disappearing", Some("1d".into()), admin).unwrap().option.as_deref(), Some("1d"));

    // Unknown keys are errors, not silent no-ops.
    assert!(matches!(r.apply("chat.nonexistent", None, admin), Err(FeatureError::Unknown(_))));

    // Every feature in a scope is listed for the settings screen.
    assert!(r.list(Scope::User).len() > 10);
}
