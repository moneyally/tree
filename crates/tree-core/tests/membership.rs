//! Add / remove / receive membership handling and identity accessors.

mod common;

use common::{chat_with_insider, two_person_chat};
use openmls::prelude::Ciphersuite;
use tree_core::{Client, Incoming, TreeError, TREE_CIPHERSUITE};

#[test]
fn client_accessors() {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    assert_eq!(alice.name(), "alice");
    assert_eq!(alice.ciphersuite(), TREE_CIPHERSUITE);
    let pk = alice.signature_public_key();
    assert_eq!(pk.len(), 32, "Ed25519 public key");
    assert_ne!(pk, bob.signature_public_key());
    assert_eq!(pk, alice.signature_public_key(), "stable");
    let kp1 = alice.key_package().unwrap();
    let kp2 = alice.key_package().unwrap();
    assert!(kp1.len() > 1000, "PQ key package is large: {}", kp1.len());
    assert_ne!(kp1, kp2, "key packages are one-time and fresh");
}

#[test]
fn unsupported_ciphersuite_refused() {
    let r = Client::with_provider(
        "x",
        tree_core::DefaultProvider::default(),
        Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    );
    assert!(matches!(r, Err(TreeError::UnsupportedCiphersuite)));
}

#[test]
fn new_group_state() {
    let alice = Client::new("alice").unwrap();
    let g = alice.create_group().unwrap();
    assert!(g.is_member());
    assert_eq!(g.epoch(), 0);
    assert_eq!(g.members(), vec!["alice".to_string()]);
    assert_eq!(g.id().len(), 16, "random 16-byte group id");
    assert!(!g.verification_code().is_empty());
    let g2 = alice.create_group().unwrap();
    assert_ne!(g.id(), g2.id());
}

/// Add reports the right names and epochs to every existing member, and
/// both sides agree on members and verification code afterwards.
#[test]
fn add_reported_to_existing_members() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    assert_eq!(a.epoch(), 1);
    assert_eq!(b.epoch(), 1);
    assert_eq!(a.members(), vec!["alice", "bob"]);
    assert_eq!(b.members(), a.members());
    assert_eq!(a.verification_code(), b.verification_code());
    assert_eq!(a.id(), b.id());

    let carol = Client::new("carol").unwrap();
    let before = a.verification_code();
    let add = a.add(&alice, &carol.key_package().unwrap()).unwrap();
    assert_eq!(a.epoch(), 2);
    assert_ne!(a.verification_code(), before, "code changes with the epoch");
    assert_eq!(
        b.receive(&bob, &add.commit).unwrap(),
        Incoming::GroupChanged { added: vec!["carol".into()], removed: vec![], epoch: 2 }
    );
    let c = carol.join(&add.welcome).unwrap();
    assert_eq!(c.epoch(), 2);
    assert_eq!(c.members(), vec!["alice", "bob", "carol"]);
    assert_eq!(a.verification_code(), b.verification_code());
    assert_eq!(a.verification_code(), c.verification_code());
}

/// Remove reports the removed name to the others and `RemovedFromGroup` to
/// the removed device, which can then neither send nor receive.
#[test]
fn remove_reported_and_removed_device_locked_out() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let carol = Client::new("carol").unwrap();
    let add = a.add(&alice, &carol.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut c = carol.join(&add.welcome).unwrap();

    let rm = a.remove(&alice, "bob").unwrap();
    assert_eq!(a.members(), vec!["alice", "carol"]);
    assert_eq!(
        c.receive(&carol, &rm).unwrap(),
        Incoming::GroupChanged { added: vec![], removed: vec!["bob".into()], epoch: 3 }
    );
    assert_eq!(b.receive(&bob, &rm).unwrap(), Incoming::RemovedFromGroup);
    assert!(!b.is_member());
    assert!(a.is_member() && c.is_member());
    assert!(matches!(b.send(&bob, b"still here?"), Err(TreeError::NotAMember)));
    let m = a.send(&alice, b"bye bob").unwrap();
    assert!(matches!(b.receive(&bob, &m), Err(TreeError::NotAMember)));
    assert!(matches!(c.receive(&carol, &m), Ok(Incoming::Message { .. })));
}

#[test]
fn remove_unknown_member() {
    let (alice, _bob, mut a, _b) = two_person_chat();
    let e = a.epoch();
    match a.remove(&alice, "nobody") {
        Err(TreeError::UnknownMember(n)) => assert_eq!(n, "nobody"),
        Err(e) => panic!("wrong error {e:?}"),
        Ok(_) => panic!("removed a non-member"),
    }
    assert_eq!(a.epoch(), e, "failed remove must not change the epoch");
}

/// Removing yourself through `remove` is refused and leaves the group usable.
#[test]
fn remove_self_refused() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    assert!(a.remove(&alice, "alice").is_err());
    assert!(a.is_member());
    let m = a.send(&alice, b"still fine").unwrap();
    assert!(matches!(b.receive(&bob, &m), Ok(Incoming::Message { .. })));
}

/// A key refresh is seen by the others as a change with no membership delta.
#[test]
fn refresh_keys_processed() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let before = b.verification_code();
    let c = b.refresh_keys(&bob).unwrap();
    assert_eq!(
        a.receive(&alice, &c).unwrap(),
        Incoming::GroupChanged { added: vec![], removed: vec![], epoch: 2 }
    );
    assert_ne!(b.verification_code(), before);
    assert_eq!(a.verification_code(), b.verification_code());
    let m = a.send(&alice, b"after refresh").unwrap();
    assert_eq!(
        b.receive(&bob, &m).unwrap(),
        Incoming::Message { from: "alice".into(), body: b"after refresh".to_vec() }
    );
}

/// A one-time key package can be used for one join only.
#[test]
fn welcome_cannot_be_joined_twice() {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut a = alice.create_group().unwrap();
    let w = a.add(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    assert!(bob.join(&w).is_ok());
    assert!(bob.join(&w).is_err(), "same welcome joined twice");
}

/// A welcome for someone else's key package is refused.
#[test]
fn welcome_for_other_device_refused() {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let eve = Client::new("eve").unwrap();
    let mut a = alice.create_group().unwrap();
    let w = a.add(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    assert!(eve.join(&w).is_err());
    assert!(bob.join(&w).is_ok());
}

/// Non-welcome bytes handed to `join` are reported as malformed.
#[test]
fn join_with_group_message_refused() {
    let (alice, bob, mut a, _b) = two_person_chat();
    let m = a.send(&alice, b"x").unwrap();
    assert!(matches!(bob.join(&m), Err(TreeError::Malformed(_))));
    // The MLS part of a commit is a valid MLS message but not a welcome.
    let carol = Client::new("carol").unwrap();
    let add = a.add(&alice, &carol.key_package().unwrap()).unwrap();
    match carol.join(&add.commit[33..]) {
        Err(TreeError::Malformed(s)) => assert!(s.contains("not a welcome"), "{s}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

/// Adding the same key package twice is refused and leaves state unchanged.
#[test]
fn same_key_package_twice_refused() {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut a = alice.create_group().unwrap();
    let kp = bob.key_package().unwrap();
    a.add(&alice, &kp).unwrap();
    let e = a.epoch();
    assert!(a.add(&alice, &kp).is_err(), "same key package added twice");
    assert_eq!(a.epoch(), e);
    assert_eq!(a.members(), vec!["alice", "bob"]);
}

/// A tampered commit is refused and the genuine one still applies.
#[test]
fn tampered_commit_rejected_genuine_still_applies() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let carol = Client::new("carol").unwrap();
    let add = a.add(&alice, &carol.key_package().unwrap()).unwrap();
    for frac in [10, 50, 90, 99] {
        let mut t = add.commit.clone();
        let i = t.len() * frac / 100;
        t[i] ^= 0x04;
        assert!(b.receive(&bob, &t).is_err());
        assert_eq!(b.epoch(), 1);
    }
    assert!(matches!(b.receive(&bob, &add.commit), Ok(Incoming::GroupChanged { epoch: 2, .. })));
}

/// A proposal from a member is stored (`Incoming::Proposal`) and folded into
/// the next commit made by a Tree client.
#[test]
fn insider_proposal_stored_and_committed() {
    use openmls::prelude::LeafNodeParameters;
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let (p, s) = (&m.provider, &m.signer);
    let (prop, _) = m
        .group
        .as_mut()
        .unwrap()
        .propose_self_update(p, s, LeafNodeParameters::default())
        .unwrap();
    let sealed = m.seal(&prop.to_bytes().unwrap());
    assert_eq!(a.receive(&alice, &sealed).unwrap(), Incoming::Proposal);
    assert_eq!(b.receive(&bob, &sealed).unwrap(), Incoming::Proposal);
    // Alice's next commit (a key refresh) includes the stored proposal; Bob
    // processes it and stays in sync.
    let c = a.refresh_keys(&alice).unwrap();
    assert!(matches!(b.receive(&bob, &c), Ok(Incoming::GroupChanged { .. })));
    assert_eq!(a.verification_code(), b.verification_code());
}

/// An insider's remove proposal is committed silently by the next honest
/// commit. The committing client learns nothing, the others see a removal.
/// (Documented MLS behaviour; see docs/TESTING.md.)
#[test]
fn insider_remove_proposal_carried_by_honest_commit() {
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let (p, s) = (&m.provider, &m.signer);
    let g = m.group.as_mut().unwrap();
    let bob_idx = g
        .members()
        .find(|x| x.credential.serialized_content() == b"bob")
        .unwrap()
        .index;
    let (prop, _) = g.propose_remove_member(p, s, bob_idx).unwrap();
    let sealed = m.seal(&prop.to_bytes().unwrap());
    assert_eq!(a.receive(&alice, &sealed).unwrap(), Incoming::Proposal);
    let commit = a.refresh_keys(&alice).unwrap();
    assert_eq!(a.members(), vec!["alice", "mallory"], "bob removed by alice's refresh");
    assert_eq!(b.receive(&bob, &sealed).unwrap(), Incoming::Proposal);
    assert_eq!(b.receive(&bob, &commit).unwrap(), Incoming::RemovedFromGroup);
}

/// A join request (external Add proposal) relayed by a member is stored, and
/// the next honest commit, here a plain key refresh by alice, adds the
/// requester. The others see "added" in a commit authored by alice; the
/// welcome for the new device is discarded by `refresh_keys` (F-007).
#[test]
fn external_join_proposal_folded_into_key_refresh() {
    use openmls::prelude::{GroupEpoch, GroupId, JoinProposal, KeyPackageIn, ProtocolVersion};
    use openmls::prelude::tls_codec::Deserialize;
    use openmls_traits::OpenMlsProvider;

    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let outsider = common::Insider::new("outsider");
    let kp = KeyPackageIn::tls_deserialize_exact(outsider.key_package())
        .unwrap()
        .validate(outsider.provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let req = JoinProposal::new::<<tree_core::DefaultProvider as OpenMlsProvider>::StorageProvider>(
        kp,
        GroupId::from_slice(&a.id()),
        GroupEpoch::from(a.epoch()),
        &outsider.signer,
    )
    .unwrap();
    let sealed = m.seal(&req.to_bytes().unwrap());
    assert_eq!(a.receive(&alice, &sealed).unwrap(), Incoming::Proposal);
    assert_eq!(b.receive(&bob, &sealed).unwrap(), Incoming::Proposal);
    let c = a.refresh_keys(&alice).unwrap();
    assert_eq!(
        b.receive(&bob, &c).unwrap(),
        Incoming::GroupChanged { added: vec!["outsider".into()], removed: vec![], epoch: 3 }
    );
    assert_eq!(a.members(), vec!["alice", "bob", "mallory", "outsider"]);
}

/// KNOWN ISSUE (F-007): a commit that arrives before a proposal it refers to
/// is refused, AND its decryption key is consumed, so it can never be
/// processed, even after the proposal arrives. An insider who sends a
/// proposal to only some members can cut the others off from the group
/// through the next honest commit.
#[test]
fn commit_before_its_proposal_is_lost() {
    use openmls::prelude::LeafNodeParameters;
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let (p, s) = (&m.provider, &m.signer);
    let (prop, _) = m
        .group
        .as_mut()
        .unwrap()
        .propose_self_update(p, s, LeafNodeParameters::default())
        .unwrap();
    let sealed = m.seal(&prop.to_bytes().unwrap());
    // Only alice gets the proposal.
    assert_eq!(a.receive(&alice, &sealed).unwrap(), Incoming::Proposal);
    let commit = a.refresh_keys(&alice).unwrap();
    let r = b.receive(&bob, &commit);
    assert!(matches!(r, Err(TreeError::Rejected(ref s)) if s.contains("MissingProposal")), "{r:?}");
    // The proposal arrives late; the commit is now permanently unreadable.
    assert_eq!(b.receive(&bob, &sealed).unwrap(), Incoming::Proposal);
    let r = b.receive(&bob, &commit);
    assert!(matches!(r, Err(TreeError::Rejected(ref s)) if s.contains("SecretReuseError")), "{r:?}");
    assert_eq!(b.epoch(), 2);
    assert_eq!(a.epoch(), 3);
}

/// Names are self-chosen credential contents, not authenticated identities:
/// two members can carry the same name and `remove(name)` takes the first.
#[test]
fn duplicate_names_are_possible() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let fake = Client::new("bob").unwrap();
    let add = a.add(&alice, &fake.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut f = fake.join(&add.welcome).unwrap();
    assert_eq!(a.members(), vec!["alice", "bob", "bob"]);

    // A message from the impostor is reported with the same `from`.
    let m = f.send(&fake, b"it's me, bob").unwrap();
    match a.receive(&alice, &m).unwrap() {
        Incoming::Message { from, .. } => assert_eq!(from, "bob"),
        other => panic!("{other:?}"),
    }
    // remove("bob") removes the first leaf: the real bob.
    let rm = a.remove(&alice, "bob").unwrap();
    assert_eq!(b.receive(&bob, &rm).unwrap(), Incoming::RemovedFromGroup);
    assert!(matches!(f.receive(&fake, &rm), Ok(Incoming::GroupChanged { .. })));
}
