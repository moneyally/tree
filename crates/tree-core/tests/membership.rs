//! Add / remove / receive membership handling and identity accessors.

mod common;

use common::{chat_with_insider, ids, two_person_chat, Now, TAG_LEN};
use openmls::prelude::{tls_codec::Deserialize, Ciphersuite, LeafNodeParameters, MlsMessageIn, ProcessedMessageContent};
use tree_core::{Client, Incoming, MemberId, TreeError, TREE_CIPHERSUITE};

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

/// Member id = SHA-256("tree/member-id/v1" || signature key) (PROTOCOL.md 5.2).
#[test]
fn member_id_derivation() {
    use sha2::{Digest, Sha256};
    let alice = Client::new("alice").unwrap();
    let mut h = Sha256::new();
    h.update(b"tree/member-id/v1");
    h.update(alice.signature_public_key());
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(alice.member_id(), MemberId(expected));
    assert_eq!(MemberId::of(&alice.signature_public_key()), alice.member_id());
    assert_eq!(alice.member_id().as_bytes(), &expected);
    let hex = alice.member_id().to_hex();
    assert_eq!(hex.len(), 64);
    assert_eq!(hex, expected.iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert_eq!(format!("{}", alice.member_id()), hex);
    assert_eq!(format!("{:?}", alice.member_id()), format!("MemberId({})", &hex[..16]));
    assert_ne!(alice.member_id(), Client::new("alice").unwrap().member_id(), "same name, other key");
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
    assert_eq!(g.members(), vec![alice.member_id()]);
    assert_eq!(g.id().len(), 16, "random 16-byte group id");
    assert!(!g.verification_code().is_empty());
    assert!(g.pending_commit().is_none());
    let g2 = alice.create_group().unwrap();
    assert_ne!(g.id(), g2.id());
}

/// Add reports the right members and epochs to every existing member, and
/// both sides agree on members and verification code afterwards.
#[test]
fn add_reported_to_existing_members() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    assert_eq!(a.epoch(), 1);
    assert_eq!(b.epoch(), 1);
    assert_eq!(a.members(), vec![alice.member_id(), bob.member_id()]);
    assert_eq!(b.members(), a.members());
    assert_eq!(a.verification_code(), b.verification_code());
    assert_eq!(a.id(), b.id());

    let carol = Client::new("carol").unwrap();
    let before = a.verification_code();
    let add = a.add_now(&alice, &carol.key_package().unwrap()).unwrap();
    assert_eq!(a.epoch(), 2);
    assert_ne!(a.verification_code(), before, "code changes with the epoch");
    assert_eq!(
        b.receive(&bob, &add.commit).unwrap(),
        Incoming::GroupChanged { added: vec![carol.member_id()], removed: vec![], epoch: 2, own_commit_discarded: false, settings_changed: false, by: alice.member_id() }
    );
    let c = carol.join(&add.welcome).unwrap();
    assert_eq!(c.epoch(), 2);
    assert_eq!(c.members(), vec![alice.member_id(), bob.member_id(), carol.member_id()]);
    assert_eq!(a.verification_code(), b.verification_code());
    assert_eq!(a.verification_code(), c.verification_code());
}

/// All devices of a person are added in one commit (one epoch).
#[test]
fn several_devices_added_in_one_commit() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let phone = Client::new("carol").unwrap();
    let laptop = Client::new("carol").unwrap();
    let p = a.add(&alice, &[phone.key_package().unwrap(), laptop.key_package().unwrap()]).unwrap();
    assert_eq!(p.added, vec![phone.member_id(), laptop.member_id()]);
    a.confirm_commit(&alice).unwrap();
    assert_eq!(a.epoch(), 2);
    match b.receive(&bob, &p.commit).unwrap() {
        Incoming::GroupChanged { added, epoch: 2, .. } => {
            assert_eq!(added, vec![phone.member_id(), laptop.member_id()])
        }
        other => panic!("{other:?}"),
    }
    let w = p.welcome.unwrap();
    assert_eq!(phone.join(&w).unwrap().verification_code(), a.verification_code());
    assert_eq!(laptop.join(&w).unwrap().verification_code(), a.verification_code());
    assert!(matches!(a.add(&alice, &[] as &[Vec<u8>]), Err(TreeError::Group(_))));
}

/// Remove reports the removed member to the others and `RemovedFromGroup`
/// to the removed device, which can then neither send nor receive.
#[test]
fn remove_reported_and_removed_device_locked_out() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let carol = Client::new("carol").unwrap();
    let add = a.add_now(&alice, &carol.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut c = carol.join(&add.welcome).unwrap();

    let rm = a.remove_now(&alice, &[bob.member_id()]).unwrap();
    assert_eq!(a.members(), vec![alice.member_id(), carol.member_id()]);
    assert_eq!(
        c.receive(&carol, &rm).unwrap(),
        Incoming::GroupChanged { added: vec![], removed: vec![bob.member_id()], epoch: 3, own_commit_discarded: false, settings_changed: false, by: alice.member_id() }
    );
    assert_eq!(b.receive(&bob, &rm).unwrap(), Incoming::RemovedFromGroup);
    assert!(!b.is_member());
    assert!(a.is_member() && c.is_member());
    assert!(matches!(b.send(&bob, b"still here?"), Err(TreeError::NotAMember)));
    assert!(matches!(b.refresh_keys(&bob), Err(TreeError::NotAMember)));
    let m = a.send(&alice, b"bye bob").unwrap();
    assert!(matches!(b.receive(&bob, &m), Err(TreeError::NotAMember)));
    assert!(matches!(c.receive(&carol, &m), Ok(Incoming::Message { .. })));
}

/// F-008: several members (all devices of a person) removed in one commit;
/// listing an id twice is harmless.
#[test]
fn several_members_removed_in_one_commit() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let phone = Client::new("carol").unwrap();
    let laptop = Client::new("carol").unwrap();
    let p = a.add(&alice, &[phone.key_package().unwrap(), laptop.key_package().unwrap()]).unwrap();
    a.confirm_commit(&alice).unwrap();
    b.receive(&bob, &p.commit).unwrap();
    let ids = [phone.member_id(), laptop.member_id(), phone.member_id()];
    let rm = a.remove(&alice, &ids).unwrap();
    let mut removed = rm.removed.clone();
    removed.sort();
    let mut expected = vec![phone.member_id(), laptop.member_id()];
    expected.sort();
    assert_eq!(removed, expected);
    a.confirm_commit(&alice).unwrap();
    assert_eq!(a.epoch(), 3, "one commit");
    match b.receive(&bob, &rm.commit).unwrap() {
        Incoming::GroupChanged { removed, .. } => {
            assert_eq!(removed.len(), 2);
            assert!(removed.contains(&phone.member_id()) && removed.contains(&laptop.member_id()));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(b.members(), vec![alice.member_id(), bob.member_id()]);
    assert!(matches!(a.remove(&alice, &[]), Err(TreeError::Group(_))));
}

#[test]
fn remove_unknown_member() {
    let (alice, _bob, mut a, _b) = two_person_chat();
    let e = a.epoch();
    let nobody = MemberId([7; 32]);
    match a.remove(&alice, &[nobody]) {
        Err(TreeError::UnknownMember(n)) => assert_eq!(n, nobody.to_hex()),
        Err(e) => panic!("wrong error {e:?}"),
        Ok(_) => panic!("removed a non-member"),
    }
    assert_eq!(a.epoch(), e, "failed remove must not change the epoch");
    assert!(a.pending_commit().is_none());
}

/// Removing yourself through `remove` is refused and leaves the group usable.
#[test]
fn remove_self_refused() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    assert!(matches!(a.remove(&alice, &[bob.member_id(), alice.member_id()]), Err(TreeError::Group(_))));
    assert!(a.is_member());
    assert!(a.pending_commit().is_none());
    let m = a.send(&alice, b"still fine").unwrap();
    assert!(matches!(b.receive(&bob, &m), Ok(Incoming::Message { .. })));
}

/// A key refresh is seen by the others as a change with no membership delta.
#[test]
fn refresh_keys_processed() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let before = b.verification_code();
    let c = b.refresh_now(&bob).unwrap();
    assert_eq!(
        a.receive(&alice, &c).unwrap(),
        Incoming::GroupChanged { added: vec![], removed: vec![], epoch: 2, own_commit_discarded: false, settings_changed: false, by: bob.member_id() }
    );
    assert_ne!(b.verification_code(), before);
    assert_eq!(a.verification_code(), b.verification_code());
    let m = a.send(&alice, b"after refresh").unwrap();
    assert_eq!(
        b.receive(&bob, &m).unwrap(),
        Incoming::Message { from: alice.member_id(), body: b"after refresh".to_vec() }
    );
}

/// A one-time key package can be used for one join only.
#[test]
fn welcome_cannot_be_joined_twice() {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut a = alice.create_group().unwrap();
    let w = a.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
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
    let w = a.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
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
    let add = a.add_now(&alice, &carol.key_package().unwrap()).unwrap();
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
    a.add_now(&alice, &kp).unwrap();
    let e = a.epoch();
    assert!(a.add(&alice, &[&kp]).is_err(), "same key package added twice");
    assert!(a.pending_commit().is_none(), "failed add leaves nothing pending");
    assert_eq!(a.epoch(), e);
    assert_eq!(a.members(), vec![alice.member_id(), bob.member_id()]);
    a.refresh_now(&alice).unwrap();
}

/// A tampered commit is refused and the genuine one still applies.
#[test]
fn tampered_commit_rejected_genuine_still_applies() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let carol = Client::new("carol").unwrap();
    let add = a.add_now(&alice, &carol.key_package().unwrap()).unwrap();
    for frac in [10, 50, 90, 99] {
        let mut t = add.commit.clone();
        let i = t.len() * frac / 100;
        t[i] ^= 0x04;
        assert!(b.receive(&bob, &t).is_err());
        assert_eq!(b.epoch(), 1);
    }
    assert!(matches!(b.receive(&bob, &add.commit), Ok(Incoming::GroupChanged { epoch: 2, .. })));
}

/// The add commit carries no update path (PROTOCOL.md 6.4; BENCHMARKS.md
/// recommendation 4), the key refresh does.
#[test]
fn add_commit_has_no_update_path_refresh_has_one() {
    let (alice, _bob, mut a, _b, mut m) = chat_with_insider("mallory");
    let has_path = |m: &mut common::Insider, sealed: &[u8]| {
        let msg = MlsMessageIn::tls_deserialize_exact(&sealed[1 + TAG_LEN..]).unwrap();
        let p = msg.try_into_protocol_message().unwrap();
        let provider = &m.provider;
        let g = m.group.as_mut().unwrap();
        match g.process_message(provider, p).unwrap().into_content() {
            ProcessedMessageContent::StagedCommitMessage(c) => {
                let path = c.update_path_leaf_node().is_some();
                g.merge_staged_commit(provider, *c).unwrap();
                path
            }
            _ => panic!("expected a commit"),
        }
    };
    let carol = Client::new("carol").unwrap();
    let add = a.add_now(&alice, &carol.key_package().unwrap()).unwrap();
    assert!(!has_path(&mut m, &add.commit));
    let refresh = a.refresh_now(&alice).unwrap();
    assert!(has_path(&mut m, &refresh));
    let rm = a.remove_now(&alice, &[carol.member_id()]).unwrap();
    assert!(has_path(&mut m, &rm));
}

// ----- F-007: proposals ------------------------------------------------------

/// F-007 (fixed): a proposal from a member is rejected before MLS and never
/// stored, so the next honest commit does not carry it.
#[test]
fn insider_proposal_rejected_not_stored() {
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let (p, s) = (&m.provider, &m.signer);
    let (prop, _) = m.group.as_mut().unwrap().propose_self_update(p, s, LeafNodeParameters::default()).unwrap();
    let sealed = m.seal(&prop.to_bytes().unwrap());
    for r in [a.receive(&alice, &sealed), b.receive(&bob, &sealed)] {
        assert!(matches!(r, Err(TreeError::Rejected(ref s)) if s.contains("proposals")), "{r:?}");
    }
    let c = a.refresh_now(&alice).unwrap();
    assert_eq!(
        b.receive(&bob, &c).unwrap(),
        Incoming::GroupChanged { added: vec![], removed: vec![], epoch: 3, own_commit_discarded: false, settings_changed: false, by: alice.member_id() }
    );
    assert_eq!(a.verification_code(), b.verification_code());
}

/// F-007 (fixed): an insider's remove proposal no longer rides on an honest
/// commit.
#[test]
fn insider_remove_proposal_not_carried_by_honest_commit() {
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let (p, s) = (&m.provider, &m.signer);
    let g = m.group.as_mut().unwrap();
    let bob_idx = g.members().find(|x| x.signature_key == bob.signature_public_key()).unwrap().index;
    let (prop, _) = g.propose_remove_member(p, s, bob_idx).unwrap();
    let sealed = m.seal(&prop.to_bytes().unwrap());
    assert!(a.receive(&alice, &sealed).is_err());
    let commit = a.refresh_now(&alice).unwrap();
    assert_eq!(a.members(), vec![alice.member_id(), bob.member_id(), m.member_id()], "bob still there");
    assert!(b.receive(&bob, &sealed).is_err());
    assert!(matches!(b.receive(&bob, &commit), Ok(Incoming::GroupChanged { .. })));
    assert!(b.is_member());
}

/// F-007 (fixed): a join request (external Add proposal) relayed by a member
/// is rejected; a key refresh adds nobody.
#[test]
fn external_join_proposal_rejected() {
    use openmls::prelude::{GroupEpoch, GroupId, JoinProposal, KeyPackageIn, ProtocolVersion};
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
    assert!(matches!(a.receive(&alice, &sealed), Err(TreeError::Rejected(_))));
    assert!(matches!(b.receive(&bob, &sealed), Err(TreeError::Rejected(_))));
    let c = a.refresh_now(&alice).unwrap();
    assert!(matches!(b.receive(&bob, &c).unwrap(), Incoming::GroupChanged { ref added, .. } if added.is_empty()));
    assert_eq!(a.members(), vec![alice.member_id(), bob.member_id(), m.member_id()]);
}

/// F-007: a commit that refers to a proposal by reference (which Tree never
/// stores) fails cleanly: rejected, nothing merged, the group keeps working.
#[test]
fn commit_with_proposal_by_reference_fails_cleanly() {
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let (p, s) = (&m.provider, &m.signer);
    let g = m.group.as_mut().unwrap();
    let alice_idx = g.members().find(|x| x.signature_key == alice.signature_public_key()).unwrap().index;
    // mallory's own remove proposal, kept in her store, committed by reference
    g.propose_remove_member(p, s, alice_idx).unwrap();
    let (commit, _, _) = g.commit_to_pending_proposals(p, s).unwrap();
    let sealed = m.seal(&commit.to_bytes().unwrap());
    let r = b.receive(&bob, &sealed);
    assert!(matches!(r, Err(TreeError::Rejected(_))), "{r:?}");
    assert_eq!(b.epoch(), 2);
    assert_eq!(b.members(), vec![alice.member_id(), bob.member_id(), m.member_id()]);
    let msg = a.send(&alice, b"still working").unwrap();
    assert!(matches!(b.receive(&bob, &msg), Ok(Incoming::Message { .. })));
}

/// PROTOCOL.md 6.4: a commit with a proposal type Tree does not allow
/// (here: group context extensions) is rejected before merging.
#[test]
fn commit_with_disallowed_proposal_rejected() {
    use openmls::prelude::Extensions;
    let (_alice, bob, _a, mut b, mut m) = chat_with_insider("mallory");
    let (p, s) = (&m.provider, &m.signer);
    let g = m.group.as_mut().unwrap();
    let (commit, _, _) = g.update_group_context_extensions(p, Extensions::empty(), s).unwrap();
    let sealed = m.seal(&commit.to_bytes().unwrap());
    let r = b.receive(&bob, &sealed);
    assert!(matches!(r, Err(TreeError::Rejected(ref s)) if s.contains("settings")), "{r:?}");
    assert_eq!(b.epoch(), 2);
}

/// An add-only commit from another member without an update path is
/// accepted (Tree's own adds look like this).
#[test]
fn add_without_path_from_others_accepted() {
    let (_alice, bob, _a, mut b, mut m) = chat_with_insider("mallory");
    let carol = Client::new("carol").unwrap();
    let kp = openmls::prelude::KeyPackageIn::tls_deserialize_exact(carol.key_package().unwrap())
        .unwrap()
        .validate(&openmls_rust_crypto::RustCrypto::default(), openmls::prelude::ProtocolVersion::Mls10)
        .unwrap();
    let (p, s) = (&m.provider, &m.signer);
    let g = m.group.as_mut().unwrap();
    let (commit, _, _) = g.add_members_without_update(p, s, &[kp]).unwrap();
    let sealed = m.seal(&commit.to_bytes().unwrap());
    assert!(matches!(b.receive(&bob, &sealed), Ok(Incoming::GroupChanged { epoch: 3, .. })));
}

// ----- F-008: names are not identities ---------------------------------------

/// F-008 (fixed): two devices that use the same display name are still
/// different members; removal by id removes exactly the one meant.
#[test]
fn same_name_different_members() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let fake = Client::new("bob").unwrap();
    let add = a.add_now(&alice, &fake.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut f = fake.join(&add.welcome).unwrap();
    assert_eq!(a.members(), ids(&[&alice, &bob, &fake]));
    assert_ne!(fake.member_id(), bob.member_id());

    // A message from the impostor carries its own id.
    let m = f.send(&fake, b"it's me, bob").unwrap();
    match a.receive(&alice, &m).unwrap() {
        Incoming::Message { from, .. } => assert_eq!(from, fake.member_id()),
        other => panic!("{other:?}"),
    }
    // Removing the impostor by id leaves the real bob.
    let rm = a.remove_now(&alice, &[fake.member_id()]).unwrap();
    assert_eq!(f.receive(&fake, &rm).unwrap(), Incoming::RemovedFromGroup);
    assert!(matches!(b.receive(&bob, &rm), Ok(Incoming::GroupChanged { .. })));
    assert_eq!(a.members(), ids(&[&alice, &bob]));
}

// ----- F-009: no names in MLS -------------------------------------------------

/// F-009: key packages (public, stored on the server) carry no display name,
/// only the signature key in the credential.
#[test]
fn key_package_carries_no_name() {
    let c = Client::new("very-unusual-name-9c1e").unwrap();
    let kp = c.key_package().unwrap();
    let needle = b"very-unusual-name-9c1e";
    assert!(!kp.windows(needle.len()).any(|w| w == needle));
    assert_eq!(MemberId::of_key_package(&kp).unwrap(), c.member_id());
    assert!(MemberId::of_key_package(&kp[..10]).is_err());
}

/// F-009: a key package whose credential is not exactly the signature key
/// (e.g. a name) is refused by the adder, and an add commit carrying one is
/// refused by receivers.
#[test]
fn name_credentials_refused() {
    use openmls::prelude::{BasicCredential, CredentialWithKey, KeyPackage};
    use openmls::prelude::tls_codec::Serialize;
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    // an outsider whose credential is a name
    let named = common::Insider::new("x");
    let cred = CredentialWithKey {
        credential: BasicCredential::new(b"carol".to_vec()).into(),
        signature_key: named.signer.to_public_vec().into(),
    };
    let kp = KeyPackage::builder()
        .leaf_node_capabilities(
            openmls::prelude::Capabilities::builder()
                .extensions(vec![openmls::prelude::ExtensionType::Unknown(tree_core::group_settings::EXTENSION_TYPE)])
                .build(),
        )
        .build(TREE_CIPHERSUITE, &named.provider, &named.signer, cred)
        .unwrap();
    let bytes = kp.key_package().tls_serialize_detached().unwrap();
    assert!(matches!(a.add(&alice, &[&bytes]), Err(TreeError::InvalidKeyPackage(_))));
    // mallory (raw MLS) adds it anyway; bob refuses the commit
    let (p, s) = (&m.provider, &m.signer);
    let (commit, _, _) = m.group.as_mut().unwrap().add_members_without_update(p, s, &[kp.key_package().clone()]).unwrap();
    let sealed = m.seal(&commit.to_bytes().unwrap());
    let r = b.receive(&bob, &sealed);
    assert!(matches!(r, Err(TreeError::Rejected(ref s)) if s.contains("credential")), "{r:?}");
    assert_eq!(b.members(), vec![alice.member_id(), bob.member_id(), m.member_id()]);
}

// ----- admins and group settings (PROTOCOL.md 6.11) ---------------------------

use tree_core::group_settings::{ChatSetting, GroupSettings};

/// The creator is the only admin; only admins remove members or change
/// settings; settings changes reach every member.
#[test]
fn admins_and_settings() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let carol = Client::new("carol").unwrap();
    let add = a.add_now(&alice, &carol.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut c = carol.join(&add.welcome).unwrap();
    assert_eq!(a.settings().admins, vec![alice.member_id()]);
    assert_eq!(c.settings(), a.settings(), "joiners get the settings with the welcome");
    assert!(a.is_admin(&alice.member_id()) && !b.is_admin(&bob.member_id()));

    // bob is not an admin: he may not remove or change settings.
    assert!(matches!(b.remove(&bob, &[carol.member_id()]), Err(TreeError::NotAdmin)));
    assert!(matches!(b.change_settings(&bob, &GroupSettings::default()), Err(TreeError::NotAdmin)));
    // bob may still add (any member may add in v1) and refresh.
    b.refresh_now(&bob).map(|r| {
        a.receive(&alice, &r).unwrap();
        c.receive(&carol, &r).unwrap();
    }).unwrap();

    // alice names the group, switches media off and makes bob admin.
    let mut s = a.settings();
    s.name = Some("우리 가족".into());
    s.admins.push(bob.member_id());
    s.features.insert("chat.media".into(), ChatSetting { applied: false, option: None });
    let p = a.change_settings(&alice, &s).unwrap();
    a.confirm_commit(&alice).unwrap();
    for (g, me) in [(&mut b, &bob), (&mut c, &carol)] {
        assert_eq!(
            g.receive(me, &p.commit).unwrap(),
            Incoming::GroupChanged { added: vec![], removed: vec![], epoch: 4, own_commit_discarded: false, settings_changed: true, by: alice.member_id() }
        );
        assert_eq!(g.settings(), s);
    }
    // Invalid settings are refused before anything is sent.
    let mut no_admin = s.clone();
    no_admin.admins.clear();
    assert!(a.change_settings(&alice, &no_admin).is_err());
    assert!(a.pending_commit().is_none());

    // Now bob may remove carol.
    let rm = b.remove_now(&bob, &[carol.member_id()]).unwrap();
    a.receive(&alice, &rm).unwrap();
    assert_eq!(c.receive(&carol, &rm).unwrap(), Incoming::RemovedFromGroup);
    // An admin who is removed drops out of the admin list.
    let rm = a.remove_now(&alice, &[bob.member_id()]).unwrap();
    assert_eq!(b.receive(&bob, &rm).unwrap(), Incoming::RemovedFromGroup);
    assert_eq!(a.settings().admins, vec![alice.member_id()]);
}

/// A non-admin insider's settings change or removal is rejected by every
/// device, even though MLS itself would accept it.
#[test]
fn non_admin_commits_rejected() {
    let (alice, bob, _a, mut b, mut m) = chat_with_insider("mallory");
    let (p, s) = (&m.provider, &m.signer);
    let g = m.group.as_mut().unwrap();
    // mallory makes herself the only admin
    let evil = GroupSettings { admins: vec![MemberId::of(&s.to_public_vec())], ..Default::default() };
    let ext = openmls::prelude::Extensions::from_vec(vec![
        openmls::prelude::Extension::RequiredCapabilities(openmls::prelude::RequiredCapabilitiesExtension::new(
            &[openmls::prelude::ExtensionType::Unknown(tree_core::group_settings::EXTENSION_TYPE)],
            &[],
            &[],
        )),
        openmls::prelude::Extension::Unknown(
            tree_core::group_settings::EXTENSION_TYPE,
            openmls::prelude::UnknownExtension(evil.encode().unwrap()),
        ),
    ])
    .unwrap();
    let (commit, _, _) = g.update_group_context_extensions(p, ext, s).unwrap();
    g.clear_pending_commit(openmls_traits::OpenMlsProvider::storage(p)).unwrap();
    let sealed = m.seal(&commit.to_bytes().unwrap());
    let r = b.receive(&bob, &sealed);
    assert!(matches!(r, Err(TreeError::Rejected(ref e)) if e.contains("only an admin")), "{r:?}");

    // mallory removes alice
    let (p, s) = (&m.provider, &m.signer);
    let g = m.group.as_mut().unwrap();
    let alice_idx = g.members().find(|x| x.signature_key == alice.signature_public_key()).unwrap().index;
    let (commit, _, _) = g.remove_members(p, s, &[alice_idx]).unwrap();
    let sealed = m.seal(&commit.to_bytes().unwrap());
    let r = b.receive(&bob, &sealed);
    assert!(matches!(r, Err(TreeError::Rejected(ref e)) if e.contains("only an admin")), "{r:?}");
    assert_eq!(b.epoch(), 2);
}

/// An admin's commit that would leave the group without an admin who is a
/// member is rejected by receivers.
#[test]
fn settings_without_admin_rejected() {
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    // alice makes mallory admin
    let mut s = a.settings();
    s.admins.push(m.member_id());
    let p = a.change_settings(&alice, &s).unwrap();
    a.confirm_commit(&alice).unwrap();
    b.receive(&bob, &p.commit).unwrap();
    m.receive_commit(&p.commit);
    // mallory (admin now) sends settings naming nobody who is a member
    let (pr, sg) = (&m.provider, &m.signer);
    let bad = GroupSettings { admins: vec![MemberId([9; 32])], ..Default::default() };
    let ext = openmls::prelude::Extensions::from_vec(vec![
        openmls::prelude::Extension::RequiredCapabilities(openmls::prelude::RequiredCapabilitiesExtension::new(
            &[openmls::prelude::ExtensionType::Unknown(tree_core::group_settings::EXTENSION_TYPE)],
            &[],
            &[],
        )),
        openmls::prelude::Extension::Unknown(
            tree_core::group_settings::EXTENSION_TYPE,
            openmls::prelude::UnknownExtension(bad.encode().unwrap()),
        ),
    ])
    .unwrap();
    let (commit, _, _) = m.group.as_mut().unwrap().update_group_context_extensions(pr, ext, sg).unwrap();
    let sealed = m.seal(&commit.to_bytes().unwrap());
    let r = b.receive(&bob, &sealed);
    assert!(matches!(r, Err(TreeError::Rejected(ref e)) if e.contains("admin")), "{r:?}");
}

/// A modified admin client cannot change a permanently locked chat key
/// (`chat.e2e` released, `chat.private_to_public` applied) or write an
/// option outside the feature's format: every device rejects the commit,
/// and an honest client refuses to make one.
#[test]
fn locked_keys_and_bad_options_in_settings_rejected() {
    use tree_core::group_settings::ChatSetting;
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let mut s = a.settings();
    s.admins.push(m.member_id());
    let p = a.change_settings(&alice, &s).unwrap();
    a.confirm_commit(&alice).unwrap();
    b.receive(&bob, &p.commit).unwrap();
    m.receive_commit(&p.commit);
    let crafted = |key: &str, applied: bool, option: Option<&str>| {
        let mut evil = s.clone();
        evil.features.insert(key.into(), ChatSetting { applied, option: option.map(str::to_string) });
        evil
    };
    let cases = [
        (crafted("chat.e2e", false, None), "permanently locked"),
        (crafted("chat.private_to_public", true, None), "permanently locked"),
    ];
    for (evil, why) in cases {
        assert!(a.change_settings(&alice, &evil).is_err(), "an honest admin client refuses: {why}");
        let (pr, sg) = (&m.provider, &m.signer);
        let ext = openmls::prelude::Extensions::from_vec(vec![
            openmls::prelude::Extension::RequiredCapabilities(openmls::prelude::RequiredCapabilitiesExtension::new(
                &[openmls::prelude::ExtensionType::Unknown(tree_core::group_settings::EXTENSION_TYPE)],
                &[],
                &[],
            )),
            openmls::prelude::Extension::Unknown(
                tree_core::group_settings::EXTENSION_TYPE,
                openmls::prelude::UnknownExtension(evil.encode().unwrap()),
            ),
        ])
        .unwrap();
        let g = m.group.as_mut().unwrap();
        let (commit, _, _) = g.update_group_context_extensions(pr, ext, sg).unwrap();
        g.clear_pending_commit(openmls_traits::OpenMlsProvider::storage(pr)).unwrap();
        let sealed = m.seal(&commit.to_bytes().unwrap());
        let r = b.receive(&bob, &sealed);
        assert!(matches!(r, Err(TreeError::Rejected(ref e)) if e.contains(why)), "{why}: {r:?}");
        assert!(!b.settings().features.contains_key("chat.e2e"));
    }
    // An option this version does not know is not refused (a newer client
    // may write it; refusing would split the group) but reads as the
    // default; an honest client never writes it.
    for (key, opt, want) in [("chat.disappearing", "forever", Some("1d")), ("chat.media", "1d", None)] {
        let evil = crafted(key, true, Some(opt));
        assert!(a.change_settings(&alice, &evil).is_err(), "an honest admin client refuses {key}={opt}");
        let (pr, sg) = (&m.provider, &m.signer);
        let ext = openmls::prelude::Extensions::from_vec(vec![
            openmls::prelude::Extension::RequiredCapabilities(openmls::prelude::RequiredCapabilitiesExtension::new(
                &[openmls::prelude::ExtensionType::Unknown(tree_core::group_settings::EXTENSION_TYPE)],
                &[],
                &[],
            )),
            openmls::prelude::Extension::Unknown(
                tree_core::group_settings::EXTENSION_TYPE,
                openmls::prelude::UnknownExtension(evil.encode().unwrap()),
            ),
        ])
        .unwrap();
        let g = m.group.as_mut().unwrap();
        let (commit, _, _) = g.update_group_context_extensions(pr, ext, sg).unwrap();
        let sealed = m.seal(&commit.to_bytes().unwrap());
        let (pr, g) = (&m.provider, m.group.as_mut().unwrap());
        g.merge_pending_commit(pr).unwrap();
        b.receive(&bob, &sealed).unwrap();
        a.receive(&alice, &sealed).unwrap();
        assert_eq!(b.settings().features[key].option.as_deref(), want, "{key}={opt} reads as the default");
        assert_eq!(a.settings().features[key].option.as_deref(), want);
    }
    // A valid option from the same admin is accepted.
    let ok = crafted("chat.disappearing", true, Some("1d"));
    let p = a.change_settings(&alice, &ok).unwrap();
    a.confirm_commit(&alice).unwrap();
    b.receive(&bob, &p.commit).unwrap();
    assert_eq!(b.settings().features["chat.disappearing"].option.as_deref(), Some("1d"));
}


/// An admin's group-context commit may hold exactly Tree's settings and the
/// required-capabilities extension naming only them (PROTOCOL.md 6.11).
/// Anything else is rejected by receivers.
#[test]
fn group_context_holds_only_tree_settings() {
    use openmls::prelude::{CredentialType, Extension, ExtensionType, Extensions, ProposalType, RequiredCapabilitiesExtension, UnknownExtension};
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let mut s = a.settings();
    s.admins.push(m.member_id());
    let p = a.change_settings(&alice, &s).unwrap();
    a.confirm_commit(&alice).unwrap();
    b.receive(&bob, &p.commit).unwrap();
    m.receive_commit(&p.commit);
    let et = ExtensionType::Unknown(tree_core::group_settings::EXTENSION_TYPE);
    let settings = || Extension::Unknown(tree_core::group_settings::EXTENSION_TYPE, UnknownExtension(s.encode().unwrap()));
    let required = |p: &[ProposalType], c: &[CredentialType]| Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&[et], p, c));
    let cases: Vec<(&str, Vec<Extension>)> = vec![
        ("settings without required capabilities", vec![settings()]),
        ("required capabilities without settings", vec![required(&[], &[])]),
        ("a required proposal type", vec![required(&[ProposalType::Add], &[]), settings()]),
        ("a required credential type", vec![required(&[], &[CredentialType::Basic]), settings()]),
        ("an empty context", vec![]),
    ];
    let epoch = b.epoch();
    let mut reached_tree = Vec::new();
    for (what, list) in cases {
        let (pr, sg) = (&m.provider, &m.signer);
        let g = m.group.as_mut().unwrap();
        let ext = Extensions::from_vec(list).unwrap();
        // Some shapes MLS itself refuses to build; they cannot reach Tree.
        let Ok((commit, _, _)) = g.update_group_context_extensions(pr, ext, sg) else { continue };
        reached_tree.push(what);
        g.clear_pending_commit(openmls::prelude::OpenMlsProvider::storage(pr)).unwrap();
        let sealed = m.seal(&commit.to_bytes().unwrap());
        let r = b.receive(&bob, &sealed);
        assert!(matches!(r, Err(TreeError::Rejected(ref e)) if e.contains("only Tree's settings")), "{what}: {r:?}");
        assert_eq!(b.epoch(), epoch, "{what}: nothing applied");
    }
    assert!(
        ["required capabilities without settings", "a required proposal type", "a required credential type"]
            .iter()
            .all(|w| reached_tree.contains(w)),
        "{reached_tree:?}"
    );
    // The well-formed change is accepted (the checks are not over-strict).
    let (pr, sg) = (&m.provider, &m.signer);
    let g = m.group.as_mut().unwrap();
    let ext = Extensions::from_vec(vec![required(&[], &[]), settings()]).unwrap();
    let (commit, _, _) = g.update_group_context_extensions(pr, ext, sg).unwrap();
    let sealed = m.seal(&commit.to_bytes().unwrap());
    assert!(b.receive(&bob, &sealed).is_ok());
    assert_eq!(b.epoch(), epoch + 1);
}

#[test]
fn member_id_hex_parsing() {
    let id = MemberId([0xab; 32]);
    assert_eq!(MemberId::from_hex(&id.to_hex()), Some(id));
    assert_eq!(MemberId::from_hex(&id.to_hex().to_uppercase()), Some(id));
    assert_eq!(MemberId::from_hex(&"a".repeat(63)), None);
    assert_eq!(MemberId::from_hex(&"a".repeat(65)), None);
    assert_eq!(MemberId::from_hex(&"g".repeat(64)), None);
    // 64 bytes but not ASCII: refused, never sliced inside a character.
    assert_eq!(MemberId::from_hex(&"é".repeat(32)), None);
}

// ----- Wave 3: adds by permission, the next admin (PROTOCOL.md 6.11.1) -------

/// `chat.member_adds` released: an honest non-admin's client refuses to
/// add, and a modified one (raw MLS) gets its add commit rejected by every
/// member; a role with `add` makes it allowed again, and applied, anyone
/// adds.
#[test]
fn member_adds_follow_settings_and_roles() {
    use openmls_traits::OpenMlsProvider;
    use tree_core::group_settings::{perm, Role};
    let (alice, bob, mut a, mut b, mut m) = chat_with_insider("mallory");
    let mut s = a.settings();
    s.features.insert("chat.member_adds".into(), ChatSetting { applied: false, option: None });
    let p = a.change_settings(&alice, &s).unwrap();
    a.confirm_commit(&alice).unwrap();
    b.receive(&bob, &p.commit).unwrap();
    m.receive_commit(&p.commit);
    let carol = Client::new("carol").unwrap();
    assert!(matches!(b.add(&bob, &[carol.key_package().unwrap()]), Err(TreeError::NotAdmin)));
    // mallory adds anyway: alice and bob refuse it.
    let kp = common::Insider::new("x").key_package();
    let kp = openmls::prelude::KeyPackageIn::tls_deserialize_exact(&kp[..])
        .unwrap()
        .validate(m.provider.crypto(), openmls::prelude::ProtocolVersion::Mls10)
        .unwrap();
    let (pr, sg) = (&m.provider, &m.signer);
    let (commit, _, _) = m.group.as_mut().unwrap().add_members_without_update(pr, sg, &[kp]).unwrap();
    let sealed = m.seal(&commit.to_bytes().unwrap());
    for r in [a.receive(&alice, &sealed), b.receive(&bob, &sealed)] {
        assert!(matches!(r, Err(TreeError::Rejected(ref e)) if e.contains("add permission")), "{r:?}");
    }
    m.group.as_mut().unwrap().clear_pending_commit(m.provider.storage()).unwrap();
    // A role with `add` lets bob add.
    let mut s = a.settings();
    s.roles.insert("door".into(), Role { name: "door".into(), color: "#123456".into(), perms: [perm::ADD.to_string()].into() });
    s.member_roles.insert(bob.member_id(), ["door".to_string()].into());
    let p = a.change_settings(&alice, &s).unwrap();
    a.confirm_commit(&alice).unwrap();
    b.receive(&bob, &p.commit).unwrap();
    assert!(b.settings().may_add(&bob.member_id()));
    let add = b.add_now(&bob, &carol.key_package().unwrap()).unwrap();
    assert!(matches!(a.receive(&alice, &add.commit), Ok(Incoming::GroupChanged { by, .. }) if by == bob.member_id()));
}

/// The next admin is the member in the lowest leaf who is not leaving and
/// not restricted; every member computes the same one.
#[test]
fn successor_is_the_same_everywhere() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let carol = Client::new("carol").unwrap();
    let add = a.add_now(&alice, &carol.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let c = carol.join(&add.welcome).unwrap();
    for g in [&a, &b, &c] {
        assert_eq!(g.successor(&[alice.member_id()], 0), Some(bob.member_id()));
        assert_eq!(g.successor(&[alice.member_id(), bob.member_id()], 0), Some(carol.member_id()));
    }
    let mut s = a.settings();
    s.restricted.insert(bob.member_id(), i64::MAX);
    let p = a.change_settings(&alice, &s).unwrap();
    a.confirm_commit(&alice).unwrap();
    b.receive(&bob, &p.commit).unwrap();
    assert_eq!(a.successor(&[alice.member_id()], 0), Some(carol.member_id()), "restricted members are skipped");
    assert_eq!(b.successor(&[alice.member_id()], 0), Some(carol.member_id()));
}
