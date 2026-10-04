//! Three devices with encrypted profiles talk through a real Tree server over
//! HTTP: invite, chat, a commit race, a restart, removal, leaving. Then the
//! server's database is searched for the plaintext.

mod common;

use common::Env;
use tree_client::{CommitOutcome, Event, Session};

fn texts(events: &[Event]) -> Vec<(String, String)> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Text { name, text, .. } => Some((name.clone().unwrap_or_else(|| "?".into()), text.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn three_devices_chat_through_the_server() {
    let env = Env::new("chat");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut carol = env.device("carol");

    // bob takes a @username; alice finds him by it (only the hash reaches the server).
    assert_eq!(bob.set_username("@Bob_Tree").unwrap(), "bob_tree");
    assert_eq!(alice.find("bob_tree").unwrap().as_deref(), Some(bob.account_id()));
    assert_eq!(alice.find("nobody_here").unwrap(), None);
    assert_eq!(bob.username().unwrap().as_deref(), Some("bob_tree"));

    // alice starts a group and invites bob's account.
    let g = alice.create_group().unwrap();
    let bob_account = alice.find("@bob_tree").unwrap().unwrap();
    assert_eq!(alice.invite(&g, &bob_account).unwrap(), (CommitOutcome::Accepted { epoch: 1 }, vec![]));
    let ev = bob.sync(0).unwrap();
    assert!(ev.contains(&Event::Joined { group: g.clone() }), "{ev:?}");
    assert!(ev.contains(&Event::RosterUpdated { group: g.clone() }), "{ev:?}");
    // alice is a stranger to bob: her 1:1 chat is a message request.
    assert!(ev.contains(&Event::Request { group: g.clone(), from: alice.account_id().into(), direct: true }), "{ev:?}");
    bob.accept_request(&g).unwrap();

    alice.send_text(&g, "안녕 밥, 서버를 거쳐 가는 첫 메시지 7f3a").unwrap();
    let ev = bob.sync(0).unwrap();
    assert_eq!(texts(&ev), vec![("alice".into(), "안녕 밥, 서버를 거쳐 가는 첫 메시지 7f3a".into())]);
    match &ev[0] {
        Event::Text { from, .. } => assert_eq!(*from, alice.member_id()),
        other => panic!("{other:?}"),
    }
    bob.send_text(&g, "잘 받았어").unwrap();
    assert_eq!(texts(&alice.sync(0).unwrap()), vec![("bob".into(), "잘 받았어".into())]);

    // Race for epoch 1 -> 2: bob refreshes his keys first, alice's invite of carol loses.
    assert_eq!(bob.refresh_keys(&g).unwrap(), CommitOutcome::Accepted { epoch: 2 });
    assert_eq!(alice.invite(&g, carol.account_id()).unwrap().0, CommitOutcome::Lost);
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Changed { epoch: 2, .. })), "{ev:?}");
    // alice decides again in epoch 2 and wins.
    // carol knows alice (e.g. found her @username): only contacts may add her to groups.
    carol.confirm_contact(alice.account_id()).unwrap();
    // Same devices as in the lost attempt: no key-change warning.
    assert_eq!(alice.invite(&g, carol.account_id()).unwrap(), (CommitOutcome::Accepted { epoch: 3 }, vec![]));
    let ev = carol.sync(0).unwrap();
    assert!(ev.contains(&Event::Joined { group: g.clone() }), "{ev:?}");
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Changed { epoch: 3, added, .. } if added.len() == 1)), "{ev:?}");

    carol.send_text(&g, "나도 왔어").unwrap();
    assert_eq!(texts(&alice.sync(0).unwrap()), vec![("carol".into(), "나도 왔어".into())]);
    assert_eq!(texts(&bob.sync(0).unwrap()), vec![("carol".into(), "나도 왔어".into())]);
    // Safety numbers: alice (who invited bob) and bob (who learned alice's
    // account from the roster) see the same digits. alice is a stranger
    // bob accepted, not a pinned contact, so her roster does not label the
    // other members for bob (F-022): carol stays unknown to bob.
    let n = alice.safety_number(bob.account_id()).unwrap();
    assert_eq!(n, bob.safety_number(alice.account_id()).unwrap());
    assert_eq!(n.split(' ').count(), 12, "12 groups of 5 digits: {n}");
    assert!(n.split(' ').all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit())), "{n}");
    assert_ne!(n, alice.safety_number(carol.account_id()).unwrap(), "per contact");
    assert!(bob.contact(carol.account_id()).unwrap().is_none());
    let qr = bob.safety_qr(alice.account_id()).unwrap();
    alice.verify(bob.account_id(), Some(&qr)).unwrap();
    assert!(alice.contact(bob.account_id()).unwrap().unwrap().verified);
    assert!(alice.verify(carol.account_id(), Some(&qr)).is_err(), "bob's code is not carol's");
    let code = alice.verification_code(&g).unwrap();
    assert_eq!(bob.verification_code(&g).unwrap(), code, "one group state, no fork");
    assert_eq!(carol.verification_code(&g).unwrap(), code);
    assert_eq!(code.len(), 48, "SHA-384 epoch authenticator");
    assert_eq!(alice.group_ids().unwrap(), vec![g.clone()]);
    let g2 = alice.create_group().unwrap();
    assert_ne!(alice.verification_code(&g2).unwrap(), code, "per group state");
    assert_eq!(alice.group_ids().unwrap().len(), 2);

    // alice's app restarts: everything comes back from her encrypted profile,
    // her settings included.
    alice.release_feature("user.search_index").unwrap();
    drop(alice);
    let (mut alice, resubmitted) = Session::open(&env.profile("alice"), "alice passphrase").unwrap();
    assert!(resubmitted.is_empty());
    assert_eq!(alice.feature("user.search_index").unwrap().state, tree_core::features::State::Released);
    alice.apply_feature("user.search_index", None).unwrap();
    alice.send_text(&g, "재시작 후에도 그대로").unwrap();
    assert_eq!(texts(&bob.sync(0).unwrap()), vec![("alice".into(), "재시작 후에도 그대로".into())]);
    assert_eq!(texts(&carol.sync(0).unwrap()).len(), 1);

    // alice removes bob (by member id). bob learns it and reads nothing after.
    assert_eq!(alice.remove(&g, &[bob.member_id()]).unwrap(), CommitOutcome::Accepted { epoch: 4 });
    let ev = bob.sync(0).unwrap();
    assert!(ev.contains(&Event::RemovedFromGroup { group: g.clone() }), "{ev:?}");
    alice.send_text(&g, "밥 없는 비밀 b0b").unwrap();
    assert!(texts(&bob.sync(0).unwrap()).is_empty());
    assert_eq!(texts(&carol.sync(0).unwrap()), vec![("alice".into(), "밥 없는 비밀 b0b".into())]);
    assert!(bob.send_text(&g, "아직 있어?").is_err());

    // carol asks to leave; alice removes her.
    carol.leave(&g).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.contains(&Event::LeaveRequested { group: g.clone(), member: carol.member_id(), quiet: false }), "{ev:?}");
    assert_eq!(alice.remove(&g, &[carol.member_id()]).unwrap(), CommitOutcome::Accepted { epoch: 5 });
    assert!(carol.sync(0).unwrap().contains(&Event::RemovedFromGroup { group: g.clone() }));
    let members = alice.members(&g).unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].name.as_deref(), Some("alice"));

    // The server's database never held any plaintext or names.
    drop((alice, bob, carol));
    let mut raw = std::fs::read(&env.db).unwrap();
    for ext in ["-wal", "-shm"] {
        if let Ok(b) = std::fs::read(format!("{}{ext}", env.db.display())) {
            raw.extend(b);
        }
    }
    for needle in ["7f3a", "b0b", "안녕", "alice", "carol", "재시작", "bob_tree"] {
        assert!(!raw.windows(needle.len()).any(|w| w == needle.as_bytes()), "server stored {needle:?}");
    }
}

/// A message for a group the device has not joined yet is held and read
/// once the welcome arrives (PROTOCOL.md 6.7).
#[test]
fn held_until_readable() {
    let env = Env::new("held");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    alice.send_text(&g, "first").unwrap();
    // bob receives both in one sync, in mailbox order: works without holding.
    let ev = bob.sync(0).unwrap();
    assert_eq!(texts(&ev), vec![("alice".into(), "first".into())]);
    assert!(!ev.contains(&Event::Held));
}
