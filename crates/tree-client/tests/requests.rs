//! Message requests, blocking and who may add this device (through a real server).

mod common;

use common::Env;
use tree_client::{Event, GroupStatus};

fn texts(ev: &[Event]) -> Vec<(String, bool)> {
    ev.iter()
        .filter_map(|e| match e {
            Event::Text { text, request, .. } => Some((text.clone(), *request)),
            _ => None,
        })
        .collect()
}

#[test]
fn requests_blocking_and_group_add() {
    let env = Env::new("requests");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut mallory = env.device("mallory");

    // A stranger's 1:1 chat is a request; its messages are marked as such.
    let g = mallory.create_group().unwrap();
    mallory.invite(&g, bob.account_id()).unwrap();
    mallory.send_text(&g, "hi, want to buy something?").unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.contains(&Event::Request { group: g.clone(), from: mallory.account_id().into(), direct: true }), "{ev:?}");
    assert_eq!(texts(&ev), vec![("hi, want to buy something?".into(), true)]);
    assert_eq!(bob.group_status(&g).unwrap(), GroupStatus::Request { from: Some(mallory.account_id().into()) });

    // Decline and block: mallory's group asks for bob's removal; nothing more is shown.
    bob.decline(&g, true).unwrap();
    assert!(bob.contact(mallory.account_id()).unwrap().unwrap().blocked);
    let ev = mallory.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::LeaveRequested { .. })), "{ev:?}");
    mallory.send_text(&g, "hello?").unwrap();
    assert!(texts(&bob.sync(0).unwrap()).is_empty());

    // A blocked account's new chat is declined at once.
    let g2 = mallory.create_group().unwrap();
    mallory.invite(&g2, bob.account_id()).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Declined { reason, .. } if reason == "blocked")), "{ev:?}");
    assert_eq!(bob.group_status(&g2).unwrap(), GroupStatus::Declined);

    // A stranger adding bob to a group (3+ members) is declined by default
    // (user.group_add = contacts only).
    let g3 = alice.create_group().unwrap();
    alice.invite(&g3, mallory.account_id()).unwrap();
    mallory.sync(0).unwrap();
    mallory.accept_request(&g3).unwrap();
    alice.invite(&g3, bob.account_id()).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Declined { reason, .. } if reason.contains("user.group_add"))), "{ev:?}");

    // bob allows everyone to add him: a stranger's group becomes a request.
    let s = bob.release_feature("user.group_add").unwrap();
    assert_eq!(s.state, tree_core::features::State::Released);
    let g4 = alice.create_group().unwrap();
    alice.invite(&g4, mallory.account_id()).unwrap();
    alice.invite(&g4, bob.account_id()).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.contains(&Event::Request { group: g4.clone(), from: alice.account_id().into(), direct: false }), "{ev:?}");
    bob.accept_request(&g4).unwrap();
    alice.send_text(&g4, "welcome").unwrap();
    assert_eq!(texts(&bob.sync(0).unwrap()), vec![("welcome".into(), false)]);
    // alice is now a contact: her next 1:1 chat is accepted directly.
    let g5 = alice.create_group().unwrap();
    alice.invite(&g5, bob.account_id()).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(!ev.iter().any(|e| matches!(e, Event::Request { .. } | Event::Declined { .. })), "{ev:?}");
    assert_eq!(bob.group_status(&g5).unwrap(), GroupStatus::Accepted);

    // user.group_add = nobody: not even a contact may add bob to a group.
    bob.apply_feature("user.group_add", Some("nobody".into())).unwrap();
    let g7 = alice.create_group().unwrap();
    alice.invite(&g7, mallory.account_id()).unwrap();
    alice.invite(&g7, bob.account_id()).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Declined { reason, .. } if reason.contains("nobody"))), "{ev:?}");
    bob.release_feature("user.group_add").unwrap();

    // Messages of a blocked member in an accepted group are dropped.
    mallory.sync(0).unwrap();
    mallory.send_text(&g4, "from mallory").unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(texts(&ev).is_empty() && ev.iter().any(|e| matches!(e, Event::Dropped { .. })), "{ev:?}");
    bob.unblock(mallory.account_id()).unwrap();
    mallory.send_text(&g4, "again").unwrap();
    assert_eq!(texts(&bob.sync(0).unwrap()), vec![("again".into(), false)]);

    // Strangers blocked entirely (user.stranger_block).
    alice.apply_feature("user.stranger_block", None).unwrap();
    let mut eve = env.device("eve");
    let g6 = eve.create_group().unwrap();
    eve.invite(&g6, alice.account_id()).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Declined { reason, .. } if reason.contains("stranger_block"))), "{ev:?}");

    // Settings survive a restart; permanent locks hold.
    drop(alice);
    let (alice, _) = tree_client::Session::open(&env.profile("alice"), "alice passphrase").unwrap();
    assert_eq!(alice.feature("user.stranger_block").unwrap().state, tree_core::features::State::Applied);
    assert!(matches!(alice.release_feature("user.key_change_warning"), Err(tree_client::Error::Feature(c)) if c == "LOCKED_ALWAYS"));
    assert!(matches!(alice.apply_feature("chat.media", None), Err(tree_client::Error::Feature(c)) if c == "NOT_ADMIN"));
    assert!(alice.features().unwrap().iter().any(|s| s.key == "user.message_requests"));
}

/// Admins through the server: only admins rename, change chat settings and
/// remove; every member sees the same settings.
#[test]
fn admins_through_the_server() {
    let env = Env::new("admins");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut carol = env.device("carol");
    bob.add_contact(alice.account_id()).unwrap();
    carol.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    alice.invite(&g, carol.account_id()).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();

    alice.set_group_name(&g, Some("산악회".into())).unwrap();
    alice.set_chat_feature(&g, "chat.media", false, None).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Changed { settings_changed: true, .. })), "{ev:?}");
    let s = bob.group_settings(&g).unwrap();
    assert_eq!(s.name.as_deref(), Some("산악회"));
    assert!(!s.features["chat.media"].applied);
    assert_eq!(s.admins, vec![alice.member_id()]);

    // bob is not an admin.
    assert!(matches!(bob.remove(&g, &[carol.member_id()]), Err(tree_client::Error::Core(tree_core::TreeError::NotAdmin))));
    assert!(bob.set_group_name(&g, Some("x".into())).is_err());
    // Permanent locks hold for admins too.
    assert!(matches!(alice.set_chat_feature(&g, "chat.e2e", false, None), Err(tree_client::Error::Feature(c)) if c == "LOCKED_ALWAYS"));
    assert!(matches!(alice.set_chat_feature(&g, "user.typing", false, None), Err(tree_client::Error::Feature(_))));

    // alice makes bob admin; bob removes carol.
    alice.make_admin(&g, bob.member_id(), true).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert_eq!(bob.remove(&g, &[carol.member_id()]).unwrap(), tree_client::CommitOutcome::Accepted { epoch: 6 });
    assert!(carol.sync(0).unwrap().contains(&Event::RemovedFromGroup { group: g.clone() }));
    alice.sync(0).unwrap();
    assert_eq!(alice.group_settings(&g).unwrap(), bob.group_settings(&g).unwrap());
    // The server database never saw the group name.
    let raw = std::fs::read(&env.db).unwrap();
    assert!(!raw.windows("산악회".len()).any(|w| w == "산악회".as_bytes()));
}
