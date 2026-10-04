//! Feature switches that the server or other devices see, toggled both
//! ways through a real server: each one must really change the behaviour.

mod common;

use common::Env;
use tree_client::{Error, Event, GroupStatus};
use tree_core::features::{LockReason, State};

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// `user.discoverable`: released, nobody finds the @username (the answer is
/// the same as for a name nobody has); applied again, they do. It holds for
/// a name registered while released, too.
#[test]
fn discoverable_controls_username_lookups() {
    let env = Env::new("discoverable");
    let alice = env.device("alice");
    let bob = env.device("bob");
    assert_eq!(alice.set_username("alice_d").unwrap(), "alice_d");
    assert_eq!(bob.find("@alice_d").unwrap().as_deref(), Some(alice.account_id()));

    assert_eq!(alice.release_feature("user.discoverable").unwrap().state, State::Released);
    assert_eq!(bob.find("@alice_d").unwrap(), None);
    assert_eq!(bob.find("@nobody_has_this").unwrap(), None, "same answer as an unknown name");
    // Hidden, but still hers.
    let carol = env.device("carol");
    assert!(matches!(carol.set_username("alice_d"), Err(Error::Server { status: 409, .. })));

    assert_eq!(alice.apply_feature("user.discoverable", None).unwrap().state, State::Applied);
    assert_eq!(bob.find("@alice_d").unwrap().as_deref(), Some(alice.account_id()));

    // Released before a name is chosen: the name is registered hidden.
    carol.release_feature("user.discoverable").unwrap();
    carol.set_username("carol_d").unwrap();
    assert_eq!(bob.find("carol_d").unwrap(), None);
    carol.apply_feature("user.discoverable", None).unwrap();
    assert_eq!(bob.find("carol_d").unwrap().as_deref(), Some(carol.account_id()));
    // No name at all: the switch still works locally.
    let dave = env.device("dave");
    assert_eq!(dave.release_feature("user.discoverable").unwrap().state, State::Released);
    assert!(matches!(dave.apply_feature("user.discoverable", Some("x".into())), Err(Error::InvalidOption(_))));
}

/// Joining through an invite link is the joiner's own choice: it is
/// accepted even with `user.group_add = nobody` and message requests on.
/// Without a link use, the same owner's group is still refused.
#[test]
fn a_link_join_is_the_joiners_choice() {
    let env = Env::new("linkchoice");
    let mut alice = env.device("alice");
    let mut dave = env.device("dave");
    let carol = env.device("carol");
    dave.apply_feature("user.group_add", Some("nobody".into())).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, carol.account_id()).unwrap();
    let link = alice.create_invite_link(&g, 3600, 5).unwrap();
    dave.join_invite_link(&link).unwrap();
    alice.sync(0).unwrap();
    let ev = dave.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Joined { .. })), "{ev:?}");
    assert_eq!(dave.group_status(&g).unwrap(), GroupStatus::Accepted);
    // The owner adding dave to another group without a link use: refused.
    let g2 = alice.create_group().unwrap();
    alice.invite(&g2, carol.account_id()).unwrap();
    alice.invite(&g2, dave.account_id()).unwrap();
    let ev = dave.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Declined { reason, .. } if reason.contains("nobody"))), "{ev:?}");
}

/// `chat.e2e` is permanently on: an admin cannot release it, applying it
/// writes nothing into the group settings, and every member's settings
/// screen shows it applied and locked.
#[test]
fn locked_chat_keys_report_their_locked_value() {
    let env = Env::new("lockedchat");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    let epoch = alice.epoch(&g).unwrap();
    assert!(matches!(alice.set_chat_feature(&g, "chat.e2e", false, None), Err(Error::Feature(c)) if c == "LOCKED_ALWAYS"));
    alice.set_chat_feature(&g, "chat.e2e", true, None).unwrap();
    assert_eq!(alice.epoch(&g).unwrap(), epoch, "no commit for a no-op");
    assert!(!alice.group_settings(&g).unwrap().features.contains_key("chat.e2e"));
    assert!(matches!(alice.set_chat_feature(&g, "chat.private_to_public", true, None), Err(Error::Feature(c)) if c == "RELEASED_ALWAYS"));
    for s in [&mut alice, &mut bob] {
        let f = s.chat_features(&g).unwrap();
        let e2e = f.iter().find(|f| f.key == "chat.e2e").unwrap();
        assert_eq!(e2e.state, State::Applied);
        assert!(matches!(e2e.locked_by, Some(LockReason::Always(_))));
        let p = f.iter().find(|f| f.key == "chat.private_to_public").unwrap();
        assert_eq!(p.state, State::Released);
    }
}

/// `user.read_receipts` released: nobody's receipts are shown, not even
/// ones stored before, and none are sent; applied again, they show.
#[test]
fn read_receipts_released_hides_stored_receipts() {
    let env = Env::new("receipts");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    let id = alice.send_text(&g, "read me").unwrap();
    bob.sync(0).unwrap();
    bob.mark_read(&g, std::slice::from_ref(&id)).unwrap();
    alice.sync(0).unwrap();
    assert_eq!(alice.read_by(&g, &id).unwrap(), vec![bob.member_id().to_hex()]);

    alice.release_feature("user.read_receipts").unwrap();
    assert!(alice.read_by(&g, &id).unwrap().is_empty(), "stored receipts are hidden after a release");
    let id2 = bob.send_text(&g, "from bob").unwrap();
    alice.sync(0).unwrap();
    alice.mark_read(&g, std::slice::from_ref(&id2)).unwrap();
    assert!(!bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::Read { .. })), "none sent");

    alice.apply_feature("user.read_receipts", None).unwrap();
    assert_eq!(alice.read_by(&g, &id).unwrap(), vec![bob.member_id().to_hex()]);
}

/// Options are validated (`INVALID_OPTION`) and `chat.disappearing` takes
/// the documented durations: no option means 1 day, `1h` an hour.
#[test]
fn options_are_checked_and_durations_work() {
    let env = Env::new("options");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();

    for bad in ["forever", "0", "1y", "400d"] {
        match alice.set_chat_feature(&g, "chat.disappearing", true, Some(bad.into())) {
            Err(Error::InvalidOption(why)) => assert!(why.contains("chat.disappearing") && why.contains("1d"), "{why}"),
            other => panic!("{bad}: {other:?}"),
        }
    }
    assert!(matches!(alice.set_chat_feature(&g, "chat.mention_all", true, Some("everyone".into())), Err(Error::InvalidOption(_))));
    assert!(matches!(bob.apply_feature("user.group_add", Some("everyone".into())), Err(Error::InvalidOption(_))));
    assert!(matches!(bob.apply_feature("user.typing", Some("1".into())), Err(Error::InvalidOption(_))));
    assert!(!alice.group_settings(&g).unwrap().features.contains_key("chat.disappearing"), "nothing was written");

    // Applied without an option: the default, 1 day, on both sides.
    alice.set_chat_feature(&g, "chat.disappearing", true, None).unwrap();
    bob.sync(0).unwrap();
    let f = bob.chat_features(&g).unwrap();
    assert_eq!(f.iter().find(|f| f.key == "chat.disappearing").unwrap().option.as_deref(), Some("1d"));
    alice.send_text(&g, "a day").unwrap();
    bob.sync(0).unwrap();
    let exp = |s: &mut tree_client::Session, text: &str| {
        s.history(&g, 50).unwrap().into_iter().find(|m| m.text.as_deref() == Some(text)).unwrap().expires_at
    };
    let day = exp(&mut bob, "a day").expect("expires");
    assert!((day - now() - 86400).abs() < 60, "{}", day - now());

    // An hour, written the documented way.
    alice.set_chat_feature(&g, "chat.disappearing", true, Some("1h".into())).unwrap();
    bob.sync(0).unwrap();
    alice.send_text(&g, "an hour").unwrap();
    bob.sync(0).unwrap();
    let hour = exp(&mut bob, "an hour").expect("expires");
    assert!((hour - now() - 3600).abs() < 60, "{}", hour - now());

    // Released: new messages stay.
    alice.set_chat_feature(&g, "chat.disappearing", false, None).unwrap();
    bob.sync(0).unwrap();
    alice.send_text(&g, "stays").unwrap();
    bob.sync(0).unwrap();
    assert_eq!(exp(&mut bob, "stays"), None);
    assert_eq!(exp(&mut alice, "stays"), None);
}
