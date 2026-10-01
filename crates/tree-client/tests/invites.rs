//! Group invite links (PROTOCOL.md 8.7) through a real server.

mod common;

use common::Env;
use tree_client::{Error, Event, GroupStatus};

#[test]
fn strangers_join_through_a_link() {
    let env = Env::new("invites");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut carol = env.device("carol");
    let mut dave = env.device("dave");
    let g = alice.create_group().unwrap();
    // bob is a member but not an admin: he cannot make links.
    bob.add_contact(alice.account_id()).unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    assert!(matches!(bob.create_invite_link(&g, 3600, 5), Err(Error::Feature(c)) if c == "NOT_ADMIN"));

    // The link is two uses; making it applies chat.invite_link for everyone.
    let link = alice.create_invite_link(&g, 3600, 2).unwrap();
    assert!(link.starts_with("tree://join/"));
    assert!(alice.group_settings(&g).unwrap().features["chat.invite_link"].applied);
    assert_eq!(alice.invite_links(&g).unwrap().len(), 1);
    bob.sync(0).unwrap();

    // carol is a stranger to alice and has message requests on; she asked
    // to join, so the group arrives accepted.
    assert_eq!(carol.join_invite_link(&link).unwrap(), alice.account_id());
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::InviteLinkUsed { account, .. } if account == carol.account_id())), "{ev:?}");
    let ev = carol.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Joined { .. })), "{ev:?}");
    assert_eq!(carol.group_status(&g).unwrap(), GroupStatus::Accepted);
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    let id = carol.send_text(&g, "joined by link").unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Text { id: i, .. } if *i == id)), "{ev:?}");

    // A damaged link, a link of another kind.
    assert!(dave.join_invite_link("tree://join/abc").is_err());
    assert!(dave.join_invite_link("https://example.org").is_err());

    // Admins release links: alice refuses the next request even though the
    // server still counted it.
    alice.revoke_invite_links(&g).unwrap();
    assert!(!alice.group_settings(&g).unwrap().features["chat.invite_link"].applied);
    match dave.join_invite_link(&link) {
        Err(Error::Server { status: 404, .. }) => {}
        other => panic!("{other:?}"),
    }

    // A new link with one use: dave joins; then it is used up.
    let link2 = alice.create_invite_link(&g, 3600, 1).unwrap();
    dave.join_invite_link(&link2).unwrap();
    let mut eve = env.device("eve");
    assert!(matches!(eve.join_invite_link(&link2), Err(Error::Server { status: 404, .. })));
    alice.sync(0).unwrap();
    assert!(dave.sync(0).unwrap().iter().any(|e| matches!(e, Event::Joined { .. })));
    assert_eq!(alice.members(&g).unwrap().len(), 4);

    // A blocked account's request is refused by the owner's device.
    let link3 = alice.create_invite_link(&g, 3600, 5).unwrap();
    alice.block(eve.account_id()).unwrap();
    eve.join_invite_link(&link3).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains("blocked"))), "{ev:?}");
    assert_eq!(alice.members(&g).unwrap().len(), 4);
}
