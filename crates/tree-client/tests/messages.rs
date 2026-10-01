//! Edits, deletion for everyone, reactions, disappearing messages, view-once
//! files and search, with the group's settings enforced on both sides.

mod common;

use common::Env;
use tree_client::Event;

fn find<T>(ev: &[Event], f: impl Fn(&Event) -> Option<T>) -> Option<T> {
    ev.iter().find_map(f)
}

#[test]
fn edits_deletes_reactions_disappearing_view_once() {
    let env = Env::new("messages");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();

    // text with an id, stored on both sides
    let id = alice.send_text(&g, "모임은 7시").unwrap();
    let ev = bob.sync(0).unwrap();
    assert_eq!(find(&ev, |e| match e { Event::Text { id, .. } => Some(id.clone()), _ => None }), Some(id.clone()));
    assert_eq!(bob.history(&g, 10).unwrap().last().unwrap().text.as_deref(), Some("모임은 7시"));

    // edit by the sender
    alice.edit(&g, &id, "모임은 8시").unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Edited { text, .. } if text == "모임은 8시")), "{ev:?}");
    let m = bob.history(&g, 10).unwrap().pop().unwrap();
    assert_eq!((m.text.as_deref(), m.edited_at.is_some()), (Some("모임은 8시"), true));
    // bob cannot edit alice's message
    assert!(bob.edit(&g, &id, "hacked").is_err());

    // reactions
    bob.react(&g, &id, "👍", false).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Reaction { emoji, remove: false, .. } if emoji == "👍")), "{ev:?}");
    assert_eq!(alice.history(&g, 10).unwrap().last().unwrap().reactions["👍"], vec![bob.member_id().to_hex()]);

    // delete for everyone
    alice.delete_for_all(&g, &id).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Deleted { .. })), "{ev:?}");
    let m = bob.history(&g, 10).unwrap().pop().unwrap();
    assert!(m.deleted && m.text.is_none() && m.reactions.is_empty());

    // search on the device
    alice.send_text(&g, "searchable needle 51a").unwrap();
    bob.sync(0).unwrap();
    assert_eq!(bob.search("needle 51").unwrap().len(), 1);
    bob.release_feature("user.search_index").unwrap();
    assert!(bob.search("needle").is_err());

    // admins release edits and reactions: refused on both sides
    alice.set_chat_feature(&g, "chat.edit", false, None).unwrap();
    alice.set_chat_feature(&g, "chat.reactions", false, None).unwrap();
    bob.sync(0).unwrap();
    let id2 = bob.send_text(&g, "no edits now").unwrap();
    alice.sync(0).unwrap();
    assert!(matches!(bob.edit(&g, &id2, "x"), Err(tree_client::Error::Feature(c)) if c == "LOCKED_BY_CHAT"));
    assert!(alice.react(&g, &id2, "😀", false).is_err());

    // a 1-second edit window: too late after 2 seconds
    alice.set_chat_feature(&g, "chat.edit", true, Some("1".into())).unwrap();
    bob.sync(0).unwrap();
    let id3 = alice.send_text(&g, "quick").unwrap();
    bob.sync(0).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2100));
    assert!(alice.edit(&g, &id3, "too late").is_err());

    // disappearing messages: 2 seconds
    alice.set_chat_feature(&g, "chat.disappearing", true, Some("2".into())).unwrap();
    bob.sync(0).unwrap();
    alice.send_text(&g, "this vanishes c3d").unwrap();
    bob.sync(0).unwrap();
    assert!(bob.history(&g, 50).unwrap().iter().any(|m| m.text.as_deref() == Some("this vanishes c3d") && m.expires_at.is_some()));
    std::thread::sleep(std::time::Duration::from_millis(3100));
    assert!(!bob.history(&g, 50).unwrap().iter().any(|m| m.text.as_deref() == Some("this vanishes c3d")));
    assert!(!alice.history(&g, 50).unwrap().iter().any(|m| m.text.as_deref() == Some("this vanishes c3d")));

    // view-once file: opens once
    let f = alice.send_file(&g, b"secret photo", "p.jpg", "image/jpeg", true).unwrap();
    let ev = bob.sync(0).unwrap();
    let got = find(&ev, |e| match e { Event::File { file, .. } => Some(file.clone()), _ => None }).unwrap();
    assert!(got.view_once);
    assert_eq!(bob.download(&got).unwrap(), b"secret photo");
    assert!(bob.received_file(&f.id).unwrap().is_none(), "reference gone after one view");
    assert!(alice.received_file(&f.id).unwrap().is_none());
    alice.set_chat_feature(&g, "chat.view_once", false, None).unwrap();
    bob.sync(0).unwrap();
    assert!(alice.send_file(&g, b"x", "x", "x", true).is_err());
}
