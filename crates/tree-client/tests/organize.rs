//! Read receipts, typing, note to self, stranger labels, folders.

mod common;

use common::Env;
use tree_client::Event;

#[test]
fn receipts_typing_notes_labels_folders() {
    let env = Env::new("organize");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.sync(0).unwrap();

    // Unread count and read receipts.
    let id = alice.send_text(&g, "hello").unwrap();
    bob.sync(0).unwrap();
    assert_eq!(bob.unread(&g).unwrap(), 1);
    bob.mark_read(&g, std::slice::from_ref(&id)).unwrap();
    assert_eq!(bob.unread(&g).unwrap(), 0);
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Read { ids, .. } if ids == &vec![id.clone()])), "{ev:?}");
    assert_eq!(alice.read_by(&g, &id).unwrap(), vec![bob.member_id().to_hex()]);

    // Receipts go both ways or not at all.
    alice.release_feature("user.read_receipts").unwrap();
    let id2 = alice.send_text(&g, "again").unwrap();
    bob.sync(0).unwrap();
    bob.mark_read(&g, std::slice::from_ref(&id2)).unwrap();
    assert!(!alice.sync(0).unwrap().iter().any(|e| matches!(e, Event::Read { .. })), "alice released receipts: she sees none");
    assert!(alice.read_by(&g, &id2).unwrap().is_empty());
    alice.mark_read(&g, std::slice::from_ref(&id2)).unwrap();
    assert!(!bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::Read { .. })), "and sends none");

    // Typing, both ways.
    bob.set_typing(&g, true).unwrap();
    assert!(alice.sync(0).unwrap().iter().any(|e| matches!(e, Event::Typing { on: true, .. })));
    alice.release_feature("user.typing").unwrap();
    bob.set_typing(&g, false).unwrap();
    assert!(!alice.sync(0).unwrap().iter().any(|e| matches!(e, Event::Typing { .. })));

    // Note to self: one member, made once, hidden when released.
    let note = bob.note_to_self().unwrap().unwrap();
    assert_eq!(bob.note_to_self().unwrap().unwrap(), note);
    assert_eq!(bob.members(&note).unwrap().len(), 1);
    bob.send_text(&note, "milk").unwrap();
    assert_eq!(bob.history(&note, 10).unwrap().len(), 1);
    bob.release_feature("user.note_to_self").unwrap();
    assert!(bob.note_to_self().unwrap().is_none());
    bob.apply_feature("user.note_to_self", None).unwrap();

    // Stranger labels and the group safety notice.
    let mut carol = env.device("carol");
    let l = alice.stranger_labels(carol.account_id()).unwrap().unwrap();
    assert!(l.not_contact && l.no_common_group && l.name_unverified);
    let l = bob.stranger_labels(alice.account_id()).unwrap().unwrap();
    assert!(!l.not_contact && l.no_common_group && l.name_unverified, "{l:?}");
    // A stranger (carol) adds bob to a group of three.
    carol.release_feature("user.group_add").unwrap();
    bob.release_feature("user.group_add").unwrap();
    let g3 = carol.create_group().unwrap();
    let mut dave = env.device("dave");
    dave.add_contact(carol.account_id()).unwrap();
    carol.invite(&g3, dave.account_id()).unwrap();
    carol.invite(&g3, bob.account_id()).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::GroupSafetyNotice { adder, .. } if adder == carol.account_id())), "{ev:?}");
    dave.sync(0).unwrap();

    // Folders: user folders, built-in ones, quiet folder for muted chats.
    bob.create_folder("family").unwrap();
    bob.file_chat("family", &g, true).unwrap();
    assert!(bob.create_folder("").is_err());
    assert!(bob.file_chat("nope", &g, true).is_err());
    let f = bob.folders().unwrap();
    let get = |name: &str| f.iter().find(|x| x.name == name).cloned();
    assert_eq!(get("family").unwrap().chats, vec![hex::encode(&g)]);
    assert!(get("direct").unwrap().chats.contains(&hex::encode(&g)));
    assert!(get("groups").unwrap().chats.contains(&hex::encode(&g3)));
    assert!(get("quiet").is_none(), "released by default");
    bob.apply_feature("user.quiet_folder", None).unwrap();
    bob.mute(&g3, true).unwrap();
    assert!(bob.is_muted(&g3).unwrap());
    assert_eq!(bob.folders().unwrap().iter().find(|x| x.name == "quiet").unwrap().chats, vec![hex::encode(&g3)]);
    bob.delete_folder("family").unwrap();
    assert!(!bob.folders().unwrap().iter().any(|x| x.name == "family"));
    bob.release_feature("user.default_folders").unwrap();
    assert!(!bob.folders().unwrap().iter().any(|x| x.kind == "unread"));
}

#[test]
fn link_previews_and_last_seen() {
    use tree_client::payload::LinkPreview;
    use tree_client::TextOptions;
    let env = Env::new("preview");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.sync(0).unwrap();

    let p = LinkPreview { url: "https://example.org/a".into(), title: "Example".into(), description: Some("a page".into()) };
    let with = TextOptions { preview: Some(p.clone()), ..Default::default() };
    let preview_of = |ev: &[Event]| {
        ev.iter().rev().find_map(|e| match e {
            Event::Text { preview, .. } => Some(preview.clone()),
            _ => None,
        })
    };
    alice.send_text_with(&g, "look https://example.org/a", &with).unwrap();
    assert_eq!(preview_of(&bob.sync(0).unwrap()), Some(Some(p.clone())));
    // Receivers who released previews get the text without it.
    bob.release_feature("user.link_preview").unwrap();
    alice.send_text_with(&g, "again", &with).unwrap();
    assert_eq!(preview_of(&bob.sync(0).unwrap()), Some(None));
    // Senders who released previews send none.
    bob.apply_feature("user.link_preview", None).unwrap();
    alice.release_feature("user.link_preview").unwrap();
    alice.send_text_with(&g, "third", &with).unwrap();
    assert_eq!(preview_of(&bob.sync(0).unwrap()), Some(None));
    // Malformed previews are refused.
    let bad = TextOptions { preview: Some(LinkPreview { url: "file:///etc/passwd".into(), title: "x".into(), description: None }), ..Default::default() };
    assert!(alice.send_text_with(&g, "x", &bad).is_err());
    let long = TextOptions { preview: Some(LinkPreview { url: "https://e.org".into(), title: "t".repeat(201), description: None }), ..Default::default() };
    assert!(alice.send_text_with(&g, "x", &long).is_err());

    // Last seen: released by default; both sides must apply it.
    alice.announce_seen(&g).unwrap();
    bob.sync(0).unwrap();
    assert_eq!(bob.last_seen(&g, &alice.member_id()).unwrap(), None);
    alice.apply_feature("user.last_seen", None).unwrap();
    alice.announce_seen(&g).unwrap();
    bob.sync(0).unwrap();
    assert_eq!(bob.last_seen(&g, &alice.member_id()).unwrap(), None, "bob does not share his, so he sees none");
    bob.apply_feature("user.last_seen", None).unwrap();
    alice.announce_seen(&g).unwrap();
    bob.sync(0).unwrap();
    let t = bob.last_seen(&g, &alice.member_id()).unwrap().unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!((now - t).abs() <= 5, "the receiver's own clock");
}
