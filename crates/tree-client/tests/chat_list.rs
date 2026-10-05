//! Chat list basics and contacts through a real server: mute with a
//! duration, archive (and what brings a chat back), pins, drafts, unread
//! markers, silent send, quiet leave, stranger labels and username links.
//! Every setting involved is toggled both ways.

mod common;

use common::Env;
use tree_client::organize::{message_meta, MAX_PINNED};
use tree_client::{Error, Event, Session, TextOptions};
use tree_core::features::State;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// alice starts a 1:1 chat with bob (bob has alice as a contact, so no request).
fn pair(env: &Env) -> (Session, Session, Vec<u8>) {
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.confirm_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.sync(0).unwrap();
    (alice, bob, g)
}

fn silent_of(ev: &[Event]) -> Option<bool> {
    ev.iter().rev().find_map(|e| match e {
        Event::Text { silent, .. } => Some(*silent),
        _ => None,
    })
}

/// Mute for 1 h / until unmuted / a moment; muted chats do not notify; the
/// quiet folder holds only chats muted now.
#[test]
fn mute_with_a_duration() {
    let env = Env::new("mute");
    let (mut alice, mut bob, g) = pair(&env);
    assert!(bob.should_notify(&g, false).unwrap());
    let until = bob.mute_for(&g, Some(3600)).unwrap().unwrap();
    assert!((until - now() - 3600).abs() <= 2);
    assert!(bob.is_muted(&g).unwrap());
    assert_eq!(bob.muted_until(&g).unwrap(), Some(until));
    alice.send_text(&g, "muted?").unwrap();
    bob.sync(0).unwrap();
    assert!(!bob.should_notify(&g, false).unwrap(), "muted chats do not notify");
    assert_eq!(bob.unread(&g).unwrap(), 1, "but the message is unread");
    let st = bob.chat_state(&g).unwrap();
    assert!(st.muted && st.muted_until == Some(until));

    // Until unmuted: no end time.
    assert_eq!(bob.mute_for(&g, None).unwrap(), None);
    assert!(bob.is_muted(&g).unwrap());
    assert_eq!(bob.muted_until(&g).unwrap(), None);
    bob.mute(&g, false).unwrap();
    assert!(!bob.is_muted(&g).unwrap());
    assert!(bob.should_notify(&g, false).unwrap());

    // A timed mute ends by itself, also in the quiet folder.
    bob.apply_feature("user.quiet_folder", None).unwrap();
    bob.mute_for(&g, Some(1)).unwrap();
    let quiet = |b: &mut Session| b.folders().unwrap().into_iter().find(|f| f.kind == "quiet").unwrap().chats;
    assert_eq!(quiet(&mut bob), vec![hex::encode(&g)]);
    std::thread::sleep(std::time::Duration::from_millis(2100));
    assert!(!bob.is_muted(&g).unwrap());
    assert!(quiet(&mut bob).is_empty());
    assert!(bob.should_notify(&g, false).unwrap());

    // Out of range.
    assert!(matches!(bob.mute_for(&g, Some(0)), Err(Error::Usage(_))));
    assert!(matches!(bob.mute_for(&g, Some(400 * 86400)), Err(Error::Usage(_))));
    // The apps' choices all fit.
    for (_, s) in tree_client::organize::MUTE_CHOICES {
        bob.mute_for(&g, *s).unwrap();
    }
}

/// Silent send: the flag travels inside the encrypted message, receivers
/// store it, and apps do not notify for it.
#[test]
fn silent_send() {
    let env = Env::new("silent");
    let (mut alice, mut bob, g) = pair(&env);
    let quiet = TextOptions { silent: true, ..Default::default() };
    let id = alice.send_text_with(&g, "late at night", &quiet).unwrap();
    let ev = bob.sync(0).unwrap();
    assert_eq!(silent_of(&ev), Some(true), "{ev:?}");
    assert!(!bob.should_notify(&g, true).unwrap());
    assert_eq!(bob.unread(&g).unwrap(), 1);
    let stored = bob.history(&g, 10).unwrap();
    let m = stored.iter().find(|m| m.id == id).unwrap();
    assert!(message_meta(m).silent, "the receiver keeps the flag");
    assert!(message_meta(alice.history(&g, 10).unwrap().iter().find(|m| m.id == id).unwrap()).silent, "and the sender");

    // A normal message notifies.
    let id2 = alice.send_text(&g, "good morning").unwrap();
    assert_eq!(silent_of(&bob.sync(0).unwrap()), Some(false));
    assert!(bob.should_notify(&g, false).unwrap());
    assert!(!message_meta(bob.history(&g, 10).unwrap().iter().find(|m| m.id == id2).unwrap()).silent);
}

/// Markup: the flag is kept on both sides, so apps can draw bold, italic...
/// in the history too, not only when the message arrives.
#[test]
fn formatted_flag_is_kept() {
    let env = Env::new("fmt");
    let (mut alice, mut bob, g) = pair(&env);
    let fmt = TextOptions { formatted: true, ..Default::default() };
    let id = alice.send_text_with(&g, "**bold**", &fmt).unwrap();
    let plain = alice.send_text(&g, "**not markup**").unwrap();
    bob.sync(0).unwrap();
    let h = bob.history(&g, 10).unwrap();
    assert!(message_meta(h.iter().find(|m| m.id == id).unwrap()).formatted);
    assert!(!message_meta(h.iter().find(|m| m.id == plain).unwrap()).formatted);
    assert!(message_meta(alice.history(&g, 10).unwrap().iter().find(|m| m.id == id).unwrap()).formatted, "and the sender");
}

/// Archive: out of the main list; a new message brings an unmuted chat
/// back (`user.unarchive_on_message`), a muted one stays archived, a silent
/// message does not bring it back. Released: archived chats stay archived.
#[test]
fn archive_and_what_brings_a_chat_back() {
    let env = Env::new("archive");
    let (mut alice, mut bob, g) = pair(&env);
    let archived = |b: &Session| b.chat_list().unwrap().iter().find(|c| c.group == g).unwrap().archived;
    bob.archive_chat(&g, true).unwrap();
    assert!(bob.is_archived(&g).unwrap() && archived(&bob));
    alice.send_text(&g, "hi again").unwrap();
    bob.sync(0).unwrap();
    assert!(!archived(&bob), "an unmuted archived chat comes back");

    // Muted: stays archived.
    bob.archive_chat(&g, true).unwrap();
    bob.mute_for(&g, Some(3600)).unwrap();
    alice.send_text(&g, "still there?").unwrap();
    bob.sync(0).unwrap();
    assert!(archived(&bob), "muted chats stay archived");
    bob.mute(&g, false).unwrap();

    // Silent: stays archived.
    alice.send_text_with(&g, "shh", &TextOptions { silent: true, ..Default::default() }).unwrap();
    bob.sync(0).unwrap();
    assert!(archived(&bob), "a silent message does not bring it back");

    // Released: archived chats stay archived; applied again: they come back.
    assert_eq!(bob.release_feature("user.unarchive_on_message").unwrap().state, State::Released);
    alice.send_text(&g, "hello?").unwrap();
    bob.sync(0).unwrap();
    assert!(archived(&bob), "released: stays archived");
    bob.apply_feature("user.unarchive_on_message", None).unwrap();
    alice.send_text(&g, "hello!").unwrap();
    bob.sync(0).unwrap();
    assert!(!archived(&bob));

    // By hand.
    bob.archive_chat(&g, true).unwrap();
    bob.archive_chat(&g, false).unwrap();
    assert!(!bob.is_archived(&g).unwrap());
}

/// Pins: at most five, in order, on top of the list; moving, unpinning;
/// archiving drops a pin and pinning brings a chat out of the archive.
#[test]
fn pinned_chats_on_top() {
    let env = Env::new("pins");
    let (mut alice, mut bob, g) = pair(&env);
    let mut others = Vec::new();
    for _ in 0..MAX_PINNED {
        others.push(bob.create_group().unwrap());
    }
    // Activity order first: the newest chat on top.
    alice.send_text(&g, "newest").unwrap();
    bob.sync(0).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let order = |b: &Session| b.chat_list().unwrap().into_iter().map(|c| c.group).collect::<Vec<_>>();
    bob.send_text(&others[2], "me").unwrap(); // a one-member chat: stored, sent nowhere
    assert_eq!(order(&bob)[0], others[2], "most recent activity first");

    for o in &others {
        bob.pin_chat(o, true).unwrap();
    }
    assert!(matches!(bob.pin_chat(&g, true), Err(Error::Usage(_))), "at most {MAX_PINNED}");
    assert_eq!(order(&bob)[..MAX_PINNED], others[..], "pinned first, in pin order");
    assert_eq!(*order(&bob).last().unwrap(), g);
    bob.pin_chat(&others[0], true).unwrap(); // idempotent
    bob.move_pinned_chat(&others[4], 0).unwrap();
    assert_eq!(bob.pinned_chats().unwrap()[0], others[4]);
    assert!(bob.move_pinned_chat(&g, 0).is_err());

    // Archiving unpins; pinning unarchives.
    bob.archive_chat(&others[1], true).unwrap();
    assert!(!bob.pinned_chats().unwrap().contains(&others[1]));
    bob.archive_chat(&g, true).unwrap();
    bob.pin_chat(&g, true).unwrap();
    assert!(!bob.is_archived(&g).unwrap());
    let st = bob.chat_state(&g).unwrap();
    assert!(st.pinned && !st.archived);
    bob.pin_chat(&g, false).unwrap();
    assert!(!bob.chat_state(&g).unwrap().pinned);
}

/// Drafts: kept in the encrypted profile (survive a restart), cleared on
/// send. Released: nothing is kept and stored drafts are deleted.
#[test]
fn drafts() {
    let env = Env::new("drafts");
    let (_alice, bob, g) = pair(&env);
    assert!(bob.set_draft(&g, "half a thought").unwrap());
    drop(bob);
    let (mut bob, _) = Session::open(&env.profile("bob"), "bob passphrase").unwrap();
    assert_eq!(bob.draft(&g).unwrap().as_deref(), Some("half a thought"), "restored after a restart");
    assert_eq!(bob.chat_state(&g).unwrap().draft.as_deref(), Some("half a thought"));
    bob.send_text(&g, "half a thought, finished").unwrap();
    assert_eq!(bob.draft(&g).unwrap(), None, "cleared on send");
    assert!(!bob.set_draft(&g, "   ").unwrap(), "blank is no draft");
    assert!(bob.set_draft(&g, &"x".repeat(70_000)).is_err());

    bob.set_draft(&g, "secret plan").unwrap();
    assert_eq!(bob.release_feature("user.drafts").unwrap().state, State::Released);
    assert_eq!(bob.draft(&g).unwrap(), None);
    assert!(!bob.set_draft(&g, "another").unwrap(), "released: not kept");
    bob.apply_feature("user.drafts", None).unwrap();
    assert_eq!(bob.draft(&g).unwrap(), None, "the release deleted the stored draft");
    assert!(bob.set_draft(&g, "back").unwrap());
    assert_eq!(bob.draft(&g).unwrap().as_deref(), Some("back"));
}

/// Mark as unread / read, and the unread folder.
#[test]
fn unread_markers() {
    let env = Env::new("unreadmark");
    let (_alice, mut bob, g) = pair(&env);
    let in_unread = |b: &mut Session| b.folders().unwrap().into_iter().find(|f| f.kind == "unread").unwrap().chats.contains(&hex::encode(&g));
    assert!(!bob.is_marked_unread(&g).unwrap());
    assert!(!in_unread(&mut bob));
    bob.mark_unread(&g, true).unwrap();
    assert!(bob.is_marked_unread(&g).unwrap() && bob.chat_state(&g).unwrap().marked_unread);
    assert!(in_unread(&mut bob));
    bob.mark_read(&g, &[]).unwrap();
    assert!(!bob.is_marked_unread(&g).unwrap(), "opening the chat clears the marker");
    bob.mark_unread(&g, true).unwrap();
    bob.mark_unread(&g, false).unwrap();
    assert!(!in_unread(&mut bob));
}

/// Quiet leave: the member list changes for everyone, but no "left" line
/// is stored; a normal leave stores one with the name, a removal a
/// "removed" line.
#[test]
fn quiet_leave() {
    let env = Env::new("quietleave");
    let mut alice = env.device("alice");
    let mut people: Vec<Session> = ["bob", "carol", "dave", "erin"].iter().map(|n| env.device(n)).collect();
    let g = alice.create_group().unwrap();
    for p in &people {
        p.confirm_contact(alice.account_id()).unwrap();
    }
    for i in 0..people.len() {
        let acc = people[i].account_id().to_string();
        alice.invite(&g, &acc).unwrap();
        for p in people.iter_mut() {
            p.sync(0).unwrap();
        }
    }
    for p in people.iter_mut() {
        p.sync(0).unwrap();
    }
    let lines = |s: &Session| s.history(&g, 100).unwrap().into_iter().filter(|m| m.kind == "left" || m.kind == "removed").collect::<Vec<_>>();

    // carol leaves quietly.
    let carol = people[1].member_id();
    people[1].leave_quietly(&g).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.contains(&Event::LeaveRequested { group: g.clone(), member: carol, quiet: true }), "{ev:?}");
    alice.remove(&g, &[carol]).unwrap();
    let ev = people[0].sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Changed { removed, .. } if removed == &vec![carol])), "the member list changes");
    assert!(lines(&people[0]).is_empty(), "no line for a quiet leave");
    assert!(lines(&alice).is_empty());
    assert_eq!(alice.members(&g).unwrap().len(), 4);

    // dave leaves normally: a "left" line with his name.
    let dave = people[2].member_id();
    people[2].leave(&g).unwrap();
    assert!(alice.sync(0).unwrap().contains(&Event::LeaveRequested { group: g.clone(), member: dave, quiet: false }));
    alice.remove(&g, &[dave]).unwrap();
    people[0].sync(0).unwrap();
    for s in [&people[0], &alice] {
        let l = lines(s);
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].kind.as_str(), l[0].sender.as_str()), ("left", dave.to_hex().as_str()));
        assert_eq!(message_meta(&l[0]).name.as_deref(), Some("dave"));
    }

    // erin is removed without asking: a "removed" line.
    let erin = people[3].member_id();
    alice.remove(&g, &[erin]).unwrap();
    people[0].sync(0).unwrap();
    assert_eq!(lines(&people[0]).last().unwrap().kind, "removed");
    assert_eq!(people[0].unread(&g).unwrap(), 0, "departure lines are not unread messages");
}

/// `user.stranger_labels`: labels while applied, none once released.
#[test]
fn stranger_labels_follow_the_setting() {
    let env = Env::new("labels");
    let (mut alice, mut bob, _g) = pair(&env);
    let carol = env.device("carol");
    let l = alice.stranger_labels(carol.account_id()).unwrap().unwrap();
    assert!(l.not_contact && l.no_common_group && l.name_unverified);
    let l = bob.stranger_labels(alice.account_id()).unwrap().unwrap();
    assert!(!l.not_contact);
    assert_eq!(alice.release_feature("user.stranger_labels").unwrap().state, State::Released);
    assert_eq!(alice.stranger_labels(carol.account_id()).unwrap(), None);
    alice.apply_feature("user.stranger_labels", None).unwrap();
    assert!(alice.stranger_labels(carol.account_id()).unwrap().is_some());
}

/// `user.username_link`: a link (and QR text) that finds the account;
/// reset gives a new link and the old one stops working while the name
/// stays; hidden names are not found by link; releasing deletes it.
#[test]
fn username_link_and_reset() {
    let env = Env::new("ulink");
    let alice = env.device("alice");
    let bob = env.device("bob");
    assert_eq!(alice.username_link().unwrap(), None, "released by default");
    assert!(alice.apply_feature("user.username_link", None).is_err(), "needs a @username");
    assert_eq!(alice.feature("user.username_link").unwrap().state, State::Released);

    alice.set_username("alice_l").unwrap();
    assert_eq!(alice.apply_feature("user.username_link", None).unwrap().state, State::Applied);
    let link = alice.username_link().unwrap().unwrap();
    assert!(link.starts_with("tree://u/"), "{link}");
    assert_eq!(alice.username_qr().unwrap().as_deref(), Some(link.as_str()));
    assert!(!link.contains("alice"), "the link does not spell the name");
    assert_eq!(bob.find_by_link(&link).unwrap().as_deref(), Some(alice.account_id()));
    // Applying again keeps the same link.
    alice.apply_feature("user.username_link", None).unwrap();
    assert_eq!(alice.username_link().unwrap().as_deref(), Some(link.as_str()));

    // QR friend add: the scanned link makes alice bob's chosen contact.
    assert_eq!(bob.add_contact_by_link(&link).unwrap().as_deref(), Some(alice.account_id()));
    assert!(bob.contact(alice.account_id()).unwrap().unwrap().accepted);

    // Reset: new link, old one dead, the name stays.
    let link2 = alice.reset_username_link().unwrap();
    assert_ne!(link, link2);
    assert_eq!(bob.find_by_link(&link).unwrap(), None);
    assert_eq!(bob.find_by_link(&link2).unwrap().as_deref(), Some(alice.account_id()));
    assert_eq!(bob.find("alice_l").unwrap().as_deref(), Some(alice.account_id()));

    // Hidden name: not found by link either.
    alice.release_feature("user.discoverable").unwrap();
    assert_eq!(bob.find_by_link(&link2).unwrap(), None);
    alice.apply_feature("user.discoverable", None).unwrap();
    assert_eq!(bob.find_by_link(&link2).unwrap().as_deref(), Some(alice.account_id()));

    // Released: the link is deleted on the server.
    assert_eq!(alice.release_feature("user.username_link").unwrap().state, State::Released);
    assert_eq!(alice.username_link().unwrap(), None);
    assert!(matches!(alice.reset_username_link(), Err(Error::Feature(_))));
    assert_eq!(bob.find_by_link(&link2).unwrap(), None);
    // Applied again: a fresh link; dropping the name drops it too.
    alice.apply_feature("user.username_link", None).unwrap();
    let link3 = alice.username_link().unwrap().unwrap();
    assert_ne!(link3, link2);
    assert!(bob.find_by_link(&link3).unwrap().is_some());
    alice.release_username().unwrap();
    assert_eq!(bob.find_by_link(&link3).unwrap(), None);
    assert_eq!(alice.feature("user.username_link").unwrap().state, State::Released);
    assert!(bob.find_by_link("tree://join/AAAAAAAAAAAAAAAAAAAAAA").is_err());
}
