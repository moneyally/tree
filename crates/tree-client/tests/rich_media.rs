//! Rich chats (Wave 2 part B) through a real server: stickers and custom
//! emoji, locations and live locations, events with replies, round video
//! notes. Each chat key is toggled both ways, and a released key is
//! enforced by the receiving device even against a modified sender
//! (`send_unchecked`).

mod common;

use common::Env;
use tree_client::chat_events::EventDraft;
use tree_client::payload::{EventInfo, LocationInfo};
use tree_client::stickers::{custom_emoji_key, NewSticker};
use tree_client::{Error, Event, Payload, Session};

fn dropped(ev: &[Event], what: &str) -> bool {
    ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains(what)))
}

fn locked(r: Result<impl std::fmt::Debug, Error>) -> bool {
    matches!(r, Err(Error::Feature(c)) if c == "LOCKED_BY_CHAT")
}

/// alice (admin) and bob in one chat; carol too if asked.
fn chat(env: &Env, with_carol: bool) -> (Session, Session, Option<Session>, Vec<u8>) {
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.confirm_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    let carol = with_carol.then(|| {
        let mut c = env.device("carol");
        c.confirm_contact(alice.account_id()).unwrap();
        alice.invite(&g, c.account_id()).unwrap();
        c.sync(0).unwrap();
        c
    });
    bob.sync(0).unwrap();
    (alice, bob, carol, g)
}

/// Every member's device takes the admin's new settings.
fn settle(all: &mut [&mut Session]) {
    for s in all {
        s.sync(0).unwrap();
    }
}

fn png(tag: u8) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\nfake sticker ".to_vec();
    v.extend(std::iter::repeat_n(tag, 64));
    v
}

/// Packs are opaque blobs on the server, shared by a link carrying the
/// manifest's key; stickers and custom emoji reactions arrive and open
/// with their keys; `chat.stickers` released stops them on both sides.
#[test]
fn stickers_and_custom_emoji() {
    let env = Env::new("stickers");
    let (mut alice, mut bob, carol, g) = chat(&env, true);
    let mut carol = carol.unwrap();
    let items = vec![
        NewSticker { name: "웃음".into(), emoji: "😀".into(), mime: "image/png".into(), bytes: png(1) },
        NewSticker { name: "하트".into(), emoji: "❤".into(), mime: "image/png".into(), bytes: png(2) },
    ];
    let pack = alice.create_sticker_pack("Tree friends 7f3a", &items, false).unwrap();
    assert!(pack.link.starts_with("tree://stickers/"));
    assert_eq!(alice.sticker_packs().unwrap().len(), 1);
    // The server holds only ciphertext: no title, name or image bytes.
    let mut blobs = 0;
    for f in std::fs::read_dir(env.dir.join("attachments")).unwrap() {
        let b = std::fs::read(f.unwrap().path()).unwrap();
        blobs += 1;
        for needle in [&b"Tree friends 7f3a"[..], "웃음".as_bytes(), &png(1)[..], &png(2)[..]] {
            assert!(!b.windows(needle.len()).any(|w| w == needle), "plaintext on the server");
        }
    }
    assert_eq!(blobs, 3, "two images and the manifest");

    // bob installs by link; everything opens with the keys from the link.
    let installed = bob.install_sticker_pack(&pack.link).unwrap();
    assert_eq!((installed.id.as_str(), installed.manifest.title.as_str()), (pack.id.as_str(), "Tree friends 7f3a"));
    assert_eq!(bob.sticker_image(&pack.id, 1).unwrap(), png(2));
    assert!(bob.install_sticker_pack("tree://stickers/garbage").is_err());

    // A sticker: carol never installed the pack and still opens it.
    let sid = alice.send_sticker(&g, &pack.id, 0).unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Sticker { id, index: 0, emoji, .. } if *id == sid && emoji == "😀")), "{ev:?}");
    assert_eq!(carol.sticker_image(&pack.id, 0).unwrap(), png(1));
    assert_eq!(carol.sticker_in(&g, &sid).unwrap(), Some((pack.id.clone(), 0)));
    assert!(carol.sticker_image(&pack.id, 5).is_err(), "no such item");
    bob.sync(0).unwrap();
    assert!(bob.send_sticker(&g, "not-installed", 0).is_err());

    // A custom emoji reaction: stored under its own key.
    let text = alice.send_text(&g, "react to me").unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    bob.react_sticker(&g, &text, &pack.id, 1, false).unwrap();
    let ev = alice.sync(0).unwrap();
    let key = custom_emoji_key(&pack.id, 1);
    assert!(ev.iter().any(|e| matches!(e, Event::Reaction { emoji, .. } if *emoji == key)), "{ev:?}");
    let m = alice.history(&g, 50).unwrap().into_iter().find(|m| m.id == text).unwrap();
    assert_eq!(m.reactions.get(&key), Some(&vec![bob.member_id().to_hex()]));
    carol.sync(0).unwrap();

    // Released: refused by the sender, dropped by receivers.
    alice.set_chat_feature(&g, "chat.stickers", false, None).unwrap();
    settle(&mut [&mut bob, &mut carol]);
    assert!(locked(alice.send_sticker(&g, &pack.id, 0)));
    assert!(locked(bob.react_sticker(&g, &text, &pack.id, 0, false)));
    let p = Payload::Sticker { id: "aa11".into(), pack: tree_client::stickers::parse_pack_link(&pack.link).unwrap(), index: 0, emoji: "😀".into() };
    bob.send_unchecked(&g, &p).unwrap();
    assert!(dropped(&alice.sync(0).unwrap(), "chat.stickers"));
    assert!(dropped(&carol.sync(0).unwrap(), "chat.stickers"));
    // A custom emoji reaction counts as its plain emoji while released.
    let r = Payload::React {
        id: text.clone(),
        emoji: "❤".into(),
        remove: false,
        sticker: Some(tree_client::payload::StickerRef { pack: tree_client::stickers::parse_pack_link(&pack.link).unwrap(), index: 1 }),
    };
    carol.send_unchecked(&g, &r).unwrap();
    alice.sync(0).unwrap();
    let m = alice.history(&g, 50).unwrap().into_iter().find(|m| m.id == text).unwrap();
    assert_eq!(m.reactions.get("❤"), Some(&vec![carol.member_id().to_hex()]));

    // Applied again: stickers work.
    alice.set_chat_feature(&g, "chat.stickers", true, None).unwrap();
    settle(&mut [&mut bob, &mut carol]);
    let sid2 = alice.send_sticker(&g, &pack.id, 1).unwrap();
    assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::Sticker { id, .. } if *id == sid2)));

    // Removing a pack forgets it and its images on this device only.
    bob.remove_sticker_pack(&pack.id).unwrap();
    assert!(bob.sticker_packs().unwrap().is_empty());
    assert_eq!(bob.sticker_image(&pack.id, 1).unwrap(), png(2), "a received sticker still opens with its key");
}

/// A place and a live location: updates at most every 30 s (newer
/// coordinates wait for the next sync), stop, expiry by each receiver's
/// clock, only the sender may move it, and `chat.location` on both sides.
#[test]
fn locations_and_live_locations() {
    let env = Env::new("location");
    let (mut alice, mut bob, carol, g) = chat(&env, true);
    let mut carol = carol.unwrap();

    let id = alice.send_location(&g, 37.5665, 126.978, Some(12), Some("시청")).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Location { id: i, live: false, .. } if *i == id)), "{ev:?}");
    let v = bob.location(&g, &id).unwrap().unwrap();
    assert!((v.lat - 37.5665).abs() < 1e-6 && (v.lon - 126.978).abs() < 1e-6);
    assert_eq!((v.accuracy_m, v.label.as_deref(), v.live, v.ended), (Some(12), Some("시청"), false, false));
    assert!(alice.send_location(&g, 91.0, 0.0, None, None).is_err());
    assert!(alice.start_live_location(&g, 1.0, 1.0, None, 60).is_err(), "15 min, 1 h or 8 h");
    carol.sync(0).unwrap();

    // Live for 15 minutes.
    let live = alice.start_live_location(&g, 37.0, 127.0, Some(5), 900).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    let v = bob.location(&g, &live).unwrap().unwrap();
    assert!(v.live && v.live_until.is_some() && !v.ended);
    // Within 30 s: kept, not sent.
    assert!(!alice.update_live_location(&g, &live, 37.1, 127.1, Some(5)).unwrap());
    assert!(!alice.update_live_location(&g, &live, 37.2, 127.2, Some(5)).unwrap(), "newer coordinates replace waiting ones");
    assert!(!bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::LocationUpdated { .. })));
    // Once the interval passed, the next sync sends the newest position.
    alice.set_live_interval_for_tests(1).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    alice.sync(0).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::LocationUpdated { stopped: false, .. })), "{ev:?}");
    assert!((bob.location(&g, &live).unwrap().unwrap().lat - 37.2).abs() < 1e-6);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(alice.update_live_location(&g, &live, 37.3, 127.3, None).unwrap(), "due: sent at once");
    bob.sync(0).unwrap();
    assert!((bob.location(&g, &live).unwrap().unwrap().lat - 37.3).abs() < 1e-6);

    // Only the sender moves it.
    carol.sync(0).unwrap();
    carol.send_unchecked(&g, &Payload::LiveLocation { id: live.clone(), lat_e7: 0, lon_e7: 0, accuracy_m: None, stop: false }).unwrap();
    assert!(dropped(&bob.sync(0).unwrap(), "not the sender's"));

    // Stop: the last position stays, no longer live; later updates dropped.
    alice.stop_live_location(&g, &live).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::LocationUpdated { stopped: true, .. })));
    let v = bob.location(&g, &live).unwrap().unwrap();
    assert!(!v.live && v.ended && (v.lat - 37.3).abs() < 1e-6);
    assert!(alice.update_live_location(&g, &live, 1.0, 1.0, None).is_err());
    alice.send_unchecked(&g, &Payload::LiveLocation { id: live.clone(), lat_e7: 1, lon_e7: 1, accuracy_m: None, stop: false }).unwrap();
    assert!(dropped(&bob.sync(0).unwrap(), "ended"));

    // Expiry by the receiver's own clock (a short live location, sent as
    // a modified client could).
    let short = LocationInfo { id: "5e0a".into(), lat_e7: 10, lon_e7: 20, accuracy_m: None, label: None, live_secs: Some(2) };
    alice.send_unchecked(&g, &Payload::Location(short)).unwrap();
    bob.sync(0).unwrap();
    assert!(bob.location(&g, "5e0a").unwrap().unwrap().live);
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let v = bob.location(&g, "5e0a").unwrap().unwrap();
    assert!(!v.live && v.ended, "an expired live location stops showing as live");
    alice.send_unchecked(&g, &Payload::LiveLocation { id: "5e0a".into(), lat_e7: 1, lon_e7: 1, accuracy_m: None, stop: false }).unwrap();
    assert!(dropped(&bob.sync(0).unwrap(), "ended"));
    let too_long = LocationInfo { id: "5e0b".into(), lat_e7: 0, lon_e7: 0, accuracy_m: None, label: None, live_secs: Some(9 * 3600) };
    alice.send_unchecked(&g, &Payload::Location(too_long)).unwrap();
    assert!(dropped(&bob.sync(0).unwrap(), "malformed location"));

    // Released: refused and dropped, a live location stops; applied again: works.
    let sharing = alice.start_live_location(&g, 2.0, 2.0, None, 3600).unwrap();
    settle(&mut [&mut bob, &mut carol]);
    alice.set_chat_feature(&g, "chat.location", false, None).unwrap();
    settle(&mut [&mut bob, &mut carol]);
    assert!(locked(alice.update_live_location(&g, &sharing, 3.0, 3.0, None)));
    assert!(alice.update_live_location(&g, &sharing, 3.0, 3.0, None).is_err(), "no longer shared");
    assert!(locked(alice.send_location(&g, 1.0, 1.0, None, None)));
    assert!(locked(alice.start_live_location(&g, 1.0, 1.0, None, 900)));
    let l = LocationInfo { id: "5e0c".into(), lat_e7: 0, lon_e7: 0, accuracy_m: None, label: None, live_secs: None };
    bob.send_unchecked(&g, &Payload::Location(l)).unwrap();
    assert!(dropped(&alice.sync(0).unwrap(), "chat.location"));
    assert!(dropped(&carol.sync(0).unwrap(), "chat.location"));
    alice.set_chat_feature(&g, "chat.location", true, None).unwrap();
    settle(&mut [&mut bob, &mut carol]);
    let id2 = alice.send_location(&g, 1.0, 2.0, None, None).unwrap();
    assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::Location { id, .. } if *id == id2)));
}

/// Events: every device keeps the same tally; only the creator edits or
/// cancels; `chat.events` on both sides.
#[test]
fn events_with_replies() {
    let env = Env::new("events");
    let (mut alice, mut bob, carol, g) = chat(&env, true);
    let mut carol = carol.unwrap();
    let draft = EventDraft {
        title: "봄 소풍".into(),
        starts_at: 1_900_000_000,
        ends_at: Some(1_900_007_200),
        place: Some("한강".into()),
        description: Some("도시락".into()),
    };
    assert!(alice.create_event(&g, &EventDraft { ends_at: Some(1), ..draft.clone() }).is_err(), "ends before it starts");
    let id = alice.create_event(&g, &draft).unwrap();
    assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::ChatEvent { title, .. } if title == "봄 소풍")));
    carol.sync(0).unwrap();

    bob.rsvp(&g, &id, "going").unwrap();
    carol.rsvp(&g, &id, "maybe").unwrap();
    alice.rsvp(&g, &id, "not").unwrap();
    assert!(bob.rsvp(&g, &id, "perhaps").is_err());
    for _ in 0..2 {
        settle(&mut [&mut alice, &mut bob, &mut carol]);
    }
    let (a, b, c) = (alice.member_id().to_hex(), bob.member_id().to_hex(), carol.member_id().to_hex());
    for s in [&mut alice, &mut bob, &mut carol] {
        let v = s.chat_event(&g, &id).unwrap().unwrap();
        assert_eq!((v.going.clone(), v.maybe.clone(), v.not.clone()), (vec![b.clone()], vec![c.clone()], vec![a.clone()]), "same tally on every device");
        assert_eq!((v.title.as_str(), v.place.as_deref(), v.creator.as_str()), ("봄 소풍", Some("한강"), a.as_str()));
    }
    // A new answer replaces the old one.
    carol.rsvp(&g, &id, "going").unwrap();
    alice.sync(0).unwrap();
    let v = alice.chat_event(&g, &id).unwrap().unwrap();
    assert_eq!((v.going.len(), v.maybe.len()), (2, 0));
    assert_eq!(carol.chat_event(&g, &id).unwrap().unwrap().mine.as_deref(), Some("going"));

    // Only the creator changes it.
    assert!(bob.edit_event(&g, &id, &EventDraft { title: "hijack".into(), ..draft.clone() }).is_err());
    let fake = EventInfo { id: id.clone(), title: "hijack".into(), starts_at: 1, ends_at: None, place: None, description: None };
    bob.send_unchecked(&g, &Payload::EventEdit { event: fake, cancelled: true }).unwrap();
    assert!(dropped(&alice.sync(0).unwrap(), "not the creator's"));
    alice.edit_event(&g, &id, &EventDraft { title: "봄 소풍 (변경)".into(), ..draft.clone() }).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::ChatEventChanged { cancelled: false, .. })));
    let v = bob.chat_event(&g, &id).unwrap().unwrap();
    assert!(v.edited && v.title == "봄 소풍 (변경)" && v.going.len() == 2, "answers survive an edit");
    alice.cancel_event(&g, &id).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert!(bob.chat_event(&g, &id).unwrap().unwrap().cancelled);
    assert!(bob.rsvp(&g, &id, "going").is_err(), "no answers to a cancelled event");

    // Released: refused and dropped (events and answers); applied again.
    let id2 = alice.create_event(&g, &draft).unwrap();
    settle(&mut [&mut bob, &mut carol]);
    alice.set_chat_feature(&g, "chat.events", false, None).unwrap();
    settle(&mut [&mut bob, &mut carol]);
    assert!(locked(alice.create_event(&g, &draft)));
    assert!(locked(bob.rsvp(&g, &id2, "going")));
    bob.send_unchecked(&g, &Payload::Rsvp { id: id2.clone(), answer: "going".into() }).unwrap();
    assert!(dropped(&alice.sync(0).unwrap(), "chat.events"));
    let e = EventInfo { id: "e0e0".into(), title: "x".into(), starts_at: 1, ends_at: None, place: None, description: None };
    bob.send_unchecked(&g, &Payload::ChatEvent(e)).unwrap();
    assert!(dropped(&carol.sync(0).unwrap(), "chat.events"));
    alice.sync(0).unwrap();
    alice.set_chat_feature(&g, "chat.events", true, None).unwrap();
    settle(&mut [&mut bob, &mut carol]);
    bob.rsvp(&g, &id2, "going").unwrap();
    alice.sync(0).unwrap();
    assert_eq!(alice.chat_event(&g, &id2).unwrap().unwrap().going, vec![b]);
}

/// Round video notes are video files flagged as notes; `chat.video_notes`
/// released stops them on both sides while other files still go.
#[test]
fn video_notes() {
    let env = Env::new("videonotes");
    let (mut alice, mut bob, _, g) = chat(&env, false);
    let f = alice.send_video_note(&g, b"\x00\x00\x00\x18ftypmp42 square", "video/mp4", 12_000).unwrap();
    assert!(f.video_note && f.duration_ms == Some(12_000) && !f.voice);
    let ev = bob.sync(0).unwrap();
    let got = ev.iter().find_map(|e| match e { Event::File { file, .. } => Some(file.clone()), _ => None }).unwrap();
    assert!(got.video_note);
    assert_eq!(bob.download(&got).unwrap(), b"\x00\x00\x00\x18ftypmp42 square");
    assert!(alice.send_video_note(&g, b"x", "video/mp4", 61_000).is_err(), "at most a minute");
    assert!(alice.send_video_note(&g, b"x", "image/png", 1000).is_err());

    alice.set_chat_feature(&g, "chat.video_notes", false, None).unwrap();
    bob.sync(0).unwrap();
    assert!(locked(alice.send_video_note(&g, b"x", "video/mp4", 1000)));
    let forged = tree_client::FileInfo { video_note: true, msg_id: "f00d".into(), ..got.clone() };
    bob.send_unchecked(&g, &Payload::File(forged)).unwrap();
    assert!(dropped(&alice.sync(0).unwrap(), "chat.video_notes"));
    alice.send_file(&g, b"plain file", "a.txt", "text/plain", false).unwrap();
    assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::File { .. })));
    alice.set_chat_feature(&g, "chat.video_notes", true, None).unwrap();
    bob.sync(0).unwrap();
    alice.send_video_note(&g, b"again", "video/mp4", 1000).unwrap();
    assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::File { file, .. } if file.video_note)));
}
