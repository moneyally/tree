//! chat.formatting, chat.mention_all, chat.voice, chat.screenshot_block,
//! enforced on both sides.

mod common;

use common::Env;
use tree_client::{Error, Event, TextOptions};

/// The last text in a sync.
fn text(ev: &[Event]) -> Option<(bool, bool)> {
    ev.iter().rev().find_map(|e| match e {
        Event::Text { formatted, mentions_me, .. } => Some((*formatted, *mentions_me)),
        _ => None,
    })
}

#[test]
fn formatting_mentions_voice_screenshots() {
    let env = Env::new("chatfeat");
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
    bob.sync(0).unwrap();

    // Formatting: shown while applied; plain once the admins release it.
    let fmt = TextOptions { formatted: true, ..Default::default() };
    alice.send_text_with(&g, "**bold**", &fmt).unwrap();
    assert_eq!(text(&bob.sync(0).unwrap()), Some((true, false)));
    alice.set_chat_feature(&g, "chat.formatting", false, None).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    alice.send_text_with(&g, "**bold**", &fmt).unwrap();
    assert_eq!(text(&bob.sync(0).unwrap()), Some((false, false)), "the sender drops it");

    // Mentions: only the mentioned member is told.
    let m = TextOptions { mentions: vec![carol.member_id()], ..Default::default() };
    alice.send_text_with(&g, "carol?", &m).unwrap();
    assert_eq!(text(&bob.sync(0).unwrap()), Some((false, false)));
    assert_eq!(text(&carol.sync(0).unwrap()), Some((false, true)));
    let too_many = TextOptions { mentions: vec![carol.member_id(); 51], ..Default::default() };
    assert!(matches!(alice.send_text_with(&g, "x", &too_many), Err(Error::Usage(_))));

    // @all: admins only by default.
    let all = TextOptions { all: true, ..Default::default() };
    alice.send_text_with(&g, "everyone!", &all).unwrap();
    assert_eq!(text(&bob.sync(0).unwrap()), Some((false, true)));
    carol.sync(0).unwrap();
    assert!(matches!(bob.send_text_with(&g, "everyone!", &all), Err(Error::Feature(c)) if c == "LOCKED_BY_CHAT"));
    alice.set_chat_feature(&g, "chat.mention_all", true, Some("all".into())).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    bob.send_text_with(&g, "everyone, from bob", &all).unwrap();
    assert_eq!(text(&carol.sync(0).unwrap()), Some((false, true)));
    alice.sync(0).unwrap();
    alice.set_chat_feature(&g, "chat.mention_all", false, None).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert!(alice.send_text_with(&g, "x", &all).is_err(), "released: nobody, admins included");

    // Voice messages.
    let v = alice.send_voice(&g, b"OggS fake audio", "audio/ogg", 3200).unwrap();
    assert!(v.voice && v.duration_ms == Some(3200));
    let ev = bob.sync(0).unwrap();
    let got = ev.iter().find_map(|e| match e { Event::File { file, .. } => Some(file.clone()), _ => None }).unwrap();
    assert_eq!((got.voice, got.duration_ms), (true, Some(3200)));
    assert_eq!(bob.download(&got).unwrap(), b"OggS fake audio");
    carol.sync(0).unwrap();
    alice.set_chat_feature(&g, "chat.voice", false, None).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert!(matches!(alice.send_voice(&g, b"x", "audio/ogg", 1), Err(Error::Feature(c)) if c == "LOCKED_BY_CHAT"));
    alice.send_file(&g, b"a normal file", "a.txt", "text/plain", false).unwrap();
    assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::File { .. })), "other files still go");

    // Screenshot block: per user, or for everyone by the admins.
    assert!(!bob.screenshot_blocked(&g).unwrap());
    bob.set_screenshot_block(&g, true).unwrap();
    assert!(bob.screenshot_blocked(&g).unwrap());
    assert!(!carol.screenshot_blocked(&g).unwrap(), "bob's choice is his own");
    bob.set_screenshot_block(&g, false).unwrap();
    alice.set_chat_feature(&g, "chat.screenshot_block", true, None).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert!(bob.screenshot_blocked(&g).unwrap() && carol.screenshot_blocked(&g).unwrap());
}
