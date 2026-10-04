//! Profile photos (`user.profile_photo_visibility`) and per-chat profiles
//! (`user.per_chat_profile`, `chat.allow_per_chat_profiles`) through a
//! real server.

mod common;

use common::Env;
use tree_client::{Error, Event, MemberId, Payload, Session};

fn photo_event(ev: &[Event]) -> Option<bool> {
    ev.iter().find_map(|e| match e {
        Event::ProfilePhoto { removed, .. } => Some(*removed),
        _ => None,
    })
}

fn name_of(s: &mut Session, g: &[u8], m: MemberId) -> Option<String> {
    s.members(g).unwrap().into_iter().find(|x| x.id == m).and_then(|x| x.name)
}

/// The photo goes, encrypted, to the chats the setting allows; a contact
/// chat gets it with `contacts`, a chat with a stranger does not; `nobody`
/// and removing the photo take it back; members added later get it.
#[test]
fn profile_photos_follow_visibility_and_removal() {
    let env = Env::new("photos");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut dave = env.device("dave");
    let mut carol = env.device("carol");
    // g: alice invited bob (her contact). g2: bob's chat with alice and dave
    // (dave is a stranger to alice).
    bob.confirm_contact(alice.account_id()).unwrap();
    alice.confirm_contact(bob.account_id()).unwrap();
    dave.confirm_contact(bob.account_id()).unwrap();
    carol.confirm_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    let g2 = bob.create_group().unwrap();
    bob.invite(&g2, alice.account_id()).unwrap();
    bob.invite(&g2, dave.account_id()).unwrap();
    for _ in 0..2 {
        for s in [&mut alice, &mut dave, &mut bob] {
            s.sync(0).unwrap();
        }
    }
    let me = alice.member_id();
    let pic = b"\x89PNG\r\n\x1a\nalice photo 51c".to_vec();

    // Contacts only: g gets it, g2 (with dave) does not.
    alice.apply_feature("user.profile_photo_visibility", Some("contacts".into())).unwrap();
    assert!(matches!(alice.apply_feature("user.profile_photo_visibility", Some("friends".into())), Err(Error::InvalidOption(_))));
    assert!(alice.set_profile_photo(b"not an image", "text/plain").is_err());
    alice.set_profile_photo(&pic, "image/png").unwrap();
    assert_eq!(photo_event(&bob.sync(0).unwrap()), Some(false));
    let got = bob.member_photo(&g, &me).unwrap().unwrap();
    assert_eq!((got.bytes.as_slice(), got.mime.as_str()), (pic.as_slice(), "image/png"));
    assert_eq!(bob.member_photo(&g, &me).unwrap().unwrap().bytes, pic, "cached");
    assert_eq!(photo_event(&dave.sync(0).unwrap()), None);
    assert!(dave.member_photo(&g2, &me).unwrap().is_none());
    assert!(bob.member_photo(&g2, &me).unwrap().is_none(), "photos are per chat");
    // The server holds ciphertext only.
    for f in std::fs::read_dir(env.dir.join("attachments")).unwrap() {
        let b = std::fs::read(f.unwrap().path()).unwrap();
        assert!(!b.windows(pic.len()).any(|w| w == pic.as_slice()));
    }

    // Everyone in my chats: g2 gets it on the next sync.
    alice.apply_feature("user.profile_photo_visibility", Some("chats".into())).unwrap();
    alice.sync(0).unwrap();
    assert_eq!(photo_event(&dave.sync(0).unwrap()), Some(false));
    assert_eq!(dave.member_photo(&g2, &me).unwrap().unwrap().bytes, pic);
    bob.sync(0).unwrap();

    // A member added later gets it too.
    alice.invite(&g, carol.account_id()).unwrap();
    carol.sync(0).unwrap();
    alice.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert_eq!(carol.member_photo(&g, &me).unwrap().map(|p| p.bytes), Some(pic.clone()));
    bob.sync(0).unwrap();

    // Nobody (the option, or released): every chat is told it is gone.
    alice.apply_feature("user.profile_photo_visibility", Some("nobody".into())).unwrap();
    alice.sync(0).unwrap();
    assert_eq!(photo_event(&bob.sync(0).unwrap()), Some(true));
    assert_eq!(photo_event(&dave.sync(0).unwrap()), Some(true));
    assert!(bob.member_photo(&g, &me).unwrap().is_none() && dave.member_photo(&g2, &me).unwrap().is_none());
    alice.apply_feature("user.profile_photo_visibility", None).unwrap();
    alice.sync(0).unwrap();
    assert_eq!(photo_event(&bob.sync(0).unwrap()), Some(false), "default: everyone in my chats");
    alice.release_feature("user.profile_photo_visibility").unwrap();
    alice.sync(0).unwrap();
    assert_eq!(photo_event(&bob.sync(0).unwrap()), Some(true));
    alice.apply_feature("user.profile_photo_visibility", None).unwrap();
    alice.sync(0).unwrap();
    bob.sync(0).unwrap();
    dave.sync(0).unwrap();
    assert!(bob.member_photo(&g, &me).unwrap().is_some());

    // Removing the photo propagates.
    alice.remove_profile_photo().unwrap();
    assert!(alice.profile_photo().unwrap().is_none());
    assert_eq!(photo_event(&bob.sync(0).unwrap()), Some(true));
    assert_eq!(photo_event(&dave.sync(0).unwrap()), Some(true));
    assert!(bob.member_photo(&g, &me).unwrap().is_none());
    // Nothing more to send once everything matches.
    alice.sync(0).unwrap();
    assert_eq!(photo_event(&bob.sync(0).unwrap()), None);
}

/// A name and photo for one chat only: needs `user.per_chat_profile`;
/// the chat's `chat.allow_per_chat_profiles` released brings the main
/// name back and receivers ignore per-chat profiles.
#[test]
fn per_chat_profiles() {
    let env = Env::new("perchat");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.confirm_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    let g2 = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    alice.invite(&g2, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.sync(0).unwrap();
    bob.sync(0).unwrap();
    let me = alice.member_id();
    assert_eq!(name_of(&mut bob, &g, me).as_deref(), Some("alice"));

    // Released by default.
    assert!(matches!(alice.set_chat_profile(&g, Some("x"), None), Err(Error::Feature(c)) if c == "RELEASED"));
    alice.apply_feature("user.per_chat_profile", None).unwrap();
    let work = b"\x89PNG\r\n\x1a\nwork photo".to_vec();
    let main = b"\x89PNG\r\n\x1a\nmain photo".to_vec();
    alice.set_profile_photo(&main, "image/png").unwrap();
    alice.set_chat_profile(&g, Some("Alice (work)"), Some((&work, "image/png"))).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Profile { name, .. } if name == "Alice (work)")), "{ev:?}");
    assert_eq!(name_of(&mut bob, &g, me).as_deref(), Some("Alice (work)"));
    assert_eq!(name_of(&mut bob, &g2, me).as_deref(), Some("alice"), "only in that chat");
    assert_eq!(bob.member_photo(&g, &me).unwrap().unwrap().bytes, work);
    assert_eq!(bob.member_photo(&g2, &me).unwrap().unwrap().bytes, main);
    assert_eq!(alice.chat_profile(&g).unwrap().unwrap().name.as_deref(), Some("Alice (work)"));
    assert_eq!(alice.member_photo(&g, &me).unwrap().unwrap().bytes, work);

    // Back to the main profile by hand.
    alice.clear_chat_profile(&g).unwrap();
    bob.sync(0).unwrap();
    assert_eq!(name_of(&mut bob, &g, me).as_deref(), Some("alice"));
    assert_eq!(bob.member_photo(&g, &me).unwrap().unwrap().bytes, main);

    // The admin releases per-chat profiles in g: refused, the device goes
    // back to its main name, receivers ignore per-chat ones.
    alice.set_chat_profile(&g, Some("Alice (work)"), None).unwrap();
    bob.sync(0).unwrap();
    alice.set_chat_feature(&g, "chat.allow_per_chat_profiles", false, None).unwrap();
    alice.sync(0).unwrap();
    bob.sync(0).unwrap();
    assert_eq!(name_of(&mut bob, &g, me).as_deref(), Some("alice"), "reverted by alice's device");
    assert!(alice.chat_profile(&g).unwrap().is_none());
    assert!(matches!(alice.set_chat_profile(&g, Some("x"), None), Err(Error::Feature(c)) if c == "LOCKED_BY_CHAT"));
    alice.send_unchecked(&g, &Payload::Profile { name: "sneaky".into(), chat: true }).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains("chat.allow_per_chat_profiles"))));
    assert_eq!(name_of(&mut bob, &g, me).as_deref(), Some("alice"));
    alice.send_unchecked(&g, &Payload::ProfilePhoto { photo: None, mime: None, chat: true }).unwrap();
    assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains("per-chat photos"))));
    assert!(bob.member_photo(&g, &me).unwrap().is_some(), "the main photo stays");

    // Applied again in the chat; the user's own switch released reverts too.
    alice.set_chat_feature(&g, "chat.allow_per_chat_profiles", true, None).unwrap();
    bob.sync(0).unwrap();
    alice.set_chat_profile(&g, Some("Alice (work)"), None).unwrap();
    bob.sync(0).unwrap();
    assert_eq!(name_of(&mut bob, &g, me).as_deref(), Some("Alice (work)"));
    alice.release_feature("user.per_chat_profile").unwrap();
    alice.sync(0).unwrap();
    bob.sync(0).unwrap();
    assert_eq!(name_of(&mut bob, &g, me).as_deref(), Some("alice"));
}
