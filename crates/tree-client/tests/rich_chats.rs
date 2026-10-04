//! Wave 2 part A through a real server: pinned messages (`chat.pins`),
//! polls (`chat.polls`), scheduled messages, forwarding
//! (`chat.forwarding`), reminders, chat export (`chat.export`) and storage
//! clean-up (`user.storage_clean`). Every chat key is toggled, and every
//! receiving device is shown to drop what a released key forbids, sent by
//! a member whose device had not seen the release yet.

mod common;

use std::time::Duration;

use common::Env;
use tree_client::polls::PollOptions;
use tree_client::{Error, Event, Session};

fn sleep(s: u64) {
    std::thread::sleep(Duration::from_millis(s * 1000 + 100));
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn locked(r: Result<impl std::fmt::Debug, Error>) -> bool {
    matches!(r, Err(Error::Feature(c)) if c == "LOCKED_BY_CHAT")
}

fn dropped(ev: &[Event], why: &str) -> bool {
    ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains(why)))
}

/// alice (admin), bob and carol in one group, everyone synced.
fn trio(env: &Env) -> (Session, Session, Session, Vec<u8>) {
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut carol = env.device("carol");
    bob.confirm_contact(alice.account_id()).unwrap();
    carol.confirm_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    alice.invite(&g, carol.account_id()).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    bob.sync(0).unwrap();
    alice.sync(0).unwrap();
    (alice, bob, carol, g)
}

fn pinned_ids(s: &mut Session, g: &[u8]) -> Vec<String> {
    s.pins(g).unwrap().into_iter().map(|p| p.message_id).collect()
}

#[test]
fn pins_are_shared_expire_are_limited_and_follow_chat_pins() {
    let env = Env::new("pins");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    let m1 = alice.send_text(&g, "the plan").unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();

    // An admin pins; every device holds the same pin.
    assert!(alice.may_pin(&g).unwrap() && !bob.may_pin(&g).unwrap());
    alice.pin_message(&g, &m1, None).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Pinned { id, pinned: true, .. } if *id == m1)), "{ev:?}");
    carol.sync(0).unwrap();
    for s in [&mut alice, &mut bob, &mut carol] {
        let p = s.pins(&g).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].message_id.as_str(), p[0].text.as_deref(), p[0].until), (m1.as_str(), Some("the plan"), None));
    }
    // A member who is not an admin of a group cannot.
    assert!(matches!(bob.pin_message(&g, &m1, None), Err(Error::Feature(c)) if c == "NOT_ADMIN"));

    // An expiry is counted on each device from arrival; expired pins drop off.
    let m2 = alice.send_text(&g, "today only").unwrap();
    bob.sync(0).unwrap();
    // (One hour, crossed with each device's test clock, not the wall
    // clock: a one-second expiry raced slow test machines.)
    alice.pin_message(&g, &m2, Some(3600)).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap(); // (a device that syncs later keeps it that much longer)
    assert_eq!(pinned_ids(&mut bob, &g), vec![m2.clone(), m1.clone()], "newest first");
    for s in [&mut alice, &mut bob] {
        s.advance_clock_for_tests(3600 - 60);
    }
    assert_eq!(pinned_ids(&mut bob, &g), vec![m2.clone(), m1.clone()], "not yet expired");
    for s in [&mut alice, &mut bob] {
        s.advance_clock_for_tests(61);
    }
    assert_eq!(pinned_ids(&mut bob, &g), vec![m1.clone()]);
    assert_eq!(pinned_ids(&mut alice, &g), vec![m1.clone()]);
    assert_eq!(pinned_ids(&mut carol, &g), vec![m2.clone(), m1.clone()], "carol's clock has not moved");
    carol.advance_clock_for_tests(3601);
    assert_eq!(pinned_ids(&mut carol, &g), vec![m1.clone()]);
    assert!(alice.pin_message(&g, &m2, Some(0)).is_err(), "0 seconds is not an expiry");

    // At most ten pins.
    let mut ids = vec![m1.clone()];
    for i in 0..10 {
        let id = alice.send_text(&g, &format!("note {i}")).unwrap();
        if i < 9 {
            alice.pin_message(&g, &id, Some(7 * 86400)).unwrap();
            ids.push(id);
        } else {
            assert!(matches!(alice.pin_message(&g, &id, None), Err(Error::Usage(_))), "an eleventh is refused");
        }
    }
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert_eq!(bob.pins(&g).unwrap().len(), 10);
    // Unpin, everywhere.
    alice.unpin_message(&g, &m1).unwrap();
    assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::Pinned { pinned: false, .. })));
    carol.sync(0).unwrap();
    assert!(!pinned_ids(&mut bob, &g).contains(&m1));
    assert_eq!(pinned_ids(&mut bob, &g), pinned_ids(&mut carol, &g));

    // Released: nobody pins, stored pins are not shown; applied again they are.
    alice.set_chat_feature(&g, "chat.pins", false, None).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert!(locked(alice.pin_message(&g, &m1, None)));
    assert!(bob.pins(&g).unwrap().is_empty() && !alice.may_pin(&g).unwrap());
    alice.set_chat_feature(&g, "chat.pins", true, None).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert_eq!(bob.pins(&g).unwrap().len(), 9);

    // Receivers drop a pin the settings forbid: bob, made admin, pins
    // before his device saw the release; carol's device drops it.
    alice.make_admin(&g, bob.member_id(), true).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    alice.set_chat_feature(&g, "chat.pins", false, None).unwrap();
    carol.sync(0).unwrap();
    bob.unpin_message(&g, &ids[1]).unwrap(); // bob has not synced
    let ev = carol.sync(0).unwrap();
    assert!(dropped(&ev, "chat.pins"), "{ev:?}");
    assert!(!ev.iter().any(|e| matches!(e, Event::Pinned { .. })));
    bob.sync(0).unwrap();
    alice.set_chat_feature(&g, "chat.pins", true, None).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert!(pinned_ids(&mut carol, &g).contains(&ids[1]), "the dropped unpin changed nothing");
    // ... and a pin by a member who is no longer an admin.
    alice.make_admin(&g, bob.member_id(), false).unwrap();
    carol.sync(0).unwrap();
    bob.pin_message(&g, &m1, None).unwrap(); // bob still thinks he is an admin
    let ev = carol.sync(0).unwrap();
    assert!(dropped(&ev, "only admins pin"), "{ev:?}");
    assert!(!pinned_ids(&mut carol, &g).contains(&m1));

    // In a 1:1 chat either person pins.
    let mut dave = env.device("dave");
    dave.confirm_contact(alice.account_id()).unwrap();
    let d = alice.create_group().unwrap();
    alice.invite(&d, dave.account_id()).unwrap();
    dave.sync(0).unwrap();
    let hi = alice.send_text(&d, "hi dave").unwrap();
    dave.sync(0).unwrap();
    assert!(dave.may_pin(&d).unwrap());
    dave.pin_message(&d, &hi, Some(86400)).unwrap();
    alice.sync(0).unwrap();
    assert_eq!(pinned_ids(&mut alice, &d), vec![hi]);
}

#[test]
fn polls_count_votes_close_and_follow_chat_polls() {
    let env = Env::new("polls");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    let opts = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert!(alice.create_poll(&g, "Where?", &opts(&["only one"]), &PollOptions::default()).is_err(), "two options at least");
    let p = alice.create_poll(&g, "Where?", &opts(&["park", "cafe", "home"]), &PollOptions::default()).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Poll { id, question, .. } if *id == p && question == "Where?")), "{ev:?}");
    carol.sync(0).unwrap();
    assert_eq!(bob.history(&g, 5).unwrap().last().unwrap().kind, "poll");

    bob.vote(&g, &p, &[0]).unwrap();
    carol.vote(&g, &p, &[1]).unwrap();
    assert!(alice.sync(0).unwrap().iter().any(|e| matches!(e, Event::PollUpdated { .. })));
    let v = alice.poll(&g, &p).unwrap().unwrap();
    assert_eq!((v.counts.clone(), v.voters), (vec![1, 1, 0], 2));
    assert_eq!(v.voters_by_option[0], vec![bob.member_id()], "not anonymous: who voted is shown");
    // One vote state per member: the latest wins; empty takes it back.
    assert!(bob.vote(&g, &p, &[0, 1]).is_err(), "single choice");
    bob.vote(&g, &p, &[1]).unwrap();
    alice.sync(0).unwrap();
    assert_eq!(alice.poll(&g, &p).unwrap().unwrap().counts, vec![0, 2, 0]);
    bob.retract_vote(&g, &p).unwrap();
    alice.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert_eq!(alice.poll(&g, &p).unwrap().unwrap().counts, vec![0, 1, 0]);
    assert_eq!(carol.poll(&g, &p).unwrap().unwrap().counts, vec![0, 1, 0], "every device counts the same");
    assert_eq!(carol.poll(&g, &p).unwrap().unwrap().mine, vec![1]);

    // Only the creator closes; no votes after.
    assert!(bob.close_poll(&g, &p).is_err());
    alice.close_poll(&g, &p).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    assert!(bob.poll(&g, &p).unwrap().unwrap().closed);
    assert!(bob.vote(&g, &p, &[2]).is_err());

    // Anonymous and multiple choice: counts, but no names.
    let o = PollOptions { multi: true, anonymous: true, close_in: Some(2) };
    let q = alice.create_poll(&g, "Snacks?", &opts(&["a", "b", "c"]), &o).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    bob.vote(&g, &q, &[0, 2]).unwrap();
    alice.sync(0).unwrap();
    let v = alice.poll(&g, &q).unwrap().unwrap();
    assert_eq!(v.counts, vec![1, 0, 1]);
    assert!(v.anonymous && v.voters_by_option.iter().all(Vec::is_empty));
    // Closes by itself after its time.
    sleep(3);
    assert!(carol.poll(&g, &q).unwrap().unwrap().closed);
    assert!(carol.vote(&g, &q, &[1]).is_err());

    // A poll for the receivers to drop: open, then released.
    let r = alice.create_poll(&g, "Again?", &opts(&["yes", "no"]), &PollOptions::default()).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    alice.set_chat_feature(&g, "chat.polls", false, None).unwrap();
    carol.sync(0).unwrap();
    assert!(locked(alice.create_poll(&g, "x?", &opts(&["a", "b"]), &PollOptions::default())));
    assert!(locked(carol.vote(&g, &r, &[0])));
    // bob's device has not seen the release: it sends; carol's drops both.
    bob.vote(&g, &r, &[0]).unwrap();
    bob.create_poll(&g, "Sneaky?", &opts(&["a", "b"]), &PollOptions::default()).unwrap();
    let ev = carol.sync(0).unwrap();
    assert_eq!(ev.iter().filter(|e| matches!(e, Event::Dropped { reason } if reason.contains("chat.polls"))).count(), 2, "{ev:?}");
    assert!(!ev.iter().any(|e| matches!(e, Event::Poll { .. } | Event::PollUpdated { .. })));
    assert_eq!(carol.poll(&g, &r).unwrap().unwrap().voters, 0);
    // Applied again: polls work.
    bob.sync(0).unwrap();
    assert!(dropped(&alice.sync(0).unwrap(), "chat.polls"));
    alice.set_chat_feature(&g, "chat.polls", true, None).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    carol.vote(&g, &r, &[1]).unwrap();
    alice.sync(0).unwrap();
    assert_eq!(alice.poll(&g, &r).unwrap().unwrap().counts, vec![0, 1]);
}

#[test]
fn scheduled_messages_wait_on_the_device() {
    let env = Env::new("sched");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.confirm_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();

    assert!(alice.schedule_text(&g, "too late", now() - 5, false).is_err(), "the past is refused");
    assert!(alice.schedule_text(&g, "far", now() + 400 * 86400, false).is_err(), "at most a year ahead");
    let a = alice.schedule_text(&g, "first draft 9f1c", now() + 3600, false).unwrap();
    let b = alice.schedule_text(&g, "never sent 5e7d", now() + 7200, false).unwrap();
    assert_eq!(alice.scheduled(Some(&g)).unwrap().iter().map(|s| s.id.clone()).collect::<Vec<_>>(), vec![a.clone(), b.clone()]);
    // Edit text and time, cancel the other.
    alice.edit_scheduled(&a, Some("scheduled hello 9f1c"), Some(now() + 2)).unwrap();
    alice.cancel_scheduled(&b).unwrap();
    assert_eq!(alice.scheduled(None).unwrap().len(), 1);
    alice.set_draft(&g, "typing something").unwrap();
    // Not before its time: nothing in the history, nothing for bob.
    alice.sync(0).unwrap();
    assert!(alice.history(&g, 10).unwrap().iter().all(|m| m.text.as_deref() != Some("scheduled hello 9f1c")));
    assert!(!bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::Text { .. })));
    sleep(3);
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Sent { id: Some(_), .. })), "{ev:?}");
    assert!(alice.scheduled(None).unwrap().is_empty());
    assert_eq!(alice.draft(&g).unwrap().as_deref(), Some("typing something"), "the draft stays");
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Text { text, .. } if text == "scheduled hello 9f1c")), "{ev:?}");

    // One that cannot go when it is due (bob was removed meanwhile) fails then.
    let c = bob.schedule_text(&g, "left behind", now() + 2, false).unwrap();
    alice.remove(&g, &[bob.member_id()]).unwrap();
    sleep(3);
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::SendFailed { local_id, .. } if *local_id == c)), "{ev:?}");
    assert!(bob.scheduled(None).unwrap().is_empty());

    // The server never held the scheduled text in plaintext.
    drop((alice, bob));
    let raw = std::fs::read(&env.db).unwrap();
    for needle in ["9f1c", "5e7d"] {
        assert!(!raw.windows(needle.len()).any(|w| w == needle.as_bytes()), "server stored {needle:?}");
    }
}

#[test]
fn forwarding_marks_and_follows_chat_forwarding() {
    let env = Env::new("forward");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.confirm_contact(alice.account_id()).unwrap();
    let a = alice.create_group().unwrap();
    let b = alice.create_group().unwrap();
    alice.invite(&a, bob.account_id()).unwrap();
    alice.invite(&b, bob.account_id()).unwrap();
    bob.sync(0).unwrap();

    // bob's text in chat A, forwarded by alice to chat B: marked, no original sender.
    let t = bob.send_text(&a, "worth sharing").unwrap();
    alice.sync(0).unwrap();
    assert!(alice.forwarding_allowed(&a).unwrap());
    let f = alice.forward(&a, &t, &b).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Text { group, text, .. } if *group == b && text == "worth sharing")), "{ev:?}");
    let got = bob.history(&b, 5).unwrap().into_iter().find(|m| m.id == f).unwrap();
    assert!(tree_client::forward::is_forwarded(&got));
    assert_eq!(got.sender, alice.member_id().to_hex(), "shown as alice's forward, bob not named");
    assert!(!tree_client::forward::is_forwarded(&bob.history(&a, 5).unwrap().into_iter().find(|m| m.id == t).unwrap()));

    // A file reference: the same encrypted file, opened in the other chat.
    let file = alice.send_file(&a, b"report body", "report.txt", "text/plain", false).unwrap();
    bob.sync(0).unwrap();
    bob.forward(&a, &file.msg_id, &b).unwrap();
    let ev = alice.sync(0).unwrap();
    let got = ev.iter().find_map(|e| match e { Event::File { group, file, .. } if *group == b => Some(file.clone()), _ => None }).unwrap();
    assert!(got.fwd && got.msg_id != file.msg_id);
    assert_eq!(alice.download(&got).unwrap(), b"report body");
    // View-once files are not forwarded.
    let once = alice.send_file(&a, b"secret", "once.txt", "text/plain", true).unwrap();
    bob.sync(0).unwrap();
    assert!(bob.forward(&a, &once.msg_id, &b).is_err());

    // Released in chat A: refused for its messages (bob too), still fine for B's.
    alice.set_chat_feature(&a, "chat.forwarding", false, None).unwrap();
    bob.sync(0).unwrap();
    assert!(!bob.forwarding_allowed(&a).unwrap());
    assert!(locked(bob.forward(&a, &t, &b)));
    assert!(locked(alice.forward(&a, &t, &b)));
    assert!(bob.forward(&b, &f, &a).is_ok(), "chat B allows it");
    alice.set_chat_feature(&a, "chat.forwarding", true, None).unwrap();
    bob.sync(0).unwrap();
    assert!(bob.forward(&a, &t, &b).is_ok());
}

#[test]
fn export_follows_chat_export() {
    let env = Env::new("export");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.confirm_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.send_text(&g, "line one").unwrap();
    bob.sync(0).unwrap();
    bob.send_text(&g, "line two").unwrap();
    alice.sync(0).unwrap();

    let e = bob.export_chat(&g).unwrap();
    assert!(e.text.contains("alice: line one") && e.text.contains("me: line two"), "{}", e.text);
    let j: serde_json::Value = serde_json::from_str(&e.json).unwrap();
    assert_eq!(j["format"], "tree-chat-export/1");
    assert_eq!(j["messages"].as_array().unwrap().len(), 2);
    assert!(!e.json.contains("franking") && !e.json.contains("\"tag\""));
    let prefix = env.dir.join("export").display().to_string();
    let (t, js) = bob.export_chat_to(&g, &prefix).unwrap();
    assert!(std::fs::read_to_string(t).unwrap().contains("line one"));
    assert!(std::fs::read_to_string(js).unwrap().contains("line two"));

    alice.set_chat_feature(&g, "chat.export", false, None).unwrap();
    bob.sync(0).unwrap();
    assert!(!bob.export_allowed(&g).unwrap());
    assert!(locked(bob.export_chat(&g)));
    assert!(locked(alice.export_chat(&g)));
    alice.set_chat_feature(&g, "chat.export", true, None).unwrap();
    bob.sync(0).unwrap();
    assert!(bob.export_chat(&g).is_ok());
}

#[test]
fn reminders_are_local_and_fire_once() {
    let env = Env::new("remind");
    let mut alice = env.device("alice");
    let g = alice.create_group().unwrap();
    let m = alice.send_text(&g, "call the bank").unwrap();
    assert!(alice.remind_me(&g, &m, now() - 1).is_err());
    assert!(alice.remind_me(&g, "nope", now() + 60).is_err());
    // A few seconds ahead, so a slow machine still checks before it is due.
    let r = alice.remind_me(&g, &m, now() + 4).unwrap();
    let later = alice.remind_me(&g, &m, now() + 3600).unwrap();
    assert!(alice.due_reminders().unwrap().is_empty());
    assert_eq!(alice.reminders().unwrap().len(), 2);
    alice.cancel_reminder(&later).unwrap();
    sleep(5);
    let due = alice.due_reminders().unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!((due[0].id.as_str(), due[0].text.as_deref()), (r.as_str(), Some("call the bank")));
    assert!(alice.due_reminders().unwrap().is_empty(), "each fires once");
    assert!(alice.reminders().unwrap().is_empty());
}

#[test]
fn storage_clean_deletes_old_media_only_while_applied() {
    let env = Env::new("clean");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.confirm_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.send_file(&g, b"holiday photo", "photo.jpg", "image/jpeg", false).unwrap();
    let ev = bob.sync(0).unwrap();
    let f = ev.iter().find_map(|e| match e { Event::File { file, .. } => Some(file.clone()), _ => None }).unwrap();
    let dir = env.dir.join("bob-media").display().to_string();
    let path = bob.download_to_cache(&f, &dir).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"holiday photo");

    // Released (the default): nothing is deleted.
    assert_eq!(bob.feature("user.storage_clean").unwrap().state, tree_core::features::State::Released);
    sleep(2);
    bob.sync(0).unwrap();
    assert!(std::path::Path::new(&path).exists());
    assert!(matches!(bob.clean_storage(), Err(Error::Feature(_))));
    assert!(matches!(bob.apply_feature("user.storage_clean", Some("1y".into())), Err(Error::InvalidOption(_))));

    // Applied with a period the file is older than: the next sync deletes
    // it, the message stays, and it can be downloaded again.
    bob.apply_feature("user.storage_clean", Some("1".into())).unwrap();
    bob.sync(0).unwrap();
    assert!(!std::path::Path::new(&path).exists());
    assert!(bob.cached_media().unwrap().is_empty());
    assert_eq!(bob.history(&g, 5).unwrap().last().unwrap().text.as_deref(), Some("photo.jpg"));
    let again = bob.download_to_cache(&f, &dir).unwrap();
    // 90 days: a fresh file stays.
    bob.apply_feature("user.storage_clean", Some("90d".into())).unwrap();
    assert_eq!(bob.clean_storage().unwrap().files, 0);
    assert!(std::path::Path::new(&again).exists());
    bob.apply_feature("user.storage_clean", Some("1".into())).unwrap();
    sleep(2);
    let r = bob.clean_storage().unwrap();
    assert_eq!((r.files, r.bytes), (1, 13));
    assert!(!std::path::Path::new(&again).exists());
    bob.release_feature("user.storage_clean").unwrap();
    assert!(bob.clean_storage().is_err());
}

/// F-029: the media cache is keyed by attachment id and content hash and
/// checked on read: a reference with the same id but other content never
/// gets the cached file, and a changed file on disk is fetched again.
#[test]
fn the_media_cache_is_bound_to_the_content() {
    let env = Env::new("cachebind");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.confirm_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.send_file(&g, b"the real photo", "photo.jpg", "image/jpeg", false).unwrap();
    let ev = bob.sync(0).unwrap();
    let f = ev.iter().find_map(|e| match e { Event::File { file, .. } => Some(file.clone()), _ => None }).unwrap();
    let dir = env.dir.join("bob-media").display().to_string();
    let path = bob.download_to_cache(&f, &dir).unwrap();
    // Same id, other content claimed: not the cached file.
    let other = tree_client::FileInfo { pt_sha256: "00".repeat(32), ..f.clone() };
    assert!(bob.download_to_cache(&other, &dir).is_err(), "the cached file is not handed out for another hash");
    // Changed on disk: fetched again and checked.
    std::fs::write(&path, b"swapped on disk").unwrap();
    let again = bob.download_to_cache(&f, &dir).unwrap();
    assert_eq!(std::fs::read(&again).unwrap(), b"the real photo");
}

#[test]
fn new_keys_are_in_the_registry() {
    use tree_core::features::{option_choices, Registry, Scope, State};
    let r = Registry::standard();
    for k in ["chat.pins", "chat.polls", "chat.forwarding", "chat.export"] {
        let s = r.status(k).unwrap();
        assert_eq!(s.state, State::Applied, "{k}");
        assert!(r.list(Scope::Chat).iter().any(|x| x.key == k));
    }
    assert_eq!(r.status("user.storage_clean").unwrap().state, State::Released);
    assert_eq!(option_choices("user.storage_clean"), vec!["30d", "90d", "365d"]);
}
