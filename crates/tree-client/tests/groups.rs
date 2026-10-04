//! Wave 3 (groups and communities) through a real server: topics, roles
//! and their permissions, adds by permission, the admin log, the welcome
//! text, history for new members, the next admin, join approval, slow
//! mode, restricted members and communities. Every chat key is toggled
//! both ways, and for every permission a member whose own checks are
//! bypassed (`send_unchecked`: what a modified client sends) is shown to be
//! refused by the honest receivers, which judge by the MLS-authenticated
//! sender.

mod common;

use std::time::Duration;

use common::Env;
use tree_client::payload::{Payload, SharedMsg};
use tree_client::{CommitOutcome, Error, Event, GroupStatus, MemberId, Session, TextOptions};

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn code(r: Result<impl std::fmt::Debug, Error>, want: &str) -> bool {
    matches!(r, Err(Error::Feature(c)) if c == want)
}

fn dropped(ev: &[Event], why: &str) -> bool {
    ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains(why)))
}

fn text(id: &str, t: &str, topic: Option<&str>) -> Payload {
    Payload::Text { id: id.into(), text: t.into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: false, topic: topic.map(str::to_string) }
}

fn fresh_id() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).unwrap();
    hex::encode(b)
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
    sync_all(&mut [&mut bob, &mut carol, &mut alice]);
    (alice, bob, carol, g)
}

fn sync_all(s: &mut [&mut Session]) {
    for _ in 0..2 {
        for x in s.iter_mut() {
            x.sync(0).unwrap();
        }
    }
}

fn set(s: &mut Session, g: &[u8], key: &str, on: bool, option: Option<&str>) {
    let o = s.set_chat_feature(g, key, on, option.map(str::to_string)).unwrap();
    assert!(matches!(o, CommitOutcome::Accepted { .. }), "{key}: {o:?}");
}

fn has_text(s: &Session, g: &[u8], t: &str) -> bool {
    s.history(g, 500).unwrap().iter().any(|m| m.text.as_deref() == Some(t) && !m.deleted)
}

/// A new device of a new account, added to `g` by `by`.
fn join(env: &Env, by: &mut Session, g: &[u8], name: &str) -> (Session, Vec<Event>) {
    let mut d = env.device(name);
    d.confirm_contact(by.account_id()).unwrap();
    by.invite(g, d.account_id()).unwrap();
    let ev = d.sync(0).unwrap();
    (d, ev)
}

#[test]
fn topics_hold_threads_with_unread_counts_and_follow_chat_topics() {
    let env = Env::new("topics");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    // Released by default: no topics.
    assert!(code(alice.create_topic(&g, "x"), "LOCKED_BY_CHAT"));
    set(&mut alice, &g, "chat.topics", true, None);
    sync_all(&mut [&mut bob, &mut carol]);
    let plans = alice.create_topic(&g, "일정").unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::TopicChanged { id, .. } if *id == plans)), "{ev:?}");
    carol.sync(0).unwrap();
    assert_eq!(bob.topics(&g).unwrap().iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), vec!["일정"]);
    // Members do not create topics (option `admins`) ...
    assert!(code(bob.create_topic(&g, "mine"), "NOT_ADMIN"));
    assert!(!bob.may_create_topics(&g).unwrap() && alice.may_manage_topics(&g).unwrap());
    // ... and a modified client's topic is dropped by every honest device.
    bob.send_unchecked(&g, &Payload::Topic { id: "f00d".into(), name: Some("spam".into()), closed: None }).unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(dropped(&ev, "create topics"), "{ev:?}");
    assert_eq!(carol.topics(&g).unwrap().len(), 1);

    // Messages in a topic: per-topic history and unread counts.
    let o = TextOptions { topic: Some(plans.clone()), ..Default::default() };
    let m1 = alice.send_text_with(&g, "saturday?", &o).unwrap();
    alice.send_text(&g, "main chat").unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    let t = &bob.topics(&g).unwrap()[0];
    assert_eq!((t.id.as_str(), t.unread), (plans.as_str(), 1));
    let in_topic = bob.topic_history(&g, Some(&plans), 50).unwrap();
    assert_eq!(in_topic.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), vec![m1.as_str()]);
    assert!(bob.topic_history(&g, None, 50).unwrap().iter().all(|m| m.id != m1));
    bob.mark_topic_read(&g, &plans).unwrap();
    assert_eq!(bob.topics(&g).unwrap()[0].unread, 0);
    assert!(matches!(bob.send_text_with(&g, "x", &TextOptions { topic: Some("nope".into()), ..Default::default() }), Err(Error::Usage(_))));

    // Closed: only those who manage topics write in it.
    alice.close_topic(&g, &plans, true).unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    assert!(bob.topics(&g).unwrap()[0].closed);
    assert!(matches!(bob.send_text_with(&g, "late", &o), Err(Error::Usage(e)) if e.contains("closed")));
    bob.send_unchecked(&g, &text(&fresh_id(), "sneaky", Some(&plans))).unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(dropped(&ev, "the topic is closed"), "{ev:?}");
    assert!(!has_text(&carol, &g, "sneaky"));
    alice.send_text_with(&g, "admins still can", &o).unwrap();
    // A role with `topics` lets bob manage them; others' devices accept it.
    let r = alice.create_role(&g, "편집", "#3366ff", &["topics".into()]).unwrap();
    alice.assign_role(&g, &bob.member_id(), &r, true).unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    assert!(has_text(&carol, &g, "admins still can"));
    bob.close_topic(&g, &plans, false).unwrap();
    bob.rename_topic(&g, &plans, "주말 일정").unwrap();
    carol.sync(0).unwrap();
    let t = &carol.topics(&g).unwrap()[0];
    assert_eq!((t.name.as_str(), t.closed), ("주말 일정", false));
    // Option `all`: every member creates topics.
    assert!(code(carol.create_topic(&g, "carol's"), "NOT_ADMIN"));
    set(&mut alice, &g, "chat.topics", true, Some("all"));
    carol.sync(0).unwrap();
    carol.create_topic(&g, "carol's").unwrap();
    alice.sync(0).unwrap();
    assert_eq!(alice.topics(&g).unwrap().len(), 2);
    // A new member learns the topics from the adder's list.
    let (mut dave, _) = join(&env, &mut alice, &g, "dave");
    dave.sync(0).unwrap();
    assert_eq!(dave.topics(&g).unwrap().len(), 2, "{:?}", dave.topics(&g));

    // Released: no topics, a topic on a message is ignored (main chat).
    set(&mut alice, &g, "chat.topics", false, None);
    sync_all(&mut [&mut bob, &mut carol]);
    assert!(bob.topics(&g).unwrap().is_empty());
    assert!(code(alice.send_text_with(&g, "x", &o), "LOCKED_BY_CHAT"));
    bob.send_unchecked(&g, &text(&fresh_id(), "into the main chat", Some(&plans))).unwrap();
    carol.sync(0).unwrap();
    assert!(carol.topic_history(&g, None, 50).unwrap().iter().any(|m| m.text.as_deref() == Some("into the main chat")));
}

#[test]
fn roles_grant_permissions_that_every_receiver_enforces() {
    let env = Env::new("roles");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    assert!(code(bob.create_role(&g, "x", "#000000", &[]), "NOT_ADMIN"));
    assert!(matches!(alice.create_role(&g, "x", "red", &[]), Err(Error::Core(_))), "bad colour");
    let r = alice.create_role(&g, "모더", "#ff8800", &["pin".into()]).unwrap();
    alice.assign_role(&g, &bob.member_id(), &r, true).unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    let tags = carol.member_roles(&g, &bob.member_id()).unwrap();
    assert_eq!((tags.len(), tags[0].1.name.as_str(), tags[0].1.color.as_str()), (1, "모더", "#ff8800"));
    assert!(bob.may(&g, "pin").unwrap() && !bob.may(&g, "delete").unwrap() && !carol.may(&g, "pin").unwrap());

    // pin: bob's pin is accepted; carol's (no role) is dropped by bob.
    let m = alice.send_text(&g, "the plan").unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    bob.pin_message(&g, &m, None).unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Pinned { pinned: true, .. })), "{ev:?}");
    assert!(code(carol.pin_message(&g, &m, None), "NOT_ADMIN"));
    carol.send_unchecked(&g, &Payload::Pin { id: m.clone(), ttl: None, remove: true }).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(dropped(&ev, "only admins pin"), "{ev:?}");
    assert_eq!(bob.pins(&g).unwrap().len(), 1);

    // delete others' messages: refused without the permission, everywhere.
    let c = carol.send_text(&g, "carol's words").unwrap();
    sync_all(&mut [&mut alice, &mut bob]);
    assert!(code(bob.delete_as_moderator(&g, &c), "NOT_ADMIN"));
    bob.send_unchecked(&g, &Payload::Delete { id: c.clone() }).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(dropped(&ev, "only the sender"), "{ev:?}");
    assert!(has_text(&alice, &g, "carol's words"));
    alice.update_role(&g, &r, "모더", "#ff8800", &["pin".into(), "delete".into()]).unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    bob.delete_as_moderator(&g, &c).unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Deleted { id, .. } if *id == c)), "{ev:?}");
    alice.sync(0).unwrap();
    assert!(!has_text(&alice, &g, "carol's words") && !has_text(&carol, &g, "carol's words"));
    // An admin deletes too.
    let c2 = carol.send_text(&g, "again").unwrap();
    sync_all(&mut [&mut alice, &mut bob]);
    alice.delete_as_moderator(&g, &c2).unwrap();
    bob.sync(0).unwrap();
    assert!(!has_text(&bob, &g, "again"));

    // chat.roles released: roles grant nothing and show nothing, and the
    // receivers drop what a role allowed before.
    set(&mut alice, &g, "chat.roles", false, None);
    carol.sync(0).unwrap();
    assert!(carol.member_roles(&g, &bob.member_id()).unwrap().is_empty());
    bob.send_unchecked(&g, &Payload::Pin { id: m.clone(), ttl: None, remove: true }).unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(dropped(&ev, "only admins pin"), "{ev:?}");
    bob.sync(0).unwrap();
    assert!(code(bob.pin_message(&g, &m, None), "NOT_ADMIN") && !bob.may(&g, "pin").unwrap());
    assert!(code(alice.create_role(&g, "y", "#000000", &[]), "LOCKED_BY_CHAT"));
    set(&mut alice, &g, "chat.roles", true, None);
    sync_all(&mut [&mut bob, &mut carol]);
    assert!(bob.may(&g, "pin").unwrap());

    // add: chat.member_adds released, only admins and `add` roles add (the
    // core of every device rejects other adds, crates/tree-core/tests).
    set(&mut alice, &g, "chat.member_adds", false, None);
    sync_all(&mut [&mut bob, &mut carol]);
    let dave = env.device("dave");
    assert!(code(carol.invite(&g, dave.account_id()), "NOT_ADMIN"));
    assert!(code(bob.invite(&g, dave.account_id()), "NOT_ADMIN"));
    alice.update_role(&g, &r, "모더", "#ff8800", &["add".into()]).unwrap();
    bob.sync(0).unwrap();
    assert!(bob.may_add(&g).unwrap() && !carol.may_add(&g).unwrap());
    assert!(matches!(bob.invite(&g, dave.account_id()).unwrap().0, CommitOutcome::Accepted { .. }));
    alice.sync(0).unwrap();
    set(&mut alice, &g, "chat.member_adds", true, None);
    carol.sync(0).unwrap();
    let erin = env.device("erin");
    assert!(matches!(carol.invite(&g, erin.account_id()).unwrap().0, CommitOutcome::Accepted { .. }));

    // Deleting a role takes it from everyone.
    alice.sync(0).unwrap();
    alice.delete_role(&g, &r).unwrap();
    bob.sync(0).unwrap();
    assert!(bob.roles(&g).unwrap().is_empty() && !bob.may(&g, "pin").unwrap());
}

#[test]
fn admin_log_records_what_admins_did_with_the_authenticated_actor() {
    let env = Env::new("adminlog");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    alice.set_group_name(&g, Some("가족".into())).unwrap();
    set(&mut alice, &g, "chat.media", false, None);
    alice.make_admin(&g, bob.member_id(), true).unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    let a = alice.member_id().to_hex();
    let log = bob.admin_log(&g).unwrap();
    let seen = |log: &[tree_client::admin_log::AdminLogEntry], action: &str, actor: &str| log.iter().any(|e| e.action == action && e.actor == actor);
    assert!(seen(&log, "rename", &a) && seen(&log, "feature", &a) && seen(&log, "admin_add", &a), "{log:?}");
    assert!(log.iter().any(|e| e.action == "feature" && e.target.as_deref() == Some("chat.media") && e.detail.as_deref() == Some("released")));
    assert!(seen(&alice.admin_log(&g).unwrap(), "admin_add", &a), "own commits too");
    // Shown to admins only.
    assert!(code(carol.admin_log(&g), "NOT_ADMIN"));
    // Membership changes and pins, by whoever did them.
    let (_dave, _) = join(&env, &mut alice, &g, "dave");
    let m = alice.send_text(&g, "pin me").unwrap();
    bob.sync(0).unwrap();
    bob.pin_message(&g, &m, None).unwrap();
    alice.sync(0).unwrap();
    let b = bob.member_id().to_hex();
    assert!(seen(&bob.admin_log(&g).unwrap(), "add", &a));
    assert!(seen(&alice.admin_log(&g).unwrap(), "pin", &b));
    // A pin a modified client sends is dropped, so it is not logged either.
    carol.sync(0).unwrap();
    carol.send_unchecked(&g, &Payload::Pin { id: m.clone(), ttl: None, remove: true }).unwrap();
    alice.sync(0).unwrap();
    let c = carol.member_id().to_hex();
    assert!(!alice.admin_log(&g).unwrap().iter().any(|e| e.actor == c));

    // Released: nothing recorded, nothing shown; applied again, recording
    // resumes.
    set(&mut alice, &g, "chat.admin_log", false, None);
    bob.sync(0).unwrap();
    assert!(alice.admin_log(&g).unwrap().is_empty() && bob.admin_log(&g).unwrap().is_empty());
    alice.set_group_name(&g, Some("while released".into())).unwrap();
    set(&mut alice, &g, "chat.admin_log", true, None);
    bob.sync(0).unwrap();
    let log = bob.admin_log(&g).unwrap();
    assert!(!log.iter().any(|e| e.detail.as_deref() == Some("while released")), "{log:?}");
    assert!(log.iter().any(|e| e.action == "feature" && e.target.as_deref() == Some("chat.admin_log")));
}

#[test]
fn welcome_text_is_shown_to_new_members_only() {
    let env = Env::new("welcome");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    assert!(matches!(alice.set_chat_feature(&g, "chat.welcome", true, Some("x".repeat(501))), Err(Error::InvalidOption(_))));
    set(&mut alice, &g, "chat.welcome", true, Some("어서 오세요! 규칙은 고정 메시지에."));
    let ev = bob.sync(0).unwrap();
    assert!(!ev.iter().any(|e| matches!(e, Event::Welcome { .. })), "existing members see no welcome");
    carol.sync(0).unwrap();
    let (dave, ev) = join(&env, &mut alice, &g, "dave");
    assert!(ev.iter().any(|e| matches!(e, Event::Welcome { text, .. } if text.starts_with("어서 오세요"))), "{ev:?}");
    let h = dave.history(&g, 10).unwrap();
    assert!(h.iter().any(|m| m.kind == "welcome"), "{h:?}");
    assert!(!bob.history(&g, 50).unwrap().iter().any(|m| m.kind == "welcome"));
    // Released: the next member gets none.
    set(&mut alice, &g, "chat.welcome", false, None);
    let (erin, ev) = join(&env, &mut alice, &g, "erin");
    assert!(!ev.iter().any(|e| matches!(e, Event::Welcome { .. })), "{ev:?}");
    assert!(!erin.history(&g, 10).unwrap().iter().any(|m| m.kind == "welcome"));
}

#[test]
fn history_is_shared_with_new_members_by_their_adder_only() {
    let env = Env::new("history");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    assert_eq!(alice.history_share(&g).unwrap(), None);
    assert!(matches!(alice.set_chat_feature(&g, "chat.history_share", true, Some("10".into())), Err(Error::InvalidOption(_))));
    set(&mut alice, &g, "chat.history_share", true, Some("25"));
    sync_all(&mut [&mut bob, &mut carol]);
    assert_eq!(bob.history_share(&g).unwrap(), Some(25), "every member sees the notice");
    for i in 0..15 {
        alice.send_text(&g, &format!("alice {i}")).unwrap();
        bob.sync(0).unwrap();
        bob.send_text(&g, &format!("bob {i}")).unwrap();
        alice.sync(0).unwrap();
    }
    let (mut dave, ev) = join(&env, &mut alice, &g, "dave");
    let shared = ev.iter().find_map(|e| match e {
        Event::HistoryShared { by, count, .. } => Some((*by, *count)),
        _ => None,
    });
    assert_eq!(shared, Some((alice.member_id(), 25)), "{ev:?}");
    let h = dave.history(&g, 100).unwrap();
    assert!(!h.iter().any(|m| m.text.as_deref() == Some("alice 0")), "the oldest are not shared");
    let last = h.iter().find(|m| m.text.as_deref() == Some("bob 14")).unwrap();
    assert_eq!(last.sender, bob.member_id().to_hex(), "the original author, as alice claims it");
    assert_eq!(dave.shared_by(&g, &last.id).unwrap(), Some(alice.member_id()), "labelled with the sharer");
    assert_eq!(dave.shared_messages(&g).unwrap().len(), 25);
    // "shared by" names an account only as far as dave's device has the
    // sharer pinned (dave confirmed alice as a contact) ...
    let alice_account = alice.account_id().to_string();
    assert_eq!(dave.shared_by_account(&g, &last.id).unwrap(), Some(alice_account.clone()));
    // ... and a joiner who only added alice by hand (nothing pinned; it lets
    // anyone add it to groups) gets the same bundle but no account for its sharer, whatever the roster
    // labels say (F-021, F-022).
    let mut gina = env.device("gina");
    gina.add_contact(&alice_account).unwrap();
    gina.release_feature("user.group_add").unwrap();
    alice.invite(&g, gina.account_id()).unwrap();
    gina.sync(0).unwrap();
    let id = gina.shared_messages(&g).unwrap().into_keys().next().expect("a shared message");
    assert_eq!(gina.shared_by(&g, &id).unwrap(), Some(alice.member_id()));
    assert!(gina.members(&g).unwrap().iter().any(|m| m.id == alice.member_id() && m.account.as_deref() == Some(alice_account.as_str())), "labelled");
    assert_eq!(gina.shared_by_account(&g, &id).unwrap(), None, "a label alone names no account");
    assert_eq!(dave.unread(&g).unwrap(), 0, "shared messages are not new");

    // A second bundle, or one from a member that did not add this device,
    // is dropped.
    carol.sync(0).unwrap();
    let fake = SharedMsg { id: fresh_id(), from: alice.member_id().to_hex(), name: None, at: 1, kind: "text".into(), text: Some("alice said X".into()), file: None, topic: None };
    carol.send_unchecked(&g, &Payload::History { to: vec![dave.member_id().to_hex()], msgs: vec![fake.clone()] }).unwrap();
    let ev = dave.sync(0).unwrap();
    assert!(dropped(&ev, "not from the member who added"), "{ev:?}");
    let (mut erin, _) = join(&env, &mut alice, &g, "erin");
    carol.sync(0).unwrap();
    carol.send_unchecked(&g, &Payload::History { to: vec![erin.member_id().to_hex()], msgs: vec![fake.clone()] }).unwrap();
    let ev = erin.sync(0).unwrap();
    assert!(dropped(&ev, "shared history"), "{ev:?}");
    assert!(!has_text(&erin, &g, "alice said X") && !has_text(&dave, &g, "alice said X"));

    // Released: no bundle, no notice; one sent anyway is dropped.
    set(&mut alice, &g, "chat.history_share", false, None);
    assert_eq!(alice.history_share(&g).unwrap(), None);
    let (mut frank, ev) = join(&env, &mut alice, &g, "frank");
    assert!(!ev.iter().any(|e| matches!(e, Event::HistoryShared { .. })), "{ev:?}");
    assert!(frank.history(&g, 100).unwrap().iter().all(|m| !m.kind.starts_with("text")));
    alice.send_unchecked(&g, &Payload::History { to: vec![frank.member_id().to_hex()], msgs: vec![fake] }).unwrap();
    let ev = frank.sync(0).unwrap();
    assert!(dropped(&ev, "does not share history"), "{ev:?}");
}

#[test]
fn the_last_admin_names_the_next_one_before_leaving() {
    let env = Env::new("succession");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    assert_eq!(alice.successor(&g).unwrap(), Some(bob.member_id()), "the longest-standing member");
    alice.leave(&g).unwrap();
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::LeaveRequested { .. })), "{ev:?}");
    assert!(bob.group_settings(&g).unwrap().is_admin(&bob.member_id()));
    // The new admin carries out the leave request (as the apps do).
    assert!(matches!(bob.remove(&g, &[alice.member_id()]).unwrap(), CommitOutcome::Accepted { .. }));
    carol.sync(0).unwrap();
    let s = carol.group_settings(&g).unwrap();
    assert_eq!(s.admins, vec![bob.member_id()]);
    assert!(!carol.members(&g).unwrap().iter().any(|m| m.id == alice.member_id()));

    // Released: nobody is named; the group is left without a working admin.
    let env = Env::new("succession-off");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    set(&mut alice, &g, "chat.owner_succession", false, None);
    sync_all(&mut [&mut bob, &mut carol]);
    assert_eq!(alice.successor(&g).unwrap(), None);
    alice.leave(&g).unwrap();
    bob.sync(0).unwrap();
    assert_eq!(bob.group_settings(&g).unwrap().admins, vec![alice.member_id()]);
    assert!(matches!(bob.remove(&g, &[alice.member_id()]), Err(Error::Core(tree_core::TreeError::NotAdmin))));
}

#[test]
fn join_approval_holds_link_joins_for_an_admin() {
    let env = Env::new("approval");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    let link = alice.create_invite_link(&g, 3600, 5).unwrap();
    set(&mut alice, &g, "chat.join_approval", true, None);
    sync_all(&mut [&mut bob, &mut carol]);
    let mut dave = env.device("dave");
    dave.join_invite_link(&link).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::JoinRequest { account, .. } if account == dave.account_id())), "{ev:?}");
    assert!(dave.sync(0).unwrap().is_empty() || !dave.group_ids().unwrap().contains(&g), "not added yet");
    let reqs = alice.join_requests(&g).unwrap();
    assert_eq!(reqs.iter().map(|r| r.account.as_str()).collect::<Vec<_>>(), vec![dave.account_id()]);
    assert!(code(bob.approve_join(&g, dave.account_id()), "NOT_ADMIN"));
    assert!(matches!(alice.approve_join(&g, dave.account_id()).unwrap(), CommitOutcome::Accepted { .. }));
    let ev = dave.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Joined { .. })), "{ev:?}");
    assert_eq!(dave.group_status(&g).unwrap(), GroupStatus::Accepted, "the joiner asked for it");
    assert!(alice.join_requests(&g).unwrap().is_empty());
    assert!(alice.admin_log(&g).unwrap().iter().any(|e| e.action == "join_approve"));
    // Declined: never added.
    let mut erin = env.device("erin");
    erin.join_invite_link(&link).unwrap();
    alice.sync(0).unwrap();
    alice.decline_join(&g, erin.account_id()).unwrap();
    alice.sync(0).unwrap();
    erin.sync(0).unwrap();
    assert!(!erin.group_ids().unwrap().contains(&g));
    // Released: link joins are carried out at once.
    set(&mut alice, &g, "chat.join_approval", false, None);
    let mut frank = env.device("frank");
    frank.join_invite_link(&link).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::InviteLinkUsed { .. })), "{ev:?}");
    frank.sync(0).unwrap();
    assert_eq!(frank.group_status(&g).unwrap(), GroupStatus::Accepted);
}

#[test]
fn slow_mode_spaces_messages_of_members_on_both_sides() {
    let env = Env::new("slowmode");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    assert!(matches!(alice.set_chat_feature(&g, "chat.slow_mode", true, Some("5s".into())), Err(Error::InvalidOption(_))));
    set(&mut alice, &g, "chat.slow_mode", true, Some("1h"));
    sync_all(&mut [&mut bob, &mut carol]);
    assert_eq!(bob.slow_mode(&g).unwrap(), Some(3600));
    bob.send_text(&g, "one").unwrap();
    assert!(code(bob.send_text(&g, "two"), "SLOW_MODE"));
    assert!(bob.slow_mode_wait(&g).unwrap().is_some_and(|w| w > 3500));
    // Admins are not slowed down.
    alice.send_text(&g, "a1").unwrap();
    alice.send_text(&g, "a2").unwrap();
    assert_eq!(alice.slow_mode_wait(&g).unwrap(), None);
    // A modified client that ignores it: receivers hide the message and
    // tell admins.
    bob.send_unchecked(&g, &text(&fresh_id(), "too fast", None)).unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(has_text(&carol, &g, "one") && has_text(&carol, &g, "a2"));
    assert!(dropped(&ev, "slow mode"), "{ev:?}");
    assert!(!has_text(&carol, &g, "too fast"));
    assert!(!ev.iter().any(|e| matches!(e, Event::SlowModeHidden { .. })), "carol is not an admin");
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::SlowModeHidden { member, .. } if *member == bob.member_id())), "{ev:?}");
    // Released: no limit.
    set(&mut alice, &g, "chat.slow_mode", false, None);
    sync_all(&mut [&mut bob, &mut carol]);
    bob.send_text(&g, "free again").unwrap();
    bob.send_text(&g, "and again").unwrap();
    carol.sync(0).unwrap();
    assert!(has_text(&carol, &g, "and again"));
}

#[test]
fn restricted_members_read_but_cannot_send() {
    let env = Env::new("restrict");
    let (mut alice, mut bob, mut carol, g) = trio(&env);
    assert!(matches!(alice.restrict_member(&g, &alice.member_id(), Some(now() + 60)), Err(Error::Usage(_))), "not an admin");
    assert!(code(carol.restrict_member(&g, &bob.member_id(), Some(now() + 60)), "NOT_ADMIN"));
    alice.restrict_member(&g, &bob.member_id(), Some(now() + 3600)).unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    assert!(bob.restricted_until(&g).unwrap().is_some());
    assert!(code(bob.send_text(&g, "hello?"), "RESTRICTED"));
    // Still reads, but does not react either.
    let m = alice.send_text(&g, "you can read this").unwrap();
    bob.sync(0).unwrap();
    assert!(has_text(&bob, &g, "you can read this"));
    assert!(code(bob.react(&g, &m, "👍", false), "RESTRICTED"));
    // A modified client: dropped by every honest device.
    bob.send_unchecked(&g, &text(&fresh_id(), "restricted words", None)).unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(dropped(&ev, "restricted member"), "{ev:?}");
    assert!(!has_text(&carol, &g, "restricted words"));
    assert_eq!(carol.restricted_members(&g).unwrap().iter().map(|r| r.0).collect::<Vec<MemberId>>(), vec![bob.member_id()]);

    // chat.restrict released: restrictions are not enforced.
    set(&mut alice, &g, "chat.restrict", false, None);
    sync_all(&mut [&mut bob, &mut carol]);
    assert_eq!(bob.restricted_until(&g).unwrap(), None);
    bob.send_text(&g, "released").unwrap();
    carol.sync(0).unwrap();
    assert!(has_text(&carol, &g, "released"));
    set(&mut alice, &g, "chat.restrict", true, None);
    sync_all(&mut [&mut bob, &mut carol]);
    assert!(code(bob.send_text(&g, "again?"), "RESTRICTED"));
    // Lifted, and a restriction that runs out ends by itself.
    alice.restrict_member(&g, &bob.member_id(), None).unwrap();
    bob.sync(0).unwrap();
    bob.send_text(&g, "lifted").unwrap();
    alice.restrict_member(&g, &carol.member_id(), Some(now() + 2)).unwrap();
    carol.sync(0).unwrap();
    assert!(code(carol.send_text(&g, "x"), "RESTRICTED"));
    std::thread::sleep(Duration::from_millis(3100));
    carol.send_text(&g, "time is up").unwrap();
    bob.sync(0).unwrap();
    assert!(has_text(&bob, &g, "time is up"));
}

#[test]
fn communities_list_chats_and_members_join_them() {
    let env = Env::new("community");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut carol = env.device("carol");
    bob.confirm_contact(alice.account_id()).unwrap();
    carol.confirm_contact(alice.account_id()).unwrap();
    let root = alice.create_community("동네 모임").unwrap();
    assert!(alice.is_community(&root).unwrap());
    let general = alice.create_group().unwrap();
    alice.set_group_name(&general, Some("일반".into())).unwrap();
    let other = alice.create_group().unwrap();
    alice.add_community_chat(&root, &general).unwrap();
    alice.add_community_chat(&root, &other).unwrap();
    alice.invite(&root, bob.account_id()).unwrap();
    alice.invite(&root, carol.account_id()).unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    assert_eq!(bob.communities().unwrap(), vec![root.clone()]);
    let chats = bob.community_chats(&root).unwrap();
    assert_eq!(chats.iter().map(|c| (c.name.as_str(), c.joined)).collect::<Vec<_>>(), vec![("일반", false), ("", false)]);
    // Only the community's admins change the list.
    assert!(code(bob.remove_community_chat(&root, &general), "NOT_ADMIN"));

    // bob asks to join; alice's device adds him; he arrives accepted.
    bob.join_community_chat(&root, &general).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::CommunityMemberAdded { member, .. } if *member == bob.member_id())), "{ev:?}");
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Joined { group } if *group == general)), "{ev:?}");
    assert_eq!(bob.group_status(&general).unwrap(), GroupStatus::Accepted);
    assert!(bob.community_chats(&root).unwrap()[0].joined);

    // carol asks for bob's account: the requesting device is not one of
    // that account's devices, so nobody is added.
    carol.send_unchecked(&root, &Payload::JoinChat { chat: hex::encode(&other), account: bob.account_id().to_string() }).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(dropped(&ev, "not vouched for the account it names"), "{ev:?}");
    assert!(!alice.members(&other).unwrap().iter().any(|m| m.id == bob.member_id()));
    // A chat that is not listed cannot be asked for.
    let secret = alice.create_group().unwrap();
    assert!(matches!(carol.join_community_chat(&root, &secret), Err(Error::Usage(_))));
    carol.send_unchecked(&root, &Payload::JoinChat { chat: hex::encode(&secret), account: carol.account_id().to_string() }).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(dropped(&ev, "not a chat of this community"), "{ev:?}");
    // Removed from the list.
    alice.remove_community_chat(&root, &other).unwrap();
    bob.sync(0).unwrap();
    assert_eq!(bob.community_chats(&root).unwrap().len(), 1);
}

/// A stranger's device in a community names another person's account in
/// its own roster (so the admin's device records the label) and then asks
/// to join a chat as that account. The admin's device adds only a device
/// it has pinned for the named account (`vouches_for`): the label is not
/// enough, and neither is naming the admin's own account (F-021, F-022).
#[test]
fn a_stranger_naming_another_account_is_not_added_even_if_a_roster_labels_it() {
    let env = Env::new("community-stranger");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut dave = env.device("dave");
    bob.confirm_contact(alice.account_id()).unwrap();
    dave.confirm_contact(alice.account_id()).unwrap();
    let root = alice.create_community("모임").unwrap();
    let chat = alice.create_group().unwrap();
    alice.add_community_chat(&root, &chat).unwrap();
    alice.invite(&root, bob.account_id()).unwrap();
    alice.invite(&root, dave.account_id()).unwrap();
    sync_all(&mut [&mut bob, &mut dave, &mut alice]);
    let (b, d) = (bob.account_id().to_string(), dave.member_id().to_hex());

    // In a chat of dave's own, dave's (modified) client labels its device
    // as bob's account in the roster that comes with alice's welcome, so
    // alice's device takes the label (the first one, a member's word for
    // itself) and records dave's device as an unconfirmed device of bob.
    let side = dave.create_group().unwrap();
    dave.set_account_label_unchecked(&side, &dave.member_id(), &b).unwrap();
    dave.invite(&side, alice.account_id()).unwrap();
    let dev = alice.members(&root).unwrap().into_iter().find(|m| m.id == dave.member_id()).unwrap().device.unwrap();
    let label = |acc: &str| Payload::Roster {
        devices: [(d.clone(), dev.clone())].into(),
        names: Default::default(),
        accounts: [(d.clone(), acc.to_string())].into(),
        link: None,
    };
    alice.sync(0).unwrap();
    let info = alice.members(&side).unwrap().into_iter().find(|m| m.id == dave.member_id()).unwrap();
    assert_eq!(info.account.as_deref(), Some(b.as_str()), "the roster labels dave's device as bob's account");
    for target in [b.clone(), alice.account_id().to_string()] {
        // dave asks for `chat` as `target` (and labels itself so in the root
        // too, where alice's own label came first and stays).
        dave.send_unchecked(&root, &label(&target)).unwrap();
        dave.send_unchecked(&root, &Payload::JoinChat { chat: hex::encode(&chat), account: target.clone() }).unwrap();
        let ev = alice.sync(0).unwrap();
        assert!(dropped(&ev, "not vouched for the account it names"), "{target}: {ev:?}");
        assert!(!ev.iter().any(|e| matches!(e, Event::CommunityMemberAdded { .. })), "{ev:?}");
        assert!(!alice.members(&chat).unwrap().iter().any(|m| m.id == dave.member_id() || m.id == bob.member_id()));
    }
    // bob's contact on alice's device never counts dave's device.
    let c = alice.contact(&b).unwrap().unwrap();
    assert!(!c.vouches_for(&d), "{c:?}");
    // bob himself, pinned by alice's invite, is added.
    bob.join_community_chat(&root, &chat).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::CommunityMemberAdded { member, .. } if *member == bob.member_id())), "{ev:?}");
    assert!(!alice.members(&chat).unwrap().iter().any(|m| m.id == dave.member_id()));
}
