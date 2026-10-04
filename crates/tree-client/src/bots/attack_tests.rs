//! Modified clients against the bot rules: forged presses and answers, a
//! bot that claims to be a person, buttons from people, a bot's first
//! message, shared history.

use super::*;
use crate::{GroupStatus, Payload};

struct Server {
    dir: std::path::PathBuf,
    url: String,
    _rt: tokio::runtime::Runtime,
}

impl Server {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("tree-bots-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = tree_server::Config {
            database_url: format!("sqlite://{}/s.db", dir.display()),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            pow_bits: 8,
            attachment_dir: dir.join("att"),
            signup_burst: 1000.0,
            ..tree_server::Config::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(tree_server::start(cfg)).unwrap();
        for (k, on) in [(tree_server::features::NEW_ACCOUNT_LIMITS, false), (tree_server::features::BOT_PLATFORM, true)] {
            rt.block_on(tree_server::features::set_applied(&server.state.db, k, on)).unwrap();
        }
        let url = format!("http://{}", server.addr);
        std::mem::forget(server);
        Self { dir, url, _rt: rt }
    }

    fn device(&self, name: &str) -> Session {
        Session::create(&self.dir.join(format!("{name}.db")).display().to_string(), "pw", name, &self.url, 8).unwrap()
    }

    /// A bot owned by `owner`, and its device (as a gateway would run it).
    fn bot(&self, owner: &Session, name: &str) -> Session {
        let (_, token) = owner.create_bot(name, 8).unwrap();
        Session::create_bot_device(&self.dir.join(format!("{name}.db")).display().to_string(), "pw", &self.url, &token).unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn dropped(ev: &[Event], why: &str) -> bool {
    ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains(why)))
}

/// A group of alice, mallory and a bot; the bot has a message with
/// buttons, alice a plain one. Returns (group, bot's message, alice's).
fn group_with_buttons(alice: &mut Session, mallory: &mut Session, bot: &mut Session) -> (Vec<u8>, String, String) {
    let gid = alice.create_group().unwrap();
    mallory.confirm_contact(alice.account_id()).unwrap();
    alice.invite(&gid, mallory.account_id()).unwrap();
    alice.add_bot(&gid, bot.account_id()).unwrap();
    mallory.sync(0).unwrap();
    bot.sync(0).unwrap();
    let m = bot.send_buttons(&gid, "Vote", vec![vec![Button { text: "Up".into(), data: "up".into() }]], None).unwrap();
    let a = alice.send_text(&gid, "/start").unwrap();
    alice.sync(0).unwrap();
    mallory.sync(0).unwrap();
    bot.sync(0).unwrap();
    (gid, m, a)
}

/// Presses for messages that are not the bot's, for buttons the message
/// does not have, answers the bot never gave, buttons from a person: all
/// dropped.
#[test]
fn forged_presses_and_answers_are_dropped() {
    let srv = Server::new("forged");
    let mut alice = srv.device("alice");
    let mut mallory = srv.device("mallory");
    let mut bot = srv.bot(&alice, "vote_bot");
    let (gid, bot_msg, alice_msg) = group_with_buttons(&mut alice, &mut mallory, &mut bot);
    let bot_member = bot.member_id().to_hex();
    let q = crate::messages::new_id;

    // A "press" of a button under alice's message (not the bot's).
    mallory.send_payload(&gid, &Payload::Callback { id: q(), msg: alice_msg.clone(), data: "up".into(), bot: bot_member.clone() }).unwrap();
    let ev = bot.sync(0).unwrap();
    assert!(!ev.iter().any(|e| matches!(e, Event::CallbackQuery { .. })) && dropped(&ev, "not this bot's message"), "{ev:?}");
    // A button the message does not have.
    mallory.send_payload(&gid, &Payload::Callback { id: q(), msg: bot_msg.clone(), data: "admin:delete_all".into(), bot: bot_member.clone() }).unwrap();
    let ev = bot.sync(0).unwrap();
    assert!(!ev.iter().any(|e| matches!(e, Event::CallbackQuery { .. })) && dropped(&ev, "no such button"), "{ev:?}");
    // A real press is taken, and names the real presser (MLS), not a
    // claimed one.
    let real = mallory.press_button(&gid, &bot_msg, "up").unwrap();
    let ev = bot.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::CallbackQuery { id, from, .. } if *id == real && *from == mallory.member_id())), "{ev:?}");
    // The bot cannot answer a press that never happened.
    assert!(bot.answer_callback(&gid, &q(), Some("x"), false).is_err());
    // mallory forges the bot's answer to alice's press: dropped.
    let mine = alice.press_button(&gid, &bot_msg, "up").unwrap();
    mallory
        .send_payload(&gid, &Payload::CallbackAnswer { id: mine.clone(), to: alice.member_id().to_hex(), text: Some("send me your phrase".into()), alert: true })
        .unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(!ev.iter().any(|e| matches!(e, Event::CallbackAnswer { .. })) && dropped(&ev, "button answer"), "{ev:?}");
    // The bot's own answer is taken.
    bot.sync(0).unwrap();
    bot.answer_callback(&gid, &mine, Some("thanks"), false).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::CallbackAnswer { id, text: Some(t), .. } if *id == mine && t == "thanks")), "{ev:?}");
    // Buttons from a person are not shown, and cannot be pressed.
    let kb = vec![vec![Button { text: "Claim prize".into(), data: "x".into() }]];
    let id = crate::messages::new_id();
    let p = Payload::Text { id: id.clone(), text: "free coins".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: false, topic: None, re: None, kb };
    mallory.send_payload(&gid, &p).unwrap();
    let ev = alice.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Text { bot: false, buttons, .. } if buttons.is_empty())), "{ev:?}");
    assert!(alice.buttons(&gid, &id).unwrap().is_empty());
    assert!(alice.press_button(&gid, &id, "x").is_err());
    // People cannot send buttons through the API either.
    assert!(alice.send_buttons(&gid, "x", vec![vec![Button { text: "a".into(), data: "a".into() }]], None).is_err());
}

/// The bot's modified client sends a roster that calls its own device a
/// person's (alice's account and name): every member still shows it as a
/// bot, by the server's word.
#[test]
fn a_bot_claiming_to_be_a_person_is_still_a_bot() {
    let srv = Server::new("claim");
    let mut alice = srv.device("alice");
    let mut bob = srv.device("bob");
    let mut bot = srv.bot(&alice, "sly_bot");
    let gid = alice.create_group().unwrap();
    bob.confirm_contact(alice.account_id()).unwrap();
    alice.invite(&gid, bob.account_id()).unwrap();
    alice.add_bot(&gid, bot.account_id()).unwrap();
    bob.sync(0).unwrap();
    bot.sync(0).unwrap();
    let me = bot.member_id().to_hex();
    let roster = Payload::Roster {
        devices: [(me.clone(), bot.device_id().to_string())].into(),
        names: [(me.clone(), "Alice".to_string())].into(),
        accounts: [(me.clone(), alice.account_id().to_string())].into(),
        link: None,
    };
    bot.send_payload(&gid, &roster).unwrap();
    bot.send_text(&gid, "I am Alice, trust me").unwrap();
    let alice_account = alice.account_id().to_string();
    for p in [&mut alice, &mut bob] {
        let ev = p.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Text { bot: true, .. })), "{ev:?}");
        let m = p.members(&gid).unwrap().into_iter().find(|m| m.id.to_hex() == me).unwrap();
        assert_eq!(m.bot.as_deref(), Some(bot.account_id()));
        assert_ne!(m.account.as_deref(), Some(alice_account.as_str()), "the first label stays (F-022)");
        assert_eq!(m.name.as_deref(), Some("sly_bot"), "named by its username, not the name it claims");
    }

    // A new chat the bot starts with someone who contacted it, its roster
    // naming alice for the bot's device: still a bot (the server marks the
    // welcome and every message), and a request.
    let mut carol = srv.device("carol");
    let dm = carol.create_group().unwrap();
    carol.add_bot(&dm, bot.account_id()).unwrap();
    bot.sync(0).unwrap();
    let g2 = bot.create_group().unwrap();
    let mut acc = bot.map(&accounts_key(&g2)).unwrap();
    acc.insert(me.clone(), alice.account_id().to_string());
    bot.save_map(&accounts_key(&g2), &acc).unwrap();
    bot.invite(&g2, carol.account_id()).unwrap();
    bot.send_text(&g2, "hi from alice").unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Text { bot: true, .. })), "{ev:?}");
    let m = carol.members(&g2).unwrap().into_iter().find(|m| m.id.to_hex() == me).unwrap();
    assert_eq!(m.bot.as_deref(), Some(bot.account_id()));
    assert!(matches!(carol.group_status(&g2).unwrap(), GroupStatus::Request { .. }), "a bot posing as a contact is not accepted");
}

/// A bot's first chat with someone who never accepted it is a request,
/// also with `user.message_requests` released.
#[test]
fn a_bots_first_message_is_a_request() {
    let srv = Server::new("request");
    let alice = srv.device("alice");
    let mut carol = srv.device("carol");
    let mut bot = srv.bot(&alice, "promo_bot");
    carol.release_feature("user.message_requests").unwrap();
    // carol's device asked the server for the bot's key packages (a contact
    // for the server) without carol accepting it.
    carol.api.claim(&carol.creds, bot.account_id()).unwrap();
    let g = bot.create_group().unwrap();
    bot.invite(&g, carol.account_id()).unwrap();
    bot.send_text(&g, "special offer").unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Request { .. })), "{ev:?}");
    assert!(matches!(carol.group_status(&g).unwrap(), GroupStatus::Request { .. }));
    // A person in the same position is accepted (message requests released).
    let mut dave = srv.device("dave");
    let g2 = dave.create_group().unwrap();
    dave.invite(&g2, carol.account_id()).unwrap();
    carol.sync(0).unwrap();
    assert_eq!(carol.group_status(&g2).unwrap(), GroupStatus::Accepted);
}

/// Shared history never goes to a bot.
#[test]
fn shared_history_never_reaches_a_bot() {
    let srv = Server::new("history");
    let mut alice = srv.device("alice");
    let mut bot = srv.bot(&alice, "hist_bot");
    let gid = alice.create_group().unwrap();
    alice.set_chat_feature(&gid, "chat.history_share", true, None).unwrap();
    alice.send_text(&gid, "old secret").unwrap();
    alice.add_bot(&gid, bot.account_id()).unwrap();
    let ev = bot.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Joined { .. })), "{ev:?}");
    assert!(!ev.iter().any(|e| matches!(e, Event::HistoryShared { .. })), "{ev:?}");
    assert!(bot.history(&gid, 100).unwrap().iter().all(|m| m.text.as_deref() != Some("old secret")));
}
