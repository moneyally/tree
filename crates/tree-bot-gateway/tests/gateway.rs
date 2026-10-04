//! The bot gateway end to end: a real server in this process, people's
//! devices (tree-client sessions), and bots run by gateways that the bot's
//! own code talks to over the local HTTP API (PROTOCOL.md 8.16,
//! docs/BOT_GATEWAY.md).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tree_bot_gateway::{Config, Gateway};
use tree_client::{Event, Session, TextOptions};

const POW: u32 = 8;

struct Env {
    dir: PathBuf,
    url: String,
    _rt: tokio::runtime::Runtime,
}

impl Env {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("tree-gw-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = tree_server::Config {
            database_url: format!("sqlite://{}/server.db", dir.display()),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            pow_bits: POW,
            attachment_dir: dir.join("att"),
            signup_burst: 1000.0,
            signup_per_hour: 1_000_000.0,
            ..tree_server::Config::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(tree_server::start(cfg)).unwrap();
        let db = server.state.db.clone();
        rt.block_on(tree_server::features::set_applied(&db, tree_server::features::NEW_ACCOUNT_LIMITS, false)).unwrap();
        rt.block_on(tree_server::features::set_applied(&db, tree_server::features::BOT_PLATFORM, true)).unwrap();
        let url = format!("http://{}", server.addr);
        std::mem::forget(server);
        Env { dir, url, _rt: rt }
    }

    fn device(&self, name: &str) -> Session {
        Session::create(&self.dir.join(format!("{name}.db")).display().to_string(), "pw", name, &self.url, POW).unwrap()
    }

    /// `owner` creates a bot; its gateway starts. Returns (bot account, token, gateway).
    fn bot(&self, owner: &Session, username: &str) -> (String, String, Gateway) {
        let (b, token) = owner.create_bot(username, POW).unwrap();
        let s = Session::create_bot_device(&self.dir.join(format!("{username}.db")).display().to_string(), "gw pass", &self.url, &token).unwrap();
        (b.info.account, token.clone(), start(s))
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(s: Session) -> Gateway {
    let cfg = Config { listen: "127.0.0.1:0".parse().unwrap(), poll_secs: 1, settings_every: Duration::from_secs(1), ..Config::default() };
    Gateway::start(s, cfg).unwrap()
}

/// One call of the bot's own code to its gateway.
fn call(g: &Gateway, token: &str, method: &str, body: Value) -> (u16, Value) {
    let r = reqwest::blocking::Client::new()
        .post(format!("http://{}/v1/{method}", g.addr))
        .header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .timeout(Duration::from_secs(60))
        .send()
        .unwrap();
    (r.status().as_u16(), r.json().unwrap_or(Value::Null))
}

/// Every update that arrives within `secs` (confirmed as read).
fn updates(g: &Gateway, token: &str, secs: u64) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut offset = 0u64;
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        let (st, v) = call(g, token, "getUpdates", json!({ "offset": offset, "timeout": 1 }));
        assert_eq!(st, 200, "{v}");
        for u in v["result"].as_array().unwrap() {
            offset = u["update_id"].as_u64().unwrap() + 1;
            out.push(u.clone());
        }
    }
    call(g, token, "getUpdates", json!({ "offset": offset }));
    out
}

fn texts(us: &[Value]) -> Vec<String> {
    us.iter().filter_map(|u| u["message"]["text"].as_str().map(str::to_string)).collect()
}

fn sync_all(people: &mut [&mut Session]) -> Vec<Vec<Event>> {
    people.iter_mut().map(|s| s.sync(0).unwrap()).collect()
}

/// Waits until a person's sync shows a text from the bot.
fn bot_text(s: &mut Session) -> Event {
    let end = Instant::now() + Duration::from_secs(20);
    while Instant::now() < end {
        for e in s.sync(1).unwrap() {
            if matches!(e, Event::Text { bot: true, .. }) {
                return e;
            }
        }
    }
    panic!("no text from the bot");
}

/// With `bot.privacy_mode` applied (the default), a bot in a group gets
/// only what is addressed to it; with it released, everything. Its own
/// messages are labelled as a bot's for everyone.
#[test]
fn privacy_mode_decides_what_the_bot_sees() {
    let env = Env::new("privacy");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let (bot, token, g) = env.bot(&alice, "quiz_bot");
    let gid = alice.create_group().unwrap();
    bob.confirm_contact(alice.account_id()).unwrap();
    alice.invite(&gid, bob.account_id()).unwrap();
    alice.add_bot(&gid, "@quiz_bot").unwrap();
    bob.sync(0).unwrap();
    let bot_member = alice.members(&gid).unwrap().into_iter().find(|m| m.bot.is_some()).unwrap();
    assert_eq!(bot_member.bot.as_deref(), Some(bot.as_str()));

    alice.send_text(&gid, "hello everyone").unwrap();
    bob.send_text(&gid, "/start@quiz_bot").unwrap();
    bob.send_text(&gid, "/start@other_bot").unwrap();
    alice.send_text(&gid, "/help").unwrap();
    alice.send_text_with(&gid, "what do you think", &TextOptions { mentions: vec![bot_member.id], ..Default::default() }).unwrap();
    let got = updates(&g, &token, 4);
    assert_eq!(texts(&got), vec!["/start@quiz_bot", "/help", "what do you think"], "{got:?}");
    // Who sent what, as the group knows them.
    let start = &got[0]["message"];
    assert_eq!(start["from"]["id"], json!(bob.member_id().to_hex()));
    assert_eq!(start["from"]["is_bot"], json!(false));
    assert_eq!(start["chat"]["id"], json!(hex::encode(&gid)));
    assert_eq!(start["chat"]["type"], json!("group"));

    // The bot answers; everyone sees a bot.
    let (st, v) = call(&g, &token, "sendMessage", json!({ "chat_id": hex::encode(&gid), "text": "Welcome to the quiz" }));
    assert_eq!(st, 200, "{v}");
    let bot_msg = v["result"]["message_id"].as_str().unwrap().to_string();
    for p in [&mut alice, &mut bob] {
        match bot_text(p) {
            Event::Text { text, bot, buttons, .. } => assert_eq!((text.as_str(), bot, buttons.len()), ("Welcome to the quiz", true, 0)),
            _ => unreachable!(),
        }
    }
    // A reply to the bot is addressed to it.
    bob.send_text_with(&gid, "count me in", &TextOptions { reply_to: Some(bot_msg.clone()), ..Default::default() }).unwrap();
    alice.send_text(&gid, "just chatting").unwrap();
    let got = updates(&g, &token, 3);
    assert_eq!(texts(&got), vec!["count me in"]);
    assert_eq!(got[0]["message"]["reply_to_message"]["message_id"], json!(bot_msg));

    // The owner releases privacy mode: the members' devices learn it and
    // send the bot everything.
    alice.set_bot_feature(&bot, "bot.privacy_mode", false).unwrap();
    alice.refresh_bots(&gid).unwrap();
    bob.refresh_bots(&gid).unwrap();
    alice.send_text(&gid, "plain talk").unwrap();
    bob.send_text(&gid, "more plain talk").unwrap();
    let got = updates(&g, &token, 3);
    assert_eq!(texts(&got), vec!["plain talk", "more plain talk"]);
    let (_, me) = call(&g, &token, "getMe", json!({}));
    assert_eq!((me["result"]["username"].as_str(), me["result"]["can_read_all_group_messages"].as_bool()), (Some("quiz_bot"), Some(true)));

    // And applied again: back to addressed messages only.
    alice.set_bot_feature(&bot, "bot.privacy_mode", true).unwrap();
    alice.refresh_bots(&gid).unwrap();
    alice.send_text(&gid, "private again").unwrap();
    alice.send_text(&gid, "/score").unwrap();
    assert_eq!(texts(&updates(&g, &token, 3)), vec!["/score"]);
    sync_all(&mut [&mut alice, &mut bob]);
    g.stop();
}

/// Privacy mode keeps most of a talkative member's messages from the bot,
/// and an MLS receiver refuses a message more than 1,000 sender-ratchet
/// generations ahead of the last one it read. The members' devices send
/// the bot a contentless tick every `LANE_TICK_EVERY` messages, so a
/// command after 1,100 messages the bot never got is still read, and the
/// ticks never show up for anyone.
#[test]
fn a_bot_still_reads_commands_after_many_messages_it_was_not_sent() {
    let env = Env::new("ticks");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let (_bot, token, g) = env.bot(&alice, "tick_bot");
    let gid = alice.create_group().unwrap();
    bob.confirm_contact(alice.account_id()).unwrap();
    alice.invite(&gid, bob.account_id()).unwrap();
    alice.add_bot(&gid, "@tick_bot").unwrap();
    bob.sync(0).unwrap();
    for i in 0..1100 {
        alice.send_text(&gid, &format!("chatter {i}")).unwrap();
        if i % 200 == 0 {
            bob.sync(0).unwrap();
        }
    }
    alice.send_text(&gid, "/status@tick_bot").unwrap();
    let got = updates(&g, &token, 6);
    assert_eq!(texts(&got), vec!["/status@tick_bot"], "{got:?}");
    // People never see a tick: no "unsupported" drops on their side.
    let mut bob_events = Vec::new();
    for _ in 0..3 {
        bob_events.extend(bob.sync(1).unwrap());
    }
    assert!(!bob_events.iter().any(|e| matches!(e, Event::Dropped { .. })), "{bob_events:?}");
    g.stop();
}

/// Buttons under a bot's message; a press reaches the bot, the bot's
/// answer reaches the presser only.
#[test]
fn buttons_and_callbacks() {
    let env = Env::new("buttons");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let (_, token, g) = env.bot(&alice, "poll_bot");
    // A 1:1 chat with the bot: everything is for it.
    let dm = alice.create_group().unwrap();
    alice.add_bot(&dm, "@poll_bot").unwrap();
    alice.send_text(&dm, "hi there").unwrap();
    let got = updates(&g, &token, 3);
    assert_eq!(texts(&got), vec!["hi there"]);
    assert_eq!(got[0]["message"]["chat"]["type"], json!("private"));

    let kb = json!({ "inline_keyboard": [[{ "text": "Yes", "callback_data": "vote:yes" }, { "text": "No", "callback_data": "vote:no" }]] });
    let (st, v) = call(&g, &token, "sendMessage", json!({ "chat_id": hex::encode(&dm), "text": "Coffee?", "reply_markup": kb }));
    assert_eq!(st, 200, "{v}");
    let msg = v["result"]["message_id"].as_str().unwrap().to_string();
    let Event::Text { id, buttons, .. } = bot_text(&mut alice) else { unreachable!() };
    assert_eq!(id, msg);
    assert_eq!(buttons.iter().flatten().map(|b| b.data.as_str()).collect::<Vec<_>>(), vec!["vote:yes", "vote:no"]);
    assert_eq!(alice.buttons(&dm, &msg).unwrap(), buttons);
    // Only real buttons can be pressed.
    assert!(alice.press_button(&dm, &msg, "vote:maybe").is_err());
    let q = alice.press_button(&dm, &msg, "vote:yes").unwrap();
    let got = updates(&g, &token, 3);
    let cq = got.iter().find_map(|u| u.get("callback_query")).expect("a press");
    assert_eq!((cq["id"].as_str(), cq["data"].as_str(), cq["message"]["message_id"].as_str()), (Some(q.as_str()), Some("vote:yes"), Some(msg.as_str())));
    assert_eq!(cq["from"]["id"], json!(alice.member_id().to_hex()));
    let (st, v) = call(&g, &token, "answerCallbackQuery", json!({ "callback_query_id": q, "text": "Noted: yes" }));
    assert_eq!(st, 200, "{v}");
    let end = Instant::now() + Duration::from_secs(20);
    let mut answer = None;
    while answer.is_none() && Instant::now() < end {
        answer = alice.sync(1).unwrap().into_iter().find_map(|e| match e {
            Event::CallbackAnswer { id, text, alert, .. } => Some((id, text, alert)),
            _ => None,
        });
    }
    assert_eq!(answer, Some((q.clone(), Some("Noted: yes".into()), false)));
    // A second answer to the same press is refused by the gateway.
    let (st, _) = call(&g, &token, "answerCallbackQuery", json!({ "callback_query_id": q }));
    assert_eq!(st, 400);

    // In a group, a press and its answer stay between the presser and the
    // bot: bob gets neither.
    let gid = alice.create_group().unwrap();
    bob.confirm_contact(alice.account_id()).unwrap();
    alice.invite(&gid, bob.account_id()).unwrap();
    alice.add_bot(&gid, "@poll_bot").unwrap();
    bob.sync(0).unwrap();
    let (_, v) = call(&g, &token, "sendMessage", json!({ "chat_id": hex::encode(&gid), "text": "Pick one", "reply_markup": { "inline_keyboard": [[{ "text": "A", "callback_data": "a" }]] } }));
    let m2 = v["result"]["message_id"].as_str().unwrap().to_string();
    bot_text(&mut alice);
    bot_text(&mut bob);
    let q2 = alice.press_button(&gid, &m2, "a").unwrap();
    let got = updates(&g, &token, 3);
    assert!(got.iter().any(|u| u["callback_query"]["id"] == json!(q2)));
    call(&g, &token, "answerCallbackQuery", json!({ "callback_query_id": q2, "text": "A it is", "show_alert": true }));
    std::thread::sleep(Duration::from_secs(2));
    let ev = bob.sync(1).unwrap();
    assert!(!ev.iter().any(|e| matches!(e, Event::CallbackAnswer { .. } | Event::CallbackQuery { .. })), "{ev:?}");
    assert!(alice.sync(1).unwrap().iter().any(|e| matches!(e, Event::CallbackAnswer { alert: true, .. })));
    g.stop();
}

/// `chat.bots` released by the group's admin: no bot can be added, and
/// what a bot already in the group sends is dropped; nothing goes to it.
#[test]
fn chat_bots_released_drops_bot_payloads_and_refuses_adds() {
    let env = Env::new("chatbots");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let (_, token, g) = env.bot(&alice, "first_bot");
    let (_, _, g2) = env.bot(&alice, "second_bot");
    let gid = alice.create_group().unwrap();
    bob.confirm_contact(alice.account_id()).unwrap();
    alice.invite(&gid, bob.account_id()).unwrap();
    alice.add_bot(&gid, "@first_bot").unwrap();
    bob.sync(0).unwrap();
    alice.set_chat_feature(&gid, "chat.bots", false, None).unwrap();
    bob.sync(0).unwrap();
    // No adds.
    let e = alice.add_bot(&gid, "@second_bot").unwrap_err();
    assert!(e.to_string().contains("LOCKED_BY_CHAT"), "{e}");
    // Nothing reaches the bot, not even a command.
    alice.send_text(&gid, "/start").unwrap();
    assert!(texts(&updates(&g, &token, 3)).is_empty());
    // What the bot sends is dropped by everyone.
    let (st, v) = call(&g, &token, "sendMessage", json!({ "chat_id": hex::encode(&gid), "text": "still here" }));
    assert_eq!(st, 200, "{v}");
    std::thread::sleep(Duration::from_secs(2));
    for p in [&mut alice, &mut bob] {
        let ev = p.sync(1).unwrap();
        assert!(!ev.iter().any(|e| matches!(e, Event::Text { bot: true, .. })), "{ev:?}");
        assert!(ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains("chat.bots"))), "{ev:?}");
    }
    // Applied again: it works both ways.
    alice.set_chat_feature(&gid, "chat.bots", true, None).unwrap();
    bob.sync(0).unwrap();
    alice.send_text(&gid, "/start").unwrap();
    assert_eq!(texts(&updates(&g, &token, 3)), vec!["/start"]);
    call(&g, &token, "sendMessage", json!({ "chat_id": hex::encode(&gid), "text": "back" }));
    assert!(matches!(bot_text(&mut bob), Event::Text { bot: true, .. }));
    alice.add_bot(&gid, "@second_bot").unwrap();
    g.stop();
    g2.stop();
}

/// A bot reaches only people who contacted it: the server refuses to let
/// it start a chat with anyone else, even a member of its groups.
#[test]
fn a_bot_cannot_cold_message() {
    let env = Env::new("cold");
    let alice = env.device("alice");
    let mut carol = env.device("carol");
    let (b, token) = alice.create_bot("cold_bot", POW).unwrap();
    let mut bot = Session::create_bot_device(&env.dir.join("cold_bot.db").display().to_string(), "gw", &env.url, &token).unwrap();
    let g = bot.create_group().unwrap();
    let e = bot.invite(&g, carol.account_id()).unwrap_err();
    assert!(e.to_string().contains("BOT_NO_CONTACT"), "{e}");
    assert!(carol.sync(0).unwrap().is_empty());
    // carol starts a chat with it: from then on the bot may reach her.
    let dm = carol.create_group().unwrap();
    carol.add_bot(&dm, &b.info.account).unwrap();
    bot.sync(0).unwrap();
    let g2 = bot.create_group().unwrap();
    bot.invite(&g2, carol.account_id()).unwrap();
    bot.send_text(&g2, "your daily news").unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Text { bot: true, text, .. } if text == "your daily news")), "{ev:?}");
    // carol blocks it: it cannot start anything new with her.
    carol.block_bot(&b.info.account).unwrap();
    let g3 = bot.create_group().unwrap();
    assert!(bot.invite(&g3, carol.account_id()).unwrap_err().to_string().contains("BOT_NO_CONTACT"));
}

/// The local API needs the token and listens on loopback unless told
/// otherwise; after a token rotation the gateway is cut off until it
/// registers again, then catches up.
#[test]
fn local_api_token_and_rotation() {
    let env = Env::new("rotate");
    let mut alice = env.device("alice");
    let (bot, token, g) = env.bot(&alice, "rot_bot");
    let (st, v) = call(&g, "wrong", "getMe", json!({}));
    assert_eq!((st, v["ok"].as_bool()), (401, Some(false)));
    let (st, _) = call(&g, &format!("{bot}:{}", "A".repeat(43)), "getMe", json!({}));
    assert_eq!(st, 401);
    // The path form works too.
    let r = reqwest::blocking::get(format!("http://{}/bot{token}/getMe", g.addr)).unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(call(&g, &token, "noSuchMethod", json!({})).0, 404);

    let dm = alice.create_group().unwrap();
    alice.add_bot(&dm, &bot).unwrap();
    alice.send_text(&dm, "before").unwrap();
    assert_eq!(texts(&updates(&g, &token, 3)), vec!["before"]);
    // Rotated: the running gateway is cut off at once.
    let new = alice.rotate_bot_token(&bot).unwrap();
    alice.send_text(&dm, "during").unwrap();
    std::thread::sleep(Duration::from_secs(3));
    assert!(g.last_error().is_some_and(|e| e.contains("401")), "{:?}", g.last_error());
    let mut s = g.stop();
    // It registers again with the new token (same device, same mailbox).
    let device = s.device_id().to_string();
    s.reregister_bot(&new).unwrap();
    assert_eq!(s.device_id(), device);
    assert!(!s.bot_token_matches(&token).unwrap() && s.bot_token_matches(&new).unwrap());
    let g = start(s);
    assert_eq!(call(&g, &token, "getMe", json!({})).0, 401, "the old token no longer opens the local API");
    assert_eq!(texts(&updates(&g, &new, 4)), vec!["during"]);
    let (st, _) = call(&g, &new, "sendMessage", json!({ "chat_id": hex::encode(&dm), "text": "hello again" }));
    assert_eq!(st, 200);
    assert!(matches!(bot_text(&mut alice), Event::Text { bot: true, .. }));
    g.stop();

    // Not loopback: refused unless allowed.
    let (_, t2) = alice.create_bot("far_bot", POW).unwrap();
    let s2 = Session::create_bot_device(&env.dir.join("far.db").display().to_string(), "gw", &env.url, &t2).unwrap();
    let cfg = Config { listen: "0.0.0.0:0".parse().unwrap(), ..Config::default() };
    assert!(Gateway::start(s2, cfg).is_err());
}

/// Webhook mode: updates are posted to the bot's own endpoint with its
/// secret; getUpdates is refused meanwhile.
#[test]
fn webhook_mode() {
    use std::io::{Read, Write};
    let env = Env::new("webhook");
    let mut alice = env.device("alice");
    let (bot, token, g) = env.bot(&alice, "hook_bot");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (st, v) = call(&g, &token, "setWebhook", json!({ "url": format!("http://127.0.0.1:{port}/hook"), "secret_token": "s3cret" }));
    assert_eq!(st, 200, "{v}");
    assert_eq!(call(&g, &token, "setWebhook", json!({ "url": "http://192.0.2.1/hook" })).0, 400);
    assert_eq!(call(&g, &token, "getUpdates", json!({})).0, 409);
    let dm = alice.create_group().unwrap();
    alice.add_bot(&dm, &bot).unwrap();
    alice.send_text(&dm, "via hook").unwrap();
    listener.set_nonblocking(false).unwrap();
    let (mut conn, _) = listener.accept().unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut buf = vec![0u8; 65536];
    let mut got = Vec::new();
    while !String::from_utf8_lossy(&got).contains("via hook") {
        let n = conn.read(&mut buf).unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    let req = String::from_utf8_lossy(&got).to_lowercase();
    assert!(req.starts_with("post /hook") && req.contains("x-tree-bot-api-secret-token: s3cret"), "{req}");
    conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").unwrap();
    drop(conn);
    std::thread::sleep(Duration::from_secs(2));
    let (_, info) = call(&g, &token, "getWebhookInfo", json!({}));
    assert_eq!(info["result"]["pending_update_count"], json!(0), "{info}");
    assert_eq!(call(&g, &token, "deleteWebhook", json!({})).0, 200);
    assert_eq!(call(&g, &token, "getUpdates", json!({})).0, 200);
    g.stop();
}
