//! Reliable sending through a real server (PROTOCOL.md 6.13, 8.10): the
//! outbox survives lost answers, unreachable servers and crashes, and every
//! message arrives exactly once.
//!
//! A small TCP proxy sits between the sending device and the server. It can
//! forward normally, forward the request and then drop the server's answer
//! (the server has committed the send, the device sees a network error), or
//! drop the request (the server never sees it).

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use common::Env;
use tree_client::{Error, Event, OutboxState, Session};

const NORMAL: u8 = 0;
/// The request reaches the server; its answer is thrown away.
const DROP_ANSWER: u8 = 1;
/// The connection is closed before the request reaches the server.
const UNREACHABLE: u8 = 2;

struct Proxy {
    url: String,
    mode: Arc<AtomicU8>,
}

impl Proxy {
    fn new(upstream: &str) -> Self {
        let up = upstream.trim_start_matches("http://").to_string();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(NORMAL));
        let m = mode.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(client) = conn else { continue };
                let (up, m) = (up.clone(), m.clone());
                std::thread::spawn(move || relay(client, &up, &m));
            }
        });
        Proxy { url, mode }
    }

    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }
}

/// Copies both ways; the mode is checked on every chunk, so it also acts on
/// kept-alive connections. `DROP_ANSWER` drops only the answer to a send
/// (`POST /v1/messages`), so franking and the rest keep working.
fn relay(client: TcpStream, up: &str, mode: &Arc<AtomicU8>) {
    let Ok(server) = TcpStream::connect(up) else { return };
    let (mut from_client, mut to_server) = (client.try_clone().unwrap(), server.try_clone().unwrap());
    let (c2, s2, m2) = (client.try_clone().unwrap(), server.try_clone().unwrap(), mode.clone());
    let drop_next = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d2 = drop_next.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match from_client.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            match m2.load(Ordering::SeqCst) {
                UNREACHABLE => {
                    let _ = c2.shutdown(Shutdown::Both);
                    let _ = s2.shutdown(Shutdown::Both);
                    return;
                }
                DROP_ANSWER if buf[..n].starts_with(b"POST /v1/messages ") => d2.store(true, Ordering::SeqCst),
                _ => {}
            }
            if to_server.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = s2.shutdown(Shutdown::Write);
    });
    let (mut from_server, mut to_client) = (server, client);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from_server.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if drop_next.load(Ordering::SeqCst) {
            break;
        }
        if to_client.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to_client.shutdown(Shutdown::Both);
    let _ = from_server.shutdown(Shutdown::Both);
}

fn texts(ev: &[Event]) -> Vec<String> {
    ev.iter()
        .filter_map(|e| match e {
            Event::Text { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// Runs one query on the server database and returns the first column of
/// every row.
fn server_rows(env: &Env, q: &'static str) -> Vec<String> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", env.db.display())).await.unwrap();
        let rows: Vec<(String,)> = sqlx::query_as(q).fetch_all(&pool).await.unwrap();
        pool.close().await;
        rows.into_iter().map(|r| r.0).collect()
    })
}

/// alice (through the proxy) and bob (direct) in one accepted chat.
fn pair(env: &Env, proxy: &Proxy) -> (Session, Session, Vec<u8>) {
    let mut alice = Session::create(&env.profile("alice"), "alice passphrase", "alice", &proxy.url, 8).unwrap();
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.sync(0).unwrap();
    (alice, bob, g)
}

fn state_of(s: &Session, g: &[u8], id: &str) -> Option<OutboxState> {
    s.send_states(g).unwrap().get(id).copied()
}

/// The server commits a send but its answer is lost. The message shows as
/// pending; the retry sends the same bytes with the same key and the
/// server answers from its record. bob gets it exactly once, in order.
#[test]
fn lost_answer_then_retry_delivers_once() {
    let env = Env::new("outbox-lost");
    let proxy = Proxy::new(&env.url);
    let (mut alice, mut bob, g) = pair(&env, &proxy);

    proxy.set(DROP_ANSWER);
    let one = alice.send_text(&g, "one d41").unwrap();
    assert_eq!(state_of(&alice, &g, &one), Some(OutboxState::Retry), "pending after a lost answer");
    let h = alice.history(&g, 10).unwrap();
    assert_eq!(h.last().map(|m| m.text.as_deref()), Some(Some("one d41")), "in the history at once");
    let entry = alice.outbox().unwrap().pop().unwrap();
    assert_eq!(entry.attempts, 1);
    assert!((4..=5).contains(&(entry.next_at - tree_core_now())), "first wait: 5 s");
    // The server already delivered it.
    assert_eq!(texts(&bob.sync(0).unwrap()), vec!["one d41".to_string()]);

    // Back online: the user's next message pushes the waiting one first.
    proxy.set(NORMAL);
    let two = alice.send_text(&g, "two d41").unwrap();
    assert_eq!(state_of(&alice, &g, &one), Some(OutboxState::Sent));
    assert_eq!(state_of(&alice, &g, &two), Some(OutboxState::Sent));
    assert!(alice.outbox().unwrap().is_empty());
    // "one" again would be a duplicate: the server's record stopped it.
    assert_eq!(texts(&bob.sync(0).unwrap()), vec!["two d41".to_string()]);
    assert!(bob.sync(0).unwrap().is_empty());

    // The same through the plain sync loop, after the 5 s wait.
    proxy.set(DROP_ANSWER);
    let three = alice.send_text(&g, "three d41").unwrap();
    assert_eq!(state_of(&alice, &g, &three), Some(OutboxState::Retry));
    proxy.set(NORMAL);
    assert!(alice.send_pending().unwrap().is_empty(), "not due yet");
    assert_eq!(state_of(&alice, &g, &three), Some(OutboxState::Retry));
    std::thread::sleep(std::time::Duration::from_millis(5200));
    let ev = alice.sync(0).unwrap();
    assert!(ev.contains(&Event::Sent { group: g.clone(), id: Some(three.clone()) }), "{ev:?}");
    assert_eq!(texts(&bob.sync(0).unwrap()), vec!["three d41".to_string()]);
    // Each keyed send left one record on the server, under its sender's
    // device (alice: roster, three texts; bob: his name announcement).
    let devices = server_rows(&env, "SELECT device_id FROM idempotency_keys");
    assert_eq!(devices.iter().filter(|d| *d == alice.device_id()).count(), 4, "{devices:?}");
    assert_eq!(devices.iter().filter(|d| *d == bob.device_id()).count(), 1, "{devices:?}");
}

fn tree_core_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// The idempotency key at the API: the same key and request twice delivers
/// once; the same key with other content is refused; other keys are fine.
#[test]
fn same_key_twice_and_key_reuse_through_the_api() {
    let env = Env::new("outbox-api");
    let proxy = Proxy::new(&env.url);
    let (alice, mut bob, g) = pair(&env, &proxy);
    let (api, creds) = alice.waiter();
    let to = vec![bob.device_id().to_string()];
    let body = tree_server_app_body(&g);
    let key = [9u8; 16];
    let first = api.send_keyed(&creds, &to, &body, &key).unwrap();
    assert_eq!((first["delivered"].as_u64(), first["replayed"].as_bool()), (Some(1), Some(false)));
    let again = api.send_keyed(&creds, &to, &body, &key).unwrap();
    assert_eq!((again["delivered"].as_u64(), again["replayed"].as_bool()), (Some(1), Some(true)));
    let mut other = body.clone();
    other.push(0);
    match api.send_keyed(&creds, &to, &other, &key) {
        Err(Error::Server { status: 409, code }) => assert_eq!(code, "IDEMPOTENCY_KEY_REUSE"),
        r => panic!("{r:?}"),
    }
    // The same key with other recipients is another request too.
    let to2 = vec![bob.device_id().to_string(), alice.device_id().to_string()];
    assert!(matches!(api.send_keyed(&creds, &to2, &body, &key), Err(Error::Server { status: 409, .. })));
    // bob's mailbox got the body once (it is not a valid message for him,
    // so it is dropped, but only once).
    let ev = bob.sync(0).unwrap();
    assert_eq!(ev.iter().filter(|e| matches!(e, Event::Dropped { .. } | Event::Held)).count(), 1, "{ev:?}");
}

/// An application-message envelope header for `g` (the server reads only
/// the header; the rest is opaque).
fn tree_server_app_body(g: &[u8]) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&[0xee; 32]);
    v.extend_from_slice(&[0, 1, 0, 2]);
    v.push(g.len() as u8);
    v.extend_from_slice(g);
    v.extend_from_slice(&1u64.to_be_bytes());
    v.push(1);
    v.extend_from_slice(b"opaque");
    v
}

/// The app dies while an attempt is on the wire (the item is left in
/// `sending`). On open it becomes `retry` and goes out once: whether or not
/// the server had received the lost attempt.
#[test]
fn crash_while_sending_recovers_and_sends_once() {
    let env = Env::new("outbox-crash");
    let proxy = Proxy::new(&env.url);
    let (mut alice, mut bob, g) = pair(&env, &proxy);
    let path = env.profile("alice");

    // Case 1: the server got it before the crash.
    proxy.set(DROP_ANSWER);
    let a = alice.send_text(&g, "before crash 1").unwrap();
    // Case 2: the server never saw it.
    proxy.set(UNREACHABLE);
    let b = alice.send_text(&g, "before crash 2").unwrap();
    let items = alice.outbox().unwrap();
    assert_eq!(items.len(), 2);
    drop(alice);
    // Emulate the crash: both attempts were running when the app died.
    {
        let c = tree_core::Client::open(&path, "alice passphrase").unwrap();
        for i in &items {
            c.outbox_mark_sending(&i.local_id).unwrap();
        }
    }
    proxy.set(NORMAL);
    let (mut alice, _) = Session::open(&path, "alice passphrase").unwrap();
    let after = alice.outbox().unwrap();
    assert!(after.iter().all(|i| i.state == OutboxState::Retry && i.next_at <= tree_core_now()), "{after:?}");
    assert_eq!(state_of(&alice, &g, &a), Some(OutboxState::Retry));
    alice.sync(0).unwrap();
    assert_eq!(state_of(&alice, &g, &a), Some(OutboxState::Sent));
    assert_eq!(state_of(&alice, &g, &b), Some(OutboxState::Sent));
    assert_eq!(texts(&bob.sync(0).unwrap()), vec!["before crash 1".to_string(), "before crash 2".to_string()]);
    assert!(bob.sync(0).unwrap().is_empty());
}

/// While the server is unreachable, the user's own sends do not use up the
/// waiting items' attempts; after the last counted attempt an item is
/// failed, the app can retry it (fresh budget) or cancel it (gone from the
/// history). Chat messages need the server's franking tag: made offline,
/// they wait unsealed and are sealed once, later.
#[test]
fn backoff_failed_after_n_retry_and_cancel() {
    let env = Env::new("outbox-fail");
    let proxy = Proxy::new(&env.url);
    let (mut alice, mut bob, g) = pair(&env, &proxy);
    let path = env.profile("alice");

    proxy.set(UNREACHABLE);
    let a = alice.send_text(&g, "offline a").unwrap();
    let b = alice.send_text(&g, "offline b").unwrap();
    let c = alice.send_text(&g, "offline c").unwrap();
    let items = alice.outbox().unwrap();
    // a: one counted attempt (its own); the user's later sends pushed it
    // again without counting; b and c wait behind it, in order.
    let seen: Vec<_> = items.iter().map(|i| (i.state, i.attempts)).collect();
    assert_eq!(seen, vec![(OutboxState::Retry, 1), (OutboxState::Queued, 0), (OutboxState::Queued, 0)], "{items:?}");
    assert!(alice.history(&g, 10).unwrap().iter().any(|m| m.id == c));
    assert_eq!(state_of(&alice, &g, &c), Some(OutboxState::Queued));
    // Typing indicators never overtake waiting messages (and need no server).
    alice.apply_feature("user.typing", None).unwrap();
    alice.set_typing(&g, true).unwrap();

    // Bring a and b to their last attempt and make them due.
    drop(alice);
    {
        let cl = tree_core::Client::open(&path, "alice passphrase").unwrap();
        for i in &items[..2] {
            for _ in i.attempts..tree_core::storage::outbox::MAX_ATTEMPTS - 1 {
                cl.outbox_mark_retry(&i.local_id, true, tree_core_now() - 100_000, "network").unwrap();
            }
        }
    }
    let (mut alice, _) = Session::open(&path, "alice passphrase").unwrap();
    let ev = alice.send_pending().unwrap();
    let failed: Vec<_> = ev
        .iter()
        .filter_map(|e| match e {
            Event::SendFailed { id, .. } => id.clone(),
            _ => None,
        })
        .collect();
    assert_eq!(failed, vec![a.clone(), b.clone()], "{ev:?}");
    assert_eq!(state_of(&alice, &g, &a), Some(OutboxState::Failed));
    assert_eq!(state_of(&alice, &g, &c), Some(OutboxState::Retry), "c's own budget is left");

    // Back online: retry a (fresh budget), cancel b.
    proxy.set(NORMAL);
    assert!(matches!(alice.retry_send(&c), Err(Error::Usage(_))), "only failed items");
    assert!(alice.retry_send(&a).unwrap());
    assert_eq!(state_of(&alice, &g, &a), Some(OutboxState::Sent));
    alice.cancel_send(&b).unwrap();
    assert!(state_of(&alice, &g, &b).is_none());
    assert!(!alice.history(&g, 10).unwrap().iter().any(|m| m.id == b), "cancelled: out of the history");
    assert!(matches!(alice.cancel_send(&b), Err(Error::Usage(_))));
    // c goes with the next forced send; bob sees a, c, d once each.
    alice.send_text(&g, "online d").unwrap();
    assert!(alice.outbox().unwrap().is_empty());
    assert_eq!(texts(&bob.sync(0).unwrap()), vec!["offline a", "offline c", "online d"]);
}

/// Items of two groups, and of two senders, never share an idempotency
/// key, and the server keeps them apart.
#[test]
fn two_groups_two_senders_never_collide() {
    let env = Env::new("outbox-groups");
    let proxy = Proxy::new(&env.url);
    let (mut alice, mut bob, g1) = pair(&env, &proxy);
    let g2 = alice.create_group().unwrap();
    alice.invite(&g2, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    let _ = bob.accept_request(&g2);
    for i in 0..3 {
        alice.send_text(&g1, &format!("g1 {i}")).unwrap();
        alice.send_text(&g2, &format!("g2 {i}")).unwrap();
        bob.send_text(&g1, &format!("bob g1 {i}")).unwrap();
        bob.send_text(&g2, &format!("bob g2 {i}")).unwrap();
    }
    let keys = server_rows(&env, "SELECT hex(key) FROM idempotency_keys");
    let mut unique = keys.clone();
    unique.sort();
    unique.dedup();
    assert!(keys.len() >= 12, "{}", keys.len());
    assert_eq!(unique.len(), keys.len(), "every item has its own key");
    let ev = bob.sync(0).unwrap();
    assert_eq!(texts(&ev).len(), 6);
    assert_eq!(texts(&alice.sync(0).unwrap()).len(), 6);
}
