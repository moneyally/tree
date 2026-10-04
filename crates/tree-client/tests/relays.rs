//! GIFs and map tiles through the server's relays, with a fake upstream:
//! `server.gif_relay` / `server.map_relay` toggled by the operator,
//! `chat.gifs` toggled by the chat admin, a sent GIF travelling as a normal
//! encrypted attachment (receivers never touch the relay), and the
//! upstream never seeing the device.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use common::Env;
use reqwest::Method;
use tree_client::{Error, Event, Payload};

/// Requests the fake upstream got: (path with query, lower-case header lines).
type Seen = Arc<Mutex<Vec<(String, Vec<String>)>>>;

const GIF: &[u8] = b"GIF89a fake animation 9d2";
const TILE: &[u8] = b"\x89PNG\r\n\x1a\nfake tile";

/// A tiny HTTP/1.1 upstream: `/search` (JSON), `/media/<name>` (a GIF),
/// `/tiles/<z>/<x>/<y>.png` (a PNG).
fn upstream() -> (String, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let (b, s) = (base.clone(), seen.clone());
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut r = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let mut headers = Vec::new();
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                headers.push(h.trim().to_ascii_lowercase());
            }
            s.lock().unwrap().push((path.clone(), headers));
            let (ctype, body): (&str, Vec<u8>) = if path.starts_with("/search") {
                let j = serde_json::json!({ "results": [
                    { "title": "cat", "url": format!("{b}/media/cat.gif"), "preview": format!("{b}/media/cat.gif"), "width": 200, "height": 150 },
                    { "title": "elsewhere", "url": "ftp://bad.example/x.gif" },
                ]});
                ("application/json", j.to_string().into_bytes())
            } else if path.starts_with("/media/") {
                ("image/gif", GIF.to_vec())
            } else {
                ("image/png", TILE.to_vec())
            };
            let head = format!("HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = conn.write_all(head.as_bytes());
            let _ = conn.write_all(&body);
        }
    });
    (base, seen)
}

#[test]
fn gifs_and_map_tiles_through_the_relay() {
    let (base, seen) = upstream();
    let env = Env::with("relays", |c| {
        c.gif_provider_url = Some(format!("{base}/search"));
        c.map_tile_url = Some(format!("{base}/tiles/{{z}}/{{x}}/{{y}}.png"));
        c.relay_allow_http = true;
    });
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();

    // Both relays start released: unavailable, apps hide them.
    let st = alice.relay_status().unwrap();
    assert!(!st.gif && !st.map);
    assert!(matches!(alice.gif_search("cat", 5), Err(Error::Server { status: 503, code }) if code == "RELAY_UNAVAILABLE"));
    assert!(matches!(alice.map_tile(1, 0, 0), Err(Error::Server { status: 503, .. })));
    assert!(seen.lock().unwrap().is_empty(), "nothing reached the upstream");

    // The operator applies them.
    assert_eq!(env.operator(Method::POST, "/v1/features/server.gif_relay/apply").0, 200);
    assert_eq!(env.operator(Method::POST, "/v1/features/server.map_relay/apply").0, 200);
    let st = alice.relay_status().unwrap();
    assert!(st.gif && st.map);

    let found = alice.gif_search("cat", 5).unwrap();
    assert_eq!(found.len(), 1, "a result the relay may not fetch is left out");
    assert_eq!((found[0].title.as_str(), found[0].width, found[0].height), ("cat", Some(200), Some(150)));
    assert!(!found[0].media.contains("127.0.0.1"), "media ids are opaque");
    assert_eq!(alice.gif_media(found[0].preview.as_deref().unwrap()).unwrap().0, GIF);

    // Sending: alice's device fetches it and uploads it encrypted; bob
    // opens it from the attachment, never from the relay.
    let before = seen.lock().unwrap().len();
    let f = alice.send_gif(&g, &found[0]).unwrap();
    assert!(f.gif && f.mime == "image/gif");
    assert_eq!(seen.lock().unwrap().len(), before + 1, "one fetch by the sender");
    let ev = bob.sync(0).unwrap();
    let got = ev.iter().find_map(|e| match e { Event::File { file, .. } => Some(file.clone()), _ => None }).unwrap();
    assert!(got.gif);
    assert_eq!(bob.download(&got).unwrap(), GIF);
    assert_eq!(seen.lock().unwrap().len(), before + 1, "the receiver never reached the upstream");

    // A map tile.
    assert_eq!(alice.map_tile(3, 4, 5).unwrap(), TILE);
    assert!(alice.map_tile(3, 8, 0).is_err(), "no such tile");

    // What the upstream saw: the words and the tile, nothing of the device.
    for (path, headers) in seen.lock().unwrap().iter() {
        for h in headers {
            for bad in ["x-forwarded-for", "forwarded", "x-real-ip", "via", "x-tree-", "cookie", "authorization"] {
                assert!(!h.starts_with(bad), "{path}: {h}");
            }
            assert!(!h.contains(alice.device_id()) && !h.contains(alice.account_id()), "{path}: {h}");
        }
    }
    let paths: Vec<String> = seen.lock().unwrap().iter().map(|(p, _)| p.clone()).collect();
    assert!(paths.iter().any(|p| p.starts_with("/search?q=cat&limit=5")), "{paths:?}");
    assert!(paths.iter().any(|p| p == "/tiles/3/4/5.png"), "{paths:?}");

    // chat.gifs released: the sender refuses, receivers drop a flagged file.
    alice.set_chat_feature(&g, "chat.gifs", false, None).unwrap();
    bob.sync(0).unwrap();
    assert!(matches!(alice.send_gif(&g, &found[0]), Err(Error::Feature(c)) if c == "LOCKED_BY_CHAT"));
    let forged = tree_client::FileInfo { msg_id: "6f6f".into(), ..got.clone() };
    bob.send_unchecked(&g, &Payload::File(forged)).unwrap();
    assert!(alice.sync(0).unwrap().iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains("chat.gifs"))));
    alice.set_chat_feature(&g, "chat.gifs", true, None).unwrap();
    bob.sync(0).unwrap();
    alice.send_gif(&g, &found[0]).unwrap();
    assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::File { file, .. } if file.gif)));

    // The operator releases the relays again: unavailable.
    assert_eq!(env.operator(Method::POST, "/v1/features/server.gif_relay/release").0, 200);
    assert_eq!(env.operator(Method::POST, "/v1/features/server.map_relay/release").0, 200);
    assert!(!alice.relay_status().unwrap().gif);
    assert!(matches!(alice.gif_search("cat", 5), Err(Error::Server { status: 503, .. })));
    assert!(matches!(alice.gif_media(&found[0].media), Err(Error::Server { status: 503, .. })));
    assert!(matches!(alice.map_tile(1, 0, 0), Err(Error::Server { status: 503, .. })));
}
