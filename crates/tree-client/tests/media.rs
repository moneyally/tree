//! Media through a real server (PROTOCOL.md 6.12, 6.13): chunked and padded
//! files with the sender's metadata inside the message, resumable uploads
//! through the outbox (offline, interrupted, paused, refused), resumable
//! downloads, view-once and voice with multi-chunk files, and the
//! auto-download rules.
//!
//! A small TCP proxy between the sending device and the server can cut the
//! network, at once or after a number of uploaded parts.

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;

use common::Env;
use tree_client::{Error, Event, FileInfo, MediaMeta, Network, OutboxState, SendOptions, Session, Source, TransferState};
use tree_core::attachment::{ciphertext_len, padded_len};

const NORMAL: u8 = 0;
const UNREACHABLE: u8 = 2;
/// Upload part size of the test servers (small, so files have many parts).
const PART: usize = 64 * 1024;

struct Proxy {
    url: String,
    mode: Arc<AtomicU8>,
    /// Upload parts that reached the server.
    puts: Arc<AtomicUsize>,
    /// After this many forwarded parts the network goes away.
    cut_after: Arc<AtomicUsize>,
}

impl Proxy {
    fn new(upstream: &str) -> Self {
        let up = upstream.trim_start_matches("http://").to_string();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let p = Proxy {
            url,
            mode: Arc::new(AtomicU8::new(NORMAL)),
            puts: Arc::new(AtomicUsize::new(0)),
            cut_after: Arc::new(AtomicUsize::new(usize::MAX)),
        };
        let (m, puts, cut) = (p.mode.clone(), p.puts.clone(), p.cut_after.clone());
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(client) = conn else { continue };
                let (up, m, puts, cut) = (up.clone(), m.clone(), puts.clone(), cut.clone());
                std::thread::spawn(move || relay(client, &up, &m, &puts, &cut));
            }
        });
        p
    }

    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    /// The network goes away after `n` more upload parts.
    fn cut_after_parts(&self, n: usize) {
        self.cut_after.store(self.puts.load(Ordering::SeqCst) + n, Ordering::SeqCst);
    }

    fn reset(&self) {
        self.cut_after.store(usize::MAX, Ordering::SeqCst);
        self.set(NORMAL);
    }

    fn parts(&self) -> usize {
        self.puts.load(Ordering::SeqCst)
    }
}

fn relay(client: TcpStream, up: &str, mode: &Arc<AtomicU8>, puts: &Arc<AtomicUsize>, cut: &Arc<AtomicUsize>) {
    let Ok(server) = TcpStream::connect(up) else { return };
    let (mut from_client, mut to_server) = (client.try_clone().unwrap(), server.try_clone().unwrap());
    let (c2, s2, m2, puts, cut) = (client.try_clone().unwrap(), server.try_clone().unwrap(), mode.clone(), puts.clone(), cut.clone());
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = match from_client.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if buf[..n].starts_with(b"PUT /v1/uploads/") {
                if puts.load(Ordering::SeqCst) >= cut.load(Ordering::SeqCst) {
                    m2.store(UNREACHABLE, Ordering::SeqCst);
                } else {
                    puts.fetch_add(1, Ordering::SeqCst);
                }
            }
            if m2.load(Ordering::SeqCst) == UNREACHABLE {
                let _ = c2.shutdown(Shutdown::Both);
                let _ = s2.shutdown(Shutdown::Both);
                return;
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
        if to_client.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to_client.shutdown(Shutdown::Both);
    let _ = from_server.shutdown(Shutdown::Both);
}

fn env(tag: &str) -> Env {
    Env::with(tag, |c| c.upload_chunk_bytes = PART)
}

/// alice (through `via`) and bob (direct), contacts, in one accepted chat.
fn pair(env: &Env, via: &str) -> (Session, Session, Vec<u8>) {
    let mut alice = Session::create(&env.profile("alice"), "alice passphrase", "alice", via, 8).unwrap();
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.sync(0).unwrap();
    (alice, bob, g)
}

fn data(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| (i.wrapping_mul(2_654_435_761).wrapping_add(seed) >> 13) as u8).collect()
}

fn files(ev: &[Event]) -> Vec<(FileInfo, bool)> {
    ev.iter()
        .filter_map(|e| match e {
            Event::File { file, auto_download, .. } => Some((file.clone(), *auto_download)),
            _ => None,
        })
        .collect()
}

fn texts(ev: &[Event]) -> Vec<String> {
    ev.iter()
        .filter_map(|e| match e {
            Event::Text { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn server_file(env: &Env, id: &str) -> PathBuf {
    env.dir.join("attachments").join(id)
}

fn media_out(env: &Env, who: &str) -> Vec<PathBuf> {
    match std::fs::read_dir(format!("{}.media/out", env.profile(who))) {
        Ok(d) => d.map(|e| e.unwrap().path()).collect(),
        Err(_) => vec![],
    }
}

fn state_of(s: &Session, g: &[u8], id: &str) -> Option<OutboxState> {
    s.send_states(g).unwrap().get(id).copied()
}

/// A multi-chunk file from a path, with the sender's metadata and preview
/// picture inside the message; the server holds only the padded
/// ciphertext; downloads into a file; tampering is refused; files in one
/// bucket look the same size to the server.
#[test]
fn chunked_file_end_to_end_with_metadata_and_padding() {
    let env = env("media-e2e");
    let (mut alice, mut bob, g) = pair(&env, &env.url);
    let marker = b"PLAINTEXT-MARKER-77a1";
    let mut video = data(2 * 1024 * 1024 + 300_000, 1);
    video.extend_from_slice(marker);
    let src = env.dir.join("clip.mp4");
    std::fs::write(&src, &video).unwrap();
    let thumb = b"\x89PNG small preview".to_vec();
    let o = SendOptions {
        meta: MediaMeta { width: Some(1920), height: Some(1080), duration_ms: Some(4200), thumb: Some(thumb.clone()) },
        ..Default::default()
    };
    let sent = alice.send_media(&g, Source::Path(&src), "바다.mp4", "video/mp4", &o).unwrap();
    assert!(!sent.id.is_empty(), "uploaded and sent at once");
    assert_eq!((sent.size, sent.width, sent.height, sent.duration_ms), (video.len() as u64, Some(1920), Some(1080), Some(4200)));
    assert!(media_out(&env, "alice").is_empty(), "the blob is deleted once sent");
    // The sender's own history knows the id (to show and fetch it again).
    let own = alice.history(&g, 10).unwrap().pop().unwrap();
    let own: FileInfo = serde_json::from_slice(own.data.as_deref().unwrap()).unwrap();
    assert_eq!(own, sent);

    let got = files(&bob.sync(0).unwrap());
    assert_eq!(got.len(), 1);
    let file = got[0].0.clone();
    assert_eq!(file, sent);
    assert_eq!(file.thumbnail(), Some(thumb));

    // The server holds padded ciphertext only: bucket size, no marker, no name.
    let stored = std::fs::read(server_file(&env, &file.id)).unwrap();
    assert_eq!(stored.len() as u64, ciphertext_len(video.len() as u64));
    assert_eq!(padded_len(video.len() as u64) % (64 * 1024), 0, "Padmé above 1 MiB: 64 KiB steps here");
    assert!(!stored.windows(marker.len()).any(|w| w == marker));
    let db = std::fs::read(&env.db).unwrap();
    assert!(!db.windows("바다.mp4".len()).any(|w| w == "바다.mp4".as_bytes()));
    assert_eq!(env.sql_i64("SELECT size FROM attachments WHERE id = ?", &file.id), stored.len() as i64);

    // Download into a file.
    let out = env.dir.join("bob-clip.mp4");
    bob.download_to(&file, &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), video);
    assert!(!Path::new(&format!("{}.tree-part", out.display())).exists());
    assert!(bob.transfers().list().is_empty());

    // A tampered blob is refused and nothing is written.
    let mut t = stored.clone();
    t[3 * 1024 * 1024 / 2] ^= 1;
    std::fs::write(server_file(&env, &file.id), &t).unwrap();
    let out2 = env.dir.join("tampered.mp4");
    assert!(bob.download_to(&file, &out2).is_err());
    assert!(!out2.exists());
    std::fs::write(server_file(&env, &file.id), &stored).unwrap();
    assert_eq!(bob.download(&file).unwrap(), video);
    // A reference that lies about the size or content is refused.
    let mut lie = file.clone();
    lie.size -= 1;
    assert!(bob.download(&lie).is_err());

    // Two files in one bucket look the same to the server.
    let a = alice.send_file(&g, &data(1500, 2), "a.txt", "text/plain", false).unwrap();
    let b = alice.send_file(&g, &data(1900, 3), "b.txt", "text/plain", false).unwrap();
    let (la, lb) = (std::fs::metadata(server_file(&env, &a.id)).unwrap().len(), std::fs::metadata(server_file(&env, &b.id)).unwrap().len());
    assert_eq!((la, lb), (32 + 2048 + 16, 32 + 2048 + 16));
}

/// View-once and voice work with multi-chunk files.
#[test]
fn view_once_and_voice_with_chunked_media() {
    let env = env("media-vo");
    let (mut alice, mut bob, g) = pair(&env, &env.url);
    let photo = data(1024 * 1024 + 4321, 4);
    let vo = alice.send_media(&g, Source::Bytes(&photo), "p.jpg", "image/jpeg", &SendOptions { view_once: true, ..Default::default() }).unwrap();
    assert!(alice.history(&g, 5).unwrap().last().unwrap().data.is_none(), "the sender keeps no reference");
    let voice = data(1024 * 1024 + 99, 5);
    let v = alice.send_voice(&g, &voice, "audio/ogg", 61_000).unwrap();
    let got = files(&bob.sync(0).unwrap());
    assert_eq!(got.iter().map(|f| f.0.clone()).collect::<Vec<_>>(), vec![vo.clone(), v.clone()]);
    assert!(!got[0].1, "view-once never downloads by itself");
    assert_eq!(bob.download(&got[0].0).unwrap(), photo);
    assert_eq!(bob.received_file(&vo.id).unwrap(), None, "opened once, reference gone");
    let msg = bob.history(&g, 10).unwrap().into_iter().find(|m| m.id == vo.msg_id).unwrap();
    assert!(msg.data.is_none());
    let got_voice = &got[1].0;
    assert!(got_voice.voice && got_voice.duration_ms == Some(61_000));
    assert_eq!(bob.download(got_voice).unwrap(), voice);
    assert!(bob.received_file(&v.id).unwrap().is_some(), "not view-once: kept");
}

/// The app is closed after some parts and opened again: the upload goes on
/// from where the server got to. Then the network goes away mid-upload;
/// back online it continues, and no part is sent twice. An upload the
/// server dropped (unfinished after a day) starts again.
#[test]
fn upload_resumes_after_interruption_and_restart() {
    let env = env("media-resume");
    let proxy = Proxy::new(&env.url);
    let (mut alice, mut bob, g) = pair(&env, &proxy.url);
    let path = env.profile("alice");
    let big = data(17 * PART - 1000, 6); // 17 parts once padded and sealed
    let total = ciphertext_len(big.len() as u64);
    let parts = total.div_ceil(PART as u64) as usize;

    // At most 5 parts per pass: the send returns with the upload under way.
    alice.set_upload_slice(Some(5 * PART as u64));
    let f = alice.send_file(&g, &big, "big.bin", "application/octet-stream", false).unwrap();
    assert!(f.id.is_empty(), "not uploaded yet");
    assert!(alice.uploading().unwrap());
    let t = alice.transfers().get(&f.msg_id).unwrap();
    assert_eq!((t.upload, t.done, t.total, t.state), (true, 5 * PART as u64, total, TransferState::Queued));
    assert_eq!(proxy.parts(), 5);
    assert_eq!(state_of(&alice, &g, &f.msg_id), Some(OutboxState::Queued));
    assert_eq!(media_out(&env, "alice").len(), 1, "the blob waits on disk");

    // The app stops; the next start resumes from part 5.
    drop(alice);
    let (mut alice, _) = Session::open(&path, "alice passphrase").unwrap();
    assert_eq!(alice.transfers().get(&f.msg_id).map(|t| t.state), Some(TransferState::Queued));
    assert_eq!(env.sql_i64("SELECT received FROM uploads WHERE ?1 = ?1", ""), 5);
    // The network goes away after three more parts.
    proxy.cut_after_parts(3);
    let ev = alice.send_pending().unwrap();
    assert!(!ev.iter().any(|e| matches!(e, Event::SendFailed { .. })), "{ev:?}");
    assert_eq!(env.sql_i64("SELECT received FROM uploads WHERE ?1 = ?1", ""), 8);
    let item = alice.outbox().unwrap().pop().unwrap();
    assert_eq!((item.state, item.attempts), (OutboxState::Retry, 0), "progress made: the attempt does not count");
    assert_eq!(alice.transfers().get(&f.msg_id).unwrap().state, TransferState::Failed);

    // Back online: the rest, nothing twice.
    proxy.reset();
    alice.set_upload_slice(None);
    let ev = alice.send_pending().unwrap();
    assert!(ev.contains(&Event::Sent { group: g.clone(), id: Some(f.msg_id.clone()) }), "{ev:?}");
    assert_eq!(proxy.parts(), parts, "every part reached the server exactly once");
    assert!(media_out(&env, "alice").is_empty());
    assert!(alice.transfers().list().is_empty());
    let got = files(&bob.sync(0).unwrap());
    assert_eq!(got.len(), 1);
    assert_eq!(bob.download(&got[0].0).unwrap(), big);
    assert!(bob.sync(0).unwrap().is_empty(), "delivered once");

    // The server drops an unfinished upload (a day passed): the client
    // starts it again from the first part.
    alice.set_upload_slice(Some(2 * PART as u64));
    let small = &big[..5 * PART];
    let f2 = alice.send_file(&g, small, "again.bin", "application/octet-stream", false).unwrap();
    assert_eq!(env.sql("DELETE FROM uploads WHERE received = 2 AND ?1 = ?1", ""), 1);
    let before = proxy.parts();
    alice.set_upload_slice(None);
    let ev = alice.send_pending().unwrap();
    assert!(ev.contains(&Event::Sent { group: g.clone(), id: Some(f2.msg_id.clone()) }), "{ev:?}");
    let parts2 = ciphertext_len(small.len() as u64).div_ceil(PART as u64) as usize;
    assert_eq!(proxy.parts() - before, parts2, "started again from the first part");
    let got = files(&bob.sync(0).unwrap());
    assert_eq!(bob.download(&got[0].0).unwrap(), small);
}

/// Offline, a file waits in the outbox (pending in the chat) and goes, in
/// order, once the server is back. A refused upload (quota) fails the
/// message: retry once the quota allows, or cancel (blob and history entry
/// gone).
#[test]
fn offline_queue_and_refused_upload() {
    let env = Env::with("media-offline", |c| {
        c.upload_chunk_bytes = PART;
        // The first file (512 KiB bucket) and a 3 MiB one do not both fit.
        c.upload_quota_bytes_per_day = 3 * 1024 * 1024 + 512 * 1024;
    });
    let proxy = Proxy::new(&env.url);
    let (mut alice, mut bob, g) = pair(&env, &proxy.url);

    proxy.set(UNREACHABLE);
    let photo = data(300_000, 7);
    let f = alice.send_file(&g, &photo, "offline.jpg", "image/jpeg", false).unwrap();
    assert!(f.id.is_empty());
    assert_eq!(state_of(&alice, &g, &f.msg_id), Some(OutboxState::Retry));
    let h = alice.history(&g, 5).unwrap();
    assert_eq!(h.last().map(|m| (m.kind.as_str(), m.text.as_deref())), Some(("file", Some("offline.jpg"))), "in the chat at once");
    let t = alice.send_text(&g, "see the photo").unwrap();
    assert_eq!(state_of(&alice, &g, &t), Some(OutboxState::Queued), "waits behind the file");

    // Back online: the user's next send pushes everything, in order.
    proxy.set(NORMAL);
    alice.send_text(&g, "online now").unwrap();
    assert!(alice.outbox().unwrap().is_empty());
    let ev = bob.sync(0).unwrap();
    let order: Vec<String> = ev
        .iter()
        .filter_map(|e| match e {
            Event::File { file, .. } => Some(file.name.clone()),
            Event::Text { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(order, vec!["offline.jpg", "see the photo", "online now"]);
    assert_eq!(bob.download(&files(&ev)[0].0).unwrap(), photo);

    // The quota (3.5 MiB a day) has no room for a 3 MiB file now: refused, failed.
    let big = data(3 * 1024 * 1024, 8);
    match alice.send_file(&g, &big, "big.bin", "application/octet-stream", false) {
        Err(Error::Server { status: 403, code }) => assert_eq!(code, "QUOTA_EXCEEDED"),
        r => panic!("{r:?}"),
    }
    let failed = alice.outbox().unwrap().pop().unwrap();
    let id = failed.message_id.clone().unwrap();
    assert_eq!(failed.state, OutboxState::Failed);
    assert!(alice.retry_send(&id).is_err(), "still over the quota");
    // A new day (the quota counter goes): the user retries, it goes.
    env.sql("DELETE FROM upload_quota WHERE ?1 = ?1", "");
    assert!(alice.retry_send(&id).unwrap());
    assert_eq!(files(&bob.sync(0).unwrap()).len(), 1);

    // Refused again; this time the user cancels: blob and entry go.
    assert!(alice.send_file(&g, &big, "big2.bin", "application/octet-stream", false).is_err());
    let id = alice.outbox().unwrap().pop().unwrap().message_id.unwrap();
    assert_eq!(media_out(&env, "alice").len(), 1);
    alice.cancel_send(&id).unwrap();
    assert!(media_out(&env, "alice").is_empty());
    assert!(!alice.history(&g, 20).unwrap().iter().any(|m| m.id == id));
    assert!(alice.transfers().list().is_empty());
}

/// Pause holds the upload (and the chat's later messages); resume sends
/// both in order; a paused upload can be cancelled (the server drops it).
#[test]
fn pause_resume_and_cancel_upload() {
    let env = env("media-pause");
    let proxy = Proxy::new(&env.url);
    let (mut alice, mut bob, g) = pair(&env, &proxy.url);
    let file = data(6 * PART, 9);
    alice.set_upload_slice(Some(2 * PART as u64));
    let f = alice.send_file(&g, &file, "movie.bin", "video/mp4", false).unwrap();
    alice.pause_transfer(&f.msg_id).unwrap();
    let before = proxy.parts();
    alice.send_pending().unwrap();
    assert_eq!(proxy.parts(), before, "paused: nothing goes");
    assert_eq!(alice.transfers().get(&f.msg_id).unwrap().state, TransferState::Paused);
    assert!(!alice.uploading().unwrap());
    let t = alice.send_text(&g, "after the movie").unwrap();
    assert_eq!(state_of(&alice, &g, &t), Some(OutboxState::Queued));
    assert!(bob.sync(0).unwrap().iter().all(|e| !matches!(e, Event::Text { .. } | Event::File { .. })));

    alice.set_upload_slice(None);
    assert!(alice.resume_transfer(&f.msg_id).unwrap());
    assert!(alice.outbox().unwrap().is_empty());
    let ev = bob.sync(0).unwrap();
    assert_eq!(files(&ev).len(), 1);
    assert_eq!(texts(&ev), vec!["after the movie".to_string()]);

    // Cancel a paused upload: gone here and on the server.
    alice.set_upload_slice(Some(PART as u64));
    let f2 = alice.send_file(&g, &file, "second.bin", "video/mp4", false).unwrap();
    assert_eq!(env.sql_i64("SELECT COUNT(*) FROM uploads WHERE ?1 = ?1", ""), 1);
    alice.pause_transfer(&f2.msg_id).unwrap();
    alice.cancel_send(&f2.msg_id).unwrap();
    assert_eq!(env.sql_i64("SELECT COUNT(*) FROM uploads WHERE ?1 = ?1", ""), 0);
    assert!(media_out(&env, "alice").is_empty());
    assert!(alice.outbox().unwrap().is_empty());
    assert!(matches!(alice.pause_transfer(&f2.msg_id), Err(Error::Usage(_))));
}

/// `user.auto_download`: only contacts' files, only on the networks and up
/// to the size the option allows, never view-once, nothing when released.
/// The app reports the network.
#[test]
fn auto_download_rules() {
    let env = env("media-auto");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut carol = env.device("carol");
    // bob knows alice; carol is a stranger to bob (alice's contact only).
    bob.add_contact(alice.account_id()).unwrap();
    carol.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    alice.invite(&g, carol.account_id()).unwrap();
    for s in [&mut bob, &mut carol, &mut alice] {
        s.sync(0).unwrap();
    }
    for s in [&mut bob, &mut carol, &mut alice] {
        s.sync(0).unwrap();
    }
    let small = data(500, 10);
    let check = |from: &mut Session, bob: &mut Session, o: SendOptions, n: usize| -> bool {
        from.send_media(&g, Source::Bytes(&small[..n]), "f", "application/octet-stream", &o).unwrap();
        let got = files(&bob.sync(0).unwrap());
        assert_eq!(got.len(), 1);
        got[0].1
    };
    let plain = SendOptions::default;

    // Applied by default with `wifi:20m`, but the app has not said the network.
    assert_eq!(bob.feature("user.auto_download").unwrap().option.as_deref(), None);
    assert!(!check(&mut alice, &mut bob, plain(), 500), "network unknown");
    bob.set_network(Network::Wifi);
    assert!(check(&mut alice, &mut bob, plain(), 500), "a contact, Wi-Fi, small");
    assert!(!check(&mut carol, &mut bob, plain(), 500), "a stranger: never");
    assert!(!check(&mut alice, &mut bob, SendOptions { view_once: true, ..plain() }, 500), "view-once: never");
    bob.set_network(Network::Mobile);
    assert!(!check(&mut alice, &mut bob, plain(), 500), "wifi only");

    // The user changes the option: mobile too, but at most 400 bytes.
    assert_eq!(bob.apply_feature("user.auto_download", Some("wifi+mobile:400".into())).unwrap().option.as_deref(), Some("wifi+mobile:400"));
    assert!(check(&mut alice, &mut bob, plain(), 400));
    assert!(!check(&mut alice, &mut bob, plain(), 401), "over the size limit");
    assert!(!check(&mut carol, &mut bob, plain(), 10), "strangers still never");
    // Invalid options are refused; the setting stays as it was.
    assert!(matches!(bob.apply_feature("user.auto_download", Some("lte".into())), Err(Error::InvalidOption(_))));
    assert_eq!(bob.feature("user.auto_download").unwrap().option.as_deref(), Some("wifi+mobile:400"));
    bob.apply_feature("user.auto_download", Some("never".into())).unwrap();
    assert!(!check(&mut alice, &mut bob, plain(), 10));
    // Released: nothing downloads by itself; applied again: the default.
    bob.release_feature("user.auto_download").unwrap();
    bob.set_network(Network::Wifi);
    assert!(!check(&mut alice, &mut bob, plain(), 10));
    assert_eq!(bob.apply_feature("user.auto_download", None).unwrap().option.as_deref(), Some("wifi:20m"));
    assert!(check(&mut alice, &mut bob, plain(), 10));
    // Once bob makes carol a contact, her files download too.
    bob.add_contact(carol.account_id()).unwrap();
    assert!(check(&mut carol, &mut bob, plain(), 10));
}
