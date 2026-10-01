//! Message franking and reports (PROTOCOL.md 8.5).
//!
//! Every chat message (text, edit, file) is sent as a `franked` payload: the
//! inner payload exactly as encoded, a fresh key `k`, and the server's tag
//! over `com = HMAC-SHA-256(k, "tree/franking/v1" || len(group) || group || inner)`
//! bound to the sender's account. The receiver keeps the record with the
//! message; reporting hands it to the server, which can then check that the
//! reported account really sent exactly this content. HMAC-SHA-256 only, as
//! in the published franking constructions.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Session};

const COMMIT_LABEL: &[u8] = b"tree/franking/v1";

/// What a receiving device keeps to be able to report a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The inner payload exactly as received.
    pub payload: String,
    /// Base64 franking key and server tag; the minute the tag was made.
    pub key: String,
    pub tag: String,
    pub minute: i64,
}

impl Record {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("JSON")
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_json::from_slice(b).ok()
    }
}

/// `com` for a payload in a group.
pub fn commitment(k: &[u8], group_id: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k).expect("HMAC takes any key length");
    m.update(COMMIT_LABEL);
    m.update(&(group_id.len() as u32).to_be_bytes());
    m.update(group_id);
    m.update(payload);
    m.finalize().into_bytes().into()
}

/// What the server said about a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportReceipt {
    pub id: String,
    /// Every message's franking checked out against the reported account.
    pub verified: bool,
}

impl Session {
    /// Franks an inner payload for sending: a fresh key, the server's tag.
    pub(crate) fn frank(&self, gid: &[u8], inner: &str) -> Result<Record, Error> {
        let mut k = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(k.as_mut()).expect("operating system random number generator failed");
        let com = commitment(k.as_ref(), gid, inner.as_bytes());
        let (tag, minute) = self.api.frank(&self.creds, &com)?;
        Ok(Record { payload: inner.to_string(), key: B64.encode(k.as_ref()), tag, minute })
    }

    /// Reports messages of one sender in a group to the server's operator,
    /// with their franking records (PROTOCOL.md 8.5). The plaintext of these
    /// messages leaves the device, by the user's choice. `user.report` is
    /// always on.
    pub fn report(&mut self, gid: &[u8], ids: &[&str], reason: &str) -> Result<ReportReceipt, Error> {
        if ids.is_empty() {
            return Err(Error::Usage("nothing to report".into()));
        }
        let me = self.member_id().to_hex();
        let mut sender = None;
        let mut messages = Vec::new();
        for id in ids {
            let m = self.client.message(gid, id)?.ok_or_else(|| Error::Usage(format!("no such message {id}")))?;
            if m.sender == me {
                return Err(Error::Usage("you cannot report your own message".into()));
            }
            if sender.get_or_insert_with(|| m.sender.clone()) != &m.sender {
                return Err(Error::Usage("one report covers one sender".into()));
            }
            // A message without a record (deleted, or sent unfranked) is
            // reported as text only and shows as unverified.
            let rec = m.franking.as_deref().and_then(Record::decode).unwrap_or(Record {
                payload: m.text.clone().unwrap_or_default(),
                key: String::new(),
                tag: String::new(),
                minute: 0,
            });
            messages.push(json!({
                "payload": rec.payload, "key": rec.key, "tag": rec.tag, "minute": rec.minute,
                "group_id": B64.encode(gid),
            }));
        }
        let sender = sender.expect("ids is not empty");
        let account = self
            .map(&crate::accounts_key(gid))?
            .get(&sender)
            .cloned()
            .ok_or_else(|| Error::Usage("the sender's account is not known on this device".into()))?;
        let v = self.api.report(&self.creds, &json!({ "reported_account": account, "reason": reason, "messages": messages }))?;
        Ok(ReportReceipt {
            id: v["id"].as_str().unwrap_or_default().to_string(),
            verified: v["verified"].as_bool().unwrap_or(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_binds_key_group_and_payload() {
        let c = commitment(&[1; 32], b"g", b"p");
        assert_ne!(c, commitment(&[2; 32], b"g", b"p"));
        assert_ne!(c, commitment(&[1; 32], b"h", b"p"));
        assert_ne!(c, commitment(&[1; 32], b"g", b"q"));
        // The group length is framed: ("gp", "") and ("g", "p") differ.
        assert_ne!(commitment(&[1; 32], b"gp", b""), commitment(&[1; 32], b"g", b"p"));
        let r = Record { payload: "{}".into(), key: "a".into(), tag: "b".into(), minute: 60 };
        assert_eq!(Record::decode(&r.encode()), Some(r));
        assert_eq!(Record::decode(b"junk"), None);
    }

    /// A modified client that skips franking: honest receivers drop it.
    #[test]
    fn unfranked_messages_are_dropped() {
        use crate::payload::Payload;
        use crate::Event;
        let dir = std::env::temp_dir().join(format!("tree-unfranked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = tree_server::Config {
            database_url: format!("sqlite://{}/s.db", dir.display()),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            pow_bits: 8,
            attachment_dir: dir.join("att"),
            ..tree_server::Config::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(tree_server::start(cfg)).unwrap();
        let url = format!("http://{}", server.addr);
        let p = |n: &str| dir.join(format!("{n}.db")).display().to_string();
        let mut alice = Session::create(&p("a"), "pw", "alice", &url, 8).unwrap();
        let mut bob = Session::create(&p("b"), "pw", "bob", &url, 8).unwrap();
        bob.add_contact(alice.account_id()).unwrap();
        let g = alice.create_group().unwrap();
        alice.invite(&g, bob.account_id()).unwrap();
        bob.sync(0).unwrap();
        let to = alice.other_devices(&g).unwrap();
        let raw = Payload::Text { id: "00".repeat(16), text: "not franked".into(), fmt: false, mentions: vec![], all: false, preview: None };
        alice.send_encoded(&g, &to, &raw.encode()).unwrap();
        let ev = bob.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason == "unfranked message")), "{ev:?}");
        assert!(!ev.iter().any(|e| matches!(e, Event::Text { .. })));
        // A franked payload whose inside is not a chat message is dropped too.
        let odd = Payload::Franked { p: Payload::Leave.encode().iter().map(|b| *b as char).collect(), k: String::new(), tag: String::new(), m: 0 };
        alice.send_encoded(&g, &to, &odd.encode()).unwrap();
        let ev = bob.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason == "malformed franked payload")), "{ev:?}");
        // Normal messages still arrive.
        alice.send_text(&g, "franked").unwrap();
        assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::Text { text, .. } if text == "franked")));
        drop(rt);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
