//! What Tree apps put inside MLS application messages (v1).
//!
//! JSON, one object per message. Unknown types are shown as "unsupported",
//! never as text. Everything here is end-to-end encrypted and authenticated
//! by MLS; the sender is the MLS member id, never a field of the payload.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Payload {
    /// A chat message. `id`: random, unique in the group (hex), used by
    /// edits, deletions and reactions.
    Text {
        id: String,
        text: String,
        /// The text uses Tree's formatting markup (APP_PROTOCOL.md 1.1;
        /// `chat.formatting`).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        fmt: bool,
        /// Member ids (hex) mentioned (at most 50).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        mentions: Vec<String>,
        /// @all (`chat.mention_all`).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        all: bool,
        /// A link preview the sender's device made (`user.link_preview`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preview: Option<LinkPreview>,
        /// Silent send: receivers' apps do not notify for this message.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        silent: bool,
        /// Forwarded from another chat (`chat.forwarding`); the original
        /// sender is not named.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        fwd: bool,
    },
    /// The sender replaces the text of its own message `id` (chat.edit).
    Edit { id: String, text: String },
    /// The sender deletes its own message `id` for everyone (chat.delete_for_all).
    Delete { id: String },
    /// The sender adds (or with `remove`, takes back) a reaction (chat.reactions).
    React {
        id: String,
        emoji: String,
        #[serde(default)]
        remove: bool,
    },
    /// Member id (hex) -> server device id, sent by whoever added devices,
    /// to everyone (PROTOCOL.md Q8: the app keeps this mapping). A wrong
    /// entry only misroutes messages; it cannot reveal anything. `names` are
    /// the sender's view of display names: hints for new members until each
    /// member's own `Profile` arrives.
    Roster {
        devices: BTreeMap<String, String>,
        #[serde(default)]
        names: BTreeMap<String, String>,
        /// Member id -> account id, as the adder learned it from the server's
        /// key-package claim. Lets every member pin the devices of a contact.
        #[serde(default)]
        accounts: BTreeMap<String, String>,
        /// The nonce (hex) the new member's device sent with its invite
        /// link request, if it joined by link, so it can accept this group
        /// without a request (PROTOCOL.md 8.7).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        link: Option<String>,
    },
    /// The sender's own display name. Names never go to the server (F-009);
    /// they travel only inside the group, end-to-end encrypted.
    Profile { name: String },
    /// The sender asks to be removed (PROTOCOL.md 6.5). `quiet`: the
    /// other members' apps show no "left" line in the chat (the member list
    /// still changes for everyone).
    Leave {
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        quiet: bool,
    },
    /// The sender asks the admins to remove other devices of its own
    /// account (member ids, hex) that it unlinked (PROTOCOL.md 8.11).
    RemoveDevice { members: Vec<String> },
    /// The sender read these messages (`user.read_receipts`).
    Read { ids: Vec<String> },
    /// The sender started or stopped typing (`user.typing`); not stored.
    Typing { on: bool },
    /// The sender's app is open now (`user.last_seen`); the time is the
    /// receiver's own.
    Seen,
    /// An encrypted attachment (PROTOCOL.md 6.12).
    File(FileInfo),
    /// A chat message (`text`, `edit` or `file`) with its franking
    /// (PROTOCOL.md 8.5): `p` is the inner payload exactly as encoded, `k`
    /// the franking key, `tag` the server's tag made at minute `m`.
    Franked { p: String, k: String, tag: String, m: i64 },
    /// Pins message `id` for the whole chat (`chat.pins`, `pins.rs`):
    /// `ttl` seconds from when each device receives it (none: until
    /// unpinned); `remove` unpins.
    Pin {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl: Option<i64>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        remove: bool,
    },
    /// A poll (`chat.polls`, `polls.rs`).
    Poll(PollDef),
    /// The sender's whole vote in poll `id` (option indexes); empty takes
    /// the vote back. The latest one of each member counts.
    Vote {
        id: String,
        #[serde(default)]
        choices: Vec<u32>,
    },
    /// The poll's creator closes poll `id`.
    PollClose { id: String },
}

/// A poll as its creator sent it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollDef {
    /// Message id of the poll in the group (as for `text`).
    pub id: String,
    /// The question (at most 300 characters).
    pub q: String,
    /// 2 to 10 options, each 1 to 100 characters.
    pub opts: Vec<String>,
    /// Several options may be chosen.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub multi: bool,
    /// Apps do not show who voted for what (votes are still
    /// MLS-authenticated to every member's device; see `polls.rs`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub anon: bool,
    /// Closes this many seconds after each device received it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_in: Option<i64>,
}

/// A link preview, made by the sender's device (which fetched the page), so
/// receivers never contact the site. Limits: url 2048, title 200,
/// description 500 characters; longer previews are dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkPreview {
    pub url: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl LinkPreview {
    pub fn is_valid(&self) -> bool {
        let n = |s: &str| s.chars().count();
        (self.url.starts_with("https://") || self.url.starts_with("http://"))
            && n(&self.url) <= 2048
            && n(&self.title) <= 200
            && self.description.as_deref().is_none_or(|d| n(d) <= 500)
    }
}

/// Where an attachment is and how to open it. Only ever inside an
/// end-to-end encrypted message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    /// Message id in the group (as for `text`).
    #[serde(default)]
    pub msg_id: String,
    /// Opened once, then the reference is deleted (chat.view_once).
    #[serde(default)]
    pub view_once: bool,
    /// A voice message (`chat.voice`), with its length.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub voice: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Server attachment id.
    pub id: String,
    /// File key (base64, 32 bytes) and STREAM nonce prefix (base64, 7 bytes).
    pub key: String,
    pub nonce: String,
    pub size: u64,
    /// Hex SHA-256 of the ciphertext and of the plaintext (key commitment).
    pub ct_sha256: String,
    pub pt_sha256: String,
    pub name: String,
    pub mime: String,
    /// Forwarded from another chat (`chat.forwarding`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fwd: bool,
}

impl Payload {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serialisable")
    }

    /// Payloads that are franked when sent (content a member could report).
    pub fn is_franked_kind(&self) -> bool {
        matches!(self, Payload::Text { .. } | Payload::Edit { .. } | Payload::File(_) | Payload::Poll(_))
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_format() {
        let t = Payload::Text { id: "01".into(), text: "안녕".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: false };
        assert_eq!(String::from_utf8(t.encode()).unwrap(), r#"{"t":"text","id":"01","text":"안녕"}"#);
        for p in [
            Payload::Edit { id: "01".into(), text: "x".into() },
            Payload::Delete { id: "01".into() },
            Payload::React { id: "01".into(), emoji: "👍".into(), remove: true },
        ] {
            assert_eq!(Payload::decode(&p.encode()), Some(p));
        }
        assert_eq!(
            Payload::decode(br#"{"t":"react","id":"01","emoji":"x"}"#),
            Some(Payload::React { id: "01".into(), emoji: "x".into(), remove: false })
        );
        assert_eq!(Payload::decode(&t.encode()), Some(t));
        let r = Payload::Roster {
            devices: [("ab".to_string(), "dev".to_string())].into(),
            names: Default::default(),
            accounts: [("ab".to_string(), "acc".to_string())].into(),
            link: Some("cd".into()),
        };
        assert_eq!(Payload::decode(&r.encode()), Some(r));
        assert!(Payload::decode(br#"{"t":"roster","devices":{}}"#).is_some(), "names optional");
        let p = Payload::Profile { name: "bob".into() };
        assert_eq!(Payload::decode(&p.encode()), Some(p));
        assert_eq!(Payload::decode(br#"{"t":"leave"}"#), Some(Payload::Leave { quiet: false }));
        assert_eq!(Payload::Leave { quiet: false }.encode(), br#"{"t":"leave"}"#.to_vec(), "older apps read it");
        let q = Payload::Leave { quiet: true };
        assert_eq!(q.encode(), br#"{"t":"leave","quiet":true}"#.to_vec());
        assert_eq!(Payload::decode(&q.encode()), Some(q));
        let s = Payload::Text { id: "02".into(), text: "shh".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: true, fwd: false };
        assert_eq!(String::from_utf8(s.encode()).unwrap(), r#"{"t":"text","id":"02","text":"shh","silent":true}"#);
        assert_eq!(Payload::decode(&s.encode()), Some(s));
        let r = Payload::RemoveDevice { members: vec!["ab".into()] };
        assert_eq!(String::from_utf8(r.encode()).unwrap(), r#"{"t":"remove_device","members":["ab"]}"#);
        assert_eq!(Payload::decode(&r.encode()), Some(r));
        assert_eq!(Payload::decode(br#"{"t":"sticker"}"#), None);
        // Unknown fields are ignored (a newer app's additions).
        assert!(Payload::decode(br#"{"t":"text","id":"01","text":"x","future":1}"#).is_some());
        assert_eq!(Payload::decode(b"plain"), None);
    }
}

#[cfg(test)]
mod rich_tests {
    use super::*;

    /// Wave 2 part A payloads: exact encodings, and older readers keep
    /// working (a forwarded text is a text with one more field).
    #[test]
    fn pins_polls_votes_forwarding() {
        let pin = Payload::Pin { id: "01".into(), ttl: Some(86400), remove: false };
        assert_eq!(String::from_utf8(pin.encode()).unwrap(), r#"{"t":"pin","id":"01","ttl":86400}"#);
        let unpin = Payload::Pin { id: "01".into(), ttl: None, remove: true };
        assert_eq!(String::from_utf8(unpin.encode()).unwrap(), r#"{"t":"pin","id":"01","remove":true}"#);
        let poll = Payload::Poll(PollDef { id: "02".into(), q: "Lunch?".into(), opts: vec!["a".into(), "b".into()], multi: true, anon: false, close_in: None });
        assert_eq!(String::from_utf8(poll.encode()).unwrap(), r#"{"t":"poll","id":"02","q":"Lunch?","opts":["a","b"],"multi":true}"#);
        assert!(poll.is_franked_kind(), "a poll is content a member can report");
        let vote = Payload::Vote { id: "02".into(), choices: vec![1] };
        assert_eq!(String::from_utf8(vote.encode()).unwrap(), r#"{"t":"vote","id":"02","choices":[1]}"#);
        assert_eq!(Payload::decode(br#"{"t":"vote","id":"02"}"#), Some(Payload::Vote { id: "02".into(), choices: vec![] }));
        let close = Payload::PollClose { id: "02".into() };
        assert_eq!(String::from_utf8(close.encode()).unwrap(), r#"{"t":"poll_close","id":"02"}"#);
        for p in [pin, unpin, poll, vote, close] {
            assert_eq!(Payload::decode(&p.encode()), Some(p.clone()));
            assert!(!matches!(p, Payload::Vote { .. } | Payload::Pin { .. } | Payload::PollClose { .. }) || !p.is_franked_kind());
        }
        let f = Payload::Text { id: "03".into(), text: "hi".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: true };
        assert_eq!(String::from_utf8(f.encode()).unwrap(), r#"{"t":"text","id":"03","text":"hi","fwd":true}"#);
        assert_eq!(Payload::decode(&f.encode()), Some(f));
        // A file reference without `fwd` (older apps) reads as not forwarded.
        let old = br#"{"t":"file","id":"x","key":"k","nonce":"n","size":1,"ct_sha256":"","pt_sha256":"","name":"a","mime":"b"}"#;
        assert!(matches!(Payload::decode(old), Some(Payload::File(FileInfo { fwd: false, .. }))));
    }
}
