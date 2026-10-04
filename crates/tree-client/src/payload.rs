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
        /// The topic (thread) it belongs to (`chat.topics`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        topic: Option<String>,
    },
    /// The sender replaces the text of its own message `id` (chat.edit).
    Edit { id: String, text: String },
    /// The sender deletes its own message `id` for everyone
    /// (chat.delete_for_all), or, as an admin or with a role that may
    /// delete, another member's message (APP_PROTOCOL.md 9.2).
    Delete { id: String },
    /// The sender adds (or with `remove`, takes back) a reaction (chat.reactions).
    React {
        id: String,
        emoji: String,
        #[serde(default)]
        remove: bool,
        /// A custom emoji from a pack (`chat.stickers`); `emoji` is then the
        /// pack's plain emoji for it, which older apps show instead.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sticker: Option<StickerRef>,
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
    Profile {
        name: String,
        /// A name for this chat only (`user.per_chat_profile`, allowed by
        /// the chat's `chat.allow_per_chat_profiles`).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        chat: bool,
    },
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
    /// Settings of the sender's account, sent only to the account's own
    /// self group (`self_sync.rs`; APP_PROTOCOL.md 6.4).
    Settings { s: Vec<crate::self_sync::SyncEntry> },
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
    /// A sticker: item `index` of the pack whose manifest is `pack`
    /// (`chat.stickers`, APP_PROTOCOL.md 8.1). `emoji`: the item's plain
    /// emoji, shown where the image cannot be.
    Sticker {
        id: String,
        pack: BlobRef,
        index: u32,
        emoji: String,
    },
    /// A place, or the start of a live location (`chat.location`).
    Location(LocationInfo),
    /// A new position of the sender's own live location `id`, or its end
    /// (`stop`). Not franked (sent up to every 30 s).
    LiveLocation {
        id: String,
        lat_e7: i64,
        lon_e7: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        accuracy_m: Option<u32>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        stop: bool,
    },
    /// An event members can answer (`chat.events`).
    ChatEvent(EventInfo),
    /// The creator changes or cancels its event `event.id`.
    EventEdit {
        event: EventInfo,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        cancelled: bool,
    },
    /// The sender's answer to event `id`: `going`, `maybe` or `not`.
    Rsvp { id: String, answer: String },
    /// Creates topic `id` (with `name`), renames it, closes or reopens it
    /// (`chat.topics`, `topics.rs`).
    Topic {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        closed: Option<bool>,
    },
    /// The topics the sender knows, sent after it added members so they
    /// learn the names (`topics.rs`).
    Topics { list: Vec<TopicDef> },
    /// Recent messages re-sent by the device that added `to` (member ids,
    /// hex) for them only (`chat.history_share`, `history_share.rs`).
    /// Authors and times inside are the sharing device's claims.
    History { to: Vec<String>, msgs: Vec<SharedMsg> },
    /// In a community root group: the sender asks to be added to chat
    /// `chat` (group id, hex) as account `account` (`community.rs`).
    JoinChat { chat: String, account: String },
    /// The sender's profile photo (an encrypted attachment), or none:
    /// removed. `chat`: for this chat only (`user.per_chat_profile`).
    ProfilePhoto {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        photo: Option<BlobRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mime: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        chat: bool,
    },
}

/// A topic as a `topics` list carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicDef {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub closed: bool,
}

/// One message inside a `history` bundle, as the sharing device has it.
/// `from`, `name` and `at` are its claims: the original MLS
/// authentication is not carried (APP_PROTOCOL.md 9.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedMsg {
    pub id: String,
    /// Member id (hex) of the original author, as claimed.
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// When the sharing device received it (unix seconds), as claimed.
    pub at: i64,
    /// `text` or `file`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
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

/// Lowercase hex SHA-256, as in `pt_sha256` fields.
pub(crate) fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

/// An encrypted blob on the server and how to open it (PROTOCOL.md 6.12):
/// the same fields as a file reference, without name and type. Used for
/// sticker images and manifests and for profile photos.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlobRef {
    pub id: String,
    /// The file secret (base64, 32 bytes), as in a file reference.
    pub key: String,
    pub size: u64,
    pub pt_sha256: String,
    /// Attachment format version ([`tree_core::attachment::VERSION`]).
    #[serde(default)]
    pub v: u32,
}

impl BlobRef {
    /// As a file reference, to download it with [`crate::Session::download`].
    pub fn file(&self, name: &str, mime: &str) -> FileInfo {
        FileInfo {
            msg_id: String::new(),
            view_once: false,
            voice: false,
            duration_ms: None,
            gif: false,
            video_note: false,
            id: self.id.clone(),
            key: self.key.clone(),
            size: self.size,
            pt_sha256: self.pt_sha256.clone(),
            name: name.to_string(),
            mime: mime.to_string(),
            v: self.v,
            width: None,
            height: None,
            thumb: None,
            fwd: false,
            topic: None,
        }
    }
}

/// A custom emoji: item `index` of the pack `pack`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StickerRef {
    pub pack: BlobRef,
    pub index: u32,
}

/// A place: latitude and longitude in units of 10^-7 degrees (integers, so
/// every device reads the same value), accuracy in metres, an optional
/// label. `live_secs`: a live location that the sender updates for that
/// long (900, 3600 or 28800 seconds), measured by each receiver's clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationInfo {
    pub id: String,
    pub lat_e7: i64,
    pub lon_e7: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accuracy_m: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_secs: Option<u32>,
}

/// An event: title (at most 200 characters), start and optional end (unix
/// seconds, as the creator entered them), place and description (at most
/// 200 and 2000 characters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventInfo {
    pub id: String,
    pub title: String,
    pub starts_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
    /// A voice message (`chat.voice`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub voice: bool,
    /// Length of a voice message, video or other recording.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// A GIF the sender found through the server's relay (`chat.gifs`);
    /// the file itself was uploaded by the sender like any other.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub gif: bool,
    /// A round video note (`chat.video_notes`): short, square video.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub video_note: bool,
    /// Server attachment id.
    pub id: String,
    /// The file secret (base64, 32 bytes): input to HKDF, which derives the
    /// cipher key, the nonce prefix and the commitment key.
    pub key: String,
    /// Plaintext size in bytes (the server sees only the padded size).
    pub size: u64,
    /// Hex SHA-256 of the plaintext.
    pub pt_sha256: String,
    pub name: String,
    pub mime: String,
    /// Attachment format version ([`tree_core::attachment::VERSION`]).
    #[serde(default)]
    pub v: u32,
    /// Picture or video size in pixels, if the sender's app gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// A small preview picture made by the sender (base64 JPEG or PNG, at
    /// most [`MAX_THUMB`] bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumb: Option<String>,
    /// Forwarded from another chat (`chat.forwarding`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fwd: bool,
    /// The topic (thread) it belongs to (`chat.topics`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

/// Largest preview picture in a message (decoded bytes).
pub const MAX_THUMB: usize = 32 * 1024;
/// Longest file name and type, in characters.
pub const MAX_NAME: usize = 255;
pub const MAX_MIME: usize = 127;

impl FileInfo {
    /// Fits the format and its limits (checked on sending and on receiving;
    /// a reference that does not is dropped).
    pub fn is_valid(&self) -> bool {
        let b64 = |s: &str| crate::api::unb64(s).ok();
        let hex64 = |s: &str| s.len() == 64 && hex::decode(s).is_ok();
        self.v == tree_core::attachment::VERSION
            && b64(&self.key).is_some_and(|k| k.len() == 32)
            && hex64(&self.pt_sha256)
            && self.size <= tree_core::attachment::MAX_FILE
            && self.name.chars().count() <= MAX_NAME
            && self.mime.chars().count() <= MAX_MIME
            && self.width.is_none_or(|w| w <= 100_000)
            && self.height.is_none_or(|h| h <= 100_000)
            && self.thumb.as_deref().is_none_or(|t| b64(t).is_some_and(|b| b.len() <= MAX_THUMB))
    }

    /// The preview picture's bytes.
    pub fn thumbnail(&self) -> Option<Vec<u8>> {
        self.thumb.as_deref().and_then(|t| crate::api::unb64(t).ok())
    }
}

impl Payload {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serialisable")
    }

    /// Payloads that are franked when sent (content a member could report).
    pub fn is_franked_kind(&self) -> bool {
        matches!(
            self,
            Payload::Text { .. }
                | Payload::Edit { .. }
                | Payload::File(_)
                | Payload::Poll(_)
                | Payload::Sticker { .. }
                | Payload::Location(_)
                | Payload::ChatEvent(_)
        )
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
        let t = Payload::Text { id: "01".into(), text: "안녕".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: false, topic: None };
        assert_eq!(String::from_utf8(t.encode()).unwrap(), r#"{"t":"text","id":"01","text":"안녕"}"#);
        for p in [
            Payload::Edit { id: "01".into(), text: "x".into() },
            Payload::Delete { id: "01".into() },
            Payload::React { id: "01".into(), emoji: "👍".into(), remove: true, sticker: None },
        ] {
            assert_eq!(Payload::decode(&p.encode()), Some(p));
        }
        assert_eq!(
            Payload::decode(br#"{"t":"react","id":"01","emoji":"x"}"#),
            Some(Payload::React { id: "01".into(), emoji: "x".into(), remove: false, sticker: None })
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
        let p = Payload::Profile { name: "bob".into(), chat: false };
        assert_eq!(p.encode(), br#"{"t":"profile","name":"bob"}"#.to_vec(), "older apps read it");
        assert_eq!(Payload::decode(&p.encode()), Some(p));
        assert_eq!(Payload::decode(br#"{"t":"leave"}"#), Some(Payload::Leave { quiet: false }));
        assert_eq!(Payload::Leave { quiet: false }.encode(), br#"{"t":"leave"}"#.to_vec(), "older apps read it");
        let q = Payload::Leave { quiet: true };
        assert_eq!(q.encode(), br#"{"t":"leave","quiet":true}"#.to_vec());
        assert_eq!(Payload::decode(&q.encode()), Some(q));
        let s = Payload::Text { id: "02".into(), text: "shh".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: true, fwd: false, topic: None };
        assert_eq!(String::from_utf8(s.encode()).unwrap(), r#"{"t":"text","id":"02","text":"shh","silent":true}"#);
        assert_eq!(Payload::decode(&s.encode()), Some(s));
        let r = Payload::RemoveDevice { members: vec!["ab".into()] };
        assert_eq!(String::from_utf8(r.encode()).unwrap(), r#"{"t":"remove_device","members":["ab"]}"#);
        assert_eq!(Payload::decode(&r.encode()), Some(r));
        assert_eq!(Payload::decode(br#"{"t":"sticker"}"#), None, "a sticker needs its pack");
        assert_eq!(Payload::decode(br#"{"t":"no_such_type"}"#), None);
        // Unknown fields are ignored (a newer app's additions).
        assert!(Payload::decode(br#"{"t":"text","id":"01","text":"x","future":1}"#).is_some());
        assert_eq!(Payload::decode(b"plain"), None);
    }

    fn blob() -> BlobRef {
        BlobRef { id: "a".into(), key: "k".into(), size: 3, pt_sha256: "p".into(), v: tree_core::attachment::VERSION }
    }

    /// The rich-chat payloads round-trip, and fields older apps do not know
    /// are left out when unused, so those apps decode the payload unchanged.
    #[test]
    fn rich_payloads_round_trip() {
        let all = [
            Payload::Sticker { id: "01".into(), pack: blob(), index: 2, emoji: "😀".into() },
            Payload::Location(LocationInfo { id: "02".into(), lat_e7: 375_665_000, lon_e7: 1_269_780_000, accuracy_m: Some(5), label: Some("시청".into()), live_secs: Some(900) }),
            Payload::LiveLocation { id: "02".into(), lat_e7: 1, lon_e7: -2, accuracy_m: None, stop: true },
            Payload::ChatEvent(EventInfo { id: "03".into(), title: "회의".into(), starts_at: 1_800_000_000, ends_at: None, place: None, description: Some("d".into()) }),
            Payload::EventEdit { event: EventInfo { id: "03".into(), title: "t".into(), starts_at: 1, ends_at: Some(2), place: Some("p".into()), description: None }, cancelled: true },
            Payload::Rsvp { id: "03".into(), answer: "going".into() },
            Payload::ProfilePhoto { photo: Some(blob()), mime: Some("image/png".into()), chat: false },
            Payload::ProfilePhoto { photo: None, mime: None, chat: true },
            Payload::React { id: "01".into(), emoji: "😀".into(), remove: false, sticker: Some(StickerRef { pack: blob(), index: 1 }) },
            Payload::Profile { name: "chat name".into(), chat: true },
        ];
        for p in all {
            assert_eq!(Payload::decode(&p.encode()), Some(p.clone()), "{p:?}");
        }
        let r = Payload::React { id: "01".into(), emoji: "👍".into(), remove: false, sticker: None };
        assert_eq!(String::from_utf8(r.encode()).unwrap(), r#"{"t":"react","id":"01","emoji":"👍","remove":false}"#);
        let f = blob().file("x", "image/gif");
        let v: serde_json::Value = serde_json::from_slice(&Payload::File(f.clone()).encode()).unwrap();
        assert!(v.get("gif").is_none() && v.get("video_note").is_none(), "flags only when set");
        let g = FileInfo { gif: true, video_note: true, ..f };
        assert_eq!(Payload::decode(&Payload::File(g.clone()).encode()), Some(Payload::File(g)));
        assert!(Payload::Sticker { id: "1".into(), pack: blob(), index: 0, emoji: "x".into() }.is_franked_kind());
        assert!(!Payload::Rsvp { id: "1".into(), answer: "going".into() }.is_franked_kind());
        assert!(!Payload::LiveLocation { id: "1".into(), lat_e7: 0, lon_e7: 0, accuracy_m: None, stop: false }.is_franked_kind());
    }
}

#[cfg(test)]
mod group_tests {
    use super::*;

    /// Wave 3 payloads round-trip, and the new optional fields are left out
    /// when unused, so older apps read texts and files unchanged.
    #[test]
    fn wave3_payloads() {
        let t = Payload::Text { id: "01".into(), text: "hi".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: false, topic: Some("t1".into()) };
        assert_eq!(String::from_utf8(t.encode()).unwrap(), r#"{"t":"text","id":"01","text":"hi","topic":"t1"}"#);
        let all = [
            t,
            Payload::Topic { id: "t1".into(), name: Some("일정".into()), closed: None },
            Payload::Topic { id: "t1".into(), name: None, closed: Some(true) },
            Payload::Topics { list: vec![TopicDef { id: "t1".into(), name: "n".into(), closed: false }] },
            Payload::History {
                to: vec!["ab".into()],
                msgs: vec![SharedMsg { id: "1".into(), from: "cd".into(), name: Some("bob".into()), at: 5, kind: "text".into(), text: Some("x".into()), file: None, topic: None }],
            },
            Payload::JoinChat { chat: "00".into(), account: "acc".into() },
        ];
        for p in all {
            assert_eq!(Payload::decode(&p.encode()), Some(p.clone()), "{p:?}");
            assert!(!matches!(p, Payload::Topic { .. } | Payload::Topics { .. } | Payload::History { .. } | Payload::JoinChat { .. }) || !p.is_franked_kind());
        }
        assert_eq!(String::from_utf8(Payload::Topic { id: "t".into(), name: None, closed: Some(false) }.encode()).unwrap(), r#"{"t":"topic","id":"t","closed":false}"#);
        let v: serde_json::Value = serde_json::from_slice(&Payload::File(blob_file()).encode()).unwrap();
        assert!(v.get("topic").is_none(), "no topic field unless set");
    }

    fn blob_file() -> FileInfo {
        BlobRef { id: "a".into(), key: "k".into(), size: 3, pt_sha256: "p".into(), v: 2 }.file("x", "y")
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
        let f = Payload::Text { id: "03".into(), text: "hi".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: true, topic: None };
        assert_eq!(String::from_utf8(f.encode()).unwrap(), r#"{"t":"text","id":"03","text":"hi","fwd":true}"#);
        assert_eq!(Payload::decode(&f.encode()), Some(f));
        // A file reference without `fwd` (older apps) reads as not forwarded.
        let old = br#"{"t":"file","id":"x","key":"k","nonce":"n","size":1,"ct_sha256":"","pt_sha256":"","name":"a","mime":"b"}"#;
        assert!(matches!(Payload::decode(old), Some(Payload::File(FileInfo { fwd: false, .. }))));
    }
}
