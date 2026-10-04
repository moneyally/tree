//! Rich chats (Wave 2 part B, APP_PROTOCOL.md 8): where the new payloads
//! arrive, what every sync does for them, round video notes, and the blob
//! helpers the sticker and profile-photo code share.
//!
//! Every payload here travels inside MLS like a text; the server sees only
//! ciphertext (and, for stickers and photos, opaque encrypted blobs). Each
//! is checked against its chat setting by the sending device and again by
//! every receiving device:
//!
//! | Setting | Default | Effect |
//! | --- | --- | --- |
//! | `chat.stickers` | applied | stickers and custom emoji reactions (`stickers.rs`) |
//! | `chat.gifs` | applied | files flagged as GIFs from the relay (`relay.rs`) |
//! | `chat.location` | applied | places and live locations (`location.rs`) |
//! | `chat.events` | applied | events and replies (`chat_events.rs`) |
//! | `chat.video_notes` | applied | files flagged as round video notes (here) |
//! | `chat.allow_per_chat_profiles` | applied | members' names / photos for this chat only (`profile.rs`) |

use serde::{de::DeserializeOwned, Serialize};
use tree_core::MemberId;
use zeroize::Zeroizing;

use crate::messages::FileKind;
use crate::payload::{BlobRef, FileInfo, Payload};
use crate::{api, Error, Event, GroupStatus, Session};

/// Longest round video note (milliseconds).
pub const MAX_VIDEO_NOTE_MS: u64 = 60_000;
/// Longest message id taken from another device.
pub(crate) const MAX_ID: usize = 64;

/// The payloads this module routes (`on_rich`).
pub(crate) fn is_rich(p: &Payload) -> bool {
    matches!(
        p,
        Payload::Sticker { .. }
            | Payload::Location(_)
            | Payload::LiveLocation { .. }
            | Payload::ChatEvent(_)
            | Payload::EventEdit { .. }
            | Payload::Rsvp { .. }
            | Payload::ProfilePhoto { .. }
    )
}

impl Session {
    /// A JSON value kept on this device (`None` if absent or unreadable).
    pub(crate) fn app_get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, Error> {
        Ok(self.client.app_data(key)?.and_then(|v| serde_json::from_slice(&v).ok()))
    }

    /// Stores (or with `None` deletes) a JSON value on this device.
    pub(crate) fn app_put<T: Serialize>(&self, key: &str, v: Option<&T>) -> Result<(), Error> {
        let bytes = v.map(|v| serde_json::to_vec(v).expect("JSON"));
        Ok(self.client.set_app_data(key, bytes.as_deref())?)
    }

    /// The group is still a message request on this device.
    pub(crate) fn is_request(&self, gid: &[u8]) -> Result<bool, Error> {
        Ok(matches!(self.group_status(gid)?, GroupStatus::Request { .. }))
    }

    /// Encrypts `bytes` with a fresh file key and uploads the ciphertext
    /// with the existing attachment API (PROTOCOL.md 6.12).
    pub(crate) fn upload_blob(&self, bytes: &[u8]) -> Result<BlobRef, Error> {
        let (ct, fk) = tree_core::attachment::encrypt(bytes)?;
        let id = self.api.upload(&self.creds, &ct)?;
        Ok(BlobRef {
            id,
            key: api::b64(&fk.key[..]),
            nonce: api::b64(&fk.nonce_prefix),
            size: fk.size,
            ct_sha256: hex::encode(fk.ciphertext_sha256),
            pt_sha256: hex::encode(fk.plaintext_sha256),
        })
    }

    /// Downloads and opens a blob (checked against its hashes), refusing
    /// one larger than `max` bytes before fetching it.
    pub(crate) fn download_blob(&self, r: &BlobRef, max: u64) -> Result<Zeroizing<Vec<u8>>, Error> {
        if r.size > max {
            return Err(Error::Protocol("blob larger than allowed".into()));
        }
        Ok(Zeroizing::new(self.download(&r.file("", "application/octet-stream"))?))
    }

    /// Sends a round video note (short, square video; `chat.video_notes`
    /// and `chat.media`). Apps record it; the client checks the length.
    pub fn send_video_note(&mut self, gid: &[u8], bytes: &[u8], mime: &str, duration_ms: u64) -> Result<FileInfo, Error> {
        if duration_ms == 0 || duration_ms > MAX_VIDEO_NOTE_MS {
            return Err(Error::Usage(format!("a video note is at most {} seconds", MAX_VIDEO_NOTE_MS / 1000)));
        }
        if !mime.starts_with("video/") {
            return Err(Error::Usage("a video note is a video".into()));
        }
        let kind = FileKind { gif: false, video_note: Some(duration_ms) };
        self.send_attachment_as(gid, bytes, "video note", mime, false, None, kind)
    }

    /// Sends `p` as it is, without this device's own checks: what a
    /// modified client could send. Only for tests of the receiving side's
    /// checks; apps never call it.
    #[doc(hidden)]
    pub fn send_unchecked(&mut self, gid: &[u8], p: &Payload) -> Result<usize, Error> {
        self.send_payload(gid, p)
    }

    /// Routes a rich-chat payload from member `from` (blocked senders were
    /// filtered already).
    pub(crate) fn on_rich(
        &mut self,
        gid: &[u8],
        from: MemberId,
        p: Payload,
        franking: Option<Vec<u8>>,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        self.note_traffic(gid)?;
        match p {
            Payload::Sticker { id, pack, index, emoji } => self.on_sticker(gid, from, id, pack, index, emoji, franking, events),
            Payload::Location(l) => self.on_location(gid, from, l, franking, events),
            Payload::LiveLocation { id, lat_e7, lon_e7, accuracy_m, stop } => {
                self.on_live_location(gid, from, &id, (lat_e7, lon_e7, accuracy_m), stop, events)
            }
            Payload::ChatEvent(e) => self.on_chat_event(gid, from, e, franking, events),
            Payload::EventEdit { event, cancelled } => self.on_event_edit(gid, from, event, cancelled, events),
            Payload::Rsvp { id, answer } => self.on_rsvp(gid, from, &id, &answer, events),
            Payload::ProfilePhoto { photo, mime, chat } => self.on_profile_photo(gid, from, photo, mime, chat, events),
            _ => {
                events.push(Event::Dropped { reason: "not a rich-chat message".into() });
                Ok(())
            }
        }
    }

    /// What every sync does for rich chats: live locations due for their
    /// next update go out, and every group gets the profile photo and
    /// per-chat profile it should have. Best effort: a failure (no network
    /// for an upload, a refused send, which the outbox shows) is tried
    /// again by the next sync and never fails the sync itself.
    pub(crate) fn rich_sync(&mut self) -> Result<(), Error> {
        let _ = self.flush_live_locations();
        let _ = self.share_profiles();
        Ok(())
    }
}
