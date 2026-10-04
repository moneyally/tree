//! Chat messages on top of the group: send and receive text and files,
//! edits, deletion for everyone, reactions, disappearing messages and
//! view-once files, with history kept in the encrypted device database.
//!
//! The group's chat settings (PROTOCOL.md 6.11) are enforced by every device
//! on both sides: a device refuses to send what the admins released, and
//! drops what another (modified) client sends anyway.
//!
//! | Setting | Default | Effect |
//! | --- | --- | --- |
//! | `chat.media` | applied | files allowed |
//! | `chat.edit` | applied, option = window (duration, default 24 h) | own messages editable within the window |
//! | `chat.delete_for_all` | applied, option = window (duration, default 24 h) | own messages deletable for everyone within the window |
//! | `chat.reactions` | applied | reactions allowed |
//! | `chat.view_once` | applied | view-once files allowed |
//! | `chat.disappearing` | released; option = duration (`90`, `30m`, `1h`, `1d`, `2w`; default `1d`) | every message expires that long after it arrives |
//! | `chat.voice` | applied | voice messages allowed |
//! | `chat.formatting` | applied | formatting markup is shown; released: shown as plain text |
//! | `chat.mention_all` | applied, option `admins` (default) or `all` | who may @all; otherwise the @all is ignored |
//! | `chat.screenshot_block` | released | the apps block screenshots of the chat (also per user) |
//! | `chat.gifs`, `chat.video_notes` | applied | files flagged as a GIF / a video note allowed (`gifs.rs`, `video_notes.rs`) |
//!
//! Windows are measured with this device's own clock from when it received
//! (or sent) the original, never from a time the sender claims.

use std::time::{SystemTime, UNIX_EPOCH};

use tree_core::features::{self, Registry, State};
use tree_core::storage::messages::StoredMessage;
use tree_core::MemberId;
use zeroize::Zeroizing;

use crate::payload::{FileInfo, Payload};
use crate::{api, Error, Event, GroupStatus, Session};

/// Default edit / delete-for-all window (design: 24 hours).
pub const DEFAULT_WINDOW: i64 = 24 * 3600;
/// Mentions per message.
pub const MAX_MENTIONS: usize = 50;

/// How a text is sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextOptions {
    /// The text uses Tree's formatting markup.
    pub formatted: bool,
    pub mentions: Vec<MemberId>,
    /// @all.
    pub all: bool,
    /// A preview of a link in the text, made by this device's app
    /// (`user.link_preview`).
    pub preview: Option<crate::payload::LinkPreview>,
    /// Silent send: the receivers' apps do not notify (APP_PROTOCOL.md 1).
    pub silent: bool,
}

pub(crate) fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub(crate) fn new_id() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("operating system random number generator failed");
    hex::encode(b)
}

fn screenshot_key(gid: &[u8]) -> String {
    format!("screenshot/{}", hex::encode(gid))
}

/// What a stored text keeps besides its text: formatting, a preview and
/// the silent flag.
fn text_data(formatted: bool, preview: Option<&crate::payload::LinkPreview>, silent: bool) -> Option<Vec<u8>> {
    if !formatted && preview.is_none() && !silent {
        return None;
    }
    let mut v = serde_json::json!({});
    if formatted {
        v["fmt"] = true.into();
    }
    if silent {
        v["silent"] = true.into();
    }
    if let Some(p) = preview {
        v["preview"] = serde_json::to_value(p).expect("JSON");
    }
    Some(serde_json::to_vec(&v).expect("JSON"))
}

/// What kind of file an attachment is besides voice and view-once.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FileKind {
    /// Found through the GIF relay (`chat.gifs`).
    pub gif: bool,
    /// A round video note (`chat.video_notes`) of this length.
    pub video_note: Option<u64>,
}

/// A stored file reference: which group and message it belongs to.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredFile {
    group: String,
    info: FileInfo,
}

impl Session {
    /// A chat feature as the group's admins set it (or its default).
    /// A permanently locked key (`chat.e2e`) always has its locked value,
    /// whatever the group settings hold.
    pub(crate) fn chat_feature(&mut self, gid: &[u8], key: &str) -> Result<(bool, Option<String>), Error> {
        let st = Registry::standard().status(key)?;
        if st.locked_by.is_none() {
            if let Some(s) = self.group_settings(gid)?.features.get(key) {
                return Ok((s.applied, s.option.clone()));
            }
        }
        Ok((st.state == State::Applied, st.option))
    }

    /// Every chat setting of the group as the admins left it (defaults
    /// where they changed nothing), for a group settings screen. Permanent
    /// locks (`chat.e2e`) carry their reason and always their locked value.
    pub fn chat_features(&mut self, gid: &[u8]) -> Result<Vec<tree_core::features::Status>, Error> {
        let set = self.group_settings(gid)?.features;
        Ok(Registry::standard()
            .list(tree_core::features::Scope::Chat)
            .into_iter()
            .map(|mut st| {
                if let (None, Some(s)) = (&st.locked_by, set.get(st.key)) {
                    st.state = if s.applied { State::Applied } else { State::Released };
                    st.option = s.option.clone();
                }
                st
            })
            .collect())
    }

    fn chat_allows(&mut self, gid: &[u8], key: &str) -> Result<bool, Error> {
        Ok(self.chat_feature(gid, key)?.0)
    }

    /// Edit / delete window in seconds (option of the feature, or the default).
    fn window(&mut self, gid: &[u8], key: &str) -> Result<i64, Error> {
        let (_, opt) = self.chat_feature(gid, key)?;
        Ok(features::option_seconds(key, opt.as_deref()).unwrap_or(DEFAULT_WINDOW))
    }

    /// When a message arriving now should disappear, if the group says so.
    /// The option is a duration (`features::option_format`: `90`, `30m`,
    /// `1d`, ...); applied without one (older settings) means its default.
    fn expiry(&mut self, gid: &[u8]) -> Result<Option<i64>, Error> {
        let (on, opt) = self.chat_feature(gid, "chat.disappearing")?;
        Ok(if on { features::option_seconds("chat.disappearing", opt.as_deref()).map(|s| now() + s) } else { None })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store(
        &mut self,
        gid: &[u8],
        id: &str,
        sender: &MemberId,
        kind: &str,
        text: Option<String>,
        data: Option<Vec<u8>>,
        franking: Option<Vec<u8>>,
    ) -> Result<bool, Error> {
        let expires_at = self.expiry(gid)?;
        Ok(self.client.store_message(&StoredMessage {
            group_id: gid.to_vec(),
            id: id.to_string(),
            sender: sender.to_hex(),
            received_at: now(),
            kind: kind.into(),
            text,
            data,
            edited_at: None,
            deleted: false,
            expires_at,
            reactions: Default::default(),
            franking,
        })?)
    }

    fn locked_by_chat() -> Error {
        Error::Feature("LOCKED_BY_CHAT".into())
    }

    /// Sends a text message; returns its id.
    pub fn send_text(&mut self, gid: &[u8], text: &str) -> Result<String, Error> {
        self.send_text_with(gid, text, &TextOptions::default())
    }

    /// Sends a text with formatting and mentions. Formatting is dropped
    /// (plain text sent) if the group released `chat.formatting`; an @all
    /// the group does not allow this device is refused.
    pub fn send_text_with(&mut self, gid: &[u8], text: &str, o: &TextOptions) -> Result<String, Error> {
        if o.mentions.len() > MAX_MENTIONS {
            return Err(Error::Usage(format!("at most {MAX_MENTIONS} mentions")));
        }
        let me = self.member_id();
        if o.all && !self.may_mention_all(gid, &me)? {
            return Err(Self::locked_by_chat());
        }
        let fmt = o.formatted && self.chat_allows(gid, "chat.formatting")?;
        let preview = match &o.preview {
            Some(p) if !p.is_valid() => return Err(Error::Usage("link preview too long or not a web link".into())),
            Some(p) if self.is_applied("user.link_preview")? => Some(p.clone()),
            _ => None,
        };
        let id = new_id();
        let mentions = o.mentions.iter().map(|m| m.to_hex()).collect();
        let data = text_data(fmt, preview.as_ref(), o.silent);
        let p = Payload::Text { id: id.clone(), text: text.to_string(), fmt, mentions, all: o.all, preview, silent: o.silent };
        // Stored in the history with the outbox item, before it goes out.
        self.queue_payload(gid, &p, Some(&id), |s| s.store(gid, &id, &me, "text", Some(text.to_string()), data, None).map(|_| ()))?;
        self.set_draft(gid, "")?;
        Ok(id)
    }

    /// May `who` @all in this group (`chat.mention_all`)?
    fn may_mention_all(&mut self, gid: &[u8], who: &MemberId) -> Result<bool, Error> {
        let (on, opt) = self.chat_feature(gid, "chat.mention_all")?;
        Ok(on && (opt.as_deref() == Some("all") || self.group(gid)?.is_admin(who)))
    }

    /// Whether the apps must block screenshots of this chat: the admins
    /// applied `chat.screenshot_block`, or this user did for this chat. It
    /// stops the screenshot function of honest apps; it cannot stop a camera
    /// or a modified app.
    pub fn screenshot_blocked(&mut self, gid: &[u8]) -> Result<bool, Error> {
        Ok(self.chat_allows(gid, "chat.screenshot_block")? || self.client.app_data(&screenshot_key(gid))?.is_some())
    }

    /// This user's own choice for one chat (independent of the admins').
    pub fn set_screenshot_block(&self, gid: &[u8], on: bool) -> Result<(), Error> {
        Ok(self.client.set_app_data(&screenshot_key(gid), on.then_some(&b"1"[..]))?)
    }

    /// The own message `id`, if it can still be changed under `key`'s window.
    fn own_changeable(&mut self, gid: &[u8], id: &str, key: &str) -> Result<StoredMessage, Error> {
        if !self.chat_allows(gid, key)? {
            return Err(Self::locked_by_chat());
        }
        let m = self.client.message(gid, id)?.ok_or_else(|| Error::Usage("no such message".into()))?;
        if m.sender != self.member_id().to_hex() || m.deleted {
            return Err(Error::Usage("only your own messages can be changed".into()));
        }
        if now() - m.received_at > self.window(gid, key)? {
            return Err(Error::Usage("too late to change this message".into()));
        }
        Ok(m)
    }

    /// Edits one of this device's own text messages (chat.edit).
    pub fn edit(&mut self, gid: &[u8], id: &str, text: &str) -> Result<(), Error> {
        let m = self.own_changeable(gid, id, "chat.edit")?;
        if m.kind != "text" {
            return Err(Error::Usage("only text can be edited".into()));
        }
        self.queue_payload(gid, &Payload::Edit { id: id.into(), text: text.into() }, None, |s| {
            Ok(s.client.edit_message(gid, id, text, now(), None)?)
        })?;
        Ok(())
    }

    /// Deletes one of this device's own messages for everyone (chat.delete_for_all).
    pub fn delete_for_all(&mut self, gid: &[u8], id: &str) -> Result<(), Error> {
        self.own_changeable(gid, id, "chat.delete_for_all")?;
        self.queue_payload(gid, &Payload::Delete { id: id.into() }, None, |s| Ok(s.client.delete_message(gid, id)?))?;
        Ok(())
    }

    /// Reacts to a message (chat.reactions); `remove` takes it back.
    pub fn react(&mut self, gid: &[u8], id: &str, emoji: &str, remove: bool) -> Result<(), Error> {
        if !self.chat_allows(gid, "chat.reactions")? {
            return Err(Self::locked_by_chat());
        }
        if emoji.is_empty() || emoji.chars().count() > 8 {
            return Err(Error::Usage("a reaction is one emoji".into()));
        }
        let m = self.client.message(gid, id)?.ok_or_else(|| Error::Usage("no such message".into()))?;
        if m.deleted {
            return Err(Error::Usage("the message was deleted".into()));
        }
        let me = self.member_id().to_hex();
        self.queue_payload(gid, &Payload::React { id: id.into(), emoji: emoji.into(), remove, sticker: None }, None, |s| {
            Ok(s.client.react(gid, id, &me, emoji, remove)?)
        })?;
        Ok(())
    }

    /// Encrypts `bytes` with a fresh key, uploads the ciphertext and sends the
    /// key inside the group (PROTOCOL.md 6.12). `view_once` needs
    /// `chat.view_once`; every file needs `chat.media`.
    pub fn send_file(&mut self, gid: &[u8], bytes: &[u8], name: &str, mime: &str, view_once: bool) -> Result<FileInfo, Error> {
        self.send_attachment(gid, bytes, name, mime, view_once, None)
    }

    /// Sends a voice message (`chat.voice` and `chat.media`).
    pub fn send_voice(&mut self, gid: &[u8], bytes: &[u8], mime: &str, duration_ms: u64) -> Result<FileInfo, Error> {
        self.send_attachment(gid, bytes, "voice", mime, false, Some(duration_ms))
    }

    fn send_attachment(
        &mut self,
        gid: &[u8],
        bytes: &[u8],
        name: &str,
        mime: &str,
        view_once: bool,
        voice: Option<u64>,
    ) -> Result<FileInfo, Error> {
        self.send_attachment_as(gid, bytes, name, mime, view_once, voice, FileKind::default())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn send_attachment_as(
        &mut self,
        gid: &[u8],
        bytes: &[u8],
        name: &str,
        mime: &str,
        view_once: bool,
        voice: Option<u64>,
        kind: FileKind,
    ) -> Result<FileInfo, Error> {
        if !self.chat_allows(gid, "chat.media")?
            || (view_once && !self.chat_allows(gid, "chat.view_once")?)
            || (voice.is_some() && !self.chat_allows(gid, "chat.voice")?)
            || (kind.gif && !self.chat_allows(gid, "chat.gifs")?)
            || (kind.video_note.is_some() && !self.chat_allows(gid, "chat.video_notes")?)
        {
            return Err(Self::locked_by_chat());
        }
        let (ct, fk) = tree_core::attachment::encrypt(bytes)?;
        let id = self.api.upload(&self.creds, &ct)?;
        let info = FileInfo {
            msg_id: new_id(),
            view_once,
            voice: voice.is_some(),
            duration_ms: voice.or(kind.video_note),
            gif: kind.gif,
            video_note: kind.video_note.is_some(),
            id,
            key: api::b64(&fk.key[..]),
            nonce: api::b64(&fk.nonce_prefix),
            size: fk.size,
            ct_sha256: hex::encode(fk.ciphertext_sha256),
            pt_sha256: hex::encode(fk.plaintext_sha256),
            name: name.to_string(),
            mime: mime.to_string(),
        };
        // The sender keeps no reference to a view-once file.
        let data = (!view_once).then(|| serde_json::to_vec(&info).expect("JSON"));
        let me = self.member_id();
        self.queue_payload(gid, &Payload::File(info.clone()), Some(&info.msg_id), |s| {
            s.store(gid, &info.msg_id, &me, "file", Some(info.name.clone()), data, None).map(|_| ())
        })?;
        Ok(info)
    }

    /// A file reference received earlier, by attachment id (gone after a
    /// view-once file was opened).
    pub fn received_file(&self, id: &str) -> Result<Option<FileInfo>, Error> {
        Ok(match self.client.app_data(&format!("file/{id}"))? {
            Some(v) => Some(serde_json::from_slice::<StoredFile>(&v).map_err(|_| Error::Protocol("damaged file reference".into()))?.info),
            None => None,
        })
    }

    /// Downloads and opens an attachment; fails if anything does not match
    /// the message (tampering, wrong key, different content). A view-once
    /// file's reference is deleted after it opened once.
    pub fn download(&self, f: &FileInfo) -> Result<Vec<u8>, Error> {
        let bad = || Error::Protocol("malformed file reference".into());
        let key: [u8; 32] = api::unb64(&f.key)?.try_into().map_err(|_| bad())?;
        let nonce: [u8; 7] = api::unb64(&f.nonce)?.try_into().map_err(|_| bad())?;
        let ct_h: [u8; 32] = hex::decode(&f.ct_sha256).map_err(|_| bad())?.try_into().map_err(|_| bad())?;
        let pt_h: [u8; 32] = hex::decode(&f.pt_sha256).map_err(|_| bad())?.try_into().map_err(|_| bad())?;
        let fk = tree_core::attachment::FileKey {
            key: Zeroizing::new(key),
            nonce_prefix: nonce,
            size: f.size,
            ciphertext_sha256: ct_h,
            plaintext_sha256: pt_h,
        };
        let ct = self.api.download(&self.creds, &f.id)?;
        let plain = tree_core::attachment::decrypt(&ct, &fk)?;
        if f.view_once {
            if let Some(v) = self.client.app_data(&format!("file/{}", f.id))? {
                if let Ok(sf) = serde_json::from_slice::<StoredFile>(&v) {
                    if let Ok(g) = hex::decode(&sf.group) {
                        self.client.set_message_data(&g, &f.msg_id, None)?;
                    }
                }
            }
            self.client.set_app_data(&format!("file/{}", f.id), None)?;
        }
        Ok(plain)
    }

    /// The newest `limit` messages of a group (oldest first), after removing
    /// expired ones.
    pub fn history(&self, gid: &[u8], limit: u32) -> Result<Vec<StoredMessage>, Error> {
        self.client.purge_expired_messages(now())?;
        Ok(self.client.messages(gid, limit, None)?)
    }

    /// Searches the history on this device (`user.search_index`).
    pub fn search(&self, needle: &str) -> Result<Vec<StoredMessage>, Error> {
        if !self.is_applied("user.search_index")? {
            return Err(Error::Feature("RELEASED".into()));
        }
        self.client.purge_expired_messages(now())?;
        Ok(self.client.search_messages(needle, 100)?)
    }

    /// Handles a message-type payload from member `from` (blocked senders
    /// were filtered already).
    /// `franking` is the record that lets this device report the message.
    pub(crate) fn on_message(
        &mut self,
        gid: &[u8],
        from: MemberId,
        p: Payload,
        franking: Option<Vec<u8>>,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let refuse = |events: &mut Vec<Event>, why: &str| events.push(Event::Dropped { reason: why.to_string() });
        self.note_traffic(gid)?;
        let request = matches!(self.group_status(gid)?, GroupStatus::Request { .. });
        let name = self.names(gid)?.get(&from.to_hex()).cloned();
        match p {
            Payload::Text { id, text, fmt, mentions, all, preview, silent } => {
                // A preview is shown only while this user wants previews.
                let preview = match preview {
                    Some(p) if p.is_valid() && self.is_applied("user.link_preview")? => Some(p),
                    _ => None,
                };
                // Formatting the group released is shown as plain text; an
                // @all the sender may not make is ignored.
                let formatted = fmt && self.chat_allows(gid, "chat.formatting")?;
                let me = self.member_id().to_hex();
                let all = all && self.may_mention_all(gid, &from)?;
                let mentions_me = all || mentions.iter().take(MAX_MENTIONS).any(|m| *m == me);
                if !self.store(gid, &id, &from, "text", Some(text.clone()), text_data(formatted, preview.as_ref(), silent), franking)? {
                    refuse(events, "duplicate message id");
                    return Ok(());
                }
                self.on_new_message(gid, silent)?;
                events.push(Event::Text { group: gid.to_vec(), id, from, name, text, request, formatted, mentions_me, preview, silent });
            }
            Payload::Edit { id, text } => match self.changeable_by(gid, &id, &from, "chat.edit")? {
                Ok(m) if m.kind == "text" => {
                    self.client.edit_message(gid, &id, &text, now(), franking.as_deref())?;
                    events.push(Event::Edited { group: gid.to_vec(), id, from, text });
                }
                Ok(_) => refuse(events, "only text can be edited"),
                Err(why) => refuse(events, why),
            },
            Payload::Delete { id } => match self.changeable_by(gid, &id, &from, "chat.delete_for_all")? {
                Ok(_) => {
                    self.client.delete_message(gid, &id)?;
                    events.push(Event::Deleted { group: gid.to_vec(), id, from });
                }
                Err(why) => refuse(events, why),
            },
            Payload::React { id, emoji, remove, sticker } => {
                if !self.chat_allows(gid, "chat.reactions")? {
                    refuse(events, "reactions are released in this group (chat.reactions)");
                    return Ok(());
                }
                if emoji.is_empty() || emoji.chars().count() > 8 {
                    refuse(events, "malformed reaction");
                    return Ok(());
                }
                // A custom emoji counts as itself only while the chat
                // allows stickers; otherwise as its plain emoji.
                let emoji = match sticker {
                    Some(st) => self.custom_reaction_key(gid, &st)?.unwrap_or(emoji),
                    None => emoji,
                };
                match self.client.message(gid, &id)? {
                    Some(m) if !m.deleted => {
                        self.client.react(gid, &id, &from.to_hex(), &emoji, remove)?;
                        events.push(Event::Reaction { group: gid.to_vec(), id, from, emoji, remove });
                    }
                    _ => refuse(events, "reaction to an unknown message"),
                }
            }
            Payload::File(file) => {
                if !self.chat_allows(gid, "chat.media")? {
                    refuse(events, "attachments are released in this group (chat.media)");
                    return Ok(());
                }
                if file.voice && !self.chat_allows(gid, "chat.voice")? {
                    refuse(events, "voice messages are released in this group (chat.voice)");
                    return Ok(());
                }
                if file.view_once && !self.chat_allows(gid, "chat.view_once")? {
                    refuse(events, "view-once files are released in this group (chat.view_once)");
                    return Ok(());
                }
                if file.gif && !self.chat_allows(gid, "chat.gifs")? {
                    refuse(events, "GIFs are released in this group (chat.gifs)");
                    return Ok(());
                }
                if file.video_note && !self.chat_allows(gid, "chat.video_notes")? {
                    refuse(events, "video notes are released in this group (chat.video_notes)");
                    return Ok(());
                }
                let data = serde_json::to_vec(&file).expect("JSON");
                if !self.store(gid, &file.msg_id, &from, "file", Some(file.name.clone()), Some(data), franking)? {
                    refuse(events, "duplicate message id");
                    return Ok(());
                }
                let stored = StoredFile { group: hex::encode(gid), info: file.clone() };
                self.client.set_app_data(&format!("file/{}", file.id), Some(&serde_json::to_vec(&stored).expect("JSON")))?;
                self.on_new_message(gid, false)?;
                events.push(Event::File { group: gid.to_vec(), from, name, file, request });
            }
            _ => refuse(events, "not a message"),
        }
        Ok(())
    }

    /// May `from` still edit or delete message `id` under `key`? Measured
    /// from when this device received the original.
    fn changeable_by(&mut self, gid: &[u8], id: &str, from: &MemberId, key: &str) -> Result<Result<StoredMessage, &'static str>, Error> {
        if !self.chat_allows(gid, key)? {
            return Ok(Err("released in this group"));
        }
        let Some(m) = self.client.message(gid, id)? else { return Ok(Err("unknown message")) };
        if m.sender != from.to_hex() {
            return Ok(Err("only the sender may change a message"));
        }
        if m.deleted {
            return Ok(Err("the message was deleted"));
        }
        if now() - m.received_at > self.window(gid, key)? {
            return Ok(Err("too late to change this message"));
        }
        Ok(Ok(m))
    }
}

#[cfg(test)]
mod tests {
    /// The design's edit / delete window: 24 hours.
    #[test]
    fn default_window_is_a_day() {
        assert_eq!(super::DEFAULT_WINDOW, 86_400);
    }
}
