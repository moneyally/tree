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
//! | `chat.edit` | applied, window 86400 s | own messages editable within the window |
//! | `chat.delete_for_all` | applied, window 86400 s | own messages deletable for everyone within the window |
//! | `chat.reactions` | applied | reactions allowed |
//! | `chat.view_once` | applied | view-once files allowed |
//! | `chat.disappearing` | released; option = seconds | every message expires that long after it arrives |
//!
//! Windows are measured with this device's own clock from when it received
//! (or sent) the original, never from a time the sender claims.

use std::time::{SystemTime, UNIX_EPOCH};

use tree_core::features::{Registry, State};
use tree_core::storage::messages::StoredMessage;
use tree_core::MemberId;
use zeroize::Zeroizing;

use crate::payload::{FileInfo, Payload};
use crate::{api, Error, Event, GroupStatus, Session};

/// Default edit / delete-for-all window (design: 24 hours).
pub const DEFAULT_WINDOW: i64 = 24 * 3600;

pub(crate) fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn new_id() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("operating system random number generator failed");
    hex::encode(b)
}

/// A stored file reference: which group and message it belongs to.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredFile {
    group: String,
    info: FileInfo,
}

impl Session {
    /// A chat feature as the group's admins set it (or its default).
    pub(crate) fn chat_feature(&mut self, gid: &[u8], key: &str) -> Result<(bool, Option<String>), Error> {
        if let Some(s) = self.group_settings(gid)?.features.get(key) {
            return Ok((s.applied, s.option.clone()));
        }
        let st = Registry::standard().status(key).map_err(|e| Error::Feature(e.code().into()))?;
        Ok((st.state == State::Applied, st.option))
    }

    fn chat_allows(&mut self, gid: &[u8], key: &str) -> Result<bool, Error> {
        Ok(self.chat_feature(gid, key)?.0)
    }

    /// Edit / delete window in seconds (option of the feature, or the default).
    fn window(&mut self, gid: &[u8], key: &str) -> Result<i64, Error> {
        let (_, opt) = self.chat_feature(gid, key)?;
        Ok(opt.and_then(|o| o.parse().ok()).unwrap_or(DEFAULT_WINDOW))
    }

    /// When a message arriving now should disappear, if the group says so.
    fn expiry(&mut self, gid: &[u8]) -> Result<Option<i64>, Error> {
        let (on, opt) = self.chat_feature(gid, "chat.disappearing")?;
        Ok(if on { opt.and_then(|o| o.parse::<i64>().ok()).filter(|s| *s > 0).map(|s| now() + s) } else { None })
    }

    fn store(&mut self, gid: &[u8], id: &str, sender: &MemberId, kind: &str, text: Option<String>, data: Option<Vec<u8>>) -> Result<bool, Error> {
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
        })?)
    }

    fn locked_by_chat() -> Error {
        Error::Feature("LOCKED_BY_CHAT".into())
    }

    /// Sends a text message; returns its id.
    pub fn send_text(&mut self, gid: &[u8], text: &str) -> Result<String, Error> {
        let id = new_id();
        self.send_payload(gid, &Payload::Text { id: id.clone(), text: text.to_string() })?;
        let me = self.member_id();
        self.store(gid, &id, &me, "text", Some(text.to_string()), None)?;
        Ok(id)
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
        self.send_payload(gid, &Payload::Edit { id: id.into(), text: text.into() })?;
        Ok(self.client.edit_message(gid, id, text, now())?)
    }

    /// Deletes one of this device's own messages for everyone (chat.delete_for_all).
    pub fn delete_for_all(&mut self, gid: &[u8], id: &str) -> Result<(), Error> {
        self.own_changeable(gid, id, "chat.delete_for_all")?;
        self.send_payload(gid, &Payload::Delete { id: id.into() })?;
        Ok(self.client.delete_message(gid, id)?)
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
        self.send_payload(gid, &Payload::React { id: id.into(), emoji: emoji.into(), remove })?;
        let me = self.member_id().to_hex();
        Ok(self.client.react(gid, id, &me, emoji, remove)?)
    }

    /// Encrypts `bytes` with a fresh key, uploads the ciphertext and sends the
    /// key inside the group (PROTOCOL.md 6.12). `view_once` needs
    /// `chat.view_once`; every file needs `chat.media`.
    pub fn send_file(&mut self, gid: &[u8], bytes: &[u8], name: &str, mime: &str, view_once: bool) -> Result<FileInfo, Error> {
        if !self.chat_allows(gid, "chat.media")? || (view_once && !self.chat_allows(gid, "chat.view_once")?) {
            return Err(Self::locked_by_chat());
        }
        let (ct, fk) = tree_core::attachment::encrypt(bytes)?;
        let id = self.api.upload(&self.creds, &ct)?;
        let info = FileInfo {
            msg_id: new_id(),
            view_once,
            id,
            key: api::b64(&fk.key[..]),
            nonce: api::b64(&fk.nonce_prefix),
            size: fk.size,
            ct_sha256: hex::encode(fk.ciphertext_sha256),
            pt_sha256: hex::encode(fk.plaintext_sha256),
            name: name.to_string(),
            mime: mime.to_string(),
        };
        self.send_payload(gid, &Payload::File(info.clone()))?;
        // The sender keeps no reference to a view-once file.
        let data = (!view_once).then(|| serde_json::to_vec(&info).expect("JSON"));
        let me = self.member_id();
        self.store(gid, &info.msg_id, &me, "file", Some(info.name.clone()), data)?;
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
    pub(crate) fn on_message(&mut self, gid: &[u8], from: MemberId, p: Payload, events: &mut Vec<Event>) -> Result<(), Error> {
        let refuse = |events: &mut Vec<Event>, why: &str| events.push(Event::Dropped { reason: why.to_string() });
        let request = matches!(self.group_status(gid)?, GroupStatus::Request { .. });
        let name = self.names(gid)?.get(&from.to_hex()).cloned();
        match p {
            Payload::Text { id, text } => {
                if !self.store(gid, &id, &from, "text", Some(text.clone()), None)? {
                    refuse(events, "duplicate message id");
                    return Ok(());
                }
                events.push(Event::Text { group: gid.to_vec(), id, from, name, text, request });
            }
            Payload::Edit { id, text } => match self.changeable_by(gid, &id, &from, "chat.edit")? {
                Ok(m) if m.kind == "text" => {
                    self.client.edit_message(gid, &id, &text, now())?;
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
            Payload::React { id, emoji, remove } => {
                if !self.chat_allows(gid, "chat.reactions")? {
                    refuse(events, "reactions are released in this group (chat.reactions)");
                    return Ok(());
                }
                if emoji.is_empty() || emoji.chars().count() > 8 {
                    refuse(events, "malformed reaction");
                    return Ok(());
                }
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
                if file.view_once && !self.chat_allows(gid, "chat.view_once")? {
                    refuse(events, "view-once files are released in this group (chat.view_once)");
                    return Ok(());
                }
                let data = serde_json::to_vec(&file).expect("JSON");
                if !self.store(gid, &file.msg_id, &from, "file", Some(file.name.clone()), Some(data))? {
                    refuse(events, "duplicate message id");
                    return Ok(());
                }
                let stored = StoredFile { group: hex::encode(gid), info: file.clone() };
                self.client.set_app_data(&format!("file/{}", file.id), Some(&serde_json::to_vec(&stored).expect("JSON")))?;
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
