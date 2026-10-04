//! Recent history for new members (`chat.history_share`, option 25 to 100
//! messages, APP_PROTOCOL.md 9.5).
//!
//! Design: the device whose commit added the new members re-sends its
//! newest N texts and files in ONE `history` application message to the
//! group, naming the new members in `to`. It travels inside MLS like any
//! message (the server sees one more ciphertext of the usual kind and
//! nothing about its content or its addressees). Other members' devices
//! ignore a bundle not addressed to them. No separate group is needed.
//!
//! A receiving device takes a bundle only if:
//! * its own member id is in `to`, and `chat.history_share` is applied in
//!   the group settings it holds;
//! * the MLS-authenticated sender is a current member and is the member
//!   that added this device: the signer of the welcome's group info, as
//!   MLS verified it when this device joined (not the sender of some
//!   roster, which any member could race);
//! * it is the first bundle, within a day of joining.
//!
//! Honest limit: the original messages' MLS authentication is not carried
//! (it cannot be: MLS signatures cover the sending context, not a
//! re-sendable record). Authors, names and times inside a bundle are the
//! sharing member's claims. Apps show every shared message with a "shared
//! by X" label, X being the authenticated sharer, named like any author:
//! its own announced name, and an account only as
//! [`Session::shared_by_account`] gives it (the account this device has
//! the sharer pinned for, F-021/F-022; never a roster label alone, and never
//! the `name` a bundle carries, which is not kept). Shared messages are not
//! franked again and cannot be reported as the original author's; edits
//! and deletions by the claimed author apply to them like to any message.
//! View-once files, messages that were themselves shared, and deleted
//! messages are never re-sent. While the setting is applied, the apps show
//! the notice "new members see the recent conversation".

use std::collections::BTreeMap;

use tree_core::features;
use tree_core::MemberId;

use crate::messages::now;
use crate::payload::{FileInfo, Payload, SharedMsg};
use crate::topics::message_topic;
use crate::{Error, Event, Session};

/// Largest encoded bundle (the server takes 256 KiB per message; MLS and
/// the envelope add a little).
pub const MAX_BUNDLE: usize = 200 * 1024;
/// Longest text re-sent, in characters (longer ones are cut).
pub const MAX_SHARED_TEXT: usize = 4096;
/// A bundle is taken only this long after joining.
const JOIN_WINDOW: i64 = 86400;

fn shared_key(gid: &[u8]) -> String {
    format!("shared/{}", hex::encode(gid))
}

pub(crate) fn taken_key(gid: &[u8]) -> String {
    format!("histtaken/{}", hex::encode(gid))
}

pub(crate) fn joined_key(gid: &[u8]) -> String {
    format!("joined/{}", hex::encode(gid))
}

pub(crate) fn adder_key(gid: &[u8]) -> String {
    format!("adder/{}", hex::encode(gid))
}

impl Session {
    /// How many messages new members get, while `chat.history_share` is
    /// applied. Apps show "new members see the recent conversation" then.
    pub fn history_share(&mut self, gid: &[u8]) -> Result<Option<u32>, Error> {
        let (on, opt) = self.chat_feature(gid, "chat.history_share")?;
        Ok(if on { features::option_count("chat.history_share", opt.as_deref()).map(|n| n as u32) } else { None })
    }

    /// Who shared message `id` with this device (`None`: it was received
    /// directly). Its author is then only that member's claim.
    pub fn shared_by(&self, gid: &[u8], id: &str) -> Result<Option<MemberId>, Error> {
        let m: BTreeMap<String, String> = self.app_get(&shared_key(gid))?.unwrap_or_default();
        Ok(m.get(id).and_then(|h| MemberId::from_hex(h)))
    }

    /// The account of whoever shared message `id`, only if this device
    /// trusts the sharer as that account ([`Session::vouched_account`]: one
    /// of this account's devices, or a device pinned for a contact). A
    /// roster's label alone gives `None`.
    pub fn shared_by_account(&self, gid: &[u8], id: &str) -> Result<Option<String>, Error> {
        match self.shared_by(gid, id)? {
            Some(m) => self.vouched_account(gid, &m),
            None => Ok(None),
        }
    }

    /// Every shared message of the group: message id -> sharer (member id,
    /// hex), for labelling a whole history at once.
    pub fn shared_messages(&self, gid: &[u8]) -> Result<BTreeMap<String, String>, Error> {
        Ok(self.app_get(&shared_key(gid))?.unwrap_or_default())
    }

    /// After this device's commit added `new` members: one bundle of the
    /// newest messages for them, if the group shares history.
    pub(crate) fn share_history(&mut self, gid: &[u8], new: &[MemberId]) -> Result<(), Error> {
        let Some(n) = self.history_share(gid)? else { return Ok(()) };
        // The self group holds settings, not a conversation to share.
        if new.is_empty() || self.is_self_group(gid)? {
            return Ok(());
        }
        let shared: BTreeMap<String, String> = self.app_get(&shared_key(gid))?.unwrap_or_default();
        let names = self.names(gid)?;
        let mut msgs = Vec::new();
        for m in self.client.messages(gid, u32::MAX, None)?.into_iter().rev() {
            if msgs.len() >= n as usize {
                break;
            }
            if m.deleted || shared.contains_key(&m.id) {
                continue;
            }
            let (text, file) = match m.kind.as_str() {
                "text" => (m.text.clone().map(|t| t.chars().take(MAX_SHARED_TEXT).collect()), None),
                "file" => match m.data.as_deref().and_then(|d| serde_json::from_slice::<FileInfo>(d).ok()) {
                    Some(f) if !f.view_once && !f.id.is_empty() => (None, Some(FileInfo { thumb: None, ..f })),
                    _ => continue,
                },
                _ => continue,
            };
            msgs.push(SharedMsg {
                id: m.id.clone(),
                from: m.sender.clone(),
                name: names.get(&m.sender).cloned(),
                at: m.received_at,
                kind: m.kind.clone(),
                text,
                file,
                topic: message_topic(&m),
            });
        }
        msgs.reverse();
        let to: Vec<String> = new.iter().map(MemberId::to_hex).collect();
        // The oldest give way until the bundle fits one message.
        loop {
            let p = Payload::History { to: to.clone(), msgs: msgs.clone() };
            if p.encode().len() <= MAX_BUNDLE || msgs.is_empty() {
                if !msgs.is_empty() {
                    self.send_payload(gid, &p)?;
                }
                return Ok(());
            }
            let cut = (msgs.len() / 10).max(1);
            msgs.drain(..cut);
        }
    }

    /// A `history` bundle from `from` (see the module rules).
    pub(crate) fn on_history(&mut self, gid: &[u8], from: MemberId, to: Vec<String>, msgs: Vec<SharedMsg>, events: &mut Vec<Event>) -> Result<(), Error> {
        let me = self.member_id();
        if !to.contains(&me.to_hex()) {
            return Ok(()); // for someone else
        }
        let drop = |events: &mut Vec<Event>, why: &str| events.push(Event::Dropped { reason: format!("shared history: {why}") });
        let Some(n) = self.history_share(gid)? else {
            drop(events, "the group does not share history (chat.history_share)");
            return Ok(());
        };
        if !self.group(gid)?.members().contains(&from) {
            drop(events, "not from a current member");
            return Ok(());
        }
        let adder = self.client.app_data(&adder_key(gid))?.and_then(|v| String::from_utf8(v).ok());
        if adder.as_deref() != Some(from.to_hex().as_str()) {
            drop(events, "not from the member who added this device");
            return Ok(());
        }
        if self.client.app_data(&taken_key(gid))?.is_some() {
            drop(events, "already received");
            return Ok(());
        }
        if self.time_of(&joined_key(gid))?.is_none_or(|t| now() - t > JOIN_WINDOW) {
            drop(events, "too long after joining");
            return Ok(());
        }
        self.client.set_app_data(&taken_key(gid), Some(b"1"))?;
        let mut shared: BTreeMap<String, String> = self.app_get(&shared_key(gid))?.unwrap_or_default();
        let t = now();
        let mut count = 0u32;
        for m in msgs.into_iter().take(n as usize) {
            let Some(author) = MemberId::from_hex(&m.from) else { continue };
            if m.id.is_empty() || m.id.len() > crate::rich_media::MAX_ID || self.client.message(gid, &m.id)?.is_some() {
                continue;
            }
            let at = m.at.clamp(0, t);
            let topic = m.topic.filter(|_| self.chat_on(gid, "chat.topics").unwrap_or(false));
            let (kind, text, data) = match (m.kind.as_str(), m.text, m.file) {
                ("text", Some(text), None) if text.chars().count() <= MAX_SHARED_TEXT => {
                    let data = topic.map(|tp| serde_json::to_vec(&serde_json::json!({ "topic": tp })).expect("JSON"));
                    ("text", Some(text), data)
                }
                ("file", None, Some(f)) if f.is_valid() && !f.view_once && f.msg_id == m.id => {
                    let f = FileInfo { topic, ..f };
                    let name = f.name.clone();
                    ("file", Some(name), Some(serde_json::to_vec(&f).expect("JSON")))
                }
                _ => continue,
            };
            let expires_at = self.chat_feature(gid, "chat.disappearing")?;
            let expires_at = if expires_at.0 { features::option_seconds("chat.disappearing", expires_at.1.as_deref()).map(|s| t + s) } else { None };
            let stored = self.client.store_message(&tree_core::storage::messages::StoredMessage {
                group_id: gid.to_vec(),
                id: m.id.clone(),
                sender: author.to_hex(),
                received_at: at,
                kind: kind.into(),
                text,
                data,
                edited_at: None,
                deleted: false,
                expires_at,
                reactions: Default::default(),
                franking: None,
            })?;
            if stored {
                shared.insert(m.id, from.to_hex());
                count += 1;
            }
        }
        self.app_put(&shared_key(gid), Some(&shared))?;
        events.push(Event::HistoryShared { group: gid.to_vec(), by: from, count });
        Ok(())
    }
}
