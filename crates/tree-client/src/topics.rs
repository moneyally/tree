//! Topics: threads inside a group (`chat.topics`, APP_PROTOCOL.md 9.1).
//!
//! A topic is shared state carried by MLS application messages, like pins:
//! `topic` creates (new id, with a name), renames, closes or reopens one,
//! and every device applies it to its own list (`topics/<group hex>`) after
//! checking, with the MLS-authenticated sender:
//!
//! * `chat.topics` must be applied (released: no topics are shown, a
//!   topic on a message is ignored and the message shows in the main chat);
//! * creating needs an admin or a role with `topics`, or any member when
//!   the option is `all`; renaming, closing and reopening need an admin or a
//!   role with `topics`;
//! * at most [`MAX_TOPICS`] topics, names 1 to [`MAX_TOPIC_NAME`]
//!   characters;
//! * a message in a closed topic from a member who may not manage topics
//!   is dropped.
//!
//! Texts and files carry the topic id (`topic`); other kinds belong to the
//! main chat. Unread counts are kept per topic on the device. A member who
//! joins later learns the topics from a `topics` list the adder sends (if
//! the adder may manage topics); a message in a topic this device does not
//! know is kept under that id and shown as an unnamed topic.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tree_core::group_settings::perm;
use tree_core::storage::messages::StoredMessage;
use tree_core::MemberId;

use crate::messages::{new_id, now};
use crate::payload::{Payload, TopicDef};
use crate::{Error, Event, Session};

/// Topics per group.
pub const MAX_TOPICS: usize = 100;
/// Longest topic name, in characters.
pub const MAX_TOPIC_NAME: usize = 64;
/// Longest topic id taken from another device.
const MAX_TOPIC_ID: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    id: String,
    name: String,
    #[serde(default)]
    closed: bool,
    by: String,
    at: i64,
}

/// A topic as the apps show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topic {
    pub id: String,
    pub name: String,
    pub closed: bool,
    /// Who created it (member id), as this device saw it.
    pub created_by: Option<MemberId>,
    /// Messages in it since the user last read it.
    pub unread: u32,
}

fn topics_key(gid: &[u8]) -> String {
    format!("topics/{}", hex::encode(gid))
}

fn unread_key(gid: &[u8]) -> String {
    format!("topicunread/{}", hex::encode(gid))
}

fn valid_name(n: &str) -> bool {
    let c = n.trim().chars().count();
    (1..=MAX_TOPIC_NAME).contains(&c) && n.chars().count() <= MAX_TOPIC_NAME && !n.chars().any(char::is_control)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_TOPIC_ID && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The topic a stored text or file belongs to (from its data).
pub fn message_topic(m: &StoredMessage) -> Option<String> {
    let v: serde_json::Value = m.data.as_deref().and_then(|d| serde_json::from_slice(d).ok())?;
    v["topic"].as_str().map(str::to_string)
}

impl Session {
    fn stored_topics(&self, gid: &[u8]) -> Result<Vec<Stored>, Error> {
        Ok(self.app_get(&topics_key(gid))?.unwrap_or_default())
    }

    fn save_topics(&self, gid: &[u8], v: &[Stored]) -> Result<(), Error> {
        self.app_put(&topics_key(gid), (!v.is_empty()).then_some(&v))
    }

    fn topics_on(&mut self, gid: &[u8]) -> Result<bool, Error> {
        self.chat_on(gid, "chat.topics")
    }

    /// May `who` create topics: `chat.topics` applied and an admin or a
    /// role with `topics`, or anyone with the option `all`.
    fn may_create_topic(&mut self, gid: &[u8], who: &MemberId) -> Result<bool, Error> {
        let (on, opt) = self.chat_feature(gid, "chat.topics")?;
        Ok(on && (opt.as_deref() == Some("all") || self.member_may(gid, who, perm::TOPICS)?))
    }

    /// May this device create topics in the group?
    pub fn may_create_topics(&mut self, gid: &[u8]) -> Result<bool, Error> {
        let me = self.member_id();
        self.may_create_topic(gid, &me)
    }

    /// May this device rename, close and reopen topics?
    pub fn may_manage_topics(&mut self, gid: &[u8]) -> Result<bool, Error> {
        Ok(self.topics_on(gid)? && self.may(gid, perm::TOPICS)?)
    }

    /// The group's topics on this device with their unread counts (none
    /// while `chat.topics` is released).
    pub fn topics(&mut self, gid: &[u8]) -> Result<Vec<Topic>, Error> {
        if !self.topics_on(gid)? {
            return Ok(vec![]);
        }
        let unread: BTreeMap<String, u32> = self.app_get(&unread_key(gid))?.unwrap_or_default();
        let mut out: Vec<Topic> = self
            .stored_topics(gid)?
            .into_iter()
            .map(|t| Topic {
                unread: unread.get(&t.id).copied().unwrap_or(0),
                created_by: MemberId::from_hex(&t.by),
                id: t.id,
                name: t.name,
                closed: t.closed,
            })
            .collect();
        // Messages in topics this device was never told about.
        for (id, n) in unread {
            if !out.iter().any(|t| t.id == id) {
                out.push(Topic { id, name: String::new(), closed: false, created_by: None, unread: n });
            }
        }
        Ok(out)
    }

    /// Whether `from` may make this topic change (sender and receivers
    /// alike). `Err` is the reason it does not apply.
    fn topic_change_ok(&mut self, gid: &[u8], from: &MemberId, id: &str, name: Option<&str>) -> Result<Result<(), &'static str>, Error> {
        if !self.topics_on(gid)? {
            return Ok(Err("topics are released in this group (chat.topics)"));
        }
        if !valid_id(id) || name.is_some_and(|n| !valid_name(n)) {
            return Ok(Err("malformed topic"));
        }
        let v = self.stored_topics(gid)?;
        if v.iter().any(|t| t.id == id) {
            if !self.member_may(gid, from, perm::TOPICS)? {
                return Ok(Err("only admins and roles with the topics permission change topics"));
            }
        } else {
            if name.is_none() {
                return Ok(Err("unknown topic"));
            }
            if !self.may_create_topic(gid, from)? {
                return Ok(Err("only admins and roles with the topics permission create topics here"));
            }
            if v.len() >= MAX_TOPICS {
                return Ok(Err("too many topics"));
            }
        }
        Ok(Ok(()))
    }

    /// Applies a topic change to this device's list (sender and receivers
    /// alike). `Err` is the reason it does not apply.
    fn apply_topic(&mut self, gid: &[u8], from: &MemberId, id: &str, name: Option<&str>, closed: Option<bool>) -> Result<Result<(), &'static str>, Error> {
        if let Err(why) = self.topic_change_ok(gid, from, id, name)? {
            return Ok(Err(why));
        }
        let mut v = self.stored_topics(gid)?;
        match v.iter_mut().find(|t| t.id == id) {
            None => {
                let name = name.unwrap_or_default();
                v.push(Stored { id: id.into(), name: name.trim().into(), closed: closed.unwrap_or(false), by: from.to_hex(), at: now() });
            }
            Some(t) => {
                if let Some(n) = name {
                    t.name = n.trim().into();
                }
                if let Some(c) = closed {
                    t.closed = c;
                }
            }
        }
        self.save_topics(gid, &v)?;
        let action = match (name, closed) {
            (_, Some(true)) => "topic_close",
            (_, Some(false)) => "topic_reopen",
            _ => "topic",
        };
        self.log_admin(gid, from, action, Some(id.to_string()), name.map(str::to_string))?;
        Ok(Ok(()))
    }

    fn send_topic(&mut self, gid: &[u8], id: &str, name: Option<&str>, closed: Option<bool>) -> Result<(), Error> {
        let me = self.member_id();
        // Checked here exactly as receivers check it.
        if let Err(w) = self.topic_change_ok(gid, &me, id, name)? {
            return Err(if w.contains("released") {
                Error::Feature("LOCKED_BY_CHAT".into())
            } else if w.starts_with("only") {
                Error::Feature("NOT_ADMIN".into())
            } else {
                Error::Usage(w.into())
            });
        }
        let p = Payload::Topic { id: id.into(), name: name.map(str::to_string), closed };
        self.queue_payload(gid, &p, None, |s| s.apply_topic(gid, &me, id, name, closed).map(|_| ()))?;
        Ok(())
    }

    /// Creates a topic; returns its id.
    pub fn create_topic(&mut self, gid: &[u8], name: &str) -> Result<String, Error> {
        if !valid_name(name) {
            return Err(Error::Usage(format!("a topic name is 1 to {MAX_TOPIC_NAME} characters")));
        }
        let id = new_id()[..16].to_string();
        self.send_topic(gid, &id, Some(name), None)?;
        Ok(id)
    }

    pub fn rename_topic(&mut self, gid: &[u8], id: &str, name: &str) -> Result<(), Error> {
        if !self.stored_topics(gid)?.iter().any(|t| t.id == id) {
            return Err(Error::Usage("no such topic".into()));
        }
        self.send_topic(gid, id, Some(name), None)
    }

    /// Closes (or with `closed = false` reopens) a topic: only members who
    /// may manage topics write in a closed one.
    pub fn close_topic(&mut self, gid: &[u8], id: &str, closed: bool) -> Result<(), Error> {
        if !self.stored_topics(gid)?.iter().any(|t| t.id == id) {
            return Err(Error::Usage("no such topic".into()));
        }
        self.send_topic(gid, id, None, Some(closed))
    }

    /// The sending side's check of a message's topic.
    pub(crate) fn check_send_topic(&mut self, gid: &[u8], topic: Option<&str>) -> Result<(), Error> {
        let Some(id) = topic else { return Ok(()) };
        if !self.topics_on(gid)? {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        let t = self.stored_topics(gid)?.into_iter().find(|t| t.id == id).ok_or_else(|| Error::Usage("no such topic".into()))?;
        if t.closed && !self.may(gid, perm::TOPICS)? {
            return Err(Error::Usage("the topic is closed".into()));
        }
        Ok(())
    }

    /// The receiving side: the topic a message from `from` is kept under
    /// (`Ok(None)`: the main chat), or the reason it is dropped.
    pub(crate) fn receive_topic(&mut self, gid: &[u8], from: &MemberId, topic: Option<String>) -> Result<Result<Option<String>, &'static str>, Error> {
        let Some(id) = topic else { return Ok(Ok(None)) };
        if !self.topics_on(gid)? {
            return Ok(Ok(None));
        }
        if !valid_id(&id) {
            return Ok(Err("malformed topic"));
        }
        let closed = self.stored_topics(gid)?.iter().any(|t| t.id == id && t.closed);
        if closed && !self.member_may(gid, from, perm::TOPICS)? {
            return Ok(Err("the topic is closed"));
        }
        Ok(Ok(Some(id)))
    }

    /// One more unread message in `topic`.
    pub(crate) fn note_topic_message(&self, gid: &[u8], topic: &str) -> Result<(), Error> {
        let mut u: BTreeMap<String, u32> = self.app_get(&unread_key(gid))?.unwrap_or_default();
        *u.entry(topic.to_string()).or_default() += 1;
        self.app_put(&unread_key(gid), Some(&u))
    }

    /// The user read a topic: its unread count goes back to zero.
    pub fn mark_topic_read(&self, gid: &[u8], topic: &str) -> Result<(), Error> {
        let mut u: BTreeMap<String, u32> = self.app_get(&unread_key(gid))?.unwrap_or_default();
        u.remove(topic);
        self.app_put(&unread_key(gid), (!u.is_empty()).then_some(&u))
    }

    /// The newest `limit` messages of a topic (`None`: the main chat, the
    /// messages without a topic), oldest first.
    pub fn topic_history(&self, gid: &[u8], topic: Option<&str>, limit: u32) -> Result<Vec<StoredMessage>, Error> {
        self.client.purge_expired_messages(now())?;
        let mut out: Vec<StoredMessage> =
            self.client.messages(gid, u32::MAX, None)?.into_iter().filter(|m| message_topic(m).as_deref() == topic).collect();
        let skip = out.len().saturating_sub(limit as usize);
        out.drain(..skip);
        Ok(out)
    }

    /// A `topic` payload from `from`.
    pub(crate) fn on_topic(&mut self, gid: &[u8], from: MemberId, id: String, name: Option<String>, closed: Option<bool>, events: &mut Vec<Event>) -> Result<(), Error> {
        match self.apply_topic(gid, &from, &id, name.as_deref(), closed)? {
            Ok(()) => events.push(Event::TopicChanged { group: gid.to_vec(), id, from }),
            Err(why) => events.push(Event::Dropped { reason: why.into() }),
        }
        Ok(())
    }

    /// A `topics` list: entries this device does not know are taken, from a
    /// sender who may manage topics.
    pub(crate) fn on_topic_list(&mut self, gid: &[u8], from: MemberId, list: Vec<TopicDef>, events: &mut Vec<Event>) -> Result<(), Error> {
        if !self.topics_on(gid)? || !self.member_may(gid, &from, perm::TOPICS)? {
            events.push(Event::Dropped { reason: "topic list from a member who may not manage topics".into() });
            return Ok(());
        }
        let mut v = self.stored_topics(gid)?;
        let mut changed = false;
        for t in list.into_iter().take(MAX_TOPICS) {
            if v.len() >= MAX_TOPICS || !valid_id(&t.id) || !valid_name(&t.name) || v.iter().any(|s| s.id == t.id) {
                continue;
            }
            v.push(Stored { id: t.id, name: t.name.trim().into(), closed: t.closed, by: from.to_hex(), at: now() });
            changed = true;
        }
        if changed {
            self.save_topics(gid, &v)?;
            events.push(Event::TopicChanged { group: gid.to_vec(), id: String::new(), from });
        }
        Ok(())
    }

    /// After adding members: the topic list for them, if this device may
    /// manage topics and there are any. Best effort.
    pub(crate) fn send_topic_list(&mut self, gid: &[u8]) -> Result<(), Error> {
        if !self.may_manage_topics(gid)? {
            return Ok(());
        }
        let list: Vec<TopicDef> = self.stored_topics(gid)?.into_iter().map(|t| TopicDef { id: t.id, name: t.name, closed: t.closed }).collect();
        if !list.is_empty() {
            self.send_payload(gid, &Payload::Topics { list })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_ids() {
        assert!(valid_name("일정") && valid_name(&"a".repeat(64)));
        assert!(!valid_name("") && !valid_name("   ") && !valid_name(&"a".repeat(65)) && !valid_name("a\u{0}b"));
        assert!(valid_id("0123abcd") && !valid_id("") && !valid_id("a/b") && !valid_id(&"a".repeat(33)));
    }
}
