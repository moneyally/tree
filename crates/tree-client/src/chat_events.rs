//! Events with replies (`chat.events`, APP_PROTOCOL.md 8.4).
//!
//! A member creates an event (title, time, place, description) inside the
//! chat; every member answers going / maybe / not, and every device keeps
//! the tally itself from the answers it received (the newest answer of a
//! member counts). Only the creator can change or cancel the event. All of
//! it travels inside MLS; the server sees ciphertext only.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tree_core::MemberId;

use crate::messages::now;
use crate::payload::{EventInfo, Payload};
use crate::{Error, Event, Session};

/// The answers a member can give.
pub const ANSWERS: [&str; 3] = ["going", "maybe", "not"];
pub const MAX_TITLE: usize = 200;
pub const MAX_PLACE: usize = 200;
pub const MAX_DESCRIPTION: usize = 2000;

/// What a new or changed event says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventDraft {
    pub title: String,
    /// Unix seconds.
    pub starts_at: i64,
    pub ends_at: Option<i64>,
    pub place: Option<String>,
    pub description: Option<String>,
}

/// The stored state of an event message (its `data`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    info: EventInfo,
    creator: String,
    #[serde(default)]
    cancelled: bool,
    #[serde(default)]
    edited_at: Option<i64>,
    /// Member id (hex) -> answer.
    #[serde(default)]
    answers: BTreeMap<String, String>,
}

/// An event as the apps show it, with the tally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatEventView {
    pub id: String,
    pub creator: String,
    pub title: String,
    pub starts_at: i64,
    pub ends_at: Option<i64>,
    pub place: Option<String>,
    pub description: Option<String>,
    pub cancelled: bool,
    pub edited: bool,
    /// Member ids (hex) per answer.
    pub going: Vec<String>,
    pub maybe: Vec<String>,
    pub not: Vec<String>,
    /// This device's own answer.
    pub mine: Option<String>,
}

fn opt(s: &Option<String>) -> Option<String> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn info_ok(i: &EventInfo) -> bool {
    let n = |s: &Option<String>, max: usize| s.as_ref().is_none_or(|s| s.chars().count() <= max);
    !i.id.is_empty()
        && i.id.len() <= crate::rich_media::MAX_ID
        && !i.title.trim().is_empty()
        && i.title.chars().count() <= MAX_TITLE
        && n(&i.place, MAX_PLACE)
        && n(&i.description, MAX_DESCRIPTION)
        && i.ends_at.is_none_or(|e| e >= i.starts_at)
}

impl EventDraft {
    fn info(&self, id: String) -> Result<EventInfo, Error> {
        let i = EventInfo {
            id,
            title: self.title.trim().to_string(),
            starts_at: self.starts_at,
            ends_at: self.ends_at,
            place: opt(&self.place),
            description: opt(&self.description),
        };
        if !info_ok(&i) {
            return Err(Error::Usage(format!(
                "an event needs a title of at most {MAX_TITLE} characters, a place of at most {MAX_PLACE}, a description of at most {MAX_DESCRIPTION}, and an end after its start"
            )));
        }
        Ok(i)
    }
}

impl Session {
    fn events_allowed(&mut self, gid: &[u8]) -> Result<(), Error> {
        if !self.chat_feature(gid, "chat.events")?.0 {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        Ok(())
    }

    fn stored_event(&self, gid: &[u8], id: &str) -> Result<Option<Stored>, Error> {
        Ok(match self.client.message(gid, id)? {
            Some(m) if m.kind == "event" && !m.deleted => m.data.as_deref().and_then(|d| serde_json::from_slice(d).ok()),
            _ => None,
        })
    }

    fn save_event(&self, gid: &[u8], s: &Stored) -> Result<(), Error> {
        Ok(self.client.set_message_data(gid, &s.info.id, Some(&serde_json::to_vec(s).expect("JSON")))?)
    }

    /// Creates an event in the chat (`chat.events`); returns its id.
    pub fn create_event(&mut self, gid: &[u8], draft: &EventDraft) -> Result<String, Error> {
        self.events_allowed(gid)?;
        let id = crate::messages::new_id();
        let info = draft.info(id.clone())?;
        let me = self.member_id();
        let s = Stored { info: info.clone(), creator: me.to_hex(), cancelled: false, edited_at: None, answers: BTreeMap::new() };
        let data = serde_json::to_vec(&s).expect("JSON");
        let title = info.title.clone();
        self.queue_payload(gid, &Payload::ChatEvent(info), Some(&id), |x| x.store(gid, &id, &me, "event", Some(title), Some(data), None).map(|_| ()))?;
        Ok(id)
    }

    fn own_event(&mut self, gid: &[u8], id: &str) -> Result<Stored, Error> {
        self.events_allowed(gid)?;
        let s = self.stored_event(gid, id)?.ok_or_else(|| Error::Usage("no such event".into()))?;
        if s.creator != self.member_id().to_hex() {
            return Err(Error::Usage("only the creator can change an event".into()));
        }
        if s.cancelled {
            return Err(Error::Usage("the event was cancelled".into()));
        }
        Ok(s)
    }

    /// The creator changes its event.
    pub fn edit_event(&mut self, gid: &[u8], id: &str, draft: &EventDraft) -> Result<(), Error> {
        let mut s = self.own_event(gid, id)?;
        s.info = draft.info(id.to_string())?;
        s.edited_at = Some(now());
        let p = Payload::EventEdit { event: s.info.clone(), cancelled: false };
        self.queue_payload(gid, &p, None, |x| x.save_event(gid, &s))?;
        Ok(())
    }

    /// The creator cancels its event (it stays, marked cancelled).
    pub fn cancel_event(&mut self, gid: &[u8], id: &str) -> Result<(), Error> {
        let mut s = self.own_event(gid, id)?;
        s.cancelled = true;
        s.edited_at = Some(now());
        let p = Payload::EventEdit { event: s.info.clone(), cancelled: true };
        self.queue_payload(gid, &p, None, |x| x.save_event(gid, &s))?;
        Ok(())
    }

    /// Answers an event: `going`, `maybe` or `not` (a new answer replaces
    /// the old one).
    pub fn rsvp(&mut self, gid: &[u8], id: &str, answer: &str) -> Result<(), Error> {
        self.events_allowed(gid)?;
        if !ANSWERS.contains(&answer) {
            return Err(Error::Usage("the answer is going, maybe or not".into()));
        }
        let mut s = self.stored_event(gid, id)?.ok_or_else(|| Error::Usage("no such event".into()))?;
        if s.cancelled {
            return Err(Error::Usage("the event was cancelled".into()));
        }
        s.answers.insert(self.member_id().to_hex(), answer.to_string());
        self.queue_payload(gid, &Payload::Rsvp { id: id.into(), answer: answer.into() }, None, |x| x.save_event(gid, &s))?;
        Ok(())
    }

    /// An event of the group with its tally, as this device counted it.
    pub fn chat_event(&mut self, gid: &[u8], id: &str) -> Result<Option<ChatEventView>, Error> {
        let Some(s) = self.stored_event(gid, id)? else { return Ok(None) };
        // Only current members' answers count.
        let members: Vec<String> = self.members(gid)?.into_iter().map(|m| m.id.to_hex()).collect();
        let who = |a: &str| s.answers.iter().filter(|(m, x)| *x == a && members.contains(m)).map(|(m, _)| m.clone()).collect();
        Ok(Some(ChatEventView {
            id: s.info.id.clone(),
            creator: s.creator.clone(),
            title: s.info.title.clone(),
            starts_at: s.info.starts_at,
            ends_at: s.info.ends_at,
            place: s.info.place.clone(),
            description: s.info.description.clone(),
            cancelled: s.cancelled,
            edited: s.edited_at.is_some(),
            going: who("going"),
            maybe: who("maybe"),
            not: who("not"),
            mine: s.answers.get(&self.member_id().to_hex()).cloned(),
        }))
    }

    fn refuse_released(&mut self, gid: &[u8], events: &mut Vec<Event>) -> Result<bool, Error> {
        if self.chat_feature(gid, "chat.events")?.0 {
            return Ok(false);
        }
        events.push(Event::Dropped { reason: "events are released in this group (chat.events)".into() });
        Ok(true)
    }

    pub(crate) fn on_chat_event(&mut self, gid: &[u8], from: MemberId, e: EventInfo, franking: Option<Vec<u8>>, events: &mut Vec<Event>) -> Result<(), Error> {
        if self.refuse_released(gid, events)? {
            return Ok(());
        }
        if !info_ok(&e) {
            events.push(Event::Dropped { reason: "malformed event".into() });
            return Ok(());
        }
        let s = Stored { info: e.clone(), creator: from.to_hex(), cancelled: false, edited_at: None, answers: BTreeMap::new() };
        if !self.store(gid, &e.id, &from, "event", Some(e.title.clone()), Some(serde_json::to_vec(&s).expect("JSON")), franking)? {
            events.push(Event::Dropped { reason: "duplicate message id".into() });
            return Ok(());
        }
        self.on_new_message(gid, false)?;
        let name = self.names(gid)?.get(&from.to_hex()).cloned();
        let request = self.is_request(gid)?;
        events.push(Event::ChatEvent { group: gid.to_vec(), id: e.id, from, name, title: e.title, request });
        Ok(())
    }

    pub(crate) fn on_event_edit(&mut self, gid: &[u8], from: MemberId, e: EventInfo, cancelled: bool, events: &mut Vec<Event>) -> Result<(), Error> {
        if self.refuse_released(gid, events)? {
            return Ok(());
        }
        let Some(mut s) = self.stored_event(gid, &e.id)? else {
            events.push(Event::Dropped { reason: "change of an unknown event".into() });
            return Ok(());
        };
        if s.creator != from.to_hex() || s.cancelled || !info_ok(&e) {
            events.push(Event::Dropped { reason: "event change refused (not the creator's, cancelled, or malformed)".into() });
            return Ok(());
        }
        s.info = e;
        s.cancelled = cancelled;
        s.edited_at = Some(now());
        self.save_event(gid, &s)?;
        events.push(Event::ChatEventChanged { group: gid.to_vec(), id: s.info.id, from, cancelled });
        Ok(())
    }

    pub(crate) fn on_rsvp(&mut self, gid: &[u8], from: MemberId, id: &str, answer: &str, events: &mut Vec<Event>) -> Result<(), Error> {
        if self.refuse_released(gid, events)? {
            return Ok(());
        }
        let Some(mut s) = self.stored_event(gid, id)? else {
            events.push(Event::Dropped { reason: "answer to an unknown event".into() });
            return Ok(());
        };
        if !ANSWERS.contains(&answer) || s.cancelled {
            events.push(Event::Dropped { reason: "answer refused (malformed, or the event was cancelled)".into() });
            return Ok(());
        }
        s.answers.insert(from.to_hex(), answer.to_string());
        self.save_event(gid, &s)?;
        events.push(Event::Rsvp { group: gid.to_vec(), id: id.to_string(), from, answer: answer.to_string() });
        Ok(())
    }
}
