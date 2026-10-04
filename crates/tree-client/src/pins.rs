//! Pinned messages (`chat.pins`, APP_PROTOCOL.md 1 `pin`).
//!
//! Pins are shared state carried by MLS application messages: whoever may
//! pin (an admin, or either person in a 1:1 chat) sends `pin`, and every
//! device, the sender's included, applies it to its own copy of the chat's
//! pins (`pins/<group hex>`). Every device checks the same rules on
//! arrival, in the server's order, so every member sees the same pins:
//!
//! * the sender must be an admin, or the chat has two members;
//! * `chat.pins` must be applied (released: received pins are dropped and
//!   stored ones are not shown);
//! * the pinned message must be in this device's history and not deleted;
//! * at most [`MAX_PINS`]: the sending device refuses an eleventh; a
//!   receiving device that would hold more drops the oldest pin;
//! * an expiry is a duration (`ttl`), measured with each device's own clock
//!   from when it received the pin, never a time the sender claims. Expired
//!   pins drop off on each device when read.
//!
//! Limits: a member who joins later does not learn earlier pins (there is
//! no history sharing yet), and a pin of a message the device never had
//! (joined later, or it disappeared) is dropped there.

use serde::{Deserialize, Serialize};
use tree_core::MemberId;

use crate::messages::now;
use crate::payload::Payload;
use crate::{Error, Event, Session};

/// Pins per chat.
pub const MAX_PINS: usize = 10;
/// Longest pin expiry (and the range a `ttl` must be in): 365 days.
pub const MAX_PIN_TTL: i64 = 365 * 86400;
/// Expiries the apps offer: 24 hours, 7 days, 30 days, until unpinned.
pub const PIN_CHOICES: &[(&str, Option<i64>)] =
    &[("24h", Some(86400)), ("7d", Some(7 * 86400)), ("30d", Some(30 * 86400)), ("forever", None)];

/// One stored pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    id: String,
    by: String,
    at: i64,
    #[serde(default)]
    until: Option<i64>,
}

/// A pinned message as the apps show it (newest pin first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub message_id: String,
    /// Who pinned it (member id).
    pub by: MemberId,
    /// When this device received the pin.
    pub pinned_at: i64,
    /// When it drops off on this device; `None` = until unpinned.
    pub until: Option<i64>,
    /// The message's kind and text (file name for a file).
    pub kind: String,
    pub text: Option<String>,
}

fn pins_key(gid: &[u8]) -> String {
    format!("pins/{}", hex::encode(gid))
}

fn valid_ttl(ttl: Option<i64>) -> bool {
    ttl.is_none_or(|t| (1..=MAX_PIN_TTL).contains(&t))
}

impl Session {
    fn stored_pins(&self, gid: &[u8]) -> Result<Vec<Stored>, Error> {
        Ok(self.client.app_data(&pins_key(gid))?.and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default())
    }

    fn save_pins(&self, gid: &[u8], v: &[Stored]) -> Result<(), Error> {
        let data = (!v.is_empty()).then(|| serde_json::to_vec(v).expect("JSON"));
        Ok(self.client.set_app_data(&pins_key(gid), data.as_deref())?)
    }

    /// Applies a pin (or unpin) to this device's copy: the same on the
    /// sender and on every receiver.
    fn apply_pin(&self, gid: &[u8], id: &str, by: &MemberId, ttl: Option<i64>, remove: bool) -> Result<(), Error> {
        let t = now();
        let mut v = self.stored_pins(gid)?;
        v.retain(|p| p.id != id && p.until.is_none_or(|u| u > t));
        if !remove {
            v.push(Stored { id: id.to_string(), by: by.to_hex(), at: t, until: ttl.map(|s| t + s) });
        }
        // The oldest pins give way (every device drops the same ones).
        let extra = v.len().saturating_sub(MAX_PINS);
        v.drain(..extra);
        self.save_pins(gid, &v)
    }

    /// May this device pin in the chat (`chat.pins` applied, and an admin
    /// or one of two members)? Apps show the pin action only then.
    pub fn may_pin(&mut self, gid: &[u8]) -> Result<bool, Error> {
        let me = self.member_id();
        Ok(self.chat_on(gid, "chat.pins")? && self.may_moderate(gid, &me)?)
    }

    /// Pins message `id` for everyone, for `ttl` seconds (one of
    /// [`PIN_CHOICES`]; `None` = until unpinned). Pinning a pinned message
    /// again sets its new expiry.
    pub fn pin_message(&mut self, gid: &[u8], id: &str, ttl: Option<i64>) -> Result<(), Error> {
        self.send_pin(gid, id, ttl, false)
    }

    /// Unpins message `id` for everyone.
    pub fn unpin_message(&mut self, gid: &[u8], id: &str) -> Result<(), Error> {
        self.send_pin(gid, id, None, true)
    }

    fn send_pin(&mut self, gid: &[u8], id: &str, ttl: Option<i64>, remove: bool) -> Result<(), Error> {
        if !self.chat_on(gid, "chat.pins")? {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        let me = self.member_id();
        if !self.may_moderate(gid, &me)? {
            return Err(Error::Feature("NOT_ADMIN".into()));
        }
        if !valid_ttl(ttl) {
            return Err(Error::Usage("a pin lasts 1 second to 365 days, or until unpinned".into()));
        }
        if !remove {
            match self.client.message(gid, id)? {
                Some(m) if !m.deleted => {}
                _ => return Err(Error::Usage("no such message".into())),
            }
            let active = self.pins(gid)?;
            if active.len() >= MAX_PINS && !active.iter().any(|p| p.message_id == id) {
                return Err(Error::Usage(format!("at most {MAX_PINS} pinned messages: unpin one first")));
            }
        }
        let p = Payload::Pin { id: id.into(), ttl, remove };
        self.queue_payload(gid, &p, None, |s| s.apply_pin(gid, id, &me, ttl, remove))?;
        Ok(())
    }

    /// The chat's pins on this device, newest first. Expired pins and pins
    /// of messages that are gone drop off; none while `chat.pins` is
    /// released.
    pub fn pins(&mut self, gid: &[u8]) -> Result<Vec<Pin>, Error> {
        if !self.chat_on(gid, "chat.pins")? {
            return Ok(vec![]);
        }
        self.client.purge_expired_messages(now())?;
        let t = now();
        let stored = self.stored_pins(gid)?;
        let mut keep = Vec::new();
        let mut out = Vec::new();
        for p in stored {
            if p.until.is_some_and(|u| u <= t) {
                continue;
            }
            let Some(m) = self.client.message(gid, &p.id)?.filter(|m| !m.deleted) else { continue };
            if let Some(by) = MemberId::from_hex(&p.by) {
                out.push(Pin { message_id: p.id.clone(), by, pinned_at: p.at, until: p.until, kind: m.kind, text: m.text });
            }
            keep.push(p);
        }
        self.save_pins(gid, &keep)?;
        out.reverse();
        Ok(out)
    }

    pub(crate) fn on_pin(
        &mut self,
        gid: &[u8],
        from: MemberId,
        id: String,
        ttl: Option<i64>,
        remove: bool,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let drop = |events: &mut Vec<Event>, why: &str| events.push(Event::Dropped { reason: why.to_string() });
        if !self.chat_on(gid, "chat.pins")? {
            drop(events, "pins are released in this group (chat.pins)");
        } else if !self.may_moderate(gid, &from)? {
            drop(events, "only admins pin in this group");
        } else if !valid_ttl(ttl) {
            drop(events, "malformed pin");
        } else if !remove && self.client.message(gid, &id)?.is_none_or(|m| m.deleted) {
            drop(events, "pin of an unknown message");
        } else {
            self.apply_pin(gid, &id, &from, ttl, remove)?;
            events.push(Event::Pinned { group: gid.to_vec(), id, from, pinned: !remove });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choices_and_ttl_range() {
        assert_eq!(PIN_CHOICES.len(), 4);
        assert!(PIN_CHOICES.iter().all(|(_, t)| valid_ttl(*t)));
        assert!(!valid_ttl(Some(0)) && !valid_ttl(Some(-5)) && !valid_ttl(Some(MAX_PIN_TTL + 1)));
        assert!(valid_ttl(None));
    }
}
