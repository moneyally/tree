//! Rich chats, wave 2 part A (PRODUCT_PLAN.md): what the modules
//! [`crate::pins`], [`crate::polls`], [`crate::forward`],
//! [`crate::schedule`] and [`crate::storage_clean`] share.
//!
//! | Key | Default | Effect |
//! | --- | --- | --- |
//! | `chat.pins` | applied | admins (or either person in a 1:1) pin messages for everyone; released: nobody pins, received pins are dropped, stored ones hidden |
//! | `chat.polls` | applied | polls, votes and closing; released: refused when sending, dropped when received |
//! | `chat.forwarding` | applied | messages of the chat may be forwarded (and saved / copied in the apps); released: the client refuses, the apps hide the actions |
//! | `chat.export` | applied | the chat's history may be exported to a local file; released: refused |
//! | `user.storage_clean` | released; option = a duration of 1 s to 365 days (default `90d`) | downloaded media older than that is deleted from this device |
//!
//! Like every chat setting (APP_PROTOCOL.md 3), chat keys are checked by
//! the sending device and again by every receiving device on arrival.

use tree_core::MemberId;

use crate::payload::Payload;
use crate::{Error, Event, Session};

impl Session {
    /// A chat feature as the admins set it (`true` = applied).
    pub(crate) fn chat_on(&mut self, gid: &[u8], key: &str) -> Result<bool, Error> {
        Ok(self.chat_feature(gid, key)?.0)
    }

    /// May `who` change shared chat state such as pins: an admin, or either
    /// person of a 1:1 chat (two members, as `requests.rs` counts them).
    pub(crate) fn may_moderate(&mut self, gid: &[u8], who: &MemberId) -> Result<bool, Error> {
        let g = self.group(gid)?;
        Ok(g.is_admin(who) || g.members().len() <= 2)
    }

    /// A pin or poll payload from member `from` (blocked senders dropped).
    pub(crate) fn on_rich(
        &mut self,
        gid: &[u8],
        from: MemberId,
        p: Payload,
        franking: Option<Vec<u8>>,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if let Some(a) = self.map(&crate::accounts_key(gid))?.get(&from.to_hex()) {
            if self.is_blocked(a)? {
                events.push(Event::Dropped { reason: "from a blocked account".into() });
                return Ok(());
            }
        }
        self.note_traffic(gid)?;
        match p {
            Payload::Pin { id, ttl, remove } => self.on_pin(gid, from, id, ttl, remove, events),
            Payload::Poll(def) => self.on_poll(gid, from, def, franking, events),
            Payload::Vote { id, choices } => self.on_vote(gid, from, id, choices, events),
            Payload::PollClose { id } => self.on_poll_close(gid, from, id, events),
            _ => Ok(events.push(Event::Dropped { reason: "not a pin or poll".into() })),
        }
    }

    /// Run by every sync after receiving: scheduled messages that came due
    /// go out, and downloaded media past `user.storage_clean` is deleted
    /// (at most once an hour).
    pub(crate) fn after_sync(&mut self) -> Result<Vec<Event>, Error> {
        let events = self.send_due_scheduled()?;
        self.clean_storage_if_due()?;
        Ok(events)
    }
}
