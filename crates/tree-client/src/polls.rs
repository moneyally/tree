//! Polls (`chat.polls`, APP_PROTOCOL.md 1 `poll`, `vote`, `poll_close`).
//!
//! A poll is a chat message (kind `poll` in the history, franked like a
//! text so it can be reported). Votes are MLS application messages; every
//! device counts them itself from what it received:
//!
//! * one vote state per person: the latest `vote` of a member replaces its
//!   earlier one, an empty one takes it back, and the devices of one
//!   account count once (F-030): a vote from a device this device knows
//!   as the same account (its own linked devices, or devices pinned for a
//!   contact) replaces that account's earlier vote from another device.
//!   Devices this device cannot tie to an account (strangers, devices only
//!   a roster claimed) count each on their own, so counts can differ
//!   between devices that know different accounts;
//! * a vote must fit the poll (option indexes in range, no repeats, at most
//!   one unless the poll allows several) and arrive before the poll closed
//!   on this device; anything else is dropped;
//! * only the poll's creator closes it; a close time is a duration from
//!   when each device received the poll (its own clock);
//! * `chat.polls` released: polls, votes and closes are refused when sent
//!   and dropped when received.
//!
//! **Anonymous polls, honestly.** `anon` only means the apps do not show
//! who voted for what. Every vote is still an MLS message authenticated as
//! its sender and delivered to every member's device, so each device knows
//! who voted for what (and a modified app can show it). Only members see
//! votes; the server sees ciphertext as for any message. A truly anonymous
//! poll needs a different cryptographic protocol, which Tree does not have.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tree_core::MemberId;

use crate::messages::{new_id, now};
use crate::payload::{PollDef, Payload};
use crate::{Error, Event, GroupStatus, Session};

pub const MAX_QUESTION: usize = 300;
pub const MAX_OPTION: usize = 100;
pub const MIN_OPTIONS: usize = 2;
pub const MAX_OPTIONS: usize = 10;
/// Longest close time: 30 days.
pub const MAX_CLOSE_IN: i64 = 30 * 86400;

/// How a poll is made.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PollOptions {
    /// Several options may be chosen.
    pub multi: bool,
    /// Apps do not show who voted (see the module notes for what this
    /// does not hide).
    pub anonymous: bool,
    /// Closes this many seconds after arrival (1 s to 30 days).
    pub close_in: Option<i64>,
}

/// What the history keeps with a poll message.
#[derive(Serialize, Deserialize)]
struct StoredPoll {
    def: PollDef,
    #[serde(default)]
    closes_at: Option<i64>,
}

/// Votes and state of one poll on this device.
#[derive(Default, Serialize, Deserialize)]
struct Votes {
    /// Member id (hex) -> chosen options.
    votes: BTreeMap<String, Vec<u32>>,
    #[serde(default)]
    closed: bool,
}

/// A poll as the apps show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollView {
    pub id: String,
    pub creator: MemberId,
    pub question: String,
    pub options: Vec<String>,
    pub multi: bool,
    pub anonymous: bool,
    /// Closed by its creator or past its close time.
    pub closed: bool,
    pub closes_at: Option<i64>,
    /// Votes per option.
    pub counts: Vec<u32>,
    /// Members who voted.
    pub voters: u32,
    /// This device's own choices.
    pub mine: Vec<u32>,
    /// Who chose each option (member ids); empty for anonymous polls.
    pub voters_by_option: Vec<Vec<MemberId>>,
}

fn votes_key(gid: &[u8], id: &str) -> String {
    format!("poll/{}/{id}", hex::encode(gid))
}

/// A poll definition within the limits.
fn valid_def(d: &PollDef) -> bool {
    let n = |s: &str| s.chars().count();
    !d.q.trim().is_empty()
        && n(&d.q) <= MAX_QUESTION
        && (MIN_OPTIONS..=MAX_OPTIONS).contains(&d.opts.len())
        && d.opts.iter().all(|o| !o.trim().is_empty() && n(o) <= MAX_OPTION)
        && d.close_in.is_none_or(|c| (1..=MAX_CLOSE_IN).contains(&c))
        && !d.id.is_empty()
        && d.id.len() <= 64
}

/// A vote that fits the poll: indexes in range, no repeats, one unless
/// the poll allows several (empty = take the vote back).
fn valid_vote(def: &PollDef, choices: &[u32]) -> bool {
    let mut c = choices.to_vec();
    c.sort_unstable();
    c.dedup();
    c.len() == choices.len() && choices.iter().all(|&i| (i as usize) < def.opts.len()) && (def.multi || choices.len() <= 1)
}

impl Session {
    fn stored_poll(&self, gid: &[u8], id: &str) -> Result<Option<(String, StoredPoll)>, Error> {
        let Some(m) = self.client.message(gid, id)? else { return Ok(None) };
        if m.kind != "poll" || m.deleted {
            return Ok(None);
        }
        Ok(m.data.as_deref().and_then(|d| serde_json::from_slice(d).ok()).map(|p| (m.sender, p)))
    }

    fn votes(&self, gid: &[u8], id: &str) -> Result<Votes, Error> {
        Ok(self.client.app_data(&votes_key(gid, id))?.and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default())
    }

    fn save_votes(&self, gid: &[u8], id: &str, v: &Votes) -> Result<(), Error> {
        Ok(self.client.set_app_data(&votes_key(gid, id), Some(&serde_json::to_vec(v).expect("JSON")))?)
    }

    fn poll_closed(&self, gid: &[u8], id: &str, p: &StoredPoll) -> Result<bool, Error> {
        Ok(self.votes(gid, id)?.closed || p.closes_at.is_some_and(|t| t <= now()))
    }

    fn polls_on(&mut self, gid: &[u8]) -> Result<(), Error> {
        if self.chat_on(gid, "chat.polls")? {
            Ok(())
        } else {
            Err(Error::Feature("LOCKED_BY_CHAT".into()))
        }
    }

    /// Starts a poll (`chat.polls`); returns its message id.
    pub fn create_poll(&mut self, gid: &[u8], question: &str, options: &[String], o: &PollOptions) -> Result<String, Error> {
        self.polls_on(gid)?;
        let def = PollDef {
            id: new_id(),
            q: question.trim().to_string(),
            opts: options.iter().map(|s| s.trim().to_string()).collect(),
            multi: o.multi,
            anon: o.anonymous,
            close_in: o.close_in,
        };
        if !valid_def(&def) {
            return Err(Error::Usage(format!(
                "a poll has a question (at most {MAX_QUESTION} characters), {MIN_OPTIONS} to {MAX_OPTIONS} options (at most {MAX_OPTION} each) and closes within 30 days"
            )));
        }
        let me = self.member_id();
        let id = def.id.clone();
        let stored = StoredPoll { closes_at: def.close_in.map(|c| now() + c), def: def.clone() };
        let data = serde_json::to_vec(&stored).expect("JSON");
        let q = def.q.clone();
        self.queue_payload(gid, &Payload::Poll(def), Some(&id), |s| {
            s.store(gid, &id, &me, "poll", Some(q), Some(data), None).map(|_| ())
        })?;
        Ok(id)
    }

    /// Votes in a poll (replaces this member's earlier vote); empty
    /// `choices` takes the vote back.
    pub fn vote(&mut self, gid: &[u8], poll: &str, choices: &[u32]) -> Result<(), Error> {
        self.polls_on(gid)?;
        let (_, p) = self.stored_poll(gid, poll)?.ok_or_else(|| Error::Usage("no such poll".into()))?;
        if self.poll_closed(gid, poll, &p)? {
            return Err(Error::Usage("the poll is closed".into()));
        }
        if !valid_vote(&p.def, choices) {
            return Err(Error::Usage("that vote does not fit the poll".into()));
        }
        let me = self.member_id().to_hex();
        let choices = choices.to_vec();
        self.queue_payload(gid, &Payload::Vote { id: poll.into(), choices: choices.clone() }, None, |s| {
            s.record_vote(gid, poll, &me, choices)
        })?;
        Ok(())
    }

    /// Takes this member's vote back.
    pub fn retract_vote(&mut self, gid: &[u8], poll: &str) -> Result<(), Error> {
        self.vote(gid, poll, &[])
    }

    /// The creator closes the poll for everyone.
    pub fn close_poll(&mut self, gid: &[u8], poll: &str) -> Result<(), Error> {
        self.polls_on(gid)?;
        let (creator, _) = self.stored_poll(gid, poll)?.ok_or_else(|| Error::Usage("no such poll".into()))?;
        if creator != self.member_id().to_hex() {
            return Err(Error::Usage("only the poll's creator closes it".into()));
        }
        self.queue_payload(gid, &Payload::PollClose { id: poll.into() }, None, |s| s.mark_closed(gid, poll))?;
        Ok(())
    }

    /// Who a vote counts for: the account, if this device ties the member
    /// to one it trusts (`own/members`, or pinned for a contact; never a
    /// roster label alone), otherwise the member (device) itself.
    fn voter_key(&self, gid: &[u8], member: &str) -> Result<String, Error> {
        let Some(m) = MemberId::from_hex(member) else { return Ok(format!("device:{member}")) };
        Ok(match self.vouched_account(gid, &m)? {
            Some(a) => format!("account:{a}"),
            None => format!("device:{member}"),
        })
    }

    fn record_vote(&self, gid: &[u8], poll: &str, member: &str, choices: Vec<u32>) -> Result<(), Error> {
        let mut v = self.votes(gid, poll)?;
        // The newest vote of an account replaces its other devices' votes.
        let key = self.voter_key(gid, member)?;
        let others: Vec<String> = v.votes.keys().filter(|m| *m != member).cloned().collect();
        for m in others {
            if self.voter_key(gid, &m)? == key {
                v.votes.remove(&m);
            }
        }
        if choices.is_empty() {
            v.votes.remove(member);
        } else {
            v.votes.insert(member.to_string(), choices);
        }
        self.save_votes(gid, poll, &v)
    }

    fn mark_closed(&self, gid: &[u8], poll: &str) -> Result<(), Error> {
        let mut v = self.votes(gid, poll)?;
        v.closed = true;
        self.save_votes(gid, poll, &v)
    }

    /// A poll with its tally as counted on this device, or `None` if this
    /// device does not have it (any more).
    pub fn poll(&mut self, gid: &[u8], poll: &str) -> Result<Option<PollView>, Error> {
        let Some((creator, p)) = self.stored_poll(gid, poll)? else { return Ok(None) };
        let closed = self.poll_closed(gid, poll, &p)?;
        let v = self.votes(gid, poll)?;
        let current: Vec<String> = self.group(gid)?.members().iter().map(MemberId::to_hex).collect();
        let me = self.member_id().to_hex();
        let n = p.def.opts.len();
        let mut counts = vec![0u32; n];
        let mut by: Vec<Vec<MemberId>> = vec![vec![]; n];
        let mut voters = 0;
        let mut counted = std::collections::HashSet::new();
        // This device's own vote first, then one vote per account (F-030).
        let mut order: Vec<(&String, &Vec<u32>)> = v.votes.iter().collect();
        order.sort_by_key(|(m, _)| **m != me);
        for (m, c) in order {
            // A member who left no longer counts (as on every device).
            if !current.contains(m) && *m != me {
                continue;
            }
            if !counted.insert(self.voter_key(gid, m)?) {
                continue;
            }
            voters += 1;
            for &i in c {
                if let Some(x) = counts.get_mut(i as usize) {
                    *x += 1;
                    if let (false, Some(id)) = (p.def.anon, MemberId::from_hex(m)) {
                        by[i as usize].push(id);
                    }
                }
            }
        }
        if p.def.anon {
            by = vec![vec![]; n];
        }
        Ok(Some(PollView {
            id: poll.to_string(),
            creator: MemberId::from_hex(&creator).ok_or_else(|| Error::Protocol("damaged poll".into()))?,
            question: p.def.q,
            options: p.def.opts,
            multi: p.def.multi,
            anonymous: p.def.anon,
            closed,
            closes_at: p.closes_at,
            counts,
            voters,
            mine: v.votes.get(&me).cloned().unwrap_or_default(),
            voters_by_option: by,
        }))
    }

    pub(crate) fn on_poll(
        &mut self,
        gid: &[u8],
        from: MemberId,
        def: PollDef,
        franking: Option<Vec<u8>>,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if !self.chat_on(gid, "chat.polls")? {
            events.push(Event::Dropped { reason: "polls are released in this group (chat.polls)".into() });
            return Ok(());
        }
        if !valid_def(&def) {
            events.push(Event::Dropped { reason: "malformed poll".into() });
            return Ok(());
        }
        let id = def.id.clone();
        let q = def.q.clone();
        let stored = StoredPoll { closes_at: def.close_in.map(|c| now() + c), def };
        if !self.store(gid, &id, &from, "poll", Some(q.clone()), Some(serde_json::to_vec(&stored).expect("JSON")), franking)? {
            events.push(Event::Dropped { reason: "duplicate message id".into() });
            return Ok(());
        }
        self.on_new_message(gid, false)?;
        let request = matches!(self.group_status(gid)?, GroupStatus::Request { .. });
        let name = self.names(gid)?.get(&from.to_hex()).cloned();
        events.push(Event::Poll { group: gid.to_vec(), id, from, name, question: q, request });
        Ok(())
    }

    pub(crate) fn on_vote(&mut self, gid: &[u8], from: MemberId, id: String, choices: Vec<u32>, events: &mut Vec<Event>) -> Result<(), Error> {
        let why = if !self.chat_on(gid, "chat.polls")? {
            Some("polls are released in this group (chat.polls)")
        } else {
            match self.stored_poll(gid, &id)? {
                None => Some("vote in an unknown poll"),
                Some((_, p)) if self.poll_closed(gid, &id, &p)? => Some("vote after the poll closed"),
                Some((_, p)) if !valid_vote(&p.def, &choices) => Some("vote does not fit the poll"),
                Some(_) => None,
            }
        };
        if let Some(why) = why {
            events.push(Event::Dropped { reason: why.into() });
            return Ok(());
        }
        self.record_vote(gid, &id, &from.to_hex(), choices)?;
        events.push(Event::PollUpdated { group: gid.to_vec(), id });
        Ok(())
    }

    pub(crate) fn on_poll_close(&mut self, gid: &[u8], from: MemberId, id: String, events: &mut Vec<Event>) -> Result<(), Error> {
        let why = if !self.chat_on(gid, "chat.polls")? {
            Some("polls are released in this group (chat.polls)")
        } else {
            match self.stored_poll(gid, &id)? {
                None => Some("close of an unknown poll"),
                Some((creator, _)) if creator != from.to_hex() => Some("only the poll's creator closes it"),
                Some(_) => None,
            }
        };
        if let Some(why) = why {
            events.push(Event::Dropped { reason: why.into() });
            return Ok(());
        }
        self.mark_closed(gid, &id)?;
        events.push(Event::PollUpdated { group: gid.to_vec(), id });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(multi: bool) -> PollDef {
        PollDef { id: "01".into(), q: "Where?".into(), opts: vec!["a".into(), "b".into(), "c".into()], multi, anon: false, close_in: None }
    }

    #[test]
    fn limits() {
        assert!(valid_def(&def(false)));
        let mut d = def(false);
        d.opts.truncate(1);
        assert!(!valid_def(&d), "two options at least");
        d.opts = (0..11).map(|i| i.to_string()).collect();
        assert!(!valid_def(&d), "ten at most");
        let mut d = def(false);
        d.q = "x".repeat(MAX_QUESTION + 1);
        assert!(!valid_def(&d));
        let mut d = def(false);
        d.opts[1] = " ".into();
        assert!(!valid_def(&d), "no empty option");
        let mut d = def(false);
        d.close_in = Some(0);
        assert!(!valid_def(&d));
        d.close_in = Some(MAX_CLOSE_IN);
        assert!(valid_def(&d));
    }

    #[test]
    fn votes_fit_the_poll() {
        assert!(valid_vote(&def(false), &[]));
        assert!(valid_vote(&def(false), &[2]));
        assert!(!valid_vote(&def(false), &[0, 1]), "single choice");
        assert!(valid_vote(&def(true), &[0, 2]));
        assert!(!valid_vote(&def(true), &[1, 1]), "no repeats");
        assert!(!valid_vote(&def(true), &[3]), "in range");
    }
}
