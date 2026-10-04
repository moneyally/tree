//! Scheduled messages and reminders: both live on this device only.
//!
//! **Scheduled messages.** The text waits in the encrypted device database
//! (`sched/<id>`) until its time; then it enters the outbox
//! (PROTOCOL.md 6.13) and goes out like any message, sealed and franked at
//! that moment. The server never holds the plaintext and does not schedule
//! anything: it receives the message when it is sent. So the app must be
//! running at that time, or the next sync after it sends the message (it
//! then arrives late, with the time it was actually sent). Every sync sends
//! what is due ([`Session::send_due_scheduled`]). A scheduled message is
//! not in the chat's history until it is sent; until then it can be listed,
//! edited and cancelled. A chat setting that forbids it when it is due
//! (or a chat this device left) fails it then, reported as `SendFailed`.
//!
//! **Reminders** ("remind me about this message") are kept in `remind/<id>`
//! with the chat, the message id and the time. The app asks for
//! [`Session::due_reminders`] (after every sync, and on a timer) and shows a
//! local notification; nothing leaves the device.

use serde::{Deserialize, Serialize};

use crate::messages::{new_id, now, TextOptions};
use crate::{Error, Event, Session};

/// The furthest a message can be scheduled or a reminder set: one year.
pub const MAX_AHEAD: i64 = 365 * 86400;
/// Longest scheduled text (as drafts): 64 KiB.
pub const MAX_SCHEDULED_TEXT: usize = 64 * 1024;

/// A message waiting for its time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scheduled {
    pub id: String,
    /// Group id (hex).
    pub group: String,
    pub text: String,
    /// When it goes out (unix seconds, this device's clock).
    pub at: i64,
    #[serde(default)]
    pub silent: bool,
    pub created_at: i64,
}

/// A reminder about a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reminder {
    pub id: String,
    /// Group id (hex).
    pub group: String,
    pub message_id: String,
    pub at: i64,
    /// The message's text when the reminder is read (not stored with it);
    /// `None` if the message is gone.
    #[serde(skip)]
    pub text: Option<String>,
}

fn check_time(at: i64) -> Result<(), Error> {
    let t = now();
    if at <= t || at > t + MAX_AHEAD {
        return Err(Error::Usage("choose a time in the future, at most a year ahead".into()));
    }
    Ok(())
}

fn check_text(text: &str) -> Result<(), Error> {
    if text.trim().is_empty() || text.len() > MAX_SCHEDULED_TEXT {
        return Err(Error::Usage("a scheduled message has text, at most 64 KiB".into()));
    }
    Ok(())
}

impl Session {
    fn list_json<T: for<'a> Deserialize<'a>>(&self, prefix: &str) -> Result<Vec<T>, Error> {
        let mut out = Vec::new();
        for k in self.client.app_data_keys(prefix)? {
            if let Some(v) = self.client.app_data(&k)? {
                if let Ok(x) = serde_json::from_slice(&v) {
                    out.push(x);
                }
            }
        }
        Ok(out)
    }

    fn put<T: Serialize>(&self, key: &str, v: &T) -> Result<(), Error> {
        Ok(self.client.set_app_data(key, Some(&serde_json::to_vec(v).expect("JSON")))?)
    }

    /// Schedules a text for `at` (unix seconds, in the future, at most a
    /// year ahead); returns the schedule id.
    pub fn schedule_text(&mut self, gid: &[u8], text: &str, at: i64, silent: bool) -> Result<String, Error> {
        check_time(at)?;
        check_text(text)?;
        if !self.group(gid)?.is_member() {
            return Err(Error::Usage("this device is not a member of the group".into()));
        }
        let s = Scheduled { id: new_id(), group: hex::encode(gid), text: text.to_string(), at, silent, created_at: now() };
        self.put(&format!("sched/{}", s.id), &s)?;
        Ok(s.id)
    }

    /// Scheduled messages (of one chat, or all), soonest first.
    pub fn scheduled(&self, gid: Option<&[u8]>) -> Result<Vec<Scheduled>, Error> {
        let g = gid.map(hex::encode);
        let mut v: Vec<Scheduled> = self.list_json("sched/")?;
        v.retain(|s| g.as_ref().is_none_or(|g| *g == s.group));
        v.sort_by_key(|s| (s.at, s.created_at));
        Ok(v)
    }

    fn one_scheduled(&self, id: &str) -> Result<Scheduled, Error> {
        let v = self.client.app_data(&format!("sched/{id}"))?.ok_or_else(|| Error::Usage("no such scheduled message".into()))?;
        serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged scheduled message".into()))
    }

    /// Changes the text and/or time of a scheduled message.
    pub fn edit_scheduled(&self, id: &str, text: Option<&str>, at: Option<i64>) -> Result<Scheduled, Error> {
        let mut s = self.one_scheduled(id)?;
        if let Some(t) = text {
            check_text(t)?;
            s.text = t.to_string();
        }
        if let Some(a) = at {
            check_time(a)?;
            s.at = a;
        }
        self.put(&format!("sched/{id}"), &s)?;
        Ok(s)
    }

    /// Cancels a scheduled message (nothing was sent).
    pub fn cancel_scheduled(&self, id: &str) -> Result<(), Error> {
        self.one_scheduled(id)?;
        Ok(self.client.set_app_data(&format!("sched/{id}"), None)?)
    }

    /// Sends every scheduled message whose time has come (sync calls
    /// this): `Sent` for each that went out or waits in the outbox,
    /// `SendFailed` (with the schedule id) for one that cannot be sent.
    pub fn send_due_scheduled(&mut self) -> Result<Vec<Event>, Error> {
        let t = now();
        let mut events = Vec::new();
        for s in self.scheduled(None)?.into_iter().filter(|s| s.at <= t) {
            self.client.set_app_data(&format!("sched/{}", s.id), None)?;
            let Ok(gid) = hex::decode(&s.group) else { continue };
            // Sending clears the chat's draft; the user's draft is not ours to drop.
            let draft = self.draft(&gid).unwrap_or(None);
            let r = self.send_text_with(&gid, &s.text, &TextOptions { silent: s.silent, ..Default::default() });
            if let Some(d) = draft {
                self.set_draft(&gid, &d)?;
            }
            events.push(match r {
                Ok(id) => Event::Sent { group: gid, id: Some(id) },
                Err(e) => Event::SendFailed { group: gid, id: None, local_id: s.id, reason: e.to_string() },
            });
        }
        Ok(events)
    }

    // --- reminders ---

    /// Reminds this user about message `message_id` at `at`; returns the
    /// reminder id.
    pub fn remind_me(&self, gid: &[u8], message_id: &str, at: i64) -> Result<String, Error> {
        check_time(at)?;
        if self.client.message(gid, message_id)?.is_none() {
            return Err(Error::Usage("no such message".into()));
        }
        let r = Reminder { id: new_id(), group: hex::encode(gid), message_id: message_id.to_string(), at, text: None };
        self.put(&format!("remind/{}", r.id), &r)?;
        Ok(r.id)
    }

    fn with_text(&self, mut r: Reminder) -> Result<Reminder, Error> {
        if let Ok(g) = hex::decode(&r.group) {
            r.text = self.client.message(&g, &r.message_id)?.filter(|m| !m.deleted).and_then(|m| m.text);
        }
        Ok(r)
    }

    /// Reminders not due yet, soonest first.
    pub fn reminders(&self) -> Result<Vec<Reminder>, Error> {
        let mut v: Vec<Reminder> = self.list_json("remind/")?;
        v.sort_by_key(|r| r.at);
        v.into_iter().map(|r| self.with_text(r)).collect()
    }

    pub fn cancel_reminder(&self, id: &str) -> Result<(), Error> {
        Ok(self.client.set_app_data(&format!("remind/{id}"), None)?)
    }

    /// Reminders whose time has come, each returned once (then deleted):
    /// the app shows a local notification for each.
    pub fn due_reminders(&self) -> Result<Vec<Reminder>, Error> {
        let t = now();
        let mut out = Vec::new();
        for r in self.reminders()?.into_iter().filter(|r| r.at <= t) {
            self.cancel_reminder(&r.id)?;
            out.push(r);
        }
        Ok(out)
    }
}
