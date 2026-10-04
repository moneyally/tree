//! Reliable sending (PROTOCOL.md 6.13): every application message except
//! typing and presence goes through the durable outbox in the encrypted
//! profile, and every attempt carries the item's idempotency key
//! (PROTOCOL.md 8.10).
//!
//! * The message is sealed (MLS-encrypted) once. Normally that happens at
//!   enqueue, in the same database transaction that advances the group's
//!   keys and stores the history entry. A chat message needs the server's
//!   franking tag first; if the server cannot be reached for it, the
//!   encoded payload waits in the outbox and is sealed, once, by the first
//!   attempt that gets the tag. After that only the stored bytes are sent.
//! * Items of one group go out in the order they were made; an item
//!   waiting for its next attempt holds back the later ones of its group.
//! * A send by the user makes its group's waiting items go now; such an
//!   early attempt does not use up their budget of attempts.
//! * Passing errors (network, server 5xx, 408, 425, 429) are retried with
//!   backoff; other refusals fail the item at once. Failed items stay
//!   until the user retries or cancels them.
//! * A file item uploads its attachment first ([`crate::media`]); it is
//!   sealed once the upload is complete. An attempt that moved the upload
//!   on does not use up the budget of attempts.

use std::collections::{HashMap, HashSet};

use tree_core::storage::outbox::{idempotency_key, OutboxItem, OutboxState};

use crate::media::Up;
use crate::messages::now;
use crate::payload::Payload;
use crate::{Error, Event, Session};

/// One outbox item as an app shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    pub local_id: String,
    pub group: Vec<u8>,
    /// The history message it carries (text, file), if any.
    pub message_id: Option<String>,
    pub state: OutboxState,
    pub attempts: u32,
    /// Unix seconds of the next automatic attempt (`retry`).
    pub next_at: i64,
    pub last_error: Option<String>,
}

impl From<OutboxItem> for OutboxEntry {
    fn from(i: OutboxItem) -> Self {
        OutboxEntry {
            local_id: i.local_id,
            group: i.group_id,
            message_id: i.message_id,
            state: i.state,
            attempts: i.attempts,
            next_at: i.next_at,
            last_error: i.last_error,
        }
    }
}

/// What one attempt came to.
#[derive(Debug)]
pub(crate) enum Attempt {
    Sent(usize),
    Retry,
    /// A file upload is paused or used up this pass's share: not a failure,
    /// but later items of the group wait.
    Hold,
    Failed(Error),
}

/// Worth trying again later.
pub(crate) fn transient(e: &Error) -> bool {
    match e {
        Error::Network(_) => true,
        Error::Server { status, .. } => *status >= 500 || matches!(status, 408 | 425 | 429),
        _ => false,
    }
}

fn new_local_id() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("operating system random number generator failed");
    hex::encode(b)
}

/// The outcome for one item out of a pass.
fn take(pass: Vec<(String, Attempt)>, local_id: &str) -> Option<Attempt> {
    pass.into_iter().find(|(id, _)| id == local_id).map(|(_, a)| a)
}

/// Typing and presence: worthless later, never queued.
fn ephemeral(p: &Payload) -> bool {
    matches!(p, Payload::Typing { .. } | Payload::Seen)
}

impl Session {
    /// Sends a payload to the group: ephemeral ones directly (and only
    /// when nothing older of this group waits, so they never overtake),
    /// everything else through the outbox. Returns how many devices it was
    /// delivered to now (0 if it waits in the outbox).
    pub(crate) fn send_payload(&mut self, gid: &[u8], p: &Payload) -> Result<usize, Error> {
        if ephemeral(p) {
            // Typing and presence are worthless later: never from inside a
            // receive batch (F-024), and never ahead of older items.
            if self.api.receiving() || self.client.outbox_unsent(Some(gid))?.iter().any(|i| i.state != OutboxState::Failed) {
                return Ok(0);
            }
            let to = self.other_devices(gid)?;
            if to.is_empty() {
                return Ok(0);
            }
            return self.send_encoded(gid, &to, &p.encode());
        }
        self.queue_payload(gid, p, None, |_| Ok(()))
    }

    /// Puts `p` into the outbox together with `local` (which stores the
    /// history entry), in one transaction, then sends it (after anything
    /// older of the group). A refusal by the server is returned as the
    /// error (the item is then `failed`); a network problem is not: the
    /// item waits for the next sync.
    pub(crate) fn queue_payload(
        &mut self,
        gid: &[u8],
        p: &Payload,
        message_id: Option<&str>,
        local: impl FnOnce(&mut Self) -> Result<(), Error>,
    ) -> Result<usize, Error> {
        self.queue_item(gid, p, message_id, None, local)
    }

    /// [`Session::queue_payload`], optionally for a file: `upload` is the
    /// item's local id (its blob is named by it) and its upload record. A
    /// file item is never sealed at enqueue (the attachment id comes with
    /// the upload) and is queued even with no other device in the group
    /// (the upload still has to happen for this user's history).
    pub(crate) fn queue_item(
        &mut self,
        gid: &[u8],
        p: &Payload,
        message_id: Option<&str>,
        upload: Option<(String, crate::media::UploadState)>,
        local: impl FnOnce(&mut Self) -> Result<(), Error>,
    ) -> Result<usize, Error> {
        if !self.group(gid)?.is_member() {
            return Err(Error::Usage("this device is not a member of the group".into()));
        }
        let to = self.other_devices(gid)?;
        if to.is_empty() && upload.is_none() {
            local(self)?;
            return Ok(0);
        }
        let inner = p.encode();
        // Inside a receive batch nothing goes to the network (F-024): the
        // item is sealed now only if that needs no server call (a chat
        // message needs the franking tag), and it is sent after the batch.
        let receiving = self.api.receiving();
        // Seal now unless it is a file, or an older item of this group still
        // waits for its seal (it must keep its place).
        let behind_unsealed =
            self.client.outbox_unsent(Some(gid))?.iter().any(|i| i.body.is_none() && i.state != OutboxState::Failed);
        let needs_server = Payload::decode(&inner).is_some_and(|p| p.is_franked_kind());
        let encoded = if behind_unsealed || upload.is_some() || (receiving && needs_server) {
            None
        } else {
            match self.seal_payload(gid, &inner) {
                Ok(e) => Some(e),
                Err(e) if transient(&e) => None,
                Err(e) => return Err(e),
            }
        };
        let local_id = upload.as_ref().map(|(l, _)| l.clone()).unwrap_or_else(new_local_id);
        let mut item = OutboxItem::new(&local_id, gid, message_id, now());
        self.client.begin_batch()?;
        let r = self.enqueue_in_batch(gid, &mut item, encoded, inner, to, |s| {
            if let Some((l, st)) = &upload {
                s.save_upload(l, st)?;
            }
            local(s)
        });
        self.end_batch()?;
        r?;
        if receiving {
            return Ok(0);
        }
        match take(self.drive_outbox(Some(gid))?, &local_id) {
            Some(Attempt::Sent(n)) => Ok(n),
            Some(Attempt::Failed(e)) => Err(e),
            Some(Attempt::Retry | Attempt::Hold) | None => Ok(0),
        }
    }

    fn enqueue_in_batch(
        &mut self,
        gid: &[u8],
        item: &mut OutboxItem,
        encoded: Option<Vec<u8>>,
        inner: Vec<u8>,
        to: Vec<String>,
        local: impl FnOnce(&mut Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match encoded {
            Some(enc) => {
                let body = self.with(gid, |g, c| g.send(c, &enc))?;
                let key = idempotency_key(gid, &self.member_id().0, &item.local_id, &body);
                item.body = Some(body);
                item.recipients = to;
                item.idempotency_key = Some(key.to_vec());
            }
            None => item.payload = Some(inner),
        }
        local(self)?;
        self.client.outbox_enqueue(item)?;
        self.note_traffic(gid)
    }

    /// The bytes that get sealed: chat messages franked (a server call).
    fn seal_payload(&self, gid: &[u8], inner: &[u8]) -> Result<Vec<u8>, Error> {
        let p = Payload::decode(inner).ok_or_else(|| Error::Protocol("damaged outbox payload".into()))?;
        if !p.is_franked_kind() {
            return Ok(inner.to_vec());
        }
        let text = String::from_utf8(inner.to_vec()).map_err(|_| Error::Protocol("payload is not text".into()))?;
        let r = self.frank(gid, &text)?;
        Ok(Payload::Franked { p: r.payload, k: r.key, tag: r.tag, m: r.minute }.encode())
    }

    /// One pass over the outbox: every due item (and with `force`, every
    /// waiting item of that group), oldest first, one group's items in
    /// order. Returns what happened to each item tried, in that order.
    pub(crate) fn drive_outbox(&mut self, force: Option<&[u8]>) -> Result<Vec<(String, Attempt)>, Error> {
        let t = now();
        let mut held: HashSet<Vec<u8>> = HashSet::new();
        let mut out = Vec::new();
        for item in self.client.outbox_unsent(None)? {
            if item.state == OutboxState::Failed || held.contains(&item.group_id) {
                continue;
            }
            let due = item.next_at <= t;
            if !due && force != Some(item.group_id.as_slice()) {
                held.insert(item.group_id.clone());
                continue;
            }
            let a = self.attempt(item.clone(), due)?;
            if matches!(a, Attempt::Retry | Attempt::Hold) {
                held.insert(item.group_id.clone());
            }
            out.push((item.local_id, a));
        }
        Ok(out)
    }

    /// One attempt: seal if not sealed yet, then send the stored bytes with
    /// the stored key. `due`: counts against the item's attempts.
    fn attempt(&mut self, mut item: OutboxItem, due: bool) -> Result<Attempt, Error> {
        let gid = item.group_id.clone();
        if item.body.is_none() {
            let mut inner = item.payload.clone().unwrap_or_default();
            // A file: its upload first, then the reference gets the id.
            if let Some(st) = self.upload_state(&item.local_id)? {
                match self.drive_upload(&item.local_id, st) {
                    Up::Done(id) => match Payload::decode(&inner) {
                        Some(Payload::File(mut f)) => {
                            f.id = id;
                            inner = Payload::File(f).encode();
                        }
                        _ => {
                            self.client.outbox_mark_failed(&item.local_id, "damaged outbox item")?;
                            return Ok(Attempt::Failed(Error::Protocol("damaged outbox item".into())));
                        }
                    },
                    Up::Hold => return Ok(Attempt::Hold),
                    // An attempt that moved the upload on does not count.
                    Up::Failed { error, progressed } => return self.after_failure(&item, due && !progressed, error),
                }
            }
            let enc = match self.seal_payload(&gid, &inner) {
                Ok(e) => e,
                Err(e) => return self.after_failure(&item, due, e),
            };
            let to = self.other_devices(&gid)?;
            if to.is_empty() {
                self.client.outbox_mark_sent(&item.local_id, now())?;
                self.upload_finished(&item.local_id)?;
                return Ok(Attempt::Sent(0));
            }
            self.client.begin_batch()?;
            let sealed = self.with(&gid, |g, c| g.send(c, &enc)).and_then(|body| {
                let key = idempotency_key(&gid, &self.member_id().0, &item.local_id, &body);
                self.client.outbox_seal(&item.local_id, &body, &to, &key)?;
                Ok(())
            });
            self.end_batch()?;
            if let Err(e) = sealed {
                // The group is gone or this device left it: never sendable.
                self.client.outbox_mark_failed(&item.local_id, &e.to_string())?;
                return Ok(Attempt::Failed(e));
            }
            item = self.client.outbox_item(&item.local_id)?.ok_or_else(|| Error::Protocol("outbox item vanished".into()))?;
        }
        let (Some(body), Some(key)) = (item.body.as_deref(), item.idempotency_key.as_deref()) else {
            self.client.outbox_mark_failed(&item.local_id, "damaged outbox item")?;
            return Ok(Attempt::Failed(Error::Protocol("damaged outbox item".into())));
        };
        self.client.outbox_mark_sending(&item.local_id)?;
        match self.api.send_keyed(&self.creds, &item.recipients, body, key) {
            Ok(v) => {
                self.client.outbox_mark_sent(&item.local_id, now())?;
                self.upload_finished(&item.local_id)?;
                Ok(Attempt::Sent(v["delivered"].as_u64().unwrap_or(0) as usize))
            }
            Err(e) => self.after_failure(&item, due, e),
        }
    }

    fn after_failure(&mut self, item: &OutboxItem, due: bool, e: Error) -> Result<Attempt, Error> {
        if !transient(&e) {
            self.client.outbox_mark_failed(&item.local_id, &e.to_string())?;
            return Ok(Attempt::Failed(e));
        }
        Ok(match self.client.outbox_mark_retry(&item.local_id, due, now(), &e.to_string())? {
            OutboxState::Failed => Attempt::Failed(e),
            _ => Attempt::Retry,
        })
    }

    /// Sends every outbox item that is due (sync does this too). Reports
    /// messages that went out (`Sent`) and items that were given up
    /// (`SendFailed`).
    pub fn send_pending(&mut self) -> Result<Vec<Event>, Error> {
        let before: HashMap<String, OutboxItem> =
            self.client.outbox_unsent(None)?.into_iter().map(|i| (i.local_id.clone(), i)).collect();
        let mut events = Vec::new();
        for (id, a) in self.drive_outbox(None)? {
            let Some(item) = before.get(&id) else { continue };
            match a {
                Attempt::Sent(_) if item.message_id.is_some() => {
                    events.push(Event::Sent { group: item.group_id.clone(), id: item.message_id.clone() })
                }
                Attempt::Failed(e) => events.push(Event::SendFailed {
                    group: item.group_id.clone(),
                    id: item.message_id.clone(),
                    local_id: id,
                    reason: e.to_string(),
                }),
                _ => {}
            }
        }
        Ok(events)
    }

    /// Items not sent yet (queued, sending, retry, failed), oldest first.
    pub fn outbox(&self) -> Result<Vec<OutboxEntry>, Error> {
        Ok(self.client.outbox_unsent(None)?.into_iter().map(Into::into).collect())
    }

    /// Send state of this device's messages in a group (message id ->
    /// state); messages without one were received, or sent long ago.
    pub fn send_states(&self, gid: &[u8]) -> Result<HashMap<String, OutboxState>, Error> {
        Ok(self.client.outbox_states(gid)?.into_iter().collect())
    }

    /// The unsent item with this local id or message id.
    fn find_item(&self, id: &str) -> Result<OutboxItem, Error> {
        self.client
            .outbox_unsent(None)?
            .into_iter()
            .find(|i| i.local_id == id || i.message_id.as_deref() == Some(id))
            .ok_or_else(|| Error::Usage("no such message waiting to be sent".into()))
    }

    /// The user retries a failed item (by local id or message id): a fresh
    /// budget of attempts, and one attempt now. Returns true if it went out.
    pub fn retry_send(&mut self, id: &str) -> Result<bool, Error> {
        let item = self.find_item(id)?;
        if !self.client.outbox_retry_now(&item.local_id, now())? {
            return Err(Error::Usage("only a failed message can be retried".into()));
        }
        match take(self.drive_outbox(Some(&item.group_id))?, &item.local_id) {
            Some(Attempt::Sent(_)) => Ok(true),
            Some(Attempt::Failed(e)) => Err(e),
            _ => Ok(false),
        }
    }

    /// The user gives up on a failed item (by local id or message id): it
    /// leaves the outbox, and its message leaves this device's history.
    /// Others may still have it if an earlier attempt reached the server
    /// and only the answer was lost.
    /// A paused file upload can be cancelled too; its partial upload goes.
    pub fn cancel_send(&mut self, id: &str) -> Result<(), Error> {
        let item = self.find_item(id)?;
        let paused = self.upload_state(&item.local_id)?.is_some_and(|u| u.paused);
        if paused && item.state != OutboxState::Failed {
            self.client.outbox_mark_failed(&item.local_id, "cancelled")?;
        }
        let Some(item) = self.client.outbox_cancel(&item.local_id)? else {
            return Err(Error::Usage("only a failed message can be cancelled".into()));
        };
        self.upload_cancelled(&item.local_id)?;
        if let Some(m) = &item.message_id {
            self.client.remove_message(&item.group_id, m)?;
        }
        Ok(())
    }
}
