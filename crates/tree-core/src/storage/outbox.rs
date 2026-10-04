//! The outbox (`tree_outbox`, schema v5): messages this device is sending,
//! kept in the encrypted database until the server confirmed them
//! (PROTOCOL.md 6.13).
//!
//! States: `queued -> sending -> sent | retry -> sending ... | failed`.
//!
//! * An item is enqueued once per local id (a second enqueue with the same
//!   id changes nothing).
//! * Its MLS ciphertext is made once and stored with it; every retry sends
//!   exactly these bytes with the same idempotency key. Re-encrypting would
//!   use new message keys and make a second, different ciphertext of the
//!   same message.
//! * A failed attempt waits [`backoff`] (5 s, doubling, at most 1 h); after
//!   [`MAX_ATTEMPTS`] counted attempts the item is `failed` until the user
//!   retries or cancels it.
//! * An item still `sending` when the profile is opened was cut off by a
//!   crash: [`Client::outbox_recover`] turns it into `retry`.
//! * A `sent` item keeps only its ids and state (the ciphertext is erased),
//!   so an enqueue of the same local id stays a no-op.

use rusqlite::{params, OptionalExtension, Row};
use sha2::{Digest, Sha256};

use super::{storage_err, StoredProvider};
use crate::{client::Client, error::TreeError, provider::TreeProvider};

/// Attempts before an item is `failed`.
pub const MAX_ATTEMPTS: u32 = 8;
/// First wait after a failed attempt, doubled after each one.
pub const BACKOFF_FIRST: i64 = 5;
/// Longest wait between attempts.
pub const BACKOFF_MAX: i64 = 3600;
/// `sent` records are dropped after this long (they only keep enqueue
/// idempotent and the history's "sent" mark).
pub const SENT_KEEP: i64 = 30 * 86400;
/// Domain label of [`idempotency_key`].
pub const IDEMPOTENCY_LABEL: &[u8] = b"tree/outbox/idempotency/v1";

/// Where an item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboxState {
    /// Enqueued, never attempted.
    Queued,
    /// An attempt is running (or was cut off by a crash).
    Sending,
    /// The server confirmed it.
    Sent,
    /// An attempt failed; the next one is due at `next_at`.
    Retry,
    /// Given up: the server refused it, or every attempt failed.
    Failed,
}

impl OutboxState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sending => "sending",
            Self::Sent => "sent",
            Self::Retry => "retry",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => Self::Queued,
            "sending" => Self::Sending,
            "sent" => Self::Sent,
            "retry" => Self::Retry,
            "failed" => Self::Failed,
            _ => return None,
        })
    }

    /// Still on its way (shown as pending).
    pub fn is_pending(self) -> bool {
        matches!(self, Self::Queued | Self::Sending | Self::Retry)
    }
}

/// One item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    /// Unique on this device (random, chosen at enqueue).
    pub local_id: String,
    pub group_id: Vec<u8>,
    /// The history message this item carries, if it is one (text, file).
    pub message_id: Option<String>,
    /// The encoded app payload while it is not sealed yet (it needs the
    /// server for its franking tag); erased when sealed.
    pub payload: Option<Vec<u8>>,
    /// The sealed MLS message, made once.
    pub body: Option<Vec<u8>>,
    /// Device ids it goes to (fixed when sealed).
    pub recipients: Vec<String>,
    /// Sent with every attempt (fixed when sealed).
    pub idempotency_key: Option<Vec<u8>>,
    pub state: OutboxState,
    /// Counted failed attempts.
    pub attempts: u32,
    /// Unix seconds when the next attempt is due.
    pub next_at: i64,
    pub created_at: i64,
    /// Why the last attempt failed (error text, no content).
    pub last_error: Option<String>,
}

impl OutboxItem {
    /// A new `queued` item.
    pub fn new(local_id: &str, group_id: &[u8], message_id: Option<&str>, now: i64) -> Self {
        OutboxItem {
            local_id: local_id.to_string(),
            group_id: group_id.to_vec(),
            message_id: message_id.map(str::to_string),
            payload: None,
            body: None,
            recipients: vec![],
            idempotency_key: None,
            state: OutboxState::Queued,
            attempts: 0,
            next_at: now,
            created_at: now,
            last_error: None,
        }
    }
}

/// Wait after `attempts` counted failed attempts (`attempts >= 1`):
/// 5 s, 10 s, 20 s, ... at most 1 h.
pub fn backoff(attempts: u32) -> i64 {
    let shift = attempts.saturating_sub(1).min(20);
    (BACKOFF_FIRST << shift).min(BACKOFF_MAX)
}

/// The idempotency key of a sealed item:
///
/// ```text
/// SHA-256( lp(label) || lp(group_id) || lp(sender member id) || lp(local_id) || lp(body) )
/// lp(x) = uint32 big-endian length of x || x
/// ```
///
/// It binds the group, the sender, the item and its content, each with a
/// length prefix, so two different items (other group, other sender, other
/// local id or other ciphertext) never share a key. It is an identifier,
/// not a secret: the server sees the body anyway.
pub fn idempotency_key(group_id: &[u8], sender: &[u8], local_id: &str, body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [IDEMPOTENCY_LABEL, group_id, sender, local_id.as_bytes(), body] {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

const COLS: &str =
    "local_id, group_id, message_id, payload, body, recipients, idem_key, state, attempts, next_at, created_at, last_error";

fn from_row(r: &Row<'_>) -> rusqlite::Result<OutboxItem> {
    let recipients: String = r.get(5)?;
    let state: String = r.get(7)?;
    Ok(OutboxItem {
        local_id: r.get(0)?,
        group_id: r.get(1)?,
        message_id: r.get(2)?,
        payload: r.get(3)?,
        body: r.get(4)?,
        recipients: serde_json::from_str(&recipients).unwrap_or_default(),
        idempotency_key: r.get(6)?,
        state: OutboxState::parse(&state).unwrap_or(OutboxState::Failed),
        attempts: r.get::<_, i64>(8)?.max(0) as u32,
        next_at: r.get(9)?,
        created_at: r.get(10)?,
        last_error: r.get(11)?,
    })
}

impl Client<StoredProvider> {
    fn oconn(&self) -> &rusqlite::Connection {
        &self.provider.storage.conn
    }

    fn outbox_exec(&self, sql: &str, p: impl rusqlite::Params) -> Result<usize, TreeError> {
        self.provider.atomically(|| self.oconn().execute(sql, p).map_err(storage_err))
    }

    /// Adds an item. Idempotent by local id: returns false (and changes
    /// nothing) if an item with this id exists or existed.
    pub fn outbox_enqueue(&self, item: &OutboxItem) -> Result<bool, TreeError> {
        let recipients = serde_json::to_string(&item.recipients).map_err(storage_err)?;
        let n = self.outbox_exec(
            &format!("INSERT OR IGNORE INTO tree_outbox ({COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"),
            params![
                item.local_id,
                item.group_id,
                item.message_id,
                item.payload,
                item.body,
                recipients,
                item.idempotency_key,
                item.state.as_str(),
                item.attempts as i64,
                item.next_at,
                item.created_at,
                item.last_error
            ],
        )?;
        Ok(n == 1)
    }

    pub fn outbox_item(&self, local_id: &str) -> Result<Option<OutboxItem>, TreeError> {
        self.oconn()
            .query_row(&format!("SELECT {COLS} FROM tree_outbox WHERE local_id = ?1"), params![local_id], from_row)
            .optional()
            .map_err(storage_err)
    }

    /// Every item that is not `sent`, oldest first (optionally of one group).
    pub fn outbox_unsent(&self, group_id: Option<&[u8]>) -> Result<Vec<OutboxItem>, TreeError> {
        let mut stmt = self
            .oconn()
            .prepare(&format!(
                "SELECT {COLS} FROM tree_outbox WHERE state != 'sent' AND (?1 IS NULL OR group_id = ?1) ORDER BY seq"
            ))
            .map_err(storage_err)?;
        let rows = stmt.query_map(params![group_id], from_row).map_err(storage_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_err)
    }

    /// Stores the sealed message, its recipients and its idempotency key,
    /// and erases the unsealed payload. Call inside the batch that advanced
    /// the group's keys, so both reach the disk together.
    pub fn outbox_seal(&self, local_id: &str, body: &[u8], recipients: &[String], key: &[u8]) -> Result<(), TreeError> {
        let recipients = serde_json::to_string(recipients).map_err(storage_err)?;
        self.outbox_exec(
            "UPDATE tree_outbox SET body = ?2, recipients = ?3, idem_key = ?4, payload = NULL \
             WHERE local_id = ?1 AND body IS NULL AND state != 'sent'",
            params![local_id, body, recipients, key],
        )?;
        Ok(())
    }

    /// An attempt starts (stored before the request goes out).
    pub fn outbox_mark_sending(&self, local_id: &str) -> Result<(), TreeError> {
        self.outbox_set(local_id, OutboxState::Sending, None, None, None)
    }

    /// The server confirmed it: the ciphertext and recipients are erased.
    pub fn outbox_mark_sent(&self, local_id: &str, now: i64) -> Result<(), TreeError> {
        self.outbox_exec(
            "UPDATE tree_outbox SET state = 'sent', payload = NULL, body = NULL, recipients = '[]', last_error = NULL, next_at = ?2 \
             WHERE local_id = ?1",
            params![local_id, now],
        )?;
        Ok(())
    }

    /// An attempt failed for a passing reason. `counted`: it was due (a
    /// forced early attempt does not use up the budget). Returns the new
    /// state: `retry` with the next due time, or `failed` after
    /// [`MAX_ATTEMPTS`].
    pub fn outbox_mark_retry(&self, local_id: &str, counted: bool, now: i64, error: &str) -> Result<OutboxState, TreeError> {
        let item = self.outbox_item(local_id)?.ok_or_else(|| TreeError::Storage("no such outbox item".into()))?;
        let attempts = item.attempts + u32::from(counted);
        if attempts >= MAX_ATTEMPTS {
            self.outbox_set(local_id, OutboxState::Failed, Some(attempts), None, Some(error))?;
            return Ok(OutboxState::Failed);
        }
        let next = if counted { now + backoff(attempts) } else { item.next_at };
        self.outbox_set(local_id, OutboxState::Retry, Some(attempts), Some(next), Some(error))?;
        Ok(OutboxState::Retry)
    }

    /// Given up for good (the server refused it, or it cannot be sealed).
    pub fn outbox_mark_failed(&self, local_id: &str, error: &str) -> Result<(), TreeError> {
        self.outbox_set(local_id, OutboxState::Failed, None, None, Some(error))
    }

    fn outbox_set(
        &self,
        local_id: &str,
        state: OutboxState,
        attempts: Option<u32>,
        next_at: Option<i64>,
        error: Option<&str>,
    ) -> Result<(), TreeError> {
        self.outbox_exec(
            "UPDATE tree_outbox SET state = ?2, attempts = COALESCE(?3, attempts), next_at = COALESCE(?4, next_at), \
             last_error = COALESCE(?5, last_error) WHERE local_id = ?1 AND state != 'sent'",
            params![local_id, state.as_str(), attempts.map(i64::from), next_at, error],
        )?;
        Ok(())
    }

    /// After opening the profile: items cut off in `sending` by a crash
    /// become `retry`, due at once (the attempt counts), and old `sent`
    /// records are dropped. Returns how many items were recovered.
    pub fn outbox_recover(&self, now: i64) -> Result<usize, TreeError> {
        self.provider.atomically(|| {
            self.oconn()
                .execute("DELETE FROM tree_outbox WHERE state = 'sent' AND next_at < ?1", params![now - SENT_KEEP])
                .map_err(storage_err)?;
            let stuck: Vec<String> = {
                let mut stmt = self.oconn().prepare("SELECT local_id FROM tree_outbox WHERE state = 'sending'").map_err(storage_err)?;
                let rows = stmt.query_map([], |r| r.get(0)).map_err(storage_err)?;
                rows.collect::<Result<_, _>>().map_err(storage_err)?
            };
            for id in &stuck {
                let item = self.outbox_item(id)?.ok_or_else(|| TreeError::Storage("outbox item vanished".into()))?;
                let attempts = item.attempts + 1;
                let state = if attempts >= MAX_ATTEMPTS { OutboxState::Failed } else { OutboxState::Retry };
                self.oconn()
                    .execute(
                        "UPDATE tree_outbox SET state = ?2, attempts = ?3, next_at = ?4, last_error = 'interrupted' WHERE local_id = ?1",
                        params![id, state.as_str(), attempts as i64, now],
                    )
                    .map_err(storage_err)?;
            }
            Ok(stuck.len())
        })
    }

    /// The user asks to try a `failed` item again: a fresh budget of
    /// attempts, due now. Returns false if the item is not `failed`.
    pub fn outbox_retry_now(&self, local_id: &str, now: i64) -> Result<bool, TreeError> {
        let n = self.outbox_exec(
            "UPDATE tree_outbox SET state = 'retry', attempts = 0, next_at = ?2 WHERE local_id = ?1 AND state = 'failed'",
            params![local_id, now],
        )?;
        Ok(n == 1)
    }

    /// The user gives up on a `failed` item: it is removed (with its
    /// ciphertext). Returns the item, or `None` if it is not `failed`.
    pub fn outbox_cancel(&self, local_id: &str) -> Result<Option<OutboxItem>, TreeError> {
        let Some(item) = self.outbox_item(local_id)?.filter(|i| i.state == OutboxState::Failed) else {
            return Ok(None);
        };
        self.outbox_exec("DELETE FROM tree_outbox WHERE local_id = ?1 AND state = 'failed'", params![local_id])?;
        Ok(Some(item))
    }

    /// Send state of the history messages of a group that have one
    /// (message id -> state). Received messages have none.
    pub fn outbox_states(&self, group_id: &[u8]) -> Result<Vec<(String, OutboxState)>, TreeError> {
        let mut stmt = self
            .oconn()
            .prepare("SELECT message_id, state FROM tree_outbox WHERE group_id = ?1 AND message_id IS NOT NULL ORDER BY seq")
            .map_err(storage_err)?;
        let rows = stmt
            .query_map(params![group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(storage_err)?;
        let mut out = Vec::new();
        for r in rows {
            let (id, st) = r.map_err(storage_err)?;
            out.push((id, OutboxState::parse(&st).unwrap_or(OutboxState::Failed)));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_schedule() {
        let waits: Vec<i64> = (1..=MAX_ATTEMPTS).map(backoff).collect();
        assert_eq!(waits, vec![5, 10, 20, 40, 80, 160, 320, 640]);
        assert_eq!(backoff(10), 2560);
        assert_eq!(backoff(11), 3600, "capped at an hour");
        assert_eq!(backoff(u32::MAX), 3600);
        assert_eq!(backoff(0), 5);
    }

    #[test]
    fn states_round_trip() {
        for s in [OutboxState::Queued, OutboxState::Sending, OutboxState::Sent, OutboxState::Retry, OutboxState::Failed] {
            assert_eq!(OutboxState::parse(s.as_str()), Some(s));
        }
        assert_eq!(OutboxState::parse("lost"), None);
    }

    #[test]
    fn keys_bind_every_field() {
        let base = idempotency_key(b"group", b"sender", "id1", b"body");
        assert_eq!(base, idempotency_key(b"group", b"sender", "id1", b"body"), "deterministic");
        for other in [
            idempotency_key(b"group2", b"sender", "id1", b"body"),
            idempotency_key(b"group", b"sender2", "id1", b"body"),
            idempotency_key(b"group", b"sender", "id2", b"body"),
            idempotency_key(b"group", b"sender", "id1", b"body2"),
            // moving bytes between fields changes the key (length prefixes)
            idempotency_key(b"groups", b"ender", "id1", b"body"),
            idempotency_key(b"group", b"sender", "id1b", b"ody"),
        ] {
            assert_ne!(base, other);
        }
    }
}
