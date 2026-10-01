//! Message history on the device (`tree_messages`, schema v4).
//!
//! Plaintext history is exactly what forward secrecy does not protect
//! (PROTOCOL.md 6.3 item 6), so it lives only in the encrypted database,
//! deleted rows are overwritten (`secure_delete`), and messages with an
//! expiry (disappearing messages) are removed by [`Client::purge_expired_messages`].

use std::collections::BTreeMap;

use rusqlite::{params, OptionalExtension, Row};

use super::{storage_err, StoredProvider};
use crate::{client::Client, error::TreeError, provider::TreeProvider};

/// One message as kept on the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub group_id: Vec<u8>,
    /// Sender-chosen random id (hex), unique per group.
    pub id: String,
    /// Member id (hex) of the sender.
    pub sender: String,
    /// When this device received (or sent) it, unix seconds.
    pub received_at: i64,
    /// "text" or "file".
    pub kind: String,
    pub text: Option<String>,
    /// Kind-specific data (e.g. the file reference).
    pub data: Option<Vec<u8>>,
    pub edited_at: Option<i64>,
    /// Deleted for everyone: text and data are gone.
    pub deleted: bool,
    pub expires_at: Option<i64>,
    /// Emoji -> member ids (hex) that reacted with it.
    pub reactions: BTreeMap<String, Vec<String>>,
    /// What lets this device report the message (PROTOCOL.md 8.5): the
    /// payload as received with its franking key and server tag. Erased
    /// with the message.
    pub franking: Option<Vec<u8>>,
}

const COLS: &str = "group_id, id, sender, received_at, kind, text, data, edited_at, deleted, expires_at, reactions, franking";

fn from_row(r: &Row<'_>) -> rusqlite::Result<StoredMessage> {
    let reactions: String = r.get(10)?;
    Ok(StoredMessage {
        group_id: r.get(0)?,
        id: r.get(1)?,
        sender: r.get(2)?,
        received_at: r.get(3)?,
        kind: r.get(4)?,
        text: r.get(5)?,
        data: r.get(6)?,
        edited_at: r.get(7)?,
        deleted: r.get::<_, i64>(8)? != 0,
        expires_at: r.get(9)?,
        reactions: serde_json::from_str(&reactions).unwrap_or_default(),
        franking: r.get(11)?,
    })
}

impl Client<StoredProvider> {
    fn conn(&self) -> &rusqlite::Connection {
        &self.provider.storage.conn
    }

    /// Stores a message; a second copy with the same (group, id) is ignored.
    /// Returns false for such a duplicate.
    pub fn store_message(&self, m: &StoredMessage) -> Result<bool, TreeError> {
        let reactions = serde_json::to_string(&m.reactions).map_err(storage_err)?;
        self.provider.atomically(|| {
            let n = self
                .conn()
                .execute(
                    &format!("INSERT OR IGNORE INTO tree_messages ({COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"),
                    params![m.group_id, m.id, m.sender, m.received_at, m.kind, m.text, m.data, m.edited_at, m.deleted, m.expires_at, reactions, m.franking],
                )
                .map_err(storage_err)?;
            Ok(n == 1)
        })
    }

    pub fn message(&self, group_id: &[u8], id: &str) -> Result<Option<StoredMessage>, TreeError> {
        self.conn()
            .query_row(&format!("SELECT {COLS} FROM tree_messages WHERE group_id = ?1 AND id = ?2"), params![group_id, id], from_row)
            .optional()
            .map_err(storage_err)
    }

    /// Replaces the text of a message (an edit already checked by the
    /// caller), with the edit's franking record.
    pub fn edit_message(&self, group_id: &[u8], id: &str, text: &str, at: i64, franking: Option<&[u8]>) -> Result<(), TreeError> {
        self.provider.atomically(|| {
            self.conn()
                .execute(
                    "UPDATE tree_messages SET text = ?3, edited_at = ?4, franking = ?5 WHERE group_id = ?1 AND id = ?2 AND deleted = 0",
                    params![group_id, id, text, at, franking],
                )
                .map(|_| ())
                .map_err(storage_err)
        })
    }

    /// Deletes a message for everyone: its text and data are erased, a
    /// placeholder row stays so a late edit cannot bring it back.
    pub fn delete_message(&self, group_id: &[u8], id: &str) -> Result<(), TreeError> {
        self.provider.atomically(|| {
            self.conn()
                .execute(
                    "UPDATE tree_messages SET text = NULL, data = NULL, franking = NULL, deleted = 1, reactions = '{}' WHERE group_id = ?1 AND id = ?2",
                    params![group_id, id],
                )
                .map(|_| ())
                .map_err(storage_err)
        })
    }

    /// Adds or removes one member's reaction.
    pub fn react(&self, group_id: &[u8], id: &str, member: &str, emoji: &str, remove: bool) -> Result<(), TreeError> {
        let Some(mut m) = self.message(group_id, id)? else { return Ok(()) };
        if m.deleted {
            return Ok(());
        }
        let list = m.reactions.entry(emoji.to_string()).or_default();
        list.retain(|x| x != member);
        if !remove {
            list.push(member.to_string());
        }
        m.reactions.retain(|_, v| !v.is_empty());
        let json = serde_json::to_string(&m.reactions).map_err(storage_err)?;
        self.provider.atomically(|| {
            self.conn()
                .execute("UPDATE tree_messages SET reactions = ?3 WHERE group_id = ?1 AND id = ?2", params![group_id, id, json])
                .map(|_| ())
                .map_err(storage_err)
        })
    }

    /// Replaces the kind-specific data (e.g. drops a view-once file reference).
    pub fn set_message_data(&self, group_id: &[u8], id: &str, data: Option<&[u8]>) -> Result<(), TreeError> {
        self.provider.atomically(|| {
            self.conn()
                .execute("UPDATE tree_messages SET data = ?3 WHERE group_id = ?1 AND id = ?2", params![group_id, id, data])
                .map(|_| ())
                .map_err(storage_err)
        })
    }

    /// Newest `limit` messages of a group received before `before`
    /// (unix seconds, exclusive), oldest first.
    pub fn messages(&self, group_id: &[u8], limit: u32, before: Option<i64>) -> Result<Vec<StoredMessage>, TreeError> {
        let mut stmt = self
            .conn()
            .prepare(&format!(
                "SELECT {COLS} FROM tree_messages WHERE group_id = ?1 AND received_at < ?2 \
                 ORDER BY received_at DESC, id DESC LIMIT ?3"
            ))
            .map_err(storage_err)?;
        let rows = stmt.query_map(params![group_id, before.unwrap_or(i64::MAX), limit], from_row).map_err(storage_err)?;
        let mut v = rows.collect::<Result<Vec<_>, _>>().map_err(storage_err)?;
        v.reverse();
        Ok(v)
    }

    /// Messages whose text contains `needle` (case-insensitive for ASCII),
    /// newest first, at most `limit`. Search runs on this device only.
    pub fn search_messages(&self, needle: &str, limit: u32) -> Result<Vec<StoredMessage>, TreeError> {
        let pattern = format!("%{}%", needle.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
        let mut stmt = self
            .conn()
            .prepare(&format!(
                "SELECT {COLS} FROM tree_messages WHERE deleted = 0 AND text LIKE ?1 ESCAPE '\\' \
                 ORDER BY received_at DESC LIMIT ?2"
            ))
            .map_err(storage_err)?;
        let rows = stmt.query_map(params![pattern, limit], from_row).map_err(storage_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_err)
    }

    /// Removes messages whose expiry has passed (disappearing messages).
    /// Returns how many.
    pub fn purge_expired_messages(&self, now: i64) -> Result<usize, TreeError> {
        self.provider.atomically(|| {
            self.conn()
                .execute("DELETE FROM tree_messages WHERE expires_at IS NOT NULL AND expires_at <= ?1", params![now])
                .map_err(storage_err)
        })
    }

    /// Removes the whole history of a group.
    pub fn forget_messages(&self, group_id: &[u8]) -> Result<usize, TreeError> {
        self.provider.atomically(|| {
            self.conn().execute("DELETE FROM tree_messages WHERE group_id = ?1", params![group_id]).map_err(storage_err)
        })
    }
}
