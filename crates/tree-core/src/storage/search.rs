//! On-device full-text search index (`user.search_index`).
//!
//! An SQLite FTS5 index inside the same SQLCipher database as the history,
//! so it is encrypted like everything else and never leaves the device.
//! It exists only while the setting is applied: [`Client::build_search_index`]
//! creates it and fills it from the stored history, [`Client::drop_search_index`]
//! deletes it (tables and triggers; `secure_delete` overwrites the freed
//! pages). Triggers on `tree_messages` keep it current: new messages, edits,
//! deletions for everyone and expiring (disappearing) messages.
//!
//! Tokens: the `unicode61` tokenizer (words split at spaces and punctuation,
//! case and diacritics folded). Queries match words by prefix, so `사과`
//! finds `사과를` and `tree` finds `trees`; a piece from the middle of a word
//! is not found.

use rusqlite::{params, OptionalExtension};

use super::{storage_err, StoredProvider};
use super::messages::StoredMessage;
use crate::{client::Client, error::TreeError, provider::TreeProvider};

const CREATE: &str = "
    CREATE TABLE IF NOT EXISTS tree_search_ids (
        rid      INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id BLOB NOT NULL,
        id       TEXT NOT NULL,
        UNIQUE (group_id, id)
    );
    CREATE VIRTUAL TABLE IF NOT EXISTS tree_search USING fts5(text, tokenize = 'unicode61 remove_diacritics 2');
    CREATE TRIGGER IF NOT EXISTS tree_search_ins AFTER INSERT ON tree_messages
        WHEN NEW.deleted = 0 AND NEW.text IS NOT NULL AND NEW.text <> '' BEGIN
        INSERT OR IGNORE INTO tree_search_ids (group_id, id) VALUES (NEW.group_id, NEW.id);
        INSERT INTO tree_search (rowid, text)
            VALUES ((SELECT rid FROM tree_search_ids WHERE group_id = NEW.group_id AND id = NEW.id), NEW.text);
    END;
    CREATE TRIGGER IF NOT EXISTS tree_search_del AFTER DELETE ON tree_messages BEGIN
        DELETE FROM tree_search WHERE rowid = (SELECT rid FROM tree_search_ids WHERE group_id = OLD.group_id AND id = OLD.id);
        DELETE FROM tree_search_ids WHERE group_id = OLD.group_id AND id = OLD.id;
    END;
    CREATE TRIGGER IF NOT EXISTS tree_search_upd AFTER UPDATE OF text, deleted ON tree_messages BEGIN
        DELETE FROM tree_search WHERE rowid = (SELECT rid FROM tree_search_ids WHERE group_id = OLD.group_id AND id = OLD.id);
        DELETE FROM tree_search_ids WHERE group_id = OLD.group_id AND id = OLD.id;
        INSERT OR IGNORE INTO tree_search_ids (group_id, id)
            SELECT NEW.group_id, NEW.id WHERE NEW.deleted = 0 AND NEW.text IS NOT NULL AND NEW.text <> '';
        INSERT INTO tree_search (rowid, text)
            SELECT rid, NEW.text FROM tree_search_ids
            WHERE group_id = NEW.group_id AND id = NEW.id AND NEW.deleted = 0 AND NEW.text IS NOT NULL AND NEW.text <> '';
    END;";

const DROP: &str = "
    DROP TRIGGER IF EXISTS tree_search_ins;
    DROP TRIGGER IF EXISTS tree_search_del;
    DROP TRIGGER IF EXISTS tree_search_upd;
    DROP TABLE IF EXISTS tree_search;
    DROP TABLE IF EXISTS tree_search_ids;";

/// Words of a search turned into an FTS5 query: each word quoted (no query
/// syntax gets through) and matched by prefix; all words must match.
/// `None` if there is no word in it.
pub fn fts_query(needle: &str) -> Option<String> {
    let words: Vec<String> = needle
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .take(16)
        .map(|w| format!("\"{}\"*", w.replace('"', "")))
        .collect();
    (!words.is_empty()).then(|| words.join(" "))
}

impl Client<StoredProvider> {
    fn search_conn(&self) -> &rusqlite::Connection {
        &self.provider.storage.conn
    }

    /// Whether the search index exists.
    pub fn has_search_index(&self) -> Result<bool, TreeError> {
        self.search_conn()
            .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tree_search'", [], |_| Ok(()))
            .optional()
            .map(|r| r.is_some())
            .map_err(storage_err)
    }

    /// Creates the index (if missing) and fills it from the whole stored
    /// history. Returns how many messages it holds.
    pub fn build_search_index(&self) -> Result<usize, TreeError> {
        self.provider.atomically(|| {
            let c = self.search_conn();
            c.execute_batch(DROP).map_err(storage_err)?;
            c.execute_batch(CREATE).map_err(storage_err)?;
            // Removed entries are taken out of the index's pages, not only
            // marked (FTS5 secure-delete; best effort on older SQLite).
            let _ = c.execute("INSERT INTO tree_search (tree_search, rank) VALUES ('secure-delete', 1)", []);
            c.execute(
                "INSERT INTO tree_search_ids (group_id, id)
                 SELECT group_id, id FROM tree_messages WHERE deleted = 0 AND text IS NOT NULL AND text <> ''",
                [],
            )
            .map_err(storage_err)?;
            c.execute(
                "INSERT INTO tree_search (rowid, text)
                 SELECT i.rid, m.text FROM tree_search_ids i JOIN tree_messages m ON m.group_id = i.group_id AND m.id = i.id",
                [],
            )
            .map_err(storage_err)
        })
    }

    /// Deletes the index and its triggers. The history itself stays.
    pub fn drop_search_index(&self) -> Result<(), TreeError> {
        self.provider.atomically(|| self.search_conn().execute_batch(DROP).map_err(storage_err))
    }

    /// Messages matching every word of `needle` (by word prefix), newest
    /// first, at most `limit`. Needs the index ([`Client::build_search_index`]).
    pub fn search_index(&self, needle: &str, limit: u32) -> Result<Vec<StoredMessage>, TreeError> {
        if !self.has_search_index()? {
            return Err(TreeError::Storage("there is no search index".into()));
        }
        let Some(q) = fts_query(needle) else { return Ok(vec![]) };
        let mut stmt = self
            .search_conn()
            .prepare(
                "SELECT i.group_id, i.id FROM tree_search s JOIN tree_search_ids i ON i.rid = s.rowid
                 WHERE tree_search MATCH ?1",
            )
            .map_err(storage_err)?;
        let keys = stmt
            .query_map(params![q], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?)))
            .map_err(storage_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_err)?;
        let mut out = Vec::new();
        for (g, id) in keys {
            if let Some(m) = self.message(&g, &id)? {
                if !m.deleted {
                    out.push(m);
                }
            }
        }
        out.sort_by_key(|m| std::cmp::Reverse(m.received_at));
        out.truncate(limit as usize);
        Ok(out)
    }

    /// Rows in the index (for tests and the settings screen).
    pub fn search_index_size(&self) -> Result<usize, TreeError> {
        if !self.has_search_index()? {
            return Ok(0);
        }
        self.search_conn()
            .query_row("SELECT count(*) FROM tree_search_ids", [], |r| r.get::<_, i64>(0))
            .map(|n| n as usize)
            .map_err(storage_err)
    }
}

#[cfg(test)]
mod tests {
    use super::fts_query;

    #[test]
    fn queries_are_quoted_prefixes() {
        assert_eq!(fts_query("사과 tree").as_deref(), Some("\"사과\"* \"tree\"*"));
        assert_eq!(fts_query("a\" OR b NEAR(").as_deref(), Some("\"a\"* \"OR\"* \"b\"* \"NEAR\"*"));
        assert_eq!(fts_query(" .,; "), None);
    }
}
