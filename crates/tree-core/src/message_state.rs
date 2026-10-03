//! Bounded local metadata for structured E2E message events.
//!
//! Plaintext bodies are intentionally not kept here. The actual conversation
//! history belongs in the future SQLCipher message store. This state only
//! keeps enough authenticated metadata to authorize edits/deletes, reject
//! stale per-sender events and replay out-of-order mutations.

use crate::{
    error::TreeError,
    group::MemberId,
    message::{MessageEvent, MessageId},
};

const VERSION: u8 = 1;
const MAX_RECORDS: usize = 4096;
const MAX_PENDING: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MessageRecord {
    pub id: MessageId,
    pub author: MemberId,
    pub created_at: i64,
    pub ttl_secs: u32,
    pub view_once: bool,
    pub deleted: bool,
    pub last_edit_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingMutation {
    pub from: MemberId,
    pub event: MessageEvent,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct MessageLedger {
    pub next_seq: u64,
    pub records: Vec<MessageRecord>,
    pub pending: Vec<PendingMutation>,
}

impl MessageLedger {
    pub fn next_outgoing_seq(&mut self) -> Result<u64, TreeError> {
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| TreeError::Group("message sequence exhausted".into()))?;
        Ok(self.next_seq)
    }

    pub fn record_new(&mut self, record: MessageRecord) -> bool {
        if self.records.iter().any(|r| r.id == record.id) {
            return false;
        }
        if self.records.len() >= MAX_RECORDS {
            self.records.remove(0);
        }
        self.records.push(record);
        true
    }

    pub fn record(&self, id: MessageId) -> Option<&MessageRecord> {
        self.records.iter().find(|r| r.id == id)
    }

    pub fn record_mut(&mut self, id: MessageId) -> Option<&mut MessageRecord> {
        self.records.iter_mut().find(|r| r.id == id)
    }

    pub fn queue_pending(&mut self, mutation: PendingMutation) {
        if self.pending.len() >= MAX_PENDING {
            self.pending.remove(0);
        }
        self.pending.push(mutation);
    }

    pub fn take_pending_for(&mut self, target: MessageId) -> Vec<PendingMutation> {
        let mut found = Vec::new();
        let mut rest = Vec::with_capacity(self.pending.len());
        for mutation in self.pending.drain(..) {
            if mutation.event.target() == Some(target) {
                found.push(mutation);
            } else {
                rest.push(mutation);
            }
        }
        self.pending = rest;
        found
    }

    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        if self.sender_seq.len() > u16::MAX as usize
            || self.records.len() > u16::MAX as usize
            || self.pending.len() > u16::MAX as usize
        {
            return Err(TreeError::Storage("message ledger is too large".into()));
        }
        let mut out = vec![VERSION];
        out.extend_from_slice(&self.next_seq.to_be_bytes());

        out.extend_from_slice(&(self.records.len() as u16).to_be_bytes());
        for record in &self.records {
            out.extend_from_slice(record.id.as_bytes());
            out.extend_from_slice(record.author.as_bytes());
            out.extend_from_slice(&record.created_at.to_be_bytes());
            out.extend_from_slice(&record.ttl_secs.to_be_bytes());
            let mut flags = 0u8;
            if record.view_once {
                flags |= 1;
            }
            if record.deleted {
                flags |= 2;
            }
            out.push(flags);
            out.extend_from_slice(&record.last_edit_seq.to_be_bytes());
        }

        out.extend_from_slice(&(self.pending.len() as u16).to_be_bytes());
        for mutation in &self.pending {
            out.extend_from_slice(mutation.from.as_bytes());
            let bytes = mutation.event.encode()?;
            if bytes.len() > u32::MAX as usize {
                return Err(TreeError::Storage("pending message operation is too large".into()));
            }
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        let mut r = Reader(bytes);
        if r.u8()? != VERSION {
            return Err(damaged());
        }
        let next_seq = r.u64()?;

        let record_count = r.u16()? as usize;
        if record_count > MAX_RECORDS {
            return Err(damaged());
        }
        let mut records = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            let id = MessageId(r.array()?);
            let author = MemberId(r.array()?);
            let created_at = r.i64()?;
            let ttl_secs = r.u32()?;
            let flags = r.u8()?;
            if flags & !0b11 != 0 {
                return Err(damaged());
            }
            let last_edit_seq = r.u64()?;
            records.push(MessageRecord {
                id,
                author,
                created_at,
                ttl_secs,
                view_once: flags & 1 != 0,
                deleted: flags & 2 != 0,
                last_edit_seq,
            });
        }

        let pending_count = r.u16()? as usize;
        if pending_count > MAX_PENDING {
            return Err(damaged());
        }
        let mut pending = Vec::with_capacity(pending_count);
        for _ in 0..pending_count {
            let from = MemberId(r.array()?);
            let event = MessageEvent::decode(r.bytes(u32::MAX as usize)?)?;
            if matches!(event, MessageEvent::New { .. }) {
                return Err(damaged());
            }
            pending.push(PendingMutation { from, event });
        }

        if !r.0.is_empty() {
            return Err(damaged());
        }
        Ok(Self {
            next_seq,
            records,
            pending,
        })
    }
}

fn damaged() -> TreeError {
    TreeError::Storage("stored message ledger is damaged".into())
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], TreeError> {
        if self.0.len() < n {
            return Err(damaged());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, TreeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TreeError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("length checked")))
    }

    fn u32(&mut self) -> Result<u32, TreeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("length checked")))
    }

    fn u64(&mut self) -> Result<u64, TreeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("length checked")))
    }

    fn i64(&mut self) -> Result<i64, TreeError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("length checked")))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TreeError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, TreeError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(damaged());
        }
        Ok(self.take(len)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_round_trips_without_plaintext_history() {
        let sender = MemberId([1; 32]);
        let id = MessageId([2; 16]);
        let event = MessageEvent::Edit {
            target: id,
            seq: 2,
            edited_at: 42,
            body: b"edited locally".to_vec(),
        };
        let ledger = MessageLedger {
            next_seq: 8,
            records: vec![MessageRecord {
                id,
                author: sender,
                created_at: 10,
                ttl_secs: 86400,
                view_once: false,
                deleted: false,
                last_edit_seq: 2,
            }],
            pending: vec![PendingMutation { from: sender, event }],
        };
        let bytes = ledger.encode().unwrap();
        let decoded = MessageLedger::decode(&bytes).unwrap();
        assert_eq!(decoded, ledger);
    }

    #[test]
    fn duplicate_message_id_is_not_reinserted() {
        let id = MessageId([1; 16]);
        let author = MemberId([2; 32]);
        let record = MessageRecord {
            id,
            author,
            created_at: 1,
            ttl_secs: 0,
            view_once: false,
            deleted: false,
            last_edit_seq: 0,
        };
        let mut ledger = MessageLedger::default();
        assert!(ledger.record_new(record.clone()));
        assert!(!ledger.record_new(record));
        assert_eq!(ledger.records.len(), 1);
    }
}
