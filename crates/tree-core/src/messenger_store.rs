//! Durable messenger repository backed by the device's SQLCipher database.
//!
//! This layer intentionally stores plaintext only inside the already encrypted
//! local profile. It is not part of the network protocol.

use rusqlite::{params, OptionalExtension};
use crate::{error::TreeError, message::{MessageEvent, MessageId}, storage::StoredProvider};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboxState {
    Queued,
    Sending,
    Retry,
    Sent,
    Failed,
    Cancelled,
    Superseded,
}

impl OutboxState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sending => "sending",
            Self::Retry => "retry",
            Self::Sent => "sent",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Superseded => "superseded",
        }
    }

    pub fn parse(value: &str) -> Result<Self, TreeError> {
        match value {
            "queued" => Ok(Self::Queued),
            "sending" => Ok(Self::Sending),
            "retry" => Ok(Self::Retry),
            "sent" => Ok(Self::Sent),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "superseded" => Ok(Self::Superseded),
            _ => Err(TreeError::Storage("invalid outbox state".into())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMessage {
    pub group_id: Vec<u8>,
    pub message_id: MessageId,
    pub sender: [u8; 32],
    pub sequence: u64,
    pub created_at: i64,
    pub edited_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub view_once: bool,
    pub deleted: bool,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxItem {
    pub local_id: [u8; 16],
    pub group_id: Vec<u8>,
    pub message_id: Option<MessageId>,
    pub kind: u8,
    pub envelope: Vec<u8>,
    pub state: OutboxState,
    pub attempts: u32,
    pub next_retry_at: i64,
    pub created_at: i64,
    pub last_error_code: Option<String>,
    pub server_id: Option<String>,
}

fn local_err(e: impl std::fmt::Display) -> TreeError {
    TreeError::Storage(e.to_string())
}

fn parse_id<const N: usize>(bytes: Vec<u8>, what: &str) -> Result<[u8; N], TreeError> {
    bytes.try_into().map_err(|_| TreeError::Storage(format!("{what} has invalid length")))
}

impl StoredProvider {
    pub(crate) fn store_message_event(
        &self,
        group_id: &[u8],
        event: &MessageEvent,
        sender: &[u8; 32],
    ) -> Result<(), TreeError> {
        let (id, seq, created_at, ttl_secs, view_once, deleted, body) = match event {
            MessageEvent::New { id, seq, sent_at, ttl_secs, view_once, body, .. } => {
                (*id, *seq, *sent_at, *ttl_secs, *view_once, false, body.clone())
            }
            _ => return Err(TreeError::Storage("only New events create stored messages".into())),
        };
        let now = crate::message::DEFAULT_EDIT_WINDOW_SECS as i64;
        let expires_at = (ttl_secs != 0).then_some(created_at.saturating_add(ttl_secs as i64));
        let _ = now;
        self.storage.conn.execute(
            "INSERT OR IGNORE INTO tree_messages
             (group_id,message_id,sender_member_id,sequence,created_at,edited_at,expires_at,view_once,deleted,body)
             VALUES (?1,?2,?3,?4,?5,NULL,?6,?7,?8,?9)",
            params![group_id, id.as_bytes().as_slice(), sender.as_slice(), seq as i64, created_at, expires_at, view_once as i64, deleted as i64, body],
        ).map_err(local_err)?;
        Ok(())
    }

    pub(crate) fn mark_message_edited(
        &self,
        group_id: &[u8],
        id: &MessageId,
        edited_at: i64,
        body: &[u8],
    ) -> Result<(), TreeError> {
        self.storage.conn.execute(
            "UPDATE tree_messages SET body=?3, edited_at=?4, deleted=0
             WHERE group_id=?1 AND message_id=?2",
            params![group_id, id.as_bytes().as_slice(), body, edited_at],
        ).map_err(local_err)?;
        Ok(())
    }

    pub(crate) fn mark_message_deleted(
        &self,
        group_id: &[u8],
        id: &MessageId,
    ) -> Result<(), TreeError> {
        self.storage.conn.execute(
            "UPDATE tree_messages SET deleted=1 WHERE group_id=?1 AND message_id=?2",
            params![group_id, id.as_bytes().as_slice()],
        ).map_err(local_err)?;
        Ok(())
    }

    pub(crate) fn get_message(
        &self,
        group_id: &[u8],
        id: &MessageId,
    ) -> Result<Option<StoredMessage>, TreeError> {
        let row = self.storage.conn.query_row(
            "SELECT group_id,message_id,sender_member_id,sequence,created_at,edited_at,expires_at,view_once,deleted,body
             FROM tree_messages WHERE group_id=?1 AND message_id=?2",
            params![group_id, id.as_bytes().as_slice()],
            |r| {
                let group: Vec<u8> = r.get(0)?;
                let msg: Vec<u8> = r.get(1)?;
                let sender: Vec<u8> = r.get(2)?;
                Ok((group, msg, sender, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?, r.get(5)?, r.get(6)?, r.get::<_, i64>(7)?, r.get::<_, i64>(8)?, r.get(9)?))
            },
        ).optional().map_err(local_err)?;

        row.map(|(group, msg, sender, sequence, created_at, edited_at, expires_at, view_once, deleted, body)| {
            Ok(StoredMessage {
                group_id: group,
                message_id: MessageId(parse_id(msg, "message_id")?),
                sender: parse_id(sender, "sender_member_id")?,
                sequence: sequence.try_into().map_err(|_| TreeError::Storage("negative message sequence".into()))?,
                created_at,
                edited_at,
                expires_at,
                view_once: view_once != 0,
                deleted: deleted != 0,
                body,
            })
        }).transpose()
    }

    pub(crate) fn list_messages(
        &self,
        group_id: &[u8],
        limit: u32,
    ) -> Result<Vec<StoredMessage>, TreeError> {
        let rows = {
            let mut stmt = self.storage.conn.prepare(
                "SELECT group_id,message_id,sender_member_id,sequence,created_at,edited_at,expires_at,view_once,deleted,body
                 FROM tree_messages WHERE group_id=?1 ORDER BY sequence,created_at LIMIT ?2",
            ).map_err(local_err)?;
            stmt.query_map(params![group_id, limit.min(5000) as i64], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, Vec<u8>>(9)?,
                ))
            }).map_err(local_err)?
                .collect::<Result<Vec<_>, _>>().map_err(local_err)?
        };

        rows.into_iter().map(|(group,msg,sender,sequence,created_at,edited_at,expires_at,view_once,deleted,body)| {
            Ok(StoredMessage {
                group_id: group,
                message_id: MessageId(parse_id(msg, "message_id")?),
                sender: parse_id(sender, "sender_member_id")?,
                sequence: sequence.try_into().map_err(|_| TreeError::Storage("negative message sequence".into()))?,
                created_at,
                edited_at,
                expires_at,
                view_once: view_once != 0,
                deleted: deleted != 0,
                body,
            })
        }).collect()
    }

    pub(crate) fn enqueue_outbox(
        &self,
        local_id: [u8; 16],
        group_id: &[u8],
        message_id: Option<MessageId>,
        kind: u8,
        envelope: &[u8],
        now: i64,
    ) -> Result<(), TreeError> {
        self.storage.conn.execute(
            "INSERT INTO tree_outbox
             (local_id,group_id,message_id,kind,envelope,state,attempts,next_retry_at,created_at,last_error_code,server_id)
             VALUES (?1,?2,?3,?4,?5,'queued',0,?6,?6,NULL,NULL)",
            params![local_id.as_slice(), group_id, message_id.map(|m| m.as_bytes().as_slice()), kind as i64, envelope, now],
        ).map_err(local_err)?;
        Ok(())
    }

    pub(crate) fn due_outbox(&self, now: i64, limit: u32) -> Result<Vec<OutboxItem>, TreeError> {
        let mut stmt = self.storage.conn.prepare(
            "SELECT local_id,group_id,message_id,kind,envelope,state,attempts,next_retry_at,created_at,last_error_code,server_id
             FROM tree_outbox WHERE state IN ('queued','retry') AND next_retry_at<=?1
             ORDER BY created_at LIMIT ?2",
        ).map_err(local_err)?;
        let rows = stmt.query_map(params![now, limit.min(1000) as i64], |r| {
            Ok((
                r.get::<_,Vec<u8>>(0)?, r.get::<_,Vec<u8>>(1)?, r.get::<_,Option<Vec<u8>>>(2)?,
                r.get::<_,i64>(3)?, r.get::<_,Vec<u8>>(4)?, r.get::<_,String>(5)?,
                r.get::<_,i64>(6)?, r.get::<_,i64>(7)?, r.get::<_,i64>(8)?,
                r.get::<_,Option<String>>(9)?, r.get::<_,Option<String>>(10)?
            ))
        }).map_err(local_err)?;

        rows.map(|row| -> Result<OutboxItem, TreeError> {
            let (local,group,msg,kind,envelope,state,attempts,next_retry_at,created_at,last_error_code,server_id)=row.map_err(local_err)?;
            Ok(OutboxItem{
                local_id:parse_id(local,"outbox local_id")?,
                group_id:group,
                message_id:msg.map(|v|parse_id(v,"outbox message_id")).transpose()?.map(MessageId),
                kind:kind.try_into().map_err(|_|TreeError::Storage("invalid outbox kind".into()))?,
                envelope,
                state:OutboxState::parse(&state)?,
                attempts:attempts.try_into().map_err(|_|TreeError::Storage("invalid outbox attempts".into()))?,
                next_retry_at,
                created_at,
                last_error_code,
                server_id,
            })
        }).collect()
    }

    pub(crate) fn mark_outbox_sending(&self, local_id: &[u8;16], now:i64)->Result<(),TreeError>{
        self.storage.conn.execute("UPDATE tree_outbox SET state='sending', attempts=attempts+1, last_error_code=NULL WHERE local_id=?1 AND state IN ('queued','retry')",params![local_id.as_slice()]).map_err(local_err)?; Ok(())
    }

    pub(crate) fn mark_outbox_sent(&self, local_id:&[u8;16], server_id:&str)->Result<(),TreeError>{
        self.storage.conn.execute("UPDATE tree_outbox SET state='sent',server_id=?2 WHERE local_id=?1",params![local_id.as_slice(),server_id]).map_err(local_err)?; Ok(())
    }

    pub(crate) fn mark_outbox_retry(&self, local_id:&[u8;16], code:&str, next_retry_at:i64)->Result<(),TreeError>{
        self.storage.conn.execute("UPDATE tree_outbox SET state='retry',last_error_code=?2,next_retry_at=?3 WHERE local_id=?1",params![local_id.as_slice(),code,next_retry_at]).map_err(local_err)?; Ok(())
    }

    pub(crate) fn mark_outbox_failed(&self, local_id:&[u8;16], code:&str)->Result<(),TreeError>{
        self.storage.conn.execute("UPDATE tree_outbox SET state='failed',last_error_code=?2 WHERE local_id=?1",params![local_id.as_slice(),code]).map_err(local_err)?; Ok(())
    }

    pub(crate) fn outbox_count(&self)->Result<u64,TreeError>{
        self.storage.conn.query_row("SELECT COUNT(*) FROM tree_outbox WHERE state NOT IN ('sent','cancelled','superseded')",[],|r|r.get::<_,i64>(0)).map(|n|n.max(0) as u64).map_err(local_err)
    }

    pub(crate) fn message_count(&self,group_id:&[u8])->Result<u64,TreeError>{
        self.storage.conn.query_row("SELECT COUNT(*) FROM tree_messages WHERE group_id=?1",params![group_id],|r|r.get::<_,i64>(0)).map(|n|n.max(0) as u64).map_err(local_err)
    }

    pub(crate) fn purge_local_expired(&self,now:i64)->Result<u64,TreeError>{
        let n=self.storage.conn.execute("DELETE FROM tree_messages WHERE expires_at IS NOT NULL AND expires_at<=?1",params![now]).map_err(local_err)?;
        Ok(n as u64)
    }
}
