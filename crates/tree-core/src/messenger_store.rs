//! Durable messenger repository backed by the device's SQLCipher database.
//!
//! This layer intentionally stores plaintext only inside the already encrypted
//! local profile. It is not part of the network protocol.

use rusqlite::params;

use crate::{
    error::TreeError,
    message::{MessageEvent, MessageId},
};

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

fn storage_err(e: impl std::fmt::Display) -> TreeError {
    TreeError::Storage(e.to_string())
}

fn parse_id<const N: usize>(bytes: Vec<u8>, what: &str) -> Result<[u8; N], TreeError> {
    bytes
        .try_into()
        .map_err(|_| TreeError::Storage(format!("{what} has invalid length")))
}

impl crate::storage::StoredProvider {
    pub(crate) fn store_message_event(
        &self,
        group_id: &[u8],
        event: &MessageEvent,
        sender: &[u8; 32],
    ) -> Result<(), TreeError> {
        match event {
            MessageEvent::New {
                id,
                seq,
                sent_at,
                ttl_secs,
                view_once,
                body,
                ..
            } => {
                let expires_at =
                    (*ttl_secs != 0).then_some(sent_at.saturating_add(*ttl_secs as i64));
                self.connection()
                    .execute(
                        "INSERT OR IGNORE INTO tree_messages \
                         (group_id,message_id,sender_member_id,sequence,created_at,expires_at,view_once,deleted,body) \
                         VALUES (?1,?2,?3,?4,?5,?6,?7,0,?8)",
                        params![
                            group_id,
                            id.as_bytes().as_slice(),
                            sender.as_slice(),
                            *seq as i64,
                            *sent_at,
                            expires_at,
                            *view_once as i64,
                            body,
                        ],
                    )
                    .map_err(storage_err)?;
            }
            MessageEvent::Edit {
                target,
                edited_at,
                body,
                ..
            } => {
                self.mark_message_edited(group_id, target, *edited_at, body)?;
            }
            MessageEvent::Delete { target, .. } => {
                self.mark_message_deleted(group_id, target)?;
            }
            MessageEvent::Reaction { .. }
            | MessageEvent::Read { .. }
            | MessageEvent::Typing { .. } => {}
        }
        Ok(())
    }

    fn mark_message_edited(
        &self,
        group_id: &[u8],
        id: &MessageId,
        edited_at: i64,
        body: &[u8],
    ) -> Result<(), TreeError> {
        self.connection()
            .execute(
                "UPDATE tree_messages SET body=?3, edited_at=?4, deleted=0 \
                 WHERE group_id=?1 AND message_id=?2",
                params![group_id, id.as_bytes().as_slice(), body, edited_at],
            )
            .map_err(storage_err)?;
        Ok(())
    }

    fn mark_message_deleted(&self, group_id: &[u8], id: &MessageId) -> Result<(), TreeError> {
        self.connection()
            .execute(
                "UPDATE tree_messages SET deleted=1 WHERE group_id=?1 AND message_id=?2",
                params![group_id, id.as_bytes().as_slice()],
            )
            .map_err(storage_err)?;
        Ok(())
    }

    pub(crate) fn list_messages(
        &self,
        group_id: &[u8],
        limit: u32,
    ) -> Result<Vec<StoredMessage>, TreeError> {
        let mut stmt = self
            .connection()
            .prepare(
                "SELECT group_id,message_id,sender_member_id,sequence,created_at,edited_at,\
                 expires_at,view_once,deleted,body \
                 FROM tree_messages WHERE group_id=?1 \
                 ORDER BY sequence,created_at LIMIT ?2",
            )
            .map_err(storage_err)?;
        let mapped = stmt
            .query_map(params![group_id, i64::from(limit.min(5000))], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            })
            .map_err(storage_err)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row.map_err(storage_err)?);
        }

        rows.into_iter()
            .map(
                |(
                    group,
                    message,
                    sender,
                    sequence,
                    created_at,
                    edited_at,
                    expires_at,
                    view_once,
                    deleted,
                    body,
                )| {
                    Ok(StoredMessage {
                        group_id: group,
                        message_id: MessageId(parse_id(message, "message_id")?),
                        sender: parse_id(sender, "sender_member_id")?,
                        sequence: sequence
                            .try_into()
                            .map_err(|_| TreeError::Storage("negative message sequence".into()))?,
                        created_at,
                        edited_at,
                        expires_at,
                        view_once: view_once != 0,
                        deleted: deleted != 0,
                        body,
                    })
                },
            )
            .collect()
    }

    pub(crate) fn due_outbox(&self, now: i64, limit: u32) -> Result<Vec<OutboxItem>, TreeError> {
        let mut stmt = self.connection().prepare(
            "SELECT local_id,group_id,message_id,kind,envelope,state,attempts,next_retry_at,created_at,last_error_code,server_id
             FROM tree_outbox
             WHERE (state='queued' OR state='retry') AND next_retry_at <= ?1
             ORDER BY created_at, local_id LIMIT ?2",
        ).map_err(storage_err)?;
        let rows = stmt
            .query_map(params![now, i64::from(limit.min(1000))], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            })
            .map_err(storage_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (
                local,
                group,
                message,
                kind,
                envelope,
                state,
                attempts,
                next_retry,
                created,
                error,
                server,
            ) = row.map_err(storage_err)?;
            let attempts = u32::try_from(attempts)
                .map_err(|_| TreeError::Storage("negative outbox attempts".into()))?;
            let kind =
                u8::try_from(kind).map_err(|_| TreeError::Storage("invalid outbox kind".into()))?;
            out.push(OutboxItem {
                local_id: parse_id(local, "outbox local_id")?,
                group_id: group,
                message_id: message
                    .map(|v| parse_id(v, "outbox message_id").map(MessageId))
                    .transpose()?,
                kind,
                envelope,
                state: OutboxState::parse(&state)?,
                attempts,
                next_retry_at: next_retry,
                created_at: created,
                last_error_code: error,
                server_id: server,
            });
        }
        Ok(out)
    }

    pub(crate) fn mark_outbox_sending(
        &self,
        local_id: [u8; 16],
        now: i64,
    ) -> Result<bool, TreeError> {
        let changed = self
            .connection()
            .execute(
                "UPDATE tree_outbox SET state='sending', attempts=attempts+1
                 WHERE local_id=?1 AND (state='queued' OR (state='retry' AND next_retry_at <= ?2))",
                params![local_id.as_slice(), now],
            )
            .map_err(storage_err)?;
        Ok(changed == 1)
    }

    pub(crate) fn mark_outbox_sent(
        &self,
        local_id: [u8; 16],
        server_id: &str,
    ) -> Result<(), TreeError> {
        self.connection()
            .execute(
                "UPDATE tree_outbox SET state='sent', server_id=?2, last_error_code=NULL
                 WHERE local_id=?1 AND state='sending'",
                params![local_id.as_slice(), server_id],
            )
            .map_err(storage_err)?;
        Ok(())
    }

    pub(crate) fn mark_outbox_retry(
        &self,
        local_id: [u8; 16],
        error_code: &str,
        next_retry_at: i64,
    ) -> Result<(), TreeError> {
        self.connection()
            .execute(
                "UPDATE tree_outbox SET state='retry', last_error_code=?2, next_retry_at=?3
                 WHERE local_id=?1 AND state='sending'",
                params![local_id.as_slice(), error_code, next_retry_at],
            )
            .map_err(storage_err)?;
        Ok(())
    }

    pub(crate) fn mark_outbox_failed(
        &self,
        local_id: [u8; 16],
        error_code: &str,
    ) -> Result<(), TreeError> {
        self.connection()
            .execute(
                "UPDATE tree_outbox SET state='failed', last_error_code=?2
                 WHERE local_id=?1 AND state='sending'",
                params![local_id.as_slice(), error_code],
            )
            .map_err(storage_err)?;
        Ok(())
    }

    pub(crate) fn recover_sending_outbox(&self, now: i64) -> Result<u32, TreeError> {
        let changed = self
            .connection()
            .execute(
                "UPDATE tree_outbox SET state='retry', next_retry_at=?1,
                        last_error_code='CLIENT_RESTART'
                 WHERE state='sending'",
                params![now],
            )
            .map_err(storage_err)?;
        u32::try_from(changed)
            .map_err(|_| TreeError::Storage("outbox recovery count overflow".into()))
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
        self.connection()
            .execute(
                "INSERT OR IGNORE INTO tree_outbox \
                 (local_id,group_id,message_id,kind,envelope,state,attempts,next_retry_at,created_at) \
                 VALUES (?1,?2,?3,?4,?5,'queued',0,?6,?6)",
                params![
                    local_id.as_slice(),
                    group_id,
                    message_id.as_ref().map(|m| m.as_bytes().as_slice()),
                    kind as i64,
                    envelope,
                    now,
                ],
            )
            .map_err(storage_err)?;
        Ok(())
    }
}
