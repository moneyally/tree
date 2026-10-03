//! Structured E2E chat-message protocol.
//!
//! Every value in this module is carried inside an MLS application message.
//! The server sees only the outer Tree envelope and cannot inspect any of
//! these fields.
//!
//! The protocol is deliberately small and versioned. Message authors are not
//! serialized here: MLS authenticates the sender. A per-sender sequence
//! number prevents replay and stale edit/delete/reaction operations.

use getrandom::getrandom;

use crate::error::TreeError;

pub(crate) const MESSAGE_MAGIC: &[u8] = b"TREEMSG\x01";
const MAX_BODY: usize = 512 * 1024;
const MAX_REACTION: usize = 64;
const MAX_PREVIEW: usize = 16 * 1024;

pub const DEFAULT_EDIT_WINDOW_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub [u8; 16]);

impl MessageId {
    pub fn generate() -> Result<Self, TreeError> {
        let mut id = [0u8; 16];
        getrandom(&mut id)
            .map_err(|e| TreeError::Identity(format!("OS randomness unavailable: {e}")))?;
        Ok(Self(id))
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    New = 1,
    Edit = 2,
    Delete = 3,
    Reaction = 4,
    Read = 5,
    Typing = 6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageEvent {
    New {
        id: MessageId,
        seq: u64,
        sent_at: i64,
        ttl_secs: u32,
        view_once: bool,
        body: Vec<u8>,
        preview: Option<Vec<u8>>,
    },
    Edit {
        target: MessageId,
        seq: u64,
        edited_at: i64,
        body: Vec<u8>,
    },
    Delete {
        target: MessageId,
        seq: u64,
        deleted_at: i64,
    },
    Reaction {
        target: MessageId,
        seq: u64,
        reaction: String,
        add: bool,
    },
    Read {
        target: MessageId,
        seq: u64,
        read_at: i64,
    },
    Typing {
        seq: u64,
        active: bool,
    },
}

impl MessageEvent {
    pub fn kind(&self) -> MessageKind {
        match self {
            Self::New { .. } => MessageKind::New,
            Self::Edit { .. } => MessageKind::Edit,
            Self::Delete { .. } => MessageKind::Delete,
            Self::Reaction { .. } => MessageKind::Reaction,
            Self::Read { .. } => MessageKind::Read,
            Self::Typing { .. } => MessageKind::Typing,
        }
    }

    pub fn seq(&self) -> u64 {
        match self {
            Self::New { seq, .. }
            | Self::Edit { seq, .. }
            | Self::Delete { seq, .. }
            | Self::Reaction { seq, .. }
            | Self::Read { seq, .. }
            | Self::Typing { seq, .. } => *seq,
        }
    }

    pub fn target(&self) -> Option<MessageId> {
        match self {
            Self::New { id, .. } => Some(*id),
            Self::Edit { target, .. }
            | Self::Delete { target, .. }
            | Self::Reaction { target, .. }
            | Self::Read { target, .. } => Some(*target),
            Self::Typing { .. } => None,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(MAGIC);
        out.push(self.kind() as u8);
        out.extend_from_slice(&self.seq().to_be_bytes());

        match self {
            Self::New {
                id,
                sent_at,
                ttl_secs,
                view_once,
                body,
                preview,
                ..
            } => {
                check_body(body)?;
                if let Some(preview) = preview {
                    if preview.len() > MAX_PREVIEW {
                        return Err(TreeError::Group("message preview is too large".into()));
                    }
                }
                out.extend_from_slice(id.as_bytes());
                out.extend_from_slice(&sent_at.to_be_bytes());
                out.extend_from_slice(&ttl_secs.to_be_bytes());
                out.push(*view_once as u8);
                put_bytes_u32(&mut out, body);
                match preview {
                    None => out.push(0),
                    Some(preview) => {
                        out.push(1);
                        put_bytes_u32(&mut out, preview);
                    }
                }
            }
            Self::Edit {
                target,
                edited_at,
                body,
                ..
            } => {
                check_body(body)?;
                out.extend_from_slice(target.as_bytes());
                out.extend_from_slice(&edited_at.to_be_bytes());
                put_bytes_u32(&mut out, body);
            }
            Self::Delete {
                target, deleted_at, ..
            } => {
                out.extend_from_slice(target.as_bytes());
                out.extend_from_slice(&deleted_at.to_be_bytes());
            }
            Self::Reaction {
                target,
                reaction,
                add,
                ..
            } => {
                if reaction.is_empty() || reaction.len() > MAX_REACTION {
                    return Err(TreeError::Group("reaction length is invalid".into()));
                }
                if !reaction.chars().all(|c| !c.is_control()) {
                    return Err(TreeError::Group("reaction contains control characters".into()));
                }
                out.extend_from_slice(target.as_bytes());
                out.push(*add as u8);
                put_bytes_u8(&mut out, reaction.as_bytes())?;
            }
            Self::Read { target, read_at, .. } => {
                out.extend_from_slice(target.as_bytes());
                out.extend_from_slice(&read_at.to_be_bytes());
            }
            Self::Typing { active, .. } => out.push(*active as u8),
        }

        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        if !bytes.starts_with(MESSAGE_MAGIC) {
            return Err(TreeError::Malformed("not a Tree message".into()));
        }
        let mut r = Reader(&bytes[MESSAGE_MAGIC.len()..]);
        let kind = match r.u8()? {
            1 => MessageKind::New,
            2 => MessageKind::Edit,
            3 => MessageKind::Delete,
            4 => MessageKind::Reaction,
            5 => MessageKind::Read,
            6 => MessageKind::Typing,
            _ => return Err(TreeError::Malformed("unknown Tree message kind".into())),
        };
        let seq = r.u64()?;

        let event = match kind {
            MessageKind::New => {
                let id = MessageId(r.array()?);
                let sent_at = r.i64()?;
                let ttl_secs = r.u32()?;
                let view_once = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(TreeError::Malformed("invalid view-once flag".into())),
                };
                let body = r.bytes(MAX_BODY)?;
                let preview = match r.u8()? {
                    0 => None,
                    1 => Some(r.bytes(MAX_PREVIEW)?),
                    _ => return Err(TreeError::Malformed("invalid preview flag".into())),
                };
                Self::New {
                    id,
                    seq,
                    sent_at,
                    ttl_secs,
                    view_once,
                    body,
                    preview,
                }
            }
            MessageKind::Edit => {
                let target = MessageId(r.array()?);
                let edited_at = r.i64()?;
                let body = r.bytes(MAX_BODY)?;
                Self::Edit {
                    target,
                    seq,
                    edited_at,
                    body,
                }
            }
            MessageKind::Delete => {
                let target = MessageId(r.array()?);
                let deleted_at = r.i64()?;
                Self::Delete {
                    target,
                    seq,
                    deleted_at,
                }
            }
            MessageKind::Reaction => {
                let target = MessageId(r.array()?);
                let add = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(TreeError::Malformed("invalid reaction flag".into())),
                };
                let reaction = String::from_utf8(r.bytes(MAX_REACTION)?)
                    .map_err(|_| TreeError::Malformed("reaction is not UTF-8".into()))?;
                Self::Reaction {
                    target,
                    seq,
                    reaction,
                    add,
                }
            }
            MessageKind::Read => {
                let target = MessageId(r.array()?);
                let read_at = r.i64()?;
                Self::Read {
                    target,
                    seq,
                    read_at,
                }
            }
            MessageKind::Typing => {
                let active = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(TreeError::Malformed("invalid typing flag".into())),
                };
                Self::Typing { seq, active }
            }
        };

        if !r.0.is_empty() {
            return Err(TreeError::Malformed("trailing bytes in Tree message".into()));
        }
        Ok(event)
    }
}

fn check_body(body: &[u8]) -> Result<(), TreeError> {
    if body.len() > MAX_BODY {
        return Err(TreeError::Group("message body is too large".into()));
    }
    if body.starts_with(MAGIC) {
        return Err(TreeError::Rejected(
            "structured Tree message uses a reserved namespace".into(),
        ));
    }
    Ok(())
}

fn put_bytes_u32(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn put_bytes_u8(out: &mut Vec<u8>, value: &[u8]) -> Result<(), TreeError> {
    if value.len() > u8::MAX as usize {
        return Err(TreeError::Group("message field is too large".into()));
    }
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    Ok(())
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], TreeError> {
        if self.0.len() < n {
            return Err(TreeError::Malformed("truncated Tree message".into()));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, TreeError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, TreeError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("length checked"),
        ))
    }

    fn u64(&mut self) -> Result<u64, TreeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("length checked"),
        ))
    }

    fn i64(&mut self) -> Result<i64, TreeError> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("length checked"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TreeError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, TreeError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(TreeError::Group("message field exceeds limit".into()));
        }
        Ok(self.take(n)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_event_types_round_trip() {
        let id = MessageId::generate().unwrap();
        let target = MessageId::generate().unwrap();
        let events = [
            MessageEvent::New {
                id,
                seq: 1,
                sent_at: 100,
                ttl_secs: 86400,
                view_once: false,
                body: b"hello".to_vec(),
                preview: Some(b"preview".to_vec()),
            },
            MessageEvent::Edit {
                target,
                seq: 2,
                edited_at: 101,
                body: b"edited".to_vec(),
            },
            MessageEvent::Delete {
                target,
                seq: 3,
                deleted_at: 102,
            },
            MessageEvent::Reaction {
                target,
                seq: 4,
                reaction: "thumbsup".into(),
                add: true,
            },
            MessageEvent::Read {
                target,
                seq: 5,
                read_at: 103,
            },
            MessageEvent::Typing {
                seq: 6,
                active: true,
            },
        ];

        for event in events {
            let encoded = event.encode().unwrap();
            assert_eq!(MessageEvent::decode(&encoded).unwrap(), event);
        }
    }

    #[test]
    fn malformed_and_oversized_inputs_are_rejected() {
        assert!(MessageEvent::decode(b"TREEMSG\x01").is_err());

        let too_large = MessageEvent::New {
            id: MessageId([1; 16]),
            seq: 1,
            sent_at: 0,
            ttl_secs: 0,
            view_once: false,
            body: vec![0u8; MAX_BODY + 1],
            preview: None,
        };
        assert!(too_large.encode().is_err());

        let mut encoded = MessageEvent::Typing {
            seq: 1,
            active: true,
        }
        .encode()
        .unwrap();
        encoded[0] = b'X';
        assert!(MessageEvent::decode(&encoded).is_err());
    }

    #[test]
    fn message_ids_are_128_bit_and_render_stably() {
        let id = MessageId([0xab; 16]);
        assert_eq!(id.to_hex(), "abababababababababababababababab");
    }
}
