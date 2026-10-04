//! E2E bot-lane protocol.
//!
//! In privacy mode a bot is not a member of the main conversation. Clients
//! create a separate MLS group ("lane") containing the conversation members
//! and the bot device, then forward only bot-addressed events into that lane.
//! The server only sees another encrypted MLS group.
//!
//! This module defines the lane identifier and the allowlisted event payload;
//! it does not decide UI presentation and does not execute bot code.

use sha2::{Digest, Sha256};

use crate::error::TreeError;
use crate::message::MessageId;

const MAGIC: &[u8] = b"TREEBOTLANE\x01";
const MAX_BOT_ID: usize = 64;
const MAX_COMMAND: usize = 256;
const MAX_TEXT: usize = 4096;
const MAX_CALLBACK_ID: usize = 128;
const MAX_CALLBACK_DATA: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BotLaneMode {
    Privacy,
    FullAccess,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BotLaneDescriptor {
    pub bot_id: String,
    pub source_group_id: Vec<u8>,
    pub lane_group_id: Vec<u8>,
    pub mode: BotLaneMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BotLaneEvent {
    Command {
        message_id: MessageId,
        command: String,
        text: String,
    },
    Mention {
        message_id: MessageId,
        text: String,
    },
    Reply {
        message_id: MessageId,
        text: String,
    },
    Button {
        callback_id: String,
        data: Vec<u8>,
    },
}

impl BotLaneDescriptor {
    /// Stable lane group id derived from the source group and bot id.
    /// The id is public metadata; the lane contents remain E2E encrypted.
    pub fn derive_lane_group_id(source_group_id: &[u8], bot_id: &str) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"tree/bot-lane-group/v1");
        h.update((source_group_id.len() as u32).to_be_bytes());
        h.update(source_group_id);
        h.update(bot_id.as_bytes());
        h.finalize()[..16].to_vec()
    }

    pub fn new(
        bot_id: &str,
        source_group_id: Vec<u8>,
        mode: BotLaneMode,
    ) -> Result<Self, TreeError> {
        if bot_id.is_empty() || bot_id.len() > MAX_BOT_ID {
            return Err(TreeError::Group("bot id is invalid".into()));
        }
        if source_group_id.is_empty() || source_group_id.len() > 255 {
            return Err(TreeError::Group("source group id is invalid".into()));
        }
        let lane_group_id = Self::derive_lane_group_id(&source_group_id, bot_id);
        Ok(Self {
            bot_id: bot_id.to_owned(),
            source_group_id,
            lane_group_id,
            mode,
        })
    }

    pub fn is_privacy_mode(&self) -> bool {
        matches!(self.mode, BotLaneMode::Privacy)
    }
}

impl BotLaneEvent {
    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(MAGIC);
        match self {
            Self::Command {
                message_id,
                command,
                text,
            } => {
                validate_command(command)?;
                validate_text(text)?;
                out.push(1);
                out.extend_from_slice(message_id.as_bytes());
                put_string(&mut out, command, MAX_COMMAND)?;
                put_string(&mut out, text, MAX_TEXT)?;
            }
            Self::Mention { message_id, text } => {
                validate_text(text)?;
                out.push(2);
                out.extend_from_slice(message_id.as_bytes());
                put_string(&mut out, text, MAX_TEXT)?;
            }
            Self::Reply { message_id, text } => {
                validate_text(text)?;
                out.push(3);
                out.extend_from_slice(message_id.as_bytes());
                put_string(&mut out, text, MAX_TEXT)?;
            }
            Self::Button { callback_id, data } => {
                if callback_id.is_empty() || callback_id.len() > MAX_CALLBACK_ID {
                    return Err(TreeError::Group("callback id is invalid".into()));
                }
                if data.len() > MAX_CALLBACK_DATA {
                    return Err(TreeError::Group("callback data is too large".into()));
                }
                out.push(4);
                put_string(&mut out, callback_id, MAX_CALLBACK_ID)?;
                put_bytes(&mut out, data)?;
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        if !bytes.starts_with(MAGIC) {
            return Err(TreeError::Malformed("not a Tree bot-lane event".into()));
        }
        let mut r = Reader(&bytes[MAGIC.len()..]);
        let event = match r.u8()? {
            1 => Self::Command {
                message_id: MessageId(r.array()?),
                command: r.string(MAX_COMMAND)?,
                text: r.string(MAX_TEXT)?,
            },
            2 => Self::Mention {
                message_id: MessageId(r.array()?),
                text: r.string(MAX_TEXT)?,
            },
            3 => Self::Reply {
                message_id: MessageId(r.array()?),
                text: r.string(MAX_TEXT)?,
            },
            4 => Self::Button {
                callback_id: r.string(MAX_CALLBACK_ID)?,
                data: r.bytes(MAX_CALLBACK_DATA)?,
            },
            _ => return Err(TreeError::Malformed("unknown bot-lane event".into())),
        };
        if !r.0.is_empty() {
            return Err(TreeError::Malformed("trailing bot-lane bytes".into()));
        }
        match &event {
            Self::Command { command, text, .. } => {
                validate_command(command)?;
                validate_text(text)?;
            }
            Self::Mention { text, .. } | Self::Reply { text, .. } => validate_text(text)?,
            Self::Button { callback_id, data } => {
                if callback_id.is_empty() || callback_id.len() > MAX_CALLBACK_ID {
                    return Err(TreeError::Malformed("callback id is invalid".into()));
                }
                if data.len() > MAX_CALLBACK_DATA {
                    return Err(TreeError::Malformed("callback data is too large".into()));
                }
            }
        }
        Ok(event)
    }

    /// Events a privacy-mode lane may carry. Full-access bots are handled by
    /// the normal conversation path and do not need this allowlist.
    pub fn allowed_in_privacy_mode(&self) -> bool {
        matches!(
            self,
            Self::Command { .. } | Self::Mention { .. } | Self::Reply { .. } | Self::Button { .. }
        )
    }
}

fn validate_command(command: &str) -> Result<(), TreeError> {
    if command.is_empty()
        || command.len() > MAX_COMMAND
        || !command.starts_with('/')
        || command.chars().any(char::is_control)
    {
        return Err(TreeError::Group("invalid bot command".into()));
    }
    Ok(())
}

fn validate_text(text: &str) -> Result<(), TreeError> {
    if text.len() > MAX_TEXT || text.chars().any(char::is_control) {
        return Err(TreeError::Group(
            "bot-lane text is too large or contains controls".into(),
        ));
    }
    Ok(())
}

fn put_string(out: &mut Vec<u8>, value: &str, max: usize) -> Result<(), TreeError> {
    if value.len() > max || value.len() > u16::MAX as usize {
        return Err(TreeError::Group("bot-lane string is too large".into()));
    }
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), TreeError> {
    if value.len() > MAX_CALLBACK_DATA || value.len() > u32::MAX as usize {
        return Err(TreeError::Group("bot-lane bytes are too large".into()));
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], TreeError> {
        if self.0.len() < n {
            return Err(TreeError::Malformed("truncated bot-lane event".into()));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, TreeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TreeError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("length checked"),
        ))
    }

    fn u32(&mut self) -> Result<u32, TreeError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("length checked"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TreeError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    fn string(&mut self, max: usize) -> Result<String, TreeError> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(TreeError::Malformed("bot-lane string exceeds limit".into()));
        }
        String::from_utf8(self.take(n)?.to_vec())
            .map_err(|_| TreeError::Malformed("bot-lane string is not UTF-8".into()))
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, TreeError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(TreeError::Malformed("bot-lane bytes exceed limit".into()));
        }
        Ok(self.take(n)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_id_is_stable_and_bot_specific() {
        let a = BotLaneDescriptor::derive_lane_group_id(b"group", "bot-a");
        let b = BotLaneDescriptor::derive_lane_group_id(b"group", "bot-a");
        let c = BotLaneDescriptor::derive_lane_group_id(b"group", "bot-b");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn privacy_lane_allowlist_round_trips() {
        let events = [
            BotLaneEvent::Command {
                message_id: MessageId([1; 16]),
                command: "/start".into(),
                text: "hello".into(),
            },
            BotLaneEvent::Mention {
                message_id: MessageId([2; 16]),
                text: "@bot hello".into(),
            },
            BotLaneEvent::Reply {
                message_id: MessageId([3; 16]),
                text: "reply".into(),
            },
            BotLaneEvent::Button {
                callback_id: "cb1".into(),
                data: b"answer".to_vec(),
            },
        ];
        for event in events {
            let encoded = event.encode().unwrap();
            let decoded = BotLaneEvent::decode(&encoded).unwrap();
            assert_eq!(decoded, event);
            assert!(decoded.allowed_in_privacy_mode());
        }
    }

    #[test]
    fn malformed_and_disallowed_commands_are_rejected() {
        assert!(BotLaneEvent::decode(b"TREEBOTLANE\x01").is_err());
        assert!(BotLaneEvent::Command {
            message_id: MessageId([1; 16]),
            command: "start".into(),
            text: "".into(),
        }
        .encode()
        .is_err());
    }
}
