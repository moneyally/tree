//! Private channels (Wave 4, PROTOCOL.md 6.11.2, APP_PROTOCOL.md 10.2):
//! end-to-end encrypted, up to 1,000 members, only admins post.
//!
//! A private channel is an ordinary MLS group whose settings carry the
//! `channel` flag, set when it is created and never changed (every device
//! refuses a commit that changes it). The rule "only admins post" is
//! enforced by the sending device and again by every receiving device,
//! judged by the MLS-authenticated sender, never by anything in the payload:
//! a modified client's post from a non-admin is dropped by everyone.
//!
//! | Setting | Default | Effect |
//! | --- | --- | --- |
//! | `channel.comments` | released | members may comment on posts (a text with `re` naming a post); released: comments are dropped |
//! | `channel.signatures` | released | the apps show the posting admin's name; released: posts show the channel's name |
//!
//! What members may send besides comments: reactions, votes and event
//! answers (responses, not posts), edits and deletions of their own
//! comments, and the group's plumbing (names, rosters, receipts, leaving).
//! Signatures are a display rule: every member's device still knows which
//! admin device sent a post (MLS authenticates the sender).

use tree_core::group_settings::GroupSettings;
use tree_core::storage::messages::StoredMessage;
use tree_core::MemberId;

use crate::groups::is_speech;
use crate::payload::Payload;
use crate::{Error, Session};

/// Stored text data with the message it answers (`re`).
pub(crate) fn with_re(data: Option<Vec<u8>>, re: Option<&str>) -> Option<Vec<u8>> {
    let Some(re) = re else { return data };
    let mut v: serde_json::Value = data.as_deref().and_then(|d| serde_json::from_slice(d).ok()).unwrap_or_else(|| serde_json::json!({}));
    v["re"] = re.into();
    Some(serde_json::to_vec(&v).expect("JSON"))
}

/// The message a stored text answers (a comment's post), if any.
pub fn message_re(m: &StoredMessage) -> Option<String> {
    let v: serde_json::Value = m.data.as_deref().and_then(|d| serde_json::from_slice(d).ok())?;
    v["re"].as_str().map(str::to_string)
}

fn valid_msg_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Why a channel refuses `p` from `from` (`None`: allowed). Groups that
/// are not channels allow everything here.
pub(crate) fn refusal(s: &GroupSettings, from: &MemberId, p: &Payload) -> Option<(&'static str, &'static str)> {
    if !s.channel || s.may_post(from) || !is_speech(p) {
        return None;
    }
    match p {
        Payload::Text { re: Some(_), .. } if s.may_comment(from) => None,
        Payload::Text { re: Some(_), .. } => Some(("LOCKED_BY_CHAT", "comments are released in this channel (channel.comments)")),
        Payload::React { .. }
        | Payload::Vote { .. }
        | Payload::Rsvp { .. }
        | Payload::Edit { .. }
        | Payload::Delete { .. }
        | Payload::Pin { .. }
        | Payload::JoinChat { .. } => None,
        _ => Some(("NOT_ADMIN", "only admins post in a channel")),
    }
}

/// Whether a chat key belongs in this private group's settings:
/// `chat.public_listing` never (a private group is never listed publicly;
/// public spaces are a separate thing on the server), `channel.*` only in a
/// channel.
pub(crate) fn private_key_fits(key: &str, channel: bool) -> Result<(), Error> {
    if key == "chat.public_listing" {
        return Err(Error::Feature("PUBLIC_SPACES_ONLY".into()));
    }
    if key.starts_with("channel.") && !channel {
        return Err(Error::Feature("CHANNELS_ONLY".into()));
    }
    Ok(())
}

impl Session {
    /// Starts a private channel with only this device in it (its admin).
    /// End-to-end encrypted like any group; at most 1,000 members.
    pub fn create_channel(&mut self, name: &str) -> Result<Vec<u8>, Error> {
        let g = self.client.create_channel()?;
        let gid = g.id();
        self.groups.insert(gid.clone(), g);
        self.init_group_maps(&gid)?;
        self.note_refreshed(&gid)?;
        if !name.trim().is_empty() {
            self.set_group_name(&gid, Some(name.trim().to_string()))?;
        }
        Ok(gid)
    }

    /// Is this group a private channel?
    pub fn is_channel(&mut self, gid: &[u8]) -> Result<bool, Error> {
        Ok(self.group_settings(gid)?.channel)
    }

    /// May this device post here (every member of a group; in a channel
    /// its admins)?
    pub fn may_post(&mut self, gid: &[u8]) -> Result<bool, Error> {
        let me = self.member_id();
        Ok(self.group_settings(gid)?.may_post(&me))
    }

    /// May this device comment on posts (a channel with `channel.comments`)?
    pub fn may_comment(&mut self, gid: &[u8]) -> Result<bool, Error> {
        let me = self.member_id();
        Ok(self.group_settings(gid)?.may_comment(&me))
    }

    /// Whether the posting admin's name is shown (`channel.signatures`);
    /// always true outside channels.
    pub fn shows_signatures(&mut self, gid: &[u8]) -> Result<bool, Error> {
        let s = self.group_settings(gid)?;
        Ok(!s.channel || s.feature_on("channel.signatures"))
    }

    /// The name to show as the author of a stored message: the member's
    /// name, or `None` for a channel post while `channel.signatures` is
    /// released (the apps show the channel's name). Comments always show
    /// their author.
    pub fn author_shown(&mut self, gid: &[u8], m: &StoredMessage) -> Result<Option<String>, Error> {
        if !self.shows_signatures(gid)? && message_re(m).is_none() {
            return Ok(None);
        }
        let name = self.names(gid)?.get(&m.sender).cloned();
        Ok(Some(name.unwrap_or_else(|| m.sender.chars().take(8).collect())))
    }

    /// Comments on post `post`, oldest first.
    pub fn comments(&self, gid: &[u8], post: &str) -> Result<Vec<StoredMessage>, Error> {
        Ok(self.history(gid, u32::MAX)?.into_iter().filter(|m| message_re(m).as_deref() == Some(post)).collect())
    }

    /// Comments on `post` (`channel.comments`).
    pub fn comment(&mut self, gid: &[u8], post: &str, text: &str) -> Result<String, Error> {
        let o = crate::TextOptions { reply_to: Some(post.to_string()), ..Default::default() };
        self.send_text_with(gid, text, &o)
    }

    /// The sending side's checks of a reply: an existing message; in a
    /// channel a post (not a comment), and comments must be applied.
    pub(crate) fn check_send_reply(&mut self, gid: &[u8], re: Option<&str>) -> Result<(), Error> {
        let Some(re) = re else { return Ok(()) };
        let m = self.client.message(gid, re)?.filter(|m| !m.deleted).ok_or_else(|| Error::Usage("no such message".into()))?;
        let s = self.group_settings(gid)?;
        if s.channel {
            if !s.may_comment(&self.member_id()) {
                return Err(Error::Feature("LOCKED_BY_CHAT".into()));
            }
            if message_re(&m).is_some() {
                return Err(Error::Usage("comments answer posts, not comments".into()));
            }
        }
        Ok(())
    }

    /// The receiving side's check of a reply: in a channel it must name a
    /// post this device has (comments are dropped otherwise); elsewhere a
    /// malformed reference is just ignored.
    pub(crate) fn receive_reply(&mut self, gid: &[u8], _from: &MemberId, re: Option<String>) -> Result<Result<Option<String>, &'static str>, Error> {
        let Some(re) = re else { return Ok(Ok(None)) };
        let channel = self.is_channel(gid)?;
        if !valid_msg_id(&re) {
            return Ok(if channel { Err("malformed comment") } else { Ok(None) });
        }
        if channel {
            match self.client.message(gid, &re)? {
                Some(m) if !m.deleted && message_re(&m).is_none() => {}
                _ => return Ok(Err("comment on an unknown post")),
            }
        }
        Ok(Ok(Some(re)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_core::group_settings::ChatSetting;

    fn text(re: Option<&str>) -> Payload {
        Payload::Text { id: "1".into(), text: "x".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: false, topic: None, re: re.map(str::to_string), kb: vec![] }
    }

    #[test]
    fn who_may_send_what() {
        let (admin, member) = (MemberId([1; 32]), MemberId([2; 32]));
        let mut s = GroupSettings { admins: vec![admin], channel: true, ..Default::default() };
        assert_eq!(refusal(&s, &admin, &text(None)), None);
        assert_eq!(refusal(&s, &member, &text(None)).map(|r| r.0), Some("NOT_ADMIN"));
        assert_eq!(refusal(&s, &member, &text(Some("ab"))).map(|r| r.0), Some("LOCKED_BY_CHAT"));
        assert_eq!(refusal(&s, &member, &Payload::React { id: "1".into(), emoji: "👍".into(), remove: false, sticker: None }), None);
        assert_eq!(refusal(&s, &member, &Payload::Typing { on: true }), None, "plumbing");
        assert_eq!(refusal(&s, &member, &Payload::Leave { quiet: false }), None);
        s.features.insert("channel.comments".into(), ChatSetting { applied: true, option: None });
        assert_eq!(refusal(&s, &member, &text(Some("ab"))), None);
        assert_eq!(refusal(&s, &member, &text(None)).map(|r| r.0), Some("NOT_ADMIN"), "still no posts");
        s.channel = false;
        assert_eq!(refusal(&s, &member, &text(None)), None, "groups: everyone");
    }

    #[test]
    fn re_in_stored_data() {
        let d = with_re(crate::messages::text_data(true, None, false), Some("ab"));
        let m = StoredMessage {
            group_id: vec![],
            id: "x".into(),
            sender: "s".into(),
            received_at: 0,
            kind: "text".into(),
            text: None,
            data: d,
            edited_at: None,
            deleted: false,
            expires_at: None,
            reactions: Default::default(),
            franking: None,
        };
        assert_eq!(message_re(&m).as_deref(), Some("ab"));
        assert_eq!(with_re(None, None), None);
    }
}
