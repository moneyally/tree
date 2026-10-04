//! Group settings inside the MLS group state (PROTOCOL.md 6.11).
//!
//! The admin list, the group name and the chat-scope feature settings are a
//! Tree extension of the MLS group context, so every member holds the same
//! values (they are part of the transcript every commit agrees on) and the
//! server never sees them. Only an admin can change them, by a commit with
//! a GroupContextExtensions proposal; every device rejects such a commit from
//! anyone else, and rejects removals by non-admins.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{error::TreeError, features, group::MemberId};

/// Extension type, in the range RFC 9420 section 17.3 reserves for private use.
pub const EXTENSION_TYPE: u16 = 0xF2E0;
/// Largest encoded settings value accepted.
pub const MAX_LEN: usize = 16 * 1024;

/// One chat-scope feature as set by an admin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatSetting {
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub option: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSettings {
    /// Member ids allowed to change settings and remove others.
    pub admins: Vec<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Chat-scope feature key -> setting (keys absent = default).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub features: BTreeMap<String, ChatSetting>,
}

impl Serialize for MemberId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for MemberId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        MemberId::from_hex(&s).ok_or_else(|| serde::de::Error::custom("member id must be 64 hex digits"))
    }
}

impl GroupSettings {
    /// Encoding carried in the extension: JSON, at most [`MAX_LEN`] bytes.
    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        let v = serde_json::to_vec(self).map_err(|e| TreeError::Malformed(e.to_string()))?;
        if v.len() > MAX_LEN {
            return Err(TreeError::Group("group settings too large".into()));
        }
        Ok(v)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        if bytes.len() > MAX_LEN {
            return Err(TreeError::Malformed("group settings too large".into()));
        }
        serde_json::from_slice(bytes).map_err(|e| TreeError::Malformed(format!("group settings: {e}")))
    }

    /// Rules every valid settings value meets for the members `members`.
    pub fn check(&self, members: &[MemberId]) -> Result<(), TreeError> {
        if !self.admins.iter().any(|a| members.contains(a)) {
            return Err(TreeError::Group("a group needs at least one admin who is a member".into()));
        }
        if self.name.as_ref().is_some_and(|n| n.chars().count() > 128) {
            return Err(TreeError::Group("group name longer than 128 characters".into()));
        }
        if self.features.keys().any(|k| !k.starts_with("chat.")) {
            return Err(TreeError::Group("only chat.* features belong in group settings".into()));
        }
        for (k, s) in &self.features {
            // A permanent lock (chat.e2e, chat.private_to_public) is not a
            // group's choice, whatever an admin's client writes.
            if features::contradicts_lock(k, s.applied) {
                return Err(TreeError::Group(format!("{k} is permanently locked")));
            }
            if s.applied {
                features::check_option(k, s.option.clone()).map_err(|e| match e {
                    features::FeatureError::InvalidOption(why) => TreeError::Group(format!("invalid option: {why}")),
                    other => TreeError::Group(other.code().into()),
                })?;
            }
        }
        Ok(())
    }

    /// The settings as they take effect: entries that contradict a
    /// permanent lock are dropped (the locked value always holds).
    pub fn without_locked(mut self) -> Self {
        self.features.retain(|k, s| !features::contradicts_lock(k, s.applied));
        self
    }

    pub fn is_admin(&self, m: &MemberId) -> bool {
        self.admins.contains(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_limit_and_name_length() {
        let base = GroupSettings { name: Some(String::new()), ..Default::default() }.encode().unwrap().len();
        let at = GroupSettings { name: Some("a".repeat(MAX_LEN - base)), ..Default::default() }.encode().unwrap();
        assert!(GroupSettings::decode(&at).is_ok(), "exactly the limit decodes");
        let mut over = at.clone();
        over.insert(0, b' ');
        assert!(matches!(GroupSettings::decode(&over), Err(TreeError::Malformed(e)) if e.contains("too large")));
        let m = [id(1)];
        let named = |n: usize| GroupSettings { admins: vec![id(1)], name: Some("가".repeat(n)), ..Default::default() };
        assert!(named(128).check(&m).is_ok(), "128 characters (not bytes) are fine");
        assert!(named(129).check(&m).is_err());
    }

    #[test]
    fn size_limit_is_exact() {
        assert_eq!(MAX_LEN, 16 * 1024);
        let base = GroupSettings { name: Some(String::new()), ..Default::default() }.encode().unwrap().len();
        let at = GroupSettings { name: Some("a".repeat(MAX_LEN - base)), ..Default::default() };
        assert_eq!(at.encode().unwrap().len(), MAX_LEN);
        let over = GroupSettings { name: Some("a".repeat(MAX_LEN - base + 1)), ..Default::default() };
        assert!(over.encode().is_err());
    }

    fn id(b: u8) -> MemberId {
        MemberId([b; 32])
    }

    #[test]
    fn round_trip_and_rules() {
        let mut s = GroupSettings { admins: vec![id(1)], name: Some("가족".into()), ..Default::default() };
        s.features.insert("chat.media".into(), ChatSetting { applied: false, option: None });
        let enc = s.encode().unwrap();
        assert_eq!(GroupSettings::decode(&enc).unwrap(), s);
        assert!(String::from_utf8(enc).unwrap().contains(&id(1).to_hex()));
        assert!(s.check(&[id(1), id(2)]).is_ok());
        assert!(s.check(&[id(2)]).is_err(), "admin not a member");
        let mut bad = s.clone();
        bad.features.insert("user.typing".into(), ChatSetting { applied: true, option: None });
        assert!(bad.check(&[id(1)]).is_err());
        let mut long = s.clone();
        long.name = Some("x".repeat(129));
        assert!(long.check(&[id(1)]).is_err());
        assert!(GroupSettings::decode(b"{\"admins\":[\"zz\"]}").is_err());
        assert!(GroupSettings::decode(&vec![b' '; MAX_LEN + 1]).is_err());
        let huge = GroupSettings { name: Some("x".repeat(MAX_LEN)), ..s };
        assert!(huge.encode().is_err());
    }

    #[test]
    fn locked_keys_hold() {
        let base = GroupSettings { admins: vec![id(1)], ..Default::default() };
        let with = |k: &str, applied: bool, option: Option<&str>| {
            let mut s = base.clone();
            s.features.insert(k.into(), ChatSetting { applied, option: option.map(str::to_string) });
            s
        };
        assert!(with("chat.e2e", false, None).check(&[id(1)]).is_err());
        assert!(with("chat.private_to_public", true, None).check(&[id(1)]).is_err());
        assert!(with("chat.e2e", true, None).check(&[id(1)]).is_ok(), "the locked value itself is harmless");
        assert!(with("chat.disappearing", true, Some("never")).check(&[id(1)]).is_err());
        assert!(with("chat.disappearing", true, Some("1h")).check(&[id(1)]).is_ok());
        assert!(with("chat.future_thing", true, Some("x")).check(&[id(1)]).is_ok(), "unknown keys: newer clients");
        // Read side: a contradiction (e.g. in a group's first settings) is dropped.
        let s = with("chat.e2e", false, None).without_locked();
        assert!(!s.features.contains_key("chat.e2e"));
        let s = with("chat.media", false, None).without_locked();
        assert!(!s.features["chat.media"].applied);
    }
}
