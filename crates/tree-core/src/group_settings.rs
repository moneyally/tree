//! Group settings inside the MLS group state (PROTOCOL.md 6.11).
//!
//! The admin list, the group name and the chat-scope feature settings are a
//! Tree extension of the MLS group context, so every member holds the same
//! values (they are part of the transcript every commit agrees on) and the
//! server never sees them. Only an admin can change them, by a commit with
//! a GroupContextExtensions proposal; every device rejects such a commit from
//! anyone else, and rejects removals by non-admins.
//!
//! Wave 3 (PROTOCOL.md 6.11.1) adds roles with permissions, role
//! assignments (member tags), restricted members and the chat list of a
//! community. All of them are optional fields that older versions ignore,
//! and all of them count against the same 16 KiB.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::{Deserialize, Serialize};

use crate::{error::TreeError, features, group::MemberId};

/// Extension type, in the range RFC 9420 section 17.3 reserves for private use.
pub const EXTENSION_TYPE: u16 = 0xF2E0;
/// Largest encoded settings value accepted.
pub const MAX_LEN: usize = 16 * 1024;
/// Roles per group.
pub const MAX_ROLES: usize = 16;
/// Longest role name, in characters.
pub const MAX_ROLE_NAME: usize = 32;
/// Roles one member holds at most.
pub const MAX_ROLES_PER_MEMBER: usize = 4;
/// Role assignments per group (each costs about 70 bytes of the 16 KiB).
pub const MAX_ASSIGNMENTS: usize = 150;
/// Restricted members per group.
pub const MAX_RESTRICTED: usize = 50;
/// Chats per community.
pub const MAX_COMMUNITY_CHATS: usize = 50;
/// Longest chat name in a community list, in characters.
pub const MAX_COMMUNITY_NAME: usize = 64;
/// Members (devices, MLS leaves) of a private channel at most: a private
/// channel stays end-to-end encrypted, and its size is bounded so that
/// commits and welcomes stay within the server's limits (BENCHMARKS.md).
pub const MAX_CHANNEL_MEMBERS: usize = 1000;

/// What a role may allow besides what every member may do. Admins may do
/// all of it.
pub mod perm {
    /// Pin and unpin messages (`chat.pins`).
    pub const PIN: &str = "pin";
    /// Delete other members' messages for everyone.
    pub const DELETE: &str = "delete";
    /// Add members while `chat.member_adds` is released.
    pub const ADD: &str = "add";
    /// Create, rename, close and reopen topics (`chat.topics`).
    pub const TOPICS: &str = "topics";
    pub const ALL: [&str; 4] = [PIN, DELETE, ADD, TOPICS];
}

/// A role admins defined: a name, a colour for the member tag, and the
/// permissions it grants (a subset of [`perm::ALL`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    /// `#rrggbb`.
    pub color: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub perms: BTreeSet<String>,
}

/// One chat listed by a community root group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityChat {
    /// The chat's group id, hex.
    pub id: String,
    pub name: String,
}

/// Present on a community root group (PROTOCOL.md 6.11.1): the chats it
/// gathers. Its members are the community's members, its admins the
/// community's admins.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Community {
    #[serde(default)]
    pub chats: Vec<CommunityChat>,
}

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
    /// Role id (1 to 16 of `a-z`, `0-9`, `_`) -> role (`chat.roles`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub roles: BTreeMap<String, Role>,
    /// Member -> the role ids it holds (its member tags).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub member_roles: BTreeMap<MemberId, BTreeSet<String>>,
    /// Member -> until when (unix seconds) it may read but not send
    /// (`chat.restrict`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub restricted: BTreeMap<MemberId, i64>,
    /// Set on a community root group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community: Option<Community>,
    /// A private channel (Wave 4, PROTOCOL.md 6.11.2): only admins post;
    /// members comment while `channel.comments` is applied. Set when the
    /// group is created and never changed afterwards.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub channel: bool,
}

/// A valid role id.
pub fn valid_role_id(id: &str) -> bool {
    (1..=16).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn valid_color(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].bytes().all(|b| b.is_ascii_hexdigit())
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
        let set: HashSet<&MemberId> = members.iter().collect();
        if !self.admins.iter().any(|a| set.contains(a)) {
            return Err(TreeError::Group("a group needs at least one admin who is a member".into()));
        }
        if self.name.as_ref().is_some_and(|n| n.chars().count() > 128) {
            return Err(TreeError::Group("group name longer than 128 characters".into()));
        }
        if self.features.keys().any(|k| !k.starts_with("chat.") && !k.starts_with("channel.")) {
            return Err(TreeError::Group("only chat.* and channel.* features belong in group settings".into()));
        }
        if !self.channel && self.features.keys().any(|k| k.starts_with("channel.")) {
            return Err(TreeError::Group("channel.* features belong to channels".into()));
        }
        // A private group is never listed in the public directory: public
        // spaces are a separate thing on the server (chat.private_to_public).
        if self.features.get("chat.public_listing").is_some_and(|s| s.applied) {
            return Err(TreeError::Group("a private group is never listed publicly".into()));
        }
        if self.channel && members.len() > MAX_CHANNEL_MEMBERS {
            return Err(TreeError::Group(format!("a private channel has at most {MAX_CHANNEL_MEMBERS} members")));
        }
        for (k, s) in &self.features {
            // A permanent lock (chat.e2e, chat.private_to_public) is not a
            // group's choice, whatever an admin's client writes.
            if features::contradicts_lock(k, s.applied) {
                return Err(TreeError::Group(format!("{k} is permanently locked")));
            }
        }
        self.check_wave3()
    }

    /// Limits of roles, assignments, restrictions and the community list.
    /// Entries for members who left are allowed (they are ignored when
    /// read) but count against the limits.
    pub fn check_wave3(&self) -> Result<(), TreeError> {
        let bad = |why: String| Err(TreeError::Group(why));
        if self.roles.len() > MAX_ROLES {
            return bad(format!("at most {MAX_ROLES} roles"));
        }
        for (id, r) in &self.roles {
            if !valid_role_id(id) {
                return bad("a role id is 1 to 16 of a-z, 0-9, _".into());
            }
            let n = r.name.trim().chars().count();
            if n == 0 || r.name.chars().count() > MAX_ROLE_NAME || r.name.chars().any(char::is_control) {
                return bad(format!("a role name is 1 to {MAX_ROLE_NAME} characters"));
            }
            if !valid_color(&r.color) {
                return bad("a role colour is #rrggbb".into());
            }
            if r.perms.iter().any(|p| !perm::ALL.contains(&p.as_str())) {
                return bad(format!("role permissions are {}", perm::ALL.join(", ")));
            }
        }
        let mut assignments = 0;
        for held in self.member_roles.values() {
            if held.is_empty() || held.len() > MAX_ROLES_PER_MEMBER {
                return bad(format!("a member holds 1 to {MAX_ROLES_PER_MEMBER} roles"));
            }
            if held.iter().any(|r| !self.roles.contains_key(r)) {
                return bad("a member holds a role that does not exist".into());
            }
            assignments += held.len();
        }
        if assignments > MAX_ASSIGNMENTS {
            return bad(format!("at most {MAX_ASSIGNMENTS} role assignments"));
        }
        if self.restricted.len() > MAX_RESTRICTED {
            return bad(format!("at most {MAX_RESTRICTED} restricted members"));
        }
        if self.restricted.keys().any(|m| self.admins.contains(m)) {
            return bad("an admin cannot be restricted".into());
        }
        if let Some(c) = &self.community {
            if c.chats.len() > MAX_COMMUNITY_CHATS {
                return bad(format!("at most {MAX_COMMUNITY_CHATS} chats in a community"));
            }
            let mut seen = HashSet::new();
            for ch in &c.chats {
                let id_ok = ch.id.len() == 32 && ch.id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                if !id_ok || !seen.insert(&ch.id) || ch.name.chars().count() > MAX_COMMUNITY_NAME {
                    return bad("a community chat is a 16-byte group id (hex) and a name of at most 64 characters, listed once".into());
                }
            }
        }
        Ok(())
    }

    /// [`GroupSettings::check`] plus the option of every applied setting, for
    /// a change this device makes. Incoming changes are not refused for an
    /// option this version does not know (a newer client may write one, and
    /// refusing a commit the others accept would split the group); such an
    /// option reads as the default instead ([`GroupSettings::effective`]).
    pub fn check_own(&self, members: &[MemberId]) -> Result<(), TreeError> {
        self.check(members)?;
        for (k, s) in &self.features {
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
    /// permanent lock are dropped (the locked value always holds), and an
    /// option this version does not accept is replaced by the default.
    pub fn effective(mut self) -> Self {
        self.features.retain(|k, s| !features::contradicts_lock(k, s.applied));
        for (k, s) in self.features.iter_mut() {
            if s.applied && features::check_option(k, s.option.clone()).is_err() {
                s.option = features::check_option(k, None).ok().flatten();
            }
        }
        self
    }

    pub fn is_admin(&self, m: &MemberId) -> bool {
        self.admins.contains(m)
    }

    /// May `m` post in this group? Everyone, except in a channel, where
    /// only admins post (members comment, [`GroupSettings::may_comment`]).
    pub fn may_post(&self, m: &MemberId) -> bool {
        !self.channel || self.is_admin(m)
    }

    /// May `m` comment on a post here: in a channel while
    /// `channel.comments` is applied (admins too).
    pub fn may_comment(&self, _m: &MemberId) -> bool {
        self.channel && self.feature_on("channel.comments")
    }

    /// Whether the chat-scope feature `key` is applied here (its default
    /// when the admins never changed it).
    pub fn feature_on(&self, key: &str) -> bool {
        match self.features.get(key) {
            Some(s) if !features::contradicts_lock(key, s.applied) => s.applied,
            _ => features::standard_default(key).unwrap_or(false),
        }
    }

    /// May `m` do what permission `p` ([`perm`]) covers? Admins may do
    /// everything; others through a role, while `chat.roles` is applied.
    pub fn may(&self, m: &MemberId, p: &str) -> bool {
        self.is_admin(m)
            || (self.feature_on("chat.roles")
                && self.member_roles.get(m).is_some_and(|held| {
                    held.iter().any(|r| self.roles.get(r).is_some_and(|r| r.perms.contains(p)))
                }))
    }

    /// May `m` add members? Everyone while `chat.member_adds` is applied;
    /// otherwise admins and roles with [`perm::ADD`].
    pub fn may_add(&self, m: &MemberId) -> bool {
        self.feature_on("chat.member_adds") || self.may(m, perm::ADD)
    }

    /// Until when `m` is restricted (`chat.restrict` applied, the time not
    /// passed at `now`).
    pub fn restricted_until(&self, m: &MemberId, now: i64) -> Option<i64> {
        if !self.feature_on("chat.restrict") {
            return None;
        }
        self.restricted.get(m).copied().filter(|u| *u > now)
    }

    /// The roles `m` holds, while `chat.roles` is applied.
    pub fn roles_of(&self, m: &MemberId) -> Vec<(String, Role)> {
        if !self.feature_on("chat.roles") {
            return vec![];
        }
        self.member_roles
            .get(m)
            .into_iter()
            .flatten()
            .filter_map(|id| self.roles.get(id).map(|r| (id.clone(), r.clone())))
            .collect()
    }

    /// Drops entries about members who are gone (admins, roles held,
    /// restrictions), as [`crate::Group::settings`] shows them.
    pub fn only_members(mut self, members: &[MemberId]) -> Self {
        let set: HashSet<&MemberId> = members.iter().collect();
        self.admins.retain(|a| set.contains(a));
        self.member_roles.retain(|m, _| set.contains(m));
        self.restricted.retain(|m, _| set.contains(m));
        self
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

    fn role(perms: &[&str]) -> Role {
        Role { name: "mod".into(), color: "#00aa11".into(), perms: perms.iter().map(|p| p.to_string()).collect() }
    }

    /// Wave 3 fields: limits, permissions through roles (only while
    /// `chat.roles` is applied), `chat.member_adds`, restrictions, and
    /// older encodings still decode.
    #[test]
    fn roles_restrictions_community() {
        let base = GroupSettings { admins: vec![id(1)], ..Default::default() };
        let m = [id(1), id(2), id(3)];
        let mut s = base.clone();
        s.roles.insert("mods".into(), role(&[perm::PIN, perm::DELETE]));
        s.member_roles.insert(id(2), ["mods".to_string()].into());
        assert!(s.check(&m).is_ok());
        assert!(s.may(&id(2), perm::PIN) && s.may(&id(2), perm::DELETE) && !s.may(&id(2), perm::ADD));
        assert!(!s.may(&id(3), perm::PIN) && s.may(&id(1), perm::TOPICS), "admins may everything");
        assert_eq!(s.roles_of(&id(2)).len(), 1);
        // Released: roles grant nothing and show nothing.
        let mut off = s.clone();
        off.features.insert("chat.roles".into(), ChatSetting { applied: false, option: None });
        assert!(!off.may(&id(2), perm::PIN) && off.roles_of(&id(2)).is_empty());
        // Adds: anyone by default; released, admins and `add` roles.
        assert!(s.may_add(&id(3)));
        let mut closed = s.clone();
        closed.features.insert("chat.member_adds".into(), ChatSetting { applied: false, option: None });
        assert!(!closed.may_add(&id(3)) && !closed.may_add(&id(2)) && closed.may_add(&id(1)));
        closed.roles.get_mut("mods").unwrap().perms.insert(perm::ADD.into());
        assert!(closed.may_add(&id(2)));
        // Bad roles are refused.
        for (rid, r) in [
            ("Bad-Id", role(&[])),
            ("ok", Role { name: "".into(), ..role(&[]) }),
            ("ok", Role { name: "x".repeat(MAX_ROLE_NAME + 1), ..role(&[]) }),
            ("ok", Role { color: "red".into(), ..role(&[]) }),
            ("ok", role(&["fly"])),
        ] {
            let mut b = base.clone();
            b.roles.insert(rid.into(), r);
            assert!(b.check(&m).is_err(), "{rid}");
        }
        let mut b = base.clone();
        b.member_roles.insert(id(2), ["nope".to_string()].into());
        assert!(b.check(&m).is_err(), "unknown role");
        let mut b = base.clone();
        for i in 0..=MAX_ROLES {
            b.roles.insert(format!("r{i}"), role(&[]));
        }
        assert!(b.check(&m).is_err(), "too many roles");
        let mut b = s.clone();
        for i in 0..MAX_ASSIGNMENTS as u8 + 1 {
            b.member_roles.insert(MemberId([i.wrapping_add(10); 32]), ["mods".to_string()].into());
        }
        assert!(b.check(&m).is_err(), "too many assignments");
        // Restrictions: until a time, never an admin, released: not enforced.
        let mut r = base.clone();
        r.restricted.insert(id(3), 1000);
        assert!(r.check(&m).is_ok());
        assert_eq!(r.restricted_until(&id(3), 999), Some(1000));
        assert_eq!(r.restricted_until(&id(3), 1000), None, "over");
        let mut ro = r.clone();
        ro.features.insert("chat.restrict".into(), ChatSetting { applied: false, option: None });
        assert_eq!(ro.restricted_until(&id(3), 0), None);
        r.restricted.insert(id(1), 1000);
        assert!(r.check(&m).is_err(), "an admin cannot be restricted");
        // Community lists.
        let mut c = base.clone();
        c.community = Some(Community { chats: vec![CommunityChat { id: "ab".repeat(16), name: "일반".into() }] });
        assert!(c.check(&m).is_ok());
        c.community.as_mut().unwrap().chats.push(CommunityChat { id: "ab".repeat(16), name: "again".into() });
        assert!(c.check(&m).is_err(), "listed once");
        c.community = Some(Community { chats: vec![CommunityChat { id: "zz".into(), name: "x".into() }] });
        assert!(c.check(&m).is_err(), "group id");
        // Round trip, and entries of members who left are dropped when read.
        let enc = s.encode().unwrap();
        assert_eq!(GroupSettings::decode(&enc).unwrap(), s);
        assert!(GroupSettings::decode(br#"{"admins":[],"unknown_newer_field":1}"#).is_ok(), "newer fields are ignored");
        let gone = s.clone().only_members(&[id(1)]);
        assert!(gone.member_roles.is_empty());
        // A base encoding has none of the new fields (older readers).
        assert!(!String::from_utf8(base.encode().unwrap()).unwrap().contains("roles"));
    }

    #[test]
    fn channels() {
        let base = GroupSettings { admins: vec![id(1)], channel: true, ..Default::default() };
        assert!(base.check(&[id(1), id(2)]).is_ok());
        assert!(base.may_post(&id(1)) && !base.may_post(&id(2)), "only admins post");
        assert!(!base.may_comment(&id(2)), "comments released by default");
        let mut c = base.clone();
        c.features.insert("channel.comments".into(), ChatSetting { applied: true, option: None });
        assert!(c.check(&[id(1)]).is_ok() && c.may_comment(&id(2)));
        // channel.* keys only in channels; never listed publicly.
        let mut g = c.clone();
        g.channel = false;
        assert!(g.check(&[id(1)]).is_err(), "channel key in a group");
        assert!(GroupSettings { admins: vec![id(1)], ..Default::default() }.may_post(&id(2)), "groups: everyone");
        let mut listed = base.clone();
        listed.features.insert("chat.public_listing".into(), ChatSetting { applied: true, option: None });
        assert!(listed.check(&[id(1)]).is_err(), "a private group is never listed");
        listed.features.insert("chat.public_listing".into(), ChatSetting { applied: false, option: None });
        assert!(listed.check(&[id(1)]).is_ok());
        // At most 1,000 members.
        let many: Vec<MemberId> = (0..MAX_CHANNEL_MEMBERS as u32).map(|i| { let mut b = [0u8; 32]; b[..4].copy_from_slice(&i.to_be_bytes()); b[31] = 1; MemberId(b) }).collect();
        let mut big = base.clone();
        big.admins = vec![many[0]];
        assert!(big.check(&many).is_ok());
        let mut more = many.clone();
        more.push(id(9));
        assert!(big.check(&more).is_err());
        // Round trip; groups encode without the flag.
        assert_eq!(GroupSettings::decode(&c.encode().unwrap()).unwrap(), c);
        assert!(!String::from_utf8(GroupSettings { admins: vec![id(1)], ..Default::default() }.encode().unwrap()).unwrap().contains("channel"));
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
        assert!(with("chat.disappearing", true, Some("never")).check_own(&[id(1)]).is_err());
        assert!(with("chat.disappearing", true, Some("never")).check(&[id(1)]).is_ok(), "incoming: not refused");
        assert!(with("chat.disappearing", true, Some("1h")).check_own(&[id(1)]).is_ok());
        let s = with("chat.disappearing", true, Some("never")).effective();
        assert_eq!(s.features["chat.disappearing"].option.as_deref(), Some("1d"), "read as the default");
        assert!(with("chat.future_thing", true, Some("x")).check(&[id(1)]).is_ok(), "unknown keys: newer clients");
        // Read side: a contradiction (e.g. in a group's first settings) is dropped.
        let s = with("chat.e2e", false, None).effective();
        assert!(!s.features.contains_key("chat.e2e"));
        let s = with("chat.media", false, None).effective();
        assert!(!s.features["chat.media"].applied);
    }
}
