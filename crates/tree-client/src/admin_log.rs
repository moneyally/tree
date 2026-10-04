//! The admin log (`chat.admin_log`, APP_PROTOCOL.md 9.3): each device
//! records the admin actions it observes, derived from the commits it
//! merges and the messages it accepts, with the actor MLS authenticated
//! (the committer of a commit, the sender of a message). Nothing is sent
//! for it: the log is device-local, so a device that joined later has no
//! entries from before, and two devices may differ in what they saw.
//!
//! Recorded: settings changes (name, admins, chat features, roles and role
//! assignments, restrictions, a community's chats), members added and
//! removed, pins and unpins, messages deleted by moderators, topic
//! changes, join requests approved or declined on this device. At most
//! [`MAX_ENTRIES`] per group (the oldest go). Released: nothing is
//! recorded and the stored log is not shown. The log is shown to admins.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tree_core::group_settings::GroupSettings;
use tree_core::MemberId;

use crate::messages::now;
use crate::{Error, Session};

/// Entries kept per group.
pub const MAX_ENTRIES: usize = 500;

/// One observed admin action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLogEntry {
    /// When this device observed it (its own clock).
    pub at: i64,
    /// Member id (hex) of who did it, as MLS authenticated it.
    pub actor: String,
    /// `rename`, `admin_add`, `admin_remove`, `feature`, `role_create`,
    /// `role_update`, `role_delete`, `role_assign`, `role_unassign`,
    /// `restrict`, `unrestrict`, `community_add`, `community_remove`,
    /// `add`, `remove`, `pin`, `unpin`, `delete`, `topic`, `topic_close`,
    /// `topic_reopen`, `join_approve`, `join_decline`.
    pub action: String,
    /// What it was done to: a member id, feature key, role id, topic id,
    /// group id or account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

fn log_key(gid: &[u8]) -> String {
    format!("adminlog/{}", hex::encode(gid))
}

fn feature_text(s: Option<&tree_core::group_settings::ChatSetting>) -> String {
    match s {
        None => "default".into(),
        Some(s) if !s.applied => "released".into(),
        Some(s) => match &s.option {
            Some(o) => format!("applied: {o}"),
            None => "applied".into(),
        },
    }
}

/// What changed between two settings values, as log entries
/// (action, target, detail).
pub(crate) fn settings_diff(before: &GroupSettings, after: &GroupSettings) -> Vec<(&'static str, Option<String>, Option<String>)> {
    let mut out = Vec::new();
    if before.name != after.name {
        out.push(("rename", None, after.name.clone()));
    }
    for a in after.admins.iter().filter(|a| !before.admins.contains(a)) {
        out.push(("admin_add", Some(a.to_hex()), None));
    }
    for a in before.admins.iter().filter(|a| !after.admins.contains(a)) {
        out.push(("admin_remove", Some(a.to_hex()), None));
    }
    let keys: BTreeSet<&String> = before.features.keys().chain(after.features.keys()).collect();
    for k in keys {
        let (b, a) = (before.features.get(k), after.features.get(k));
        if b != a {
            out.push(("feature", Some(k.clone()), Some(feature_text(a))));
        }
    }
    for (id, r) in &after.roles {
        match before.roles.get(id) {
            None => out.push(("role_create", Some(id.clone()), Some(r.name.clone()))),
            Some(old) if old != r => out.push(("role_update", Some(id.clone()), Some(r.name.clone()))),
            _ => {}
        }
    }
    for (id, r) in before.roles.iter().filter(|(id, _)| !after.roles.contains_key(*id)) {
        out.push(("role_delete", Some(id.clone()), Some(r.name.clone())));
    }
    let members: BTreeSet<&MemberId> = before.member_roles.keys().chain(after.member_roles.keys()).collect();
    for m in members {
        let empty = BTreeSet::new();
        let (b, a) = (before.member_roles.get(m).unwrap_or(&empty), after.member_roles.get(m).unwrap_or(&empty));
        for r in a.difference(b) {
            out.push(("role_assign", Some(m.to_hex()), Some(r.clone())));
        }
        for r in b.difference(a) {
            out.push(("role_unassign", Some(m.to_hex()), Some(r.clone())));
        }
    }
    for (m, u) in &after.restricted {
        if before.restricted.get(m) != Some(u) {
            out.push(("restrict", Some(m.to_hex()), Some(u.to_string())));
        }
    }
    for m in before.restricted.keys().filter(|m| !after.restricted.contains_key(*m)) {
        out.push(("unrestrict", Some(m.to_hex()), None));
    }
    let chats = |s: &GroupSettings| s.community.as_ref().map(|c| c.chats.iter().map(|c| c.id.clone()).collect::<BTreeSet<_>>()).unwrap_or_default();
    let (cb, ca) = (chats(before), chats(after));
    for c in ca.difference(&cb) {
        out.push(("community_add", Some(c.clone()), None));
    }
    for c in cb.difference(&ca) {
        out.push(("community_remove", Some(c.clone()), None));
    }
    out
}

impl Session {
    /// Records one admin action `actor` took, while `chat.admin_log` is
    /// applied.
    pub(crate) fn log_admin(&mut self, gid: &[u8], actor: &MemberId, action: &str, target: Option<String>, detail: Option<String>) -> Result<(), Error> {
        if !self.chat_on(gid, "chat.admin_log")? {
            return Ok(());
        }
        let mut v: Vec<AdminLogEntry> = self.app_get(&log_key(gid))?.unwrap_or_default();
        v.push(AdminLogEntry { at: now(), actor: actor.to_hex(), action: action.into(), target, detail });
        let extra = v.len().saturating_sub(MAX_ENTRIES);
        v.drain(..extra);
        self.app_put(&log_key(gid), Some(&v))
    }

    /// Records what a merged commit by `actor` changed (`before`: the
    /// settings before it).
    pub(crate) fn log_commit(&mut self, gid: &[u8], actor: &MemberId, before: &GroupSettings, added: &[MemberId], removed: &[MemberId]) -> Result<(), Error> {
        let after = self.group_settings(gid)?;
        let gone: Vec<String> = removed.iter().map(MemberId::to_hex).collect();
        for (action, target, detail) in settings_diff(before, &after) {
            // A removed member drops out of the admins, roles and
            // restrictions by itself: its "remove" entry says it all.
            if target.as_ref().is_some_and(|t| gone.contains(t)) {
                continue;
            }
            self.log_admin(gid, actor, action, target, detail)?;
        }
        for m in added {
            self.log_admin(gid, actor, "add", Some(m.to_hex()), None)?;
        }
        for m in removed {
            self.log_admin(gid, actor, "remove", Some(m.to_hex()), None)?;
        }
        Ok(())
    }

    /// The admin log of a group on this device, oldest first. Only for
    /// admins (`NOT_ADMIN` otherwise); empty while `chat.admin_log` is
    /// released.
    pub fn admin_log(&mut self, gid: &[u8]) -> Result<Vec<AdminLogEntry>, Error> {
        let me = self.member_id();
        if !self.group(gid)?.is_admin(&me) {
            return Err(Error::Feature("NOT_ADMIN".into()));
        }
        if !self.chat_on(gid, "chat.admin_log")? {
            return Ok(vec![]);
        }
        Ok(self.app_get(&log_key(gid))?.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_core::group_settings::{ChatSetting, Role};

    #[test]
    fn diff_names_every_change() {
        let m = |b: u8| MemberId([b; 32]);
        let before = GroupSettings { admins: vec![m(1)], ..Default::default() };
        let mut after = before.clone();
        after.name = Some("n".into());
        after.admins.push(m(2));
        after.features.insert("chat.media".into(), ChatSetting { applied: false, option: None });
        after.roles.insert("r".into(), Role { name: "mod".into(), color: "#112233".into(), perms: ["pin".to_string()].into() });
        after.member_roles.insert(m(3), ["r".to_string()].into());
        after.restricted.insert(m(4), 99);
        let d = settings_diff(&before, &after);
        let actions: Vec<&str> = d.iter().map(|x| x.0).collect();
        assert_eq!(actions, vec!["rename", "admin_add", "feature", "role_create", "role_assign", "restrict"]);
        assert_eq!(d[2].2.as_deref(), Some("released"));
        let back = settings_diff(&after, &before);
        let actions: Vec<&str> = back.iter().map(|x| x.0).collect();
        assert_eq!(actions, vec!["rename", "admin_remove", "feature", "role_delete", "role_unassign", "unrestrict"]);
        assert!(settings_diff(&before, &before).is_empty());
    }
}
