//! Groups and communities for the apps (Wave 3): topics, roles and member
//! tags, the admin log, the welcome text, history for new members, the
//! next admin, join approval, slow mode, restricted members and
//! communities. Only type conversions; the behaviour is in `tree_client`.

use tree_core::group_settings::{perm, Role};

use crate::{member, unhex, Commit, Message, TreeSession, R};

/// A role (member tag) and what it allows.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoleInfo {
    pub id: String,
    pub name: String,
    /// `#rrggbb`.
    pub color: String,
    /// From `role_permissions()`: `pin`, `delete`, `add`, `topics`.
    pub perms: Vec<String>,
}

impl From<(String, Role)> for RoleInfo {
    fn from((id, r): (String, Role)) -> Self {
        RoleInfo { id, name: r.name, color: r.color, perms: r.perms.into_iter().collect() }
    }
}

/// What a role can allow.
#[uniffi::export]
pub fn role_permissions() -> Vec<String> {
    perm::ALL.iter().map(|p| p.to_string()).collect()
}

/// A topic (thread) of a group.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TopicInfo {
    pub id: String,
    /// Empty for a topic this device was never told about.
    pub name: String,
    pub closed: bool,
    pub unread: u32,
    pub created_by: Option<String>,
}

/// One admin action this device observed (`chat.admin_log`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct AdminLogItem {
    pub at: i64,
    /// Member id of who did it, as MLS authenticated it.
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
}

/// An invite-link join waiting for an admin (`chat.join_approval`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct JoinRequestInfo {
    pub account: String,
    pub at: i64,
}

/// A restricted member and until when.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RestrictedMember {
    pub member: String,
    pub until: i64,
}

/// A chat of a community.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CommunityChatInfo {
    pub id: String,
    pub name: String,
    pub joined: bool,
}

#[uniffi::export]
impl TreeSession {
    // --- permissions and roles ---

    /// May this device do what `perm` covers (`pin`, `delete`, `add`,
    /// `topics`)?
    pub fn may(&self, group: String, perm: String) -> R<bool> {
        Ok(self.s().may(&unhex(&group, "group")?, &perm)?)
    }

    pub fn may_add(&self, group: String) -> R<bool> {
        Ok(self.s().may_add(&unhex(&group, "group")?)?)
    }

    pub fn roles(&self, group: String) -> R<Vec<RoleInfo>> {
        Ok(self.s().roles(&unhex(&group, "group")?)?.into_iter().map(Into::into).collect())
    }

    pub fn create_role(&self, group: String, name: String, color: String, perms: Vec<String>) -> R<String> {
        Ok(self.s().create_role(&unhex(&group, "group")?, &name, &color, &perms)?)
    }

    pub fn update_role(&self, group: String, id: String, name: String, color: String, perms: Vec<String>) -> R<()> {
        Ok(self.s().update_role(&unhex(&group, "group")?, &id, &name, &color, &perms)?)
    }

    pub fn delete_role(&self, group: String, id: String) -> R<()> {
        Ok(self.s().delete_role(&unhex(&group, "group")?, &id)?)
    }

    pub fn assign_role(&self, group: String, member_id: String, role: String, on: bool) -> R<()> {
        Ok(self.s().assign_role(&unhex(&group, "group")?, &member(&member_id)?, &role, on)?)
    }

    // --- restricted members, slow mode, moderation ---

    /// Restricts a member until `until` (unix seconds); null lifts it.
    pub fn restrict_member(&self, group: String, member_id: String, until: Option<i64>) -> R<()> {
        Ok(self.s().restrict_member(&unhex(&group, "group")?, &member(&member_id)?, until)?)
    }

    pub fn restricted_members(&self, group: String) -> R<Vec<RestrictedMember>> {
        Ok(self
            .s()
            .restricted_members(&unhex(&group, "group")?)?
            .into_iter()
            .map(|(m, until)| RestrictedMember { member: m.to_hex(), until })
            .collect())
    }

    /// Until when this device may not send here, if restricted.
    pub fn restricted_until(&self, group: String) -> R<Option<i64>> {
        Ok(self.s().restricted_until(&unhex(&group, "group")?)?)
    }

    /// The slow-mode interval in seconds, while applied.
    pub fn slow_mode(&self, group: String) -> R<Option<i64>> {
        Ok(self.s().slow_mode(&unhex(&group, "group")?)?)
    }

    /// Seconds before this device may send its next message (slow mode).
    pub fn slow_mode_wait(&self, group: String) -> R<Option<i64>> {
        Ok(self.s().slow_mode_wait(&unhex(&group, "group")?)?)
    }

    /// Deletes another member's message for everyone (admins and roles
    /// with `delete`).
    pub fn delete_as_moderator(&self, group: String, id: String) -> R<()> {
        Ok(self.s().delete_as_moderator(&unhex(&group, "group")?, &id)?)
    }

    pub fn welcome_text(&self, group: String) -> R<Option<String>> {
        Ok(self.s().welcome_text(&unhex(&group, "group")?)?)
    }

    /// Who becomes admin if this device (the only admin) leaves now.
    pub fn successor(&self, group: String) -> R<Option<String>> {
        Ok(self.s().successor(&unhex(&group, "group")?)?.map(|m| m.to_hex()))
    }

    /// How many recent messages new members get; null while history
    /// sharing is released. Show "new members see the recent
    /// conversation" while set.
    pub fn history_share(&self, group: String) -> R<Option<u32>> {
        Ok(self.s().history_share(&unhex(&group, "group")?)?)
    }

    // --- topics ---

    pub fn topics(&self, group: String) -> R<Vec<TopicInfo>> {
        Ok(self
            .s()
            .topics(&unhex(&group, "group")?)?
            .into_iter()
            .map(|t| TopicInfo { id: t.id, name: t.name, closed: t.closed, unread: t.unread, created_by: t.created_by.map(|m| m.to_hex()) })
            .collect())
    }

    pub fn may_create_topics(&self, group: String) -> R<bool> {
        Ok(self.s().may_create_topics(&unhex(&group, "group")?)?)
    }

    pub fn may_manage_topics(&self, group: String) -> R<bool> {
        Ok(self.s().may_manage_topics(&unhex(&group, "group")?)?)
    }

    pub fn create_topic(&self, group: String, name: String) -> R<String> {
        Ok(self.s().create_topic(&unhex(&group, "group")?, &name)?)
    }

    pub fn rename_topic(&self, group: String, id: String, name: String) -> R<()> {
        Ok(self.s().rename_topic(&unhex(&group, "group")?, &id, &name)?)
    }

    pub fn close_topic(&self, group: String, id: String, closed: bool) -> R<()> {
        Ok(self.s().close_topic(&unhex(&group, "group")?, &id, closed)?)
    }

    pub fn mark_topic_read(&self, group: String, topic: String) -> R<()> {
        Ok(self.s().mark_topic_read(&unhex(&group, "group")?, &topic)?)
    }

    /// Sends a text in a topic; returns its id.
    pub fn send_text_in_topic(&self, group: String, topic: String, text: String) -> R<String> {
        let o = tree_client::TextOptions { topic: Some(topic), ..Default::default() };
        Ok(self.s().send_text_with(&unhex(&group, "group")?, &text, &o)?)
    }

    /// The newest messages of a topic (null: the main chat).
    pub fn topic_history(&self, group: String, topic: Option<String>, limit: u32) -> R<Vec<Message>> {
        let gid = unhex(&group, "group")?;
        let s = self.s();
        let shared = s.shared_messages(&gid)?;
        Ok(s.topic_history(&gid, topic.as_deref(), limit)?
            .into_iter()
            .map(|m| {
                let mut m: Message = m.into();
                m.shared_by = shared.get(&m.id).cloned();
                m
            })
            .collect())
    }

    // --- admin log, join approval ---

    /// For admins: what this device saw admins do.
    pub fn admin_log(&self, group: String) -> R<Vec<AdminLogItem>> {
        Ok(self
            .s()
            .admin_log(&unhex(&group, "group")?)?
            .into_iter()
            .map(|e| AdminLogItem { at: e.at, actor: e.actor, action: e.action, target: e.target, detail: e.detail })
            .collect())
    }

    pub fn join_requests(&self, group: String) -> R<Vec<JoinRequestInfo>> {
        Ok(self
            .s()
            .join_requests(&unhex(&group, "group")?)?
            .into_iter()
            .map(|r| JoinRequestInfo { account: r.account, at: r.at })
            .collect())
    }

    pub fn approve_join(&self, group: String, account: String) -> R<Commit> {
        Ok(self.s().approve_join(&unhex(&group, "group")?, &account)?.into())
    }

    pub fn decline_join(&self, group: String, account: String) -> R<()> {
        Ok(self.s().decline_join(&unhex(&group, "group")?, &account)?)
    }

    // --- communities ---

    pub fn create_community(&self, name: String) -> R<String> {
        Ok(hex::encode(self.s().create_community(&name)?))
    }

    pub fn is_community(&self, group: String) -> R<bool> {
        Ok(self.s().is_community(&unhex(&group, "group")?)?)
    }

    pub fn communities(&self) -> R<Vec<String>> {
        Ok(self.s().communities()?.into_iter().map(hex::encode).collect())
    }

    pub fn community_chats(&self, community: String) -> R<Vec<CommunityChatInfo>> {
        Ok(self
            .s()
            .community_chats(&unhex(&community, "community")?)?
            .into_iter()
            .map(|c| CommunityChatInfo { id: hex::encode(c.id), name: c.name, joined: c.joined })
            .collect())
    }

    pub fn add_community_chat(&self, community: String, group: String) -> R<()> {
        Ok(self.s().add_community_chat(&unhex(&community, "community")?, &unhex(&group, "group")?)?)
    }

    pub fn remove_community_chat(&self, community: String, group: String) -> R<()> {
        Ok(self.s().remove_community_chat(&unhex(&community, "community")?, &unhex(&group, "group")?)?)
    }

    pub fn join_community_chat(&self, community: String, group: String) -> R<()> {
        Ok(self.s().join_community_chat(&unhex(&community, "community")?, &unhex(&group, "group")?)?)
    }
}
