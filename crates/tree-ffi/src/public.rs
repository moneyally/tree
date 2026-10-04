//! Public groups and channels (not end-to-end, `is_public` on every
//! object) and private channels (end-to-end) for the apps (Wave 4). Only
//! type conversions; the behaviour is in `tree_client::public` and
//! `tree_client::channel`.

use tree_client::{PublicPost, PublicSpace};

use crate::{unhex, Message, TreeSession, R};

/// A public group or channel. NOT end-to-end encrypted: `is_public` is
/// always true and the apps show "Public" wherever it appears.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PublicSpaceInfo {
    pub id: String,
    pub is_public: bool,
    /// `group` or `channel`.
    pub kind: String,
    pub handle: String,
    pub name: String,
    pub description: String,
    pub avatar: Option<String>,
    pub members: u64,
    /// `chat.public_listing`.
    pub listed: bool,
    /// `channel.comments`.
    pub comments: bool,
    /// `channel.signatures`.
    pub signatures: bool,
    /// `chat.slow_mode` in seconds, if applied.
    pub slow_mode: Option<i64>,
    /// `owner`, `admin`, `member`, or null (not subscribed).
    pub role: Option<String>,
    pub notify: bool,
    pub banned: bool,
    /// Admin and banned accounts (admins only).
    pub admins: Vec<String>,
    pub bans: Vec<String>,
    pub unread: u32,
}

impl From<PublicSpace> for PublicSpaceInfo {
    fn from(s: PublicSpace) -> Self {
        PublicSpaceInfo {
            id: s.id,
            is_public: s.is_public,
            kind: s.kind,
            handle: s.handle,
            name: s.name,
            description: s.description,
            avatar: s.avatar,
            members: s.members,
            listed: s.listed,
            comments: s.comments,
            signatures: s.signatures,
            slow_mode: s.slow_mode,
            role: s.role,
            notify: s.notify,
            banned: s.banned,
            admins: s.admins,
            bans: s.bans,
            unread: s.unread,
        }
    }
}

/// A post or comment of a public space (`is_public` always true).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PublicPostInfo {
    pub id: String,
    pub space: String,
    pub is_public: bool,
    pub reply_to: Option<String>,
    pub text: Option<String>,
    pub created_at: i64,
    pub edited: bool,
    pub mine: bool,
    /// Null for a channel post while `channel.signatures` is released.
    pub author: Option<String>,
    pub author_name: Option<String>,
    pub comments: u32,
}

impl From<PublicPost> for PublicPostInfo {
    fn from(p: PublicPost) -> Self {
        PublicPostInfo {
            id: p.id,
            space: p.space,
            is_public: p.is_public,
            reply_to: p.reply_to,
            text: p.text,
            created_at: p.created_at,
            edited: p.edited_at.is_some(),
            mine: p.mine,
            author: p.author,
            author_name: p.author_name,
            comments: p.comments,
        }
    }
}

fn spaces(v: Vec<PublicSpace>) -> Vec<PublicSpaceInfo> {
    v.into_iter().map(Into::into).collect()
}

fn posts(v: Vec<PublicPost>) -> Vec<PublicPostInfo> {
    v.into_iter().map(Into::into).collect()
}

#[uniffi::export]
impl TreeSession {
    // --- public spaces (not end-to-end) ---

    /// `kind`: `group` or `channel`.
    pub fn public_create(&self, kind: String, name: String, handle: String, description: String) -> R<PublicSpaceInfo> {
        Ok(self.s().public_create(&kind, &name, &handle, &description, None)?.into())
    }

    pub fn public_space(&self, space: String) -> R<PublicSpaceInfo> {
        Ok(self.s().public_space(&space)?.into())
    }

    pub fn public_find(&self, handle: String) -> R<Option<PublicSpaceInfo>> {
        Ok(self.s().public_find(&handle)?.map(Into::into))
    }

    pub fn public_directory(&self, query: String) -> R<Vec<PublicSpaceInfo>> {
        Ok(spaces(self.s().public_directory(&query)?))
    }

    pub fn public_subscriptions(&self) -> R<Vec<PublicSpaceInfo>> {
        Ok(spaces(self.s().public_subscriptions()?))
    }

    /// The subscribed spaces as kept on this device (no network).
    pub fn public_cached(&self) -> R<Vec<PublicSpaceInfo>> {
        Ok(spaces(self.s().public_cached()?))
    }

    pub fn public_join(&self, space: String) -> R<PublicSpaceInfo> {
        Ok(self.s().public_join(&space)?.into())
    }

    pub fn public_leave(&self, space: String) -> R<()> {
        Ok(self.s().public_leave(&space)?)
    }

    pub fn public_set_notify(&self, space: String, on: bool) -> R<PublicSpaceInfo> {
        Ok(self.s().public_set_notify(&space, on)?.into())
    }

    pub fn public_set_feature(&self, space: String, key: String, apply: bool, option: Option<String>) -> R<PublicSpaceInfo> {
        Ok(self.s().public_set_feature(&space, &key, apply, option.as_deref())?.into())
    }

    pub fn public_set_admin(&self, space: String, account: String, admin: bool) -> R<PublicSpaceInfo> {
        Ok(self.s().public_set_admin(&space, &account, admin)?.into())
    }

    pub fn public_ban(&self, space: String, account: String, ban: bool) -> R<PublicSpaceInfo> {
        Ok(self.s().public_ban(&space, &account, ban)?.into())
    }

    pub fn public_update(&self, space: String, name: Option<String>, description: Option<String>) -> R<PublicSpaceInfo> {
        Ok(self.s().public_update(&space, name.as_deref(), description.as_deref())?.into())
    }

    pub fn public_delete_space(&self, space: String) -> R<()> {
        Ok(self.s().public_delete_space(&space)?)
    }

    pub fn public_post(&self, space: String, text: String, reply_to: Option<String>) -> R<PublicPostInfo> {
        Ok(self.s().public_post(&space, &text, reply_to.as_deref())?.into())
    }

    pub fn public_edit(&self, space: String, post: String, text: String) -> R<PublicPostInfo> {
        Ok(self.s().public_edit(&space, &post, &text)?.into())
    }

    pub fn public_delete(&self, space: String, post: String) -> R<()> {
        Ok(self.s().public_delete(&space, &post)?)
    }

    pub fn public_report(&self, post: String, reason: String) -> R<()> {
        Ok(self.s().public_report(&post, &reason)?)
    }

    /// Changes that arrived for one space.
    pub fn public_sync(&self, space: String) -> R<u32> {
        Ok(self.s().public_sync(&space)?)
    }

    /// Spaces with changes.
    pub fn public_sync_all(&self) -> R<Vec<String>> {
        Ok(self.s().public_sync_all()?)
    }

    /// The newest posts of a space without subscribing (nothing kept).
    pub fn public_peek(&self, space: String) -> R<Vec<PublicPostInfo>> {
        Ok(posts(self.s().public_peek(&space)?))
    }

    pub fn public_load_older(&self, space: String) -> R<u32> {
        Ok(self.s().public_load_older(&space)?)
    }

    pub fn public_load_comments(&self, space: String, post: String) -> R<Vec<PublicPostInfo>> {
        Ok(posts(self.s().public_load_comments(&space, &post)?))
    }

    pub fn public_posts(&self, space: String, limit: u32) -> R<Vec<PublicPostInfo>> {
        Ok(posts(self.s().public_posts(&space, limit as usize)?))
    }

    pub fn public_comments(&self, space: String, post: String) -> R<Vec<PublicPostInfo>> {
        Ok(posts(self.s().public_comments(&space, &post)?))
    }

    pub fn public_unread(&self, space: String) -> R<u32> {
        Ok(self.s().public_unread(&space)?)
    }

    pub fn public_mark_read(&self, space: String) -> R<()> {
        Ok(self.s().public_mark_read(&space)?)
    }

    // --- private channels (end-to-end) ---

    /// A new private channel (hex id): only admins post, up to 1,000 members.
    pub fn create_channel(&self, name: String) -> R<String> {
        Ok(hex::encode(self.s().create_channel(&name)?))
    }

    pub fn is_channel(&self, group: String) -> R<bool> {
        Ok(self.s().is_channel(&unhex(&group, "group")?)?)
    }

    pub fn may_post(&self, group: String) -> R<bool> {
        Ok(self.s().may_post(&unhex(&group, "group")?)?)
    }

    pub fn may_comment(&self, group: String) -> R<bool> {
        Ok(self.s().may_comment(&unhex(&group, "group")?)?)
    }

    pub fn shows_signatures(&self, group: String) -> R<bool> {
        Ok(self.s().shows_signatures(&unhex(&group, "group")?)?)
    }

    /// Comments on a post (`channel.comments`); returns the comment's id.
    pub fn comment(&self, group: String, post: String, text: String) -> R<String> {
        Ok(self.s().comment(&unhex(&group, "group")?, &post, &text)?)
    }

    pub fn comments(&self, group: String, post: String) -> R<Vec<Message>> {
        Ok(self.s().comments(&unhex(&group, "group")?, &post)?.into_iter().map(Into::into).collect())
    }

    /// The author name to show for message `id`; null: show the channel's
    /// name (`channel.signatures` released).
    pub fn author_shown(&self, group: String, id: String) -> R<Option<String>> {
        let gid = unhex(&group, "group")?;
        let mut s = self.s();
        let m = s.history(&gid, u32::MAX)?.into_iter().find(|m| m.id == id);
        match m {
            Some(m) => Ok(s.author_shown(&gid, &m)?),
            None => Ok(None),
        }
    }
}
