//! UniFFI bindings of [`tree_client::Session`] for the apps.
//!
//! Every call blocks (network and Argon2id): apps call from a background
//! thread. Group and member ids cross the boundary as lowercase hex.
//! Nothing here adds behaviour; it only converts types.

use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};

use tree_client::{CommitOutcome, Event, FileInfo, GroupStatus, MemberId, Session, TextOptions, Words};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TreeError {
    /// The server refused (`code` as in SERVER_API.md, e.g. `SUSPENDED`).
    #[error("server answered {status} {code}")]
    Server { status: u16, code: String },
    #[error("network: {reason}")]
    Network { reason: String },
    /// A feature-registry code (`LOCKED_BY_CHAT`, `NOT_ADMIN`, ...).
    #[error("feature: {code}")]
    Feature { code: String },
    /// `INVALID_OPTION`: `reason` says which values the feature takes.
    #[error("INVALID_OPTION: {reason}")]
    InvalidOption { reason: String },
    /// Wrong passphrase, or a damaged database.
    #[error("wrong passphrase or damaged database")]
    WrongKey,
    #[error("{reason}")]
    Usage { reason: String },
    #[error("{reason}")]
    Other { reason: String },
}

impl From<tree_client::Error> for TreeError {
    fn from(e: tree_client::Error) -> Self {
        use tree_client::Error as E;
        match e {
            E::Server { status, code } => TreeError::Server { status, code },
            E::Network(reason) => TreeError::Network { reason },
            E::Feature(code) => TreeError::Feature { code },
            E::InvalidOption(reason) => TreeError::InvalidOption { reason },
            E::Usage(reason) => TreeError::Usage { reason },
            E::Core(tree_core::error::TreeError::WrongKey) => TreeError::WrongKey,
            other => TreeError::Other { reason: other.to_string() },
        }
    }
}

type R<T> = Result<T, TreeError>;

fn unhex(s: &str, what: &str) -> R<Vec<u8>> {
    hex::decode(s).map_err(|_| TreeError::Usage { reason: format!("{what} must be hex") })
}

fn member(s: &str) -> R<MemberId> {
    MemberId::from_hex(s).ok_or_else(|| TreeError::Usage { reason: "member id must be 64 hex characters".into() })
}

/// An attachment reference (inside an end-to-end encrypted message).
#[derive(Debug, Clone, uniffi::Record)]
pub struct Attachment {
    pub msg_id: String,
    pub view_once: bool,
    pub voice: bool,
    pub duration_ms: Option<u64>,
    pub id: String,
    pub key: String,
    pub nonce: String,
    pub size: u64,
    pub ct_sha256: String,
    pub pt_sha256: String,
    pub name: String,
    pub mime: String,
}

impl From<FileInfo> for Attachment {
    fn from(f: FileInfo) -> Self {
        Attachment {
            msg_id: f.msg_id,
            view_once: f.view_once,
            voice: f.voice,
            duration_ms: f.duration_ms,
            id: f.id,
            key: f.key,
            nonce: f.nonce,
            size: f.size,
            ct_sha256: f.ct_sha256,
            pt_sha256: f.pt_sha256,
            name: f.name,
            mime: f.mime,
        }
    }
}

impl From<Attachment> for FileInfo {
    fn from(f: Attachment) -> Self {
        FileInfo {
            msg_id: f.msg_id,
            view_once: f.view_once,
            voice: f.voice,
            duration_ms: f.duration_ms,
            id: f.id,
            key: f.key,
            nonce: f.nonce,
            size: f.size,
            ct_sha256: f.ct_sha256,
            pt_sha256: f.pt_sha256,
            name: f.name,
            mime: f.mime,
        }
    }
}

/// What a sync reports (tree_client::Event; ids as hex).
#[derive(Debug, Clone, uniffi::Enum)]
pub enum TreeEvent {
    Text {
        group: String,
        id: String,
        from: String,
        name: Option<String>,
        text: String,
        request: bool,
        formatted: bool,
        mentions_me: bool,
        preview: Option<Preview>,
        /// Sent silently: do not notify (see `should_notify`).
        silent: bool,
    },
    Edited { group: String, id: String, from: String, text: String },
    Deleted { group: String, id: String, from: String },
    Reaction { group: String, id: String, from: String, emoji: String, remove: bool },
    File { group: String, from: String, name: Option<String>, file: Attachment, request: bool },
    Request { group: String, from: String, direct: bool },
    Declined { group: String, from: String, reason: String },
    Joined { group: String },
    Changed { group: String, added: Vec<String>, removed: Vec<String>, epoch: u64, own_commit_discarded: bool, settings_changed: bool },
    Profile { group: String, member: String, name: String },
    KeyChanged { account: String, new_members: Vec<String>, was_verified: bool },
    RosterUpdated { group: String },
    /// `quiet`: the member left quietly (no "left" line is stored).
    LeaveRequested { group: String, member: String, quiet: bool },
    RemovedFromGroup { group: String },
    Held,
    Dropped { reason: String },
    InviteLinkUsed { group: String, account: String },
    Read { group: String, from: String, ids: Vec<String> },
    Typing { group: String, from: String, on: bool },
    GroupSafetyNotice { group: String, adder: String },
}

fn ids(v: Vec<MemberId>) -> Vec<String> {
    v.into_iter().map(|m| m.to_hex()).collect()
}

impl From<Event> for TreeEvent {
    fn from(e: Event) -> Self {
        let h = hex::encode;
        match e {
            Event::Text { group, id, from, name, text, request, formatted, mentions_me, preview, silent } => TreeEvent::Text {
                group: h(group),
                id,
                from: from.to_hex(),
                name,
                text,
                request,
                formatted,
                mentions_me,
                preview: preview.map(|p| Preview { url: p.url, title: p.title, description: p.description }),
                silent,
            },
            Event::Edited { group, id, from, text } => TreeEvent::Edited { group: h(group), id, from: from.to_hex(), text },
            Event::Deleted { group, id, from } => TreeEvent::Deleted { group: h(group), id, from: from.to_hex() },
            Event::Reaction { group, id, from, emoji, remove } => TreeEvent::Reaction { group: h(group), id, from: from.to_hex(), emoji, remove },
            Event::File { group, from, name, file, request } => TreeEvent::File { group: h(group), from: from.to_hex(), name, file: file.into(), request },
            Event::Request { group, from, direct } => TreeEvent::Request { group: h(group), from, direct },
            Event::Declined { group, from, reason } => TreeEvent::Declined { group: h(group), from, reason },
            Event::Joined { group } => TreeEvent::Joined { group: h(group) },
            Event::Changed { group, added, removed, epoch, own_commit_discarded, settings_changed } => TreeEvent::Changed {
                group: h(group),
                added: ids(added),
                removed: ids(removed),
                epoch,
                own_commit_discarded,
                settings_changed,
            },
            Event::Profile { group, member, name } => TreeEvent::Profile { group: h(group), member: member.to_hex(), name },
            Event::KeyChanged { account, new_members, was_verified } => TreeEvent::KeyChanged { account, new_members: ids(new_members), was_verified },
            Event::RosterUpdated { group } => TreeEvent::RosterUpdated { group: h(group) },
            Event::LeaveRequested { group, member, quiet } => TreeEvent::LeaveRequested { group: h(group), member: member.to_hex(), quiet },
            Event::RemovedFromGroup { group } => TreeEvent::RemovedFromGroup { group: h(group) },
            Event::Held => TreeEvent::Held,
            Event::Dropped { reason } => TreeEvent::Dropped { reason },
            Event::InviteLinkUsed { group, account } => TreeEvent::InviteLinkUsed { group: h(group), account },
            Event::Read { group, from, ids } => TreeEvent::Read { group: h(group), from: from.to_hex(), ids },
            Event::Typing { group, from, on } => TreeEvent::Typing { group: h(group), from: from.to_hex(), on },
            Event::GroupSafetyNotice { group, adder } => TreeEvent::GroupSafetyNotice { group: h(group), adder },
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Message {
    pub id: String,
    pub sender: String,
    pub received_at: i64,
    /// `text`, `file`, or a line about a member who went: `left` (asked to
    /// leave) or `removed` (`sender` is that member, `who` its name). A
    /// quiet leave has no line.
    pub kind: String,
    pub text: Option<String>,
    pub edited: bool,
    pub deleted: bool,
    pub expires_at: Option<i64>,
    /// Emoji and how many members reacted with it.
    pub reactions: Vec<Reaction>,
    /// Sent silently (no notification).
    pub silent: bool,
    /// For `left` / `removed`: the member's name when it went.
    pub who: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Reaction {
    pub emoji: String,
    pub members: Vec<String>,
}

impl From<tree_client::StoredMessage> for Message {
    fn from(m: tree_client::StoredMessage) -> Self {
        let meta = tree_client::organize::message_meta(&m);
        Message {
            silent: meta.silent,
            who: meta.name,
            id: m.id,
            sender: m.sender,
            received_at: m.received_at,
            kind: m.kind,
            text: m.text,
            edited: m.edited_at.is_some(),
            deleted: m.deleted,
            expires_at: m.expires_at,
            reactions: m.reactions.into_iter().map(|(emoji, members)| Reaction { emoji, members }).collect(),
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Member {
    pub id: String,
    pub device: Option<String>,
    pub name: Option<String>,
    pub duplicate_name: bool,
    pub admin: bool,
    /// For `safety_number` / `verify`.
    pub account: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Contact {
    pub account: String,
    pub members: Vec<String>,
    pub verified: bool,
    pub accepted: bool,
    pub blocked: bool,
}

/// One setting as a settings screen draws it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Feature {
    pub key: String,
    pub applied: bool,
    pub option: Option<String>,
    /// Why it cannot be changed here, if it cannot (`always: ...`, `server`,
    /// `chat`, `plan`).
    pub locked_by: Option<String>,
    /// Values the app offers for the option (empty: the feature takes none).
    pub choices: Vec<String>,
    /// A release was asked for but takes effect only then (unix seconds);
    /// until then the feature still works and `applied` stays true. Show
    /// "release pending until <date>".
    pub release_pending_until: Option<i64>,
}

impl From<tree_core::features::Status> for Feature {
    fn from(s: tree_core::features::Status) -> Self {
        use tree_core::features::LockReason as L;
        Feature {
            key: s.key.to_string(),
            applied: s.state == tree_core::features::State::Applied,
            option: s.option,
            choices: if s.locked_by.is_some() { Vec::new() } else { tree_core::features::option_choices(s.key) },
            locked_by: s.locked_by.map(|l| match l {
                L::Always(r) => format!("always: {r}"),
                L::Server => "server".into(),
                L::Chat => "chat".into(),
                L::Plan => "plan".into(),
            }),
            release_pending_until: None,
        }
    }
}

/// A user setting with what only the session knows (a pending release).
fn user_feature(s: &Session, f: tree_core::features::Status) -> R<Feature> {
    let pending = s.release_pending(f.key)?;
    Ok(Feature { release_pending_until: pending, ..f.into() })
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatFeature {
    pub key: String,
    pub applied: bool,
    pub option: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupInfo {
    pub id: String,
    pub name: Option<String>,
    pub epoch: u64,
    pub admins: Vec<String>,
    /// Chat settings the admins changed from their defaults.
    pub features: Vec<ChatFeature>,
    /// `accepted`, `request` or `declined`.
    pub status: String,
    pub request_from: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Recovery {
    pub active: bool,
    /// `replace` or `release`, pending until `pending_at` (unix seconds).
    pub pending: Option<String>,
    pub pending_at: Option<i64>,
}

impl From<tree_client::RecoveryStatus> for Recovery {
    fn from(s: tree_client::RecoveryStatus) -> Self {
        Recovery { active: s.active, pending_at: s.pending.as_ref().map(|p| p.1), pending: s.pending.map(|p| p.0) }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct NewPhrase {
    pub words: String,
    pub status: Recovery,
}

/// A link preview made by the sender's app (receivers never fetch the page).
#[derive(Debug, Clone, uniffi::Record)]
pub struct Preview {
    pub url: String,
    pub title: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Labels {
    pub not_contact: bool,
    pub no_common_group: bool,
    pub name_unverified: bool,
}

/// One chat as the chat list shows it (`chat_list` gives them in order:
/// pinned first, then by last activity; archived ones go in their own
/// section).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatEntry {
    pub group: String,
    pub pinned: bool,
    pub archived: bool,
    pub muted: bool,
    /// End of a timed mute (unix seconds); none while muted until unmuted.
    pub muted_until: Option<i64>,
    pub marked_unread: bool,
    pub unread: u32,
    pub draft: Option<String>,
    pub last_activity: i64,
}

impl From<tree_client::organize::ChatState> for ChatEntry {
    fn from(c: tree_client::organize::ChatState) -> Self {
        ChatEntry {
            group: hex::encode(c.group),
            pinned: c.pinned,
            archived: c.archived,
            muted: c.muted,
            muted_until: c.muted_until,
            marked_unread: c.marked_unread,
            unread: c.unread,
            draft: c.draft,
            last_activity: c.last_activity,
        }
    }
}

/// A mute duration the apps offer: `label` (`1h`, `8h`, `1w`, `forever`)
/// and seconds (none: until unmuted).
#[derive(Debug, Clone, uniffi::Record)]
pub struct MuteChoice {
    pub label: String,
    pub seconds: Option<i64>,
}

/// The mute durations to offer.
#[uniffi::export]
pub fn mute_choices() -> Vec<MuteChoice> {
    tree_client::organize::MUTE_CHOICES.iter().map(|(l, s)| MuteChoice { label: l.to_string(), seconds: *s }).collect()
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatFolder {
    pub name: String,
    /// `user`, `unread`, `direct`, `groups` or `quiet`.
    pub kind: String,
    pub chats: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ReportReceipt {
    pub id: String,
    pub verified: bool,
}

/// Result of a commit: `accepted` with the new epoch, or lost to another
/// member's commit (sync and try again).
#[derive(Debug, Clone, uniffi::Record)]
pub struct Commit {
    pub accepted: bool,
    pub epoch: u64,
}

impl From<CommitOutcome> for Commit {
    fn from(o: CommitOutcome) -> Self {
        match o {
            CommitOutcome::Accepted { epoch } => Commit { accepted: true, epoch },
            CommitOutcome::Lost => Commit { accepted: false, epoch: 0 },
        }
    }
}

/// One profile (device) of a Tree account.
#[derive(uniffi::Object)]
pub struct TreeSession {
    /// `None` once the account was deleted.
    inner: Mutex<Option<Session>>,
    waiter: (tree_client::Api, tree_client::Creds),
}

/// The session behind the lock (panics if the account was deleted: the app
/// must drop the object then; UniFFI turns the panic into an error).
struct Live<'a>(MutexGuard<'a, Option<Session>>);

impl Deref for Live<'_> {
    type Target = Session;
    fn deref(&self) -> &Session {
        self.0.as_ref().expect("the account was deleted")
    }
}

impl DerefMut for Live<'_> {
    fn deref_mut(&mut self) -> &mut Session {
        self.0.as_mut().expect("the account was deleted")
    }
}

impl TreeSession {
    fn wrap(s: Session) -> std::sync::Arc<Self> {
        let waiter = s.waiter();
        std::sync::Arc::new(Self { inner: Mutex::new(Some(s)), waiter })
    }

    fn s(&self) -> Live<'_> {
        Live(self.inner.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

#[uniffi::export]
impl TreeSession {
    /// A new account on this device. `pow_bits` as the server requires (20).
    #[uniffi::constructor]
    pub fn create(path: String, passphrase: String, name: String, server: String, pow_bits: u32) -> R<std::sync::Arc<Self>> {
        Ok(Self::wrap(Session::create(&path, &passphrase, &name, &server, pow_bits)?))
    }

    /// Opens an existing profile (resubmits pending commits).
    #[uniffi::constructor]
    pub fn open(path: String, passphrase: String) -> R<std::sync::Arc<Self>> {
        Ok(Self::wrap(Session::open(&path, &passphrase)?.0))
    }

    /// A new device for the account behind the recovery phrase.
    #[uniffi::constructor]
    pub fn recover(
        path: String,
        passphrase: String,
        name: String,
        server: String,
        phrase: String,
        revoke_others: bool,
        pow_bits: u32,
    ) -> R<std::sync::Arc<Self>> {
        Ok(Self::wrap(Session::recover(&path, &passphrase, &name, &server, &phrase, revoke_others, pow_bits)?))
    }

    pub fn name(&self) -> String {
        self.s().name().to_string()
    }
    pub fn account_id(&self) -> String {
        self.s().account_id().to_string()
    }
    pub fn device_id(&self) -> String {
        self.s().device_id().to_string()
    }
    pub fn member_id(&self) -> String {
        self.s().member_id().to_hex()
    }

    // --- sync ---

    /// Long-polls up to `wait` seconds until something is in the mailbox,
    /// without blocking other calls on this session; then call `sync(0)`.
    pub fn wait(&self, wait: u64) -> R<bool> {
        Ok(self.waiter.0.wait_pending(&self.waiter.1, wait)?)
    }

    /// Receives and processes everything waiting (long-polls up to `wait`
    /// seconds; holds the session meanwhile, prefer `wait` + `sync(0)`).
    pub fn sync(&self, wait: u64) -> R<Vec<TreeEvent>> {
        Ok(self.s().sync(wait)?.into_iter().map(Into::into).collect())
    }

    /// Endpoint of a push gateway (UnifiedPush style) or `None`.
    pub fn set_push_endpoint(&self, endpoint: Option<String>) -> R<()> {
        Ok(self.s().set_push_endpoint(endpoint.as_deref())?)
    }

    // --- groups ---

    pub fn groups(&self) -> R<Vec<String>> {
        Ok(self.s().group_ids()?.into_iter().map(hex::encode).collect())
    }

    pub fn create_group(&self) -> R<String> {
        Ok(hex::encode(self.s().create_group()?))
    }

    pub fn group(&self, group: String) -> R<GroupInfo> {
        let gid = unhex(&group, "group")?;
        let mut s = self.s();
        let st = s.group_settings(&gid)?;
        let (status, request_from) = match s.group_status(&gid)? {
            GroupStatus::Accepted => ("accepted", None),
            GroupStatus::Request { from } => ("request", from),
            GroupStatus::Declined => ("declined", None),
        };
        Ok(GroupInfo {
            id: group,
            name: st.name.clone(),
            epoch: s.epoch(&gid)?,
            admins: ids(st.admins.clone()),
            features: st.features.iter().map(|(k, v)| ChatFeature { key: k.clone(), applied: v.applied, option: v.option.clone() }).collect(),
            status: status.into(),
            request_from,
        })
    }

    pub fn members(&self, group: String) -> R<Vec<Member>> {
        let gid = unhex(&group, "group")?;
        let mut s = self.s();
        let admins = s.group_settings(&gid)?.admins;
        Ok(s.members(&gid)?
            .into_iter()
            .map(|m| Member {
                admin: admins.contains(&m.id),
                id: m.id.to_hex(),
                device: m.device,
                name: m.name,
                duplicate_name: m.duplicate_name,
                account: m.account,
            })
            .collect())
    }

    /// Adds every device of an account (or `@username`).
    pub fn invite(&self, group: String, account_or_username: String) -> R<Commit> {
        let gid = unhex(&group, "group")?;
        let mut s = self.s();
        let account = if account_or_username.starts_with('@') {
            s.find(&account_or_username)?.ok_or_else(|| TreeError::Usage { reason: "no such @username".into() })?
        } else {
            account_or_username
        };
        Ok(s.invite(&gid, &account)?.0.into())
    }

    pub fn remove(&self, group: String, members: Vec<String>) -> R<Commit> {
        let gid = unhex(&group, "group")?;
        let m = members.iter().map(|x| member(x)).collect::<R<Vec<_>>>()?;
        Ok(self.s().remove(&gid, &m)?.into())
    }

    pub fn refresh_keys(&self, group: String) -> R<Commit> {
        Ok(self.s().refresh_keys(&unhex(&group, "group")?)?.into())
    }

    /// Deletes the account everywhere and this device's profile at `path`
    /// (the path it was created or opened with). The object is unusable
    /// afterwards.
    pub fn delete_account(&self, path: String) -> R<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let s = g.take().ok_or_else(|| TreeError::Usage { reason: "already deleted".into() })?;
        Ok(s.delete_account(&path)?)
    }

    /// After a suspected compromise: new keys in every group now. (Regular
    /// refreshes happen by themselves during `sync`.)
    pub fn refresh_all(&self) -> R<Vec<String>> {
        Ok(self.s().refresh_all()?.into_iter().map(hex::encode).collect())
    }

    /// Asks the admins to remove this device. `quiet`: the others' apps
    /// show no "left" line (the member list still changes for everyone).
    pub fn leave(&self, group: String, quiet: bool) -> R<()> {
        let gid = unhex(&group, "group")?;
        if quiet {
            self.s().leave_quietly(&gid)?;
        } else {
            self.s().leave(&gid)?;
        }
        Ok(())
    }

    pub fn make_admin(&self, group: String, member_id: String, admin: bool) -> R<Commit> {
        Ok(self.s().make_admin(&unhex(&group, "group")?, member(&member_id)?, admin)?.into())
    }

    pub fn set_group_name(&self, group: String, name: Option<String>) -> R<Commit> {
        Ok(self.s().set_group_name(&unhex(&group, "group")?, name)?.into())
    }

    /// Admins: apply or release a chat setting for everyone.
    pub fn set_chat_feature(&self, group: String, key: String, apply: bool, option: Option<String>) -> R<Commit> {
        Ok(self.s().set_chat_feature(&unhex(&group, "group")?, &key, apply, option)?.into())
    }

    /// The group's chat settings for a settings screen (admins change them
    /// with `set_chat_feature`).
    pub fn chat_features(&self, group: String) -> R<Vec<Feature>> {
        Ok(self.s().chat_features(&unhex(&group, "group")?)?.into_iter().map(Into::into).collect())
    }

    pub fn screenshot_blocked(&self, group: String) -> R<bool> {
        Ok(self.s().screenshot_blocked(&unhex(&group, "group")?)?)
    }

    pub fn set_screenshot_block(&self, group: String, on: bool) -> R<()> {
        Ok(self.s().set_screenshot_block(&unhex(&group, "group")?, on)?)
    }

    // --- invite links ---

    pub fn create_invite_link(&self, group: String, lifetime_secs: i64, max_uses: u32) -> R<String> {
        Ok(self.s().create_invite_link(&unhex(&group, "group")?, lifetime_secs, max_uses)?)
    }

    pub fn revoke_invite_links(&self, group: String) -> R<()> {
        Ok(self.s().revoke_invite_links(&unhex(&group, "group")?)?)
    }

    /// Returns the account that will add this device.
    pub fn join_invite_link(&self, link: String) -> R<String> {
        Ok(self.s().join_invite_link(&link)?)
    }

    // --- messages ---

    pub fn send_text(&self, group: String, text: String) -> R<String> {
        Ok(self.s().send_text(&unhex(&group, "group")?, &text)?)
    }

    /// `silent`: the receivers' apps do not notify.
    #[allow(clippy::too_many_arguments)]
    pub fn send_text_with(
        &self,
        group: String,
        text: String,
        formatted: bool,
        mentions: Vec<String>,
        all: bool,
        preview: Option<Preview>,
        silent: bool,
    ) -> R<String> {
        let o = TextOptions {
            silent,
            formatted,
            mentions: mentions.iter().map(|m| member(m)).collect::<R<_>>()?,
            all,
            preview: preview.map(|p| tree_client::payload::LinkPreview { url: p.url, title: p.title, description: p.description }),
        };
        Ok(self.s().send_text_with(&unhex(&group, "group")?, &text, &o)?)
    }

    pub fn edit(&self, group: String, id: String, text: String) -> R<()> {
        Ok(self.s().edit(&unhex(&group, "group")?, &id, &text)?)
    }

    pub fn delete_for_all(&self, group: String, id: String) -> R<()> {
        Ok(self.s().delete_for_all(&unhex(&group, "group")?, &id)?)
    }

    pub fn react(&self, group: String, id: String, emoji: String, remove: bool) -> R<()> {
        Ok(self.s().react(&unhex(&group, "group")?, &id, &emoji, remove)?)
    }

    pub fn send_file(&self, group: String, bytes: Vec<u8>, name: String, mime: String, view_once: bool) -> R<Attachment> {
        Ok(self.s().send_file(&unhex(&group, "group")?, &bytes, &name, &mime, view_once)?.into())
    }

    pub fn send_voice(&self, group: String, bytes: Vec<u8>, mime: String, duration_ms: u64) -> R<Attachment> {
        Ok(self.s().send_voice(&unhex(&group, "group")?, &bytes, &mime, duration_ms)?.into())
    }

    /// Downloads, checks and decrypts an attachment.
    pub fn download(&self, file: Attachment) -> R<Vec<u8>> {
        Ok(self.s().download(&file.into())?)
    }

    /// The user opened the chat and saw these messages (sends a read
    /// receipt if `user.read_receipts`; resets the unread count).
    pub fn mark_read(&self, group: String, ids: Vec<String>) -> R<()> {
        Ok(self.s().mark_read(&unhex(&group, "group")?, &ids)?)
    }

    pub fn read_by(&self, group: String, id: String) -> R<Vec<String>> {
        Ok(self.s().read_by(&unhex(&group, "group")?, &id)?)
    }

    /// The app came to the foreground (`user.last_seen`).
    pub fn announce_seen(&self, group: String) -> R<()> {
        Ok(self.s().announce_seen(&unhex(&group, "group")?)?)
    }

    pub fn last_seen(&self, group: String, member_id: String) -> R<Option<i64>> {
        Ok(self.s().last_seen(&unhex(&group, "group")?, &member(&member_id)?)?)
    }

    pub fn set_typing(&self, group: String, on: bool) -> R<()> {
        Ok(self.s().set_typing(&unhex(&group, "group")?, on)?)
    }

    pub fn unread(&self, group: String) -> R<u32> {
        Ok(self.s().unread(&unhex(&group, "group")?)?)
    }

    /// The notes chat (created on first use), or none if hidden.
    pub fn note_to_self(&self) -> R<Option<String>> {
        Ok(self.s().note_to_self()?.map(hex::encode))
    }

    /// None while `user.stranger_labels` is released (show no labels).
    pub fn stranger_labels(&self, account: String) -> R<Option<Labels>> {
        let l = self.s().stranger_labels(&account)?;
        Ok(l.map(|l| Labels { not_contact: l.not_contact, no_common_group: l.no_common_group, name_unverified: l.name_unverified }))
    }

    pub fn folders(&self) -> R<Vec<ChatFolder>> {
        Ok(self.s().folders()?.into_iter().map(|f| ChatFolder { name: f.name, kind: f.kind, chats: f.chats }).collect())
    }

    pub fn create_folder(&self, name: String) -> R<()> {
        Ok(self.s().create_folder(&name)?)
    }

    pub fn delete_folder(&self, name: String) -> R<()> {
        Ok(self.s().delete_folder(&name)?)
    }

    pub fn file_chat(&self, folder: String, group: String, add: bool) -> R<()> {
        Ok(self.s().file_chat(&folder, &unhex(&group, "group")?, add)?)
    }

    /// Mutes until unmuted (`on`) or unmutes.
    pub fn mute(&self, group: String, on: bool) -> R<()> {
        Ok(self.s().mute(&unhex(&group, "group")?, on)?)
    }

    /// Mutes for `seconds` (one of `mute_choices`), or until unmuted
    /// (none). Returns when the mute ends.
    pub fn mute_for(&self, group: String, seconds: Option<i64>) -> R<Option<i64>> {
        Ok(self.s().mute_for(&unhex(&group, "group")?, seconds)?)
    }

    /// Whether to notify for a new message (not while muted, never for a
    /// silent message).
    pub fn should_notify(&self, group: String, silent: bool) -> R<bool> {
        Ok(self.s().should_notify(&unhex(&group, "group")?, silent)?)
    }

    pub fn archive_chat(&self, group: String, on: bool) -> R<()> {
        Ok(self.s().archive_chat(&unhex(&group, "group")?, on)?)
    }

    /// At most five pinned chats; pinning a sixth is a `Usage` error.
    pub fn pin_chat(&self, group: String, on: bool) -> R<()> {
        Ok(self.s().pin_chat(&unhex(&group, "group")?, on)?)
    }

    pub fn move_pinned_chat(&self, group: String, to: u32) -> R<()> {
        Ok(self.s().move_pinned_chat(&unhex(&group, "group")?, to as usize)?)
    }

    pub fn mark_unread(&self, group: String, on: bool) -> R<()> {
        Ok(self.s().mark_unread(&unhex(&group, "group")?, on)?)
    }

    /// Keeps the unsent text (empty deletes it); false if not kept
    /// (`user.drafts` released).
    pub fn set_draft(&self, group: String, text: String) -> R<bool> {
        Ok(self.s().set_draft(&unhex(&group, "group")?, &text)?)
    }

    pub fn draft(&self, group: String) -> R<Option<String>> {
        Ok(self.s().draft(&unhex(&group, "group")?)?)
    }

    /// Every chat in list order (pinned first, then by last activity).
    pub fn chat_list(&self) -> R<Vec<ChatEntry>> {
        Ok(self.s().chat_list()?.into_iter().map(Into::into).collect())
    }

    pub fn history(&self, group: String, limit: u32) -> R<Vec<Message>> {
        Ok(self.s().history(&unhex(&group, "group")?, limit)?.into_iter().map(Into::into).collect())
    }

    pub fn search(&self, needle: String) -> R<Vec<Message>> {
        Ok(self.s().search(&needle)?.into_iter().map(Into::into).collect())
    }

    /// Reports messages of one sender (PROTOCOL.md 8.5).
    pub fn report(&self, group: String, ids: Vec<String>, reason: String) -> R<ReportReceipt> {
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        let r = self.s().report(&unhex(&group, "group")?, &ids, &reason)?;
        Ok(ReportReceipt { id: r.id, verified: r.verified })
    }

    // --- people ---

    /// Findable or hidden as `user.discoverable` says.
    pub fn set_username(&self, name: String) -> R<String> {
        Ok(self.s().set_username(&name)?)
    }

    pub fn release_username(&self) -> R<()> {
        Ok(self.s().release_username()?)
    }

    pub fn username(&self) -> R<Option<String>> {
        Ok(self.s().username()?)
    }

    /// Account id behind a @username, if discoverable.
    pub fn find(&self, username: String) -> R<Option<String>> {
        Ok(self.s().find(&username)?)
    }

    /// `tree://u/...` while `user.username_link` is applied (it needs a
    /// @username); the QR code shows the same text.
    pub fn username_link(&self) -> R<Option<String>> {
        Ok(self.s().username_link()?)
    }

    /// A new link; the old one stops working, the @username stays.
    pub fn reset_username_link(&self) -> R<String> {
        Ok(self.s().reset_username_link()?)
    }

    /// The account behind a username link, if it still works.
    pub fn find_by_link(&self, link: String) -> R<Option<String>> {
        Ok(self.s().find_by_link(&link)?)
    }

    /// Scanned QR code or opened link: adds the account as a contact.
    pub fn add_contact_by_link(&self, link: String) -> R<Option<String>> {
        Ok(self.s().add_contact_by_link(&link)?)
    }

    pub fn contacts(&self) -> R<Vec<Contact>> {
        Ok(self
            .s()
            .contacts()?
            .into_iter()
            .map(|c| Contact { account: c.account, members: c.members, verified: c.verified, accepted: c.accepted, blocked: c.blocked })
            .collect())
    }

    pub fn add_contact(&self, account: String) -> R<()> {
        Ok(self.s().add_contact(&account)?)
    }

    pub fn block(&self, account: String) -> R<()> {
        Ok(self.s().block(&account)?)
    }

    pub fn unblock(&self, account: String) -> R<()> {
        Ok(self.s().unblock(&account)?)
    }

    pub fn accept_request(&self, group: String) -> R<()> {
        Ok(self.s().accept_request(&unhex(&group, "group")?)?)
    }

    pub fn decline_request(&self, group: String, block: bool) -> R<()> {
        Ok(self.s().decline(&unhex(&group, "group")?, block)?)
    }

    /// 60 digits to compare with the contact (PROTOCOL.md 5.4).
    pub fn safety_number(&self, account: String) -> R<String> {
        Ok(self.s().safety_number(&account)?)
    }

    /// QR payload to show; the other side scans it and calls `verify`.
    pub fn safety_qr(&self, account: String) -> R<Vec<u8>> {
        Ok(self.s().safety_qr(&account)?)
    }

    pub fn verify(&self, account: String, scanned_qr: Option<Vec<u8>>) -> R<()> {
        Ok(self.s().verify(&account, scanned_qr.as_deref())?)
    }

    // --- settings ---

    /// Every user setting with its state, for the settings screen.
    pub fn features(&self) -> R<Vec<Feature>> {
        let s = self.s();
        s.features()?.into_iter().map(|f| user_feature(&s, f)).collect()
    }

    /// `option`: one of `option_choices(key)` or another value of the
    /// feature's format; anything else is `InvalidOption`.
    pub fn apply_feature(&self, key: String, option: Option<String>) -> R<Feature> {
        let s = self.s();
        let f = s.apply_feature(&key, option)?;
        user_feature(&s, f)
    }

    /// Check `release_pending_until` in the answer: some releases (the
    /// recovery phrase without its words) take effect only later.
    pub fn release_feature(&self, key: String) -> R<Feature> {
        let s = self.s();
        let f = s.release_feature(&key)?;
        user_feature(&s, f)
    }

    /// A new recovery phrase (shown once, never stored); `korean` picks the
    /// Korean word list. With the `current` phrase the old one stops working
    /// at once; otherwise only after 7 days (`status.pending`).
    pub fn new_recovery_phrase(&self, words: u32, korean: bool, current: Option<String>) -> R<NewPhrase> {
        let list = if korean { Words::Korean } else { Words::English };
        let (p, st) = self.s().new_recovery_phrase(words as usize, list, current.as_deref())?;
        Ok(NewPhrase { words: p.words().to_string(), status: st.into() })
    }

    pub fn release_recovery(&self, current: Option<String>) -> R<Recovery> {
        Ok(self.s().release_recovery(current.as_deref())?.into())
    }

    /// Warn the user if `pending` is set and they did not ask for it.
    pub fn recovery_status(&self) -> R<Recovery> {
        Ok(self.s().recovery_status()?.into())
    }
}
