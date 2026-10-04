//! UniFFI bindings of [`tree_client::Session`] for the apps.
//!
//! Every call blocks (network and Argon2id): apps call from a background
//! thread. Group and member ids cross the boundary as lowercase hex.
//! Nothing here adds behaviour; it only converts types.

use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};

use tree_client::{CommitOutcome, Event, FileInfo, GroupStatus, MediaMeta, MemberId, OutboxState, SendOptions, Session, Source, TextOptions, Words};

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
            E::Usage(reason) => TreeError::Usage { reason },
            E::Core(tree_core::error::TreeError::WrongKey) => TreeError::WrongKey,
            other => TreeError::Other { reason: other.to_string() },
        }
    }
}

type R<T> = Result<T, TreeError>;

/// Default share of an upload per call (see `TreeSession::set_upload_slice`).
pub const UPLOAD_SLICE: u64 = 4 << 20;

fn unhex(s: &str, what: &str) -> R<Vec<u8>> {
    hex::decode(s).map_err(|_| TreeError::Usage { reason: format!("{what} must be hex") })
}

fn member(s: &str) -> R<MemberId> {
    MemberId::from_hex(s).ok_or_else(|| TreeError::Usage { reason: "member id must be 64 hex characters".into() })
}

/// An attachment reference (inside an end-to-end encrypted message), with
/// what the sender's app said about the file.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Attachment {
    pub msg_id: String,
    pub view_once: bool,
    pub voice: bool,
    pub duration_ms: Option<u64>,
    /// Server attachment id (empty while the sender's upload runs).
    pub id: String,
    /// The file secret (base64).
    pub key: String,
    /// Plaintext size in bytes.
    pub size: u64,
    pub pt_sha256: String,
    pub name: String,
    pub mime: String,
    /// Format version (2).
    pub version: u32,
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// The sender's preview picture (JPEG or PNG).
    pub thumbnail: Option<Vec<u8>>,
}

impl From<FileInfo> for Attachment {
    fn from(f: FileInfo) -> Self {
        let thumbnail = f.thumbnail();
        Attachment {
            msg_id: f.msg_id,
            view_once: f.view_once,
            voice: f.voice,
            duration_ms: f.duration_ms,
            id: f.id,
            key: f.key,
            size: f.size,
            pt_sha256: f.pt_sha256,
            name: f.name,
            mime: f.mime,
            version: f.v,
            width: f.width,
            height: f.height,
            thumbnail,
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
            size: f.size,
            pt_sha256: f.pt_sha256,
            name: f.name,
            mime: f.mime,
            v: f.version,
            width: f.width,
            height: f.height,
            thumb: f.thumbnail.as_deref().map(tree_client::api::b64),
        }
    }
}

/// How a file is sent, and what the app knows about it (all of it travels
/// inside the encrypted message).
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct MediaOptions {
    pub view_once: bool,
    pub voice: bool,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
    /// A small preview picture the app made (at most 32 KiB).
    pub thumbnail: Option<Vec<u8>>,
}

impl From<MediaOptions> for SendOptions {
    fn from(o: MediaOptions) -> Self {
        SendOptions {
            view_once: o.view_once,
            voice: o.voice,
            meta: MediaMeta { width: o.width, height: o.height, duration_ms: o.duration_ms, thumb: o.thumbnail },
        }
    }
}

/// One upload or download as a progress bar shows it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Transfer {
    pub message_id: String,
    pub upload: bool,
    /// Bytes moved so far, of `total` (encrypted, padded size).
    pub done: u64,
    pub total: u64,
    /// `queued`, `running`, `paused` or `failed`.
    pub state: String,
}

impl From<tree_client::Transfer> for Transfer {
    fn from(t: tree_client::Transfer) -> Self {
        use tree_client::TransferState as S;
        let state = match t.state {
            S::Queued => "queued",
            S::Running => "running",
            S::Paused => "paused",
            S::Failed => "failed",
        };
        Transfer { message_id: t.message_id, upload: t.upload, done: t.done, total: t.total, state: state.into() }
    }
}

/// The network the device is on (decides `user.auto_download`).
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum NetworkKind {
    /// Wi-Fi or another unmetered network (wired).
    Wifi,
    /// A metered mobile network.
    Mobile,
    /// Offline or unknown.
    None,
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
    },
    Edited { group: String, id: String, from: String, text: String },
    Deleted { group: String, id: String, from: String },
    Reaction { group: String, id: String, from: String, emoji: String, remove: bool },
    /// `auto_download`: fetch it now without a tap (`user.auto_download`).
    File { group: String, from: String, name: Option<String>, file: Attachment, request: bool, auto_download: bool },
    Request { group: String, from: String, direct: bool },
    Declined { group: String, from: String, reason: String },
    Joined { group: String },
    Changed { group: String, added: Vec<String>, removed: Vec<String>, epoch: u64, own_commit_discarded: bool, settings_changed: bool },
    Profile { group: String, member: String, name: String },
    KeyChanged { account: String, new_members: Vec<String>, was_verified: bool },
    RosterUpdated { group: String },
    LeaveRequested { group: String, member: String },
    RemovedFromGroup { group: String },
    Held,
    Dropped { reason: String },
    InviteLinkUsed { group: String, account: String },
    Read { group: String, from: String, ids: Vec<String> },
    Typing { group: String, from: String, on: bool },
    GroupSafetyNotice { group: String, adder: String },
    /// A message that waited in the outbox reached the server.
    Sent { group: String, id: Option<String> },
    /// An outbox item was given up; offer `retry_send` / `cancel_send`.
    SendFailed { group: String, id: Option<String>, local_id: String, reason: String },
}

fn ids(v: Vec<MemberId>) -> Vec<String> {
    v.into_iter().map(|m| m.to_hex()).collect()
}

impl From<Event> for TreeEvent {
    fn from(e: Event) -> Self {
        let h = hex::encode;
        match e {
            Event::Text { group, id, from, name, text, request, formatted, mentions_me, preview } => TreeEvent::Text {
                group: h(group),
                id,
                from: from.to_hex(),
                name,
                text,
                request,
                formatted,
                mentions_me,
                preview: preview.map(|p| Preview { url: p.url, title: p.title, description: p.description }),
            },
            Event::Edited { group, id, from, text } => TreeEvent::Edited { group: h(group), id, from: from.to_hex(), text },
            Event::Deleted { group, id, from } => TreeEvent::Deleted { group: h(group), id, from: from.to_hex() },
            Event::Reaction { group, id, from, emoji, remove } => TreeEvent::Reaction { group: h(group), id, from: from.to_hex(), emoji, remove },
            Event::File { group, from, name, file, request, auto_download } => {
                TreeEvent::File { group: h(group), from: from.to_hex(), name, file: file.into(), request, auto_download }
            }
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
            Event::LeaveRequested { group, member } => TreeEvent::LeaveRequested { group: h(group), member: member.to_hex() },
            Event::RemovedFromGroup { group } => TreeEvent::RemovedFromGroup { group: h(group) },
            Event::Held => TreeEvent::Held,
            Event::Dropped { reason } => TreeEvent::Dropped { reason },
            Event::InviteLinkUsed { group, account } => TreeEvent::InviteLinkUsed { group: h(group), account },
            Event::Read { group, from, ids } => TreeEvent::Read { group: h(group), from: from.to_hex(), ids },
            Event::Typing { group, from, on } => TreeEvent::Typing { group: h(group), from: from.to_hex(), on },
            Event::GroupSafetyNotice { group, adder } => TreeEvent::GroupSafetyNotice { group: h(group), adder },
            Event::Sent { group, id } => TreeEvent::Sent { group: h(group), id },
            Event::SendFailed { group, id, local_id, reason } => TreeEvent::SendFailed { group: h(group), id, local_id, reason },
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Message {
    pub id: String,
    pub sender: String,
    pub received_at: i64,
    pub kind: String,
    pub text: Option<String>,
    pub edited: bool,
    pub deleted: bool,
    pub expires_at: Option<i64>,
    /// Emoji and how many members reacted with it.
    pub reactions: Vec<Reaction>,
    /// This device's own message on its way: `pending` (in the outbox),
    /// `failed` (offer retry / cancel), `sent`; empty for received messages
    /// and old ones.
    pub status: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Reaction {
    pub emoji: String,
    pub members: Vec<String>,
}

impl From<tree_client::StoredMessage> for Message {
    fn from(m: tree_client::StoredMessage) -> Self {
        Message {
            id: m.id,
            sender: m.sender,
            received_at: m.received_at,
            kind: m.kind,
            text: m.text,
            edited: m.edited_at.is_some(),
            deleted: m.deleted,
            expires_at: m.expires_at,
            reactions: m.reactions.into_iter().map(|(emoji, members)| Reaction { emoji, members }).collect(),
            status: String::new(),
        }
    }
}

/// `status` of [`Message`] for an outbox state.
fn send_status(s: OutboxState) -> &'static str {
    match s {
        OutboxState::Sent => "sent",
        OutboxState::Failed => "failed",
        _ => "pending",
    }
}

/// A message not sent yet, as an outbox screen shows it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct OutboxEntry {
    pub local_id: String,
    pub group: String,
    pub message_id: Option<String>,
    /// `queued`, `sending`, `retry` or `failed`.
    pub state: String,
    pub attempts: u32,
    /// Unix seconds of the next automatic attempt.
    pub next_at: i64,
    pub last_error: Option<String>,
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
    /// Options the settings screen offers (empty: the feature takes none).
    pub choices: Vec<String>,
}

impl From<tree_core::features::Status> for Feature {
    fn from(s: tree_core::features::Status) -> Self {
        use tree_core::features::LockReason as L;
        Feature {
            key: s.key.to_string(),
            choices: tree_core::features::option_choices(s.key),
            applied: s.state == tree_core::features::State::Applied,
            option: s.option,
            locked_by: s.locked_by.map(|l| match l {
                L::Always(r) => format!("always: {r}"),
                L::Server => "server".into(),
                L::Chat => "chat".into(),
                L::Plan => "plan".into(),
            }),
        }
    }
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
    /// Progress of transfers, read without the session lock.
    transfers: tree_client::Transfers,
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
    fn wrap(mut s: Session) -> std::sync::Arc<Self> {
        let waiter = s.waiter();
        let transfers = s.transfers();
        // A long upload gives the session back after every slice; the app's
        // loop calls `send_pending` again while `uploading` (PROTOCOL.md 6.13).
        s.set_upload_slice(Some(UPLOAD_SLICE));
        std::sync::Arc::new(Self { inner: Mutex::new(Some(s)), waiter, transfers })
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

    pub fn leave(&self, group: String) -> R<()> {
        self.s().leave(&unhex(&group, "group")?)?;
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

    pub fn send_text_with(
        &self,
        group: String,
        text: String,
        formatted: bool,
        mentions: Vec<String>,
        all: bool,
        preview: Option<Preview>,
    ) -> R<String> {
        let o = TextOptions {
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

    /// Sends a file from memory with its details (picture size, length,
    /// preview picture). The upload continues through `send_pending`.
    pub fn send_media(&self, group: String, bytes: Vec<u8>, name: String, mime: String, options: MediaOptions) -> R<Attachment> {
        let o: SendOptions = options.into();
        Ok(self.s().send_media(&unhex(&group, "group")?, Source::Bytes(&bytes), &name, &mime, &o)?.into())
    }

    /// Sends the file at `path` (read once while it is encrypted; up to 2 GiB).
    pub fn send_file_path(&self, group: String, path: String, name: String, mime: String, options: MediaOptions) -> R<Attachment> {
        let o: SendOptions = options.into();
        let p = std::path::PathBuf::from(path);
        Ok(self.s().send_media(&unhex(&group, "group")?, Source::Path(&p), &name, &mime, &o)?.into())
    }

    /// Downloads, checks and decrypts an attachment into memory. The
    /// download runs without holding the session.
    pub fn download(&self, file: Attachment) -> R<Vec<u8>> {
        let f: FileInfo = file.into();
        let d = self.s().downloader();
        let bytes = d.fetch(&f)?;
        self.s().opened(&f)?;
        Ok(bytes)
    }

    /// Downloads, checks and decrypts an attachment into the file `path`
    /// (written only when everything matched; an interrupted download
    /// resumes). Runs without holding the session.
    pub fn download_to(&self, file: Attachment, path: String) -> R<()> {
        let f: FileInfo = file.into();
        let d = self.s().downloader();
        d.fetch_to(&f, std::path::Path::new(&path))?;
        Ok(self.s().opened(&f)?)
    }

    /// Uploads and downloads in progress (without waiting for the session).
    pub fn transfers(&self) -> Vec<Transfer> {
        self.transfers.list().into_iter().map(Into::into).collect()
    }

    /// An upload waits for its next slice: call `send_pending` again.
    pub fn uploading(&self) -> R<bool> {
        Ok(self.s().uploading()?)
    }

    /// Pauses the upload of a file message (later messages of that chat wait).
    pub fn pause_transfer(&self, message_id: String) -> R<()> {
        Ok(self.s().pause_transfer(&message_id)?)
    }

    /// Resumes a paused upload; true if the message went out.
    pub fn resume_transfer(&self, message_id: String) -> R<bool> {
        Ok(self.s().resume_transfer(&message_id)?)
    }

    /// The app reports the network (`user.auto_download`).
    pub fn set_network(&self, network: NetworkKind) {
        let n = match network {
            NetworkKind::Wifi => tree_client::Network::Wifi,
            NetworkKind::Mobile => tree_client::Network::Mobile,
            NetworkKind::None => tree_client::Network::None,
        };
        self.s().set_network(n);
    }

    /// Bytes uploaded per call before the session is given back (`None`:
    /// the whole file in one call).
    pub fn set_upload_slice(&self, bytes: Option<u64>) {
        self.s().set_upload_slice(bytes);
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

    pub fn stranger_labels(&self, account: String) -> R<Labels> {
        let l = self.s().stranger_labels(&account)?;
        Ok(Labels { not_contact: l.not_contact, no_common_group: l.no_common_group, name_unverified: l.name_unverified })
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

    pub fn mute(&self, group: String, on: bool) -> R<()> {
        Ok(self.s().mute(&unhex(&group, "group")?, on)?)
    }

    /// The newest `limit` messages, with the send status of this device's own.
    pub fn history(&self, group: String, limit: u32) -> R<Vec<Message>> {
        let gid = unhex(&group, "group")?;
        let s = self.s();
        let states = s.send_states(&gid)?;
        Ok(s.history(&gid, limit)?
            .into_iter()
            .map(|m| {
                let st = states.get(&m.id).copied();
                let mut m: Message = m.into();
                m.status = st.map(send_status).unwrap_or_default().to_string();
                m
            })
            .collect())
    }

    // --- outbox (reliable sending) ---

    /// Messages not sent yet: pending (retried automatically by `sync`) or
    /// failed (the user retries or cancels them).
    pub fn outbox(&self) -> R<Vec<OutboxEntry>> {
        Ok(self
            .s()
            .outbox()?
            .into_iter()
            .map(|o| OutboxEntry {
                local_id: o.local_id,
                group: hex::encode(o.group),
                message_id: o.message_id,
                state: o.state.as_str().to_string(),
                attempts: o.attempts,
                next_at: o.next_at,
                last_error: o.last_error,
            })
            .collect())
    }

    /// Sends what is due in the outbox now (without receiving).
    pub fn send_pending(&self) -> R<Vec<TreeEvent>> {
        Ok(self.s().send_pending()?.into_iter().map(Into::into).collect())
    }

    /// Retries a failed message now (local id or message id). True if it
    /// went out.
    pub fn retry_send(&self, id: String) -> R<bool> {
        Ok(self.s().retry_send(&id)?)
    }

    /// Gives up a failed message (local id or message id); it leaves the
    /// history on this device.
    pub fn cancel_send(&self, id: String) -> R<()> {
        Ok(self.s().cancel_send(&id)?)
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

    pub fn set_username(&self, name: String, discoverable: bool) -> R<String> {
        Ok(self.s().set_username(&name, discoverable)?)
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
        Ok(self.s().features()?.into_iter().map(Into::into).collect())
    }

    pub fn apply_feature(&self, key: String, option: Option<String>) -> R<Feature> {
        Ok(self.s().apply_feature(&key, option)?.into())
    }

    pub fn release_feature(&self, key: String) -> R<Feature> {
        Ok(self.s().release_feature(&key)?.into())
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
