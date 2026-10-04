//! Rich chats, wave 2 part A: pins, polls, scheduled messages, forwarding,
//! reminders, export and storage clean-up (`tree_client::{pins, polls,
//! schedule, forward, storage_clean}`). Only type conversions.

use super::*;

/// A pinned message (newest pin first).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PinnedMessage {
    pub message_id: String,
    /// Member id of who pinned it.
    pub by: String,
    pub pinned_at: i64,
    /// When it drops off on this device; null = until unpinned.
    pub until: Option<i64>,
    pub kind: String,
    pub text: Option<String>,
}

/// A pin expiry the apps offer (`24h`, `7d`, `30d`, `forever`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PinChoice {
    pub label: String,
    pub seconds: Option<i64>,
}

#[uniffi::export]
pub fn pin_choices() -> Vec<PinChoice> {
    tree_client::pins::PIN_CHOICES.iter().map(|(l, s)| PinChoice { label: l.to_string(), seconds: *s }).collect()
}

/// A poll with its tally as counted on this device.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PollInfo {
    pub id: String,
    pub creator: String,
    pub question: String,
    pub options: Vec<String>,
    pub multi: bool,
    /// The apps do not show who voted. Votes still reach every member's
    /// device authenticated as their sender (see APP_PROTOCOL.md).
    pub anonymous: bool,
    pub closed: bool,
    pub closes_at: Option<i64>,
    pub counts: Vec<u32>,
    pub voters: u32,
    /// This device's own choices.
    pub mine: Vec<u32>,
    /// Member ids per option; empty lists for anonymous polls.
    pub voters_by_option: Vec<Vec<String>>,
}

impl From<tree_client::polls::PollView> for PollInfo {
    fn from(p: tree_client::polls::PollView) -> Self {
        PollInfo {
            id: p.id,
            creator: p.creator.to_hex(),
            question: p.question,
            options: p.options,
            multi: p.multi,
            anonymous: p.anonymous,
            closed: p.closed,
            closes_at: p.closes_at,
            counts: p.counts,
            voters: p.voters,
            mine: p.mine,
            voters_by_option: p.voters_by_option.into_iter().map(ids).collect(),
        }
    }
}

/// A message waiting on this device for its time.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ScheduledMessage {
    pub id: String,
    pub group: String,
    pub text: String,
    pub at: i64,
    pub silent: bool,
}

impl From<tree_client::schedule::Scheduled> for ScheduledMessage {
    fn from(s: tree_client::schedule::Scheduled) -> Self {
        ScheduledMessage { id: s.id, group: s.group, text: s.text, at: s.at, silent: s.silent }
    }
}

/// A reminder about a message (local only).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ReminderInfo {
    pub id: String,
    pub group: String,
    pub message_id: String,
    pub at: i64,
    /// The message's text now; null if it is gone.
    pub text: Option<String>,
}

impl From<tree_client::schedule::Reminder> for ReminderInfo {
    fn from(r: tree_client::schedule::Reminder) -> Self {
        ReminderInfo { id: r.id, group: r.group, message_id: r.message_id, at: r.at, text: r.text }
    }
}

/// A chat's history as plain text and JSON.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatExportFiles {
    pub text: String,
    pub json: String,
}

/// What a storage clean-up deleted.
#[derive(Debug, Clone, uniffi::Record)]
pub struct StorageCleanReport {
    pub files: u32,
    pub bytes: u64,
}

#[uniffi::export]
impl TreeSession {
    // --- pins (chat.pins) ---

    /// Pins a message for everyone; `ttl_secs` from `pin_choices` (null:
    /// until unpinned). Admins, or either person in a 1:1.
    pub fn pin_message(&self, group: String, id: String, ttl_secs: Option<i64>) -> R<()> {
        Ok(self.s().pin_message(&unhex(&group, "group")?, &id, ttl_secs)?)
    }

    pub fn unpin_message(&self, group: String, id: String) -> R<()> {
        Ok(self.s().unpin_message(&unhex(&group, "group")?, &id)?)
    }

    /// The chat's pins, newest first (expired ones dropped).
    pub fn pins(&self, group: String) -> R<Vec<PinnedMessage>> {
        Ok(self
            .s()
            .pins(&unhex(&group, "group")?)?
            .into_iter()
            .map(|p| PinnedMessage {
                message_id: p.message_id,
                by: p.by.to_hex(),
                pinned_at: p.pinned_at,
                until: p.until,
                kind: p.kind,
                text: p.text,
            })
            .collect())
    }

    /// Whether to show the pin action in this chat.
    pub fn may_pin(&self, group: String) -> R<bool> {
        Ok(self.s().may_pin(&unhex(&group, "group")?)?)
    }

    // --- polls (chat.polls) ---

    /// Starts a poll; `close_in_secs` null = open until its creator closes it.
    pub fn create_poll(
        &self,
        group: String,
        question: String,
        options: Vec<String>,
        multi: bool,
        anonymous: bool,
        close_in_secs: Option<i64>,
    ) -> R<String> {
        let o = tree_client::polls::PollOptions { multi, anonymous, close_in: close_in_secs };
        Ok(self.s().create_poll(&unhex(&group, "group")?, &question, &options, &o)?)
    }

    /// This member's whole vote (option indexes); empty takes it back.
    pub fn vote(&self, group: String, poll: String, choices: Vec<u32>) -> R<()> {
        Ok(self.s().vote(&unhex(&group, "group")?, &poll, &choices)?)
    }

    pub fn close_poll(&self, group: String, poll: String) -> R<()> {
        Ok(self.s().close_poll(&unhex(&group, "group")?, &poll)?)
    }

    pub fn poll(&self, group: String, poll: String) -> R<Option<PollInfo>> {
        Ok(self.s().poll(&unhex(&group, "group")?, &poll)?.map(Into::into))
    }

    // --- scheduled messages (device only) ---

    /// Sends `text` at `at` (unix seconds) from this device: the app must be
    /// running then, or the next sync sends it.
    pub fn schedule_text(&self, group: String, text: String, at: i64, silent: bool) -> R<String> {
        Ok(self.s().schedule_text(&unhex(&group, "group")?, &text, at, silent)?)
    }

    pub fn scheduled(&self, group: Option<String>) -> R<Vec<ScheduledMessage>> {
        let g = group.map(|g| unhex(&g, "group")).transpose()?;
        Ok(self.s().scheduled(g.as_deref())?.into_iter().map(Into::into).collect())
    }

    pub fn edit_scheduled(&self, id: String, text: Option<String>, at: Option<i64>) -> R<ScheduledMessage> {
        Ok(self.s().edit_scheduled(&id, text.as_deref(), at)?.into())
    }

    pub fn cancel_scheduled(&self, id: String) -> R<()> {
        Ok(self.s().cancel_scheduled(&id)?)
    }

    /// Sends what is due now (sync does it too).
    pub fn send_due_scheduled(&self) -> R<Vec<TreeEvent>> {
        Ok(self.s().send_due_scheduled()?.into_iter().map(Into::into).collect())
    }

    // --- forwarding (chat.forwarding) and export (chat.export) ---

    /// Forwards a text or file to another chat as "forwarded"; returns the
    /// new message id.
    pub fn forward(&self, from_group: String, id: String, to_group: String) -> R<String> {
        Ok(self.s().forward(&unhex(&from_group, "group")?, &id, &unhex(&to_group, "group")?)?)
    }

    /// False: hide forward, save and copy for this chat's messages.
    pub fn forwarding_allowed(&self, group: String) -> R<bool> {
        Ok(self.s().forwarding_allowed(&unhex(&group, "group")?)?)
    }

    pub fn export_allowed(&self, group: String) -> R<bool> {
        Ok(self.s().export_allowed(&unhex(&group, "group")?)?)
    }

    pub fn export_chat(&self, group: String) -> R<ChatExportFiles> {
        let e = self.s().export_chat(&unhex(&group, "group")?)?;
        Ok(ChatExportFiles { text: e.text, json: e.json })
    }

    /// Writes `<path_prefix>.txt` and `<path_prefix>.json`; returns the paths.
    pub fn export_chat_to(&self, group: String, path_prefix: String) -> R<Vec<String>> {
        let (t, j) = self.s().export_chat_to(&unhex(&group, "group")?, &path_prefix)?;
        Ok(vec![t, j])
    }

    // --- reminders (device only) ---

    pub fn remind_me(&self, group: String, message_id: String, at: i64) -> R<String> {
        Ok(self.s().remind_me(&unhex(&group, "group")?, &message_id, at)?)
    }

    pub fn reminders(&self) -> R<Vec<ReminderInfo>> {
        Ok(self.s().reminders()?.into_iter().map(Into::into).collect())
    }

    pub fn cancel_reminder(&self, id: String) -> R<()> {
        Ok(self.s().cancel_reminder(&id)?)
    }

    /// Reminders that came due, each once: show a local notification.
    pub fn due_reminders(&self) -> R<Vec<ReminderInfo>> {
        Ok(self.s().due_reminders()?.into_iter().map(Into::into).collect())
    }

    // --- downloaded media and user.storage_clean ---

    /// Opens a file into the app's media folder `dir`; returns its path.
    pub fn download_to_cache(&self, file: Attachment, dir: String) -> R<String> {
        Ok(self.s().download_to_cache(&file.into(), &dir)?)
    }

    /// Deletes downloaded files older than the `user.storage_clean` period.
    pub fn clean_storage(&self) -> R<StorageCleanReport> {
        let r = self.s().clean_storage()?;
        Ok(StorageCleanReport { files: r.files, bytes: r.bytes })
    }

    /// Paths of downloaded files kept on this device.
    pub fn cached_media(&self) -> R<Vec<String>> {
        Ok(self.s().cached_media()?.into_iter().map(|c| c.path).collect())
    }
}
