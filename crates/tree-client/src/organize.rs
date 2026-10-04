//! Read receipts, typing, note to self, stranger labels, chat folders and
//! the chat list (mute, archive, pins, drafts, unread markers, departures).
//! Everything here lives on the device or inside end-to-end encrypted
//! messages; the server learns nothing new.
//!
//! | Setting | Default | Behaviour |
//! | --- | --- | --- |
//! | `user.read_receipts` | applied | `mark_read` tells the others; others' receipts are stored and shown (`read_by`, `Event::Read`) only while applied, both ways; receipts stored earlier are hidden after a release |
//! | `user.typing` | applied | `set_typing` tells the others; shown only while applied (both ways) |
//! | `user.peek` | applied | apps may show a chat without calling `mark_read` (no receipt) |
//! | `user.note_to_self` | applied | a one-member group for notes; released: apps hide it |
//! | `user.stranger_labels` | applied | `stranger_labels(account)`; released: `None` (apps show no labels) |
//! | `user.group_safety_notice` | applied | `Event::GroupSafetyNotice` when a non-contact adds this device to a group |
//! | `user.folders` | applied | user folders of chats |
//! | `user.default_folders` | applied | built-in folders: unread, direct, groups |
//! | `user.quiet_folder` | released | muted chats are gathered in their own folder |
//! | `user.drafts` | applied | a draft per chat is kept until sent; released: none kept, stored ones deleted |
//! | `user.unarchive_on_message` | applied | a new (not silent) message brings an archived chat back to the list unless the chat is muted; released: archived chats stay archived |
//!
//! Per-chat actions (not settings): mute for a while or until unmuted,
//! archive, pin (at most [`MAX_PINNED`], in order), mark unread. A muted
//! chat and a silent message never notify ([`Session::should_notify`]).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tree_core::storage::messages::StoredMessage;
use tree_core::MemberId;

use crate::messages::now;
use crate::payload::Payload;
use crate::{Error, Event, GroupStatus, Session};

/// Message ids per read receipt.
pub const MAX_READ_IDS: usize = 100;
/// Pinned chats (design: more with Pro later).
pub const MAX_PINNED: usize = 5;
/// Longest draft kept (bytes).
pub const MAX_DRAFT: usize = 64 * 1024;
/// Longest timed mute (a year); longer means "until unmuted".
pub const MAX_MUTE: i64 = 366 * 86400;
/// The mute durations the apps offer: label and seconds (`None`: until
/// unmuted).
pub const MUTE_CHOICES: &[(&str, Option<i64>)] =
    &[("1h", Some(3600)), ("8h", Some(8 * 3600)), ("1w", Some(7 * 86400)), ("forever", None)];

const K_NOTE: &str = "note/self";
const K_FOLDERS: &str = "folders";
const K_MUTED: &str = "muted";
const K_ARCHIVED: &str = "archived";
const K_PINNED: &str = "pinned";
pub(crate) const DRAFTS: &str = "user.drafts";
const UNARCHIVE: &str = "user.unarchive_on_message";

fn reads_key(gid: &[u8]) -> String {
    format!("reads/{}", hex::encode(gid))
}

fn seen_key(gid: &[u8]) -> String {
    format!("seen/{}", hex::encode(gid))
}

fn unread_key(gid: &[u8]) -> String {
    format!("unread/{}", hex::encode(gid))
}

fn marked_key(gid: &[u8]) -> String {
    format!("unreadmark/{}", hex::encode(gid))
}

fn draft_key(gid: &[u8]) -> String {
    format!("draft/{}", hex::encode(gid))
}

fn leaving_key(gid: &[u8]) -> String {
    format!("leaving/{}", hex::encode(gid))
}

/// How a person relates to this user, for warnings next to their name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrangerLabels {
    /// Not a contact the user chose.
    pub not_contact: bool,
    /// In no other group with the user.
    pub no_common_group: bool,
    /// The safety number was never compared.
    pub name_unverified: bool,
}

/// A folder and the chats in it (group ids, hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub name: String,
    /// `user` folders can be renamed and deleted; `unread`, `direct`,
    /// `groups`, `quiet` are built in.
    pub kind: String,
    pub chats: Vec<String>,
}

/// One chat as the chat list needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatState {
    pub group: Vec<u8>,
    pub pinned: bool,
    pub archived: bool,
    pub muted: bool,
    /// End of a timed mute (unix seconds); `None` while muted until unmuted
    /// (or not muted).
    pub muted_until: Option<i64>,
    /// The user marked the chat unread.
    pub marked_unread: bool,
    /// Messages received since the user last read the chat.
    pub unread: u32,
    pub draft: Option<String>,
    /// When the newest message arrived or was sent (or the chat started),
    /// this device's clock.
    pub last_activity: i64,
}

/// What a stored message carries besides its text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageMeta {
    /// Sent silently (no notification).
    pub silent: bool,
    /// For a `left` / `removed` line: the member's name when it went.
    pub name: Option<String>,
}

/// Reads [`MessageMeta`] from a stored message.
pub fn message_meta(m: &StoredMessage) -> MessageMeta {
    if m.kind == "file" {
        return MessageMeta::default();
    }
    let v: serde_json::Value = m.data.as_deref().and_then(|d| serde_json::from_slice(d).ok()).unwrap_or_default();
    MessageMeta { silent: v["silent"] == true, name: v["name"].as_str().map(str::to_string) }
}

#[derive(Default, Serialize, Deserialize)]
struct Folders(BTreeMap<String, BTreeSet<String>>);

/// Muted chats: group hex -> end (unix seconds; 0 = until unmuted).
type Mutes = BTreeMap<String, i64>;

fn active(m: &Mutes, h: &str, t: i64) -> Option<i64> {
    m.get(h).copied().filter(|&u| u == 0 || u > t)
}

impl Session {
    fn json<T: for<'a> Deserialize<'a> + Default>(&self, key: &str) -> Result<T, Error> {
        Ok(self.client.app_data(key)?.and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default())
    }

    fn put_json<T: Serialize>(&self, key: &str, v: &T) -> Result<(), Error> {
        Ok(self.client.set_app_data(key, Some(&serde_json::to_vec(v).expect("JSON")))?)
    }

    // --- read receipts and typing ---

    /// The user read these messages: unread count back to zero, the
    /// "marked unread" marker gone, and a receipt to the others if
    /// `user.read_receipts` is applied. Apps call this when a chat is
    /// opened, not when it is only previewed (`user.peek`).
    pub fn mark_read(&mut self, gid: &[u8], ids: &[String]) -> Result<(), Error> {
        self.client.set_app_data(&unread_key(gid), None)?;
        self.client.set_app_data(&marked_key(gid), None)?;
        if ids.is_empty() || !self.is_applied("user.read_receipts")? {
            return Ok(());
        }
        for chunk in ids.chunks(MAX_READ_IDS) {
            self.send_payload(gid, &Payload::Read { ids: chunk.to_vec() })?;
        }
        Ok(())
    }

    /// Marks a chat unread (or takes the marker away) without touching
    /// messages or receipts. Opening the chat ([`Session::mark_read`])
    /// clears it.
    pub fn mark_unread(&self, gid: &[u8], on: bool) -> Result<(), Error> {
        Ok(self.client.set_app_data(&marked_key(gid), on.then_some(&b"1"[..]))?)
    }

    pub fn is_marked_unread(&self, gid: &[u8]) -> Result<bool, Error> {
        Ok(self.client.app_data(&marked_key(gid))?.is_some())
    }

    pub(crate) fn on_read(&mut self, gid: &[u8], from: MemberId, ids: Vec<String>, events: &mut Vec<Event>) -> Result<(), Error> {
        if !self.is_applied("user.read_receipts")? {
            return Ok(());
        }
        let ids: Vec<String> = ids.into_iter().take(MAX_READ_IDS).collect();
        let mut reads: BTreeMap<String, BTreeSet<String>> = self.json(&reads_key(gid))?;
        for id in &ids {
            if self.client.message(gid, id)?.is_some() {
                reads.entry(id.clone()).or_default().insert(from.to_hex());
            }
        }
        self.put_json(&reads_key(gid), &reads)?;
        events.push(Event::Read { group: gid.to_vec(), from, ids });
        Ok(())
    }

    /// Members (hex) who read message `id`, as far as their receipts arrived.
    /// Empty while `user.read_receipts` is released (both ways: receipts
    /// stored before the release are hidden too, not deleted).
    pub fn read_by(&self, gid: &[u8], id: &str) -> Result<Vec<String>, Error> {
        if !self.is_applied("user.read_receipts")? {
            return Ok(Vec::new());
        }
        let reads: BTreeMap<String, BTreeSet<String>> = self.json(&reads_key(gid))?;
        Ok(reads.get(id).map(|s| s.iter().cloned().collect()).unwrap_or_default())
    }

    /// The app came to the foreground: tells the group "seen now" if
    /// `user.last_seen` is applied (released by default).
    pub fn announce_seen(&mut self, gid: &[u8]) -> Result<(), Error> {
        if self.is_applied("user.last_seen")? {
            self.send_payload(gid, &Payload::Seen)?;
        }
        Ok(())
    }

    pub(crate) fn on_seen(&mut self, gid: &[u8], from: MemberId) -> Result<(), Error> {
        if !self.is_applied("user.last_seen")? {
            return Ok(());
        }
        let mut seen: BTreeMap<String, i64> = self.json(&seen_key(gid))?;
        seen.insert(from.to_hex(), now());
        self.put_json(&seen_key(gid), &seen)
    }

    /// When this device last heard `member` was online (its own clock), if
    /// both sides apply `user.last_seen`.
    pub fn last_seen(&self, gid: &[u8], member: &MemberId) -> Result<Option<i64>, Error> {
        if !self.is_applied("user.last_seen")? {
            return Ok(None);
        }
        Ok(self.json::<BTreeMap<String, i64>>(&seen_key(gid))?.get(&member.to_hex()).copied())
    }

    /// Tells the others the user is (or stopped) typing, if `user.typing`.
    pub fn set_typing(&mut self, gid: &[u8], on: bool) -> Result<(), Error> {
        if self.is_applied("user.typing")? {
            self.send_payload(gid, &Payload::Typing { on })?;
        }
        Ok(())
    }

    /// Messages that arrived since the user last read this chat.
    pub fn unread(&self, gid: &[u8]) -> Result<u32, Error> {
        self.json::<u32>(&unread_key(gid))
    }

    /// A text or file arrived: one more unread, and an archived chat comes
    /// back to the list if it is not muted, the message is not silent and
    /// `user.unarchive_on_message` is applied.
    pub(crate) fn on_new_message(&self, gid: &[u8], silent: bool) -> Result<(), Error> {
        let n = self.unread(gid)?;
        self.put_json(&unread_key(gid), &(n + 1))?;
        if !silent && self.is_archived(gid)? && !self.is_muted(gid)? && self.is_applied(UNARCHIVE)? {
            self.archive_chat(gid, false)?;
        }
        Ok(())
    }

    /// Whether an app should notify for a new message in this chat: not
    /// while the chat is muted, never for a silent message, never for a
    /// declined chat.
    pub fn should_notify(&self, gid: &[u8], silent: bool) -> Result<bool, Error> {
        Ok(!silent && !self.is_muted(gid)? && self.group_status(gid)? != GroupStatus::Declined)
    }

    // --- note to self ---

    /// The one-member group for notes (created on first use). `None` while
    /// `user.note_to_self` is released (apps hide it).
    pub fn note_to_self(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if !self.is_applied("user.note_to_self")? {
            return Ok(None);
        }
        if let Some(g) = self.client.app_data(K_NOTE)? {
            if self.group(&g).is_ok() {
                return Ok(Some(g));
            }
        }
        let g = self.create_group()?;
        self.client.set_app_data(K_NOTE, Some(&g))?;
        Ok(Some(g))
    }

    // --- stranger labels ---

    /// Labels for a person (by account) as the user knows them; `None`
    /// while `user.stranger_labels` is released (apps show none).
    pub fn stranger_labels(&mut self, account: &str) -> Result<Option<StrangerLabels>, Error> {
        if !self.is_applied("user.stranger_labels")? {
            return Ok(None);
        }
        let c = self.contact(account)?;
        let mut groups = 0;
        for gid in self.group_ids()? {
            if self.map(&crate::accounts_key(&gid))?.values().any(|a| a == account) {
                groups += 1;
            }
        }
        Ok(Some(StrangerLabels {
            not_contact: !c.as_ref().is_some_and(|c| c.accepted),
            no_common_group: groups <= 1,
            name_unverified: !c.as_ref().is_some_and(|c| c.verified),
        }))
    }

    // --- folders ---

    pub fn create_folder(&self, name: &str) -> Result<(), Error> {
        if !self.is_applied("user.folders")? {
            return Err(Error::Feature("LOCKED_BY_USER".into()));
        }
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(Error::Usage("folder names have 1 to 64 characters".into()));
        }
        let mut f: Folders = self.json(K_FOLDERS)?;
        f.0.entry(name.to_string()).or_default();
        self.put_json(K_FOLDERS, &f)
    }

    pub fn delete_folder(&self, name: &str) -> Result<(), Error> {
        let mut f: Folders = self.json(K_FOLDERS)?;
        f.0.remove(name);
        self.put_json(K_FOLDERS, &f)
    }

    /// Puts a chat into a user folder (`add`) or takes it out.
    pub fn file_chat(&self, name: &str, gid: &[u8], add: bool) -> Result<(), Error> {
        let mut f: Folders = self.json(K_FOLDERS)?;
        let set = f.0.get_mut(name).ok_or_else(|| Error::Usage("no such folder".into()))?;
        if add {
            set.insert(hex::encode(gid));
        } else {
            set.remove(&hex::encode(gid));
        }
        self.put_json(K_FOLDERS, &f)
    }

    // --- mute ---

    fn mutes(&self) -> Result<Mutes, Error> {
        let Some(v) = self.client.app_data(K_MUTED)? else { return Ok(Mutes::new()) };
        if let Ok(m) = serde_json::from_slice::<Mutes>(&v) {
            return Ok(m);
        }
        // Before timed mutes the value was a list of chats muted until unmuted.
        Ok(serde_json::from_slice::<BTreeSet<String>>(&v).map(|s| s.into_iter().map(|g| (g, 0)).collect()).unwrap_or_default())
    }

    /// Mutes a chat for `seconds` (1 s to a year), or until unmuted
    /// (`None`). Returns when the mute ends (`None`: until unmuted). A
    /// muted chat does not notify and is gathered in the quiet folder.
    pub fn mute_for(&self, gid: &[u8], seconds: Option<i64>) -> Result<Option<i64>, Error> {
        if seconds.is_some_and(|s| !(1..=MAX_MUTE).contains(&s)) {
            return Err(Error::Usage("a mute lasts 1 second to a year, or until unmuted".into()));
        }
        let t = now();
        let until = seconds.map(|s| t + s);
        let mut m = self.mutes()?;
        m.retain(|_, u| *u == 0 || *u > t);
        m.insert(hex::encode(gid), until.unwrap_or(0));
        self.put_json(K_MUTED, &m)?;
        Ok(until)
    }

    /// Mutes a chat until unmuted (`on`), or unmutes it.
    pub fn mute(&self, gid: &[u8], on: bool) -> Result<(), Error> {
        if on {
            self.mute_for(gid, None)?;
            return Ok(());
        }
        let mut m = self.mutes()?;
        m.remove(&hex::encode(gid));
        self.put_json(K_MUTED, &m)
    }

    /// Muted now (a timed mute that ended counts as unmuted).
    pub fn is_muted(&self, gid: &[u8]) -> Result<bool, Error> {
        Ok(active(&self.mutes()?, &hex::encode(gid), now()).is_some())
    }

    /// When a timed mute ends; `None` if the chat is muted until unmuted
    /// or not muted ([`Session::is_muted`] tells which).
    pub fn muted_until(&self, gid: &[u8]) -> Result<Option<i64>, Error> {
        Ok(active(&self.mutes()?, &hex::encode(gid), now()).filter(|&u| u != 0))
    }

    // --- archive and pins ---

    /// Archives a chat (it leaves the main list; a pin is dropped) or
    /// brings it back. See `user.unarchive_on_message` for what brings it
    /// back by itself.
    pub fn archive_chat(&self, gid: &[u8], on: bool) -> Result<(), Error> {
        let h = hex::encode(gid);
        let mut a: BTreeSet<String> = self.json(K_ARCHIVED)?;
        if on {
            a.insert(h.clone());
            let mut p: Vec<String> = self.json(K_PINNED)?;
            p.retain(|x| *x != h);
            self.put_json(K_PINNED, &p)?;
        } else {
            a.remove(&h);
        }
        self.put_json(K_ARCHIVED, &a)
    }

    pub fn is_archived(&self, gid: &[u8]) -> Result<bool, Error> {
        Ok(self.json::<BTreeSet<String>>(K_ARCHIVED)?.contains(&hex::encode(gid)))
    }

    /// Pinned chats in order (only chats that still exist).
    pub fn pinned_chats(&self) -> Result<Vec<Vec<u8>>, Error> {
        let alive: BTreeSet<Vec<u8>> = self.group_ids()?.into_iter().collect();
        Ok(self.json::<Vec<String>>(K_PINNED)?.iter().filter_map(|h| hex::decode(h).ok()).filter(|g| alive.contains(g)).collect())
    }

    /// Pins a chat at the end of the pinned ones (at most [`MAX_PINNED`];
    /// an archived chat comes back) or unpins it.
    pub fn pin_chat(&self, gid: &[u8], on: bool) -> Result<(), Error> {
        let h = hex::encode(gid);
        let mut p: Vec<String> = self.pinned_chats()?.iter().map(hex::encode).collect();
        if on {
            if p.contains(&h) {
                return Ok(());
            }
            if p.len() >= MAX_PINNED {
                return Err(Error::Usage(format!("at most {MAX_PINNED} chats can be pinned")));
            }
            p.push(h);
            self.archive_chat(gid, false)?;
        } else {
            p.retain(|x| *x != h);
        }
        self.put_json(K_PINNED, &p)
    }

    /// Moves a pinned chat to position `to` (0 = top) among the pinned.
    pub fn move_pinned_chat(&self, gid: &[u8], to: usize) -> Result<(), Error> {
        let h = hex::encode(gid);
        let mut p: Vec<String> = self.pinned_chats()?.iter().map(hex::encode).collect();
        let from = p.iter().position(|x| *x == h).ok_or_else(|| Error::Usage("the chat is not pinned".into()))?;
        let x = p.remove(from);
        p.insert(to.min(p.len()), x);
        self.put_json(K_PINNED, &p)
    }

    // --- drafts ---

    /// Keeps the unsent text of a chat (restored when the chat opens;
    /// cleared when a text is sent). Empty text deletes it. Returns whether
    /// a draft is kept: none while `user.drafts` is released.
    pub fn set_draft(&self, gid: &[u8], text: &str) -> Result<bool, Error> {
        if text.len() > MAX_DRAFT {
            return Err(Error::Usage(format!("a draft has at most {MAX_DRAFT} bytes")));
        }
        let keep = !text.trim().is_empty() && self.is_applied(DRAFTS)?;
        self.client.set_app_data(&draft_key(gid), keep.then_some(text.as_bytes()))?;
        Ok(keep)
    }

    /// The draft of a chat, if any (none while `user.drafts` is released).
    pub fn draft(&self, gid: &[u8]) -> Result<Option<String>, Error> {
        if !self.is_applied(DRAFTS)? {
            return Ok(None);
        }
        Ok(self.client.app_data(&draft_key(gid))?.and_then(|v| String::from_utf8(v).ok()))
    }

    /// Deletes every draft (`user.drafts` released).
    pub(crate) fn delete_drafts(&self) -> Result<(), Error> {
        for k in self.client.app_data_keys("draft/")? {
            self.client.set_app_data(&k, None)?;
        }
        Ok(())
    }

    // --- the chat list ---

    fn last_activity(&self, gid: &[u8]) -> Result<i64, Error> {
        let last = self.client.messages(gid, 1, None)?.last().map(|m| m.received_at);
        Ok(match last {
            Some(t) => t,
            None => self.time_of(&format!("traffic/{}", hex::encode(gid)))?.unwrap_or(0),
        })
    }

    /// Everything the chat list shows about one chat.
    pub fn chat_state(&self, gid: &[u8]) -> Result<ChatState, Error> {
        let h = hex::encode(gid);
        let t = now();
        let mute = active(&self.mutes()?, &h, t);
        Ok(ChatState {
            group: gid.to_vec(),
            pinned: self.json::<Vec<String>>(K_PINNED)?.contains(&h),
            archived: self.is_archived(gid)?,
            muted: mute.is_some(),
            muted_until: mute.filter(|&u| u != 0),
            marked_unread: self.is_marked_unread(gid)?,
            unread: self.unread(gid)?,
            draft: self.draft(gid)?,
            last_activity: self.last_activity(gid)?,
        })
    }

    /// Every chat in list order: pinned chats first in their order, then
    /// the others by last activity (newest first). Archived chats are in
    /// the list too (`archived`): apps show them in their own section.
    pub fn chat_list(&self) -> Result<Vec<ChatState>, Error> {
        let pins: Vec<Vec<u8>> = self.pinned_chats()?;
        let mut rest = Vec::new();
        let own = self.self_group()?;
        for g in self.group_ids()? {
            if !pins.contains(&g) && own.as_ref() != Some(&g) {
                rest.push(self.chat_state(&g)?);
            }
        }
        rest.sort_by(|a, b| b.last_activity.cmp(&a.last_activity).then_with(|| a.group.cmp(&b.group)));
        let mut out = pins.iter().map(|g| self.chat_state(g)).collect::<Result<Vec<_>, _>>()?;
        out.extend(rest);
        Ok(out)
    }

    // --- departures ---

    /// A member asked to leave; remembered until its removal arrives.
    pub(crate) fn note_leave_request(&self, gid: &[u8], from: &MemberId, quiet: bool) -> Result<(), Error> {
        let mut l: BTreeMap<String, bool> = self.json(&leaving_key(gid))?;
        l.insert(from.to_hex(), quiet);
        self.put_json(&leaving_key(gid), &l)
    }

    /// Members were removed: a `left` line (it asked to leave) or a
    /// `removed` line in the history, none for a quiet leave.
    pub(crate) fn note_departures(&mut self, gid: &[u8], removed: &[MemberId]) -> Result<(), Error> {
        if removed.is_empty() {
            return Ok(());
        }
        let me = self.member_id();
        let mut leaving: BTreeMap<String, bool> = self.json(&leaving_key(gid))?;
        let names = self.names(gid)?;
        for m in removed.iter().filter(|m| **m != me) {
            let kind = match leaving.remove(&m.to_hex()) {
                Some(true) => continue,
                Some(false) => "left",
                None => "removed",
            };
            let data = names.get(&m.to_hex()).map(|n| serde_json::to_vec(&serde_json::json!({ "name": n })).expect("JSON"));
            let mut id = [0u8; 16];
            getrandom::getrandom(&mut id).expect("operating system random number generator failed");
            self.store(gid, &hex::encode(id), m, kind, None, data, None)?;
        }
        if leaving.is_empty() {
            self.client.set_app_data(&leaving_key(gid), None)?;
        } else {
            self.put_json(&leaving_key(gid), &leaving)?;
        }
        Ok(())
    }

    /// All folders the settings allow: user folders, then the built-in ones.
    pub fn folders(&mut self) -> Result<Vec<Folder>, Error> {
        let mut out = Vec::new();
        let own = self.self_group()?;
        let gids: Vec<Vec<u8>> = self.group_ids()?.into_iter().filter(|g| own.as_ref() != Some(g)).collect();
        let alive: BTreeSet<String> = gids.iter().map(hex::encode).collect();
        if self.is_applied("user.folders")? {
            for (name, chats) in self.json::<Folders>(K_FOLDERS)?.0 {
                out.push(Folder { name, kind: "user".into(), chats: chats.into_iter().filter(|c| alive.contains(c)).collect() });
            }
        }
        if self.is_applied("user.default_folders")? {
            let (mut unread, mut direct, mut groups) = (vec![], vec![], vec![]);
            for g in &gids {
                let h = hex::encode(g);
                if self.unread(g)? > 0 || self.is_marked_unread(g)? {
                    unread.push(h.clone());
                }
                if self.group(g)?.members().len() <= 2 {
                    direct.push(h);
                } else {
                    groups.push(h);
                }
            }
            out.push(Folder { name: "unread".into(), kind: "unread".into(), chats: unread });
            out.push(Folder { name: "direct".into(), kind: "direct".into(), chats: direct });
            out.push(Folder { name: "groups".into(), kind: "groups".into(), chats: groups });
        }
        if self.is_applied("user.quiet_folder")? {
            let (m, t) = (self.mutes()?, now());
            let muted: Vec<String> = m.keys().filter(|c| alive.contains(*c) && active(&m, c, t).is_some()).cloned().collect();
            out.push(Folder { name: "quiet".into(), kind: "quiet".into(), chats: muted });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mute_ends() {
        let m: Mutes = [("a".to_string(), 0), ("b".to_string(), 100), ("c".to_string(), 50)].into();
        assert_eq!(active(&m, "a", 75), Some(0), "until unmuted");
        assert_eq!(active(&m, "b", 75), Some(100));
        assert_eq!(active(&m, "c", 75), None, "ended");
        assert_eq!(active(&m, "c", 50), None, "ends at its time");
        assert_eq!(active(&m, "d", 75), None);
    }

    #[test]
    fn mute_choices_fit() {
        for (_, s) in MUTE_CHOICES {
            assert!(s.is_none_or(|s| (1..=MAX_MUTE).contains(&s)));
        }
    }
}
