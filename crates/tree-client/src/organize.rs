//! Read receipts, typing, note to self, stranger labels and chat folders.
//! Everything here lives on the device or inside end-to-end encrypted
//! messages; the server learns nothing new.
//!
//! | Setting | Default | Behaviour |
//! | --- | --- | --- |
//! | `user.read_receipts` | applied | `mark_read` tells the others; others' receipts are shown only while applied (both ways) |
//! | `user.typing` | applied | `set_typing` tells the others; shown only while applied (both ways) |
//! | `user.peek` | applied | apps may show a chat without calling `mark_read` (no receipt) |
//! | `user.note_to_self` | applied | a one-member group for notes; released: apps hide it |
//! | `user.stranger_labels` | applied | `stranger_labels(account)` |
//! | `user.group_safety_notice` | applied | `Event::GroupSafetyNotice` when a non-contact adds this device to a group |
//! | `user.folders` | applied | user folders of chats |
//! | `user.default_folders` | applied | built-in folders: unread, direct, groups |
//! | `user.quiet_folder` | released | muted chats are gathered in their own folder |

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tree_core::MemberId;

use crate::payload::Payload;
use crate::{Error, Event, Session};

/// Message ids per read receipt.
pub const MAX_READ_IDS: usize = 100;
const K_NOTE: &str = "note/self";
const K_FOLDERS: &str = "folders";
const K_MUTED: &str = "muted";

fn reads_key(gid: &[u8]) -> String {
    format!("reads/{}", hex::encode(gid))
}

fn seen_key(gid: &[u8]) -> String {
    format!("seen/{}", hex::encode(gid))
}

fn unread_key(gid: &[u8]) -> String {
    format!("unread/{}", hex::encode(gid))
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

#[derive(Default, Serialize, Deserialize)]
struct Folders(BTreeMap<String, BTreeSet<String>>);

impl Session {
    fn json<T: for<'a> Deserialize<'a> + Default>(&self, key: &str) -> Result<T, Error> {
        Ok(self.client.app_data(key)?.and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default())
    }

    fn put_json<T: Serialize>(&self, key: &str, v: &T) -> Result<(), Error> {
        Ok(self.client.set_app_data(key, Some(&serde_json::to_vec(v).expect("JSON")))?)
    }

    // --- read receipts and typing ---

    /// The user read these messages: unread count back to zero, and a
    /// receipt to the others if `user.read_receipts` is applied. Apps call
    /// this when a chat is opened, not when it is only previewed (`user.peek`).
    pub fn mark_read(&mut self, gid: &[u8], ids: &[String]) -> Result<(), Error> {
        self.client.set_app_data(&unread_key(gid), None)?;
        if ids.is_empty() || !self.is_applied("user.read_receipts")? {
            return Ok(());
        }
        for chunk in ids.chunks(MAX_READ_IDS) {
            self.send_payload(gid, &Payload::Read { ids: chunk.to_vec() })?;
        }
        Ok(())
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
    pub fn read_by(&self, gid: &[u8], id: &str) -> Result<Vec<String>, Error> {
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
        seen.insert(from.to_hex(), crate::messages::now());
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

    pub(crate) fn count_unread(&self, gid: &[u8]) -> Result<(), Error> {
        let n = self.unread(gid)?;
        self.put_json(&unread_key(gid), &(n + 1))
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

    /// Labels for a person (by account) as the user knows them.
    pub fn stranger_labels(&mut self, account: &str) -> Result<StrangerLabels, Error> {
        let c = self.contact(account)?;
        let mut groups = 0;
        for gid in self.group_ids()? {
            if self.map(&crate::accounts_key(&gid))?.values().any(|a| a == account) {
                groups += 1;
            }
        }
        Ok(StrangerLabels {
            not_contact: !c.as_ref().is_some_and(|c| c.accepted),
            no_common_group: groups <= 1,
            name_unverified: !c.as_ref().is_some_and(|c| c.verified),
        })
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

    /// Mutes a chat (no notifications; gathered in the quiet folder).
    pub fn mute(&self, gid: &[u8], on: bool) -> Result<(), Error> {
        let mut m: BTreeSet<String> = self.json(K_MUTED)?;
        if on {
            m.insert(hex::encode(gid));
        } else {
            m.remove(&hex::encode(gid));
        }
        self.put_json(K_MUTED, &m)
    }

    pub fn is_muted(&self, gid: &[u8]) -> Result<bool, Error> {
        Ok(self.json::<BTreeSet<String>>(K_MUTED)?.contains(&hex::encode(gid)))
    }

    /// All folders the settings allow: user folders, then the built-in ones.
    pub fn folders(&mut self) -> Result<Vec<Folder>, Error> {
        let mut out = Vec::new();
        let gids = self.group_ids()?;
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
                if self.unread(g)? > 0 {
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
            let muted: Vec<String> = self.json::<BTreeSet<String>>(K_MUTED)?.into_iter().filter(|c| alive.contains(c)).collect();
            out.push(Folder { name: "quiet".into(), kind: "quiet".into(), chats: muted });
        }
        Ok(out)
    }
}
