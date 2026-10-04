//! Settings sync between a person's own devices (PRODUCT_PLAN.md Wave 1
//! item 10; APP_PROTOCOL.md 6.4).
//!
//! Every account has a private **self group**: an ordinary MLS group whose
//! members are only the account's own devices. The first device link
//! creates it on the existing device ([`Session::ensure_self_group`]); the
//! link carries its id to the new device sealed with the account data, and
//! the existing device adds the new one to it by commit like to any other
//! group. Nobody else is ever added, so everything in it is end-to-end
//! encrypted between the account's own devices; the server sees one more
//! group.
//!
//! What syncs: the user-scope settings (`feature/<key>`: state and option)
//! except `user.recovery_phrase` (the server's state, fetched from it) and
//! `user.app_lock` (how this device unlocks: a PIN or biometric key exists
//! per device), and the chat-list choices `folders`, `muted`, `archived`,
//! `pinned`. Drafts stay on their device.
//!
//! How: each synced key has a timestamp (milliseconds, the writer's clock)
//! and the hash of the value last synced. At every sync the device compares
//! its values with those hashes; whatever changed gets the current time
//! (at least one more than the old one) and goes to the self group in one
//! `settings` message. A receiver takes an entry only if its timestamp is
//! newer than its own for that key (equal: the larger value hash wins, so
//! all devices end up the same): last writer wins per setting.
//!
//! Who may change settings: only a member of this account's own self group,
//! which this device made or learned through a confirmed device link. A
//! `settings` message in any other group is dropped, so another account
//! cannot change this user's settings even from a group both are in.
//! Feature entries are applied through the feature registry like a local
//! change, so permanently locked settings stay as they are.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tree_core::MemberId;

use crate::api::{b64, unb64};
use crate::{Error, Event, GroupStatus, Payload, Session};

/// App-data key holding the self group's id.
pub(crate) const SELF_GROUP: &str = "self/group";
const TS: &str = "sync/ts/";
const SEEN: &str = "sync/seen/";
/// Chat-list keys that sync (`organize.rs`).
const EXACT: &[&str] = &["folders", "muted", "archived", "pinned"];
/// User settings that stay per device.
const NOT_SYNCED: &[&str] = &["feature/user.recovery_phrase", "feature/user.app_lock"];
/// Entries per `settings` message.
pub const MAX_SYNC_ENTRIES: usize = 512;
/// Largest value of one entry (bytes, before base64).
pub const MAX_SYNC_VALUE: usize = 64 * 1024;

/// One synced setting: app-data key, value (base64; `None`: deleted) and
/// the writer's timestamp (unix milliseconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEntry {
    pub k: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v: Option<String>,
    pub t: i64,
}

/// Whether app-data key `k` syncs between own devices.
pub fn synced(k: &str) -> bool {
    EXACT.contains(&k) || (k.starts_with("feature/") && !NOT_SYNCED.contains(&k))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn hash(v: Option<&[u8]>) -> String {
    match v {
        Some(v) => hex::encode(Sha256::digest(v)),
        None => "-".into(),
    }
}

impl Session {
    /// The self group's id, if this device has one.
    pub fn self_group(&self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.client.app_data(SELF_GROUP)?)
    }

    /// Whether `gid` is this account's own settings group (apps never list it).
    pub fn is_self_group(&self, gid: &[u8]) -> Result<bool, Error> {
        Ok(self.self_group()?.as_deref() == Some(gid))
    }

    /// The self group, created (with only this device in it) if missing.
    pub fn ensure_self_group(&mut self) -> Result<Vec<u8>, Error> {
        if let Some(g) = self.self_group()? {
            if self.group(&g).is_ok_and(|g| g.is_member()) {
                return Ok(g);
            }
        }
        let g = self.create_group()?;
        self.set_group_status(&g, &GroupStatus::Accepted)?;
        self.client.set_app_data(SELF_GROUP, Some(&g))?;
        Ok(g)
    }

    fn sync_time(&self, k: &str) -> Result<i64, Error> {
        Ok(self.time_of(&format!("{TS}{k}"))?.unwrap_or(0))
    }

    /// Synced keys this device has a value or a sync record for.
    fn synced_keys(&self) -> Result<Vec<String>, Error> {
        let mut keys: Vec<String> = self.client.app_data_keys("feature/")?;
        keys.extend(EXACT.iter().map(|k| k.to_string()));
        keys.extend(self.client.app_data_keys(SEEN)?.into_iter().map(|k| k[SEEN.len()..].to_string()));
        keys.retain(|k| synced(k));
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    /// Settings changed on this device since they were last synced, with
    /// new timestamps; marks them synced.
    fn collect_changes(&self) -> Result<Vec<SyncEntry>, Error> {
        let mut out = Vec::new();
        let t = now_ms();
        for k in self.synced_keys()? {
            let v = self.client.app_data(&k)?;
            let h = hash(v.as_deref());
            let seen = self.client.app_data(&format!("{SEEN}{k}"))?.and_then(|s| String::from_utf8(s).ok());
            if seen.as_deref() == Some(h.as_str()) || (seen.is_none() && v.is_none()) {
                continue;
            }
            if v.as_ref().is_some_and(|v| v.len() > MAX_SYNC_VALUE) {
                continue;
            }
            let ts = t.max(self.sync_time(&k)? + 1);
            self.set_time(&format!("{TS}{k}"), ts)?;
            self.client.set_app_data(&format!("{SEEN}{k}"), Some(h.as_bytes()))?;
            out.push(SyncEntry { k, v: v.map(|v| b64(&v)), t: ts });
        }
        Ok(out)
    }

    /// Sends the settings changed on this device to the account's other
    /// devices (through the self group). Returns how many were sent; 0 when
    /// nothing changed or there is no other own device yet (a device linked
    /// later gets the current values with the account data).
    pub fn push_settings(&mut self) -> Result<usize, Error> {
        let changes = self.collect_changes()?;
        if changes.is_empty() {
            return Ok(0);
        }
        let Some(g) = self.self_group()? else { return Ok(0) };
        if !self.group(&g).is_ok_and(|g| g.is_member()) || self.other_devices(&g)?.is_empty() {
            return Ok(0);
        }
        let n = changes.len();
        for chunk in changes.chunks(MAX_SYNC_ENTRIES) {
            self.send_payload(&g, &Payload::Settings { s: chunk.to_vec() })?;
        }
        Ok(n)
    }

    /// A `settings` message from member `from` of group `gid`.
    pub(crate) fn on_settings(&mut self, gid: &[u8], from: MemberId, entries: Vec<SyncEntry>, events: &mut Vec<Event>) -> Result<(), Error> {
        let members = self.group(gid)?.members();
        if !self.is_self_group(gid)? || !members.contains(&from) || from == self.member_id() {
            events.push(Event::Dropped { reason: "settings from outside this account's own devices".into() });
            return Ok(());
        }
        let mut changed = Vec::new();
        for e in entries.into_iter().take(MAX_SYNC_ENTRIES) {
            if !synced(&e.k) {
                continue;
            }
            let value = match e.v.as_deref().map(unb64).transpose() {
                Ok(v) if v.as_ref().is_none_or(|v| v.len() <= MAX_SYNC_VALUE) => v,
                _ => continue,
            };
            let local = self.client.app_data(&e.k)?;
            let local_t = self.sync_time(&e.k)?;
            let newer = e.t > local_t || (e.t == local_t && hash(value.as_deref()) > hash(local.as_deref()));
            if !newer || value == local {
                if newer {
                    self.set_time(&format!("{TS}{}", e.k), e.t)?;
                }
                continue;
            }
            if !self.apply_synced(&e.k, value.as_deref())? {
                continue;
            }
            let now_local = self.client.app_data(&e.k)?;
            self.set_time(&format!("{TS}{}", e.k), e.t)?;
            self.client.set_app_data(&format!("{SEEN}{}", e.k), Some(hash(now_local.as_deref()).as_bytes()))?;
            changed.push(e.k);
        }
        if !changed.is_empty() {
            events.push(Event::SettingsSynced { keys: changed });
        }
        Ok(())
    }

    /// Stores one synced value the way a local change would. Returns false
    /// if it is refused (malformed, or a change the registry does not
    /// allow, e.g. a permanently locked feature).
    fn apply_synced(&mut self, k: &str, v: Option<&[u8]>) -> Result<bool, Error> {
        if let Some(name) = k.strip_prefix("feature/") {
            #[derive(Deserialize)]
            struct Stored {
                applied: bool,
                option: Option<String>,
            }
            let st = match v {
                None => {
                    // Back to the default.
                    let d = tree_core::features::Registry::standard().status(name).map(|s| s.state == tree_core::features::State::Applied);
                    match d {
                        Ok(applied) => Stored { applied, option: None },
                        Err(_) => return Ok(false),
                    }
                }
                Some(v) => match serde_json::from_slice::<Stored>(v) {
                    Ok(s) => s,
                    Err(_) => return Ok(false),
                },
            };
            if self.change(name, st.applied, st.option).is_err() {
                return Ok(false);
            }
            if name == crate::organize::DRAFTS && !st.applied {
                self.delete_drafts()?;
            }
            self.local_effects(name)?;
            return Ok(true);
        }
        // Chat-list keys: JSON objects or lists as `organize.rs` writes them.
        if let Some(v) = v {
            match serde_json::from_slice::<serde_json::Value>(v) {
                Ok(j) if j.is_object() || j.is_array() => {}
                _ => return Ok(false),
            }
        }
        self.client.set_app_data(k, v)?;
        Ok(true)
    }

    /// A roster in the self group from one of its members: the devices it
    /// names are this account's own (only own devices are ever added to it).
    pub(crate) fn note_own_devices(&self, gid: &[u8], members: &[String]) -> Result<(), Error> {
        if !self.is_self_group(gid)? {
            return Ok(());
        }
        for m in members.iter().filter_map(|m| MemberId::from_hex(m)) {
            if m != self.member_id() {
                self.add_own_member(&m)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_syncs() {
        for k in ["feature/user.typing", "feature/user.search_index", "folders", "muted", "archived", "pinned"] {
            assert!(synced(k), "{k}");
        }
        for k in ["feature/user.recovery_phrase", "feature/user.app_lock", "draft/00", "server/auth_key", "self/group", "contact/x"] {
            assert!(!synced(k), "{k}");
        }
    }

    #[test]
    fn entry_format() {
        let e = SyncEntry { k: "muted".into(), v: None, t: 5 };
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"k":"muted","t":5}"#);
    }
}
