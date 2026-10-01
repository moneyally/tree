//! Tree client logic shared by every app (command line now, phone and
//! desktop apps later through UniFFI): one device's encrypted profile, the
//! server API, the receive loop, two-phase commits against the server's
//! commit ordering, and the member -> device roster of each group.
//!
//! Apps only draw screens; everything a client must do correctly lives here
//! or in `tree-core`.

pub mod api;
pub mod payload;

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tree_core::{
    wire::{peek, Peek},
    Client, Group, Incoming, PendingCommit, StoredProvider, TreeError,
};
use zeroize::Zeroizing;

pub use api::{Api, Creds};
pub use payload::Payload;
pub use tree_core::MemberId;


#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] TreeError),
    #[error("server answered {status} {code}")]
    Server { status: u16, code: String },
    #[error("network: {0}")]
    Network(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("no such group")]
    NoSuchGroup,
    #[error("{0}")]
    Usage(String),
}

/// Key packages kept on the server; topped up when fewer remain.
pub const KEY_PACKAGES_TARGET: usize = 20;
pub const KEY_PACKAGES_LOW: u64 = 10;
/// Messages for unknown groups or future epochs kept for a retry (PROTOCOL.md 6.7).
pub const MAX_HELD: usize = 256;

/// Something the user should see after a sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// `name` is the sender's display name if known (shared inside the group).
    Text { group: Vec<u8>, from: MemberId, name: Option<String>, text: String },
    Joined { group: Vec<u8> },
    Changed { group: Vec<u8>, added: Vec<MemberId>, removed: Vec<MemberId>, epoch: u64, own_commit_discarded: bool },
    /// A member announced its display name.
    Profile { group: Vec<u8>, member: MemberId, name: String },
    RosterUpdated { group: Vec<u8> },
    LeaveRequested { group: Vec<u8>, member: MemberId },
    RemovedFromGroup { group: Vec<u8> },
    /// Kept for a later retry (unknown group yet, or a future epoch).
    Held,
    /// Could not be used and was dropped.
    Dropped { reason: String },
}

/// Result of submitting a commit to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Merged; the group is now in `epoch`.
    Accepted { epoch: u64 },
    /// Another commit won this epoch; ours was discarded. Sync, then decide again.
    Lost,
}

/// Extra data of a pending commit that the server request needs.
#[derive(Default, Serialize, Deserialize)]
struct PendingExtra {
    /// (member id hex, device id) of added devices.
    added: Vec<(String, String)>,
    removed_devices: Vec<String>,
}

type Roster = BTreeMap<String, String>;

const K_SERVER: &str = "server/url";
const K_ACCOUNT: &str = "server/account_id";
const K_DEVICE: &str = "server/device_id";
const K_AUTH_KEY: &str = "server/auth_key";

fn roster_key(g: &[u8]) -> String {
    format!("roster/{}", hex::encode(g))
}
fn pending_key(g: &[u8]) -> String {
    format!("pending/{}", hex::encode(g))
}
fn names_key(g: &[u8]) -> String {
    format!("names/{}", hex::encode(g))
}
fn announce_key(g: &[u8]) -> String {
    format!("announce/{}", hex::encode(g))
}

/// One member as the app shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub id: MemberId,
    pub device: Option<String>,
    /// Display name, if this device has learned it.
    pub name: Option<String>,
    /// Another member uses the same name: tell them apart by id (F-008).
    pub duplicate_name: bool,
}

/// One device: its encrypted profile, its server account and its groups.
pub struct Session {
    client: Client<StoredProvider>,
    api: Api,
    creds: Creds,
    groups: HashMap<Vec<u8>, Group>,
}

impl Session {
    /// New device identity in a new encrypted profile, registered as a new
    /// account on `server`.
    pub fn create(path: &str, passphrase: &str, name: &str, server: &str, pow_bits: u32) -> Result<Self, Error> {
        let api = Api::new(server)?;
        let client = Client::create(path, passphrase, name)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut seed[..]).map_err(|e| Error::Protocol(e.to_string()))?;
        let key = SigningKey::from_bytes(&seed);
        let creds = api.signup(&key, pow_bits)?;
        client.set_app_data(K_SERVER, Some(server.as_bytes()))?;
        client.set_app_data(K_ACCOUNT, Some(creds.account_id.as_bytes()))?;
        client.set_app_data(K_DEVICE, Some(creds.device_id.as_bytes()))?;
        client.set_app_data(K_AUTH_KEY, Some(&seed[..]))?;
        let mut s = Self { client, api, creds, groups: HashMap::new() };
        s.ensure_key_packages()?;
        Ok(s)
    }

    /// Opens an existing profile and resubmits any commit that was waiting
    /// for the server when the app stopped (PROTOCOL.md 7.1 step 7).
    pub fn open(path: &str, passphrase: &str) -> Result<(Self, Vec<CommitOutcome>), Error> {
        let client = Client::open(path, passphrase)?;
        let text = |k: &str| -> Result<String, Error> {
            let v = client.app_data(k)?.ok_or_else(|| Error::Protocol(format!("profile lacks {k}")))?;
            String::from_utf8(v).map_err(|_| Error::Protocol(format!("{k} is not text")))
        };
        let api = Api::new(&text(K_SERVER)?)?;
        let seed: Zeroizing<Vec<u8>> = Zeroizing::new(client.app_data(K_AUTH_KEY)?.unwrap_or_default());
        let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| Error::Protocol("bad auth key".into()))?;
        let creds = Creds { account_id: text(K_ACCOUNT)?, device_id: text(K_DEVICE)?, key: SigningKey::from_bytes(&seed) };
        let mut s = Self { client, api, creds, groups: HashMap::new() };
        let mut outcomes = Vec::new();
        for gid in s.client.group_ids()? {
            if s.group(&gid)?.pending_commit().is_some() {
                outcomes.push(s.submit(&gid)?);
            }
        }
        Ok((s, outcomes))
    }

    pub fn name(&self) -> &str {
        self.client.name()
    }
    pub fn account_id(&self) -> &str {
        &self.creds.account_id
    }
    pub fn device_id(&self) -> &str {
        &self.creds.device_id
    }
    pub fn member_id(&self) -> MemberId {
        self.client.member_id()
    }

    pub fn group_ids(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.client.group_ids()?)
    }

    fn group(&mut self, gid: &[u8]) -> Result<&mut Group, Error> {
        if !self.groups.contains_key(gid) {
            let g = self.client.load_group(gid).map_err(|e| match e {
                TreeError::NoSuchGroup => Error::NoSuchGroup,
                e => e.into(),
            })?;
            self.groups.insert(gid.to_vec(), g);
        }
        Ok(self.groups.get_mut(gid).expect("just inserted"))
    }

    /// Runs `f` on the group with the client next to it (split borrow).
    fn with<T>(&mut self, gid: &[u8], f: impl FnOnce(&mut Group, &Client<StoredProvider>) -> Result<T, TreeError>) -> Result<T, Error> {
        self.group(gid)?;
        let Self { groups, client, .. } = self;
        Ok(f(groups.get_mut(gid).expect("loaded"), client)?)
    }

    fn roster(&self, gid: &[u8]) -> Result<Roster, Error> {
        Ok(match self.client.app_data(&roster_key(gid))? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged roster".into()))?,
            None => Roster::new(),
        })
    }

    fn save_roster(&self, gid: &[u8], r: &Roster) -> Result<(), Error> {
        Ok(self.client.set_app_data(&roster_key(gid), Some(&serde_json::to_vec(r).expect("JSON")))?)
    }

    /// Devices of the other members, from the roster.
    fn other_devices(&self, gid: &[u8]) -> Result<Vec<String>, Error> {
        let mut v: Vec<String> =
            self.roster(gid)?.into_values().filter(|d| *d != self.creds.device_id).collect();
        v.sort();
        v.dedup();
        Ok(v)
    }

    fn names(&self, gid: &[u8]) -> Result<Roster, Error> {
        Ok(match self.client.app_data(&names_key(gid))? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged names".into()))?,
            None => Roster::new(),
        })
    }

    fn save_names(&self, gid: &[u8], n: &Roster) -> Result<(), Error> {
        Ok(self.client.set_app_data(&names_key(gid), Some(&serde_json::to_vec(n).expect("JSON")))?)
    }

    /// Current members with their device ids and display names as known here.
    pub fn members(&mut self, gid: &[u8]) -> Result<Vec<MemberInfo>, Error> {
        let roster = self.roster(gid)?;
        let names = self.names(gid)?;
        let ids = self.group(gid)?.members();
        let name_of = |id: &MemberId| names.get(&id.to_hex()).cloned();
        Ok(ids
            .iter()
            .map(|id| {
                let name = name_of(id);
                let duplicate_name = name.is_some() && ids.iter().filter(|o| name_of(o) == name).count() > 1;
                MemberInfo { id: *id, device: roster.get(&id.to_hex()).cloned(), name, duplicate_name }
            })
            .collect())
    }

    pub fn epoch(&mut self, gid: &[u8]) -> Result<u64, Error> {
        Ok(self.group(gid)?.epoch())
    }

    pub fn verification_code(&mut self, gid: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.group(gid)?.verification_code())
    }

    /// Keeps enough one-time key packages on the server for others to add
    /// this device while it is offline.
    pub fn ensure_key_packages(&mut self) -> Result<(), Error> {
        let count = self.api.key_package_count(&self.creds)?;
        if count < KEY_PACKAGES_LOW {
            let kps = (0..KEY_PACKAGES_TARGET).map(|_| self.client.key_package()).collect::<Result<Vec<_>, _>>()?;
            self.api.upload_key_packages(&self.creds, &kps)?;
        }
        Ok(())
    }

    /// Starts a group with only this device in it.
    pub fn create_group(&mut self) -> Result<Vec<u8>, Error> {
        let g = self.client.create_group()?;
        let gid = g.id();
        self.groups.insert(gid.clone(), g);
        let mut r = Roster::new();
        r.insert(self.member_id().to_hex(), self.creds.device_id.clone());
        self.save_roster(&gid, &r)?;
        let mut n = Roster::new();
        n.insert(self.member_id().to_hex(), self.name().to_string());
        self.save_names(&gid, &n)?;
        Ok(gid)
    }

    /// Adds every device of `account_id` in one commit.
    pub fn invite(&mut self, gid: &[u8], account_id: &str) -> Result<CommitOutcome, Error> {
        self.group(gid)?;
        let claimed = self.api.claim(&self.creds, account_id)?;
        if claimed.is_empty() {
            return Err(Error::Usage("that account has no key packages left".into()));
        }
        let mut added = Vec::new();
        for (device, kp) in &claimed {
            added.push((MemberId::of_key_package(kp)?.to_hex(), device.clone()));
        }
        let kps: Vec<&[u8]> = claimed.iter().map(|(_, kp)| kp.as_slice()).collect();
        self.with(gid, |g, c| g.add(c, &kps))?;
        self.save_pending(gid, &PendingExtra { added, removed_devices: vec![] })?;
        self.submit(gid)
    }

    /// Removes members (devices) in one commit.
    pub fn remove(&mut self, gid: &[u8], members: &[MemberId]) -> Result<CommitOutcome, Error> {
        let roster = self.roster(gid)?;
        let removed_devices = members.iter().filter_map(|m| roster.get(&m.to_hex()).cloned()).collect();
        self.with(gid, |g, c| g.remove(c, members))?;
        self.save_pending(gid, &PendingExtra { added: vec![], removed_devices })?;
        self.submit(gid)
    }

    /// Refreshes this device's keys in the group (post-compromise security).
    pub fn refresh_keys(&mut self, gid: &[u8]) -> Result<CommitOutcome, Error> {
        self.with(gid, |g, c| g.refresh_keys(c))?;
        self.save_pending(gid, &PendingExtra::default())?;
        self.submit(gid)
    }

    fn save_pending(&self, gid: &[u8], e: &PendingExtra) -> Result<(), Error> {
        Ok(self.client.set_app_data(&pending_key(gid), Some(&serde_json::to_vec(e).expect("JSON")))?)
    }

    /// Sends the pending commit of `gid` to the server and acts on the answer
    /// (PROTOCOL.md 7.1). A network error leaves the commit pending; call
    /// again (or reopen) to resubmit the same bytes.
    pub fn submit(&mut self, gid: &[u8]) -> Result<CommitOutcome, Error> {
        let p: PendingCommit = self.group(gid)?.pending_commit().ok_or_else(|| Error::Usage("nothing pending".into()))?;
        let extra: PendingExtra = match self.client.app_data(&pending_key(gid))? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged pending data".into()))?,
            None => PendingExtra::default(),
        };
        let added_devices: Vec<&String> = extra.added.iter().map(|(_, d)| d).collect();
        let req = json!({
            "group_id": api::b64(gid),
            "epoch": p.epoch,
            "recipients": self.other_devices(gid)?,
            "body": api::b64(&p.commit),
            "added": added_devices,
            "welcome": p.welcome.as_ref().map(|w| api::b64(w)),
            "removed": extra.removed_devices,
        });
        let reply = self.api.commit(&self.creds, &req)?;
        let won = match (reply.status.as_u16(), reply.code()) {
            (200, _) => true,
            (409, "COMMIT_CONFLICT") => {
                reply.body["winner_sha256"].as_str() == Some(hex::encode(Sha256::digest(&p.commit)).as_str())
            }
            _ => {
                // Not accepted and never will be: drop it.
                self.with(gid, |g, c| g.discard_commit(c))?;
                self.client.set_app_data(&pending_key(gid), None)?;
                return Err(Error::Server { status: reply.status.as_u16(), code: reply.code().to_string() });
            }
        };
        if !won {
            self.with(gid, |g, c| g.discard_commit(c))?;
            self.client.set_app_data(&pending_key(gid), None)?;
            return Ok(CommitOutcome::Lost);
        }
        let epoch = self.with(gid, |g, c| g.confirm_commit(c))?;
        let mut roster = self.roster(gid)?;
        for id in &p.removed {
            roster.remove(&id.to_hex());
        }
        for (m, d) in &extra.added {
            roster.insert(m.clone(), d.clone());
        }
        self.save_roster(gid, &roster)?;
        self.client.set_app_data(&pending_key(gid), None)?;
        if !extra.added.is_empty() {
            // Tell everyone, including the new devices, who is where.
            let names = self.names(gid)?;
            self.send_payload(gid, &Payload::Roster { devices: roster, names })?;
        }
        Ok(CommitOutcome::Accepted { epoch })
    }

    pub fn send_text(&mut self, gid: &[u8], text: &str) -> Result<usize, Error> {
        self.send_payload(gid, &Payload::Text { text: text.to_string() })
    }

    /// Asks the others to remove this device (PROTOCOL.md 6.5).
    pub fn leave(&mut self, gid: &[u8]) -> Result<usize, Error> {
        self.send_payload(gid, &Payload::Leave)
    }

    /// Returns how many devices the message was delivered to.
    fn send_payload(&mut self, gid: &[u8], p: &Payload) -> Result<usize, Error> {
        let bytes = self.with(gid, |g, c| g.send(c, &p.encode()))?;
        let to = self.other_devices(gid)?;
        if to.is_empty() {
            return Ok(0);
        }
        let v: Value = self.api.send(&self.creds, &to, &bytes)?;
        Ok(v["delivered"].as_u64().unwrap_or(0) as usize)
    }

    /// Fetches and processes the mailbox (waiting up to `wait` seconds for
    /// something to arrive), acknowledges everything processed, and retries
    /// held messages after any epoch change.
    pub fn sync(&mut self, wait: u64) -> Result<Vec<Event>, Error> {
        let msgs = self.api.fetch(&self.creds, wait)?;
        let mut events = Vec::new();
        let mut ids = Vec::new();
        let mut moved = false;
        for (id, body) in msgs {
            moved |= self.handle(&body, &mut events, true)?;
            ids.push(id);
        }
        self.api.ack(&self.creds, &ids)?;
        while moved {
            moved = self.retry_held(&mut events)?;
        }
        if events.iter().any(|e| matches!(e, Event::Joined { .. })) {
            self.ensure_key_packages()?;
        }
        // After joining, tell the others our name once we know where they are.
        for key in self.client.app_data_keys("announce/")? {
            let gid = hex::decode(&key["announce/".len()..]).map_err(|_| Error::Protocol("bad key".into()))?;
            if !self.other_devices(&gid)?.is_empty() {
                let name = self.name().to_string();
                self.send_payload(&gid, &Payload::Profile { name })?;
                self.client.set_app_data(&key, None)?;
            }
        }
        Ok(events)
    }

    /// Processes one received body. Returns true if an epoch changed or a
    /// group was joined (held messages may now be readable).
    fn handle(&mut self, body: &[u8], events: &mut Vec<Event>, may_hold: bool) -> Result<bool, Error> {
        let gid = match peek(body) {
            Some(Peek::Welcome) => {
                return match self.client.join(body) {
                    Ok(g) => {
                        let gid = g.id();
                        self.groups.insert(gid.clone(), g);
                        let mut r = Roster::new();
                        r.insert(self.member_id().to_hex(), self.creds.device_id.clone());
                        self.save_roster(&gid, &r)?;
                        let mut n = Roster::new();
                        n.insert(self.member_id().to_hex(), self.name().to_string());
                        self.save_names(&gid, &n)?;
                        self.client.set_app_data(&announce_key(&gid), Some(b"1"))?;
                        events.push(Event::Joined { group: gid });
                        Ok(true)
                    }
                    Err(e) => {
                        events.push(Event::Dropped { reason: format!("welcome: {e}") });
                        Ok(false)
                    }
                };
            }
            Some(Peek::Envelope { group_id, .. }) => group_id,
            None => {
                events.push(Event::Dropped { reason: "not a Tree message".into() });
                return Ok(false);
            }
        };
        if !self.client.group_ids()?.contains(&gid) {
            return self.hold(body, events, may_hold, "unknown group");
        }
        self.group(&gid)?;
        let incoming = self.groups.get_mut(&gid).expect("loaded").receive(&self.client, body);
        match incoming {
            Ok(Incoming::Message { from, body }) => {
                self.on_payload(&gid, from, &body, events)?;
                Ok(false)
            }
            Ok(Incoming::GroupChanged { added, removed, epoch, own_commit_discarded }) => {
                let mut roster = self.roster(&gid)?;
                let mut names = self.names(&gid)?;
                for m in &removed {
                    roster.remove(&m.to_hex());
                    names.remove(&m.to_hex());
                }
                self.save_roster(&gid, &roster)?;
                self.save_names(&gid, &names)?;
                if own_commit_discarded {
                    self.client.set_app_data(&pending_key(&gid), None)?;
                }
                events.push(Event::Changed { group: gid, added, removed, epoch, own_commit_discarded });
                Ok(true)
            }
            Ok(Incoming::OwnCommitMerged { .. }) => {
                // Our own commit came back before the server's answer did.
                self.client.set_app_data(&pending_key(&gid), None)?;
                Ok(true)
            }
            Ok(Incoming::RemovedFromGroup) => {
                events.push(Event::RemovedFromGroup { group: gid });
                Ok(true)
            }
            Ok(Incoming::OwnEcho) => Ok(false),
            Err(TreeError::Rejected(why)) if why.contains("seal") => self.hold(body, events, may_hold, &why),
            Err(e) => {
                events.push(Event::Dropped { reason: e.to_string() });
                Ok(false)
            }
        }
    }

    fn on_payload(&mut self, gid: &[u8], from: MemberId, body: &[u8], events: &mut Vec<Event>) -> Result<(), Error> {
        let me = self.member_id().to_hex();
        match Payload::decode(body) {
            Some(Payload::Text { text }) => {
                let name = self.names(gid)?.get(&from.to_hex()).cloned();
                events.push(Event::Text { group: gid.to_vec(), from, name, text })
            }
            Some(Payload::Roster { devices, names }) => {
                // Only entries for current members are taken; names only as
                // hints where the member has not announced its own.
                let members: Vec<String> = self.group(gid)?.members().iter().map(|m| m.to_hex()).collect();
                let mut roster = self.roster(gid)?;
                for (m, d) in devices {
                    if members.contains(&m) && m != me {
                        roster.insert(m, d);
                    }
                }
                self.save_roster(gid, &roster)?;
                let mut known = self.names(gid)?;
                // The sender's entry for itself is its own word, like a Profile.
                let own = names.get(&from.to_hex()).cloned();
                for (m, n) in names {
                    if members.contains(&m) && m != me {
                        known.entry(m).or_insert(n);
                    }
                }
                if let Some(n) = own {
                    known.insert(from.to_hex(), n);
                }
                self.save_names(gid, &known)?;
                events.push(Event::RosterUpdated { group: gid.to_vec() });
            }
            Some(Payload::Profile { name }) => {
                let mut known = self.names(gid)?;
                known.insert(from.to_hex(), name.clone());
                self.save_names(gid, &known)?;
                events.push(Event::Profile { group: gid.to_vec(), member: from, name });
            }
            Some(Payload::Leave) => events.push(Event::LeaveRequested { group: gid.to_vec(), member: from }),
            None => events.push(Event::Dropped { reason: format!("unsupported message from {}", &from.to_hex()[..8]) }),
        }
        Ok(())
    }

    fn hold(&mut self, body: &[u8], events: &mut Vec<Event>, may_hold: bool, why: &str) -> Result<bool, Error> {
        if !may_hold {
            return Err(Error::Protocol(format!("still held: {why}")));
        }
        let keys = self.client.app_data_keys("held/")?;
        if keys.len() >= MAX_HELD {
            self.client.set_app_data(&keys[0], None)?;
        }
        let next = keys.last().and_then(|k| k[5..].parse::<u64>().ok()).map_or(0, |n| n + 1);
        self.client.set_app_data(&format!("held/{next:020}"), Some(body))?;
        events.push(Event::Held);
        Ok(false)
    }

    /// Tries every held message once. Returns true if one changed an epoch.
    fn retry_held(&mut self, events: &mut Vec<Event>) -> Result<bool, Error> {
        let mut moved = false;
        for key in self.client.app_data_keys("held/")? {
            let Some(body) = self.client.app_data(&key)? else { continue };
            let mut ev = Vec::new();
            match self.handle(&body, &mut ev, false) {
                Ok(m) => {
                    moved |= m;
                    events.extend(ev);
                    self.client.set_app_data(&key, None)?;
                }
                Err(Error::Protocol(_)) => {} // still not readable: keep it
                Err(e) => return Err(e),
            }
        }
        Ok(moved)
    }
}
