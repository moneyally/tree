//! Tree client logic shared by every app (command line now, phone and
//! desktop apps later through UniFFI): one device's encrypted profile, the
//! server API, the receive loop, two-phase commits against the server's
//! commit ordering, and the member -> device roster of each group.
//!
//! Apps only draw screens; everything a client must do correctly lives here
//! or in `tree-core`.

pub mod api;
pub mod franking;
pub mod invites;
pub mod messages;
pub mod payload;
pub mod requests;
pub mod settings;
pub mod username;

pub use requests::GroupStatus;
pub use tree_core::storage::messages::StoredMessage;

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
pub use messages::TextOptions;
pub use payload::{FileInfo, Payload};
pub use tree_core::recovery::{Phrase, Words};
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
    /// A feature-registry error code (`LOCKED_ALWAYS`, `NOT_ADMIN`, ...).
    #[error("feature: {0}")]
    Feature(String),
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
    /// `request`: the group is still a message request (not yet accepted).
    /// `formatted`: show Tree markup (sent with it and `chat.formatting`
    /// applied). `mentions_me`: this device's member is mentioned, or an
    /// @all the group allows.
    Text {
        group: Vec<u8>,
        id: String,
        from: MemberId,
        name: Option<String>,
        text: String,
        request: bool,
        formatted: bool,
        mentions_me: bool,
    },
    /// The sender edited its message `id`.
    Edited { group: Vec<u8>, id: String, from: MemberId, text: String },
    /// The sender deleted its message `id` for everyone.
    Deleted { group: Vec<u8>, id: String, from: MemberId },
    /// A member reacted to message `id` (or took the reaction back).
    Reaction { group: Vec<u8>, id: String, from: MemberId, emoji: String, remove: bool },
    /// An attachment arrived; fetch it with [`Session::download`].
    File { group: Vec<u8>, from: MemberId, name: Option<String>, file: FileInfo, request: bool },
    /// A stranger started a chat (`direct`) or added this device to a
    /// group; shown in the request inbox until accepted or declined.
    Request { group: Vec<u8>, from: String, direct: bool },
    /// A group was declined automatically (blocked adder, settings).
    Declined { group: Vec<u8>, from: String, reason: String },
    Joined { group: Vec<u8> },
    Changed { group: Vec<u8>, added: Vec<MemberId>, removed: Vec<MemberId>, epoch: u64, own_commit_discarded: bool, settings_changed: bool },
    /// A member announced its display name.
    Profile { group: Vec<u8>, member: MemberId, name: String },
    /// A contact's devices changed (new device or replaced key): compare the
    /// safety number again. Always reported (`user.key_change_warning` is
    /// permanently on). `was_verified`: the old set had been verified.
    KeyChanged { account: String, new_members: Vec<MemberId>, was_verified: bool },
    RosterUpdated { group: Vec<u8> },
    LeaveRequested { group: Vec<u8>, member: MemberId },
    RemovedFromGroup { group: Vec<u8> },
    /// Kept for a later retry (unknown group yet, or a future epoch).
    Held,
    /// Could not be used and was dropped.
    Dropped { reason: String },
    /// Someone used one of this device's invite links and was added.
    InviteLinkUsed { group: Vec<u8>, account: String },
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
fn accounts_key(g: &[u8]) -> String {
    format!("accounts/{}", hex::encode(g))
}
fn contact_key(account: &str) -> String {
    format!("contact/{account}")
}

/// What this device knows about another account (trust on first use, then
/// pinned).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub account: String,
    /// Member ids (hex) of the account's devices seen so far.
    pub members: Vec<String>,
    /// The user compared the safety number for exactly these devices.
    pub verified: bool,
    /// The user chose this contact (invited it or accepted its request).
    #[serde(default)]
    pub accepted: bool,
    #[serde(default)]
    pub blocked: bool,
}

impl Contact {
    pub fn member_ids(&self) -> Vec<MemberId> {
        self.members.iter().filter_map(|m| MemberId::from_hex(m)).collect()
    }
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

/// Pinning rule (trust on first use): the first set of devices of an account
/// is taken as it is; afterwards every member id not seen before is a key
/// change, reported, and clears "verified". Returns the updated contact if
/// anything changed.
fn merge_pins(old: Option<Contact>, account: &str, members: &[MemberId]) -> Option<(Contact, Option<Event>)> {
    let first = old.is_none();
    let mut c = old.unwrap_or_else(|| Contact { account: account.to_string(), ..Default::default() });
    let mut new: Vec<MemberId> = members.iter().filter(|m| !c.members.contains(&m.to_hex())).copied().collect();
    new.sort();
    new.dedup();
    if new.is_empty() && !first {
        return None;
    }
    let event = (!first).then(|| Event::KeyChanged { account: account.to_string(), new_members: new.clone(), was_verified: c.verified });
    if !first {
        c.verified = false;
    }
    c.members.extend(new.iter().map(MemberId::to_hex));
    Some((c, event))
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
        Self::create_with(path, passphrase, name, server, |api, key| api.signup(key, pow_bits))
    }

    /// A new profile on a new device that joins an existing account with the
    /// recovery phrase (PROTOCOL.md 8.6). Groups and history are not
    /// restored: contacts add this device again and see a key change. With
    /// `revoke_others`, every other device of the account is removed.
    pub fn recover(
        path: &str,
        passphrase: &str,
        name: &str,
        server: &str,
        phrase: &str,
        revoke_others: bool,
        pow_bits: u32,
    ) -> Result<Self, Error> {
        let phrase = Phrase::parse(phrase)?;
        let rk = phrase.recovery_key();
        Self::create_with(path, passphrase, name, server, |api, key| {
            let sig = rk.sign_recovery(&key.verifying_key().to_bytes(), revoke_others);
            api.recover(key, &rk.public_key(), &sig, revoke_others, pow_bits)
        })
    }

    fn create_with(
        path: &str,
        passphrase: &str,
        name: &str,
        server: &str,
        register: impl FnOnce(&Api, &SigningKey) -> Result<Creds, Error>,
    ) -> Result<Self, Error> {
        if std::path::Path::new(path).exists() {
            return Err(Error::Usage(format!("{path} already exists")));
        }
        let api = Api::new(server)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut seed[..]).map_err(|e| Error::Protocol(e.to_string()))?;
        let key = SigningKey::from_bytes(&seed);
        let creds = register(&api, &key)?;
        let client = Client::create(path, passphrase, name)?;
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

    fn map(&self, key: &str) -> Result<Roster, Error> {
        Ok(match self.client.app_data(key)? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Protocol(format!("damaged {key}")))?,
            None => Roster::new(),
        })
    }

    fn save_map(&self, key: &str, m: &Roster) -> Result<(), Error> {
        Ok(self.client.set_app_data(key, Some(&serde_json::to_vec(m).expect("JSON")))?)
    }

    /// Starts the per-group maps with this device's own entries.
    fn init_group_maps(&self, gid: &[u8]) -> Result<(), Error> {
        let me = self.member_id().to_hex();
        self.save_roster(gid, &[(me.clone(), self.creds.device_id.clone())].into())?;
        self.save_names(gid, &[(me.clone(), self.name().to_string())].into())?;
        self.save_map(&accounts_key(gid), &[(me, self.creds.account_id.clone())].into())
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
        self.init_group_maps(&gid)?;
        Ok(gid)
    }

    /// Registers (or changes) this account's @username. The server stores
    /// only its hash. `discoverable = false` hides it from lookups
    /// (`user.discoverable` released).
    pub fn set_username(&self, name: &str, discoverable: bool) -> Result<String, Error> {
        let n = username::normalise(name).map_err(|e| Error::Usage(e.into()))?;
        let h = username::hash(&n).map_err(|e| Error::Usage(e.into()))?;
        self.api.username(&self.creds, "apply", Some(&json!({ "hash": api::b64(&h), "discoverable": discoverable })))?;
        self.client.set_app_data("profile/username", Some(n.as_bytes()))?;
        Ok(n)
    }

    /// Registers the endpoint a push gateway gave this app (UnifiedPush
    /// style), or clears it. The server then sends only the word `wake`
    /// there when something arrives (PROTOCOL.md 8.8); the app syncs.
    pub fn set_push_endpoint(&self, endpoint: Option<&str>) -> Result<(), Error> {
        self.api.set_push(&self.creds, endpoint)
    }

    /// Makes a new recovery phrase for this account and registers its
    /// recovery key with the server (replacing any earlier phrase). The
    /// phrase is returned once to be shown to the user and is not stored.
    pub fn new_recovery_phrase(&self, words: usize, list: Words) -> Result<Phrase, Error> {
        let p = Phrase::generate(words, list)?;
        self.api.set_recovery(&self.creds, Some(&p.recovery_key().public_key()))?;
        self.change(settings::RECOVERY, true, None)?;
        Ok(p)
    }

    /// Drops the recovery key: the account can then not be recovered.
    pub fn release_recovery(&self) -> Result<(), Error> {
        self.release_feature(settings::RECOVERY).map(|_| ())
    }

    /// Whether this device registered a recovery phrase.
    pub fn has_recovery(&self) -> Result<bool, Error> {
        Ok(self.feature(settings::RECOVERY)?.state == tree_core::features::State::Applied)
    }

    pub fn release_username(&self) -> Result<(), Error> {
        self.api.username(&self.creds, "release", None)?;
        Ok(self.client.set_app_data("profile/username", None)?)
    }

    pub fn username(&self) -> Result<Option<String>, Error> {
        Ok(self.client.app_data("profile/username")?.and_then(|v| String::from_utf8(v).ok()))
    }

    /// Account id behind a discoverable @username, if any.
    pub fn find(&self, name: &str) -> Result<Option<String>, Error> {
        let h = username::hash(name).map_err(|e| Error::Usage(e.into()))?;
        match self.api.username(&self.creds, "lookup", Some(&json!({ "hash": api::b64(&h) }))) {
            Ok(v) => Ok(v["account_id"].as_str().map(str::to_string)),
            Err(Error::Server { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn contact(&self, account: &str) -> Result<Option<Contact>, Error> {
        Ok(match self.client.app_data(&contact_key(account))? {
            Some(v) => Some(serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged contact".into()))?),
            None => None,
        })
    }

    pub fn contacts(&self) -> Result<Vec<Contact>, Error> {
        let mut out = Vec::new();
        for k in self.client.app_data_keys("contact/")? {
            if let Some(c) = self.contact(&k["contact/".len()..])? {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// Records that `members` belong to `account`. The first time they are
    /// trusted as they are; afterwards any member id not seen before is a
    /// key change and is reported (and clears "verified").
    fn pin(&self, account: &str, members: &[MemberId], events: &mut Vec<Event>) -> Result<(), Error> {
        if account == self.creds.account_id {
            return Ok(());
        }
        if let Some((c, ev)) = merge_pins(self.contact(account)?, account, members) {
            self.client.set_app_data(&contact_key(account), Some(&serde_json::to_vec(&c).expect("JSON")))?;
            events.extend(ev);
        }
        Ok(())
    }

    /// The safety number shared with `account` (60 digits), from this
    /// device and the account's pinned devices.
    pub fn safety_number(&self, account: &str) -> Result<String, Error> {
        let c = self.contact(account)?.ok_or_else(|| Error::Usage("unknown contact".into()))?;
        Ok(tree_core::safety::safety_number(&[self.member_id()], &c.member_ids()))
    }

    /// The QR payload this device shows for `account`.
    pub fn safety_qr(&self, account: &str) -> Result<Vec<u8>, Error> {
        let c = self.contact(account)?.ok_or_else(|| Error::Usage("unknown contact".into()))?;
        Ok(tree_core::safety::qr_payload(&[self.member_id()], &c.member_ids()))
    }

    /// Marks the contact verified after the user compared the safety number
    /// (or scanned the other side's QR code: pass it to check it first).
    pub fn verify(&self, account: &str, scanned_qr: Option<&[u8]>) -> Result<(), Error> {
        let mut c = self.contact(account)?.ok_or_else(|| Error::Usage("unknown contact".into()))?;
        if let Some(q) = scanned_qr {
            if !tree_core::safety::qr_matches(q, &[self.member_id()], &c.member_ids()) {
                return Err(Error::Usage("the scanned code does not match: do not trust this contact".into()));
            }
        }
        c.verified = true;
        Ok(self.client.set_app_data(&contact_key(account), Some(&serde_json::to_vec(&c).expect("JSON")))?)
    }

    /// Adds every device of `account_id` in one commit. Returns the outcome
    /// and any key-change warnings for that account.
    pub fn invite(&mut self, gid: &[u8], account_id: &str) -> Result<(CommitOutcome, Vec<Event>), Error> {
        self.group(gid)?;
        let claimed = self.api.claim(&self.creds, account_id)?;
        if claimed.is_empty() {
            return Err(Error::Usage("that account has no key packages left".into()));
        }
        let mut added = Vec::new();
        let mut ids = Vec::new();
        for (device, kp) in &claimed {
            let id = MemberId::of_key_package(kp)?;
            ids.push(id);
            added.push((id.to_hex(), device.clone()));
        }
        let mut events = Vec::new();
        self.pin(account_id, &ids, &mut events)?;
        self.accept_contact(account_id)?;
        let mut accounts = self.map(&accounts_key(gid))?;
        for i in &ids {
            accounts.insert(i.to_hex(), account_id.to_string());
        }
        self.save_map(&accounts_key(gid), &accounts)?;
        let kps: Vec<&[u8]> = claimed.iter().map(|(_, kp)| kp.as_slice()).collect();
        self.with(gid, |g, c| g.add(c, &kps))?;
        self.save_pending(gid, &PendingExtra { added, removed_devices: vec![] })?;
        Ok((self.submit(gid)?, events))
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
            let members: Vec<String> = self.group(gid)?.members().iter().map(|m| m.to_hex()).collect();
            let mut accounts = self.map(&accounts_key(gid))?;
            accounts.retain(|m, _| members.contains(m));
            self.save_map(&accounts_key(gid), &accounts)?;
            self.send_payload(gid, &Payload::Roster { devices: roster, names, accounts })?;
        }
        Ok(CommitOutcome::Accepted { epoch })
    }

    /// The settings every member of the group agrees on: admins, name, chat features.
    pub fn group_settings(&mut self, gid: &[u8]) -> Result<tree_core::group_settings::GroupSettings, Error> {
        Ok(self.group(gid)?.settings())
    }

    /// An admin changes the group settings (one commit through the server).
    pub fn change_group_settings(&mut self, gid: &[u8], new: &tree_core::group_settings::GroupSettings) -> Result<CommitOutcome, Error> {
        self.with(gid, |g, c| g.change_settings(c, new))?;
        self.save_pending(gid, &PendingExtra::default())?;
        self.submit(gid)
    }

    pub fn make_admin(&mut self, gid: &[u8], member: MemberId, admin: bool) -> Result<CommitOutcome, Error> {
        let mut s = self.group_settings(gid)?;
        s.admins.retain(|a| *a != member);
        if admin {
            s.admins.push(member);
        }
        self.change_group_settings(gid, &s)
    }

    pub fn set_group_name(&mut self, gid: &[u8], name: Option<String>) -> Result<CommitOutcome, Error> {
        let mut s = self.group_settings(gid)?;
        s.name = name;
        self.change_group_settings(gid, &s)
    }

    /// An admin applies or releases a chat-scope feature for the whole group
    /// (checked against the registry: permanent locks, server locks).
    pub fn set_chat_feature(&mut self, gid: &[u8], key: &str, apply: bool, option: Option<String>) -> Result<CommitOutcome, Error> {
        use tree_core::features::{Caller, Plan, Registry, Scope};
        let mut r = Registry::standard();
        let admin = Caller { plan: Plan::Free, is_admin: true };
        let status = if apply { r.apply(key, option, admin) } else { r.release(key, admin) }
            .map_err(|e| Error::Feature(e.code().into()))?;
        if !r.list(Scope::Chat).iter().any(|s| s.key == status.key) {
            return Err(Error::Feature("NOT_A_CHAT_FEATURE".into()));
        }
        let mut s = self.group_settings(gid)?;
        s.features.insert(
            key.to_string(),
            tree_core::group_settings::ChatSetting { applied: status.state == tree_core::features::State::Applied, option: status.option },
        );
        self.change_group_settings(gid, &s)
    }


    /// Asks the others to remove this device (PROTOCOL.md 6.5).
    pub fn leave(&mut self, gid: &[u8]) -> Result<usize, Error> {
        self.send_payload(gid, &Payload::Leave)
    }

    /// Returns how many devices the message was delivered to.
    pub(crate) fn send_payload(&mut self, gid: &[u8], p: &Payload) -> Result<usize, Error> {
        let to = self.other_devices(gid)?;
        if to.is_empty() {
            return Ok(0);
        }
        let encoded = if p.is_franked_kind() {
            let inner = String::from_utf8(p.encode()).expect("JSON is UTF-8");
            let r = self.frank(gid, &inner)?;
            Payload::Franked { p: r.payload, k: r.key, tag: r.tag, m: r.minute }.encode()
        } else {
            p.encode()
        };
        let bytes = self.with(gid, |g, c| g.send(c, &encoded))?;
        let v: Value = self.api.send(&self.creds, &to, &bytes)?;
        Ok(v["delivered"].as_u64().unwrap_or(0) as usize)
    }

    /// Fetches and processes the mailbox (waiting up to `wait` seconds for
    /// something to arrive), acknowledges everything processed, and retries
    /// held messages after any epoch change.
    pub fn sync(&mut self, wait: u64) -> Result<Vec<Event>, Error> {
        self.client.purge_expired_messages(messages::now())?;
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
        self.handle_invite_requests(&mut events)?;
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
                        self.init_group_maps(&gid)?;
                        self.client.set_app_data(&announce_key(&gid), Some(b"1"))?;
                        self.set_group_status(&gid, &GroupStatus::Request { from: None })?;
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
        if self.group_status(&gid)? == GroupStatus::Declined {
            return Ok(false); // ignored after declining
        }
        self.group(&gid)?;
        let incoming = self.groups.get_mut(&gid).expect("loaded").receive(&self.client, body);
        match incoming {
            Ok(Incoming::Message { from, body }) => {
                self.on_payload(&gid, from, &body, events)?;
                Ok(false)
            }
            Ok(Incoming::GroupChanged { added, removed, epoch, own_commit_discarded, settings_changed }) => {
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
                events.push(Event::Changed { group: gid, added, removed, epoch, own_commit_discarded, settings_changed });
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
        let (payload, franking) = match Payload::decode(body) {
            Some(Payload::Franked { p, k, tag, m }) => match Payload::decode(p.as_bytes()) {
                Some(inner) if inner.is_franked_kind() => {
                    let rec = franking::Record { payload: p, key: k, tag, minute: m };
                    (Some(inner), Some(rec.encode()))
                }
                _ => {
                    events.push(Event::Dropped { reason: "malformed franked payload".into() });
                    return Ok(());
                }
            },
            other => (other, None),
        };
        match payload {
            Some(p @ (Payload::Text { .. } | Payload::Edit { .. } | Payload::Delete { .. } | Payload::React { .. } | Payload::File(_))) => {
                if let Some(a) = self.map(&accounts_key(gid))?.get(&from.to_hex()) {
                    if self.is_blocked(a)? {
                        events.push(Event::Dropped { reason: "from a blocked account".into() });
                        return Ok(());
                    }
                }
                self.on_message(gid, from, p, franking, events)?;
            }
            Some(Payload::Roster { devices, names, accounts }) => {
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
                // Remember and pin the devices of each named account.
                let mut known_accounts = self.map(&accounts_key(gid))?;
                let mut by_account: BTreeMap<String, Vec<MemberId>> = BTreeMap::new();
                for (m, a) in accounts {
                    if let (true, Some(id)) = (members.contains(&m) && m != me, MemberId::from_hex(&m)) {
                        known_accounts.insert(m, a.clone());
                        by_account.entry(a).or_default().push(id);
                    }
                }
                self.save_map(&accounts_key(gid), &known_accounts)?;
                for (a, ids) in by_account {
                    self.pin(&a, &ids, events)?;
                }
                // The roster's sender added us if we are still a request.
                if let Some(adder) = self.map(&accounts_key(gid))?.get(&from.to_hex()).cloned() {
                    self.decide_request(gid, &adder, events)?;
                }
                events.push(Event::RosterUpdated { group: gid.to_vec() });
            }
            Some(Payload::Profile { name }) => {
                let mut known = self.names(gid)?;
                known.insert(from.to_hex(), name.clone());
                self.save_names(gid, &known)?;
                events.push(Event::Profile { group: gid.to_vec(), member: from, name });
            }
            Some(Payload::Leave) => events.push(Event::LeaveRequested { group: gid.to_vec(), member: from }),
            Some(Payload::Franked { .. }) | None => events.push(Event::Dropped { reason: format!("unsupported message from {}", &from.to_hex()[..8]) }),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> MemberId {
        MemberId([b; 32])
    }

    #[test]
    fn pinning_rules() {
        // first contact: trusted as is, no warning
        let (c, ev) = merge_pins(None, "acc", &[id(1), id(1)]).unwrap();
        assert_eq!((c.members.len(), c.verified, ev), (1, false, None));
        // same devices again: nothing to do
        assert!(merge_pins(Some(c.clone()), "acc", &[id(1)]).is_none());
        // a device missing from a claim (no key packages left) is no change
        assert!(merge_pins(Some(c.clone()), "acc", &[]).is_none());
        // verified, then a new device appears: warning, verification cleared
        let verified = Contact { verified: true, ..c };
        let (c2, ev) = merge_pins(Some(verified), "acc", &[id(1), id(2)]).unwrap();
        assert_eq!(ev, Some(Event::KeyChanged { account: "acc".into(), new_members: vec![id(2)], was_verified: true }));
        assert!(!c2.verified);
        assert_eq!(c2.member_ids(), vec![id(1), id(2)]);
        // unverified change is reported too
        let (_, ev) = merge_pins(Some(c2), "acc", &[id(3)]).unwrap();
        assert!(matches!(ev, Some(Event::KeyChanged { was_verified: false, .. })));
    }
}
