//! Device linking with a two-sided confirmation code (PROTOCOL.md 8.11;
//! `user.device_link_code`, permanently applied).
//!
//! The new device ([`NewDevice`]) shows a link; an existing device of the
//! account reads it ([`Session::scan_link`]). Both show a six-digit code
//! computed from their own view of the whole exchange; the person confirms
//! on both that the codes are the same. Only then does the existing device
//! authorise the new one on the server, send it the account data sealed to
//! its key, and add it to every accepted group with ordinary MLS commits
//! (from the key packages the new device sent along). A link that is only
//! scanned, or confirmed on one side, links nothing.
//!
//! Removing a device ([`Session::remove_device`]) takes it out of every
//! group: by a remove commit where this device is an admin, otherwise by
//! asking the admins (a `remove_device` message they see as a leave
//! request for that member), then deletes it on the server.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tree_core::link::{self as core, Invitation, NewDeviceLink, Offer, Reveal};
use tree_core::{Client, MemberId, StoredProvider};
use zeroize::Zeroizing;

use crate::api::{b64, unb64, Api, Creds, Reply};
use crate::{CommitOutcome, Error, GroupStatus, Payload, PendingExtra, Session};

/// One-time key packages a new device sends along (plus its last-resort one,
/// used for any further group).
pub const LINK_KEY_PACKAGES: usize = core::MAX_KEY_PACKAGES - 1;
/// Account data entries carried to a new device, and their total size.
pub const MAX_ENTRIES: usize = 4096;
/// App-data keys copied to a new device: the account's contacts and
/// settings, username, recovery state (a setting), notes chat and folders.
/// Also the settings-sync state and the self group's id (`self_sync.rs`).
const CARRIED_PREFIXES: &[&str] = &["contact/", "feature/", "sync/"];
const CARRIED_KEYS: &[&str] = &["profile/username", "note/self", "folders", "muted", "archived", "pinned", OWN_MEMBERS, crate::self_sync::SELF_GROUP];
/// MLS member ids (hex) of this account's other devices, learned through
/// device links: their group additions are this account's own.
pub(crate) const OWN_MEMBERS: &str = "own/members";

/// Where a device link stands, on either device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkStatus {
    /// Waiting for the other device.
    Waiting,
    /// Compare this code with the other device, then confirm or refuse.
    Code { code: String },
    /// This side confirmed; waiting for the other side.
    Confirmed { code: String },
    /// Done. On the existing device: groups it could not add the new
    /// device to (it can invite it to them by hand).
    Linked { device_id: String, missed_groups: Vec<Vec<u8>> },
    /// Nothing was linked (refused, expired, codes differed, ...).
    Cancelled { reason: String },
}

/// What the existing device seals for the new one.
#[derive(Serialize, Deserialize)]
struct AccountData {
    account_id: String,
    /// App-data key -> value (base64).
    entries: BTreeMap<String, String>,
}

fn carried(key: &str) -> bool {
    CARRIED_KEYS.contains(&key) || CARRIED_PREFIXES.iter().any(|p| key.starts_with(p))
}

fn ok(r: Reply) -> Result<Value, Error> {
    if r.status.is_success() {
        Ok(r.body)
    } else {
        Err(Error::Server { status: r.status.as_u16(), code: r.code().to_string() })
    }
}

fn protocol(e: impl std::fmt::Display) -> Error {
    Error::Protocol(e.to_string())
}

fn remove_profile(path: &str) {
    let _ = tree_core::storage::pin::disable_pin(std::path::Path::new(path));
    for p in [path.to_string(), format!("{path}.hdr"), format!("{path}-wal"), format!("{path}-shm"), format!("{path}-journal")] {
        let _ = std::fs::remove_file(p);
    }
}

/// The member id all key packages of a reveal share (one device).
fn member_of(kps: &[Vec<u8>]) -> Result<MemberId, Error> {
    let mut ids = kps.iter().map(|k| MemberId::of_key_package(k)).collect::<Result<Vec<_>, _>>()?;
    ids.dedup();
    match ids.as_slice() {
        [one] => Ok(*one),
        _ => Err(Error::Protocol("the new device's key packages name different members".into())),
    }
}

/// A new device while it is being linked. Its encrypted profile exists
/// from the start and is deleted again if the link does not complete.
pub struct NewDevice {
    link: NewDeviceLink,
    api: Api,
    key: SigningKey,
    seed: Zeroizing<[u8; 32]>,
    client: Option<Client<StoredProvider>>,
    path: String,
    server: String,
    offer: Option<Offer>,
    reveal: Option<Reveal>,
    hash: Option<[u8; 32]>,
    status: LinkStatus,
    session: Option<Session>,
}

impl NewDevice {
    /// A new encrypted profile at `path` that waits to be linked to an
    /// account on `server`. Show [`NewDevice::link`] as a QR code or text.
    pub fn start(path: &str, passphrase: &str, name: &str, server: &str) -> Result<Self, Error> {
        if std::path::Path::new(path).exists() {
            return Err(Error::Usage(format!("{path} already exists")));
        }
        let api = Api::new(server)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut seed[..]).map_err(protocol)?;
        let key = SigningKey::from_bytes(&seed);
        let client = Client::create(path, passphrase, name)?;
        Ok(Self {
            link: NewDeviceLink::new(key.verifying_key().to_bytes()),
            api,
            key,
            seed,
            client: Some(client),
            path: path.to_string(),
            server: server.to_string(),
            offer: None,
            reveal: None,
            hash: None,
            status: LinkStatus::Waiting,
            session: None,
        })
    }

    /// The text to show (also the QR code's content).
    pub fn link(&self) -> String {
        self.link.invitation.encode()
    }

    pub fn status(&self) -> LinkStatus {
        self.status.clone()
    }

    fn path(&self) -> String {
        format!("/v1/links/{}/new", self.link.invitation.link_id_text())
    }

    fn step(&self, body: Value) -> Result<Value, Error> {
        ok(self.api.request(&self.key, "", Method::POST, &self.path(), Some(&body))?)
    }

    fn cancelled(&mut self, reason: &str) -> LinkStatus {
        self.client = None;
        remove_profile(&self.path);
        self.status = LinkStatus::Cancelled { reason: reason.to_string() };
        self.status.clone()
    }

    /// Checks for progress (call every second or two while the link screen
    /// is open).
    pub fn poll(&mut self) -> Result<LinkStatus, Error> {
        if matches!(self.status, LinkStatus::Linked { .. } | LinkStatus::Cancelled { .. }) {
            return Ok(self.status.clone());
        }
        let r = self.api.request(&self.key, "", Method::GET, &self.path(), None)?;
        let v = match r.status.as_u16() {
            404 => return Ok(self.status.clone()), // not scanned yet
            410 => return Ok(self.cancelled("the link expired")),
            _ => ok(r)?,
        };
        match v["state"].as_str().unwrap_or("") {
            "cancelled" => return Ok(self.cancelled("the other device refused")),
            "offered" if self.offer.is_none() => self.on_offer(&v)?,
            "linked" if matches!(self.status, LinkStatus::Confirmed { .. }) => self.on_linked(&v)?,
            _ => {}
        }
        Ok(self.status.clone())
    }

    fn on_offer(&mut self, v: &Value) -> Result<(), Error> {
        let raw = unb64(v["offer"].as_str().unwrap_or(""))?;
        let offer: Offer = serde_json::from_slice(&raw).map_err(|_| Error::Protocol("damaged link offer".into()))?;
        let client = self.client.as_ref().ok_or_else(|| Error::Usage("link closed".into()))?;
        let mut kps = (0..LINK_KEY_PACKAGES).map(|_| client.key_package()).collect::<Result<Vec<_>, _>>()?;
        kps.push(client.last_resort_key_package()?);
        let reveal = self.link.reveal(&kps);
        let hash = core::transcript_hash(&self.link.invitation, &offer, &reveal)?;
        self.step(json!({ "action": "reveal", "reveal": b64(&serde_json::to_vec(&reveal).expect("JSON")) }))?;
        self.status = LinkStatus::Code { code: core::code(&hash) };
        self.offer = Some(offer);
        self.reveal = Some(reveal);
        self.hash = Some(hash);
        Ok(())
    }

    /// The person compared the codes: `true` they match, `false` they do
    /// not (or the person did not start this). Refusing deletes the profile.
    pub fn confirm(&mut self, matches: bool) -> Result<LinkStatus, Error> {
        let LinkStatus::Code { code } = self.status.clone() else {
            return Err(Error::Usage("no code to confirm yet".into()));
        };
        if !matches {
            let _ = self.step(json!({ "action": "cancel" }));
            return Ok(self.cancelled("refused on this device"));
        }
        let hash = self.hash.expect("set with the code");
        let sig = self.key.sign(&core::confirm_message(&self.link.invitation.link_id, &hash));
        self.step(json!({ "action": "confirm", "transcript_hash": b64(&hash), "signature": b64(&sig.to_bytes()) }))?;
        self.status = LinkStatus::Confirmed { code };
        self.poll()
    }

    fn on_linked(&mut self, v: &Value) -> Result<(), Error> {
        let (Some(offer), Some(reveal), Some(hash)) = (self.offer.clone(), self.reveal.clone(), self.hash) else {
            return Err(Error::Protocol("link state lost".into()));
        };
        let sealed = unb64(v["sealed"].as_str().unwrap_or(""))?;
        let device_id = v["device_id"].as_str().ok_or_else(|| Error::Protocol("server reply lacks device_id".into()))?.to_string();
        let plain = Zeroizing::new(core::open(&self.link.hpke, &offer.hpke_pub()?, &hash, &sealed)?);
        let data: AccountData = serde_json::from_slice(&plain).map_err(|_| Error::Protocol("damaged account data".into()))?;
        if data.account_id != offer.account_id || data.entries.len() > MAX_ENTRIES {
            return Err(Error::Protocol("account data does not fit the link".into()));
        }
        let client = self.client.take().ok_or_else(|| Error::Usage("link closed".into()))?;
        client.set_app_data(crate::K_SERVER, Some(self.server.as_bytes()))?;
        client.set_app_data(crate::K_ACCOUNT, Some(offer.account_id.as_bytes()))?;
        client.set_app_data(crate::K_DEVICE, Some(device_id.as_bytes()))?;
        client.set_app_data(crate::K_AUTH_KEY, Some(&self.seed[..]))?;
        for (k, val) in &data.entries {
            if carried(k) {
                client.set_app_data(k, Some(&unb64(val)?))?;
            }
        }
        // The existing device is one of ours (its member id was in the
        // confirmed transcript).
        let mut own: Vec<String> = client.app_data(OWN_MEMBERS)?.and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default();
        if MemberId::from_hex(&offer.member_id).is_some() && !own.contains(&offer.member_id) {
            own.push(offer.member_id.clone());
        }
        own.retain(|m| *m != client.member_id().to_hex());
        client.set_app_data(OWN_MEMBERS, Some(&serde_json::to_vec(&own).expect("JSON")))?;
        // The last-resort key package sent along stays usable until the
        // next rotation.
        let kps = reveal.key_packages()?;
        if let Some(lr) = kps.last() {
            client.set_app_data(crate::LAST_RESORT_CUR, Some(lr))?;
        }
        let creds = Creds { account_id: offer.account_id.clone(), device_id: device_id.clone(), key: self.key.clone() };
        let mut s = Session::from_parts(client, self.api.clone(), creds, &self.path);
        s.set_time(crate::LAST_RESORT_AT, crate::messages::now())?;
        let _ = self.step(json!({ "action": "done" }));
        s.ensure_key_packages()?;
        s.sync_search_index()?;
        self.session = Some(s);
        self.status = LinkStatus::Linked { device_id, missed_groups: vec![] };
        Ok(())
    }

    /// The linked session (once [`LinkStatus::Linked`]).
    pub fn finish(mut self) -> Result<Session, Error> {
        self.session.take().ok_or_else(|| Error::Usage("not linked yet".into()))
    }

    /// Gives up: tells the server and deletes the new profile.
    pub fn abandon(mut self) {
        if self.client.is_some() {
            let _ = self.step(json!({ "action": "cancel" }));
            self.cancelled("abandoned");
        }
    }
}

/// The existing device's side of an open link.
pub(crate) struct ExistingLink {
    inv: Invitation,
    hpke: core::HpkeKey,
    offer: Offer,
    reveal: Option<Reveal>,
    hash: Option<[u8; 32]>,
    confirmed: bool,
}

impl Session {
    /// Starts linking a new device on this computer or phone (see
    /// [`NewDevice`]).
    pub fn start_link_new_device(path: &str, passphrase: &str, name: &str, server: &str) -> Result<NewDevice, Error> {
        NewDevice::start(path, passphrase, name, server)
    }

    fn link_path(&self, inv: &Invitation, tail: &str) -> String {
        format!("/v1/links/{}{tail}", inv.link_id_text())
    }

    /// Reads a new device's link (scanned QR code or pasted text) and
    /// answers it. Then poll [`Session::link_status`] for the code.
    pub fn scan_link(&mut self, text: &str) -> Result<LinkStatus, Error> {
        let inv = Invitation::parse(text)?;
        let hpke = core::HpkeKey::generate();
        let offer = Offer {
            account_id: self.creds.account_id.clone(),
            device_id: self.creds.device_id.clone(),
            member_id: self.member_id().to_hex(),
            auth_pub: core::b64url(&self.creds.key.verifying_key().to_bytes()),
            hpke_pub: core::b64url(&hpke.public()),
        };
        let body = json!({
            "link_id": inv.link_id_text(),
            "new_auth_pub": b64(&inv.auth_pub),
            "offer": b64(&serde_json::to_vec(&offer).expect("JSON")),
        });
        ok(self.api.request(&self.creds.key, &self.creds.device_id, Method::POST, "/v1/links", Some(&body))?)?;
        self.link = Some(ExistingLink { inv, hpke, offer, reveal: None, hash: None, confirmed: false });
        self.link_status()
    }

    fn end_link(&mut self, reason: &str) -> LinkStatus {
        if let Some(l) = self.link.take() {
            let path = self.link_path(&l.inv, "/cancel");
            let _ = self.api.request(&self.creds.key, &self.creds.device_id, Method::POST, &path, None);
        }
        LinkStatus::Cancelled { reason: reason.to_string() }
    }

    /// Progress of the link this device scanned.
    pub fn link_status(&mut self) -> Result<LinkStatus, Error> {
        let Some(l) = &self.link else {
            return Err(Error::Usage("no device link open".into()));
        };
        let path = self.link_path(&l.inv, "");
        let v = ok(self.api.request(&self.creds.key, &self.creds.device_id, Method::GET, &path, None)?)?;
        match v["state"].as_str().unwrap_or("") {
            "expired" => return Ok(self.end_link("the link expired")),
            "cancelled" => {
                self.link = None;
                return Ok(LinkStatus::Cancelled { reason: "the new device refused".into() });
            }
            _ => {}
        }
        let l = self.link.as_mut().expect("checked");
        if l.hash.is_none() {
            let Some(r) = v["reveal"].as_str() else { return Ok(LinkStatus::Waiting) };
            let reveal: Reveal = match serde_json::from_slice(&unb64(r)?) {
                Ok(r) => r,
                Err(_) => return Ok(self.end_link("damaged reply from the new device")),
            };
            let checked = core::transcript_hash(&l.inv, &l.offer, &reveal)
                .map_err(Error::from)
                .and_then(|h| member_of(&reveal.key_packages()?).map(|_| h));
            match checked {
                Ok(h) => {
                    l.hash = Some(h);
                    l.reveal = Some(reveal);
                }
                // A nonce that misses the commitment: someone in the middle.
                Err(_) => return Ok(self.end_link("the new device's reply does not match its link: nothing was linked")),
            }
        }
        let code = core::code(&l.hash.expect("set above"));
        if !l.confirmed {
            return Ok(LinkStatus::Code { code });
        }
        if v["state"] != "confirmed" {
            return Ok(LinkStatus::Confirmed { code });
        }
        self.complete_link(&v)
    }

    /// The person compared the codes on both devices: `true` they match.
    /// Refusing cancels the link; nothing is added.
    pub fn confirm_link(&mut self, matches: bool) -> Result<LinkStatus, Error> {
        let Some(l) = self.link.as_mut() else {
            return Err(Error::Usage("no device link open".into()));
        };
        if l.hash.is_none() {
            return Err(Error::Usage("no code to confirm yet".into()));
        }
        if !matches {
            return Ok(self.end_link("refused on this device"));
        }
        l.confirmed = true;
        self.link_status()
    }

    /// Both sides confirmed: checks the new device's signature over our own
    /// transcript hash, authorises it, seals the account data and adds the
    /// new device to the groups.
    fn complete_link(&mut self, v: &Value) -> Result<LinkStatus, Error> {
        // The account's own settings group, which the new device joins like
        // any other group; changes made here so far go to the devices
        // already in it (`self_sync.rs`).
        self.ensure_self_group()?;
        self.push_settings()?;
        let l = self.link.as_ref().expect("open");
        let hash = l.hash.expect("set");
        let theirs = v["transcript_hash"].as_str().map(unb64).transpose()?.unwrap_or_default();
        let sig: Option<[u8; 64]> = v["new_signature"].as_str().map(unb64).transpose()?.and_then(|s| s.try_into().ok());
        let key = VerifyingKey::from_bytes(&l.inv.auth_pub).map_err(protocol)?;
        let good = theirs == hash
            && sig.is_some_and(|s| key.verify_strict(&core::confirm_message(&l.inv.link_id, &hash), &ed25519_dalek::Signature::from_bytes(&s)).is_ok());
        if !good {
            return Ok(self.end_link("the two devices saw different codes: nothing was linked"));
        }
        let data = AccountData { account_id: self.creds.account_id.clone(), entries: self.account_entries()? };
        let plain = Zeroizing::new(serde_json::to_vec(&data).expect("JSON"));
        let sealed = core::seal(&l.hpke, &l.inv.hpke_pub, &hash, &plain)?;
        let auth = self.creds.key.sign(&core::authorise_message(&l.inv.link_id, &self.creds.account_id, &l.inv.auth_pub, &hash));
        let body = json!({ "transcript_hash": b64(&hash), "signature": b64(&auth.to_bytes()), "sealed": b64(&sealed) });
        let path = self.link_path(&l.inv, "/complete");
        let reply = self.api.request(&self.creds.key, &self.creds.device_id, Method::POST, &path, Some(&body))?;
        let l = self.link.take().expect("open");
        let v = ok(reply)?;
        let device_id = v["device_id"].as_str().ok_or_else(|| Error::Protocol("server reply lacks device_id".into()))?.to_string();
        let kps = l.reveal.as_ref().expect("revealed").key_packages()?;
        let member = member_of(&kps)?;
        self.add_own_member(&member)?;
        let missed_groups = self.add_linked_device(&device_id, member, &kps)?;
        Ok(LinkStatus::Linked { device_id, missed_groups })
    }

    fn account_entries(&self) -> Result<BTreeMap<String, String>, Error> {
        let mut out = BTreeMap::new();
        for k in CARRIED_KEYS {
            if let Some(v) = self.client.app_data(k)? {
                out.insert(k.to_string(), b64(&v));
            }
        }
        for p in CARRIED_PREFIXES {
            for k in self.client.app_data_keys(p)? {
                if let Some(v) = self.client.app_data(&k)? {
                    out.insert(k, b64(&v));
                }
            }
        }
        if out.len() > MAX_ENTRIES {
            return Err(Error::Usage("too much account data to carry to a new device".into()));
        }
        Ok(out)
    }

    pub(crate) fn own_members(&self) -> Result<Vec<String>, Error> {
        Ok(self.client.app_data(OWN_MEMBERS)?.and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default())
    }

    pub(crate) fn add_own_member(&self, m: &MemberId) -> Result<(), Error> {
        let mut own = self.own_members()?;
        if !own.contains(&m.to_hex()) {
            own.push(m.to_hex());
        }
        Ok(self.client.set_app_data(OWN_MEMBERS, Some(&serde_json::to_vec(&own).expect("JSON")))?)
    }

    /// Adds the newly linked device to every accepted group this device is
    /// in, one commit each, and makes it an admin where this device is one.
    /// Returns the groups where that failed.
    fn add_linked_device(&mut self, device_id: &str, member: MemberId, kps: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, Error> {
        let mut missed = Vec::new();
        let mut next = 0;
        for gid in self.group_ids()? {
            if !self.group(&gid)?.is_member() || self.group_status(&gid)? != GroupStatus::Accepted {
                continue;
            }
            if self.group(&gid)?.members().contains(&member) {
                continue;
            }
            // One-time key packages first; the last-resort one (last) for the rest.
            let kp = &kps[next.min(kps.len() - 1)];
            match self.add_device_to_group(&gid, device_id, member, kp) {
                Ok(true) => next += 1,
                Ok(false) | Err(_) => missed.push(gid),
            }
        }
        Ok(missed)
    }

    fn add_device_to_group(&mut self, gid: &[u8], device_id: &str, member: MemberId, kp: &[u8]) -> Result<bool, Error> {
        for _ in 0..3 {
            let mut accounts = self.map(&crate::accounts_key(gid))?;
            accounts.insert(member.to_hex(), self.creds.account_id.clone());
            self.save_map(&crate::accounts_key(gid), &accounts)?;
            self.with(gid, |g, c| g.add(c, &[kp]))?;
            self.save_pending(gid, &PendingExtra { added: vec![(member.to_hex(), device_id.to_string())], removed_devices: vec![], link: None })?;
            match self.submit(gid)? {
                CommitOutcome::Accepted { .. } => {
                    let me = self.member_id();
                    if self.group(gid)?.is_admin(&me) {
                        self.make_admin(gid, member, true)?;
                    }
                    return Ok(true);
                }
                CommitOutcome::Lost => {
                    self.sync(0)?;
                }
            }
        }
        Ok(false)
    }

    /// This account's devices on the server.
    pub fn devices(&self) -> Result<Vec<String>, Error> {
        let v = ok(self.api.request(&self.creds.key, &self.creds.device_id, Method::GET, "/v1/devices", None)?)?;
        Ok(v["devices"].as_array().into_iter().flatten().filter_map(|d| d.as_str().map(str::to_string)).collect())
    }

    /// Removes another device of this account: out of every group (a
    /// remove commit where this device is an admin, otherwise a request to
    /// the admins), then from the server. Returns the groups where only a
    /// request could be sent.
    pub fn remove_device(&mut self, device_id: &str) -> Result<Vec<Vec<u8>>, Error> {
        if device_id == self.creds.device_id {
            return Err(Error::Usage("this is this device: delete the account or remove it from another device".into()));
        }
        let mut asked = Vec::new();
        let mut gone_members = Vec::new();
        for gid in self.group_ids()? {
            if !self.group(&gid)?.is_member() {
                continue;
            }
            let roster = self.roster(&gid)?;
            let in_group = self.group(&gid)?.members();
            let members: Vec<MemberId> = roster
                .iter()
                .filter(|(_, d)| d.as_str() == device_id)
                .filter_map(|(m, _)| MemberId::from_hex(m))
                .filter(|m| in_group.contains(m))
                .collect();
            if members.is_empty() {
                continue;
            }
            gone_members.extend(members.iter().map(MemberId::to_hex));
            let me = self.member_id();
            let mut removed = false;
            if self.group(&gid)?.is_admin(&me) {
                for _ in 0..3 {
                    match self.remove(&gid, &members)? {
                        CommitOutcome::Accepted { .. } => {
                            removed = true;
                            break;
                        }
                        CommitOutcome::Lost => {
                            self.sync(0)?;
                        }
                    }
                }
            }
            if !removed {
                self.send_payload(&gid, &Payload::RemoveDevice { members: members.iter().map(MemberId::to_hex).collect() })?;
                asked.push(gid);
            }
        }
        let path = format!("/v1/devices/{device_id}");
        ok(self.api.request(&self.creds.key, &self.creds.device_id, Method::DELETE, &path, None)?)?;
        let mut own = self.own_members()?;
        own.retain(|m| !gone_members.contains(m));
        self.client.set_app_data(OWN_MEMBERS, Some(&serde_json::to_vec(&own).expect("JSON")))?;
        Ok(asked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_account_data_is_carried() {
        for k in ["contact/abc", "feature/user.typing", "profile/username", "note/self", "folders", "muted", "own/members", "self/group", "sync/ts/muted"] {
            assert!(carried(k), "{k}");
        }
        for k in ["server/auth_key", "server/device_id", "roster/00", "pending/00", "keypackages/last_resort", "held/1", "invite/00", "gstatus/00"] {
            assert!(!carried(k), "{k}");
        }
    }
}
