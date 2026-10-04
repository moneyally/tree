//! Messenger Core session built on the current Tree protocol.
//!
//! This crate deliberately keeps the product layer thin: MLS state and
//! authorization stay in tree-core; this layer owns server sync, device/group
//! routing, encrypted app state, and the two-phase commit handshake.

mod api;

use std::{collections::BTreeMap, path::Path};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use tree_core::{
    group::{Group, Incoming, MemberId, PendingCommit},
    storage::StoredProvider,
    Client, TreeError,
};

pub use api::{b64, unb64, Api, Creds};

const POW_BITS: u32 = 10;
const KEY_PACKAGE_TARGET: u64 = 8;
const KEY_PACKAGE_MIN: u64 = 4;

#[derive(Debug, Error)]
pub enum Error {
    #[error("tree: {0}")]
    Tree(#[from] TreeError),
    #[error("server error {status}: {code}")]
    Server { status: u16, code: String },
    #[error("usage: {0}")]
    Usage(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    pub group_id: String,
    pub from: String,
    pub name: String,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct SyncEvent {
    pub server_id: String,
    pub group_id: Vec<u8>,
    pub incoming: Incoming,
}

pub struct Session {
    client: Client<StoredProvider>,
    api: Api,
    creds: Creds,
}

impl Session {
    /// Creates an encrypted local profile, registers the device, and seeds the
    /// server with one-time key packages.
    pub fn create(
        path: impl AsRef<Path>,
        passphrase: &str,
        name: &str,
        server: &str,
    ) -> Result<Self, Error> {
        let client = Client::create(path, passphrase, name)?;
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| Error::Usage(format!("random source failed: {e}")))?;
        let key = SigningKey::from_bytes(&seed);
        let api = Api::new(server)?;
        let creds = api.signup(&key, POW_BITS)?;
        client.set_server_auth_seed(&seed)?;
        client.set_server_account(&creds.account_id, &creds.device_id)?;

        let session = Self { client, api, creds };
        session.ensure_key_packages()?;
        Ok(session)
    }

    /// Opens a previously registered encrypted profile.
    pub fn open(path: impl AsRef<Path>, passphrase: &str, server: &str) -> Result<Self, Error> {
        let client = Client::open(path, passphrase)?;
        let seed = client
            .server_auth_seed()?
            .ok_or_else(|| Error::Usage("profile is not registered on a server".into()))?;
        let (account_id, device_id) = client
            .server_account()?
            .ok_or_else(|| Error::Usage("server account metadata is missing".into()))?;
        let api = Api::new(server)?;
        let creds = Creds {
            account_id,
            device_id,
            key: SigningKey::from_bytes(&seed),
        };
        let session = Self { client, api, creds };
        session.ensure_key_packages()?;
        Ok(session)
    }

    pub fn account_id(&self) -> &str {
        &self.creds.account_id
    }

    pub fn device_id(&self) -> &str {
        &self.creds.device_id
    }

    pub fn name(&self) -> &str {
        self.client.name()
    }

    pub fn group_ids(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.client.group_ids()?)
    }

    /// Keeps enough one-time key packages available for offline invitations.
    pub fn ensure_key_packages(&self) -> Result<u64, Error> {
        let count = self.api.key_package_count(&self.creds)?;
        if count >= KEY_PACKAGE_MIN {
            return Ok(count);
        }
        let need = KEY_PACKAGE_TARGET.saturating_sub(count);
        let mut packages = Vec::with_capacity(need as usize);
        for _ in 0..need {
            packages.push(self.client.key_package()?);
        }
        if !packages.is_empty() {
            self.api.upload_key_packages(&self.creds, &packages)?;
        }
        Ok(self.api.key_package_count(&self.creds)?)
    }

    /// Creates a local MLS group and records this device as the initial roster
    /// entry. No server state is created until a member is invited.
    pub fn create_group(&self) -> Result<Vec<u8>, Error> {
        let group = self.client.create_group()?;
        let gid = group.id();
        let mut roster = BTreeMap::new();
        roster.insert(
            self.client.member_id().to_hex(),
            self.device_id().to_string(),
        );
        self.save_roster(&gid, &roster)?;
        Ok(gid)
    }

    /// Claims another account's one-time packages, creates a pending MLS add,
    /// and submits the commit through the server's epoch-ordering endpoint.
    pub fn invite_account(&self, gid: &[u8], account_id: &str) -> Result<CommitOutcome, Error> {
        let claimed = self.api.claim(&self.creds, account_id)?;
        if claimed.is_empty() {
            return Err(Error::Usage("target account has no key package".into()));
        }

        let mut added = BTreeMap::new();
        let packages: Vec<Vec<u8>> = claimed
            .iter()
            .map(|(device_id, package)| {
                let member = MemberId::of_key_package(package)?;
                added.insert(member.to_hex(), device_id.clone());
                Ok(package.clone())
            })
            .collect::<Result<_, TreeError>>()?;

        let pending = self.with_group(gid, |group| group.add(&self.client, &packages))?;
        self.submit_pending(gid, pending, added, BTreeMap::new())
    }

    pub fn remove_members(&self, gid: &[u8], members: &[MemberId]) -> Result<CommitOutcome, Error> {
        let roster = self.roster(gid)?;
        let removed = members.to_vec();
        let pending = self.with_group(gid, |group| group.remove(&self.client, members))?;
        let mut removed_devices = BTreeMap::new();
        for member in &removed {
            if let Some(device) = roster.get(&member.to_hex()) {
                removed_devices.insert(member.to_hex(), device.clone());
            }
        }
        self.submit_pending(gid, pending, BTreeMap::new(), removed_devices)
    }

    pub fn refresh_keys(&self, gid: &[u8]) -> Result<CommitOutcome, Error> {
        let pending = self.with_group(gid, |group| group.refresh_keys(&self.client))?;
        self.submit_pending(gid, pending, BTreeMap::new(), BTreeMap::new())
    }

    pub fn set_group_name(&self, gid: &[u8], name: Option<&str>) -> Result<String, Error> {
        let body = self.with_group(gid, |group| group.set_title(&self.client, name))?;
        self.send_control(gid, &body)
    }

    pub fn set_disappearing_seconds(&self, gid: &[u8], seconds: u32) -> Result<String, Error> {
        let body = self.with_group(gid, |group| {
            group.set_disappearing_seconds(&self.client, seconds)
        })?;
        self.send_control(gid, &body)
    }

    pub fn make_admin(&self, gid: &[u8], member: MemberId, admin: bool) -> Result<String, Error> {
        let body = self.with_group(gid, |group| {
            if admin {
                group.add_admin(&self.client, member)
            } else {
                group.remove_admin(&self.client, member)
            }
        })?;
        self.send_control(gid, &body)
    }

    pub fn send_text(&self, gid: &[u8], text: &str) -> Result<String, Error> {
        let roster = self.roster(gid)?;
        let recipients: Vec<String> = roster
            .values()
            .filter(|device| device.as_str() != self.device_id())
            .cloned()
            .collect();
        if recipients.is_empty() {
            return Err(Error::Usage("group has no other devices".into()));
        }
        let (_, body) = self.with_group(gid, |group| {
            group.send_message(&self.client, text.as_bytes())
        })?;
        let reply = self.api.send(&self.creds, &recipients, &body)?;
        let id = reply.body["id"]
            .as_str()
            .or_else(|| reply.body["message_id"].as_str())
            .unwrap_or_default();
        if id.is_empty() {
            return Err(Error::Usage("server did not return a message id".into()));
        }
        Ok(id.to_string())
    }

    /// Fetches mailbox messages, routes envelopes to the correct local group,
    /// joins Welcome messages, and acknowledges only messages that have been
    /// durably handled. Future-epoch messages remain unacknowledged until the
    /// corresponding commit arrives.
    pub fn sync(&self, wait: u64) -> Result<Vec<SyncEvent>, Error> {
        let messages = self.api.fetch(&self.creds, wait)?;
        let mut events = Vec::new();
        let mut ack = Vec::new();
        let mut held: Vec<(String, Vec<u8>)> = Vec::new();

        for (server_id, body) in messages {
            match Group::peek_group_id(&body) {
                Ok(gid) => {
                    let incoming =
                        self.with_group(&gid, |group| group.receive(&self.client, &body))?;
                    if matches!(incoming, Incoming::HeldForRetry { .. }) {
                        held.push((server_id.clone(), gid.clone()));
                    } else {
                        ack.push(server_id.clone());
                    }
                    if let Incoming::Message { from, name, body } = &incoming {
                        let entry = HistoryEntry {
                            group_id: hex::encode(&gid),
                            from: from.to_hex(),
                            name: name.clone(),
                            body: body.clone(),
                        };
                        self.client.set_app_data(
                            &format!("history/{server_id}"),
                            Some(&serde_json::to_vec(&entry).map_err(|e| {
                                Error::Usage(format!("history encode failed: {e}"))
                            })?),
                        )?;
                    }
                    events.push(SyncEvent {
                        server_id,
                        group_id: gid,
                        incoming,
                    });
                }
                Err(_) => {
                    let group = self.client.join(&body)?;
                    let gid = group.id();
                    let mut roster = BTreeMap::new();
                    roster.insert(
                        self.client.member_id().to_hex(),
                        self.device_id().to_string(),
                    );
                    self.save_roster(&gid, &roster)?;
                    ack.push(server_id.clone());
                    events.push(SyncEvent {
                        server_id,
                        group_id: gid,
                        incoming: Incoming::GroupChanged {
                            added: group.members(),
                            removed: Vec::new(),
                            epoch: group.epoch(),
                            own_commit_discarded: false,
                        },
                    });
                }
            }
        }

        if !ack.is_empty() {
            self.api.ack(&self.creds, &ack)?;
        }

        // A commit fetched in the same batch can make an earlier held
        // envelope decryptable. A successful retry makes its mailbox copy
        // safe to acknowledge.
        let mut retry_ack = Vec::new();
        for (server_id, gid) in held {
            let retried = self.with_group(&gid, |group| group.retry_held(&self.client))?;
            if !retried.is_empty() {
                retry_ack.push(server_id);
                for incoming in retried {
                    events.push(SyncEvent {
                        server_id: String::new(),
                        group_id: gid.clone(),
                        incoming,
                    });
                }
            }
        }
        if !retry_ack.is_empty() {
            self.api.ack(&self.creds, &retry_ack)?;
        }

        Ok(events)
    }

    pub fn history(&self, prefix: &str) -> Result<Vec<HistoryEntry>, Error> {
        let mut out = Vec::new();
        for key in self.client.app_data_keys(&format!("history/{prefix}"))? {
            if let Some(bytes) = self.client.app_data(&key)? {
                if let Ok(entry) = serde_json::from_slice::<HistoryEntry>(&bytes) {
                    out.push(entry);
                }
            }
        }
        Ok(out)
    }

    fn with_group<T>(
        &self,
        gid: &[u8],
        f: impl FnOnce(&mut Group) -> Result<T, TreeError>,
    ) -> Result<T, Error> {
        let mut group = self.client.load_group(gid)?;
        Ok(f(&mut group)?)
    }

    fn roster(&self, gid: &[u8]) -> Result<BTreeMap<String, String>, Error> {
        let key = format!("roster/{}", hex::encode(gid));
        match self.client.app_data(&key)? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| Error::Usage(format!("roster is damaged: {e}"))),
            None => Err(Error::Usage("group roster is missing".into())),
        }
    }

    fn save_roster(&self, gid: &[u8], roster: &BTreeMap<String, String>) -> Result<(), Error> {
        let key = format!("roster/{}", hex::encode(gid));
        let bytes = serde_json::to_vec(roster)
            .map_err(|e| Error::Usage(format!("roster encode failed: {e}")))?;
        self.client.set_app_data(&key, Some(&bytes))?;
        Ok(())
    }

    fn send_control(&self, gid: &[u8], body: &[u8]) -> Result<String, Error> {
        let roster = self.roster(gid)?;
        let recipients: Vec<String> = roster
            .values()
            .filter(|device| device.as_str() != self.device_id())
            .cloned()
            .collect();
        if recipients.is_empty() {
            return Err(Error::Usage("group has no other devices".into()));
        }
        let reply = self.api.send(&self.creds, &recipients, body)?;
        reply.body["id"]
            .as_str()
            .or_else(|| reply.body["message_id"].as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Usage("server did not return a message id".into()))
    }

    fn submit_pending(
        &self,
        gid: &[u8],
        pending: PendingCommit,
        added: BTreeMap<String, String>,
        removed: BTreeMap<String, String>,
    ) -> Result<CommitOutcome, Error> {
        let roster = self.roster(gid)?;
        let recipients: Vec<String> = roster
            .values()
            .filter(|device| device.as_str() != self.device_id())
            .cloned()
            .collect();
        let request = serde_json::json!({
            "group_id": b64(gid),
            "epoch": pending.epoch,
            "recipients": recipients,
            "body": b64(&pending.commit),
            "added": added.values().cloned().collect::<Vec<_>>(),
            "welcome": pending.welcome.as_ref().map(|w| b64(w)),
            "removed": removed.values().cloned().collect::<Vec<_>>(),
        });
        let reply = self.api.commit(&self.creds, &request)?;
        let winner = if reply.status.as_u16() == 200 {
            true
        } else if reply.status.as_u16() == 409 && reply.code() == "COMMIT_CONFLICT" {
            reply.body["winner_sha256"].as_str()
                == Some(hex::encode(Sha256::digest(&pending.commit)).as_str())
        } else {
            self.with_group(gid, |group| group.discard_commit(&self.client))?;
            return Err(Error::Server {
                status: reply.status.as_u16(),
                code: reply.code().to_string(),
            });
        };

        if !winner {
            self.with_group(gid, |group| group.discard_commit(&self.client))?;
            return Ok(CommitOutcome::Lost);
        }

        let epoch = self.with_group(gid, |group| group.confirm_commit(&self.client))?;
        let mut roster = roster;
        for (member, device) in removed {
            roster.remove(&member);
            let _ = device;
        }
        roster.extend(added);
        self.save_roster(gid, &roster)?;
        Ok(CommitOutcome::Accepted { epoch })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    Accepted { epoch: u64 },
    Lost,
}
