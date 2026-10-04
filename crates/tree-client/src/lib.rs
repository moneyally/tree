//! Messenger Core session built on the current Tree protocol.
//!
//! This crate deliberately keeps the product layer thin: MLS state and
//! authorization stay in tree-core; this layer owns server sync, device/group
//! routing, encrypted app state, and the two-phase commit handshake.

mod api;

use std::{
    collections::BTreeMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use tree_core::{
    group::{Group, Incoming, MemberId, PendingCommit},
    media::{
        decrypt_preview, encrypt_manifest, EncryptedChunk, MediaComposerState, MediaEnvelope,
        MediaKey, MediaLifecycle, MediaManifest, MediaViewEvent, PreviewMode, SecureMediaBytes,
        ViewPolicy,
    },
    storage::StoredProvider,
    Client, MessageEvent, TreeError,
};

pub use api::{b64, unb64, Api, Creds, MediaChunk, MediaUploadInfo};

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
    pub media_consumed: Option<MediaViewEvent>,
}

pub struct SentMedia {
    pub message_id: tree_core::MessageId,
    pub attachment_id: [u8; 16],
    pub media_id: String,
    pub expires_at: i64,
}

pub struct DownloadedMediaChunk {
    pub index: u32,
    pub plaintext: SecureMediaBytes,
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
        self.api.key_package_count(&self.creds)
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

    /// Creates the local composer state. Rendering/editing stays on-device;
    /// this object only carries bounded edit operations and send policy.
    pub fn media_composer(&self, width: u32, height: u32) -> Result<MediaComposerState, Error> {
        Ok(MediaComposerState::new(width, height)?)
    }

    /// Sends the renderer's final edited bytes. The source bytes never leave
    /// this call; only the final edited plaintext is chunk-encrypted and sent.
    #[allow(clippy::too_many_arguments)]
    pub fn send_composed_media(
        &self,
        gid: &[u8],
        rendered_plaintext: &[u8],
        media_type: &str,
        filename: &str,
        mime: &str,
        composer: &MediaComposerState,
        preview_plaintext: Option<&[u8]>,
    ) -> Result<SentMedia, Error> {
        composer.edit.validate()?;
        let edit_script_hash = composer.edit.edit_script_hash()?;
        let output_commitment = Sha256::digest(rendered_plaintext).into();
        self.send_media_with_options(
            gid,
            rendered_plaintext,
            media_type,
            filename,
            mime,
            composer.view_policy,
            composer.preview_mode,
            preview_plaintext,
            &composer.edit.caption,
            Some((edit_script_hash, output_commitment)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_media(
        &self,
        gid: &[u8],
        plaintext: &[u8],
        media_type: &str,
        filename: &str,
        mime: &str,
        policy: ViewPolicy,
        preview_mode: PreviewMode,
        preview_plaintext: Option<&[u8]>,
    ) -> Result<SentMedia, Error> {
        self.send_media_with_caption(
            gid,
            plaintext,
            media_type,
            filename,
            mime,
            policy,
            preview_mode,
            preview_plaintext,
            "",
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_media_with_caption(
        &self,
        gid: &[u8],
        plaintext: &[u8],
        media_type: &str,
        filename: &str,
        mime: &str,
        policy: ViewPolicy,
        preview_mode: PreviewMode,
        preview_plaintext: Option<&[u8]>,
        caption: &str,
    ) -> Result<SentMedia, Error> {
        self.send_media_with_options(
            gid,
            plaintext,
            media_type,
            filename,
            mime,
            policy,
            preview_mode,
            preview_plaintext,
            caption,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn send_media_with_options(
        &self,
        gid: &[u8],
        plaintext: &[u8],
        media_type: &str,
        filename: &str,
        mime: &str,
        policy: ViewPolicy,
        preview_mode: PreviewMode,
        preview_plaintext: Option<&[u8]>,
        caption: &str,
        edit_binding: Option<([u8; 32], [u8; 32])>,
    ) -> Result<SentMedia, Error> {
        if plaintext.is_empty() {
            return Err(Error::Usage("media cannot be empty".into()));
        }
        let (epoch, message_id) = self.with_group(gid, |group| {
            Ok((group.epoch(), tree_core::MessageId::generate()?))
        })?;
        let (manifest, key) = MediaManifest::generate(
            message_id,
            gid,
            epoch,
            media_type,
            filename,
            mime,
            plaintext.len() as u64,
            policy,
            preview_mode,
        )?;
        let manifest = match edit_binding {
            Some((edit_script_hash, output_commitment)) => {
                manifest.with_edit_binding(edit_script_hash, output_commitment)?
            }
            None => manifest,
        };
        let key_commitment = manifest.key_commitment(&key)?;
        let upload = self.api.media_init(
            &self.creds,
            &encrypt_manifest(&key, &manifest)?,
            &key_commitment,
            manifest.plaintext_size,
            manifest.chunk_size,
            manifest.chunk_count,
        )?;

        for index in 0..manifest.chunk_count {
            let start = index as usize * manifest.chunk_size as usize;
            let end = (start + manifest.chunk_size as usize).min(plaintext.len());
            let chunk = tree_core::media::EncryptedChunk::encrypt(
                &key,
                &manifest,
                index,
                &plaintext[start..end],
            )?;
            self.api.media_put_chunk(
                &self.creds,
                &upload.media_id,
                &upload.capability,
                index,
                &chunk.ciphertext,
            )?;
        }

        let preview = match (preview_mode, preview_plaintext) {
            (PreviewMode::None, _) | (_, None) => None,
            (_, Some(bytes)) => Some(tree_core::media::encrypt_preview(&key, &manifest, bytes)?),
        };
        self.api
            .media_finalize(&self.creds, &upload.media_id, &upload.capability)?;
        let capability: [u8; 32] = unb64(&upload.capability)?
            .try_into()
            .map_err(|_| Error::Usage("server returned an invalid media capability".into()))?;

        let envelope = MediaEnvelope::new(
            upload.media_id.clone(),
            capability,
            manifest.clone(),
            key,
            preview,
        )?
        .with_caption(caption)?
        .encode()?;
        let view_once = matches!(policy, ViewPolicy::ViewOnce);
        let ttl_secs = match policy {
            ViewPolicy::Timed { seconds } => seconds,
            _ => 0,
        };
        let _body = self.with_group(gid, |group| {
            group.send_message_with_id(
                &self.client,
                message_id,
                &envelope,
                ttl_secs,
                view_once,
                None,
            )
        })?;
        // send_message_with_id() durably queued the encrypted MLS event.
        // Drain it here, but never bypass the queue.
        self.flush_outbox()?;

        Ok(SentMedia {
            message_id,
            attachment_id: manifest.attachment_id,
            media_id: upload.media_id,
            expires_at: upload.expires_at,
        })
    }

    pub fn decode_media_message(&self, body: &[u8]) -> Result<MediaEnvelope, Error> {
        Ok(MediaEnvelope::decode(body)?)
    }

    pub fn download_media_chunk(
        &self,
        media_id: &str,
        capability: &str,
        manifest: &MediaManifest,
        key: &MediaKey,
        index: u32,
    ) -> Result<DownloadedMediaChunk, Error> {
        let chunk: MediaChunk =
            self.api
                .media_get_chunk(&self.creds, media_id, capability, index)?;
        let encrypted = EncryptedChunk {
            index: chunk.index,
            ciphertext: chunk.ciphertext,
            sha256: chunk.sha256,
        };
        let plaintext = EncryptedChunk::decrypt(key, manifest, &encrypted)?;
        Ok(DownloadedMediaChunk {
            index,
            plaintext: SecureMediaBytes::new(plaintext),
        })
    }

    pub fn download_media_chunk_from_envelope(
        &self,
        envelope: &MediaEnvelope,
        index: u32,
    ) -> Result<DownloadedMediaChunk, Error> {
        let capability = b64(&envelope.capability);
        self.download_media_chunk(
            &envelope.media_id,
            &capability,
            &envelope.manifest,
            &envelope.file_key,
            index,
        )
    }

    pub fn decrypt_media_preview(
        &self,
        envelope: &MediaEnvelope,
    ) -> Result<Option<SecureMediaBytes>, Error> {
        match &envelope.preview {
            Some(preview) => Ok(Some(SecureMediaBytes::new(decrypt_preview(
                &envelope.file_key,
                &envelope.manifest,
                preview,
            )?))),
            None => Ok(None),
        }
    }

    pub fn new_media_view(&self, envelope: &MediaEnvelope) -> MediaLifecycle {
        MediaLifecycle::new(envelope.manifest.view_policy)
    }
    pub fn confirm_media_open(
        &self,
        envelope: &MediaEnvelope,
        consumed_at: i64,
    ) -> Result<String, Error> {
        if !matches!(envelope.manifest.view_policy, ViewPolicy::ViewOnce) {
            return Err(Error::Usage("media is not configured as view-once".into()));
        }
        let event = MediaViewEvent {
            message_id: envelope.manifest.message_id,
            attachment_id: envelope.manifest.attachment_id,
            consumed_at,
        };
        let body = event.encode()?;
        let roster = self.roster(&envelope.manifest.group_id)?;
        let recipients = roster
            .values()
            .filter(|device| device.as_str() != self.device_id())
            .cloned()
            .collect::<Vec<_>>();
        if recipients.is_empty() {
            return Err(Error::Usage("group has no other devices".into()));
        }
        let reply = self.api.send(&self.creds, &recipients, &{
            let mut group = self.client.load_group(&envelope.manifest.group_id)?;
            group.send(&self.client, &body)?
        })?;
        self.client.set_app_data(
            &format!(
                "media/consumed/{}",
                hex::encode(envelope.manifest.attachment_id)
            ),
            Some(&body),
        )?;
        reply.body["id"]
            .as_str()
            .or_else(|| reply.body["message_id"].as_str())
            .map(str::to_string)
            .ok_or_else(|| {
                Error::Usage("server did not return a media consumption message id".into())
            })
    }

    pub fn media_was_consumed(&self, attachment_id: &[u8; 16]) -> Result<bool, Error> {
        Ok(self
            .client
            .app_data(&format!("media/consumed/{}", hex::encode(attachment_id)))?
            .is_some())
    }

    /// Queues an MLS message durably and immediately drains the Outbox.
    /// If transport fails, the message remains persisted and will be retried;
    /// the caller receives the transport error rather than losing the message.
    pub fn send_text(&self, gid: &[u8], text: &str) -> Result<String, Error> {
        let (message_id, _) = self.with_group(gid, |group| {
            group.send_message(&self.client, text.as_bytes())
        })?;
        self.flush_outbox()?
            .into_iter()
            .find(|(local_id, _)| local_id == message_id.as_bytes())
            .map(|(_, server_id)| server_id)
            .ok_or_else(|| Error::Usage("message was queued but not sent yet".into()))
    }

    /// Drains durable outbound messages. Each item keeps its local idempotency
    /// key across retries and process restarts, so a server-side commit that
    /// succeeded just before a client crash cannot be duplicated.
    pub fn flush_outbox(&self) -> Result<Vec<([u8; 16], String)>, Error> {
        let now = unix_now();
        self.client.recover_sending_outbox(now)?;
        let items = self.client.due_outbox(now, 32)?;
        let mut sent = Vec::new();

        for item in items {
            if !self.client.mark_outbox_sending(item.local_id, now)? {
                continue;
            }

            let result = (|| -> Result<String, Error> {
                let roster = self.roster(&item.group_id)?;
                let recipients: Vec<String> = roster
                    .values()
                    .filter(|device| device.as_str() != self.device_id())
                    .cloned()
                    .collect();
                if recipients.is_empty() {
                    return Err(Error::Usage("group has no other devices".into()));
                }
                let reply = self.api.send_with_idempotency(
                    &self.creds,
                    &recipients,
                    &item.envelope,
                    Some(&item.local_id),
                )?;
                if !reply.status.is_success() {
                    return Err(Error::Server {
                        status: reply.status.as_u16(),
                        code: reply.code().to_string(),
                    });
                }
                reply.body["id"]
                    .as_str()
                    .or_else(|| reply.body["message_id"].as_str())
                    .map(str::to_string)
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| Error::Usage("server did not return a message id".into()))
            })();

            match result {
                Ok(server_id) => {
                    self.client.mark_outbox_sent(item.local_id, &server_id)?;
                    sent.push((item.local_id, server_id));
                }
                Err(error) if retryable_outbox_error(&error) && item.attempts < 8 => {
                    let delay = 5_i64
                        .saturating_mul(1_i64 << item.attempts.min(8))
                        .min(3600);
                    self.client.mark_outbox_retry(
                        item.local_id,
                        &outbox_error_code(&error),
                        unix_now().saturating_add(delay),
                    )?;
                }
                Err(error) => {
                    self.client
                        .mark_outbox_failed(item.local_id, &outbox_error_code(&error))?;
                    return Err(error);
                }
            }
        }
        Ok(sent)
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
                    let media_consumed = if let Incoming::Message { body, .. } = &incoming {
                        match MediaViewEvent::decode(body) {
                            Ok(event) => {
                                self.client.set_app_data(
                                    &format!("media/consumed/{}", hex::encode(event.attachment_id)),
                                    Some(body),
                                )?;
                                Some(event)
                            }
                            Err(_) => None,
                        }
                    } else {
                        None
                    };
                    if let Incoming::Message { from, name, body } = &incoming {
                        if media_consumed.is_some() {
                            events.push(SyncEvent {
                                server_id,
                                group_id: gid,
                                incoming: Incoming::NoOp,
                                media_consumed,
                            });
                            continue;
                        }
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
                        media_consumed,
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
                        media_consumed: None,
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
                        media_consumed: None,
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

    fn send_control(&self, _gid: &[u8], body: &[u8]) -> Result<String, Error> {
        let event = MessageEvent::decode(body)?;
        let local_id = event.mutation_id().0;
        self.flush_outbox()?
            .into_iter()
            .find(|(id, _)| id == &local_id)
            .map(|(_, server_id)| server_id)
            .ok_or_else(|| Error::Usage("control message was queued but not sent yet".into()))
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

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn retryable_outbox_error(error: &Error) -> bool {
    match error {
        Error::Server { status, .. } => matches!(status, 408 | 429 | 500..=599),
        Error::Usage(message) => message.starts_with("HTTP request:"),
        Error::Tree(_) => false,
    }
}

fn outbox_error_code(error: &Error) -> String {
    match error {
        Error::Server { status, code } => format!("HTTP_{status}_{code}"),
        Error::Usage(message) if message.starts_with("HTTP request:") => "NETWORK".into(),
        Error::Usage(message) => format!("USAGE_{}", message.chars().take(80).collect::<String>()),
        Error::Tree(_) => "TREE_ERROR".into(),
    }
}
