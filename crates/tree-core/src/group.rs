//! An end-to-end encrypted conversation.
//!
//! A 1:1 chat is a two-member group, so one code path covers everything.
//! Every method returns or takes plain bytes for the transport layer.
//!
//! Membership changes are two-phase (docs/PROTOCOL.md section 7.1):
//! [`Group::add`], [`Group::remove`] and [`Group::refresh_keys`] return a
//! [`PendingCommit`] without changing the group. The app submits it to the
//! server and then calls [`Group::confirm_commit`] (accepted) or
//! [`Group::discard_commit`] (another commit won the epoch).

use std::fmt;

use openmls::prelude::{tls_codec::Deserialize, *};
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    client::Client,
    error::{group_err, TreeError},
    group_state::{GroupState, PastEpoch, Pending, PendingEnvelope},
    message::{MessageEvent, MessageId, DEFAULT_EDIT_WINDOW_SECS},
    message_state::{MessageRecord, PendingMutation},
    provider::TreeProvider,
};

/// A conversation this device belongs to.
pub struct Group {
    pub(crate) mls: MlsGroup,
    pub(crate) state: GroupState,
}

/// Identifies a member (one device) of a group:
/// `SHA-256("tree/member-id/v1" || signature_key)` (PROTOCOL.md section 5.2).
///
/// Unlike the display name it cannot be chosen freely: it is bound to the
/// device's MLS signature key, which is unique within a group.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemberId(pub [u8; 32]);

impl MemberId {
    const LABEL: &'static [u8] = b"tree/member-id/v1";

    /// Member id of the device with this MLS signature public key.
    pub fn of(signature_key: &[u8]) -> Self {
        Self(
            Sha256::new()
                .chain_update(Self::LABEL)
                .chain_update(signature_key)
                .finalize()
                .into(),
        )
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Debug for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemberId({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A member as shown to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub id: MemberId,
    /// Self-chosen display name. NOT authenticated (F-008): never use it for
    /// a security decision.
    pub name: String,
    /// Another member of the group carries the same name. The app must
    /// tell them apart by `id` (safety number), not by name.
    pub duplicate_name: bool,
}

/// A commit this device made that the server has not accepted yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCommit {
    pub group_id: Vec<u8>,
    /// Epoch the commit was made in; the server orders commits per
    /// (group, epoch).
    pub epoch: u64,
    /// Sealed commit, for all other current members (including removed ones).
    pub commit: Vec<u8>,
    /// Welcome for the added devices, if any. It must only be delivered if
    /// this commit wins (send it in the same request as the commit).
    pub welcome: Option<Vec<u8>>,
    pub added: Vec<MemberId>,
    pub removed: Vec<MemberId>,
}

/// What an incoming message turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// A chat message. `from` is authenticated; `name` is not (F-008).
    Message {
        from: MemberId,
        name: String,
        body: Vec<u8>,
    },
    /// Another member's commit was merged: members joined, were removed, or
    /// someone refreshed their keys. If this device had a pending commit for
    /// the same epoch, it lost and was discarded (`own_commit_discarded`);
    /// decide again in the new epoch.
    GroupChanged {
        added: Vec<Member>,
        removed: Vec<Member>,
        epoch: u64,
        own_commit_discarded: bool,
    },
    /// Our pending commit came back from the server, so it was accepted and
    /// is now merged (same as [`Group::confirm_commit`]).
    OwnCommitMerged { epoch: u64 },
    /// This device was removed; it can no longer read or send.
    RemovedFromGroup,
    /// A future-epoch envelope was held locally until the corresponding commit arrives.
    HeldForRetry { epoch: u64 },
    /// The group's E2E settings changed through an authenticated control message.
    SettingsChanged {
        seq: u64,
        title: Option<String>,
        disappearing_seconds: u32,
    },
    /// One or more authenticated structured message events were received.
    StructuredMessages {
        events: Vec<(MemberId, MessageEvent)>,
    },
    /// A valid encrypted event caused no visible state change (duplicate or
    /// an out-of-order mutation waiting for its target message).
    NoOp,
    /// Our own message or already merged commit echoed back; nothing to do.
    OwnEcho,
}

impl Group {
    /// Every message is padded to a multiple of this many bytes so the
    /// ciphertext length leaks less about the plaintext length.
    pub const PADDING: usize = 256;

    /// Application messages of this many past epochs can still be read
    /// (F-002). Costs forward secrecy: their keys live this much longer.
    pub const PAST_EPOCHS: u64 = 2;

    /// Envelope format version byte.
    const ENVELOPE_V1: u8 = 1;
    const TAG_LEN: usize = 32;

    pub(crate) fn new(mls: MlsGroup, mut state: GroupState) -> Self {
        if state.admins.is_empty() {
            if let Some(id) = mls
                .members()
                .min_by_key(|m| m.index)
                .map(|m| MemberId::of(&m.signature_key))
            {
                state.admins.push(id);
            }
        }
        state.admins.sort_unstable();
        state.admins.dedup();
        Self { mls, state }
    }

    pub(crate) fn sender_ratchet() -> SenderRatchetConfiguration {
        // Tolerate some reordering, but bound how far ahead keys may be derived.
        SenderRatchetConfiguration::new(32, 1000)
    }

    pub fn id(&self) -> Vec<u8> {
        self.mls.group_id().as_slice().to_vec()
    }

    pub fn epoch(&self) -> u64 {
        self.mls.epoch().as_u64()
    }

    pub fn is_member(&self) -> bool {
        self.mls.is_active()
    }

    pub fn title(&self) -> Option<String> {
        self.state.title.clone()
    }

    pub fn disappearing_seconds(&self) -> u32 {
        self.state.disappearing_seconds
    }

    /// Encrypt a group-settings control message. Only the v1
    /// administrator may create settings controls.
    pub fn set_title<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        title: Option<&str>,
    ) -> Result<Vec<u8>, TreeError> {
        if !self.is_admin(me) {
            return Err(TreeError::Rejected(
                "only a group administrator may change settings".into(),
            ));
        }
        let title = title.map(str::trim).filter(|s| !s.is_empty());
        if let Some(title) = title {
            if title.len() > 128 {
                return Err(TreeError::Group(
                    "group title is limited to 128 UTF-8 bytes".into(),
                ));
            }
            if title.chars().any(char::is_control) {
                return Err(TreeError::Group(
                    "group title contains control characters".into(),
                ));
            }
        }
        self.send_control(me, Control::SetTitle(title.map(ToOwned::to_owned)))
    }

    /// Set the group disappearing timer. Zero disables it; maximum is 30 days.
    pub fn set_disappearing_seconds<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        seconds: u32,
    ) -> Result<Vec<u8>, TreeError> {
        if seconds > 30 * 86_400 {
            return Err(TreeError::Group(
                "disappearing timer is limited to 30 days".into(),
            ));
        }
        if !self.is_admin(me) {
            return Err(TreeError::Rejected(
                "only the group administrator may change settings".into(),
            ));
        }
        self.send_control(me, Control::SetDisappearingSeconds(seconds))
    }

    /// Grant administrator role to a current member.
    pub fn add_admin<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        target: MemberId,
    ) -> Result<Vec<u8>, TreeError> {
        if !self.is_admin(me) {
            return Err(TreeError::Rejected(
                "only a group administrator may change administrators".into(),
            ));
        }
        if !self.members().iter().any(|member| member.id == target) {
            return Err(TreeError::UnknownMember(target.to_hex()));
        }
        self.send_control(me, Control::AddAdmin(target))
    }

    /// Remove administrator role. At least one administrator must remain.
    pub fn remove_admin<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        target: MemberId,
    ) -> Result<Vec<u8>, TreeError> {
        if !self.is_admin(me) {
            return Err(TreeError::Rejected(
                "only a group administrator may change administrators".into(),
            ));
        }
        if self.state.admins.contains(&target) && self.state.admins.len() == 1 {
            return Err(TreeError::Group(
                "a group must always retain at least one administrator".into(),
            ));
        }
        if !self.members().iter().any(|member| member.id == target) {
            return Err(TreeError::UnknownMember(target.to_hex()));
        }
        self.send_control(me, Control::RemoveAdmin(target))
    }

    /// Current members in leaf order.
    pub fn members(&self) -> Vec<Member> {
        let list: Vec<(MemberId, String)> = self
            .mls
            .members()
            .map(|m| (MemberId::of(&m.signature_key), name_of(&m.credential)))
            .collect();
        list.iter()
            .map(|(id, name)| Member {
                id: *id,
                name: name.clone(),
                duplicate_name: list.iter().filter(|(_, n)| n == name).count() > 1,
            })
            .collect()
    }

    /// Value both sides can compare out of band (QR / safety number) to
    /// confirm they are in the same group state with no one in the middle.
    pub fn verification_code(&self) -> Vec<u8> {
        self.mls.epoch_authenticator().as_slice().to_vec()
    }

    /// True after joining until this device has sent its first key refresh.
    /// The app should then call [`Group::refresh_keys`] soon: the device's
    /// current key came from a one-time key package that sat on the server.
    pub fn should_refresh_keys(&self) -> bool {
        self.state.should_refresh
    }

    // ----- two-phase commits -------------------------------------------------

    /// Returns the encrypted group administrator list.
    pub fn admins(&self) -> Vec<MemberId> {
        self.state.admins.clone()
    }

    pub fn is_admin(&self, me: &Client<impl TreeProvider>) -> bool {
        self.state.admins.contains(&me.member_id())
    }

    /// Adds devices by their key packages, in one commit. Adding a person
    /// means adding all of their devices at once. The commit carries no
    /// update path (much smaller in large groups); the adder's own key is
    /// refreshed by its next [`Group::refresh_keys`].
    pub fn add<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        key_packages: &[impl AsRef<[u8]>],
    ) -> Result<PendingCommit, TreeError> {
        if key_packages.is_empty() {
            return Err(TreeError::Group("nothing to add".into()));
        }
        if !self.is_admin(me) {
            return Err(TreeError::Rejected(
                "only a group administrator may add members".into(),
            ));
        }
        let kps = key_packages
            .iter()
            .map(|kp| {
                let kp = KeyPackageIn::tls_deserialize_exact(kp.as_ref())
                    .map_err(|e| TreeError::Malformed(format!("{e:?}")))?
                    .validate(me.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|e| TreeError::InvalidKeyPackage(format!("{e:?}")))?;
                if kp.ciphersuite() != me.ciphersuite {
                    return Err(TreeError::InvalidKeyPackage("ciphersuite mismatch".into()));
                }
                Ok(kp)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.begin_commit(me, |mls| {
            let (commit, welcome, _info) = mls
                .add_members_without_update(&me.provider, &me.signer, &kps)
                .map_err(group_err)?;
            Ok((commit, Some(welcome)))
        })
    }

    /// Removes members (devices) by member id, all in one commit. Removing a
    /// person means removing all of their devices at once. Their reading
    /// ability ends with the epoch this commit creates.
    pub fn remove<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        members: &[MemberId],
    ) -> Result<PendingCommit, TreeError> {
        if members.is_empty() {
            return Err(TreeError::Group("nothing to remove".into()));
        }
        if !self.is_admin(me) {
            return Err(TreeError::Rejected(
                "only a group administrator may remove members".into(),
            ));
        }
        let own = me.member_id();
        let mut leaves = Vec::new();
        for id in members {
            if *id == own {
                return Err(TreeError::Group(
                    "a device cannot remove itself; send a leave request instead".into(),
                ));
            }
            if self.state.admins.contains(id)
                && self
                    .state
                    .admins
                    .iter()
                    .filter(|admin| *admin != id)
                    .count()
                    == 0
            {
                return Err(TreeError::Group(
                    "the last administrator must be transferred before removal".into(),
                ));
            }
            let index = self
                .mls
                .members()
                .find(|m| MemberId::of(&m.signature_key) == *id)
                .map(|m| m.index)
                .ok_or_else(|| TreeError::UnknownMember(id.to_hex()))?;
            if !leaves.contains(&index) {
                leaves.push(index);
            }
        }
        self.begin_commit(me, |mls| {
            let (commit, _welcome, _info) = mls
                .remove_members(&me.provider, &me.signer, &leaves)
                .map_err(group_err)?;
            Ok((commit, None))
        })
    }

    /// Refreshes this device's keys. Run periodically and after any
    /// suspicion of compromise: an attacker who copied old state loses
    /// access once this commit is merged (post-compromise security).
    pub fn refresh_keys<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
    ) -> Result<PendingCommit, TreeError> {
        self.begin_commit(me, |mls| {
            let bundle = mls
                .self_update(&me.provider, &me.signer, LeafNodeParameters::default())
                .map_err(group_err)?;
            Ok((bundle.into_commit(), None))
        })
    }

    /// The commit waiting for the server's answer, if any. After a restart,
    /// resubmit exactly these bytes before doing anything else in the group.
    pub fn pending_commit(&self) -> Option<PendingCommit> {
        let p = self.state.pending.as_ref()?;
        let staged = self.mls.pending_commit()?;
        Some(PendingCommit {
            group_id: self.id(),
            epoch: p.epoch,
            commit: p.commit.clone(),
            welcome: p.welcome.clone(),
            added: staged
                .add_proposals()
                .map(|a| {
                    MemberId::of(
                        a.add_proposal()
                            .key_package()
                            .leaf_node()
                            .signature_key()
                            .as_slice(),
                    )
                })
                .collect(),
            removed: staged
                .remove_proposals()
                .filter_map(|r| self.mls.member_at(r.remove_proposal().removed()))
                .map(|m| MemberId::of(&m.signature_key))
                .collect(),
        })
    }

    /// The server accepted our pending commit: merge it. Returns the new epoch.
    pub fn confirm_commit<P: TreeProvider>(&mut self, me: &Client<P>) -> Result<u64, TreeError> {
        let Some(pending) = &self.state.pending else {
            return Err(TreeError::NoPendingCommit);
        };
        let hash = sha256(&pending.commit);
        let sealed_in = pending.epoch;
        me.provider.atomically(|| {
            let past = self.past_epoch(me)?;
            let refreshed = self
                .mls
                .pending_commit()
                .is_some_and(|s| s.update_path_leaf_node().is_some());
            self.mls
                .merge_pending_commit(&me.provider)
                .map_err(group_err)?;
            self.state.pending = None;
            self.state.sent.push((sealed_in, hash));
            if refreshed {
                self.state.should_refresh = false;
            }
            self.entered_new_epoch(past);
            self.save(me)?;
            Ok(self.epoch())
        })
    }

    /// The server rejected our pending commit (another commit won the
    /// epoch): drop it and its welcome. Doing nothing when nothing is
    /// pending.
    pub fn discard_commit<P: TreeProvider>(&mut self, me: &Client<P>) -> Result<(), TreeError> {
        if self.state.pending.is_none() {
            return Ok(());
        }
        me.provider.atomically(|| {
            self.mls
                .clear_pending_commit(me.provider.storage())
                .map_err(group_err)?;
            self.state.pending = None;
            self.save(me)
        })
    }

    fn begin_commit<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        build: impl FnOnce(&mut MlsGroup) -> Result<(MlsMessageOut, Option<MlsMessageOut>), TreeError>,
    ) -> Result<PendingCommit, TreeError> {
        if !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }
        // (OpenMLS's own pending commit is always stored together with ours.)
        if self.state.pending.is_some() {
            return Err(TreeError::CommitPending);
        }
        let epoch = self.epoch();
        me.provider.atomically(|| {
            // Tree never stores proposals (F-007); make sure none can be
            // folded into this commit.
            self.mls
                .clear_pending_proposals(me.provider.storage())
                .map_err(group_err)?;
            let result = build(&mut self.mls).and_then(|(commit, welcome)| {
                // Sealed with the CURRENT epoch: what the other members hold.
                let commit = self.seal(me, &commit.to_bytes().map_err(group_err)?)?;
                let welcome = welcome
                    .map(|w| w.to_bytes().map_err(group_err))
                    .transpose()?;
                self.state.pending = Some(Pending {
                    epoch,
                    commit,
                    welcome,
                });
                self.save(me)
            });
            if result.is_err() {
                self.state.pending = None;
                let _ = self.mls.clear_pending_commit(me.provider.storage());
            }
            result
        })?;
        Ok(self.pending_commit().expect("pending commit just stored"))
    }

    // ----- application messages ---------------------------------------------

    fn send_control<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        control: Control,
    ) -> Result<Vec<u8>, TreeError> {
        if !self.is_admin(me) || !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }
        let old_seq = self.state.last_control_seq;
        let seq = old_seq
            .checked_add(1)
            .ok_or_else(|| TreeError::Group("settings sequence exhausted".into()))?;
        let bytes = encode_control(seq, &control)?;
        let result = me.provider.atomically(|| {
            let out = self
                .mls
                .create_message(&me.provider, &me.signer, &bytes)
                .map_err(group_err)?;
            let envelope = self.seal(me, &out.to_bytes().map_err(group_err)?)?;
            let members = self
                .mls
                .members()
                .map(|m| MemberId::of(&m.signature_key))
                .collect::<Vec<_>>();
            apply_control_state(&mut self.state, &control, &members)?;
            self.state.last_control_seq = seq;
            self.save(me)?;
            Ok(envelope)
        });
        if result.is_err() {
            self.state.last_control_seq = old_seq;
        }
        result
    }

    /// Sends a structured text message using the group's current disappearing
    /// timer. The returned id is stable across edits/deletes.
    pub fn send_message<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        body: &[u8],
    ) -> Result<(MessageId, Vec<u8>), TreeError> {
        self.send_new_message(me, body, self.state.disappearing_seconds, false, None)
    }

    pub fn send_message_with_options<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        body: &[u8],
        ttl_secs: u32,
        view_once: bool,
        preview: Option<Vec<u8>>,
    ) -> Result<(MessageId, Vec<u8>), TreeError> {
        if ttl_secs > 30 * 86_400 {
            return Err(TreeError::Group(
                "disappearing timer is limited to 30 days".into(),
            ));
        }
        self.send_new_message(me, body, ttl_secs, view_once, preview)
    }

    fn send_new_message<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        body: &[u8],
        ttl_secs: u32,
        view_once: bool,
        preview: Option<Vec<u8>>,
    ) -> Result<(MessageId, Vec<u8>), TreeError> {
        let id = MessageId::generate()?;
        let seq = self.state.messages.next_outgoing_seq()?;
        let event = MessageEvent::New {
            id,
            seq,
            sent_at: unix_now(),
            ttl_secs,
            view_once,
            body: body.to_vec(),
            preview,
        };
        let now = unix_now();
        let author = me.member_id();
        let envelope = self.send_structured_with_update(me, &event, move |group| {
            group.state.messages.record_new(MessageRecord {
                id,
                author,
                created_at: now,
                ttl_secs,
                view_once,
                deleted: false,
                last_edit_seq: seq,
            });
            Ok(())
        })?;
        Ok((id, envelope))
    }

    pub fn edit_message<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        target: MessageId,
        body: &[u8],
    ) -> Result<Vec<u8>, TreeError> {
        let record = self
            .state
            .messages
            .record(target)
            .ok_or_else(|| TreeError::UnknownMember(target.to_hex()))?;
        if record.author != me.member_id() {
            return Err(TreeError::Rejected(
                "only the message author may edit it".into(),
            ));
        }
        if record.deleted {
            return Err(TreeError::Rejected(
                "deleted message cannot be edited".into(),
            ));
        }
        if unix_now().saturating_sub(record.created_at) as u64 > DEFAULT_EDIT_WINDOW_SECS {
            return Err(TreeError::Rejected(
                "message edit window has expired".into(),
            ));
        }
        let seq = self.state.messages.next_outgoing_seq()?;
        let event = MessageEvent::Edit {
            target,
            seq,
            edited_at: unix_now(),
            body: body.to_vec(),
        };
        self.send_structured_with_update(me, &event, |group| {
            if let Some(record) = group.state.messages.record_mut(target) {
                record.last_edit_seq = seq;
            }
            Ok(())
        })
    }

    pub fn delete_message<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        target: MessageId,
    ) -> Result<Vec<u8>, TreeError> {
        let record = self
            .state
            .messages
            .record(target)
            .ok_or_else(|| TreeError::Group("message is not present in local ledger".into()))?;
        if record.author != me.member_id() {
            return Err(TreeError::Rejected(
                "only the message author may delete it".into(),
            ));
        }
        let seq = self.state.messages.next_outgoing_seq()?;
        let event = MessageEvent::Delete {
            target,
            seq,
            deleted_at: unix_now(),
        };
        self.send_structured_with_update(me, &event, |group| {
            if let Some(record) = group.state.messages.record_mut(target) {
                record.deleted = true;
                record.last_edit_seq = seq;
            }
            Ok(())
        })
    }

    pub fn react_to_message<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        target: MessageId,
        reaction: &str,
        add: bool,
    ) -> Result<Vec<u8>, TreeError> {
        if self.state.messages.record(target).is_none() {
            return Err(TreeError::Group(
                "message is not present in local ledger".into(),
            ));
        }
        let seq = self.state.messages.next_outgoing_seq()?;
        let event = MessageEvent::Reaction {
            target,
            seq,
            reaction: reaction.to_string(),
            add,
        };
        self.send_structured_with_update(me, &event, |_group| Ok(()))
    }

    pub fn send_read_receipt<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        target: MessageId,
    ) -> Result<Vec<u8>, TreeError> {
        if self.state.messages.record(target).is_none() {
            return Err(TreeError::Group(
                "message is not present in local ledger".into(),
            ));
        }
        let seq = self.state.messages.next_outgoing_seq()?;
        self.send_structured_with_update(
            me,
            &MessageEvent::Read {
                target,
                seq,
                read_at: unix_now(),
            },
            |_group| Ok(()),
        )
    }

    pub fn send_typing<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        active: bool,
    ) -> Result<Vec<u8>, TreeError> {
        let seq = self.state.messages.next_outgoing_seq()?;
        self.send_structured_with_update(me, &MessageEvent::Typing { seq, active }, |_group| Ok(()))
    }

    fn send_structured_with_update<P, F>(
        &mut self,
        me: &Client<P>,
        event: &MessageEvent,
        update: F,
    ) -> Result<Vec<u8>, TreeError>
    where
        P: TreeProvider,
        F: FnOnce(&mut Self) -> Result<(), TreeError>,
    {
        let body = event.encode()?;
        me.provider.atomically(|| {
            let out = self
                .mls
                .create_message(&me.provider, &me.signer, &body)
                .map_err(group_err)?;
            let envelope = self.seal(me, &out.to_bytes().map_err(group_err)?)?;
            update(self)?;
            self.save(me)?;
            Ok(envelope)
        })
    }

    /// Encrypts a chat message for everyone in the group (in the current
    /// epoch; also while a commit of ours is pending).
    pub fn send<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        body: &[u8],
    ) -> Result<Vec<u8>, TreeError> {
        if !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }
        if body.starts_with(CONTROL_MAGIC) {
            return Err(TreeError::Rejected(
                "message body uses a reserved Tree control prefix".into(),
            ));
        }
        me.provider.atomically(|| {
            let out = self
                .mls
                .create_message(&me.provider, &me.signer, body)
                .map_err(group_err)?;
            self.seal(me, &out.to_bytes().map_err(group_err)?)
        })
    }

    // ----- receiving ---------------------------------------------------------

    /// Decrypts and authenticates anything received for this group
    /// (PROTOCOL.md section 6.6). Anything tampered with, replayed, from a
    /// non-member, for another group, a proposal, or a commit for a past
    /// epoch is rejected.
    pub fn receive<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        bytes: &[u8],
    ) -> Result<Incoming, TreeError> {
        if !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }
        let hash = sha256(bytes);
        if let Some(p) = &self.state.pending {
            if bool::from(sha256(&p.commit).ct_eq(&hash)) {
                // The server only delivers accepted commits: ours won.
                let epoch = self.confirm_commit(me)?;
                return Ok(Incoming::OwnCommitMerged { epoch });
            }
        }
        if self
            .state
            .sent
            .iter()
            .any(|(_, h)| bool::from(h.ct_eq(&hash)))
        {
            return Ok(Incoming::OwnEcho);
        }
        if self
            .state
            .processed
            .iter()
            .any(|(_, h)| bool::from(h.ct_eq(&hash)))
        {
            return Ok(Incoming::OwnEcho);
        }
        let now = unix_now();
        self.state.prune_future(now);

        // Read only enough of the MLS message to learn its epoch. No MLS
        // state is touched until the Tree envelope seal is verified.
        let announced = peek_epoch(bytes, self.mls.group_id().as_slice())?;
        if announced > self.epoch() {
            if !self
                .state
                .future
                .iter()
                .any(|p| bool::from(sha256(&p.bytes).ct_eq(&hash)))
            {
                self.state.future.push(PendingEnvelope {
                    epoch: announced,
                    received_at: now,
                    bytes: bytes.to_vec(),
                });
                self.state.prune_future(now);
                self.save(me)?;
            }
            return Ok(Incoming::HeldForRetry { epoch: announced });
        }

        // Checked before anything is written.
        let (epoch, body) = self.open_envelope(me, bytes)?;
        let msg = MlsMessageIn::tls_deserialize_exact(body)
            .map_err(|e| TreeError::Malformed(format!("{e:?}")))?;
        let protocol = msg
            .try_into_protocol_message()
            .map_err(|_| TreeError::Malformed("not a group message".into()))?;
        if protocol.wire_format() != WireFormat::PrivateMessage {
            return Err(TreeError::Rejected(
                "only private messages are accepted".into(),
            ));
        }
        if protocol.group_id().as_slice() != self.mls.group_id().as_slice()
            || protocol.epoch().as_u64() != epoch
        {
            return Err(TreeError::Rejected(
                "header does not match the envelope".into(),
            ));
        }
        match protocol.content_type() {
            ContentType::Application => {}
            ContentType::Commit if epoch == self.epoch() => {}
            ContentType::Commit => {
                return Err(TreeError::Rejected("commit for a past epoch".into()))
            }
            ContentType::Proposal => {
                return Err(TreeError::Rejected(
                    "proposals are not accepted in Tree v1 (F-007)".into(),
                ))
            }
        }
        me.provider
            .atomically(|| self.process(me, protocol, epoch, hash))
    }

    fn process<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        protocol: ProtocolMessage,
        epoch: u64,
        hash: [u8; 32],
    ) -> Result<Incoming, TreeError> {
        let processed = self
            .mls
            .process_message(&me.provider, protocol)
            .map_err(|e| TreeError::Rejected(format!("{e:?}")))?;
        let sender = processed.sender().clone();
        let name = name_of(processed.credential());
        let aad_empty = processed.aad().is_empty();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => {
                if !aad_empty {
                    return Err(TreeError::Rejected(
                        "authenticated data must be empty".into(),
                    ));
                }
                let from = self.sender_id(epoch, &sender)?;
                let body = m.into_bytes();
                if body.starts_with(crate::message::MESSAGE_MAGIC) {
                    let event = MessageEvent::decode(&body)?;
                    let events = self.apply_message_event(from, event)?;
                    self.mark_processed(epoch, hash);
                    self.state.future.retain(|p| sha256(&p.bytes) != hash);
                    self.save(me)?;
                    return Ok(if events.is_empty() {
                        Incoming::NoOp
                    } else {
                        Incoming::StructuredMessages { events }
                    });
                }
                if body.starts_with(CONTROL_MAGIC) {
                    if epoch != self.epoch() {
                        return Err(TreeError::Rejected(
                            "settings controls from past epochs are not accepted".into(),
                        ));
                    }
                    if !self.state.admins.contains(&from) {
                        return Err(TreeError::Rejected(
                            "settings control sender is not an administrator".into(),
                        ));
                    }
                    let control = decode_control(&body)?;
                    if control.seq <= self.state.last_control_seq {
                        self.mark_processed(epoch, hash);
                        self.save(me)?;
                        return Ok(Incoming::OwnEcho);
                    }
                    let members = self
                        .mls
                        .members()
                        .map(|m| MemberId::of(&m.signature_key))
                        .collect::<Vec<_>>();
                    apply_control_state(&mut self.state, &control.control, &members)?;
                    self.state.last_control_seq = control.seq;
                    self.mark_processed(epoch, hash);
                    self.state.future.retain(|p| sha256(&p.bytes) != hash);
                    self.save(me)?;
                    return Ok(Incoming::SettingsChanged {
                        seq: control.seq,
                        title: self.state.title.clone(),
                        disappearing_seconds: self.state.disappearing_seconds,
                    });
                }
                self.mark_processed(epoch, hash);
                self.state.future.retain(|p| sha256(&p.bytes) != hash);
                self.save(me)?;
                Ok(Incoming::Message { from, name, body })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let Sender::Member(committer) = sender else {
                    return Err(TreeError::Rejected("commit from a non-member".into()));
                };
                check_commit(&staged, committer)?;
                let removed_leaves: Vec<LeafNodeIndex> = staged
                    .remove_proposals()
                    .map(|p| p.remove_proposal().removed())
                    .collect();
                let added_ids: Vec<MemberId> = staged
                    .add_proposals()
                    .map(|p| {
                        MemberId::of(
                            p.add_proposal()
                                .key_package()
                                .leaf_node()
                                .signature_key()
                                .as_slice(),
                        )
                    })
                    .collect();
                let removed: Vec<Member> = self
                    .members()
                    .into_iter()
                    .zip(self.mls.members())
                    .filter(|(_, m)| removed_leaves.contains(&m.index))
                    .map(|(member, _)| member)
                    .collect();
                let own_commit_discarded = self.state.pending.is_some();
                let past = self.past_epoch(me)?;

                // Merging another member's commit also drops our pending one.
                self.mls
                    .merge_staged_commit(&me.provider, *staged)
                    .map_err(group_err)?;
                self.state.pending = None;
                self.entered_new_epoch(past);
                let current_epoch = self.epoch();
                self.state.future.retain(|p| p.epoch > current_epoch);
                self.reconcile_admins();
                self.mark_processed(epoch, hash);
                self.save(me)?;
                if !self.mls.is_active() {
                    return Ok(Incoming::RemovedFromGroup);
                }
                let added = self
                    .members()
                    .into_iter()
                    .filter(|m| added_ids.contains(&m.id))
                    .collect();
                Ok(Incoming::GroupChanged {
                    added,
                    removed,
                    epoch: self.epoch(),
                    own_commit_discarded,
                })
            }
            ProcessedMessageContent::OwnPrivateMessage => {
                self.mark_processed(epoch, hash);
                self.state.future.retain(|p| sha256(&p.bytes) != hash);
                self.save(me)?;
                Ok(Incoming::OwnEcho)
            }
            _ => Err(TreeError::Rejected(
                "message type not accepted in Tree v1".into(),
            )),
        }
    }

    /// Member id of the sender of a message from `epoch`.
    fn sender_id(&self, epoch: u64, sender: &Sender) -> Result<MemberId, TreeError> {
        let Sender::Member(leaf) = sender else {
            return Err(TreeError::Rejected("message from a non-member".into()));
        };
        let found = if epoch == self.epoch() {
            self.mls
                .member_at(*leaf)
                .map(|m| MemberId::of(&m.signature_key))
        } else {
            self.state
                .past
                .iter()
                .find(|p| p.epoch == epoch)
                .and_then(|p| {
                    p.members
                        .iter()
                        .find(|(l, _)| *l == leaf.u32())
                        .map(|(_, id)| *id)
                })
        };
        found.ok_or_else(|| TreeError::Rejected("unknown sender".into()))
    }

    // ----- epochs ------------------------------------------------------------

    /// What to keep of the current epoch once the group moves on.
    fn past_epoch<P: TreeProvider>(&self, me: &Client<P>) -> Result<PastEpoch, TreeError> {
        Ok(PastEpoch {
            epoch: self.epoch(),
            envelope_key: self.envelope_key(me)?,
            members: self
                .mls
                .members()
                .map(|m| (m.index.u32(), MemberId::of(&m.signature_key)))
                .collect(),
        })
    }

    fn entered_new_epoch(&mut self, left: PastEpoch) {
        self.state.past.insert(0, left);
        self.state
            .prune(self.epoch().saturating_sub(Self::PAST_EPOCHS));
    }

    fn save<P: TreeProvider>(&self, me: &Client<P>) -> Result<(), TreeError> {
        let encoded = self.state.encode()?;
        me.provider
            .save_group_state(self.mls.group_id().as_slice(), &encoded)
    }

    fn reconcile_admins(&mut self) {
        let current: Vec<MemberId> = self
            .mls
            .members()
            .map(|m| MemberId::of(&m.signature_key))
            .collect();
        self.state.admins.retain(|admin| current.contains(admin));
        if self.state.admins.is_empty() {
            if let Some(id) = self
                .mls
                .members()
                .min_by_key(|m| m.index)
                .map(|m| MemberId::of(&m.signature_key))
            {
                self.state.admins.push(id);
            }
        }
        self.state.admins.sort_unstable();
        self.state.admins.dedup();
    }

    fn apply_message_event(
        &mut self,
        from: MemberId,
        event: MessageEvent,
    ) -> Result<Vec<(MemberId, MessageEvent)>, TreeError> {
        let now = unix_now();
        match event.clone() {
            MessageEvent::New {
                id,
                sent_at: _,
                ttl_secs,
                view_once,
                ..
            } => {
                if self.state.messages.record(*id).is_some() {
                    return Ok(Vec::new());
                }
                if *ttl_secs > 30 * 86_400 {
                    return Err(TreeError::Group("message TTL exceeds 30 days".into()));
                }
                let record = MessageRecord {
                    id: *id,
                    author: from,
                    created_at: now,
                    ttl_secs: *ttl_secs,
                    view_once: *view_once,
                    deleted: false,
                    last_edit_seq: event.seq(),
                };
                self.state.messages.record_new(record);
                let mut output = vec![(from, event)];
                let mut pending = self.state.messages.take_pending_for(*id);
                pending.sort_by_key(|mutation| mutation.event.seq());
                for mutation in pending {
                    if self.apply_pending_mutation(now, mutation.from, mutation.event.clone())? {
                        output.push((mutation.from, mutation.event));
                    }
                }
                Ok(output)
            }
            MessageEvent::Edit { target, .. } | MessageEvent::Delete { target, .. } => {
                if self.state.messages.record(*target).is_none() {
                    self.state
                        .messages
                        .queue_pending(PendingMutation { from, event });
                    return Ok(Vec::new());
                }
                if self.apply_pending_mutation(now, from, event.clone())? {
                    Ok(vec![(from, event)])
                } else {
                    Ok(Vec::new())
                }
            }
            MessageEvent::Reaction { target, .. } | MessageEvent::Read { target, .. } => {
                if self.state.messages.record(*target).is_none() {
                    self.state
                        .messages
                        .queue_pending(PendingMutation { from, event });
                    return Ok(Vec::new());
                }
                Ok(vec![(from, event)])
            }
            MessageEvent::Typing { .. } => Ok(vec![(from, event)]),
        }
    }

    fn apply_pending_mutation(
        &mut self,
        now: i64,
        from: MemberId,
        event: MessageEvent,
    ) -> Result<bool, TreeError> {
        let target = event
            .target()
            .ok_or_else(|| TreeError::Malformed("mutation has no target".into()))?;
        let record = self
            .state
            .messages
            .record_mut(target)
            .ok_or_else(|| TreeError::Storage("message record disappeared".into()))?;

        match &event {
            MessageEvent::Edit { seq, .. } | MessageEvent::Delete { seq, .. } => {
                if record.author != from {
                    return Err(TreeError::Rejected(
                        "message mutation sender is not the original author".into(),
                    ));
                }
                if record.deleted {
                    return Ok(false);
                }
                if now.saturating_sub(record.created_at) as u64 > DEFAULT_EDIT_WINDOW_SECS {
                    return Ok(false);
                }
                if *seq <= record.last_edit_seq {
                    return Ok(false);
                }
                if matches!(event, MessageEvent::Delete { .. }) {
                    record.deleted = true;
                }
                record.last_edit_seq = *seq;
                Ok(true)
            }
            MessageEvent::Reaction { .. } | MessageEvent::Read { .. } => {
                if record.deleted {
                    return Ok(false);
                }
                Ok(true)
            }
            MessageEvent::New { .. } | MessageEvent::Typing { .. } => Ok(false),
        }
    }

    fn mark_processed(&mut self, epoch: u64, hash: [u8; 32]) {
        self.state.processed.push((epoch, hash));
        const MAX_PROCESSED: usize = 2048;
        if self.state.processed.len() > MAX_PROCESSED {
            let drop_n = self.state.processed.len() - MAX_PROCESSED;
            self.state.processed.drain(0..drop_n);
        }
        self.state
            .prune(self.epoch().saturating_sub(Self::PAST_EPOCHS));
    }

    // ----- envelope (PROTOCOL.md section 4) ----------------------------------

    /// Outer seal over the full MLS ciphertext, keyed by a secret only
    /// members of the epoch can export. Checked BEFORE the message reaches
    /// MLS, so a tampered or injected copy is dropped without consuming the
    /// message key (otherwise the genuine message would become undecryptable).
    fn seal<P: OpenMlsProvider>(
        &self,
        me: &Client<P>,
        mls_bytes: &[u8],
    ) -> Result<Vec<u8>, TreeError> {
        let tag = envelope_tag(me, &self.envelope_key(me)?[..], mls_bytes)?;
        let mut out = Vec::with_capacity(1 + Self::TAG_LEN + mls_bytes.len());
        out.push(Self::ENVELOPE_V1);
        out.extend_from_slice(&tag);
        out.extend_from_slice(mls_bytes);
        Ok(out)
    }

    fn envelope_key<P: OpenMlsProvider>(
        &self,
        me: &Client<P>,
    ) -> Result<Zeroizing<[u8; 32]>, TreeError> {
        let key = Zeroizing::new(
            self.mls
                .export_secret(
                    me.provider.crypto(),
                    "tree/envelope/v1",
                    self.mls.group_id().as_slice(),
                    32,
                )
                .map_err(group_err)?,
        );
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&key);
        Ok(out)
    }

    /// Checks the seal under the keys of the current and retained past
    /// epochs; returns the epoch whose key matched and the MLS bytes.
    fn open_envelope<'a, P: OpenMlsProvider>(
        &self,
        me: &Client<P>,
        bytes: &'a [u8],
    ) -> Result<(u64, &'a [u8]), TreeError> {
        if bytes.len() < 1 + Self::TAG_LEN || bytes[0] != Self::ENVELOPE_V1 {
            return Err(TreeError::Malformed("bad envelope".into()));
        }
        let (tag, body) = bytes[1..].split_at(Self::TAG_LEN);
        let current = (self.epoch(), self.envelope_key(me)?);
        let keys = std::iter::once((current.0, &current.1))
            .chain(self.state.past.iter().map(|p| (p.epoch, &p.envelope_key)));
        for (epoch, key) in keys {
            let expected = envelope_tag(me, &key[..], body)?;
            if bool::from(tag.ct_eq(&expected)) {
                return Ok((epoch, body));
            }
        }
        Err(TreeError::Rejected("envelope seal mismatch".into()))
    }
}

fn envelope_tag<P: OpenMlsProvider>(
    me: &Client<P>,
    key: &[u8],
    mls_bytes: &[u8],
) -> Result<Vec<u8>, TreeError> {
    let tag = me
        .provider
        .crypto()
        .hmac(openmls_traits::types::HashType::Sha2_256, key, mls_bytes)
        .map_err(group_err)?;
    Ok(tag.as_slice()[..Group::TAG_LEN].to_vec())
}

/// Commit contents allowed in Tree v1 (PROTOCOL.md section 6.4).
fn check_commit(staged: &StagedCommit, committer: LeafNodeIndex) -> Result<(), TreeError> {
    let reject = |why: &str| {
        Err(TreeError::Rejected(format!(
            "commit not allowed in Tree v1: {why}"
        )))
    };
    let mut only_adds = true;
    let mut any = false;
    for q in staged.queued_proposals() {
        any = true;
        if q.proposal_or_ref_type() != ProposalOrRefType::Proposal {
            return reject("proposal by reference");
        }
        match q.proposal() {
            Proposal::Add(_) => {}
            Proposal::Remove(r) if r.removed() == committer => {
                return reject("committer removes itself")
            }
            Proposal::Remove(_) => only_adds = false,
            _ => return reject("proposal type"),
        }
    }
    if staged.update_path_leaf_node().is_none() && !(any && only_adds) {
        return reject("update path missing");
    }
    Ok(())
}

fn name_of(credential: &Credential) -> String {
    String::from_utf8_lossy(credential.serialized_content()).into_owned()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

const CONTROL_MAGIC: &[u8] = b"TREECTRL\x01";
const CONTROL_TITLE: u8 = 1;
const CONTROL_DISAPPEARING: u8 = 2;
const CONTROL_ADD_ADMIN: u8 = 3;
const CONTROL_REMOVE_ADMIN: u8 = 4;
const MAX_TITLE_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Control {
    SetTitle(Option<String>),
    SetDisappearingSeconds(u32),
    AddAdmin(MemberId),
    RemoveAdmin(MemberId),
}

fn encode_control(seq: u64, control: &Control) -> Result<Vec<u8>, TreeError> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(CONTROL_MAGIC);
    out.extend_from_slice(&seq.to_be_bytes());
    match control {
        Control::SetTitle(title) => {
            out.push(CONTROL_TITLE);
            match title {
                None => out.push(0),
                Some(title) => {
                    if title.len() > MAX_TITLE_BYTES {
                        return Err(TreeError::Group("group title is too long".into()));
                    }
                    out.push(1);
                    out.extend_from_slice(&(title.len() as u16).to_be_bytes());
                    out.extend_from_slice(title.as_bytes());
                }
            }
        }
        Control::SetDisappearingSeconds(seconds) => {
            if *seconds > 30 * 86_400 {
                return Err(TreeError::Group(
                    "disappearing timer is limited to 30 days".into(),
                ));
            }
            out.push(CONTROL_DISAPPEARING);
            out.extend_from_slice(&seconds.to_be_bytes());
        }
        Control::AddAdmin(target) => {
            out.push(CONTROL_ADD_ADMIN);
            out.extend_from_slice(target.as_bytes());
        }
        Control::RemoveAdmin(target) => {
            out.push(CONTROL_REMOVE_ADMIN);
            out.extend_from_slice(target.as_bytes());
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedControl {
    seq: u64,
    control: Control,
}

fn decode_control(bytes: &[u8]) -> Result<DecodedControl, TreeError> {
    if !bytes.starts_with(CONTROL_MAGIC) {
        return Err(TreeError::Malformed("not a Tree control message".into()));
    }
    let mut r = ControlReader(&bytes[CONTROL_MAGIC.len()..]);
    let seq = r.u64()?;
    let kind = r.u8()?;
    let control = match kind {
        CONTROL_TITLE => match r.u8()? {
            0 => Control::SetTitle(None),
            1 => {
                let len = r.u16()? as usize;
                if len == 0 || len > MAX_TITLE_BYTES {
                    return Err(TreeError::Malformed("invalid group title length".into()));
                }
                let title = String::from_utf8(r.take(len)?.to_vec())
                    .map_err(|_| TreeError::Malformed("group title is not UTF-8".into()))?;
                Control::SetTitle(Some(title))
            }
            _ => return Err(TreeError::Malformed("invalid title control".into())),
        },
        CONTROL_DISAPPEARING => {
            let seconds = r.u32()?;
            if seconds > 30 * 86_400 {
                return Err(TreeError::Malformed("invalid disappearing timer".into()));
            }
            Control::SetDisappearingSeconds(seconds)
        }
        CONTROL_ADD_ADMIN => Control::AddAdmin(MemberId(r.array()?)),
        CONTROL_REMOVE_ADMIN => Control::RemoveAdmin(MemberId(r.array()?)),
        _ => return Err(TreeError::Malformed("unknown Tree control type".into())),
    };
    if !r.0.is_empty() {
        return Err(TreeError::Malformed(
            "trailing bytes in Tree control".into(),
        ));
    }
    Ok(DecodedControl { seq, control })
}

fn apply_control_state(
    state: &mut GroupState,
    control: &Control,
    current_members: &[MemberId],
) -> Result<(), TreeError> {
    match control {
        Control::SetTitle(title) => state.title = title.clone(),
        Control::SetDisappearingSeconds(seconds) => state.disappearing_seconds = *seconds,
        Control::AddAdmin(target) => {
            if !current_members.contains(target) {
                return Err(TreeError::UnknownMember(target.to_hex()));
            }
            state.admins.push(*target);
            state.admins.sort_unstable();
            state.admins.dedup();
        }
        Control::RemoveAdmin(target) => {
            if state.admins.contains(target) && state.admins.len() == 1 {
                return Err(TreeError::Group(
                    "cannot remove the last administrator".into(),
                ));
            }
            state.admins.retain(|admin| admin != target);
        }
    }
    Ok(())
}

struct ControlReader<'a>(&'a [u8]);

impl ControlReader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], TreeError> {
        if self.0.len() < n {
            return Err(TreeError::Malformed("truncated Tree control".into()));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, TreeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TreeError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("length checked"),
        ))
    }

    fn u32(&mut self) -> Result<u32, TreeError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("length checked"),
        ))
    }

    fn u64(&mut self) -> Result<u64, TreeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("length checked"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TreeError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parses only the MLS private-message header from an untrusted envelope.
/// No ratchet or group state is modified here.
fn peek_epoch(bytes: &[u8], expected_group: &[u8]) -> Result<u64, TreeError> {
    if bytes.len() < 1 + Group::TAG_LEN {
        return Err(TreeError::Malformed("bad envelope".into()));
    }
    let mut mls = &bytes[1 + Group::TAG_LEN..];
    let input = MlsMessageIn::tls_deserialize(&mut mls)
        .map_err(|e| TreeError::Malformed(format!("{e:?}")))?;
    let protocol = input
        .try_into_protocol_message()
        .map_err(|_| TreeError::Malformed("not a group message".into()))?;
    if protocol.wire_format() != WireFormat::PrivateMessage {
        return Err(TreeError::Rejected(
            "only private messages are accepted".into(),
        ));
    }
    if protocol.group_id().as_slice() != expected_group {
        return Err(TreeError::Rejected(
            "envelope belongs to another group".into(),
        ));
    }
    match protocol.content_type() {
        ContentType::Application | ContentType::Commit => Ok(protocol.epoch().as_u64()),
        ContentType::Proposal => Err(TreeError::Rejected(
            "proposals are not accepted in Tree v1 (F-007)".into(),
        )),
    }
}
