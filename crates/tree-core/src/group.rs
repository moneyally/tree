//! An end-to-end encrypted conversation.
//!
//! A 1:1 chat is a two-member group, so one code path covers everything.
//! Every method returns or takes plain bytes for the transport layer.

use openmls::prelude::{tls_codec::Deserialize, *};
use openmls_traits::OpenMlsProvider;

use crate::{
    client::Client,
    error::{group_err, TreeError},
    provider::TreeProvider,
};

/// A conversation this device belongs to.
pub struct Group {
    pub(crate) mls: MlsGroup,
}

/// Output of adding someone: the commit goes to existing members,
/// the welcome goes only to the new member.
pub struct AddOutput {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// What an incoming message turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// A chat message.
    Message { from: String, body: Vec<u8> },
    /// Membership or keys changed (someone joined, left, was removed,
    /// or refreshed their keys).
    GroupChanged { added: Vec<String>, removed: Vec<String>, epoch: u64 },
    /// This device was removed; it can no longer read or send.
    RemovedFromGroup,
    /// A proposal stored for the next commit.
    Proposal,
    /// Our own message echoed back by the server; nothing to do.
    OwnEcho,
}

impl Group {
    /// Every message is padded to a multiple of this many bytes so the
    /// ciphertext length leaks less about the plaintext length.
    pub const PADDING: usize = 256;

    /// Envelope format version byte.
    const ENVELOPE_V1: u8 = 1;
    const TAG_LEN: usize = 32;

    /// Outer seal over the full MLS ciphertext, keyed by a secret only current
    /// group members can export. Checked BEFORE the message reaches MLS, so a
    /// tampered or injected copy is dropped without consuming the message key
    /// (otherwise the genuine message would become undecryptable).
    fn seal<P: OpenMlsProvider>(&self, me: &Client<P>, mls_bytes: Vec<u8>) -> Result<Vec<u8>, TreeError> {
        let tag = self.envelope_tag(me, &mls_bytes)?;
        let mut out = Vec::with_capacity(1 + Self::TAG_LEN + mls_bytes.len());
        out.push(Self::ENVELOPE_V1);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&mls_bytes);
        Ok(out)
    }

    fn envelope_tag<P: OpenMlsProvider>(&self, me: &Client<P>, mls_bytes: &[u8]) -> Result<Vec<u8>, TreeError> {
        let key = self
            .mls
            .export_secret(me.provider.crypto(), "tree/envelope/v1", self.mls.group_id().as_slice(), 32)
            .map_err(group_err)?;
        let tag = me
            .provider
            .crypto()
            .hmac(openmls_traits::types::HashType::Sha2_256, &key, mls_bytes)
            .map_err(group_err)?;
        Ok(tag.as_slice()[..Self::TAG_LEN].to_vec())
    }

    fn open_envelope<'a, P: OpenMlsProvider>(&self, me: &Client<P>, bytes: &'a [u8]) -> Result<&'a [u8], TreeError> {
        if bytes.len() < 1 + Self::TAG_LEN || bytes[0] != Self::ENVELOPE_V1 {
            return Err(TreeError::Malformed("bad envelope".into()));
        }
        let (tag, body) = bytes[1..].split_at(Self::TAG_LEN);
        let expected = self.envelope_tag(me, body)?;
        // constant-time comparison
        let diff = tag.iter().zip(expected.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
        if diff != 0 {
            return Err(TreeError::Rejected("envelope seal mismatch".into()));
        }
        Ok(body)
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

    /// Names of current members, in leaf order.
    pub fn members(&self) -> Vec<String> {
        self.mls
            .members()
            .map(|m| String::from_utf8_lossy(m.credential.serialized_content()).into_owned())
            .collect()
    }

    /// Value both sides can compare out of band (QR / safety number) to
    /// confirm they are in the same group state with no one in the middle.
    pub fn verification_code(&self) -> Vec<u8> {
        self.mls.epoch_authenticator().as_slice().to_vec()
    }

    /// Adds a device by its key package. The caller sends `commit` to the
    /// existing members and `welcome` to the new device.
    pub fn add<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        key_package: &[u8],
    ) -> Result<AddOutput, TreeError> {
        let kp = KeyPackageIn::tls_deserialize_exact(key_package)
            .map_err(|e| TreeError::Malformed(format!("{e:?}")))?
            .validate(me.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| TreeError::InvalidKeyPackage(format!("{e:?}")))?;
        if kp.ciphersuite() != me.ciphersuite {
            return Err(TreeError::InvalidKeyPackage("ciphersuite mismatch".into()));
        }

        me.provider.atomically(|| {
            let (commit, welcome, _info) = self
                .mls
                .add_members(&me.provider, &me.signer, core::slice::from_ref(&kp))
                .map_err(group_err)?;
            // Seal with the CURRENT epoch (what existing members hold), then merge.
            let commit = self.seal(me, commit.to_bytes().map_err(group_err)?)?;
            self.mls.merge_pending_commit(&me.provider).map_err(group_err)?;

            Ok(AddOutput { commit, welcome: welcome.to_bytes().map_err(group_err)? })
        })
    }

    /// Removes a member by name. Their future reading ability ends with
    /// the new epoch this commit creates.
    pub fn remove<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        name: &str,
    ) -> Result<Vec<u8>, TreeError> {
        let index = self
            .mls
            .members()
            .find(|m| m.credential.serialized_content() == name.as_bytes())
            .map(|m| m.index)
            .ok_or_else(|| TreeError::UnknownMember(name.to_string()))?;
        me.provider.atomically(|| {
            let (commit, _welcome, _info) = self
                .mls
                .remove_members(&me.provider, &me.signer, &[index])
                .map_err(group_err)?;
            let commit = self.seal(me, commit.to_bytes().map_err(group_err)?)?;
            self.mls.merge_pending_commit(&me.provider).map_err(group_err)?;
            Ok(commit)
        })
    }

    /// Refreshes this device's keys. Run periodically (e.g. daily) and after
    /// any suspicion of compromise: an attacker who copied old state loses
    /// access once this commit is processed (post-compromise security).
    pub fn refresh_keys<P: TreeProvider>(&mut self, me: &Client<P>) -> Result<Vec<u8>, TreeError> {
        me.provider.atomically(|| {
            let bundle = self
                .mls
                .self_update(&me.provider, &me.signer, LeafNodeParameters::default())
                .map_err(group_err)?;
            let commit = self.seal(me, bundle.into_commit().to_bytes().map_err(group_err)?)?;
            self.mls.merge_pending_commit(&me.provider).map_err(group_err)?;
            Ok(commit)
        })
    }

    /// Encrypts a chat message for everyone in the group.
    pub fn send<P: TreeProvider>(&mut self, me: &Client<P>, body: &[u8]) -> Result<Vec<u8>, TreeError> {
        if !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }
        me.provider.atomically(|| {
            let out = self
                .mls
                .create_message(&me.provider, &me.signer, body)
                .map_err(group_err)?;
            self.seal(me, out.to_bytes().map_err(group_err)?)
        })
    }

    /// Decrypts and authenticates anything received for this group.
    /// Anything tampered with, replayed, from a non-member, or for another
    /// group is rejected.
    pub fn receive<P: TreeProvider>(&mut self, me: &Client<P>, bytes: &[u8]) -> Result<Incoming, TreeError> {
        if !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }
        // Checked before anything is written.
        let body = self.open_envelope(me, bytes)?;
        me.provider.atomically(|| self.process(me, body))
    }

    fn process<P: TreeProvider>(&mut self, me: &Client<P>, body: &[u8]) -> Result<Incoming, TreeError> {
        let msg = MlsMessageIn::tls_deserialize_exact(body)
            .map_err(|e| TreeError::Malformed(format!("{e:?}")))?;
        let protocol = msg
            .try_into_protocol_message()
            .map_err(|_| TreeError::Malformed("not a group message".into()))?;
        let processed = self
            .mls
            .process_message(&me.provider, protocol)
            .map_err(|e| TreeError::Rejected(format!("{e:?}")))?;

        let from = String::from_utf8_lossy(processed.credential().serialized_content()).into_owned();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => Ok(Incoming::Message { from, body: m.into_bytes() }),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let added = staged
                    .add_proposals()
                    .map(|p| {
                        String::from_utf8_lossy(
                            p.add_proposal().key_package().leaf_node().credential().serialized_content(),
                        )
                        .into_owned()
                    })
                    .collect();
                let removed_idx: Vec<LeafNodeIndex> =
                    staged.remove_proposals().map(|p| p.remove_proposal().removed()).collect();
                let removed = self
                    .mls
                    .members()
                    .filter(|m| removed_idx.contains(&m.index))
                    .map(|m| String::from_utf8_lossy(m.credential.serialized_content()).into_owned())
                    .collect();
                self.mls.merge_staged_commit(&me.provider, *staged).map_err(group_err)?;
                if !self.mls.is_active() {
                    return Ok(Incoming::RemovedFromGroup);
                }
                Ok(Incoming::GroupChanged { added, removed, epoch: self.epoch() })
            }
            ProcessedMessageContent::ProposalMessage(p) => {
                self.mls.store_pending_proposal(me.provider.storage(), *p).map_err(group_err)?;
                Ok(Incoming::Proposal)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(p) => {
                self.mls.store_pending_proposal(me.provider.storage(), *p).map_err(group_err)?;
                Ok(Incoming::Proposal)
            }
            // We merge our own commits immediately, so server echoes are no-ops.
            _ => Ok(Incoming::OwnEcho),
        }
    }
}
