//! `StorageProvider` for [`SqlStorage`]: every call is forwarded unchanged to
//! the `openmls_sqlite_storage` implementation, borrowing our connection.
//!
//! Why a forwarding layer: the SQLite provider takes ownership of the
//! connection and gives no access back, but Tree needs the same connection
//! for its own tables and to wrap each group operation in one transaction.
//!
//! This file is mechanical: one method per trait method, signatures copied
//! from `openmls_traits::storage::StorageProvider` (0.6). If the trait
//! changes, compilation fails here.

use openmls_traits::storage::{traits, StorageProvider, CURRENT_VERSION};

use super::{Sql, SqlStorage};

const V: u16 = CURRENT_VERSION;

impl StorageProvider<V> for SqlStorage {
    type Error = rusqlite::Error;

    fn write_mls_join_config<
        GroupId: traits::GroupId<V>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<V>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_mls_join_config::<GroupId, MlsGroupJoinConfig>(&self.sql(), group_id, config)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<V>,
        LeafNode: traits::LeafNode<V>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::append_own_leaf_node::<GroupId, LeafNode>(&self.sql(), group_id, leaf_node)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<V>,
        ProposalRef: traits::ProposalRef<V>,
        QueuedProposal: traits::QueuedProposal<V>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::queue_proposal::<GroupId, ProposalRef, QueuedProposal>(&self.sql(), group_id, proposal_ref, proposal)
    }

    fn write_tree<GroupId: traits::GroupId<V>, TreeSync: traits::TreeSync<V>>(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_tree::<GroupId, TreeSync>(&self.sql(), group_id, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<V>,
        InterimTranscriptHash: traits::InterimTranscriptHash<V>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_interim_transcript_hash::<GroupId, InterimTranscriptHash>(&self.sql(), group_id, interim_transcript_hash)
    }

    fn write_context<
        GroupId: traits::GroupId<V>,
        GroupContext: traits::GroupContext<V>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_context::<GroupId, GroupContext>(&self.sql(), group_id, group_context)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<V>,
        ConfirmationTag: traits::ConfirmationTag<V>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_confirmation_tag::<GroupId, ConfirmationTag>(&self.sql(), group_id, confirmation_tag)
    }

    fn write_group_state<
        GroupState: traits::GroupState<V>,
        GroupId: traits::GroupId<V>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_group_state::<GroupState, GroupId>(&self.sql(), group_id, group_state)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<V>,
        MessageSecrets: traits::MessageSecrets<V>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_message_secrets::<GroupId, MessageSecrets>(&self.sql(), group_id, message_secrets)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<V>,
        ResumptionPskStore: traits::ResumptionPskStore<V>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_resumption_psk_store::<GroupId, ResumptionPskStore>(&self.sql(), group_id, resumption_psk_store)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<V>,
        LeafNodeIndex: traits::LeafNodeIndex<V>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_own_leaf_index::<GroupId, LeafNodeIndex>(&self.sql(), group_id, own_leaf_index)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<V>,
        GroupEpochSecrets: traits::GroupEpochSecrets<V>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_group_epoch_secrets::<GroupId, GroupEpochSecrets>(&self.sql(), group_id, group_epoch_secrets)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<V>,
        SignatureKeyPair: traits::SignatureKeyPair<V>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_signature_key_pair::<SignaturePublicKey, SignatureKeyPair>(&self.sql(), public_key, signature_key_pair)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<V>,
        HpkeKeyPair: traits::HpkeKeyPair<V>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_encryption_key_pair::<EncryptionKey, HpkeKeyPair>(&self.sql(), public_key, key_pair)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<V>,
        EpochKey: traits::EpochKey<V>,
        HpkeKeyPair: traits::HpkeKeyPair<V>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_encryption_epoch_key_pairs::<GroupId, EpochKey, HpkeKeyPair>(&self.sql(), group_id, epoch, leaf_index, key_pairs)
    }

    fn write_key_package<
        HashReference: traits::HashReference<V>,
        KeyPackage: traits::KeyPackage<V>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_key_package::<HashReference, KeyPackage>(&self.sql(), hash_ref, key_package)
    }

    fn write_psk<PskId: traits::PskId<V>, PskBundle: traits::PskBundle<V>>(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::write_psk::<PskId, PskBundle>(&self.sql(), psk_id, psk)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<V>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::mls_group_join_config::<GroupId, MlsGroupJoinConfig>(&self.sql(), group_id)
    }

    fn own_leaf_nodes<GroupId: traits::GroupId<V>, LeafNode: traits::LeafNode<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::own_leaf_nodes::<GroupId, LeafNode>(&self.sql(), group_id)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<V>,
        ProposalRef: traits::ProposalRef<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::queued_proposal_refs::<GroupId, ProposalRef>(&self.sql(), group_id)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<V>,
        ProposalRef: traits::ProposalRef<V>,
        QueuedProposal: traits::QueuedProposal<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::queued_proposals::<GroupId, ProposalRef, QueuedProposal>(&self.sql(), group_id)
    }

    fn tree<GroupId: traits::GroupId<V>, TreeSync: traits::TreeSync<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::tree::<GroupId, TreeSync>(&self.sql(), group_id)
    }

    fn group_context<
        GroupId: traits::GroupId<V>,
        GroupContext: traits::GroupContext<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::group_context::<GroupId, GroupContext>(&self.sql(), group_id)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<V>,
        InterimTranscriptHash: traits::InterimTranscriptHash<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::interim_transcript_hash::<GroupId, InterimTranscriptHash>(&self.sql(), group_id)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<V>,
        ConfirmationTag: traits::ConfirmationTag<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::confirmation_tag::<GroupId, ConfirmationTag>(&self.sql(), group_id)
    }

    fn group_state<GroupState: traits::GroupState<V>, GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::group_state::<GroupState, GroupId>(&self.sql(), group_id)
    }

    fn message_secrets<
        GroupId: traits::GroupId<V>,
        MessageSecrets: traits::MessageSecrets<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::message_secrets::<GroupId, MessageSecrets>(&self.sql(), group_id)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<V>,
        ResumptionPskStore: traits::ResumptionPskStore<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::resumption_psk_store::<GroupId, ResumptionPskStore>(&self.sql(), group_id)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<V>,
        LeafNodeIndex: traits::LeafNodeIndex<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::own_leaf_index::<GroupId, LeafNodeIndex>(&self.sql(), group_id)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<V>,
        GroupEpochSecrets: traits::GroupEpochSecrets<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::group_epoch_secrets::<GroupId, GroupEpochSecrets>(&self.sql(), group_id)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<V>,
        SignatureKeyPair: traits::SignatureKeyPair<V>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::signature_key_pair::<SignaturePublicKey, SignatureKeyPair>(&self.sql(), public_key)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<V>,
        EncryptionKey: traits::EncryptionKey<V>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::encryption_key_pair::<HpkeKeyPair, EncryptionKey>(&self.sql(), public_key)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<V>,
        EpochKey: traits::EpochKey<V>,
        HpkeKeyPair: traits::HpkeKeyPair<V>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::encryption_epoch_key_pairs::<GroupId, EpochKey, HpkeKeyPair>(&self.sql(), group_id, epoch, leaf_index)
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<V>,
        KeyPackage: traits::KeyPackage<V>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::key_package::<KeyPackageRef, KeyPackage>(&self.sql(), hash_ref)
    }

    fn psk<PskBundle: traits::PskBundle<V>, PskId: traits::PskId<V>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        <Sql<'_> as StorageProvider<V>>::psk::<PskBundle, PskId>(&self.sql(), psk_id)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<V>,
        ProposalRef: traits::ProposalRef<V>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::remove_proposal::<GroupId, ProposalRef>(&self.sql(), group_id, proposal_ref)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_own_leaf_nodes::<GroupId>(&self.sql(), group_id)
    }

    fn delete_group_config<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_group_config::<GroupId>(&self.sql(), group_id)
    }

    fn delete_tree<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_tree::<GroupId>(&self.sql(), group_id)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_confirmation_tag::<GroupId>(&self.sql(), group_id)
    }

    fn delete_group_state<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_group_state::<GroupId>(&self.sql(), group_id)
    }

    fn delete_context<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_context::<GroupId>(&self.sql(), group_id)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_interim_transcript_hash::<GroupId>(&self.sql(), group_id)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_message_secrets::<GroupId>(&self.sql(), group_id)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_all_resumption_psk_secrets::<GroupId>(&self.sql(), group_id)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_own_leaf_index::<GroupId>(&self.sql(), group_id)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_group_epoch_secrets::<GroupId>(&self.sql(), group_id)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<V>,
        ProposalRef: traits::ProposalRef<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::clear_proposal_queue::<GroupId, ProposalRef>(&self.sql(), group_id)
    }

    fn delete_signature_key_pair<SignaturePublicKey: traits::SignaturePublicKey<V>>(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_signature_key_pair::<SignaturePublicKey>(&self.sql(), public_key)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<V>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_encryption_key_pair::<EncryptionKey>(&self.sql(), public_key)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<V>,
        EpochKey: traits::EpochKey<V>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_encryption_epoch_key_pairs::<GroupId, EpochKey>(&self.sql(), group_id, epoch, leaf_index)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<V>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_key_package::<KeyPackageRef>(&self.sql(), hash_ref)
    }

    fn delete_psk<PskKey: traits::PskId<V>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        <Sql<'_> as StorageProvider<V>>::delete_psk::<PskKey>(&self.sql(), psk_id)
    }
}
