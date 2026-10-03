//! A device identity.
//!
//! Each device has its own signing key and its own leaf in every group, so a
//! stolen or lost device can be removed without touching the others.
//!
//! [`Client::new`] keeps everything in memory. [`Client::create`] and
//! [`Client::open`] keep the identity and all groups in an encrypted database
//! file (see [`crate::storage`]).

use std::path::Path;

use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, storage::StorageProvider as _, OpenMlsProvider};

use crate::{
    error::TreeError,
    group::{Group, MemberId},
    group_state::GroupState,
    provider::TreeProvider,
    storage::{KdfParams, KeySource, Passphrase, StoredProvider},
    DefaultProvider, TREE_CIPHERSUITE,
};

/// One device's identity and its local key store.
pub struct Client<P: OpenMlsProvider = DefaultProvider> {
    pub(crate) name: String,
    pub(crate) provider: P,
    pub(crate) signer: SignatureKeyPair,
    pub(crate) credential: CredentialWithKey,
    pub(crate) ciphersuite: Ciphersuite,
}

impl Client<DefaultProvider> {
    /// New in-memory device identity with the default provider and ciphersuite.
    pub fn new(name: &str) -> Result<Self, TreeError> {
        Self::with_provider(name, DefaultProvider::default(), TREE_CIPHERSUITE)
    }
}

// Keys of the identity record in `tree_meta`.
const META_NAME: &str = "name";
const META_CIPHERSUITE: &str = "ciphersuite";
const META_SIGNATURE_KEY: &str = "signature_public_key";
const META_CREDENTIAL: &str = "credential";
const META_SERVER_AUTH_SEED: &str = "server_auth_seed";
const META_SERVER_ACCOUNT: &str = "server_account_id";
const META_SERVER_DEVICE: &str = "server_device_id";
const META_RECOVERY_ENTROPY: &str = "recovery_entropy";

impl Client<StoredProvider> {
    /// Creates a new device identity in a new encrypted database at `path`
    /// (plus the key header `<path>.hdr`). Fails if `path` already exists.
    pub fn create(path: impl AsRef<Path>, passphrase: &str, name: &str) -> Result<Self, TreeError> {
        Self::create_with_key(
            path,
            &Passphrase::new(passphrase)?,
            name,
            KdfParams::RECOMMENDED,
        )
    }

    /// Reopens the identity stored at `path`.
    /// A wrong passphrase returns [`TreeError::WrongKey`].
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, TreeError> {
        Self::open_with_key(path, &Passphrase::new(passphrase)?)
    }

    /// [`Client::create`] with any key source (e.g. a hardware-wrapped key)
    /// and explicit Argon2id parameters for the header.
    pub fn create_with_key(
        path: impl AsRef<Path>,
        source: &dyn KeySource,
        name: &str,
        params: KdfParams,
    ) -> Result<Self, TreeError> {
        let path = path.as_ref();
        let provider = StoredProvider::create(path, source, params)?;
        let result = Self::with_provider(name, provider, TREE_CIPHERSUITE).and_then(|client| {
            client.provider.atomically(|| {
                let p = &client.provider;
                p.put_meta(META_NAME, client.name.as_bytes())?;
                p.put_meta(
                    META_CIPHERSUITE,
                    &u16::from(client.ciphersuite).to_be_bytes(),
                )?;
                p.put_meta(META_SIGNATURE_KEY, client.signer.public())?;
                let cred = client
                    .credential
                    .credential
                    .tls_serialize_detached()
                    .map_err(|e| TreeError::Malformed(format!("{e:?}")))?;
                p.put_meta(META_CREDENTIAL, &cred)
            })?;
            Ok(client)
        });
        if result.is_err() {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(crate::storage::KeyHeader::path_for(path));
        }
        result
    }

    /// [`Client::open`] with any key source.
    pub fn open_with_key(
        path: impl AsRef<Path>,
        source: &dyn KeySource,
    ) -> Result<Self, TreeError> {
        let provider = StoredProvider::open(path.as_ref(), source)?;

        let name = String::from_utf8(provider.meta(META_NAME)?)
            .map_err(|_| TreeError::Storage("stored name is not UTF-8".into()))?;
        let cs: [u8; 2] = provider
            .meta(META_CIPHERSUITE)?
            .try_into()
            .map_err(|_| TreeError::Storage("stored ciphersuite is damaged".into()))?;
        let ciphersuite = Ciphersuite::try_from(u16::from_be_bytes(cs))
            .map_err(|_| TreeError::UnsupportedCiphersuite)?;
        if !provider
            .crypto()
            .supported_ciphersuites()
            .contains(&ciphersuite)
        {
            return Err(TreeError::UnsupportedCiphersuite);
        }
        let public = provider.meta(META_SIGNATURE_KEY)?;
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &public,
            ciphersuite.signature_algorithm(),
        )
        .ok_or_else(|| TreeError::Storage("signing key missing".into()))?;
        let credential = Credential::tls_deserialize_exact(provider.meta(META_CREDENTIAL)?)
            .map_err(|e| TreeError::Storage(format!("stored credential is damaged: {e:?}")))?;

        let credential = CredentialWithKey {
            credential,
            signature_key: public.into(),
        };
        Ok(Self {
            name,
            provider,
            signer,
            credential,
            ciphersuite,
        })
    }

    /// Ids of all groups this device created or joined, oldest first
    /// (including groups it was later removed from).
    pub fn group_ids(&self) -> Result<Vec<Vec<u8>>, TreeError> {
        self.provider.group_ids()
    }

    /// Stores the 32-byte Ed25519 seed used only to authenticate HTTP
    /// requests to a Tree server. The value is stored inside the SQLCipher
    /// database, never in a sidecar plaintext file.
    pub fn set_server_auth_seed(&self, seed: &[u8; 32]) -> Result<(), TreeError> {
        self.provider.atomically(|| {
            self.provider.put_meta(META_SERVER_AUTH_SEED, seed)?;
            Ok(())
        })
    }

    /// Returns the persisted server-auth seed, if this device has been
    /// registered with a Tree server.
    pub fn server_auth_seed(&self) -> Result<Option<[u8; 32]>, TreeError> {
        self.provider
            .meta_optional(META_SERVER_AUTH_SEED)?
            .map(|v| {
                v.try_into()
                    .map_err(|_| TreeError::Storage("server auth seed is damaged".into()))
            })
            .transpose()
    }

    pub fn set_recovery_phrase(
        &self,
        phrase: &crate::recovery::RecoveryPhrase,
    ) -> Result<(), TreeError> {
        self.provider.atomically(|| {
            self.provider
                .put_meta(META_RECOVERY_ENTROPY, &phrase.entropy_bytes())?;
            Ok(())
        })
    }

    pub fn recovery_phrase(&self) -> Result<Option<crate::recovery::RecoveryPhrase>, TreeError> {
        self.provider
            .meta_optional(META_RECOVERY_ENTROPY)?
            .map(|v| {
                let entropy: [u8; 32] = v
                    .try_into()
                    .map_err(|_| TreeError::Storage("recovery entropy is damaged".into()))?;
                crate::recovery::RecoveryPhrase::from_entropy_bytes(entropy)
            })
            .transpose()
    }

    /// Stores the server account/device identifiers belonging to this local
    /// profile. They are metadata, but are kept encrypted with the profile.
    pub fn set_server_account(&self, account_id: &str, device_id: &str) -> Result<(), TreeError> {
        self.provider.atomically(|| {
            self.provider
                .put_meta(META_SERVER_ACCOUNT, account_id.as_bytes())?;
            self.provider
                .put_meta(META_SERVER_DEVICE, device_id.as_bytes())?;
            Ok(())
        })
    }

    pub fn server_account(&self) -> Result<Option<(String, String)>, TreeError> {
        let account = self.provider.meta_optional(META_SERVER_ACCOUNT)?;
        let device = self.provider.meta_optional(META_SERVER_DEVICE)?;
        match (account, device) {
            (None, None) => Ok(None),
            (Some(a), Some(d)) => Ok(Some((
                String::from_utf8(a)
                    .map_err(|_| TreeError::Storage("server account id is damaged".into()))?,
                String::from_utf8(d)
                    .map_err(|_| TreeError::Storage("server device id is damaged".into()))?,
            ))),
            _ => Err(TreeError::Storage(
                "server account metadata is incomplete".into(),
            )),
        }
    }

    /// Loads a stored group. Load each group once and keep the [`Group`]:
    /// two live copies of the same group would get out of step.
    pub fn load_group(&self, group_id: &[u8]) -> Result<Group, TreeError> {
        let mls = MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(crate::storage::storage_err)?
            .ok_or(TreeError::NoSuchGroup)?;
        let state = match self.provider.load_group_state(group_id)? {
            Some(bytes) => GroupState::decode(&bytes)?,
            None => GroupState::default(),
        };
        Ok(Group::new(mls, state))
    }
}

impl<P: TreeProvider> Client<P> {
    /// New device identity with an explicit provider and ciphersuite.
    pub fn with_provider(
        name: &str,
        provider: P,
        ciphersuite: Ciphersuite,
    ) -> Result<Self, TreeError> {
        provider
            .crypto()
            .supports(ciphersuite)
            .map_err(|_| TreeError::UnsupportedCiphersuite)?;
        if !provider
            .crypto()
            .supported_ciphersuites()
            .contains(&ciphersuite)
        {
            return Err(TreeError::UnsupportedCiphersuite);
        }

        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| TreeError::Identity(format!("{e:?}")))?;
        signer
            .store(provider.storage())
            .map_err(|e| TreeError::Identity(format!("{e:?}")))?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };

        Ok(Self {
            name: name.to_string(),
            provider,
            signer,
            credential,
            ciphersuite,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    /// Public signature key; shown to contacts as the safety number source.
    pub fn signature_public_key(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }

    /// This device's member id in every group it is in.
    pub fn member_id(&self) -> MemberId {
        MemberId::of(&self.signer.to_public_vec())
    }

    /// Publishes a fresh one-time key package (uploaded to the server so
    /// others can add this device to a group while it is offline). Its
    /// private part stays in this device's store until it is used.
    pub fn key_package(&self) -> Result<Vec<u8>, TreeError> {
        self.provider.atomically(|| {
            let bundle = KeyPackage::builder()
                .build(
                    self.ciphersuite,
                    &self.provider,
                    &self.signer,
                    self.credential.clone(),
                )
                .map_err(|e| TreeError::Identity(format!("{e:?}")))?;
            bundle
                .key_package()
                .tls_serialize_detached()
                .map_err(|e| TreeError::Malformed(format!("{e:?}")))
        })
    }

    /// Starts a new conversation with only this device in it.
    pub fn create_group(&self) -> Result<Group, TreeError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(self.ciphersuite)
            .use_ratchet_tree_extension(true)
            .padding_size(Group::PADDING)
            .sender_ratchet_configuration(Group::sender_ratchet())
            .max_past_epochs(Group::PAST_EPOCHS as usize)
            .build();
        self.provider.atomically(|| {
            let mls = MlsGroup::new(
                &self.provider,
                &self.signer,
                &config,
                self.credential.clone(),
            )
            .map_err(crate::error::group_err)?;
            self.provider.remember_group(mls.group_id().as_slice())?;
            Ok(Group::new(mls, GroupState::default()))
        })
    }

    /// Joins a conversation from a welcome message produced by [`Group::add`].
    pub fn join(&self, welcome: &[u8]) -> Result<Group, TreeError> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|e| TreeError::Malformed(format!("{e:?}")))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(TreeError::Malformed("not a welcome message".into())),
        };
        // The MLS library deletes the matching one-time key package as soon as
        // it finds its reference in the welcome, before anything is decrypted
        // or verified. Keep a copy and put it back if the join fails, so a
        // damaged or forged welcome cannot destroy it (F-006).
        let saved: Vec<(KeyPackageRef, KeyPackageBundle)> = welcome
            .secrets()
            .iter()
            .filter_map(|s| {
                let r = s.new_member();
                let kp = self.provider.storage().key_package(&r).ok().flatten()?;
                Some((r, kp))
            })
            .collect();
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .padding_size(Group::PADDING)
            .sender_ratchet_configuration(Group::sender_ratchet())
            .max_past_epochs(Group::PAST_EPOCHS as usize)
            .build();
        self.provider.atomically(|| {
            let result = (|| {
                let builder = StagedWelcome::build_from_welcome(&self.provider, &config, welcome)
                    .map_err(crate::error::group_err)?;
                let group_id = builder
                    .processed_welcome()
                    .unverified_group_info()
                    .group_id()
                    .clone();
                // A welcome never replaces a group we are still in. A stored copy
                // of a group we were removed from is replaced (we are being added
                // back), but only after the welcome has been fully verified.
                let old = MlsGroup::load(self.provider.storage(), &group_id)
                    .map_err(crate::storage::storage_err)?;
                let builder = match &old {
                    Some(g) if g.is_active() => {
                        return Err(TreeError::Group("already a member of this group".into()))
                    }
                    Some(_) => builder.replace_old_group(),
                    None => builder,
                };
                let staged = builder.build().map_err(crate::error::group_err)?;
                if let Some(mut old) = old {
                    old.delete(self.provider.storage())
                        .map_err(crate::storage::storage_err)?;
                }
                let mls = staged
                    .into_group(&self.provider)
                    .map_err(crate::error::group_err)?;
                self.provider.remember_group(mls.group_id().as_slice())?;
                // Replace the key from the one-time key package soon.
                let state = GroupState {
                    should_refresh: true,
                    ..GroupState::default()
                };
                self.provider
                    .save_group_state(mls.group_id().as_slice(), &state.encode())?;
                Ok(Group::new(mls, state))
            })();
            if result.is_err() {
                // F-006: put back the one-time key package a failed join consumed.
                for (r, kp) in &saved {
                    let _ = self.provider.storage().write_key_package(r, kp);
                }
            }
            result
        })
    }
}
