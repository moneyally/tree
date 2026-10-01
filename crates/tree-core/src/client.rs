//! A device identity.
//!
//! Each device has its own signing key and its own leaf in every group, so a
//! stolen or lost device can be removed without touching the others.
//!
//! [`Client::new`] keeps everything in memory. [`Client::create`] and
//! [`Client::open`] keep the identity and all groups in an encrypted database
//! file (see [`crate::storage`]).

use std::path::Path;

use openmls::prelude::{tls_codec::{Deserialize, Serialize}, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

use crate::{
    error::TreeError,
    group::Group,
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

impl Client<StoredProvider> {
    /// Creates a new device identity in a new encrypted database at `path`
    /// (plus the key header `<path>.hdr`). Fails if `path` already exists.
    pub fn create(path: impl AsRef<Path>, passphrase: &str, name: &str) -> Result<Self, TreeError> {
        Self::create_with_key(path, &Passphrase::new(passphrase)?, name, KdfParams::RECOMMENDED)
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
                p.put_meta(META_CIPHERSUITE, &u16::from(client.ciphersuite).to_be_bytes())?;
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
    pub fn open_with_key(path: impl AsRef<Path>, source: &dyn KeySource) -> Result<Self, TreeError> {
        let provider = StoredProvider::open(path.as_ref(), source)?;

        let name = String::from_utf8(provider.meta(META_NAME)?)
            .map_err(|_| TreeError::Storage("stored name is not UTF-8".into()))?;
        let cs: [u8; 2] = provider
            .meta(META_CIPHERSUITE)?
            .try_into()
            .map_err(|_| TreeError::Storage("stored ciphersuite is damaged".into()))?;
        let ciphersuite = Ciphersuite::try_from(u16::from_be_bytes(cs))
            .map_err(|_| TreeError::UnsupportedCiphersuite)?;
        if !provider.crypto().supported_ciphersuites().contains(&ciphersuite) {
            return Err(TreeError::UnsupportedCiphersuite);
        }
        let public = provider.meta(META_SIGNATURE_KEY)?;
        let signer = SignatureKeyPair::read(provider.storage(), &public, ciphersuite.signature_algorithm())
            .ok_or_else(|| TreeError::Storage("signing key missing".into()))?;
        let credential = Credential::tls_deserialize_exact(provider.meta(META_CREDENTIAL)?)
            .map_err(|e| TreeError::Storage(format!("stored credential is damaged: {e:?}")))?;

        let credential = CredentialWithKey { credential, signature_key: public.into() };
        Ok(Self { name, provider, signer, credential, ciphersuite })
    }

    /// Ids of all groups this device created or joined, oldest first
    /// (including groups it was later removed from).
    pub fn group_ids(&self) -> Result<Vec<Vec<u8>>, TreeError> {
        self.provider.group_ids()
    }

    /// Loads a stored group. Load each group once and keep the [`Group`]:
    /// two live copies of the same group would get out of step.
    pub fn load_group(&self, group_id: &[u8]) -> Result<Group, TreeError> {
        let mls = MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(crate::storage::storage_err)?
            .ok_or(TreeError::NoSuchGroup)?;
        Ok(Group { mls })
    }
}

impl<P: TreeProvider> Client<P> {
    /// New device identity with an explicit provider and ciphersuite.
    pub fn with_provider(name: &str, provider: P, ciphersuite: Ciphersuite) -> Result<Self, TreeError> {
        provider
            .crypto()
            .supports(ciphersuite)
            .map_err(|_| TreeError::UnsupportedCiphersuite)?;
        if !provider.crypto().supported_ciphersuites().contains(&ciphersuite) {
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

        Ok(Self { name: name.to_string(), provider, signer, credential, ciphersuite })
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

    /// Publishes a fresh one-time key package (uploaded to the server so
    /// others can add this device to a group while it is offline). Its
    /// private part stays in this device's store until it is used.
    pub fn key_package(&self) -> Result<Vec<u8>, TreeError> {
        self.provider.atomically(|| {
            let bundle = KeyPackage::builder()
                .build(self.ciphersuite, &self.provider, &self.signer, self.credential.clone())
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
            .build();
        self.provider.atomically(|| {
            let mls = MlsGroup::new(&self.provider, &self.signer, &config, self.credential.clone())
                .map_err(crate::error::group_err)?;
            self.provider.remember_group(mls.group_id().as_slice())?;
            Ok(Group { mls })
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
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .padding_size(Group::PADDING)
            .sender_ratchet_configuration(Group::sender_ratchet())
            .build();
        self.provider.atomically(|| {
            let builder = StagedWelcome::build_from_welcome(&self.provider, &config, welcome)
                .map_err(crate::error::group_err)?;
            let group_id = builder.processed_welcome().unverified_group_info().group_id().clone();
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
                old.delete(self.provider.storage()).map_err(crate::storage::storage_err)?;
            }
            let mls = staged.into_group(&self.provider).map_err(crate::error::group_err)?;
            self.provider.remember_group(mls.group_id().as_slice())?;
            Ok(Group { mls })
        })
    }
}
