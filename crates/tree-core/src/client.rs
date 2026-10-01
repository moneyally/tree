//! A device identity.
//!
//! Each device has its own signing key and its own leaf in every group, so a
//! stolen or lost device can be removed without touching the others.

use openmls::prelude::{tls_codec::{Deserialize, Serialize}, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

use crate::{error::TreeError, group::Group, DefaultProvider, TREE_CIPHERSUITE};

/// One device's identity and its local key store.
pub struct Client<P: OpenMlsProvider = DefaultProvider> {
    pub(crate) name: String,
    pub(crate) provider: P,
    pub(crate) signer: SignatureKeyPair,
    pub(crate) credential: CredentialWithKey,
    pub(crate) ciphersuite: Ciphersuite,
}

impl Client<DefaultProvider> {
    /// New device identity with the default provider and ciphersuite.
    pub fn new(name: &str) -> Result<Self, TreeError> {
        Self::with_provider(name, DefaultProvider::default(), TREE_CIPHERSUITE)
    }
}

impl<P: OpenMlsProvider> Client<P> {
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
    /// others can add this device to a group while it is offline).
    pub fn key_package(&self) -> Result<Vec<u8>, TreeError> {
        let bundle = KeyPackage::builder()
            .build(self.ciphersuite, &self.provider, &self.signer, self.credential.clone())
            .map_err(|e| TreeError::Identity(format!("{e:?}")))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| TreeError::Malformed(format!("{e:?}")))
    }

    /// Starts a new conversation with only this device in it.
    pub fn create_group(&self) -> Result<Group, TreeError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(self.ciphersuite)
            .use_ratchet_tree_extension(true)
            .padding_size(Group::PADDING)
            .sender_ratchet_configuration(Group::sender_ratchet())
            .build();
        let mls = MlsGroup::new(&self.provider, &self.signer, &config, self.credential.clone())
            .map_err(crate::error::group_err)?;
        Ok(Group { mls })
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
        let mls = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(crate::error::group_err)?
            .into_group(&self.provider)
            .map_err(crate::error::group_err)?;
        Ok(Group { mls })
    }
}
