//! Shared fixtures for the verification tests.
//!
//! `Insider` is a group member built directly on the MLS library instead of
//! on `tree_core::Client`. It joins a Tree group the normal way (key package,
//! then welcome), so it knows the epoch exporter secret and can produce
//! correctly sealed envelopes around ANY bytes. This models a malicious or
//! modified client and lets tests reach the code behind the outer seal.
#![allow(dead_code)]

use openmls::prelude::{tls_codec::Deserialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, types::HashType, OpenMlsProvider};
use tree_core::{Client, DefaultProvider, Group, MemberId, TreeError, TreeProvider, TREE_CIPHERSUITE};

pub const ENVELOPE_LABEL: &str = "tree/envelope/v1";
pub const TAG_LEN: usize = 32;

/// Commit and welcome of an add that the "server" accepted at once.
pub struct Added {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// Confirm-immediately helpers, for tests only: they skip the server's
/// commit ordering (a real client waits for acceptance, F-003).
pub trait Now {
    fn add_now<P: TreeProvider>(&mut self, me: &Client<P>, kp: &[u8]) -> Result<Added, TreeError>;
    fn remove_now<P: TreeProvider>(&mut self, me: &Client<P>, ids: &[MemberId]) -> Result<Vec<u8>, TreeError>;
    fn refresh_now<P: TreeProvider>(&mut self, me: &Client<P>) -> Result<Vec<u8>, TreeError>;
}

impl Now for Group {
    fn add_now<P: TreeProvider>(&mut self, me: &Client<P>, kp: &[u8]) -> Result<Added, TreeError> {
        let p = self.add(me, &[kp])?;
        self.confirm_commit(me)?;
        Ok(Added { commit: p.commit, welcome: p.welcome.expect("add has a welcome") })
    }
    fn remove_now<P: TreeProvider>(&mut self, me: &Client<P>, ids: &[MemberId]) -> Result<Vec<u8>, TreeError> {
        let p = self.remove(me, ids)?;
        self.confirm_commit(me)?;
        Ok(p.commit)
    }
    fn refresh_now<P: TreeProvider>(&mut self, me: &Client<P>) -> Result<Vec<u8>, TreeError> {
        let p = self.refresh_keys(me)?;
        self.confirm_commit(me)?;
        Ok(p.commit)
    }
}

/// Alice created a group and added Bob.
pub fn two_person_chat() -> (Client, Client, Group, Group) {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut a = alice.create_group().unwrap();
    let w = a.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    let b = bob.join(&w).unwrap();
    (alice, bob, a, b)
}

pub struct Insider {
    pub provider: DefaultProvider,
    pub signer: SignatureKeyPair,
    pub credential: CredentialWithKey,
    pub group: Option<MlsGroup>,
}

impl Insider {
    pub fn new(name: &str) -> Self {
        let provider = DefaultProvider::default();
        let signer = SignatureKeyPair::new(TREE_CIPHERSUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Self { provider, signer, credential, group: None }
    }

    pub fn key_package(&self) -> Vec<u8> {
        use openmls::prelude::tls_codec::Serialize;
        KeyPackage::builder()
            .build(TREE_CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .unwrap()
            .key_package()
            .tls_serialize_detached()
            .unwrap()
    }

    pub fn join(&mut self, welcome: &[u8]) {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome).unwrap();
        let MlsMessageBodyIn::Welcome(w) = msg.extract() else { panic!("not a welcome") };
        let cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .padding_size(Group::PADDING)
            .build();
        let g = StagedWelcome::new_from_welcome(&self.provider, &cfg, w, None)
            .unwrap()
            .into_group(&self.provider)
            .unwrap();
        self.group = Some(g);
    }

    pub fn group(&mut self) -> &mut MlsGroup {
        self.group.as_mut().expect("insider has not joined")
    }

    /// Envelope key of the insider's current epoch.
    pub fn envelope_key(&mut self) -> Vec<u8> {
        let crypto = self.provider.crypto();
        let g = self.group.as_ref().unwrap();
        g.export_secret(crypto, ENVELOPE_LABEL, g.group_id().as_slice(), 32).unwrap()
    }

    /// Wraps arbitrary bytes in a valid envelope for the insider's epoch.
    pub fn seal(&mut self, body: &[u8]) -> Vec<u8> {
        let key = self.envelope_key();
        let tag = self.provider.crypto().hmac(HashType::Sha2_256, &key, body).unwrap();
        let mut out = vec![1u8];
        out.extend_from_slice(&tag.as_slice()[..TAG_LEN]);
        out.extend_from_slice(body);
        out
    }

    /// A genuine MLS application message, NOT sealed.
    pub fn raw_message(&mut self, body: &[u8]) -> Vec<u8> {
        let (p, s) = (&self.provider, &self.signer);
        self.group.as_mut().unwrap().create_message(p, s, body).unwrap().to_bytes().unwrap()
    }

    /// A genuine, sealed application message (what an honest client sends).
    pub fn send(&mut self, body: &[u8]) -> Vec<u8> {
        let raw = self.raw_message(body);
        self.seal(&raw)
    }

    /// Processes a sealed commit from a Tree client.
    pub fn receive_commit(&mut self, sealed: &[u8]) {
        let body = &sealed[1 + TAG_LEN..];
        let msg = MlsMessageIn::tls_deserialize_exact(body).unwrap();
        let p = msg.try_into_protocol_message().unwrap();
        let provider = &self.provider;
        let g = self.group.as_mut().unwrap();
        let processed = g.process_message(provider, p).unwrap();
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(c) => g.merge_staged_commit(provider, *c).unwrap(),
            _ => panic!("expected a commit"),
        }
    }
}

/// Alice and Bob on Tree clients, plus an insider "mallory" built on raw MLS.
pub fn chat_with_insider(insider_name: &str) -> (Client, Client, Group, Group, Insider) {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let mut m = Insider::new(insider_name);
    let add = a.add_now(&alice, &m.key_package()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    m.join(&add.welcome);
    (alice, bob, a, b, m)
}

/// Display names of the current members, in leaf order.
pub fn names(g: &Group) -> Vec<String> {
    g.members().into_iter().map(|m| m.name).collect()
}

/// The text of an incoming chat message, if it is one.
pub fn text(r: &Result<tree_core::Incoming, TreeError>) -> Option<(MemberId, String, Vec<u8>)> {
    match r {
        Ok(tree_core::Incoming::Message { from, name, body }) => Some((*from, name.clone(), body.clone())),
        _ => None,
    }
}
