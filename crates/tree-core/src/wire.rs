//! Telling incoming bytes apart before handing them to a group
//! (PROTOCOL.md 4.1): a welcome (`Client::join`) or an envelope for a group
//! (`Group::receive` of the group named in the cleartext header).
//!
//! Nothing here is authenticated: the header only says where to route the
//! bytes. The group checks the seal before anything else.

use openmls::prelude::{tls_codec::Deserialize, ContentType, MlsMessageBodyIn, MlsMessageIn};

/// What a received byte string claims to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peek {
    /// An MLS welcome: hand it to `Client::join`.
    Welcome,
    /// A Tree envelope for this group and epoch.
    Envelope { group_id: Vec<u8>, epoch: u64, kind: Kind },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Application,
    Proposal,
    Commit,
}

/// Classifies `bytes`, or `None` if they are neither.
pub fn peek(bytes: &[u8]) -> Option<Peek> {
    match bytes.first()? {
        0x00 => match MlsMessageIn::tls_deserialize_exact(bytes).ok()?.extract() {
            MlsMessageBodyIn::Welcome(_) => Some(Peek::Welcome),
            _ => None,
        },
        0x01 if bytes.len() > 33 => {
            let p = MlsMessageIn::tls_deserialize_exact(&bytes[33..]).ok()?.try_into_protocol_message().ok()?;
            let kind = match p.content_type() {
                ContentType::Application => Kind::Application,
                ContentType::Proposal => Kind::Proposal,
                ContentType::Commit => Kind::Commit,
            };
            Some(Peek::Envelope { group_id: p.group_id().as_slice().to_vec(), epoch: p.epoch().as_u64(), kind })
        }
        _ => None,
    }
}
