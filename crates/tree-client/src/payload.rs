//! What Tree apps put inside MLS application messages (v1).
//!
//! JSON, one object per message. Unknown types are shown as "unsupported",
//! never as text. Everything here is end-to-end encrypted and authenticated
//! by MLS; the sender is the MLS member id, never a field of the payload.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Payload {
    /// A chat message.
    Text { text: String },
    /// Member id (hex) -> server device id, sent by whoever added devices,
    /// to everyone (PROTOCOL.md Q8: the app keeps this mapping). A wrong
    /// entry only misroutes messages; it cannot reveal anything. `names` are
    /// the sender's view of display names: hints for new members until each
    /// member's own `Profile` arrives.
    Roster {
        devices: BTreeMap<String, String>,
        #[serde(default)]
        names: BTreeMap<String, String>,
        /// Member id -> account id, as the adder learned it from the server's
        /// key-package claim. Lets every member pin the devices of a contact.
        #[serde(default)]
        accounts: BTreeMap<String, String>,
    },
    /// The sender's own display name. Names never go to the server (F-009);
    /// they travel only inside the group, end-to-end encrypted.
    Profile { name: String },
    /// The sender asks to be removed (PROTOCOL.md 6.5).
    Leave,
    /// An encrypted attachment (PROTOCOL.md 6.12).
    File(FileInfo),
}

/// Where an attachment is and how to open it. Only ever inside an
/// end-to-end encrypted message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    /// Server attachment id.
    pub id: String,
    /// File key (base64, 32 bytes) and STREAM nonce prefix (base64, 7 bytes).
    pub key: String,
    pub nonce: String,
    pub size: u64,
    /// Hex SHA-256 of the ciphertext and of the plaintext (key commitment).
    pub ct_sha256: String,
    pub pt_sha256: String,
    pub name: String,
    pub mime: String,
}

impl Payload {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serialisable")
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_format() {
        let t = Payload::Text { text: "안녕".into() };
        assert_eq!(String::from_utf8(t.encode()).unwrap(), r#"{"t":"text","text":"안녕"}"#);
        assert_eq!(Payload::decode(&t.encode()), Some(t));
        let r = Payload::Roster {
            devices: [("ab".to_string(), "dev".to_string())].into(),
            names: Default::default(),
            accounts: [("ab".to_string(), "acc".to_string())].into(),
        };
        assert_eq!(Payload::decode(&r.encode()), Some(r));
        assert!(Payload::decode(br#"{"t":"roster","devices":{}}"#).is_some(), "names optional");
        let p = Payload::Profile { name: "bob".into() };
        assert_eq!(Payload::decode(&p.encode()), Some(p));
        assert_eq!(Payload::decode(br#"{"t":"leave"}"#), Some(Payload::Leave));
        assert_eq!(Payload::decode(br#"{"t":"sticker"}"#), None);
        assert_eq!(Payload::decode(b"plain"), None);
    }
}
