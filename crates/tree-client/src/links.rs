//! Username links and QR codes (PROTOCOL.md 8.4, `user.username_link`,
//! released by default).
//!
//! Applying the setting makes a link `tree://u/<token>` (16 random bytes,
//! base64url) that finds this account. The server stores only
//! `SHA-256("tree/ulink/v1" || token)` next to the account, never the
//! token, and answers a lookup by that hash only while the account's
//! @username is registered and findable (`user.discoverable`). Resetting
//! the link registers a new token, so an old shared link stops working
//! while the @username stays. Releasing the setting (or the @username)
//! deletes the link on the server.
//!
//! The QR code is the link text; the apps draw it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{api, Error, Session};

const PREFIX: &str = "tree://u/";
/// The current token (base64url), while the setting is applied.
const K_LINK: &str = "profile/link";
pub(crate) const USERNAME_LINK: &str = "user.username_link";

/// What the server stores for a link token.
pub fn link_hash(token: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(b"tree/ulink/v1").chain_update(token).finalize().into()
}

fn parse(link: &str) -> Result<Vec<u8>, Error> {
    let bad = || Error::Usage("not a Tree username link".into());
    let t = link.trim().strip_prefix(PREFIX).ok_or_else(bad)?;
    let token = URL_SAFE_NO_PAD.decode(t).map_err(|_| bad())?;
    if token.len() != 16 {
        return Err(bad());
    }
    Ok(token)
}

impl Session {
    fn link_token(&self) -> Result<Option<String>, Error> {
        Ok(self.client.app_data(K_LINK)?.and_then(|v| String::from_utf8(v).ok()))
    }

    /// This account's username link, while `user.username_link` is applied.
    pub fn username_link(&self) -> Result<Option<String>, Error> {
        if !self.is_applied(USERNAME_LINK)? {
            return Ok(None);
        }
        Ok(self.link_token()?.map(|t| format!("{PREFIX}{t}")))
    }

    /// The text to put into a QR code (the link itself); apps draw it.
    pub fn username_qr(&self) -> Result<Option<String>, Error> {
        self.username_link()
    }

    /// A new link for the same @username; the old link stops working at
    /// once (the server keeps one link per account).
    pub fn reset_username_link(&self) -> Result<String, Error> {
        if !self.is_applied(USERNAME_LINK)? {
            return Err(Error::Feature("RELEASED".into()));
        }
        self.make_username_link()
    }

    /// Registers a fresh token with the server, then keeps it.
    pub(crate) fn make_username_link(&self) -> Result<String, Error> {
        if self.username()?.is_none() {
            return Err(Error::Usage("choose a @username first".into()));
        }
        let mut token = [0u8; 16];
        getrandom::getrandom(&mut token).expect("operating system random number generator failed");
        let h = link_hash(&token);
        self.api.username(&self.creds, "link/apply", Some(&json!({ "hash": api::b64(&h) })))?;
        let t = URL_SAFE_NO_PAD.encode(token);
        self.client.set_app_data(K_LINK, Some(t.as_bytes()))?;
        Ok(format!("{PREFIX}{t}"))
    }

    /// Deletes the link on the server, then here.
    pub(crate) fn drop_username_link(&self) -> Result<(), Error> {
        self.api.username(&self.creds, "link/release", None)?;
        Ok(self.client.set_app_data(K_LINK, None)?)
    }

    /// The server dropped the link with the @username: forget it here and
    /// release the setting.
    pub(crate) fn forget_username_link(&self) -> Result<(), Error> {
        self.client.set_app_data(K_LINK, None)?;
        self.change(USERNAME_LINK, false, None)?;
        Ok(())
    }

    /// The account behind a username link, if the link is current and its
    /// owner's @username is findable.
    pub fn find_by_link(&self, link: &str) -> Result<Option<String>, Error> {
        let h = link_hash(&parse(link)?);
        match self.api.username(&self.creds, "link/lookup", Some(&json!({ "hash": api::b64(&h) }))) {
            Ok(v) => Ok(v["account_id"].as_str().map(str::to_string)),
            Err(Error::Server { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Scanned a QR code or opened a link: adds its account as a contact
    /// the user chose. Returns the account, or `None` if the link no longer
    /// works.
    pub fn add_contact_by_link(&self, link: &str) -> Result<Option<String>, Error> {
        let Some(account) = self.find_by_link(link)? else { return Ok(None) };
        if account != self.account_id() {
            self.add_contact(&account)?;
        }
        Ok(Some(account))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_parse() {
        let token = [7u8; 16];
        let link = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(token));
        assert_eq!(parse(&format!(" {link} ")).unwrap(), token.to_vec());
        for bad in ["tree://join/AAAAAAAAAAAAAAAAAAAAAA", "tree://u/", "tree://u/AAAA", "https://u/AAAAAAAAAAAAAAAAAAAAAA"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let want: [u8; 32] = Sha256::digest([&b"tree/ulink/v1"[..], &token].concat()).into();
        assert_eq!(link_hash(&token), want);
        assert_ne!(link_hash(&token), crate::invites::token_hash(&token), "labels differ from invite links");
    }
}
