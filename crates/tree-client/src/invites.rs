//! Group invite links (PROTOCOL.md 8.7, `chat.invite_link`).
//!
//! An admin device makes a link `tree://join/<secret>` (16 random bytes,
//! base64url) with an expiry and a use limit and registers only the hash
//! of the secret with the server. It keeps which group the link is for. A
//! device that opens the link sends the secret; the server queues a join
//! request for the owner's device, which on its next sync adds the
//! requester through the normal MLS path if the link is still valid, the
//! group still allows links (`chat.invite_link` applied by its admins) and
//! this device is still an admin.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::InviteRequest;
use crate::messages::now;
use crate::{CommitOutcome, Error, Event, Session};

const PREFIX: &str = "tree://join/";
const FEATURE: &str = "chat.invite_link";
/// How long a "I opened this link" marker counts.
const JOIN_WINDOW: i64 = 86400;

/// "The user opened this link of `owner` at `at`" (`linkjoin/<hash hex>`).
#[derive(Serialize, Deserialize)]
struct LinkJoin {
    owner: String,
    at: i64,
}

/// A link this device made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteLink {
    pub group: String,
    pub expires_at: i64,
    pub max_uses: u32,
}

pub(crate) fn token_hash(token: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tree/invite/v1");
    h.update(token);
    h.finalize().into()
}

fn key(hash: &[u8]) -> String {
    format!("invite/{}", hex::encode(hash))
}

pub(crate) fn parse_link(link: &str) -> Result<Vec<u8>, Error> {
    let t = link.trim().strip_prefix(PREFIX).ok_or_else(|| Error::Usage("not a Tree invite link".into()))?;
    let token = URL_SAFE_NO_PAD.decode(t).map_err(|_| Error::Usage("damaged invite link".into()))?;
    if token.len() != 16 {
        return Err(Error::Usage("damaged invite link".into()));
    }
    Ok(token)
}

impl Session {
    /// Makes an invite link for a group this device administers. Applies
    /// `chat.invite_link` in the group settings if it was released.
    pub fn create_invite_link(&mut self, gid: &[u8], lifetime_secs: i64, max_uses: u32) -> Result<String, Error> {
        let me = self.member_id();
        if !self.group(gid)?.is_admin(&me) {
            return Err(Error::Feature("NOT_ADMIN".into()));
        }
        if !self.chat_feature(gid, FEATURE)?.0 {
            if let CommitOutcome::Lost = self.set_chat_feature(gid, FEATURE, true, None)? {
                return Err(Error::Usage("the group changed meanwhile; sync and try again".into()));
            }
        }
        let mut token = [0u8; 16];
        getrandom::getrandom(&mut token).expect("operating system random number generator failed");
        let h = token_hash(&token);
        let v = self.api.invite_create(&self.creds, &h, lifetime_secs, max_uses)?;
        let expires_at = v["expires_at"].as_i64().unwrap_or(now() + lifetime_secs);
        let rec = InviteLink { group: hex::encode(gid), expires_at, max_uses };
        self.client.set_app_data(&key(&h), Some(&serde_json::to_vec(&rec).expect("JSON")))?;
        Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(token)))
    }

    /// Links this device made for a group: (hash hex, link record).
    pub fn invite_links(&self, gid: &[u8]) -> Result<Vec<(String, InviteLink)>, Error> {
        let mut out = Vec::new();
        for k in self.client.app_data_keys("invite/")? {
            if let Some(rec) = self.client.app_data(&k)?.and_then(|v| serde_json::from_slice::<InviteLink>(&v).ok()) {
                if rec.group == hex::encode(gid) {
                    out.push((k["invite/".len()..].to_string(), rec));
                }
            }
        }
        Ok(out)
    }

    /// Revokes every link this device made for the group, and releases
    /// `chat.invite_link` for the group (admins only), which stops links
    /// other admins made as well.
    pub fn revoke_invite_links(&mut self, gid: &[u8]) -> Result<(), Error> {
        for (h, _) in self.invite_links(gid)? {
            let hash = hex::decode(&h).map_err(|_| Error::Protocol("bad invite key".into()))?;
            self.api.invite_revoke(&self.creds, &hash)?;
            self.client.set_app_data(&key(&hash), None)?;
        }
        if self.chat_feature(gid, FEATURE)?.0 {
            self.set_chat_feature(gid, FEATURE, false, None)?;
        }
        Ok(())
    }

    /// Uses an invite link. The link's owner adds this account when its
    /// device next syncs; the group then arrives as accepted (the user
    /// asked to join). Returns the owner's account id.
    pub fn join_invite_link(&mut self, link: &str) -> Result<String, Error> {
        let token = parse_link(link)?;
        // Everyone who has the link knows the token; only the owner's device
        // gets this nonce (from the server, with the request). A roster
        // naming it therefore comes from the device that took the request,
        // not from someone else who saw the link and claims the owner's
        // account (F-018).
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).expect("operating system random number generator failed");
        let owner = self.api.invite_join(&self.creds, &STANDARD.encode(&token), &nonce)?;
        let mark = LinkJoin { owner: owner.clone(), at: now() };
        self.client.set_app_data(&format!("linkjoin/{}", hex::encode(nonce)), Some(&serde_json::to_vec(&mark).expect("JSON")))?;
        Ok(owner)
    }

    /// True (once) if the user recently opened an invite link of `account`
    /// and `link` is the nonce (hex) this device sent with that request.
    /// Tying it to the request means the owner can bring the user into one
    /// group, the one this use was for, and nobody else can.
    pub(crate) fn take_link_join(&mut self, account: &str, link: Option<&str>) -> Result<bool, Error> {
        let Some(h) = link.filter(|h| h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit())) else { return Ok(false) };
        let k = format!("linkjoin/{h}");
        let Some(mark) = self.client.app_data(&k)?.and_then(|v| serde_json::from_slice::<LinkJoin>(&v).ok()) else {
            return Ok(false);
        };
        if mark.owner != account {
            return Ok(false);
        }
        self.client.set_app_data(&k, None)?;
        Ok(now() - mark.at <= JOIN_WINDOW)
    }

    fn handle_invite_request(&mut self, req: &InviteRequest, events: &mut Vec<Event>) -> Result<(), Error> {
        let (hash, account) = (&req.hash[..], req.account.as_str());
        let k = key(hash);
        let Some(rec) = self.client.app_data(&k)?.and_then(|v| serde_json::from_slice::<InviteLink>(&v).ok()) else {
            return Ok(()); // revoked here, or made by another device
        };
        let gid = hex::decode(&rec.group).map_err(|_| Error::Protocol("bad invite record".into()))?;
        let refuse = |events: &mut Vec<Event>, why: &str| events.push(Event::Dropped { reason: format!("invite link request from {account}: {why}") });
        if self.group(&gid).is_err() {
            self.client.set_app_data(&k, None)?;
            refuse(events, "the group is gone");
            return Ok(());
        }
        let me = self.member_id();
        if !self.group(&gid)?.is_admin(&me) || !self.chat_feature(&gid, FEATURE)?.0 {
            refuse(events, "links are no longer allowed in this group");
            return Ok(());
        }
        if self.contact(account)?.is_some_and(|c| c.blocked) {
            refuse(events, "blocked account");
            return Ok(());
        }
        // Without the joiner's nonce (an older client) the group arrives as
        // a request on its side.
        let nonce = req.nonce.as_ref().filter(|n| n.len() == 16).map(hex::encode);
        match self.invite_via(&gid, account, nonce)? {
            (CommitOutcome::Accepted { .. }, ev) => {
                events.extend(ev);
                events.push(Event::InviteLinkUsed { group: gid, account: account.to_string() });
            }
            (CommitOutcome::Lost, _) => refuse(events, "the group changed meanwhile; ask again"),
        }
        Ok(())
    }

    /// Handles join requests for this device's links (called by `sync`).
    pub(crate) fn handle_invite_requests(&mut self, events: &mut Vec<Event>) -> Result<(), Error> {
        if self.client.app_data_keys("invite/")?.is_empty() {
            return Ok(());
        }
        let mut done = Vec::new();
        for req in self.api.invite_requests(&self.creds)? {
            done.push(req.id.clone());
            // One bad request must not stop the others or block the ack.
            if let Err(e) = self.handle_invite_request(&req, events) {
                events.push(Event::Dropped { reason: format!("invite link request from {}: {e}", req.account) });
            }
        }
        if !done.is_empty() {
            self.api.invite_ack(&self.creds, &done)?;
        }
        // Forget links that expired.
        for k in self.client.app_data_keys("invite/")? {
            if let Some(rec) = self.client.app_data(&k)?.and_then(|v| serde_json::from_slice::<InviteLink>(&v).ok()) {
                if rec.expires_at + 7 * 86400 < now() {
                    self.client.set_app_data(&k, None)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_parse() {
        let t = [5u8; 16];
        let link = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(t));
        assert_eq!(parse_link(&format!(" {link}\n")).unwrap(), t.to_vec());
        assert!(parse_link("https://example.org/x").is_err());
        assert!(parse_link(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode([1u8; 15]))).is_err());
        assert!(parse_link(&format!("{PREFIX}!!")).is_err());
        assert_eq!(hex::encode(token_hash(&t)).len(), 64);
    }
}
