//! Message requests, blocking and who may add this device to groups
//! (design: user.message_requests, user.stranger_block, user.group_add, block).
//!
//! A welcome is always processed (MLS needs it), but the group starts as a
//! request until the adder's account is known from its roster. Then:
//!
//! | adder | 1:1 chat (2 members) | group (3+) |
//! | --- | --- | --- |
//! | accepted contact | accepted | accepted, unless `user.group_add` = `nobody` |
//! | blocked | declined | declined |
//! | stranger, `user.stranger_block` applied | declined | declined |
//! | stranger | request if `user.message_requests` applied, else accepted | declined if `user.group_add` applied (contacts only / nobody), else as 1:1 |
//!
//! The adder is the roster's sender, under the account it claims; the
//! claim counts only if that device is already pinned for the account (or
//! nothing is pinned yet). Otherwise the adder is treated as a stranger
//! (and a key-change warning is shown). A group the user asked to join
//! through an invite link (the roster names the nonce of that request) is
//! accepted without a request, whatever `user.group_add` says.
//!
//! Declining sends a leave request and ignores the group from then on.
//! Enforcement is on this device: the server still delivers (it cannot know
//! contacts, by design).

use serde::{Deserialize, Serialize};

use crate::{contact_key, Contact, Error, Event, Payload, Session};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupStatus {
    Accepted,
    /// Waiting for the user (`from` = adder's account once known).
    Request { from: Option<String> },
    Declined,
}

fn status_key(g: &[u8]) -> String {
    format!("gstatus/{}", hex::encode(g))
}

impl Session {
    pub fn group_status(&self, gid: &[u8]) -> Result<GroupStatus, Error> {
        Ok(match self.client.app_data(&status_key(gid))? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged group status".into()))?,
            None => GroupStatus::Accepted,
        })
    }

    pub(crate) fn set_group_status(&self, gid: &[u8], s: &GroupStatus) -> Result<(), Error> {
        match s {
            GroupStatus::Accepted => self.client.set_app_data(&status_key(gid), None)?,
            s => self.client.set_app_data(&status_key(gid), Some(&serde_json::to_vec(s).expect("JSON")))?,
        }
        Ok(())
    }

    fn save_contact(&self, c: &Contact) -> Result<(), Error> {
        Ok(self.client.set_app_data(&contact_key(&c.account), Some(&serde_json::to_vec(c).expect("JSON")))?)
    }

    fn contact_or_new(&self, account: &str) -> Result<Contact, Error> {
        Ok(self.contact(account)?.unwrap_or_else(|| Contact { account: account.to_string(), ..Default::default() }))
    }

    /// Makes `account` a contact this user chose (invited, accepted, or
    /// added by hand, e.g. after finding a @username or scanning a QR code).
    pub fn add_contact(&self, account: &str) -> Result<(), Error> {
        self.accept_contact(account)
    }

    pub(crate) fn accept_contact(&self, account: &str) -> Result<(), Error> {
        let mut c = self.contact_or_new(account)?;
        if !c.accepted {
            c.accepted = true;
            self.save_contact(&c)?;
        }
        Ok(())
    }

    /// Blocks an account: its messages are dropped and its groups declined.
    pub fn block(&self, account: &str) -> Result<(), Error> {
        let mut c = self.contact_or_new(account)?;
        c.blocked = true;
        self.save_contact(&c)
    }

    pub fn unblock(&self, account: &str) -> Result<(), Error> {
        let mut c = self.contact_or_new(account)?;
        c.blocked = false;
        self.save_contact(&c)
    }

    pub(crate) fn is_blocked(&self, account: &str) -> Result<bool, Error> {
        Ok(self.contact(account)?.is_some_and(|c| c.blocked))
    }

    /// Accepts a pending request: the group is shown normally and its adder
    /// becomes a contact.
    pub fn accept_request(&mut self, gid: &[u8]) -> Result<(), Error> {
        let GroupStatus::Request { from } = self.group_status(gid)? else {
            return Err(Error::Usage("no request for this group".into()));
        };
        if let Some(a) = from {
            self.accept_contact(&a)?;
        }
        self.set_group_status(gid, &GroupStatus::Accepted)
    }

    /// Declines a request (or leaves an accepted group the same way):
    /// asks the others to remove this device and ignores the group.
    /// `block` also blocks the adder.
    pub fn decline(&mut self, gid: &[u8], block: bool) -> Result<(), Error> {
        if let (true, GroupStatus::Request { from: Some(a) }) = (block, self.group_status(gid)?) {
            self.block(&a)?;
        }
        if self.other_devices(gid)?.is_empty() {
            self.set_group_status(gid, &GroupStatus::Declined)?;
            return Ok(());
        }
        self.send_payload(gid, &Payload::Leave { quiet: false })?;
        self.set_group_status(gid, &GroupStatus::Declined)
    }

    /// Decides a group that is still a request once its adder is known.
    /// `vouched`: the adding device is one already pinned for `adder` (or
    /// none is pinned yet); otherwise the adder only claims that account
    /// and is treated as a stranger. `link`: the nonce of the invite link
    /// request the adder says this device made.
    pub(crate) fn decide_request(
        &mut self,
        gid: &[u8],
        adder: &str,
        vouched: bool,
        link: Option<&str>,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if !matches!(self.group_status(gid)?, GroupStatus::Request { .. }) {
            return Ok(());
        }
        let c = self.contact(adder)?;
        let direct = self.group(gid)?.members().len() <= 2;
        let decline = |reason: &str| Event::Declined { group: gid.to_vec(), from: adder.to_string(), reason: reason.into() };
        if c.as_ref().is_some_and(|c| c.blocked) {
            events.push(decline("blocked"));
            return self.decline(gid, false);
        }
        // The user opened an invite link of this account and this is the
        // answer to exactly that request: they asked to join (once per
        // link use). This deliberately skips the joiner's own
        // `user.group_add` and message requests: the user chose this group.
        // The nonce went only to the link owner's device, so it vouches for
        // the adder by itself.
        if self.take_link_join(adder, link)? {
            return self.set_group_status(gid, &GroupStatus::Accepted);
        }
        // An unvouched adder gets none of a contact's trust.
        let c = c.filter(|_| vouched);
        let group_add = self.feature("user.group_add")?;
        if !direct && group_add.state == tree_core::features::State::Applied && group_add.option.as_deref() == Some("nobody") {
            events.push(decline("nobody may add you to groups (user.group_add = nobody)"));
            return self.decline(gid, false);
        }
        if c.as_ref().is_some_and(|c| c.accepted) {
            return self.set_group_status(gid, &GroupStatus::Accepted);
        }
        if !direct && self.is_applied("user.group_safety_notice")? {
            events.push(Event::GroupSafetyNotice { group: gid.to_vec(), adder: adder.to_string() });
        }
        if self.is_applied("user.stranger_block")? {
            events.push(decline("messages from strangers are blocked (user.stranger_block)"));
            return self.decline(gid, false);
        }
        if !direct && self.is_applied("user.group_add")? {
            events.push(decline("only contacts may add you to groups (user.group_add)"));
            return self.decline(gid, false);
        }
        if self.is_applied("user.message_requests")? {
            self.set_group_status(gid, &GroupStatus::Request { from: Some(adder.to_string()) })?;
            events.push(Event::Request { group: gid.to_vec(), from: adder.to_string(), direct });
            Ok(())
        } else {
            self.set_group_status(gid, &GroupStatus::Accepted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts_key;

    /// A real server in this process and a way to make devices on it.
    struct Server {
        dir: std::path::PathBuf,
        url: String,
        _rt: tokio::runtime::Runtime,
    }

    impl Server {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("tree-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let cfg = tree_server::Config {
                database_url: format!("sqlite://{}/s.db", dir.display()),
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                pow_bits: 8,
                attachment_dir: dir.join("att"),
                ..tree_server::Config::default()
            };
            let rt = tokio::runtime::Runtime::new().unwrap();
            let server = rt.block_on(tree_server::start(cfg)).unwrap();
            rt.block_on(tree_server::features::set_applied(&server.state.db, tree_server::features::NEW_ACCOUNT_LIMITS, false))
                .unwrap();
            let url = format!("http://{}", server.addr);
            std::mem::forget(server);
            Self { dir, url, _rt: rt }
        }

        fn device(&self, name: &str) -> Session {
            Session::create(&self.dir.join(format!("{name}.db")).display().to_string(), "pw", name, &self.url, 8).unwrap()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A modified client: the group's roster says its own device belongs to
    /// `claimed` (the account map is the sender's word).
    fn claim_to_be(s: &Session, gid: &[u8], claimed: &str) {
        let me = s.member_id().to_hex();
        let mut m = s.map(&accounts_key(gid)).unwrap();
        m.insert(me, claimed.to_string());
        s.save_map(&accounts_key(gid), &m).unwrap();
    }

    /// F-018: a stranger whose device claims to be one of the user's
    /// contacts gets no contact trust: a 1:1 chat is a request, a group is
    /// declined by `user.group_add`, and a key-change warning is shown.
    /// The real contact is still accepted.
    #[test]
    fn a_device_claiming_a_contacts_account_is_a_stranger() {
        let srv = Server::new("impersonate");
        let mut alice = srv.device("alice");
        let mut bob = srv.device("bob");
        let mut mallory = srv.device("mallory");
        let carol = srv.device("carol");
        // bob knows alice and has her device pinned.
        bob.add_contact(alice.account_id()).unwrap();
        let g0 = alice.create_group().unwrap();
        alice.invite(&g0, bob.account_id()).unwrap();
        bob.sync(0).unwrap();
        assert_eq!(bob.group_status(&g0).unwrap(), GroupStatus::Accepted);

        // 1:1: mallory's roster names alice's account for her own device.
        let g1 = mallory.create_group().unwrap();
        claim_to_be(&mallory, &g1, alice.account_id());
        mallory.invite(&g1, bob.account_id()).unwrap();
        let ev = bob.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::KeyChanged { account, .. } if account == alice.account_id())), "{ev:?}");
        assert!(ev.iter().any(|e| matches!(e, Event::Request { direct: true, .. })), "{ev:?}");
        assert!(matches!(bob.group_status(&g1).unwrap(), GroupStatus::Request { .. }));

        // A group: declined, since only contacts may add bob to groups.
        let g2 = mallory.create_group().unwrap();
        claim_to_be(&mallory, &g2, alice.account_id());
        mallory.invite(&g2, carol.account_id()).unwrap();
        mallory.invite(&g2, bob.account_id()).unwrap();
        let ev = bob.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Declined { reason, .. } if reason.contains("user.group_add"))), "{ev:?}");
        assert_eq!(bob.group_status(&g2).unwrap(), GroupStatus::Declined);

        // alice's own device still counts as alice.
        let g3 = alice.create_group().unwrap();
        alice.invite(&g3, bob.account_id()).unwrap();
        let ev = bob.sync(0).unwrap();
        assert!(!ev.iter().any(|e| matches!(e, Event::Request { .. } | Event::Declined { .. })), "{ev:?}");
        assert_eq!(bob.group_status(&g3).unwrap(), GroupStatus::Accepted);
    }

    /// F-018: someone else who saw a public invite link cannot pull the
    /// joiner into their own group by claiming to be the link's owner: only
    /// the owner's device learns the nonce of the join request.
    #[test]
    fn a_public_link_does_not_let_others_pull_the_joiner_in() {
        let srv = Server::new("linkclaim");
        let mut alice = srv.device("alice");
        let mut dave = srv.device("dave");
        let mut mallory = srv.device("mallory");
        let carol = srv.device("carol");
        let g = alice.create_group().unwrap();
        alice.invite(&g, carol.account_id()).unwrap();
        let link = alice.create_invite_link(&g, 3600, 10).unwrap();
        dave.join_invite_link(&link).unwrap();
        // mallory knows the link (it was published), so she knows its
        // hash; she claims alice's account and names hash and a guess.
        let token = crate::invites::parse_link(&link).unwrap();
        for fake in [hex::encode(crate::invites::token_hash(&token)), "ab".repeat(16)] {
            let gm = mallory.create_group().unwrap();
            claim_to_be(&mallory, &gm, alice.account_id());
            mallory.invite(&gm, carol.account_id()).unwrap();
            mallory.invite_via(&gm, dave.account_id(), Some(fake)).unwrap();
            let ev = dave.sync(0).unwrap();
            assert!(ev.iter().any(|e| matches!(e, Event::Declined { .. })), "{ev:?}");
            assert_eq!(dave.group_status(&gm).unwrap(), GroupStatus::Declined);
        }
        // alice's device takes the request and dave joins her group.
        alice.sync(0).unwrap();
        let ev = dave.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Joined { .. })), "{ev:?}");
        assert_eq!(dave.group_status(&g).unwrap(), GroupStatus::Accepted);
    }
}
