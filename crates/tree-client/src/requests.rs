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
//! claim counts only if that device is pinned for the account (named by the
//! server in a key-package claim this device made, or covered by a verified
//! safety number). Otherwise the adder is treated as a stranger, also when
//! the account has no pinned device yet (a contact added by hand or by
//! username link), and a key-change warning is shown for a known account.
//! A device is blocked if its account label is blocked or it was ever seen
//! for a blocked account. A group the user asked to join
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

    /// [`Session::add_contact`], and pins the devices the server names for
    /// the account right now (a key-package claim, exactly as an invite
    /// makes; the claimed key packages are not used). Adding a contact by
    /// hand or by username link pins nothing (F-021): until the server
    /// names a device in a claim this device made, or the user verifies the
    /// safety number, the contact's groups arrive as requests. Returns any
    /// key-change warnings.
    pub fn confirm_contact(&self, account: &str) -> Result<Vec<Event>, Error> {
        if account == self.account_id() {
            return Err(Error::Usage("this is your own account".into()));
        }
        let claimed = self.api.claim(&self.creds, account)?;
        let ids = claimed
            .iter()
            .map(|(_, kp)| self.client.check_key_package(kp).map(|(m, _)| m))
            .collect::<Result<Vec<_>, _>>()?;
        let mut events = Vec::new();
        self.pin(account, &ids, true, &mut events)?;
        self.accept_contact(account)?;
        Ok(events)
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
    /// `adder`: the account the adding device (`adder_member`) claims.
    /// `vouched`: that device is pinned for `adder`; otherwise the adder
    /// only claims that account and is treated as a stranger (also when the
    /// account has no pinned device at all, F-021). `link`: the nonce of
    /// the invite link request the adder says this device made.
    pub(crate) fn decide_request(
        &mut self,
        gid: &[u8],
        adder: &str,
        adder_member: &tree_core::MemberId,
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
        if c.as_ref().is_some_and(|c| c.blocked) || self.blocked_sender(gid, adder_member)? {
            events.push(decline("blocked"));
            return self.decline(gid, false);
        }
        // The user opened an invite link of this account and this is the
        // answer to exactly that request: they asked to join (once per
        // link use). This deliberately skips the joiner's own
        // `user.group_add` and message requests: the user chose this group.
        // The adder is the device the (version 2) link named, and the roster
        // names the nonce that only the link's holder could open (F-025).
        // A version 1 link named its owner only through the server: its
        // group goes to the request inbox instead.
        match self.take_link_join(adder, adder_member, link)? {
            crate::invites::LinkConsent::Verified => return self.set_group_status(gid, &GroupStatus::Accepted),
            crate::invites::LinkConsent::Unverified => {
                self.set_group_status(gid, &GroupStatus::Request { from: Some(adder.to_string()) })?;
                events.push(Event::Request { group: gid.to_vec(), from: adder.to_string(), direct });
                return Ok(());
            }
            crate::invites::LinkConsent::None => {}
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

        /// Runs `q` (with one text argument) on the server's database.
        fn sql(&self, q: &'static str, arg: &str) -> u64 {
            let (db, arg) = (format!("sqlite://{}/s.db", self.dir.display()), arg.to_string());
            self._rt.block_on(async move {
                let pool = sqlx::SqlitePool::connect(&db).await.unwrap();
                let n = sqlx::query(q).bind(arg).execute(&pool).await.unwrap().rows_affected();
                pool.close().await;
                n
            })
        }

        /// Every blob in one column of the server's database.
        fn blobs(&self, q: &'static str) -> Vec<Vec<u8>> {
            let db = format!("sqlite://{}/s.db", self.dir.display());
            self._rt.block_on(async move {
                let pool = sqlx::SqlitePool::connect(&db).await.unwrap();
                let v: Vec<(Vec<u8>,)> = sqlx::query_as(q).fetch_all(&pool).await.unwrap();
                pool.close().await;
                v.into_iter().map(|r| r.0).collect()
            })
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
        // bob knows alice and has her device pinned (the server named it
        // when bob invited her).
        let gb = bob.create_group().unwrap();
        bob.invite(&gb, alice.account_id()).unwrap();
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

    /// F-021: a contact added by username link has no pinned device. A
    /// stranger who claims that account in a roster is still a stranger: the
    /// chat is a request, a group is declined by `user.group_add`, the
    /// stranger's device is not pinned for the contact, and a warning is
    /// shown. The contact's real device, once the server names it, counts.
    #[test]
    fn a_contact_without_pinned_devices_vouches_for_nobody() {
        let srv = Server::new("emptycontact");
        let mut alice = srv.device("alice");
        let mut bob = srv.device("bob");
        let mut mallory = srv.device("mallory");
        let carol = srv.device("carol");
        alice.set_username("alice_f021").unwrap();
        alice.apply_feature("user.username_link", None).unwrap();
        let link = alice.username_link().unwrap().unwrap();
        assert_eq!(bob.add_contact_by_link(&link).unwrap().as_deref(), Some(alice.account_id()));
        let c = bob.contact(alice.account_id()).unwrap().unwrap();
        assert!(c.accepted && c.members.is_empty());

        let g1 = mallory.create_group().unwrap();
        claim_to_be(&mallory, &g1, alice.account_id());
        mallory.invite(&g1, bob.account_id()).unwrap();
        let ev = bob.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Request { direct: true, .. })), "{ev:?}");
        assert!(matches!(bob.group_status(&g1).unwrap(), GroupStatus::Request { .. }));
        assert!(ev.iter().any(|e| matches!(e, Event::KeyChanged { account, .. } if account == alice.account_id())), "warned: {ev:?}");
        let c = bob.contact(alice.account_id()).unwrap().unwrap();
        assert!(c.pinned().is_empty(), "no pin: {c:?}");
        assert!(!c.vouches_for(&mallory.member_id().to_hex()));

        let g2 = mallory.create_group().unwrap();
        claim_to_be(&mallory, &g2, alice.account_id());
        mallory.invite(&g2, carol.account_id()).unwrap();
        mallory.invite(&g2, bob.account_id()).unwrap();
        let ev = bob.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Declined { reason, .. } if reason.contains("user.group_add"))), "{ev:?}");
        assert!(bob.contact(alice.account_id()).unwrap().unwrap().pinned().is_empty());

        // bob invites alice: the server names her device, which is pinned;
        // mallory's claimed device stays unpinned.
        let gb = bob.create_group().unwrap();
        bob.invite(&gb, alice.account_id()).unwrap();
        let c = bob.contact(alice.account_id()).unwrap().unwrap();
        assert_eq!(c.pinned(), vec![alice.member_id().to_hex()]);
        assert!(!c.vouches_for(&mallory.member_id().to_hex()));
        let g3 = alice.create_group().unwrap();
        alice.invite(&g3, bob.account_id()).unwrap();
        bob.sync(0).unwrap();
        assert_eq!(bob.group_status(&g3).unwrap(), GroupStatus::Accepted);
    }

    /// A forged roster from `s`: its own device labelled `account`.
    fn forged_roster(s: &mut Session, gid: &[u8], account: &str) {
        let me = s.member_id().to_hex();
        let roster = crate::Payload::Roster {
            devices: [(me.clone(), s.device_id().to_string())].into(),
            names: Default::default(),
            accounts: [(me, account.to_string())].into(),
            link: None,
        };
        s.send_payload(gid, &roster).unwrap();
    }

    fn file() -> crate::FileInfo {
        serde_json::from_value(serde_json::json!({
            "id": "a".repeat(22), "key": "k", "size": 10, "pt_sha256": "00", "name": "f", "mime": "application/octet-stream"
        }))
        .unwrap()
    }

    /// F-022 (c): a blocked member cannot get past the block by relabelling
    /// its device: a roster never relabels a member, and a device ever seen
    /// for a blocked account stays blocked under any label.
    #[test]
    fn relabelling_does_not_escape_a_block() {
        let srv = Server::new("relabel");
        let mut alice = srv.device("alice");
        let mut bob = srv.device("bob");
        let mut mallory = srv.device("mallory");
        // bob has alice pinned; alice adds bob and mallory to a group.
        let gb = bob.create_group().unwrap();
        bob.invite(&gb, alice.account_id()).unwrap();
        mallory.confirm_contact(alice.account_id()).unwrap();
        let g = alice.create_group().unwrap();
        alice.invite(&g, mallory.account_id()).unwrap();
        alice.invite(&g, bob.account_id()).unwrap();
        mallory.sync(0).unwrap();
        bob.sync(0).unwrap();
        assert_eq!(bob.group_status(&g).unwrap(), GroupStatus::Accepted);
        bob.block(mallory.account_id()).unwrap();
        mallory.send_text(&g, "blocked").unwrap();
        assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::Dropped { .. })));

        // mallory relabels her device as a fresh account.
        forged_roster(&mut mallory, &g, "fresh-account-id");
        bob.sync(0).unwrap();
        assert_eq!(bob.map(&accounts_key(&g)).unwrap().get(&mallory.member_id().to_hex()).map(String::as_str), Some(mallory.account_id()));
        mallory.send_text(&g, "relabelled").unwrap();
        let ev = bob.sync(0).unwrap();
        assert!(!ev.iter().any(|e| matches!(e, Event::Text { .. })), "{ev:?}");
        // A new chat where her first label is the fresh one: still blocked.
        let g2 = mallory.create_group().unwrap();
        claim_to_be(&mallory, &g2, "fresh-account-id");
        mallory.invite(&g2, bob.account_id()).unwrap();
        let ev = bob.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Declined { reason, .. } if reason == "blocked")), "{ev:?}");
    }

    /// F-022 (a), (d): a stranger who labels its device with the receiver's
    /// own account is not taken as one of the receiver's devices: its files
    /// do not download by themselves and a "contacts only" profile photo is
    /// not sent to its chat.
    #[test]
    fn claiming_the_receivers_own_account_gets_nothing() {
        let srv = Server::new("ownclaim");
        let mut bob = srv.device("bob");
        let mut mallory = srv.device("mallory");
        let g = mallory.create_group().unwrap();
        claim_to_be(&mallory, &g, bob.account_id());
        mallory.invite(&g, bob.account_id()).unwrap();
        bob.sync(0).unwrap();
        bob.accept_request(&g).unwrap();
        forged_roster(&mut mallory, &g, bob.account_id());
        bob.sync(0).unwrap();
        let m = mallory.member_id();
        assert_ne!(bob.map(&accounts_key(&g)).unwrap().get(&m.to_hex()).map(String::as_str), Some(bob.account_id()), "label refused");
        assert!(bob.vouched_account(&g, &m).unwrap().is_none());
        bob.set_network(tree_core::features::Network::Wifi);
        assert!(!bob.auto_download_allowed(&g, &m, &file()).unwrap(), "a stranger's file never downloads by itself");
        bob.apply_feature(crate::profile::VISIBILITY, Some("contacts".into())).unwrap();
        assert!(!bob.photo_allowed(&g).unwrap(), "the photo is not for strangers");
        // Control: bob's real linked devices would count (own/members), and
        // with "chats" visibility the photo goes to any chat.
        bob.apply_feature(crate::profile::VISIBILITY, Some("chats".into())).unwrap();
        assert!(bob.photo_allowed(&g).unwrap());
    }

    /// F-024: handling a received message sends nothing over the network.
    /// A decline (here: a blocked account's new chat) seals its leave
    /// request into the outbox inside the receive batch, which commits; the
    /// request goes out only when the outbox is driven afterwards.
    #[test]
    fn a_decline_is_only_queued_inside_the_receive_batch() {
        let srv = Server::new("batchsend");
        let mut bob = srv.device("bob");
        let mut mallory = srv.device("mallory");
        bob.block(mallory.account_id()).unwrap();
        let g = mallory.create_group().unwrap();
        mallory.invite(&g, bob.account_id()).unwrap();
        let mut events = Vec::new();
        for (_, body) in bob.api.fetch(&bob.creds, 0).unwrap() {
            // Debug builds also stop at any request made in here
            // (`Api::assert_not_receiving`).
            bob.handle_durably(&body, &mut events, true).unwrap();
        }
        assert!(events.iter().any(|e| matches!(e, Event::Declined { reason, .. } if reason == "blocked")), "{events:?}");
        assert_eq!(bob.group_status(&g).unwrap(), GroupStatus::Declined, "the batch committed");
        let queued = bob.outbox().unwrap();
        assert_eq!(queued.len(), 1, "the leave request waits in the outbox: {queued:?}");
        assert_eq!(queued[0].state, tree_core::storage::outbox::OutboxState::Queued);
        assert!(!mallory.sync(0).unwrap().iter().any(|e| matches!(e, Event::LeaveRequested { .. })), "nothing was sent yet");
        // After the batch: the outbox sends the sealed bytes.
        bob.send_pending().unwrap();
        assert!(bob.outbox().unwrap().is_empty());
        let ev = mallory.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::LeaveRequested { .. })), "{ev:?}");
    }

    /// F-025: the invite link names its owner, so a server that names
    /// another owner is caught before anything is joined; the joiner's nonce
    /// reaches the server only sealed, never in the clear; the real owner
    /// still brings the joiner in without a request.
    #[test]
    fn the_invite_link_names_its_owner_and_the_server_never_sees_the_nonce() {
        let srv = Server::new("linkowner");
        let mut alice = srv.device("alice");
        let mut dave = srv.device("dave");
        let mallory = srv.device("mallory");
        let carol = srv.device("carol");
        let g = alice.create_group().unwrap();
        alice.invite(&g, carol.account_id()).unwrap();
        let link = alice.create_invite_link(&g, 3600, 10).unwrap();
        let crate::invites::ParsedLink::V2 { token, member, owner } = crate::invites::parse_link(&link).unwrap() else { panic!("version 2") };
        assert_eq!((member, owner.as_str()), (alice.member_id(), alice.account_id()));
        // The server holds the hash of a proof, not of the secret itself.
        assert!(srv.blobs("SELECT token_hash FROM invites").iter().all(|h| *h != crate::invites::token_hash(&token)));

        // The server claims the link is mallory's.
        assert_eq!(srv.sql("UPDATE invites SET owner_account = ?", mallory.account_id()), 1);
        let e = dave.join_invite_link(&link).unwrap_err();
        assert!(e.to_string().contains("another owner"), "{e}");
        assert!(dave.client.app_data_keys("linkjoin/").unwrap().is_empty(), "no consent recorded");
        srv.sql("UPDATE invites SET owner_account = ?", alice.account_id());
        srv.sql("DELETE FROM invite_requests WHERE account_id = ?", dave.account_id());

        // The honest path: the nonce is sealed on the server.
        assert_eq!(dave.join_invite_link(&link).unwrap(), alice.account_id());
        let keys = dave.client.app_data_keys("linkjoin/").unwrap();
        assert_eq!(keys.len(), 1);
        let nonce = hex::decode(&keys[0]["linkjoin/".len()..]).unwrap();
        let stored = srv.blobs("SELECT nonce FROM invite_requests WHERE nonce IS NOT NULL");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].len(), tree_core::invite::SEALED_NONCE_LEN);
        assert!(!stored[0].windows(16).any(|w| w == nonce.as_slice()), "the server never has the nonce in the clear");
        alice.sync(0).unwrap();
        let ev = dave.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Joined { .. })), "{ev:?}");
        assert!(!ev.iter().any(|e| matches!(e, Event::Request { .. } | Event::Declined { .. })), "{ev:?}");
        assert_eq!(dave.group_status(&g).unwrap(), GroupStatus::Accepted);
    }

    /// F-025: a version 1 link (owner only the server's word) still works,
    /// but its group arrives in the request inbox.
    #[test]
    fn an_old_link_still_works_but_arrives_as_a_request() {
        let srv = Server::new("oldlink");
        let mut alice = srv.device("alice");
        let mut dave = srv.device("dave");
        let carol = srv.device("carol");
        let g = alice.create_group().unwrap();
        alice.invite(&g, carol.account_id()).unwrap();
        // A link as older clients made it: the bare secret, registered by its hash.
        alice.create_invite_link(&g, 3600, 10).unwrap();
        let token = [42u8; 16];
        let h = crate::invites::token_hash(&token);
        alice.api.invite_create(&alice.creds, &h, 3600, 10).unwrap();
        alice.client.set_app_data(&format!("invite/{}", hex::encode(h)), Some(&serde_json::to_vec(&crate::invites::InviteLink { group: hex::encode(&g), expires_at: crate::messages::now() + 3600, max_uses: 10 }).unwrap())).unwrap();
        let old = format!("tree://join/{}", base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token));
        assert_eq!(dave.join_invite_link(&old).unwrap(), alice.account_id());
        alice.sync(0).unwrap();
        let ev = dave.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Request { from, .. } if from == alice.account_id())), "{ev:?}");
        assert!(matches!(dave.group_status(&g).unwrap(), GroupStatus::Request { .. }));
    }

    /// Join approval (`chat.join_approval`) keeps the invite-link rules of
    /// F-025: the admin's device keeps the opened nonce of a version 2
    /// request, and approving later puts it in the roster from the device
    /// the link names, so the joiner accepts the group; a version 1 link's
    /// group still lands in the request inbox after approval.
    #[test]
    fn join_approval_keeps_the_link_version_rules() {
        let srv = Server::new("approvallinks");
        let mut alice = srv.device("alice");
        let mut dave = srv.device("dave");
        let mut erin = srv.device("erin");
        let carol = srv.device("carol");
        let g = alice.create_group().unwrap();
        alice.invite(&g, carol.account_id()).unwrap();
        let link = alice.create_invite_link(&g, 3600, 10).unwrap();
        alice.set_chat_feature(&g, "chat.join_approval", true, None).unwrap();
        // Version 2: held, then approved; the joiner accepts it.
        dave.join_invite_link(&link).unwrap();
        let sent = dave.client.app_data_keys("linkjoin/").unwrap()[0]["linkjoin/".len()..].to_string();
        let ev = alice.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::JoinRequest { .. })), "{ev:?}");
        let req = alice.join_requests(&g).unwrap().into_iter().find(|r| r.account == dave.account_id()).unwrap();
        assert_eq!(req.nonce.as_deref(), Some(sent.as_str()), "the opened nonce, not the sealed bytes");
        assert!(matches!(alice.approve_join(&g, dave.account_id()).unwrap(), crate::CommitOutcome::Accepted { .. }));
        dave.sync(0).unwrap();
        assert_eq!(dave.group_status(&g).unwrap(), GroupStatus::Accepted);
        // Version 1: held, approved, and still a request on the joiner's side.
        let token = [7u8; 16];
        let h = crate::invites::token_hash(&token);
        alice.api.invite_create(&alice.creds, &h, 3600, 10).unwrap();
        alice.client.set_app_data(&format!("invite/{}", hex::encode(h)), Some(&serde_json::to_vec(&crate::invites::InviteLink { group: hex::encode(&g), expires_at: crate::messages::now() + 3600, max_uses: 10 }).unwrap())).unwrap();
        let old = format!("tree://join/{}", base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token));
        erin.join_invite_link(&old).unwrap();
        alice.sync(0).unwrap();
        assert!(alice.join_requests(&g).unwrap().iter().any(|r| r.account == erin.account_id()));
        assert!(matches!(alice.approve_join(&g, erin.account_id()).unwrap(), crate::CommitOutcome::Accepted { .. }));
        let ev = erin.sync(0).unwrap();
        assert!(ev.iter().any(|e| matches!(e, Event::Request { .. })), "{ev:?}");
        assert!(matches!(erin.group_status(&g).unwrap(), GroupStatus::Request { .. }));
    }

    /// F-035: a stranger who floods this device with messages for groups it
    /// is not in cannot push out a genuine held message (one waiting for
    /// its welcome): at most 32 per group id, and when everything is full
    /// the new message is dropped, not an older one.
    #[test]
    fn a_flood_of_unreadable_messages_keeps_the_genuine_held_one() {
        let srv = Server::new("heldflood");
        let mut alice = srv.device("alice");
        let mut bob = srv.device("bob");
        let mut mallory = srv.device("mallory");
        let ga = alice.create_group().unwrap();
        let genuine = alice.with(&ga, |g, c| g.send(c, b"for bob, before his welcome")).unwrap();
        let mut events = Vec::new();
        bob.hold(&genuine, &mut events, true, "unknown group").unwrap();
        let held = |s: &Session| -> Vec<Vec<u8>> {
            s.client.app_data_keys("held/").unwrap().iter().filter_map(|k| s.client.app_data(k).unwrap()).collect()
        };
        // One group id, many messages: only 32 are kept.
        let gm = mallory.create_group().unwrap();
        for i in 0..100u32 {
            let b = mallory.with(&gm, |g, c| g.send(c, &i.to_be_bytes())).unwrap();
            bob.hold(&b, &mut events, true, "unknown group").unwrap();
        }
        assert_eq!(held(&bob).len(), 1 + crate::MAX_HELD_PER_GROUP);
        // Many group ids: the store fills up, then new ones are dropped.
        for _ in 0..((crate::MAX_HELD / crate::MAX_HELD_PER_GROUP) + 2) {
            let g = mallory.create_group().unwrap();
            for i in 0..crate::MAX_HELD_PER_GROUP as u32 {
                let b = mallory.with(&g, |g, c| g.send(c, &i.to_be_bytes())).unwrap();
                bob.hold(&b, &mut events, true, "unknown group").unwrap();
            }
        }
        assert_eq!(held(&bob).len(), crate::MAX_HELD);
        assert!(held(&bob).contains(&genuine), "the genuine message is still held");
        assert!(events.iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains("no room"))));
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
        let crate::invites::ParsedLink::V2 { token, .. } = crate::invites::parse_link(&link).unwrap() else { panic!("version 2") };
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
