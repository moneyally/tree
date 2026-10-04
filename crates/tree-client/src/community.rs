//! Communities (APP_PROTOCOL.md 9.7): several chats under one roof.
//!
//! A community is an ordinary Tree group, the community root, whose group
//! settings carry `community.chats` (group id and name of each chat). Its
//! members are the community's members and its admins the community's
//! admins; both are agreed by MLS like any group. Nothing new reaches the
//! server: the root is a group like any other.
//!
//! * An admin creates a community (a new root group with a name) and adds
//!   or removes chats it is a member of; each chat keeps its own members
//!   and admins.
//! * A member of the community sees the list and asks to join a chat with
//!   a `join_chat` message in the root, naming its account. Each admin
//!   device of the root that is in that chat and may add members there
//!   adds it, but only if the requesting device (the MLS-authenticated
//!   sender) is vouched for the named account on the admin's device
//!   ([`crate::Contact::vouches_for`], F-021/F-022): one of the admin's own
//!   devices for the admin's own account, otherwise a device pinned for
//!   that contact. A roster label is never enough. The admin claims the
//!   account's key packages for the add, and that claim pins the devices
//!   the server names exactly as `confirm_contact` does; a requester the
//!   server does not name, or one the contact's pins do not include, is
//!   refused. So nobody can get another account added. A blocked account
//!   or device is refused before anything is claimed. Several such admins race for the same epoch; the server keeps
//!   one commit and the others find the member already there.
//! * The joining device accepts the chat at once (it asked for it).
//!
//! Limits: at most 50 chats per community (group settings, 16 KiB), names
//! up to 64 characters; a chat is joined through an admin device that is
//! in it, so a chat none of the community's admins is in cannot be joined
//! this way.

use std::collections::BTreeMap;

use tree_core::group_settings::{Community, CommunityChat, MAX_COMMUNITY_CHATS};
use tree_core::MemberId;

use crate::groups::changed_meanwhile;
use crate::messages::now;
use crate::payload::Payload;
use crate::{CommitOutcome, Error, Event, GroupStatus, Session};

/// One chat of a community as the apps list it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityChatInfo {
    pub id: Vec<u8>,
    pub name: String,
    /// This device is a member of the chat.
    pub joined: bool,
}

/// A join request an admin device carries out after the mailbox pass.
#[derive(serde::Serialize, serde::Deserialize)]
struct JoinAsk {
    root: String,
    chat: String,
    member: String,
    account: String,
}

/// A join request this device sent, by chat (hex) -> when.
fn asked_key(chat: &str) -> String {
    format!("commjoin/{chat}")
}

impl Session {
    /// Creates a community: a new root group named `name`, this device its
    /// first admin. Members are invited to it like to any group.
    pub fn create_community(&mut self, name: &str) -> Result<Vec<u8>, Error> {
        let gid = self.create_group()?;
        let mut s = self.group_settings(&gid)?;
        s.name = Some(name.to_string());
        s.community = Some(Community::default());
        match self.change_group_settings(&gid, &s)? {
            CommitOutcome::Accepted { .. } => Ok(gid),
            CommitOutcome::Lost => Err(changed_meanwhile()),
        }
    }

    /// Whether `gid` is a community root.
    pub fn is_community(&mut self, gid: &[u8]) -> Result<bool, Error> {
        // The account's self group (settings sync) is never a community,
        // whatever its settings say.
        if self.is_self_group(gid)? {
            return Ok(false);
        }
        Ok(self.group_settings(gid)?.community.is_some())
    }

    /// The community roots this device is in.
    pub fn communities(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let mut out = Vec::new();
        for g in self.group_ids()? {
            if self.group(&g)?.is_member() && self.is_community(&g)? {
                out.push(g);
            }
        }
        Ok(out)
    }

    /// The chats of a community.
    pub fn community_chats(&mut self, root: &[u8]) -> Result<Vec<CommunityChatInfo>, Error> {
        let c = self.group_settings(root)?.community.ok_or_else(|| Error::Usage("not a community".into()))?;
        let mine: Vec<String> = self.group_ids()?.iter().map(hex::encode).collect();
        let mut out = Vec::new();
        for ch in c.chats {
            let Ok(id) = hex::decode(&ch.id) else { continue };
            let joined = mine.contains(&ch.id) && self.group(&id)?.is_member();
            out.push(CommunityChatInfo { id, name: ch.name, joined });
        }
        Ok(out)
    }

    /// An admin of the community adds one of its chats (this device must be
    /// in the chat). The chat's name is its group name.
    pub fn add_community_chat(&mut self, root: &[u8], chat: &[u8]) -> Result<(), Error> {
        let me = self.member_id();
        let mut s = self.group_settings(root)?;
        if !s.is_admin(&me) {
            return Err(Error::Feature("NOT_ADMIN".into()));
        }
        if root == chat || !self.group(chat)?.is_member() {
            return Err(Error::Usage("only a chat this device is in can be added".into()));
        }
        let name: String = self.group_settings(chat)?.name.unwrap_or_default().chars().take(64).collect();
        let c = s.community.as_mut().ok_or_else(|| Error::Usage("not a community".into()))?;
        let id = hex::encode(chat);
        if c.chats.iter().any(|x| x.id == id) {
            return Ok(());
        }
        if c.chats.len() >= MAX_COMMUNITY_CHATS {
            return Err(Error::Usage(format!("at most {MAX_COMMUNITY_CHATS} chats in a community")));
        }
        c.chats.push(CommunityChat { id, name });
        match self.change_group_settings(root, &s)? {
            CommitOutcome::Accepted { .. } => Ok(()),
            CommitOutcome::Lost => Err(changed_meanwhile()),
        }
    }

    /// An admin of the community takes a chat off its list (the chat itself
    /// and its members stay as they are).
    pub fn remove_community_chat(&mut self, root: &[u8], chat: &[u8]) -> Result<(), Error> {
        let me = self.member_id();
        let mut s = self.group_settings(root)?;
        if !s.is_admin(&me) {
            return Err(Error::Feature("NOT_ADMIN".into()));
        }
        let c = s.community.as_mut().ok_or_else(|| Error::Usage("not a community".into()))?;
        let id = hex::encode(chat);
        let before = c.chats.len();
        c.chats.retain(|x| x.id != id);
        if c.chats.len() == before {
            return Ok(());
        }
        match self.change_group_settings(root, &s)? {
            CommitOutcome::Accepted { .. } => Ok(()),
            CommitOutcome::Lost => Err(changed_meanwhile()),
        }
    }

    /// A member asks the community's admins to add it to one of its chats.
    /// The chat arrives with a later sync, already accepted.
    pub fn join_community_chat(&mut self, root: &[u8], chat: &[u8]) -> Result<(), Error> {
        let id = hex::encode(chat);
        let listed = self.group_settings(root)?.community.is_some_and(|c| c.chats.iter().any(|x| x.id == id));
        if !listed {
            return Err(Error::Usage("not a chat of this community".into()));
        }
        if self.group_ids()?.iter().any(|g| g == chat) && self.group(chat)?.is_member() {
            return Ok(());
        }
        let account = self.account_id().to_string();
        self.set_time(&asked_key(&id), now())?;
        self.send_payload(root, &Payload::JoinChat { chat: id, account })?;
        Ok(())
    }

    /// Just joined `gid`: if this device asked for it through a community
    /// (in the last week), it is accepted.
    pub(crate) fn community_join_answered(&mut self, gid: &[u8]) -> Result<bool, Error> {
        let k = asked_key(&hex::encode(gid));
        let Some(at) = self.time_of(&k)? else { return Ok(false) };
        self.client.set_app_data(&k, None)?;
        Ok(now() - at <= 7 * 86400)
    }

    /// A `join_chat` from `from` in community root `root`.
    pub(crate) fn on_join_chat(&mut self, root: &[u8], from: MemberId, chat: String, account: String, events: &mut Vec<Event>) -> Result<(), Error> {
        let me = self.member_id();
        let drop = |events: &mut Vec<Event>, why: &str| events.push(Event::Dropped { reason: format!("community join: {why}") });
        let s = self.group_settings(root)?;
        let Some(c) = s.community.as_ref().filter(|_| !self.is_self_group(root).unwrap_or(true)) else {
            drop(events, "not a community");
            return Ok(());
        };
        if !c.chats.iter().any(|x| x.id == chat) {
            drop(events, "not a chat of this community");
            return Ok(());
        }
        // Only admin devices of the community act; the others ignore it.
        if !s.is_admin(&me) || from == me {
            return Ok(());
        }
        let Ok(gid) = hex::decode(&chat) else { return Ok(()) };
        if !self.group_ids()?.contains(&gid) || !self.group(&gid)?.is_member() {
            return Ok(());
        }
        if self.group(&gid)?.members().contains(&from) {
            return Ok(()); // already in
        }
        if !self.may_add(&gid)? || self.group(&gid)?.pending_commit().is_some() {
            return Ok(());
        }
        if account.is_empty()
            || account.len() > 64
            || !account.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || self.is_blocked(&account)?
            || self.blocked_sender(root, &from)?
        {
            drop(events, "bad or blocked account");
            return Ok(());
        }
        // Carried out after the mailbox pass (`handle_community_requests`):
        // a commit and its network calls never run inside the receive
        // transaction.
        let r = JoinAsk { root: hex::encode(root), chat, member: from.to_hex(), account };
        self.app_put(&format!("commreq/{}/{}", r.root, from.to_hex()), Some(&r))
    }

    /// Carries out the join requests `on_join_chat` accepted (called by
    /// `sync` after the mailbox pass), checking everything again.
    pub(crate) fn handle_community_requests(&mut self, events: &mut Vec<Event>) -> Result<(), Error> {
        for k in self.client.app_data_keys("commreq/")? {
            let r: Option<JoinAsk> = self.app_get(&k)?;
            self.client.set_app_data(&k, None)?;
            let Some(r) = r else { continue };
            let (Ok(root), Ok(gid), Some(from)) = (hex::decode(&r.root), hex::decode(&r.chat), MemberId::from_hex(&r.member)) else { continue };
            let me = self.member_id();
            let still = self.group_ids()?.contains(&root)
                && self.group_ids()?.contains(&gid)
                && self.group(&root)?.members().contains(&from)
                && self.group_settings(&root)?.is_admin(&me)
                && self.group(&gid)?.is_member()
                && !self.group(&gid)?.members().contains(&from)
                && self.group(&gid)?.pending_commit().is_none()
                && self.may_add(&gid)?;
            if !still {
                continue;
            }
            if self.is_self_group(&root)? || self.is_blocked(&r.account)? || self.blocked_sender(&root, &from)? {
                continue;
            }
            match self.add_requester(&gid, &r.account, &from) {
                Ok(Some(CommitOutcome::Accepted { .. })) => {
                    events.push(Event::CommunityMemberAdded { community: root, group: gid, member: from });
                }
                Ok(Some(CommitOutcome::Lost)) => {} // another admin's commit won
                Ok(None) => events.push(Event::Dropped { reason: "community join: the requesting device is not vouched for the account it names".into() }),
                Err(e) => events.push(Event::Dropped { reason: format!("community join: {e}") }),
            }
        }
        Ok(())
    }

    /// Is `requester` vouched for `account` on this device: one of this
    /// account's own devices (confirmed device link) for the own account,
    /// otherwise a device pinned for the contact (`vouches_for`). A label
    /// from a roster is never enough (F-021, F-022).
    pub(crate) fn vouched_for(&self, account: &str, requester: &MemberId) -> Result<bool, Error> {
        if account == self.account_id() {
            return self.is_own_device(requester);
        }
        Ok(self.contact(account)?.is_some_and(|c| c.vouches_for(&requester.to_hex())))
    }

    /// Adds every device of `account` to `gid` if the requesting device is
    /// vouched for the account (`None` otherwise: nothing is added).
    ///
    /// The add needs the account's key packages; claiming them pins the
    /// devices the server names, exactly as [`Session::confirm_contact`]
    /// does (a new device of a known contact is a key change, reported).
    /// The requester must then be vouched for: named by the server, or
    /// already pinned; a device only a roster labelled is not. For a
    /// verified contact whose pins leave the requester out, nothing is
    /// claimed.
    fn add_requester(&mut self, gid: &[u8], account: &str, requester: &MemberId) -> Result<Option<CommitOutcome>, Error> {
        let own = account == self.account_id();
        if own && !self.is_own_device(requester)? {
            return Ok(None);
        }
        if !own {
            // The user compared the safety number for exactly the pinned
            // devices of a verified contact: another device is refused
            // without asking the server. Otherwise the claim below decides.
            if self.contact(account)?.is_some_and(|c| c.verified && !c.vouches_for(&requester.to_hex())) {
                return Ok(None);
            }
        }
        let claimed = self.api.claim(&self.creds, account)?;
        let mut ids = Vec::new();
        for (_, kp) in &claimed {
            ids.push(self.client.check_key_package(kp)?.0);
        }
        if !ids.contains(requester) {
            return Ok(None);
        }
        let mut events = Vec::new();
        self.pin(account, &ids, true, &mut events)?;
        if !self.vouched_for(account, requester)? {
            return Ok(None);
        }
        let added: Vec<(String, String)> = claimed.iter().zip(&ids).map(|((d, _), id)| (id.to_hex(), d.clone())).collect();
        let mut accounts: BTreeMap<String, String> = self.map(&crate::accounts_key(gid))?;
        for i in &ids {
            accounts.insert(i.to_hex(), account.to_string());
        }
        self.save_map(&crate::accounts_key(gid), &accounts)?;
        let kps: Vec<&[u8]> = claimed.iter().map(|(_, kp)| kp.as_slice()).collect();
        self.with(gid, |g, c| g.add(c, &kps))?;
        self.save_pending(gid, &crate::PendingExtra { added, removed_devices: vec![], link: None })?;
        Ok(Some(self.submit(gid)?))
    }

    /// Sets a joined chat to accepted when the user asked for it through a
    /// community.
    pub(crate) fn accept_if_asked(&mut self, gid: &[u8]) -> Result<(), Error> {
        if self.community_join_answered(gid)? {
            self.set_group_status(gid, &GroupStatus::Accepted)?;
        }
        Ok(())
    }
}
