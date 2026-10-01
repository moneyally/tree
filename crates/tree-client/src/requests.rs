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
        self.send_payload(gid, &Payload::Leave)?;
        self.set_group_status(gid, &GroupStatus::Declined)
    }

    /// Decides a group that is still a request once its adder is known.
    pub(crate) fn decide_request(&mut self, gid: &[u8], adder: &str, events: &mut Vec<Event>) -> Result<(), Error> {
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
        // The user opened this account's invite link: they asked to join.
        if self.take_link_join(adder)? {
            return self.set_group_status(gid, &GroupStatus::Accepted);
        }
        let group_add = self.feature("user.group_add")?;
        if !direct && group_add.state == tree_core::features::State::Applied && group_add.option.as_deref() == Some("nobody") {
            events.push(decline("nobody may add you to groups (user.group_add = nobody)"));
            return self.decline(gid, false);
        }
        if c.as_ref().is_some_and(|c| c.accepted) {
            return self.set_group_status(gid, &GroupStatus::Accepted);
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
