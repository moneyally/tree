//! Groups, Wave 3 (PRODUCT_PLAN.md, APP_PROTOCOL.md 9): roles with
//! permissions and member tags, restricted members, slow mode, deleting
//! others' messages, the welcome text, and the next admin when the last
//! one leaves. Topics, the admin log, history for new members, join
//! approval and communities have their own modules (`topics.rs`,
//! `admin_log.rs`, `history_share.rs`, `invites.rs`, `community.rs`).
//!
//! Roles, assignments and restrictions live in the group settings (MLS
//! group context, PROTOCOL.md 6.11.1): only admins change them, by a
//! commit every device checks. What they allow is enforced by the sending
//! device and again by every receiving device, judged by the MLS-
//! authenticated sender, never by anything a payload claims.
//!
//! | Setting | Default | Effect |
//! | --- | --- | --- |
//! | `chat.roles` | applied | roles grant their permissions (`pin`, `delete`, `add`, `topics`) and show as member tags; released: roles grant nothing and are not shown |
//! | `chat.member_adds` | applied | any member may add members; released: admins and roles with `add` only (checked by every device's core before merging) |
//! | `chat.restrict` | applied | restricted members may read but not send until their time; released: restrictions are not enforced |
//! | `chat.slow_mode` | released; option = 10 s to 1 h (default `30s`) | members who are not admins send at most one message per interval |
//! | `chat.welcome` | released; option = a text of up to 500 characters | members who join see the text once |
//! | `chat.owner_succession` | applied | the last admin's device names the next admin before it leaves |

use std::collections::{BTreeMap, BTreeSet};

use tree_core::group_settings::{perm, GroupSettings, Role, MAX_ROLES};
use tree_core::{features, MemberId};

use crate::messages::{new_id, now};
use crate::payload::Payload;
use crate::{CommitOutcome, Error, Event, Session};

/// Everything a restricted member may not send: all but what concerns
/// only itself and the group's plumbing (names, photos, rosters, leaving,
/// read receipts, typing, presence).
pub(crate) fn is_speech(p: &Payload) -> bool {
    !matches!(
        p,
        Payload::Roster { .. }
            | Payload::Profile { .. }
            | Payload::ProfilePhoto { .. }
            | Payload::Leave { .. }
            | Payload::RemoveDevice { .. }
            | Payload::Read { .. }
            | Payload::Typing { .. }
            | Payload::Seen
    )
}

/// New messages slow mode counts (not edits, reactions, votes, ...).
pub(crate) fn counts_for_slow_mode(p: &Payload) -> bool {
    matches!(
        p,
        Payload::Text { .. } | Payload::File(_) | Payload::Sticker { .. } | Payload::Poll(_) | Payload::Location(_) | Payload::ChatEvent(_)
    )
}

fn slow_sent_key(gid: &[u8]) -> String {
    format!("slow/{}", hex::encode(gid))
}

fn slow_seen_key(gid: &[u8]) -> String {
    format!("slowseen/{}", hex::encode(gid))
}

pub(crate) fn changed_meanwhile() -> Error {
    Error::Usage("the group changed meanwhile; sync and try again".into())
}

fn accepted(o: CommitOutcome) -> Result<(), Error> {
    match o {
        CommitOutcome::Accepted { .. } => Ok(()),
        CommitOutcome::Lost => Err(changed_meanwhile()),
    }
}

/// Whether a server time (unix seconds, whole minutes) fits slow mode for
/// one member, given the server times of its earlier accepted messages.
/// With interval `i`, an honest sender (one message per `i` seconds by its
/// own clock) sends at most `ceil(60 / i)` messages in one server minute,
/// and two of its messages are at least `i - 60` seconds apart in server
/// minutes. Receivers allow exactly that, so honest messages pass and a
/// modified client gets at most about twice the rate.
pub(crate) fn slow_ok(earlier: &[i64], at: i64, i: i64) -> bool {
    let k = ((60 + i - 1) / i).max(1) as usize;
    let same = earlier.iter().filter(|t| **t == at).count();
    let last = earlier.iter().copied().max();
    same < k && last.is_none_or(|l| at - l >= i - 60)
}

impl Session {
    // --- permissions ---

    /// May this device do what permission `p` (`pin`, `delete`, `add`,
    /// `topics`) covers in the group: an admin, or a role that grants it
    /// while `chat.roles` is applied.
    pub fn may(&mut self, gid: &[u8], p: &str) -> Result<bool, Error> {
        let me = self.member_id();
        Ok(self.group_settings(gid)?.may(&me, p))
    }

    pub(crate) fn member_may(&mut self, gid: &[u8], who: &MemberId, p: &str) -> Result<bool, Error> {
        Ok(self.group_settings(gid)?.may(who, p))
    }

    /// May this device add members to the group (`chat.member_adds`)?
    pub fn may_add(&mut self, gid: &[u8]) -> Result<bool, Error> {
        let me = self.member_id();
        Ok(self.group_settings(gid)?.may_add(&me))
    }

    fn require_admin(&mut self, gid: &[u8]) -> Result<GroupSettings, Error> {
        let me = self.member_id();
        let s = self.group_settings(gid)?;
        if !s.is_admin(&me) {
            return Err(Error::Feature("NOT_ADMIN".into()));
        }
        Ok(s)
    }

    // --- roles and member tags (`chat.roles`) ---

    /// The group's roles (id, role), whether or not `chat.roles` is applied.
    pub fn roles(&mut self, gid: &[u8]) -> Result<Vec<(String, Role)>, Error> {
        Ok(self.group_settings(gid)?.roles.into_iter().collect())
    }

    /// The roles (member tags) a member holds; none while `chat.roles` is
    /// released.
    pub fn member_roles(&mut self, gid: &[u8], member: &MemberId) -> Result<Vec<(String, Role)>, Error> {
        Ok(self.group_settings(gid)?.roles_of(member))
    }

    fn roles_on(&mut self, gid: &[u8]) -> Result<GroupSettings, Error> {
        let s = self.require_admin(gid)?;
        if !s.feature_on("chat.roles") {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        Ok(s)
    }

    fn role_value(name: &str, color: &str, perms: &[String]) -> Result<Role, Error> {
        let perms: BTreeSet<String> = perms.iter().cloned().collect();
        let r = Role { name: name.trim().to_string(), color: color.to_ascii_lowercase(), perms };
        let probe = GroupSettings { roles: [("x".to_string(), r.clone())].into(), ..Default::default() };
        probe.check_wave3()?;
        Ok(r)
    }

    /// An admin creates a role (name, `#rrggbb` colour, permissions from
    /// `pin`, `delete`, `add`, `topics`). Returns its id.
    pub fn create_role(&mut self, gid: &[u8], name: &str, color: &str, perms: &[String]) -> Result<String, Error> {
        let mut s = self.roles_on(gid)?;
        if s.roles.len() >= MAX_ROLES {
            return Err(Error::Usage(format!("at most {MAX_ROLES} roles")));
        }
        let role = Self::role_value(name, color, perms)?;
        let id = new_id()[..12].to_string();
        s.roles.insert(id.clone(), role);
        accepted(self.change_group_settings(gid, &s)?)?;
        Ok(id)
    }

    /// An admin changes a role's name, colour or permissions.
    pub fn update_role(&mut self, gid: &[u8], id: &str, name: &str, color: &str, perms: &[String]) -> Result<(), Error> {
        let mut s = self.roles_on(gid)?;
        if !s.roles.contains_key(id) {
            return Err(Error::Usage("no such role".into()));
        }
        s.roles.insert(id.to_string(), Self::role_value(name, color, perms)?);
        accepted(self.change_group_settings(gid, &s)?)
    }

    /// An admin deletes a role; every member loses it.
    pub fn delete_role(&mut self, gid: &[u8], id: &str) -> Result<(), Error> {
        let mut s = self.require_admin(gid)?;
        if s.roles.remove(id).is_none() {
            return Err(Error::Usage("no such role".into()));
        }
        for held in s.member_roles.values_mut() {
            held.remove(id);
        }
        s.member_roles.retain(|_, h| !h.is_empty());
        accepted(self.change_group_settings(gid, &s)?)
    }

    /// An admin gives a member a role (`on`) or takes it away.
    pub fn assign_role(&mut self, gid: &[u8], member: &MemberId, id: &str, on: bool) -> Result<(), Error> {
        let mut s = self.roles_on(gid)?;
        if !s.roles.contains_key(id) {
            return Err(Error::Usage("no such role".into()));
        }
        if !self.group(gid)?.members().contains(member) {
            return Err(Error::Usage("not a member".into()));
        }
        let held = s.member_roles.entry(*member).or_default();
        if on {
            held.insert(id.to_string());
        } else {
            held.remove(id);
        }
        s.member_roles.retain(|_, h| !h.is_empty());
        accepted(self.change_group_settings(gid, &s)?)
    }

    // --- restricted members (`chat.restrict`) ---

    /// An admin restricts a member until `until` (unix seconds): it may
    /// read but not send. `None` lifts the restriction. Admins cannot be
    /// restricted.
    pub fn restrict_member(&mut self, gid: &[u8], member: &MemberId, until: Option<i64>) -> Result<(), Error> {
        let mut s = self.require_admin(gid)?;
        match until {
            Some(t) => {
                if !s.feature_on("chat.restrict") {
                    return Err(Error::Feature("LOCKED_BY_CHAT".into()));
                }
                if t <= now() {
                    return Err(Error::Usage("a restriction ends in the future".into()));
                }
                if s.is_admin(member) {
                    return Err(Error::Usage("an admin cannot be restricted".into()));
                }
                if !self.group(gid)?.members().contains(member) {
                    return Err(Error::Usage("not a member".into()));
                }
                s.restricted.insert(*member, t);
            }
            None => {
                if s.restricted.remove(member).is_none() {
                    return Ok(());
                }
            }
        }
        // Restrictions that ran out are dropped while we are at it.
        let t = now();
        s.restricted.retain(|_, u| *u > t);
        accepted(self.change_group_settings(gid, &s)?)
    }

    /// Restricted members and until when (only those still restricted
    /// while `chat.restrict` is applied).
    pub fn restricted_members(&mut self, gid: &[u8]) -> Result<Vec<(MemberId, i64)>, Error> {
        let s = self.group_settings(gid)?;
        let t = now();
        Ok(s.restricted.keys().filter_map(|m| s.restricted_until(m, t).map(|u| (*m, u))).collect())
    }

    /// Until when this device may not send in the group, if restricted.
    pub fn restricted_until(&mut self, gid: &[u8]) -> Result<Option<i64>, Error> {
        let me = self.member_id();
        Ok(self.group_settings(gid)?.restricted_until(&me, now()))
    }

    // --- slow mode (`chat.slow_mode`) ---

    /// The slow-mode interval in seconds, if applied.
    pub fn slow_mode(&mut self, gid: &[u8]) -> Result<Option<i64>, Error> {
        let (on, opt) = self.chat_feature(gid, "chat.slow_mode")?;
        Ok(if on { features::option_seconds("chat.slow_mode", opt.as_deref()) } else { None })
    }

    /// Seconds this device must still wait before its next message under
    /// slow mode (`None`: it may send now; admins never wait).
    pub fn slow_mode_wait(&mut self, gid: &[u8]) -> Result<Option<i64>, Error> {
        let Some(i) = self.slow_mode(gid)? else { return Ok(None) };
        let me = self.member_id();
        if self.group(gid)?.is_admin(&me) {
            return Ok(None);
        }
        let last = self.time_of(&slow_sent_key(gid))?;
        Ok(last.map(|l| l + i - now()).filter(|w| *w > 0))
    }

    /// The sending side's checks for a payload going into the outbox:
    /// restricted members send nothing but plumbing, slow mode spaces new
    /// messages. Returns whether the send counts for slow mode.
    pub(crate) fn check_sendable(&mut self, gid: &[u8], p: &Payload) -> Result<bool, Error> {
        // Settings sync between own devices is never held back by group
        // roles, restrictions or slow mode.
        if !is_speech(p) || self.is_self_group(gid)? {
            return Ok(false);
        }
        if self.restricted_until(gid)?.is_some() {
            return Err(Error::Feature("RESTRICTED".into()));
        }
        if !counts_for_slow_mode(p) {
            return Ok(false);
        }
        if self.slow_mode_wait(gid)?.is_some() {
            return Err(Error::Feature("SLOW_MODE".into()));
        }
        Ok(true)
    }

    pub(crate) fn note_slow_send(&self, gid: &[u8]) -> Result<(), Error> {
        self.set_time(&slow_sent_key(gid), now())
    }

    /// The receiving side's gate, before a payload from `from` is used:
    /// restricted members and messages that break slow mode are dropped
    /// (admins get [`Event::SlowModeHidden`]). True: go on.
    pub(crate) fn gate(&mut self, gid: &[u8], from: &MemberId, p: &Payload, events: &mut Vec<Event>) -> Result<bool, Error> {
        if !is_speech(p) {
            return Ok(true);
        }
        let s = self.group_settings(gid)?;
        if s.restricted_until(from, now()).is_some() {
            events.push(Event::Dropped { reason: "from a restricted member (chat.restrict)".into() });
            return Ok(false);
        }
        if !counts_for_slow_mode(p) || s.is_admin(from) {
            return Ok(true);
        }
        let Some(i) = self.slow_mode(gid)? else { return Ok(true) };
        // The server's arrival time (whole minutes), which every receiver
        // sees the same; this device's own clock for a retried message.
        let at = self.server_time.unwrap_or_else(now) / 60 * 60;
        let mut seen: BTreeMap<String, Vec<i64>> = self.app_get(&slow_seen_key(gid))?.unwrap_or_default();
        let earlier = seen.entry(from.to_hex()).or_default();
        if !slow_ok(earlier, at, i) {
            events.push(Event::Dropped { reason: "sent faster than slow mode allows (chat.slow_mode)".into() });
            let me = self.member_id();
            if s.is_admin(&me) {
                events.push(Event::SlowModeHidden { group: gid.to_vec(), member: *from });
            }
            return Ok(false);
        }
        earlier.push(at);
        earlier.sort_unstable();
        let keep = earlier.len().saturating_sub(8);
        earlier.drain(..keep);
        self.app_put(&slow_seen_key(gid), Some(&seen))?;
        Ok(true)
    }

    // --- deleting others' messages (`delete` permission) ---

    /// An admin, or a member whose role may `delete`, deletes another
    /// member's message for everyone (any age; `chat.delete_for_all` is
    /// about one's own messages).
    pub fn delete_as_moderator(&mut self, gid: &[u8], id: &str) -> Result<(), Error> {
        if !self.may(gid, perm::DELETE)? {
            return Err(Error::Feature("NOT_ADMIN".into()));
        }
        let m = self.client.message(gid, id)?.filter(|m| !m.deleted).ok_or_else(|| Error::Usage("no such message".into()))?;
        let me = self.member_id();
        let author = m.sender.clone();
        self.queue_payload(gid, &Payload::Delete { id: id.into() }, None, |s| Ok(s.client.delete_message(gid, id)?))?;
        if author != me.to_hex() {
            self.log_admin(gid, &me, "delete", Some(author), Some(id.to_string()))?;
        }
        Ok(())
    }

    // --- welcome text (`chat.welcome`) ---

    /// The welcome text new members see, while `chat.welcome` is applied.
    pub fn welcome_text(&mut self, gid: &[u8]) -> Result<Option<String>, Error> {
        let (on, opt) = self.chat_feature(gid, "chat.welcome")?;
        Ok(opt.filter(|_| on))
    }

    /// Just joined: the welcome text, if any, becomes a line in this
    /// device's history and an [`Event::Welcome`]. It is read from the
    /// group settings the welcome carried (authenticated by MLS), so it is
    /// the admins' text, not the adder's.
    pub(crate) fn on_joined(&mut self, gid: &[u8], events: &mut Vec<Event>) -> Result<(), Error> {
        if let Some(text) = self.welcome_text(gid)? {
            let me = self.member_id();
            self.store(gid, &new_id(), &me, "welcome", Some(text.clone()), None, None)?;
            events.push(Event::Welcome { group: gid.to_vec(), text });
        }
        Ok(())
    }

    // --- the next admin (`chat.owner_succession`) ---

    /// Before this device leaves: if it is the group's only admin and
    /// `chat.owner_succession` is applied, it first makes the next admin
    /// ([`tree_core::Group::successor`]: the member in the lowest leaf who
    /// is not restricted), so the group keeps an admin who then removes
    /// this device. Returns the new admin, if one was named.
    pub(crate) fn hand_over(&mut self, gid: &[u8]) -> Result<Option<MemberId>, Error> {
        let me = self.member_id();
        let s = self.group_settings(gid)?;
        if s.admins != [me] || !s.feature_on("chat.owner_succession") {
            return Ok(None);
        }
        let Some(next) = self.group(gid)?.successor(&[me], now()) else { return Ok(None) };
        let mut n = s;
        n.admins.push(next);
        accepted(self.change_group_settings(gid, &n)?)?;
        Ok(Some(next))
    }

    /// Who would become admin if this device's user left now (for the
    /// app's "leave" confirmation), if succession applies.
    pub fn successor(&mut self, gid: &[u8]) -> Result<Option<MemberId>, Error> {
        let me = self.member_id();
        let s = self.group_settings(gid)?;
        if s.admins != [me] || !s.feature_on("chat.owner_succession") {
            return Ok(None);
        }
        Ok(self.group(gid)?.successor(&[me], now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_mode_rule() {
        // 30 s: two per server minute, honest spacing always passes.
        assert!(slow_ok(&[], 0, 30));
        assert!(slow_ok(&[0], 0, 30));
        assert!(!slow_ok(&[0, 0], 0, 30));
        assert!(slow_ok(&[0, 0], 60, 30));
        // 10 s: six per minute.
        assert!(slow_ok(&[0; 5], 0, 10) && !slow_ok(&[0; 6], 0, 10));
        // 5 min: server minutes at least 4 min apart.
        assert!(!slow_ok(&[0], 180, 300));
        assert!(slow_ok(&[0], 240, 300));
        // 1 h: an honest pair sent 3600 s apart is >= 3540 s apart in minutes.
        for t1 in [0i64, 30, 59] {
            let (m1, m2) = (t1 / 60 * 60, (t1 + 3600) / 60 * 60);
            assert!(slow_ok(&[m1], m2, 3600));
        }
        assert!(!slow_ok(&[0], 3480, 3600));
        // Honest senders at exactly the interval never fail, for every choice.
        for i in [10i64, 30, 60, 300, 900, 3600] {
            for start in 0..60 {
                let mut seen: Vec<i64> = vec![];
                for n in 0..10 {
                    let at = (start + n * i) / 60 * 60;
                    assert!(slow_ok(&seen, at, i), "i={i} start={start} n={n}");
                    seen.push(at);
                }
            }
        }
    }

    #[test]
    fn speech_kinds() {
        assert!(is_speech(&Payload::Delete { id: "x".into() }));
        assert!(!is_speech(&Payload::Leave { quiet: false }));
        assert!(counts_for_slow_mode(&Payload::Text { id: "1".into(), text: "x".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: false, topic: None }));
        assert!(!counts_for_slow_mode(&Payload::Delete { id: "x".into() }));
    }
}
