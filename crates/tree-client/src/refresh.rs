//! Key refresh schedule (PROTOCOL.md 6.9).
//!
//! A device refreshes its own keys in a group (an UpdatePath commit: fresh
//! leaf and path secrets, the basis of post-compromise security):
//!
//! - after it joined, soon, with a random delay so that the members of a new
//!   group do not all commit at once;
//! - at least every 24 hours in which the group had traffic;
//! - in every group at once when the user suspects a compromise
//!   ([`Session::refresh_all`]).
//!
//! Commits that carry an UpdatePath for other reasons (removes, settings
//! changes) count as refreshes. A refresh that loses the race for an epoch
//! is simply tried again at the next sync.

use crate::messages::now;
use crate::{CommitOutcome, Error, Event, Session};

/// When refreshes are due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshPolicy {
    /// Seconds between refreshes in a group with traffic.
    pub interval: i64,
    /// A just-joined device refreshes after a random delay of one minute up
    /// to this long (0: at its next sync).
    pub join_delay_max: i64,
}

impl Default for RefreshPolicy {
    fn default() -> Self {
        RefreshPolicy { interval: 24 * 3600, join_delay_max: 600 }
    }
}

fn last_key(gid: &[u8]) -> String {
    format!("refresh/{}", hex::encode(gid))
}

fn traffic_key(gid: &[u8]) -> String {
    format!("traffic/{}", hex::encode(gid))
}

impl Session {
    fn time_of(&self, key: &str) -> Result<Option<i64>, Error> {
        Ok(self.client.app_data(key)?.and_then(|v| String::from_utf8(v).ok()).and_then(|s| s.parse().ok()))
    }

    fn set_time(&self, key: &str, t: i64) -> Result<(), Error> {
        Ok(self.client.set_app_data(key, Some(t.to_string().as_bytes()))?)
    }

    /// This device's own keys in `gid` were just renewed.
    pub(crate) fn note_refreshed(&self, gid: &[u8]) -> Result<(), Error> {
        self.set_time(&last_key(gid), now())
    }

    /// The group had traffic (a message sent or received).
    pub(crate) fn note_traffic(&self, gid: &[u8]) -> Result<(), Error> {
        self.set_time(&traffic_key(gid), now())
    }

    /// A joined group: due after a random delay (spreads the first
    /// refreshes of a new group's members).
    pub(crate) fn note_joined(&self, gid: &[u8]) -> Result<(), Error> {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).expect("operating system random number generator failed");
        let max = self.refresh_policy.join_delay_max.max(0);
        let delay = if max == 0 { 0 } else { 60 + (u64::from_le_bytes(r) % ((max - 60).max(0) as u64 + 1)) as i64 };
        // Recorded as if refreshed `interval - delay` ago, with traffic now.
        self.set_time(&last_key(gid), now() - self.refresh_policy.interval + delay)?;
        self.note_traffic(gid)
    }

    pub fn set_refresh_policy(&mut self, p: RefreshPolicy) {
        self.refresh_policy = p;
    }

    /// Is a refresh due in `gid`?
    pub fn refresh_due(&mut self, gid: &[u8]) -> Result<bool, Error> {
        let now = now();
        let last = self.time_of(&last_key(gid))?;
        let traffic = self.time_of(&traffic_key(gid))?;
        Ok(match (last, traffic) {
            // Joined before this schedule existed and never refreshed.
            (None, _) => self.group(gid)?.should_refresh_keys(),
            (Some(l), Some(t)) => t > l && now - l >= self.refresh_policy.interval,
            (Some(_), None) => false,
        })
    }

    /// Refreshes every group where a refresh is due (called by `sync`).
    pub(crate) fn refresh_due_groups(&mut self, events: &mut Vec<Event>) -> Result<(), Error> {
        for gid in self.group_ids()? {
            if !self.group(&gid)?.is_member() || self.group(&gid)?.pending_commit().is_some() || !self.refresh_due(&gid)? {
                continue;
            }
            match self.refresh_keys(&gid) {
                Ok(CommitOutcome::Accepted { .. }) | Ok(CommitOutcome::Lost) => {}
                // Not fatal for the sync: tried again next time.
                Err(e) => events.push(Event::Dropped { reason: format!("key refresh failed: {e}") }),
            }
        }
        Ok(())
    }

    /// Refreshes this device's keys in every group now (after a suspected
    /// compromise). Returns the groups where the refresh was accepted.
    pub fn refresh_all(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let mut done = Vec::new();
        for gid in self.group_ids()? {
            if !self.group(&gid)?.is_member() || self.group(&gid)?.pending_commit().is_some() {
                continue;
            }
            if let CommitOutcome::Accepted { .. } = self.refresh_keys(&gid)? {
                done.push(gid);
            }
        }
        Ok(done)
    }
}
