//! The user's own apply/release settings (design: every feature has apply
//! and release). User-scope features live on the device; the registry in
//! `tree-core` decides what is allowed (permanent locks, server locks,
//! option formats).
//!
//! Two settings are also the server's business, so applying or releasing
//! them goes to the server first and is stored only once it agreed:
//!
//! * `user.discoverable`: the @username's registration is changed to
//!   findable / hidden (PROTOCOL.md 8.4);
//! * `user.recovery_phrase`: the recovery key (PROTOCOL.md 8.6). Its state
//!   is what the server reports: a release without the phrase stays applied
//!   (the key still recovers the account) with a pending release until the
//!   server drops the key ([`Session::release_pending`]).

use serde::{Deserialize, Serialize};
use tree_core::features::{Caller, Plan, Registry, Scope, State, Status};

use crate::messages::now;
use crate::{Error, RecoveryStatus, Session};

const ME: Caller = Caller { plan: Plan::Free, is_admin: false };

#[derive(Serialize, Deserialize)]
struct Stored {
    applied: bool,
    option: Option<String>,
}

fn key(k: &str) -> String {
    format!("feature/{k}")
}

/// The recovery phrase setting (PROTOCOL.md 8.6).
pub(crate) const RECOVERY: &str = "user.recovery_phrase";
/// Whether the @username can be found (PROTOCOL.md 8.4).
pub(crate) const DISCOVERABLE: &str = "user.discoverable";
/// When the server drops the recovery key after a release without the
/// phrase (unix seconds). Not under `feature/`.
const RECOVERY_RELEASE_AT: &str = "recovery/release_at";

impl Session {
    /// The registry with this device's stored user settings applied.
    fn registry(&self) -> Result<Registry, Error> {
        let mut r = Registry::standard();
        let release_due = self.recovery_release_at()?.is_some_and(|t| now() >= t);
        for k in self.client.app_data_keys("feature/")? {
            let Some(v) = self.client.app_data(&k)? else { continue };
            let Ok(s) = serde_json::from_slice::<Stored>(&v) else { continue };
            let name = &k["feature/".len()..];
            // The server dropped the recovery key when the release came due.
            let applied = s.applied && !(name == RECOVERY && release_due);
            // A setting that is no longer allowed (e.g. a new lock) is ignored.
            let _ = if applied { r.apply(name, s.option, ME) } else { r.release(name, ME) };
        }
        Ok(r)
    }

    fn recovery_release_at(&self) -> Result<Option<i64>, Error> {
        Ok(self.client.app_data(RECOVERY_RELEASE_AT)?.and_then(|v| String::from_utf8(v).ok()).and_then(|s| s.parse().ok()))
    }

    /// All user-scope features with their current state, for a settings screen.
    pub fn features(&self) -> Result<Vec<Status>, Error> {
        Ok(self.registry()?.list(Scope::User))
    }

    pub fn feature(&self, k: &str) -> Result<Status, Error> {
        Ok(self.registry()?.status(k)?)
    }

    /// A release that was asked for but has not taken effect yet: when it
    /// will (unix seconds). Today only `user.recovery_phrase` released
    /// without the phrase: the server keeps the key for 7 days, so the
    /// setting stays applied until then. Apps show "release pending until".
    pub fn release_pending(&self, k: &str) -> Result<Option<i64>, Error> {
        if k != RECOVERY {
            return Ok(None);
        }
        Ok(self.recovery_release_at()?.filter(|t| now() < *t))
    }

    /// Applies a user setting (idempotent); returns the new status.
    /// `user.recovery_phrase` is applied by [`Session::new_recovery_phrase`],
    /// which shows the words.
    pub fn apply_feature(&self, k: &str, option: Option<String>) -> Result<Status, Error> {
        if k == RECOVERY {
            return Err(Error::Usage("make a recovery phrase with new_recovery_phrase".into()));
        }
        self.change_with_server(k, true, option)
    }

    /// Releases a user setting (idempotent); returns the new status.
    /// Releasing `user.recovery_phrase` asks the server to drop the recovery
    /// key; without the phrase that takes 7 days, and the returned status
    /// stays applied meanwhile (see [`Session::release_pending`]).
    pub fn release_feature(&self, k: &str) -> Result<Status, Error> {
        if k == RECOVERY {
            let st = RecoveryStatus::from_json(&self.api.recovery_release(&self.creds, None)?);
            self.record_recovery(&st)?;
            return self.feature(k);
        }
        self.change_with_server(k, false, None)
    }

    /// [`Session::change`], telling the server first where it keeps a copy.
    fn change_with_server(&self, k: &str, applied: bool, option: Option<String>) -> Result<Status, Error> {
        if k == DISCOVERABLE {
            // Refused changes (locks) must not reach the server either.
            let mut r = self.registry()?;
            let _ = (if applied { r.apply(k, option.clone(), ME) } else { r.release(k, ME) })?;
            if let Some(name) = self.username()? {
                self.register_username(&name, applied)?;
            }
        }
        self.change(k, applied, option)
    }

    pub(crate) fn change(&self, k: &str, applied: bool, option: Option<String>) -> Result<Status, Error> {
        let mut r = self.registry()?;
        let s = if applied { r.apply(k, option, ME) } else { r.release(k, ME) }?;
        // Only user-scope settings are kept on the device.
        if r.list(Scope::User).iter().any(|x| x.key == s.key) {
            let v = serde_json::to_vec(&Stored { applied, option: s.option.clone() }).expect("JSON");
            self.client.set_app_data(&key(k), Some(&v))?;
        }
        Ok(s)
    }

    /// Takes the server's word on recovery: applied while a key can
    /// recover the account, with the date of a pending release if any.
    pub(crate) fn record_recovery(&self, st: &RecoveryStatus) -> Result<(), Error> {
        let release_at = match &st.pending {
            Some((action, at)) if st.active && action == "release" => Some(*at),
            _ => None,
        };
        self.client.set_app_data(RECOVERY_RELEASE_AT, release_at.map(|t| t.to_string()).as_deref().map(str::as_bytes))?;
        self.change(RECOVERY, st.active, None)?;
        Ok(())
    }

    /// True if the user feature is applied.
    pub(crate) fn is_applied(&self, k: &str) -> Result<bool, Error> {
        Ok(self.feature(k)?.state == State::Applied)
    }
}
