//! The user's own apply/release settings (design: every feature has apply
//! and release). User-scope features live on the device; the registry in
//! `tree-core` decides what is allowed (permanent locks, server locks).

use serde::{Deserialize, Serialize};
use tree_core::features::{Caller, Plan, Registry, Scope, State, Status};

use crate::{Error, Session};

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
impl Session {
    /// The registry with this device's stored user settings applied.
    fn registry(&self) -> Result<Registry, Error> {
        let mut r = Registry::standard();
        for k in self.client.app_data_keys("feature/")? {
            let Some(v) = self.client.app_data(&k)? else { continue };
            let Ok(s) = serde_json::from_slice::<Stored>(&v) else { continue };
            let name = &k["feature/".len()..];
            // A setting that is no longer allowed (e.g. a new lock) is ignored.
            let _ = if s.applied { r.apply(name, s.option, ME) } else { r.release(name, ME) };
        }
        Ok(r)
    }

    /// All user-scope features with their current state, for a settings screen.
    pub fn features(&self) -> Result<Vec<Status>, Error> {
        Ok(self.registry()?.list(Scope::User))
    }

    pub fn feature(&self, k: &str) -> Result<Status, Error> {
        self.registry()?.status(k).map_err(|e| Error::Feature(e.code().into()))
    }

    /// Applies a user setting (idempotent); returns the new status.
    /// `user.recovery_phrase` is applied by [`Session::new_recovery_phrase`],
    /// which shows the words.
    pub fn apply_feature(&self, k: &str, option: Option<String>) -> Result<Status, Error> {
        if k == RECOVERY {
            return Err(Error::Usage("make a recovery phrase with new_recovery_phrase".into()));
        }
        self.change(k, true, option)
    }

    /// Releases a user setting (idempotent); returns the new status.
    /// Releasing `user.recovery_phrase` drops the recovery key on the server.
    pub fn release_feature(&self, k: &str) -> Result<Status, Error> {
        if k == RECOVERY {
            self.api.recovery_release(&self.creds, None)?;
        }
        self.change(k, false, None)
    }

    pub(crate) fn change(&self, k: &str, applied: bool, option: Option<String>) -> Result<Status, Error> {
        let mut r = self.registry()?;
        let s = if applied { r.apply(k, option, ME) } else { r.release(k, ME) }
            .map_err(|e| Error::Feature(e.code().into()))?;
        // Only user-scope settings are kept on the device.
        if r.list(Scope::User).iter().any(|x| x.key == s.key) {
            let v = serde_json::to_vec(&Stored { applied, option: s.option.clone() }).expect("JSON");
            self.client.set_app_data(&key(k), Some(&v))?;
        }
        Ok(s)
    }

    /// True if the user feature is applied.
    pub(crate) fn is_applied(&self, k: &str) -> Result<bool, Error> {
        Ok(self.feature(k)?.state == State::Applied)
    }
}
