//! Device protections and settings sync (`tree_client::device`,
//! `tree_client::self_sync`): PIN and platform-key unlock, the search
//! index, notification decisions, settings sync. Only type conversions.

use super::*;

/// Where PIN unlock stands for a profile.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PinUnlockState {
    pub enabled: bool,
    /// Wrong PINs left before the passphrase is needed (the PIN file is
    /// then wiped).
    pub attempts_left: u32,
    /// Enabled with a hardware-kept device secret.
    pub device_secret: bool,
}

/// What a notification for a new message may show.
#[derive(Debug, Clone, uniffi::Record)]
pub struct NotificationPlan {
    pub notify: bool,
    /// Also the text (otherwise the chat's name only).
    pub show_text: bool,
}

/// The search index on this device (`user.search_index`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct SearchIndexState {
    pub exists: bool,
    pub messages: u64,
}

/// Turns PIN unlock on for the profile at `path` (needs its passphrase).
/// `device_secret`: a hardware-kept secret of the platform, or null.
#[uniffi::export]
pub fn enable_pin_unlock(path: String, passphrase: String, pin: String, device_secret: Option<Vec<u8>>) -> R<()> {
    Ok(Session::enable_pin(&path, &passphrase, &pin, device_secret.as_deref())?)
}

/// Turns PIN unlock off (the PIN file is wiped).
#[uniffi::export]
pub fn disable_pin_unlock(path: String) -> R<()> {
    Ok(Session::disable_pin(&path)?)
}

#[uniffi::export]
pub fn pin_unlock_state(path: String) -> PinUnlockState {
    let s = Session::pin_state(&path);
    PinUnlockState { enabled: s.enabled, attempts_left: s.attempts_left as u32, device_secret: s.device_secret }
}

/// The database key for the platform keystore to wrap (biometric unlock).
/// Wrap it at once and overwrite the array afterwards.
#[uniffi::export]
pub fn key_for_platform_wrap(path: String, passphrase: String) -> R<Vec<u8>> {
    Ok(Session::key_for_platform_wrap(&path, &passphrase)?.to_vec())
}

#[uniffi::export]
impl TreeSession {
    /// Opens the profile with a PIN. Each call is one counted attempt:
    /// `WrongPin` says how many are left; `PinUnavailable` means the
    /// passphrase is needed.
    #[uniffi::constructor]
    pub fn open_with_pin(path: String, pin: String, device_secret: Option<Vec<u8>>) -> R<std::sync::Arc<Self>> {
        Ok(Self::wrap(Session::open_with_pin(&path, &pin, device_secret.as_deref())?.0))
    }

    /// Opens the profile with a database key the platform unwrapped after
    /// a biometric check.
    #[uniffi::constructor]
    pub fn open_with_platform_key(path: String, key: Vec<u8>) -> R<std::sync::Arc<Self>> {
        Ok(Self::wrap(Session::open_with_platform_key(&path, &key)?.0))
    }

    /// What a notification for a new message in `group` may show.
    pub fn notification_plan(&self, group: String, silent: bool) -> R<NotificationPlan> {
        let p = self.s().notification_plan(&unhex(&group, "group")?, silent)?;
        Ok(NotificationPlan { notify: p.notify, show_text: p.show_text })
    }

    pub fn search_index_state(&self) -> R<SearchIndexState> {
        let (exists, n) = self.s().search_index_status()?;
        Ok(SearchIndexState { exists, messages: n as u64 })
    }

    /// Sends settings changed on this device to the account's other
    /// devices now (sync does it too). Returns how many.
    pub fn push_settings(&self) -> R<u32> {
        Ok(self.s().push_settings()? as u32)
    }

    /// The account's own settings group (hex), if this device has one.
    pub fn self_group(&self) -> R<Option<String>> {
        Ok(self.s().self_group()?.map(hex::encode))
    }
}
