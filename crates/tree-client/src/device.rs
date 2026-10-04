//! Device-level protections (PRODUCT_PLAN.md Wave 1 items 7-9;
//! APP_PROTOCOL.md 6.3): PIN and platform-key unlock, the on-device search
//! index, and what a notification may show.
//!
//! | Setting | Default | Behaviour |
//! | --- | --- | --- |
//! | `user.app_lock` | released | apps close the profile when they go to the background; the option says how it opens again: `passphrase`, `pin` ([`Session::enable_pin`], attempt limit, `tree_core::storage::pin`) or `bio` (a platform keystore key bound to the biometric, wrapping the database key). Releasing it, or choosing another option, deletes the PIN file |
//! | `user.search_index` | applied | an FTS5 index inside the encrypted database; released: the index is deleted and search is refused; applied again: rebuilt from the history |
//! | `user.notification_content` | released | notifications show the chat's name only; applied: also the text ([`Session::notification_plan`]) |
//! | `user.incognito_keyboard`, `user.app_switcher_blur`, `user.pc_screen_security`, `chat.screenshot_block` | see APP_PROTOCOL.md 6.3 | carried out by the apps (system window and keyboard flags) |

use std::path::Path;

use tree_core::storage::pin::{self, PinState};
use tree_core::{KeySource, Passphrase};
use zeroize::Zeroizing;

use crate::{CommitOutcome, Error, GroupStatus, Session};

pub(crate) const SEARCH_INDEX: &str = "user.search_index";
pub(crate) const APP_LOCK: &str = "user.app_lock";
const NOTIFICATION_CONTENT: &str = "user.notification_content";

/// What a notification for a new message may show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationPlan {
    /// Show a notification at all (not muted, not silent, not declined, not
    /// this account's own settings group).
    pub notify: bool,
    /// Show the message text, not only the chat's name.
    pub show_text: bool,
}

impl Session {
    // --- unlock ---

    /// Opens the profile with a PIN (`user.app_lock` = `pin`). Every call is
    /// one counted attempt; after `PIN_MAX_ATTEMPTS` wrong ones the PIN file
    /// is wiped and the error is `PinUnavailable`: open with the passphrase.
    /// `device_secret`: the platform's hardware-kept secret, the same one
    /// given to [`Session::enable_pin`].
    pub fn open_with_pin(path: &str, pin: &str, device_secret: Option<&[u8]>) -> Result<(Self, Vec<CommitOutcome>), Error> {
        let source = pin::Pin::new(Path::new(path), pin, device_secret)?;
        Self::open_with(path, &source)
    }

    /// Turns PIN unlock on, or changes the PIN. Needs the passphrase (the
    /// database key is rebuilt from it and checked). See
    /// `tree_core::storage::pin` for what a PIN is worth against someone who
    /// copies the files, and why the attempt limit matters.
    pub fn enable_pin(path: &str, passphrase: &str, pin: &str, device_secret: Option<&[u8]>) -> Result<(), Error> {
        Ok(pin::enable_pin(Path::new(path), &Passphrase::new(passphrase)?, pin, device_secret)?)
    }

    /// Turns PIN unlock off (the PIN file is wiped). The passphrase is unaffected.
    pub fn disable_pin(path: &str) -> Result<(), Error> {
        Ok(pin::disable_pin(Path::new(path))?)
    }

    pub fn pin_state(path: &str) -> PinState {
        pin::pin_state(Path::new(path))
    }

    /// The database key, for the platform to wrap with a keystore key that
    /// only a biometric check releases (`user.app_lock` = `bio`). Checked
    /// against the database first. The caller wraps it at once and wipes
    /// its copy; the passphrase keeps working.
    pub fn key_for_platform_wrap(path: &str, passphrase: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
        Ok(pin::key_for_platform_wrap(Path::new(path), &Passphrase::new(passphrase)?)?)
    }

    /// Opens the profile with a database key the platform unwrapped (after
    /// a biometric check). A wrong key is `WrongKey`.
    pub fn open_with_platform_key(path: &str, key: &[u8]) -> Result<(Self, Vec<CommitOutcome>), Error> {
        let raw: [u8; 32] = key.try_into().map_err(|_| Error::Usage("a database key is 32 bytes".into()))?;
        let k = tree_core::storage::DbKey::from_bytes(raw);
        Self::open_with(path, &k as &dyn KeySource)
    }

    /// `user.app_lock` changed: a PIN is kept only while the lock is applied
    /// with the option `pin`.
    pub(crate) fn app_lock_changed(&self) -> Result<(), Error> {
        let f = self.feature(APP_LOCK)?;
        let pin_wanted = f.state == tree_core::features::State::Applied && f.option.as_deref() == Some("pin");
        if !pin_wanted {
            pin::disable_pin(Path::new(&self.path))?;
        }
        Ok(())
    }

    /// What changing user setting `k` does on this device besides storing
    /// it (also for changes that came from another own device).
    pub(crate) fn local_effects(&self, k: &str) -> Result<(), Error> {
        match k {
            SEARCH_INDEX => self.sync_search_index(),
            APP_LOCK => self.app_lock_changed(),
            _ => Ok(()),
        }
    }

    // --- search index ---

    /// Brings the search index in line with `user.search_index`: built from
    /// the history when applied and missing, deleted when released.
    pub(crate) fn sync_search_index(&self) -> Result<(), Error> {
        let want = self.is_applied(SEARCH_INDEX)?;
        let have = self.client.has_search_index()?;
        if want && !have {
            self.client.build_search_index()?;
        } else if !want && have {
            self.client.drop_search_index()?;
        }
        Ok(())
    }

    /// Whether the search index exists, and how many messages it holds.
    pub fn search_index_status(&self) -> Result<(bool, usize), Error> {
        Ok((self.client.has_search_index()?, self.client.search_index_size()?))
    }

    // --- notifications ---

    /// What the app may show for a new message in `gid` (`silent`: sent
    /// silently): nothing for a muted chat, a silent message, a declined
    /// chat or the own settings group; the chat's name only unless
    /// `user.notification_content` is applied; never the text of a message
    /// request (a stranger's words do not go on the lock screen) or of a
    /// chat that blocks screenshots (`chat.screenshot_block` or the user's
    /// own block for it).
    pub fn notification_plan(&mut self, gid: &[u8], silent: bool) -> Result<NotificationPlan, Error> {
        if self.is_self_group(gid)? || !self.should_notify(gid, silent)? {
            return Ok(NotificationPlan { notify: false, show_text: false });
        }
        let request = matches!(self.group_status(gid)?, GroupStatus::Request { .. });
        let show_text = self.is_applied(NOTIFICATION_CONTENT)? && !request && !self.screenshot_blocked(gid)?;
        Ok(NotificationPlan { notify: true, show_text })
    }
}
