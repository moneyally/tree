//! Feature registry: every feature has an apply and a release.
//!
//! Apps draw their settings screens from [`Registry::list`], so one
//! definition here produces the toggle on every platform.
//!
//! Rules:
//! * apply/release are idempotent and always return the current status;
//! * `AlwaysOn` features can never be released (e.g. end-to-end encryption);
//! * `AlwaysOff` features can never be applied (e.g. sending points between users);
//! * a feature released at the server layer locks the same key in lower layers;
//! * a user preference released for a chat (by a chat admin) is locked for
//!   the users of that chat (`LOCKED_BY_CHAT`);
//! * chat and server settings need an admin, bot settings the bot owner
//!   ([`Caller::is_admin`] means "has authority over the scope");
//! * plan-gated features need the plan when applied; security and
//!   moderation features are never plan-gated (security is not sold).
//!
//! Internally every feature has a [`Kind`], derived from its key, lock,
//! scope and plan, so the public [`Feature`] definition stays as it is.

use std::collections::BTreeMap;

/// Who controls a feature. Server > Chat > User for locking purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Operator flag on the server.
    Server,
    /// Group setting, agreed by all members' devices; set by admins.
    Chat,
    /// Personal setting, synced only between the user's own devices.
    User,
    /// Bot setting, set by the bot owner.
    Bot,
}

/// Permanent locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lock {
    None,
    /// Can never be released. The reason is shown when the button is pressed.
    AlwaysOn(&'static str),
    /// Can never be applied. The reason is shown when the button is pressed.
    AlwaysOff(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Free,
    Pro,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Applied,
    Released,
}

/// Static definition of a feature.
#[derive(Debug, Clone)]
pub struct Feature {
    pub key: &'static str,
    pub scope: Scope,
    pub default: State,
    pub lock: Lock,
    pub plan: Plan,
    /// Roadmap stage in which the feature ships.
    pub stage: u8,
}

/// What the API and the settings screen show for one feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub key: &'static str,
    pub state: State,
    pub option: Option<String>,
    pub locked_by: Option<LockReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockReason {
    Always(&'static str),
    Server,
    Chat,
    Plan,
}

/// Error codes, identical to the server API codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureError {
    Unknown(String),
    /// `LOCKED_ALWAYS`
    LockedAlways(&'static str),
    /// `RELEASED_ALWAYS`
    ReleasedAlways(&'static str),
    /// `LOCKED_BY_SERVER`
    LockedByServer,
    /// `LOCKED_BY_CHAT`
    LockedByChat,
    /// `NOT_ADMIN`
    NotAdmin,
    /// `PLAN_REQUIRED`
    PlanRequired,
    /// `INVALID_OPTION`: the option does not fit the feature (see
    /// [`option_format`]); the text says what would.
    InvalidOption(String),
}

impl FeatureError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unknown(_) => "UNKNOWN_FEATURE",
            Self::LockedAlways(_) => "LOCKED_ALWAYS",
            Self::ReleasedAlways(_) => "RELEASED_ALWAYS",
            Self::LockedByServer => "LOCKED_BY_SERVER",
            Self::LockedByChat => "LOCKED_BY_CHAT",
            Self::NotAdmin => "NOT_ADMIN",
            Self::PlanRequired => "PLAN_REQUIRED",
            Self::InvalidOption(_) => "INVALID_OPTION",
        }
    }
}

/// Context of the caller for one apply/release.
#[derive(Debug, Clone, Copy)]
pub struct Caller {
    pub plan: Plan,
    /// Authority over the feature's scope: chat admin for Chat, operator for
    /// Server, bot owner for Bot. Not needed for User scope.
    pub is_admin: bool,
}

/// What a feature is about. Decides which rules apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Protects keys, devices or content. Never plan-gated, never locked by
    /// a chat.
    SecurityPolicy,
    /// A setting of the group, set by its admins.
    ChatPolicy,
    /// A personal preference. A chat may release it for its members.
    UserPreference,
    /// Abuse and safety controls, and operator flags. Never plan-gated.
    ModerationPolicy,
    /// Points and paid plans.
    BillingCapability,
}

/// Device and content protection.
const SECURITY_KEYS: &[&str] = &[
    "chat.e2e",
    "chat.disappearing",
    "chat.screenshot_block",
    "chat.view_once",
    "chat.private_to_public",
    "user.app_lock",
    "user.notification_content",
    "user.key_change_warning",
    "user.device_link_code",
    "user.incognito_keyboard",
    "user.app_switcher_blur",
    "user.pc_screen_security",
    "user.discoverable",
    "user.recovery_phrase",
    "user.username_link",
];

/// Reporting, spam and stranger protection.
const MODERATION_KEYS: &[&str] = &[
    "user.report",
    "user.message_requests",
    "user.stranger_block",
    "user.stranger_labels",
    "user.group_safety_notice",
    "user.group_add",
];

pub(crate) fn kind(f: &Feature) -> Kind {
    let prefix = f.key.split('.').next().unwrap_or("");
    if SECURITY_KEYS.contains(&f.key) {
        Kind::SecurityPolicy
    } else if MODERATION_KEYS.contains(&f.key) || f.scope == Scope::Server {
        Kind::ModerationPolicy
    } else if f.plan == Plan::Pro || matches!(prefix, "points" | "pro") || f.key == "bot.pay_out_points" {
        Kind::BillingCapability
    } else if f.scope == Scope::Chat {
        Kind::ChatPolicy
    } else {
        Kind::UserPreference
    }
}

/// Feature definitions plus current state per scope.
pub struct Registry {
    defs: BTreeMap<&'static str, Feature>,
    state: BTreeMap<(Scope, &'static str), (State, Option<String>)>,
}

impl Registry {
    /// Registry with the stage-1 features from the design document.
    pub fn standard() -> Self {
        let mut r = Self { defs: BTreeMap::new(), state: BTreeMap::new() };
        for f in standard_features() {
            r.defs.insert(f.key, f);
        }
        r
    }

    /// Adds or replaces a feature definition. A permanently locked feature
    /// can never be redefined, so its lock can never be weakened (F-005).
    ///
    /// Security and moderation features can never require a paid plan.
    pub fn define(&mut self, f: Feature) -> Result<(), FeatureError> {
        if let Some(old) = self.defs.get(f.key) {
            match old.lock {
                Lock::AlwaysOn(r) => return Err(FeatureError::LockedAlways(r)),
                Lock::AlwaysOff(r) => return Err(FeatureError::ReleasedAlways(r)),
                Lock::None => {}
            }
        }
        // (kind() looks at security and moderation before the plan)
        if f.plan != Plan::Free && matches!(kind(&f), Kind::SecurityPolicy | Kind::ModerationPolicy) {
            return Err(FeatureError::LockedAlways(NOT_SOLD));
        }
        self.defs.insert(f.key, f);
        Ok(())
    }

    fn def(&self, key: &str) -> Result<&Feature, FeatureError> {
        self.defs.get(key).ok_or_else(|| FeatureError::Unknown(key.to_string()))
    }

    fn raw_state(&self, scope: Scope, f: &Feature) -> (State, Option<String>) {
        match f.lock {
            Lock::AlwaysOn(_) => return (State::Applied, None),
            Lock::AlwaysOff(_) => return (State::Released, None),
            Lock::None => {}
        }
        self.state.get(&(scope, f.key)).cloned().unwrap_or((f.default, None))
    }

    /// A server-level flag with the same key released => locked below.
    fn server_lock(&self, f: &Feature) -> bool {
        f.scope != Scope::Server
            && self
                .state
                .get(&(Scope::Server, f.key))
                .is_some_and(|(s, _)| *s == State::Released)
    }

    /// A user preference released by the chat => locked for its users.
    fn chat_lock(&self, f: &Feature) -> bool {
        f.scope == Scope::User
            && self
                .state
                .get(&(Scope::Chat, f.key))
                .is_some_and(|(s, _)| *s == State::Released)
    }

    pub fn status(&self, key: &str) -> Result<Status, FeatureError> {
        let f = self.def(key)?;
        let (state, option) = self.raw_state(f.scope, f);
        let locked_by = match f.lock {
            Lock::AlwaysOn(r) | Lock::AlwaysOff(r) => Some(LockReason::Always(r)),
            Lock::None if self.server_lock(f) => Some(LockReason::Server),
            Lock::None if self.chat_lock(f) => Some(LockReason::Chat),
            Lock::None => None,
        };
        let state = if matches!(locked_by, Some(LockReason::Server | LockReason::Chat)) { State::Released } else { state };
        Ok(Status { key: f.key, state, option, locked_by })
    }

    /// All features of one scope, for drawing a settings screen.
    pub fn list(&self, scope: Scope) -> Vec<Status> {
        self.defs
            .values()
            .filter(|f| f.scope == scope)
            .filter_map(|f| self.status(f.key).ok())
            .collect()
    }

    pub fn apply(&mut self, key: &str, option: Option<String>, who: Caller) -> Result<Status, FeatureError> {
        let f = self.def(key)?.clone();
        if let Lock::AlwaysOff(r) = f.lock {
            return Err(FeatureError::ReleasedAlways(r));
        }
        self.check_common(&f, who)?;
        if f.plan == Plan::Pro && who.plan != Plan::Pro {
            return Err(FeatureError::PlanRequired);
        }
        if matches!(f.lock, Lock::None) {
            let option = check_option(f.key, option)?;
            self.state.insert((f.scope, f.key), (State::Applied, option));
        }
        self.status(key)
    }

    pub fn release(&mut self, key: &str, who: Caller) -> Result<Status, FeatureError> {
        let f = self.def(key)?.clone();
        if let Lock::AlwaysOn(r) = f.lock {
            return Err(FeatureError::LockedAlways(r));
        }
        self.check_common(&f, who)?;
        if matches!(f.lock, Lock::None) {
            self.state.insert((f.scope, f.key), (State::Released, None));
        }
        self.status(key)
    }

    fn check_common(&self, f: &Feature, who: Caller) -> Result<(), FeatureError> {
        if matches!(f.scope, Scope::Chat | Scope::Server | Scope::Bot) && !who.is_admin {
            return Err(FeatureError::NotAdmin);
        }
        if self.server_lock(f) {
            return Err(FeatureError::LockedByServer);
        }
        if self.chat_lock(f) {
            return Err(FeatureError::LockedByChat);
        }
        Ok(())
    }

    /// A chat admin releases a user preference for everyone in the chat
    /// (e.g. no read receipts in this chat). Members then see it released
    /// and locked (`LOCKED_BY_CHAT`). Only plain user preferences can be
    /// locked this way, never security, moderation or billing features.
    pub fn release_for_chat(&mut self, key: &str, who: Caller) -> Result<Status, FeatureError> {
        let f = self.chat_lockable(key, who)?;
        self.state.insert((Scope::Chat, f.key), (State::Released, None));
        self.status(key)
    }

    /// Undoes [`Registry::release_for_chat`]: members choose again.
    pub fn apply_for_chat(&mut self, key: &str, who: Caller) -> Result<Status, FeatureError> {
        let f = self.chat_lockable(key, who)?;
        self.state.remove(&(Scope::Chat, f.key));
        self.status(key)
    }

    fn chat_lockable(&self, key: &str, who: Caller) -> Result<Feature, FeatureError> {
        let f = self.def(key)?.clone();
        if f.scope != Scope::User || f.lock != Lock::None || kind(&f) != Kind::UserPreference {
            return Err(FeatureError::LockedAlways(NOT_CHAT_LOCKABLE));
        }
        if !who.is_admin {
            return Err(FeatureError::NotAdmin);
        }
        if self.server_lock(&f) {
            return Err(FeatureError::LockedByServer);
        }
        Ok(f)
    }

    /// Operator flag for a key that also exists at a lower scope.
    pub fn set_server_flag(&mut self, key: &'static str, state: State) {
        self.state.insert((Scope::Server, key), (state, None));
    }
}

/// What the option of a feature may be. Defined here only, for every
/// platform: the registry refuses anything else with `INVALID_OPTION`, group
/// settings carrying anything else are rejected (PROTOCOL.md 6.11), and the
/// apps draw their choices from [`option_choices`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionFormat {
    /// The feature takes no option.
    Nothing,
    /// A duration between `min` and `max` seconds: whole seconds (`90`) or
    /// a whole number with one unit, `s`, `m`, `h`, `d` or `w` (`30m`, `1d`,
    /// `2w`). `default` is stored when the feature is applied without one.
    Duration { min: i64, max: i64, default: Option<&'static str> },
    /// One of these words. No option means the first one.
    OneOf(&'static [&'static str]),
    /// `user.auto_download`: `<network>[:<size>]` (see [`AutoDownload`]).
    /// `default` is stored when the feature is applied without one.
    AutoDownload { default: &'static str },
    /// A feature defined at run time with no declared format: kept as given.
    Free,
}

const MINUTE: i64 = 60;
const HOUR: i64 = 3600;
const DAY: i64 = 86400;

/// The option format of `key` (see [`OptionFormat`]).
pub fn option_format(key: &str) -> OptionFormat {
    use OptionFormat::*;
    match key {
        // How long after arrival a message disappears.
        "chat.disappearing" => Duration { min: 1, max: 365 * DAY, default: Some("1d") },
        // How long after arrival a message can still be edited / deleted
        // for everyone (no option: 24 hours).
        "chat.edit" | "chat.delete_for_all" => Duration { min: 1, max: 30 * DAY, default: None },
        "chat.mention_all" => OneOf(&["admins", "all"]),
        "user.group_add" => OneOf(&["contacts", "nobody"]),
        // How the app unlocks (no option: the passphrase).
        "user.app_lock" => OneOf(&["passphrase", "pin", "bio"]),
        "user.auto_download" => AutoDownload { default: AUTO_DOWNLOAD_DEFAULT },
        k if standard_features().iter().any(|f| f.key == k) => Nothing,
        _ => Free,
    }
}

/// Seconds in a duration option (`90`, `30s`, `5m`, `1h`, `1d`, `2w`), or
/// `None` if it is not one.
pub fn parse_duration(s: &str) -> Option<i64> {
    let s = s.trim();
    let (num, unit) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c),
        _ => (s, 's'),
    };
    if num.is_empty() || num.len() > 9 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = num.parse().ok()?;
    let mul = match unit {
        's' => 1,
        'm' => MINUTE,
        'h' => HOUR,
        'd' => DAY,
        'w' => 7 * DAY,
        _ => return None,
    };
    n.checked_mul(mul)
}

/// Checks `option` for `key` and returns what is stored: the option as
/// given (trimmed), or the format's default when there is none.
pub fn check_option(key: &str, option: Option<String>) -> Result<Option<String>, FeatureError> {
    let format = option_format(key);
    let bad = |want: String| Err(FeatureError::InvalidOption(format!("{key}: {want}")));
    match (format, option.map(|o| o.trim().to_string())) {
        (OptionFormat::Free, o) => Ok(o),
        (OptionFormat::AutoDownload { default }, None) => Ok(Some(default.to_string())),
        (OptionFormat::AutoDownload { .. }, Some(o)) => match AutoDownload::parse(&o) {
            Some(_) => Ok(Some(o)),
            None => bad("wifi, wifi+mobile or never, optionally with a size limit up to 2g (e.g. wifi:20m)".into()),
        },
        (OptionFormat::Duration { default, .. }, None) => Ok(default.map(str::to_string)),
        (_, None) => Ok(None),
        (OptionFormat::Nothing, Some(_)) => bad("takes no option".into()),
        (OptionFormat::OneOf(words), Some(o)) => {
            if words.contains(&o.as_str()) {
                Ok(Some(o))
            } else {
                bad(format!("one of {}", words.join(", ")))
            }
        }
        (OptionFormat::Duration { min, max, .. }, Some(o)) => match parse_duration(&o) {
            Some(n) if (min..=max).contains(&n) => Ok(Some(o)),
            _ => bad(format!("a duration from {min} to {max} seconds, e.g. 90, 30m, 1h, 1d, 2w")),
        },
    }
}

/// Seconds of a duration feature's option, or of its default (`None` if
/// the feature has no duration or none is set).
pub fn option_seconds(key: &str, option: Option<&str>) -> Option<i64> {
    let OptionFormat::Duration { min, max, default } = option_format(key) else { return None };
    option.or(default).and_then(parse_duration).filter(|n| (min..=max).contains(n))
}

/// Values the apps offer for a feature's option (empty: no option).
pub fn option_choices(key: &str) -> Vec<String> {
    let v: &[&str] = match (key, option_format(key)) {
        ("chat.disappearing", _) => &["5m", "1h", "1d", "7d", "30d"],
        (_, OptionFormat::Duration { .. }) => &["15m", "1h", "1d", "7d"],
        (_, OptionFormat::OneOf(words)) => words,
        (_, OptionFormat::AutoDownload { .. }) => &["wifi:5m", "wifi:20m", "wifi:100m", "wifi+mobile:5m", "wifi+mobile:20m", "never"],
        _ => &[],
    };
    v.iter().map(|s| s.to_string()).collect()
}

/// The permanent lock of a standard feature (`None` for unknown keys).
pub fn standard_lock(key: &str) -> Option<Lock> {
    standard_features().into_iter().find(|f| f.key == key).map(|f| f.lock)
}

/// A chat setting that contradicts a permanent lock (e.g. `chat.e2e`
/// released). Such a setting never takes effect: devices reject commits
/// that write one and ignore one that is already there.
pub fn contradicts_lock(key: &str, applied: bool) -> bool {
    match standard_lock(key) {
        Some(Lock::AlwaysOn(_)) => !applied,
        Some(Lock::AlwaysOff(_)) => applied,
        _ => false,
    }
}

/// `user.auto_download` when applied without an option.
pub const AUTO_DOWNLOAD_DEFAULT: &str = "wifi:20m";

/// The network a device is on, as its app reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Wi-Fi or any other unmetered network (wired).
    Wifi,
    /// A metered mobile network.
    Mobile,
    /// Offline or unknown: nothing downloads by itself.
    None,
}

/// The `user.auto_download` option: on which networks received files are
/// fetched without a tap, and up to which plaintext size. Written
/// `<network>[:<size>]`: network `wifi`, `wifi+mobile` or `never`; size a
/// whole number with `k`, `m` or `g` (powers of 1024), at most `2g`
/// (default `20m`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoDownload {
    pub wifi: bool,
    pub mobile: bool,
    pub max_bytes: u64,
}

impl AutoDownload {
    pub const DEFAULT_MAX: u64 = 20 << 20;

    pub fn parse(s: &str) -> Option<Self> {
        let (net, size) = match s.trim().split_once(':') {
            Some((n, z)) => (n, Some(z)),
            None => (s.trim(), None),
        };
        let (wifi, mobile) = match net {
            "wifi" => (true, false),
            "wifi+mobile" => (true, true),
            "never" => (false, false),
            _ => return None,
        };
        let max_bytes = match size {
            None => Self::DEFAULT_MAX,
            Some(z) => {
                let (num, mul) = match z.chars().last()? {
                    'k' => (&z[..z.len() - 1], 1u64 << 10),
                    'm' => (&z[..z.len() - 1], 1 << 20),
                    'g' => (&z[..z.len() - 1], 1 << 30),
                    _ => (z, 1),
                };
                if num.is_empty() || num.len() > 10 || !num.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                num.parse::<u64>().ok()?.checked_mul(mul).filter(|n| *n <= 2 << 30)?
            }
        };
        Some(AutoDownload { wifi, mobile, max_bytes })
    }

    /// Whether a file of `size` plaintext bytes downloads by itself on
    /// `network` (other rules, such as "contacts only", are the caller's).
    pub fn allows(&self, network: Network, size: u64) -> bool {
        let net = match network {
            Network::Wifi => self.wifi,
            Network::Mobile => self.mobile,
            Network::None => false,
        };
        net && size <= self.max_bytes
    }
}

const NOT_SOLD: &str = "security and safety features are never sold";
const NOT_CHAT_LOCKABLE: &str = "a chat can only lock personal preferences, not security settings";

const fn feat(key: &'static str, scope: Scope, default: State, stage: u8) -> Feature {
    Feature { key, scope, default, lock: Lock::None, plan: Plan::Free, stage }
}

/// Stage-1 features and permanent locks from the design document.
pub fn standard_features() -> Vec<Feature> {
    use Scope::*;
    use State::*;
    let mut v = vec![
        // chat
        feat("chat.disappearing", Chat, Released, 1),
        feat("chat.media", Chat, Applied, 1),
        feat("chat.voice", Chat, Applied, 1),
        feat("chat.reactions", Chat, Applied, 1),
        feat("chat.edit", Chat, Applied, 1),
        feat("chat.delete_for_all", Chat, Applied, 1),
        feat("chat.screenshot_block", Chat, Released, 1),
        feat("chat.invite_link", Chat, Released, 1),
        feat("chat.formatting", Chat, Applied, 1),
        feat("chat.view_once", Chat, Applied, 1),
        feat("chat.mention_all", Chat, Applied, 1),
        // user
        feat("user.read_receipts", User, Applied, 1),
        feat("user.typing", User, Applied, 1),
        feat("user.link_preview", User, Applied, 1),
        feat("user.discoverable", User, Applied, 1),
        feat("user.message_requests", User, Applied, 1),
        feat("user.stranger_block", User, Released, 1),
        feat("user.app_lock", User, Released, 1),
        feat("user.notification_content", User, Released, 1),
        feat("user.last_seen", User, Released, 1),
        feat("user.search_index", User, Applied, 1),
        feat("user.auto_download", User, Applied, 1),
        feat("user.peek", User, Applied, 1),
        feat("user.quiet_folder", User, Released, 1),
        feat("user.stranger_labels", User, Applied, 1),
        feat("user.group_safety_notice", User, Applied, 1),
        feat("user.group_add", User, Applied, 1),
        feat("user.incognito_keyboard", User, Applied, 1),
        feat("user.app_switcher_blur", User, Applied, 1),
        feat("user.pc_screen_security", User, Applied, 1),
        feat("user.username", User, Released, 1),
        // Applied once the user made a recovery phrase (the app does that at
        // sign-up); released = the server forgets the recovery key.
        feat("user.recovery_phrase", User, Released, 1),
        feat("user.note_to_self", User, Applied, 1),
        feat("user.folders", User, Applied, 1),
        feat("user.default_folders", User, Applied, 1),
        // Chat list (device only): drafts kept per chat; a new message
        // brings an archived chat back unless it is muted; a link (and QR
        // code) that finds the @username, resettable (PROTOCOL.md 8.4).
        feat("user.drafts", User, Applied, 1),
        feat("user.unarchive_on_message", User, Applied, 1),
        feat("user.username_link", User, Released, 1),
        // server flags
        feat("server.signups", Server, Applied, 1),
        // Anti-spam (design: limits for new accounts and for accounts with
        // verified reports); operators may release them.
        feat("server.new_account_limits", Server, Applied, 1),
        feat("server.report_limits", Server, Applied, 1),
        feat("server.bot_platform", Server, Applied, 2),
        feat("server.calls", Server, Applied, 3),
    ];
    let locked = [
        ("chat.e2e", Chat, Lock::AlwaysOn("end-to-end encryption is why Tree exists")),
        ("user.report", User, Lock::AlwaysOn("reporting is required for safety and app stores")),
        ("user.key_change_warning", User, Lock::AlwaysOn("without it a man-in-the-middle goes unnoticed")),
        ("user.device_link_code", User, Lock::AlwaysOn("QR-only device linking is phishable")),
        ("points.send_to_user", User, Lock::AlwaysOff("points never move between people")),
        ("points.sell_or_exchange", User, Lock::AlwaysOff("points are not money or a token")),
        ("bot.pay_out_points", Bot, Lock::AlwaysOff("bots can receive points but never pay them out")),
        ("chat.private_to_public", Chat, Lock::AlwaysOff("old private messages must never become public")),
    ];
    for (key, scope, lock) in locked {
        let default = if matches!(lock, Lock::AlwaysOn(_)) { Applied } else { Released };
        v.push(Feature { key, scope, default, lock, plan: Plan::Free, stage: 1 });
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_of_standard_features() {
        let all = standard_features();
        let k = |key: &str| kind(all.iter().find(|f| f.key == key).unwrap());
        assert_eq!(k("chat.e2e"), Kind::SecurityPolicy);
        assert_eq!(k("user.app_lock"), Kind::SecurityPolicy);
        assert_eq!(k("user.report"), Kind::ModerationPolicy);
        assert_eq!(k("server.signups"), Kind::ModerationPolicy);
        assert_eq!(k("points.send_to_user"), Kind::BillingCapability);
        assert_eq!(k("bot.pay_out_points"), Kind::BillingCapability);
        assert_eq!(k("chat.reactions"), Kind::ChatPolicy);
        assert_eq!(k("user.read_receipts"), Kind::UserPreference);
        // Every listed key exists, so the lists cannot silently rot.
        for key in SECURITY_KEYS.iter().chain(MODERATION_KEYS) {
            assert!(all.iter().any(|f| f.key == *key), "{key}");
        }
        let pro = Feature { key: "user.pro_theme", scope: Scope::User, default: State::Released, lock: Lock::None, plan: Plan::Pro, stage: 3 };
        assert_eq!(kind(&pro), Kind::BillingCapability);
        let bot = Feature { key: "bot.inline", scope: Scope::Bot, default: State::Released, lock: Lock::None, plan: Plan::Free, stage: 2 };
        assert_eq!(kind(&bot), Kind::UserPreference);
    }

    #[test]
    fn auto_download_option() {
        let p = |s: &str| AutoDownload::parse(s);
        assert_eq!(p("wifi"), Some(AutoDownload { wifi: true, mobile: false, max_bytes: 20 << 20 }));
        assert_eq!(p("wifi+mobile:5m"), Some(AutoDownload { wifi: true, mobile: true, max_bytes: 5 << 20 }));
        assert_eq!(p("never").map(|a| (a.wifi, a.mobile)), Some((false, false)));
        assert_eq!(p("wifi:2g").map(|a| a.max_bytes), Some(2 << 30));
        assert_eq!(p("wifi:1500").map(|a| a.max_bytes), Some(1500));
        for bad in ["", "lte", "wifi:", "wifi:3g", "wifi:-1m", "wifi:1t", "wifi:m", "mobile"] {
            assert_eq!(p(bad), None, "{bad}");
        }
        let a = p("wifi:1k").unwrap();
        assert!(a.allows(Network::Wifi, 1024) && !a.allows(Network::Wifi, 1025));
        assert!(!a.allows(Network::Mobile, 1) && !a.allows(Network::None, 1));
        assert!(p("wifi+mobile").unwrap().allows(Network::Mobile, 1));
        // The registry checks it and stores the default.
        let mut r = Registry::standard();
        let me = Caller { plan: Plan::Free, is_admin: false };
        assert_eq!(r.apply("user.auto_download", None, me).unwrap().option.as_deref(), Some(AUTO_DOWNLOAD_DEFAULT));
        assert_eq!(r.apply("user.auto_download", Some("lte".into()), me).unwrap_err().code(), "INVALID_OPTION");
        assert_eq!(r.apply("user.auto_download", Some(" wifi+mobile:5m ".into()), me).unwrap().option.as_deref(), Some("wifi+mobile:5m"));
        assert!(option_choices("user.auto_download").iter().all(|c| p(c).is_some()));
        assert!(option_choices("user.typing").is_empty());
    }
}
