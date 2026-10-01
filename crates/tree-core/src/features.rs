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
//! * plan-gated features need the plan when applied.

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
        }
    }
}

/// Context of the caller for one apply/release.
#[derive(Debug, Clone, Copy)]
pub struct Caller {
    pub plan: Plan,
    pub is_admin: bool,
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

    pub fn define(&mut self, f: Feature) {
        self.defs.insert(f.key, f);
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

    pub fn status(&self, key: &str) -> Result<Status, FeatureError> {
        let f = self.def(key)?;
        let (state, option) = self.raw_state(f.scope, f);
        let locked_by = match f.lock {
            Lock::AlwaysOn(r) | Lock::AlwaysOff(r) => Some(LockReason::Always(r)),
            Lock::None if self.server_lock(f) => Some(LockReason::Server),
            Lock::None => None,
        };
        let state = if locked_by == Some(LockReason::Server) { State::Released } else { state };
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
        if matches!(f.scope, Scope::Chat | Scope::Server) && !who.is_admin {
            return Err(FeatureError::NotAdmin);
        }
        if self.server_lock(f) {
            return Err(FeatureError::LockedByServer);
        }
        Ok(())
    }

    /// Operator flag for a key that also exists at a lower scope.
    pub fn set_server_flag(&mut self, key: &'static str, state: State) {
        self.state.insert((Scope::Server, key), (state, None));
    }
}

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
        // server flags
        feat("server.signups", Server, Applied, 1),
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
