//! Feature registry: lock, permission, plan and server-flag rules.

use tree_core::features::{
    standard_features, Caller, Feature, FeatureError, Lock, LockReason, Plan, Registry, Scope, State,
};

const USER: Caller = Caller { plan: Plan::Free, is_admin: false };
const ADMIN: Caller = Caller { plan: Plan::Free, is_admin: true };
const PRO_USER: Caller = Caller { plan: Plan::Pro, is_admin: false };
const PRO_ADMIN: Caller = Caller { plan: Plan::Pro, is_admin: true };
const ALL: [Caller; 4] = [USER, ADMIN, PRO_USER, PRO_ADMIN];

#[test]
fn error_codes_match_api() {
    let cases = [
        (FeatureError::Unknown("x".into()), "UNKNOWN_FEATURE"),
        (FeatureError::LockedAlways("r"), "LOCKED_ALWAYS"),
        (FeatureError::ReleasedAlways("r"), "RELEASED_ALWAYS"),
        (FeatureError::LockedByServer, "LOCKED_BY_SERVER"),
        (FeatureError::LockedByChat, "LOCKED_BY_CHAT"),
        (FeatureError::NotAdmin, "NOT_ADMIN"),
        (FeatureError::PlanRequired, "PLAN_REQUIRED"),
        (FeatureError::InvalidOption("x".into()), "INVALID_OPTION"),
    ];
    for (e, code) in cases {
        assert_eq!(e.code(), code);
    }
}

/// Options are checked against the one format table (`option_format`):
/// durations take seconds or a unit, word options one of their words, and
/// every other standard feature no option at all.
#[test]
fn options_are_validated() {
    use tree_core::features::{option_choices, option_seconds, parse_duration};
    let mut r = Registry::standard();
    let invalid = |r: &mut Registry, key: &str, opt: &str, who: Caller| {
        matches!(r.apply(key, Some(opt.into()), who), Err(FeatureError::InvalidOption(_)))
    };
    for (s, n) in [("90", 90), ("30s", 30), ("5m", 300), ("1h", 3600), ("1d", 86400), ("2w", 1_209_600), (" 7d ", 604_800)] {
        assert_eq!(parse_duration(s), Some(n), "{s}");
    }
    for s in ["", "d", "1y", "-5", "1.5h", "1dd", "h1", "9999999999", "١d"] {
        assert_eq!(parse_duration(s), None, "{s:?}");
    }
    // chat.disappearing: a duration from 1 second to a year; default 1 day.
    assert_eq!(r.apply("chat.disappearing", Some("1d".into()), ADMIN).unwrap().option.as_deref(), Some("1d"));
    assert_eq!(r.apply("chat.disappearing", Some("2".into()), ADMIN).unwrap().option.as_deref(), Some("2"));
    assert_eq!(r.apply("chat.disappearing", None, ADMIN).unwrap().option.as_deref(), Some("1d"));
    for bad in ["0", "0s", "366d", "soon", "1y"] {
        assert!(invalid(&mut r, "chat.disappearing", bad, ADMIN), "{bad}");
    }
    // The refused apply left the previous value.
    assert_eq!(r.status("chat.disappearing").unwrap().option.as_deref(), Some("1d"));
    assert_eq!(option_seconds("chat.disappearing", Some("1h")), Some(3600));
    assert_eq!(option_seconds("chat.disappearing", None), Some(86400));
    assert_eq!(option_seconds("chat.disappearing", Some("junk")), None);
    assert_eq!(option_seconds("chat.edit", None), None, "no default: the client's 24 h window");
    assert!(invalid(&mut r, "chat.edit", "31d", ADMIN));
    assert_eq!(r.apply("chat.edit", Some("15m".into()), ADMIN).unwrap().option.as_deref(), Some("15m"));
    // Word options.
    assert!(r.apply("user.group_add", Some("nobody".into()), USER).is_ok());
    assert!(r.apply("user.group_add", Some("contacts".into()), USER).is_ok());
    assert!(invalid(&mut r, "user.group_add", "everyone", USER));
    assert!(invalid(&mut r, "chat.mention_all", "some", ADMIN));
    // No option on the others.
    assert!(invalid(&mut r, "user.read_receipts", "mine", USER));
    assert!(invalid(&mut r, "chat.media", "1d", ADMIN));
    assert_eq!(r.apply("user.read_receipts", None, USER).unwrap().option, None);
    // Permission errors come before option errors.
    assert_eq!(r.apply("chat.disappearing", Some("junk".into()), USER), Err(FeatureError::NotAdmin));
    // Choices for the apps fit their own format.
    for f in standard_features().into_iter().filter(|f| f.lock == Lock::None) {
        for c in option_choices(f.key) {
            let who = if f.scope == Scope::User { USER } else { ADMIN };
            assert!(r.apply(f.key, Some(c.clone()), who).is_ok(), "{} {c}", f.key);
        }
    }
    assert_eq!(option_choices("user.group_add"), vec!["contacts", "nobody"]);
    assert!(option_choices("user.typing").is_empty());
}

#[test]
fn standard_feature_table() {
    let v = standard_features();
    let mut keys: Vec<_> = v.iter().map(|f| f.key).collect();
    keys.sort();
    let n = keys.len();
    keys.dedup();
    assert_eq!(keys.len(), n, "duplicate feature keys");
    for f in &v {
        // Defaults of locked features agree with the lock.
        match f.lock {
            Lock::AlwaysOn(r) => {
                assert_eq!(f.default, State::Applied, "{}", f.key);
                assert!(!r.is_empty());
            }
            Lock::AlwaysOff(r) => {
                assert_eq!(f.default, State::Released, "{}", f.key);
                assert!(!r.is_empty());
            }
            Lock::None => {}
        }
        assert_eq!(f.plan, Plan::Free, "{}", f.key);
        // Stage 4 only for what is locked off until then (bot payments, tips).
        assert!((1..=3).contains(&f.stage) || (f.stage == 4 && matches!(f.lock, Lock::AlwaysOff(_))), "{}", f.key);
        // The key prefix names the scope.
        let prefix = f.key.split('.').next().unwrap();
        let ok = match f.scope {
            // Channel settings (Wave 4) are chat scope too: set by admins.
            Scope::Chat => prefix == "chat" || prefix == "channel",
            Scope::User => prefix == "user" || prefix == "points",
            Scope::Server => prefix == "server",
            Scope::Bot => prefix == "bot",
        };
        assert!(ok, "{} has scope {:?}", f.key, f.scope);
    }
    let get = |k: &str| v.iter().find(|f| f.key == k).unwrap().clone();
    assert!(matches!(get("chat.e2e").lock, Lock::AlwaysOn(_)));
    assert!(matches!(get("points.send_to_user").lock, Lock::AlwaysOff(_)));
    assert!(matches!(get("bot.pay_out_points").lock, Lock::AlwaysOff(_)));
    assert!(matches!(get("bot.payments").lock, Lock::AlwaysOff(_)));
    assert!(matches!(get("bot.tips").lock, Lock::AlwaysOff(_)));
    assert_eq!((get("bot.privacy_mode").default, get("chat.bots").default), (State::Applied, State::Applied));
    assert_eq!((get("bot.directory").default, get("bot.inline").default), (State::Released, State::Released));
    assert_eq!(get("server.bot_platform").stage, 2);
    assert_eq!(get("server.calls").stage, 3);
}

/// Status of every standard feature equals its default on a fresh registry.
#[test]
fn fresh_registry_shows_defaults() {
    let r = Registry::standard();
    for f in standard_features() {
        let s = r.status(f.key).unwrap();
        assert_eq!(s.key, f.key);
        assert_eq!(s.state, f.default, "{}", f.key);
        assert_eq!(s.option, None);
        let expect_lock = match f.lock {
            Lock::AlwaysOn(x) | Lock::AlwaysOff(x) => Some(LockReason::Always(x)),
            Lock::None => None,
        };
        assert_eq!(s.locked_by, expect_lock, "{}", f.key);
    }
    assert!(matches!(r.status("nope"), Err(FeatureError::Unknown(k)) if k == "nope"));
}

/// `list` returns exactly the features of the scope.
#[test]
fn list_per_scope() {
    let r = Registry::standard();
    let all = standard_features();
    for scope in [Scope::Server, Scope::Chat, Scope::User, Scope::Bot] {
        let mut want: Vec<_> = all.iter().filter(|f| f.scope == scope).map(|f| f.key).collect();
        want.sort();
        let got: Vec<_> = r.list(scope).iter().map(|s| s.key).collect();
        assert_eq!(got, want, "{scope:?}");
    }
}

/// Permanent locks hold for every caller and survive server flags.
#[test]
fn permanent_locks() {
    let mut r = Registry::standard();
    for f in standard_features() {
        for who in ALL {
            match f.lock {
                Lock::AlwaysOn(reason) => {
                    assert_eq!(r.release(f.key, who), Err(FeatureError::LockedAlways(reason)));
                }
                Lock::AlwaysOff(reason) => {
                    assert_eq!(r.apply(f.key, Some("x".into()), who), Err(FeatureError::ReleasedAlways(reason)));
                }
                Lock::None => {}
            }
        }
    }
    // Applying an AlwaysOn / releasing an AlwaysOff is a harmless no-op for
    // those allowed to touch the scope.
    let s = r.apply("chat.e2e", Some("opt".into()), ADMIN).unwrap();
    assert_eq!((s.state, s.option), (State::Applied, None));
    assert_eq!(r.release("points.send_to_user", USER).unwrap().state, State::Released);
    assert_eq!(r.release("chat.private_to_public", ADMIN).unwrap().state, State::Released);
    assert_eq!(r.apply("chat.e2e", None, USER), Err(FeatureError::NotAdmin));

    // An operator flag cannot switch off end-to-end encryption.
    r.set_server_flag("chat.e2e", State::Released);
    let s = r.status("chat.e2e").unwrap();
    assert_eq!(s.state, State::Applied);
    assert!(matches!(s.locked_by, Some(LockReason::Always(_))));
    // Nor switch on an AlwaysOff feature.
    r.set_server_flag("points.send_to_user", State::Applied);
    assert_eq!(r.status("points.send_to_user").unwrap().state, State::Released);
}

/// Chat and Server scope need an admin, Bot scope the bot owner; User
/// scope does not.
#[test]
fn admin_rules() {
    let mut r = Registry::standard();
    for f in standard_features().into_iter().filter(|f| f.lock == Lock::None) {
        let before = r.status(f.key).unwrap();
        let needs_admin = matches!(f.scope, Scope::Chat | Scope::Server | Scope::Bot);
        for who in [USER, PRO_USER] {
            let a = r.apply(f.key, None, who);
            let rel = r.release(f.key, who);
            if needs_admin {
                assert_eq!(a, Err(FeatureError::NotAdmin), "{}", f.key);
                assert_eq!(rel, Err(FeatureError::NotAdmin), "{}", f.key);
                assert_eq!(r.status(f.key).unwrap(), before, "{} changed by non-admin", f.key);
            } else {
                assert!(a.is_ok() && rel.is_ok(), "{}", f.key);
            }
        }
        assert_eq!(r.apply(f.key, None, ADMIN).unwrap().state, State::Applied);
        assert_eq!(r.release(f.key, ADMIN).unwrap().state, State::Released);
    }
}

/// Options are kept on apply and cleared on release.
#[test]
fn options_kept_and_cleared() {
    let mut r = Registry::standard();
    let s = r.apply("user.app_lock", Some("pin".into()), USER).unwrap();
    assert_eq!((s.state, s.option.as_deref()), (State::Applied, Some("pin")));
    assert_eq!(r.status("user.app_lock").unwrap().option.as_deref(), Some("pin"));
    let s = r.apply("user.app_lock", Some("bio".into()), USER).unwrap();
    assert_eq!(s.option.as_deref(), Some("bio"));
    let s = r.release("user.app_lock", USER).unwrap();
    assert_eq!((s.state, s.option), (State::Released, None));
}

/// A server flag set to Released locks the same key at lower scopes, for
/// admins too; re-applying the flag restores the previous lower-level state.
#[test]
fn server_flag_locks_lower_scopes() {
    let mut r = Registry::standard();
    r.apply("chat.disappearing", Some("1d".into()), ADMIN).unwrap();
    r.set_server_flag("chat.disappearing", State::Released);
    let s = r.status("chat.disappearing").unwrap();
    assert_eq!(s.state, State::Released);
    assert_eq!(s.locked_by, Some(LockReason::Server));
    for who in ALL {
        let want = if who.is_admin { FeatureError::LockedByServer } else { FeatureError::NotAdmin };
        assert_eq!(r.apply("chat.disappearing", None, who), Err(want.clone()));
        assert_eq!(r.release("chat.disappearing", who), Err(want));
    }
    // User scope: no admin needed, the server lock is the error.
    r.set_server_flag("user.link_preview", State::Released);
    assert_eq!(r.apply("user.link_preview", None, USER), Err(FeatureError::LockedByServer));
    assert_eq!(r.status("user.link_preview").unwrap().state, State::Released);

    r.set_server_flag("chat.disappearing", State::Applied);
    let s = r.status("chat.disappearing").unwrap();
    assert_eq!((s.state, s.option.as_deref(), s.locked_by), (State::Applied, Some("1d"), None));
    assert!(r.release("chat.disappearing", ADMIN).is_ok());
}

/// A Server-scope feature released by an admin does not lock itself.
#[test]
fn server_scope_feature_not_self_locked() {
    let mut r = Registry::standard();
    let s = r.release("server.signups", ADMIN).unwrap();
    assert_eq!((s.state, s.locked_by), (State::Released, None));
    let s = r.apply("server.signups", None, ADMIN).unwrap();
    assert_eq!(s.state, State::Applied);
    // set_server_flag on a Server-scope key is the same state.
    r.set_server_flag("server.calls", State::Released);
    let s = r.status("server.calls").unwrap();
    assert_eq!((s.state, s.locked_by), (State::Released, None));
}

/// Pro features need the Pro plan to apply; release is always allowed.
#[test]
fn plan_gating() {
    let mut r = Registry::standard();
    for (key, scope) in [("user.pro_theme", Scope::User), ("chat.pro_bots", Scope::Chat)] {
        r.define(Feature { key, scope, default: State::Released, lock: Lock::None, plan: Plan::Pro, stage: 2 })
            .unwrap();
    }
    assert_eq!(r.apply("user.pro_theme", None, USER), Err(FeatureError::PlanRequired));
    assert_eq!(r.status("user.pro_theme").unwrap().state, State::Released);
    assert_eq!(r.apply("user.pro_theme", None, PRO_USER).unwrap().state, State::Applied);
    assert_eq!(r.release("user.pro_theme", USER).unwrap().state, State::Released);
    // Admin rights do not replace the plan, and the plan does not replace admin.
    assert_eq!(r.apply("chat.pro_bots", None, ADMIN), Err(FeatureError::PlanRequired));
    assert_eq!(r.apply("chat.pro_bots", None, PRO_USER), Err(FeatureError::NotAdmin));
    assert_eq!(r.apply("chat.pro_bots", None, PRO_ADMIN).unwrap().state, State::Applied);
    // Free features ignore the plan.
    assert!(r.apply("user.app_lock", None, PRO_USER).is_ok());
    assert!(r.apply("user.app_lock", None, USER).is_ok());
}

/// `define` adds new features but can never weaken a permanent lock
/// (regression for F-005).
#[test]
fn define_cannot_override_permanent_locks() {
    let mut r = Registry::standard();
    for f in standard_features().into_iter().filter(|f| f.lock != Lock::None) {
        let weakened = Feature { lock: Lock::None, ..f.clone() };
        let err = r.define(weakened).unwrap_err();
        assert!(matches!(err, FeatureError::LockedAlways(_) | FeatureError::ReleasedAlways(_)), "{}", f.key);
        // Even re-defining with the identical lock is refused (no silent swaps
        // of reason text or scope).
        assert!(r.define(f.clone()).is_err());
        assert_eq!(r.status(f.key).unwrap().locked_by, Some(LockReason::Always(match f.lock {
            Lock::AlwaysOn(x) | Lock::AlwaysOff(x) => x,
            Lock::None => unreachable!(),
        })));
    }
    assert!(r.release("chat.e2e", ADMIN).is_err());
    assert!(r.apply("points.send_to_user", None, ADMIN).is_err());

    // Unlocked features may be redefined, e.g. to add a lock.
    r.define(Feature {
        key: "user.app_lock",
        scope: Scope::User,
        default: State::Applied,
        lock: Lock::AlwaysOn("test"),
        plan: Plan::Free,
        stage: 1,
    })
    .unwrap();
    assert_eq!(r.release("user.app_lock", USER), Err(FeatureError::LockedAlways("test")));
    // New keys can be defined.
    r.define(Feature {
        key: "bot.greeting",
        scope: Scope::Bot,
        default: State::Applied,
        lock: Lock::None,
        plan: Plan::Free,
        stage: 2,
    })
    .unwrap();
    assert_eq!(r.status("bot.greeting").unwrap().state, State::Applied);
}

/// Unknown keys are errors for every operation.
#[test]
fn unknown_keys() {
    let mut r = Registry::standard();
    for who in ALL {
        assert!(matches!(r.apply("x.y", None, who), Err(FeatureError::Unknown(k)) if k == "x.y"));
        assert!(matches!(r.release("x.y", who), Err(FeatureError::Unknown(_))));
    }
    // Setting a server flag for an unknown key does not invent a feature.
    r.set_server_flag("x.y", State::Released);
    assert!(r.status("x.y").is_err());
}

/// Security and moderation features can never be put behind a paid plan
/// ("security is not sold"); other features can.
#[test]
fn security_is_never_plan_gated() {
    let mut r = Registry::standard();
    for key in ["user.app_lock", "user.message_requests", "chat.screenshot_block", "server.signups"] {
        let f = standard_features().into_iter().find(|f| f.key == key).unwrap();
        let err = r.define(Feature { plan: Plan::Pro, ..f.clone() }).unwrap_err();
        assert_eq!(err.code(), "LOCKED_ALWAYS", "{key}");
        assert_eq!(r.apply(key, None, if f.scope == Scope::User { USER } else { ADMIN }).unwrap().state, State::Applied, "{key} still free");
        r.define(f).unwrap(); // the free definition is fine
    }
    let pref = Feature { key: "user.auto_download", scope: Scope::User, default: State::Applied, lock: Lock::None, plan: Plan::Pro, stage: 1 };
    r.define(pref).unwrap();
    assert_eq!(r.apply("user.auto_download", None, USER), Err(FeatureError::PlanRequired));
}

/// Bot settings can only be changed by the bot owner.
#[test]
fn bot_settings_need_the_owner() {
    let mut r = Registry::standard();
    r.define(Feature { key: "bot.inline", scope: Scope::Bot, default: State::Released, lock: Lock::None, plan: Plan::Free, stage: 2 })
        .unwrap();
    for who in [USER, PRO_USER] {
        assert_eq!(r.apply("bot.inline", None, who), Err(FeatureError::NotAdmin));
        assert_eq!(r.release("bot.inline", who), Err(FeatureError::NotAdmin));
    }
    assert_eq!(r.status("bot.inline").unwrap().state, State::Released);
    let owner = ADMIN;
    assert_eq!(r.apply("bot.inline", None, owner).unwrap().state, State::Applied);
    assert_eq!(r.release("bot.inline", owner).unwrap().state, State::Released);
}

/// A chat admin releasing a user preference for the chat locks it for
/// users (LOCKED_BY_CHAT) until the chat applies it again; the user's own
/// choice is kept underneath.
#[test]
fn chat_release_locks_user_preference() {
    let mut r = Registry::standard();
    r.apply("user.read_receipts", None, USER).unwrap();
    assert_eq!(r.release_for_chat("user.read_receipts", USER), Err(FeatureError::NotAdmin));
    let s = r.release_for_chat("user.read_receipts", ADMIN).unwrap();
    assert_eq!((s.state, s.locked_by), (State::Released, Some(LockReason::Chat)));
    for who in ALL {
        assert_eq!(r.apply("user.read_receipts", None, who), Err(FeatureError::LockedByChat));
        assert_eq!(r.release("user.read_receipts", who), Err(FeatureError::LockedByChat));
    }
    assert_eq!(r.list(Scope::User).iter().find(|s| s.key == "user.read_receipts").unwrap().locked_by, Some(LockReason::Chat));
    // idempotent
    assert_eq!(r.release_for_chat("user.read_receipts", ADMIN).unwrap().locked_by, Some(LockReason::Chat));
    assert_eq!(r.apply_for_chat("user.read_receipts", USER), Err(FeatureError::NotAdmin));
    let s = r.apply_for_chat("user.read_receipts", ADMIN).unwrap();
    assert_eq!((s.state, s.option.as_deref(), s.locked_by), (State::Applied, None, None));
    assert_eq!(r.apply_for_chat("user.read_receipts", ADMIN).unwrap().locked_by, None);
    assert!(r.release("user.read_receipts", USER).is_ok());
}

/// A chat cannot lock security, moderation, billing, chat or locked
/// features, and the server lock wins over the chat lock.
#[test]
fn chat_lock_limits() {
    let mut r = Registry::standard();
    for key in ["user.app_lock", "user.report", "user.message_requests", "points.send_to_user", "chat.reactions", "user.key_change_warning"] {
        let e = r.release_for_chat(key, ADMIN).unwrap_err();
        assert_eq!(e.code(), "LOCKED_ALWAYS", "{key}");
        assert_eq!(r.apply_for_chat(key, ADMIN).unwrap_err().code(), "LOCKED_ALWAYS", "{key}");
    }
    assert!(matches!(r.release_for_chat("x.y", ADMIN), Err(FeatureError::Unknown(_))));
    r.set_server_flag("user.typing", State::Released);
    assert_eq!(r.release_for_chat("user.typing", ADMIN), Err(FeatureError::LockedByServer));
    r.set_server_flag("user.typing", State::Applied);
    r.release_for_chat("user.typing", ADMIN).unwrap();
    r.set_server_flag("user.typing", State::Released);
    assert_eq!(r.status("user.typing").unwrap().locked_by, Some(LockReason::Server));
    assert_eq!(r.apply("user.typing", None, USER), Err(FeatureError::LockedByServer));
}
