//! Device-level switches through a real server (PRODUCT_PLAN.md Wave 1
//! items 7-9): the search index follows `user.search_index`, PIN unlock
//! follows `user.app_lock`, and what a notification may show follows mute,
//! silent sends, `user.notification_content`, message requests and the
//! chat's screenshot block. The window and keyboard switches are carried
//! out by the apps (tested in `apps/desktop/.../DeviceProtectionTest.kt`);
//! here they must toggle and sync like any user setting.

mod common;

use common::Env;
use tree_client::device::NotificationPlan;
use tree_client::{Error, Session, TextOptions};
use tree_core::features::State;

#[test]
fn search_index_is_deleted_on_release_and_rebuilt_on_apply() {
    let env = Env::new("search-index");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    alice.add_contact(bob.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    bob.accept_request(&g).unwrap();
    // Applied by default: an index exists from the start.
    assert_eq!(alice.search_index_status().unwrap(), (true, 0));
    alice.send_text(&g, "내일 사과를 사자").unwrap();
    bob.send_text(&g, "Meeting at the library").unwrap();
    alice.sync(0).unwrap();
    assert_eq!(alice.search_index_status().unwrap(), (true, 2));
    let hits = |s: &Session, q: &str| s.search(q).unwrap().into_iter().map(|m| m.text.unwrap_or_default()).collect::<Vec<_>>();
    assert_eq!(hits(&alice, "사과"), vec!["내일 사과를 사자"]);
    assert_eq!(hits(&alice, "LIBR meet"), vec!["Meeting at the library"]);

    // Release: the index is gone and search is refused.
    assert_eq!(alice.release_feature("user.search_index").unwrap().state, State::Released);
    assert_eq!(alice.search_index_status().unwrap(), (false, 0));
    assert!(matches!(alice.search("사과"), Err(Error::Feature(_))));
    bob.send_text(&g, "while released").unwrap();
    alice.sync(0).unwrap();
    assert_eq!(alice.search_index_status().unwrap(), (false, 0), "nothing is indexed while released");
    // Still released after a restart.
    let path = env.profile("alice");
    drop(alice);
    let (alice, _) = Session::open(&path, "alice passphrase").unwrap();
    assert_eq!(alice.search_index_status().unwrap(), (false, 0));

    // Apply: rebuilt from the whole history.
    alice.apply_feature("user.search_index", None).unwrap();
    assert_eq!(alice.search_index_status().unwrap(), (true, 3));
    assert_eq!(hits(&alice, "released"), vec!["while released"]);
}

#[test]
fn pin_unlock_follows_app_lock_and_stops_after_ten_wrong_pins() {
    let env = Env::new("pin-lock");
    let alice = env.device("alice");
    let path = env.profile("alice");
    let account = alice.account_id().to_string();
    alice.apply_feature("user.app_lock", Some("pin".into())).unwrap();
    assert!(matches!(Session::enable_pin(&path, "wrong passphrase", "123456", None), Err(Error::Core(tree_core::TreeError::WrongKey))));
    Session::enable_pin(&path, "alice passphrase", "123456", None).unwrap();
    assert!(Session::pin_state(&path).enabled);
    drop(alice);
    // The app locked: the PIN opens the profile again.
    let (alice, _) = Session::open_with_pin(&path, "123456", None).unwrap();
    assert_eq!(alice.account_id(), account);
    // Another unlock method: the PIN file is wiped.
    alice.apply_feature("user.app_lock", Some("passphrase".into())).unwrap();
    assert!(!Session::pin_state(&path).enabled);
    alice.apply_feature("user.app_lock", Some("pin".into())).unwrap();
    Session::enable_pin(&path, "alice passphrase", "654321", None).unwrap();
    // Releasing the app lock wipes it too.
    alice.release_feature("user.app_lock").unwrap();
    assert!(!Session::pin_state(&path).enabled);
    alice.apply_feature("user.app_lock", Some("pin".into())).unwrap();
    Session::enable_pin(&path, "alice passphrase", "654321", None).unwrap();
    drop(alice);
    // Ten wrong PINs: only the passphrase opens.
    for left in (0..10u8).rev() {
        match Session::open_with_pin(&path, "000000", None) {
            Err(Error::Core(tree_core::TreeError::WrongPin(n))) => assert_eq!(n, left),
            Err(Error::Core(tree_core::TreeError::PinUnavailable)) => assert_eq!(left, 0),
            other => panic!("{:?}", other.err()),
        }
    }
    assert!(matches!(Session::open_with_pin(&path, "654321", None), Err(Error::Core(tree_core::TreeError::PinUnavailable))));
    let (alice, _) = Session::open(&path, "alice passphrase").unwrap();
    assert_eq!(alice.account_id(), account);
    // Deleting the account leaves no PIN file behind.
    Session::enable_pin(&path, "alice passphrase", "654321", None).unwrap();
    alice.delete_account(&path).unwrap();
    assert!(!std::path::Path::new(&format!("{path}.pin")).exists());
}

#[test]
fn notification_plan_respects_mute_silent_content_requests_and_screenshot_block() {
    let env = Env::new("notify-plan");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut carol = env.device("carol");
    alice.add_contact(bob.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    bob.accept_request(&g).unwrap();
    let plan = |notify, show_text| NotificationPlan { notify, show_text };

    // Default: notify with the chat's name only.
    assert_eq!(alice.notification_plan(&g, false).unwrap(), plan(true, false));
    alice.apply_feature("user.notification_content", None).unwrap();
    assert_eq!(alice.notification_plan(&g, false).unwrap(), plan(true, true));
    assert_eq!(alice.notification_plan(&g, true).unwrap(), plan(false, false), "silent send");
    alice.mute_for(&g, Some(3600)).unwrap();
    assert_eq!(alice.notification_plan(&g, false).unwrap(), plan(false, false), "muted");
    alice.mute(&g, false).unwrap();
    // A chat that blocks screenshots keeps its text off the lock screen.
    alice.set_screenshot_block(&g, true).unwrap();
    assert_eq!(alice.notification_plan(&g, false).unwrap(), plan(true, false));
    alice.set_screenshot_block(&g, false).unwrap();
    assert_eq!(alice.notification_plan(&g, false).unwrap(), plan(true, true));
    alice.release_feature("user.notification_content").unwrap();
    assert_eq!(alice.notification_plan(&g, false).unwrap(), plan(true, false));

    // A stranger's request: never its text.
    alice.apply_feature("user.notification_content", None).unwrap();
    let r = carol.create_group().unwrap();
    carol.invite(&r, alice.account_id()).unwrap();
    alice.sync(0).unwrap();
    carol.send_text_with(&r, "buy now", &TextOptions::default()).unwrap();
    alice.sync(0).unwrap();
    assert_eq!(alice.notification_plan(&r, false).unwrap(), plan(true, false));
    // A declined one: nothing.
    alice.decline(&r, false).unwrap();
    assert_eq!(alice.notification_plan(&r, false).unwrap(), plan(false, false));
}

#[test]
fn device_switches_toggle_and_keep_their_defaults() {
    let env = Env::new("device-switches");
    let alice = env.device("alice");
    // Defaults from the registry.
    for (k, on) in [
        ("user.incognito_keyboard", true),
        ("user.app_switcher_blur", true),
        ("user.pc_screen_security", true),
        ("user.search_index", true),
        ("user.notification_content", false),
        ("user.app_lock", false),
    ] {
        assert_eq!(alice.feature(k).unwrap().state == State::Applied, on, "{k}");
    }
    for k in ["user.incognito_keyboard", "user.app_switcher_blur", "user.pc_screen_security"] {
        assert_eq!(alice.release_feature(k).unwrap().state, State::Released, "{k}");
        assert_eq!(alice.feature(k).unwrap().state, State::Released);
        assert_eq!(alice.apply_feature(k, None).unwrap().state, State::Applied, "{k}");
        assert!(matches!(alice.apply_feature(k, Some("x".into())), Err(Error::InvalidOption(_))), "{k} takes no option");
    }
    assert!(matches!(alice.apply_feature("user.app_lock", Some("face".into())), Err(Error::InvalidOption(_))));
    assert_eq!(alice.apply_feature("user.app_lock", Some("bio".into())).unwrap().option.as_deref(), Some("bio"));
}
