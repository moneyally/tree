//! Settings sync between one account's own devices through its private
//! self group (APP_PROTOCOL.md 6.4), with two linked devices and a real
//! server: changes travel both ways, the last writer wins per setting,
//! per-device settings stay, locked settings stay locked, and no other
//! account can change them.

mod common;

use common::Env;
use tree_client::self_sync::SyncEntry;
use tree_client::{Event, LinkStatus, NewDevice, Payload, Session};
use tree_core::features::State;

fn code(s: &LinkStatus) -> String {
    match s {
        LinkStatus::Code { code } | LinkStatus::Confirmed { code } => code.clone(),
        other => panic!("no code: {other:?}"),
    }
}

/// Links a new device ("<name>-2") to `phone`, both people confirming.
fn link(env: &Env, phone: &mut Session, name: &str) -> Session {
    let mut nd: NewDevice = Session::start_link_new_device(&env.profile(&format!("{name}-2")), "second pw", name, &env.url).unwrap();
    phone.scan_link(&nd.link()).unwrap();
    let a = nd.poll().unwrap();
    assert_eq!(code(&a), code(&phone.link_status().unwrap()));
    phone.confirm_link(true).unwrap();
    nd.confirm(true).unwrap();
    assert!(matches!(phone.link_status().unwrap(), LinkStatus::Linked { .. }));
    assert!(matches!(nd.poll().unwrap(), LinkStatus::Linked { .. }));
    let mut desk = nd.finish().unwrap();
    // The welcome into the self group and the roster of its adder.
    desk.sync(0).unwrap();
    phone.sync(0).unwrap();
    desk.sync(0).unwrap();
    desk
}

fn synced_keys(ev: &[Event]) -> Vec<String> {
    ev.iter().flat_map(|e| if let Event::SettingsSynced { keys } = e { keys.clone() } else { vec![] }).collect()
}

fn state(s: &Session, k: &str) -> State {
    s.feature(k).unwrap().state
}

#[test]
fn settings_travel_between_own_devices_and_the_last_writer_wins() {
    let env = Env::new("selfsync");
    let mut phone = env.device("alice");
    let mut bob = env.device("bob");
    phone.add_contact(bob.account_id()).unwrap();
    let chat = phone.create_group().unwrap();
    phone.invite(&chat, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    // Set before the link: carried with the account data.
    phone.release_feature("user.read_receipts").unwrap();
    let mut desk = link(&env, &mut phone, "alice");
    let own = phone.self_group().unwrap().expect("made by the first link");
    assert_eq!(desk.self_group().unwrap().as_deref(), Some(own.as_slice()), "the id travels sealed with the account data");
    assert_eq!(state(&desk, "user.read_receipts"), State::Released);
    // The self group is never a chat.
    for s in [&phone, &desk] {
        assert!(!s.chat_list().unwrap().iter().any(|c| c.group == own), "hidden from the chat list");
    }
    assert!(desk.group_ids().unwrap().contains(&own), "but the desktop is in it");

    // Phone -> desktop: a user setting with its option, and chat-list choices.
    phone.release_feature("user.typing").unwrap();
    phone.apply_feature("user.group_add", Some("nobody".into())).unwrap();
    phone.mute_for(&chat, None).unwrap();
    phone.pin_chat(&chat, true).unwrap();
    phone.create_folder("work").unwrap();
    phone.sync(0).unwrap();
    let keys = synced_keys(&desk.sync(0).unwrap());
    for k in ["feature/user.typing", "feature/user.group_add", "muted", "pinned", "folders"] {
        assert!(keys.iter().any(|x| x == k), "{k} in {keys:?}");
    }
    assert_eq!(state(&desk, "user.typing"), State::Released);
    assert_eq!(desk.feature("user.group_add").unwrap().option.as_deref(), Some("nobody"));
    assert!(desk.is_muted(&chat).unwrap());
    assert_eq!(desk.pinned_chats().unwrap(), vec![chat.clone()]);
    assert!(desk.folders().unwrap().iter().any(|f| f.name == "work"));
    // Nothing echoes back.
    desk.sync(0).unwrap();
    assert!(synced_keys(&phone.sync(0).unwrap()).is_empty());

    // Desktop -> phone, including a release that has a local effect.
    desk.apply_feature("user.typing", None).unwrap();
    desk.release_feature("user.search_index").unwrap();
    assert!(!desk.search_index_status().unwrap().0);
    desk.mute(&chat, false).unwrap();
    desk.sync(0).unwrap();
    let keys = synced_keys(&phone.sync(0).unwrap());
    assert!(keys.contains(&"feature/user.typing".to_string()) && keys.contains(&"muted".to_string()), "{keys:?}");
    assert_eq!(state(&phone, "user.typing"), State::Applied);
    assert!(!phone.is_muted(&chat).unwrap());
    assert_eq!(state(&phone, "user.search_index"), State::Released);
    assert!(!phone.search_index_status().unwrap().0, "the phone deleted its index too");
    assert!(phone.search("x").is_err());

    // Both change the same setting before syncing: the later write wins on
    // both devices.
    phone.release_feature("user.link_preview").unwrap();
    phone.push_settings().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    desk.apply_feature("user.link_preview", None).unwrap();
    desk.release_feature("user.last_seen").unwrap(); // default already, no change
    desk.push_settings().unwrap();
    phone.sync(0).unwrap();
    desk.sync(0).unwrap();
    phone.sync(0).unwrap();
    assert_eq!(state(&phone, "user.link_preview"), State::Applied, "the desktop wrote last");
    assert_eq!(state(&desk, "user.link_preview"), State::Applied, "the phone's older write lost");

    // Per-device settings stay where they are.
    desk.apply_feature("user.app_lock", Some("pin".into())).unwrap();
    desk.sync(0).unwrap();
    phone.sync(0).unwrap();
    assert_eq!(state(&phone, "user.app_lock"), State::Released, "how a device unlocks is its own");
}

#[test]
fn only_own_devices_change_settings_and_locks_hold() {
    let env = Env::new("selfsync-guard");
    let mut phone = env.device("alice");
    let mut bob = env.device("bob");
    phone.add_contact(bob.account_id()).unwrap();
    bob.add_contact(phone.account_id()).unwrap();
    let shared = phone.create_group().unwrap();
    phone.invite(&shared, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    let mut desk = link(&env, &mut phone, "alice");
    let own = phone.self_group().unwrap().unwrap();

    let forged = |t: i64| Payload::Settings {
        s: vec![
            SyncEntry { k: "feature/user.read_receipts".into(), v: Some(tree_client::api::b64(br#"{"applied":false,"option":null}"#)), t },
            SyncEntry { k: "muted".into(), v: Some(tree_client::api::b64(br#"{}"#)), t },
        ],
    };
    // Another account, in a group both are in.
    bob.send_unchecked(&shared, &forged(i64::MAX / 2)).unwrap();
    let ev = phone.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains("own devices"))), "{ev:?}");
    assert!(synced_keys(&ev).is_empty());
    assert_eq!(state(&phone, "user.read_receipts"), State::Applied);
    // Another account, in a group of its own that the phone joins.
    let g2 = bob.create_group().unwrap();
    bob.invite(&g2, phone.account_id()).unwrap();
    phone.sync(0).unwrap();
    bob.send_unchecked(&g2, &forged(i64::MAX / 2)).unwrap();
    assert!(synced_keys(&phone.sync(0).unwrap()).is_empty());
    assert_eq!(state(&phone, "user.read_receipts"), State::Applied);

    // An own device cannot release a permanently locked setting either,
    // nor sync keys that are not settings.
    let locked = Payload::Settings {
        s: vec![
            SyncEntry { k: "feature/user.key_change_warning".into(), v: Some(tree_client::api::b64(br#"{"applied":false,"option":null}"#)), t: i64::MAX / 2 },
            SyncEntry { k: "server/auth_key".into(), v: Some(tree_client::api::b64(&[0u8; 32])), t: i64::MAX / 2 },
            SyncEntry { k: "feature/user.recovery_phrase".into(), v: Some(tree_client::api::b64(br#"{"applied":true,"option":null}"#)), t: i64::MAX / 2 },
        ],
    };
    desk.send_unchecked(&own, &locked).unwrap();
    assert!(synced_keys(&phone.sync(0).unwrap()).is_empty());
    assert_eq!(state(&phone, "user.key_change_warning"), State::Applied);
    assert_eq!(state(&phone, "user.recovery_phrase"), State::Released);
    // While the same device's ordinary setting is taken.
    desk.release_feature("user.read_receipts").unwrap();
    desk.sync(0).unwrap();
    assert_eq!(synced_keys(&phone.sync(0).unwrap()), vec!["feature/user.read_receipts".to_string()]);
    assert_eq!(state(&phone, "user.read_receipts"), State::Released);
}
