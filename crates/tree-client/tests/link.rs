//! Device linking with a two-sided confirmation code (PROTOCOL.md 8.11),
//! through a real server.

mod common;

use common::Env;
use reqwest::Method;
use serde_json::json;
use tree_client::{Error, Event, GroupStatus, LinkStatus, NewDevice, Session};
use tree_core::link::Invitation;

fn code(s: &LinkStatus) -> String {
    match s {
        LinkStatus::Code { code } | LinkStatus::Confirmed { code } => code.clone(),
        other => panic!("no code: {other:?}"),
    }
}

fn texts(ev: &[Event]) -> Vec<String> {
    ev.iter().filter_map(|e| if let Event::Text { text, .. } = e { Some(text.clone()) } else { None }).collect()
}

fn start(env: &Env, name: &str) -> NewDevice {
    Session::start_link_new_device(&env.profile(name), "desktop pw", name, &env.url).unwrap()
}

fn link_id(link: &str) -> String {
    Invitation::parse(link).unwrap().link_id_text()
}

/// alice (phone) and bob share a group; alice links a desktop.
fn setup(env: &Env) -> (Session, Session, Vec<u8>) {
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    alice.add_contact(bob.account_id()).unwrap();
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();
    alice.send_text(&g, "before the desktop").unwrap();
    bob.sync(0).unwrap();
    (alice, bob, g)
}

/// Runs a link to the end, both people confirming. Returns the new session.
fn link(alice: &mut Session, mut nd: NewDevice) -> (Session, LinkStatus) {
    assert_eq!(nd.poll().unwrap(), LinkStatus::Waiting, "nothing before the scan");
    assert_eq!(alice.scan_link(&nd.link()).unwrap(), LinkStatus::Waiting, "no code before the reveal");
    let on_new = nd.poll().unwrap();
    let on_old = alice.link_status().unwrap();
    assert_eq!(code(&on_new), code(&on_old), "both devices show the same code");
    assert!(matches!(alice.confirm_link(true).unwrap(), LinkStatus::Confirmed { .. }), "one side alone links nothing");
    assert_eq!(alice.devices().unwrap().len(), 1);
    assert!(matches!(nd.confirm(true).unwrap(), LinkStatus::Confirmed { .. }));
    let done = alice.link_status().unwrap();
    assert!(matches!(&done, LinkStatus::Linked { .. }), "{done:?}");
    assert!(matches!(nd.poll().unwrap(), LinkStatus::Linked { .. }));
    (nd.finish().unwrap(), done)
}

#[test]
fn linked_desktop_gets_the_account_and_chats_in_existing_groups() {
    let env = Env::new("link-happy");
    let (mut alice, mut bob, g) = setup(&env);
    alice.set_username("alice_link").unwrap();
    alice.apply_feature("user.typing", None).unwrap();
    alice.release_feature("user.read_receipts").unwrap();
    let notes = alice.note_to_self().unwrap();

    let (mut desk, done) = link(&mut alice, start(&env, "alice-desktop"));
    let LinkStatus::Linked { device_id, missed_groups } = done else { unreachable!() };
    assert!(missed_groups.is_empty(), "{missed_groups:?}");
    assert_eq!(desk.account_id(), alice.account_id());
    assert_eq!(desk.device_id(), device_id);
    assert_eq!(alice.devices().unwrap().len(), 2);
    // Account data came along, sealed to the new device.
    assert_eq!(desk.username().unwrap().as_deref(), Some("alice_link"));
    assert!(desk.contacts().unwrap().iter().any(|c| c.account == bob.account_id() && c.accepted));
    assert!(!desk.feature("user.read_receipts").unwrap().state.eq(&tree_core::features::State::Applied));

    // The desktop is in the existing group, accepted (its own account added
    // it), and an admin like the phone.
    let ev = desk.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Joined { group } if *group == g)), "{ev:?}");
    // The notes chat is shared by the account's devices.
    assert_eq!(desk.note_to_self().unwrap(), notes);
    assert_eq!(desk.group_status(&g).unwrap(), GroupStatus::Accepted);
    assert!(desk.group_settings(&g).unwrap().admins.contains(&desk.member_id()));
    // bob sees a new device of alice's account (a key change to compare).
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::KeyChanged { account, .. } if account == alice.account_id())), "{ev:?}");

    // Messages flow both ways, with all three devices.
    desk.send_text(&g, "from the desktop").unwrap();
    assert_eq!(texts(&bob.sync(0).unwrap()), vec!["from the desktop"]);
    assert_eq!(texts(&alice.sync(0).unwrap()), vec!["from the desktop"]);
    bob.send_text(&g, "hello both").unwrap();
    assert_eq!(texts(&desk.sync(0).unwrap()), vec!["hello both"]);
    assert_eq!(texts(&alice.sync(0).unwrap()), vec!["hello both"]);

    // The new device keeps working after a restart.
    let path = env.profile("alice-desktop");
    drop(desk);
    let (mut desk, _) = Session::open(&path, "desktop pw").unwrap();
    alice.send_text(&g, "still there?").unwrap();
    assert_eq!(texts(&desk.sync(0).unwrap()), vec!["still there?"]);

    // The lock stays: device links always need the code.
    assert!(matches!(alice.release_feature("user.device_link_code"), Err(Error::Feature(_))));
}

#[test]
fn a_relay_that_swaps_a_key_gets_different_codes_and_links_nothing() {
    let env = Env::new("link-mitm");
    let (mut alice, _bob, _g) = setup(&env);
    let mut nd = start(&env, "alice-desktop");
    let text = nd.link();
    alice.scan_link(&text).unwrap();
    // The server swaps the existing device's HPKE key for its own on the
    // way to the new device.
    let id = link_id(&text);
    let offer = env.sql_blob("SELECT offer FROM link_sessions WHERE link_id = ?", &id).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&offer).unwrap();
    v["hpke_pub"] = json!(tree_core::link::b64url(&tree_core::link::HpkeKey::generate().public()));
    assert_eq!(env.sql_set_blob("UPDATE link_sessions SET offer = ? WHERE link_id = ?", &serde_json::to_vec(&v).unwrap(), &id), 1);

    let c_new = code(&nd.poll().unwrap());
    let c_old = code(&alice.link_status().unwrap());
    assert_ne!(c_new, c_old, "the person sees two different codes");
    // Even if the person confirms anyway on both, nothing is linked.
    nd.confirm(true).unwrap();
    let st = alice.confirm_link(true).unwrap();
    assert!(matches!(&st, LinkStatus::Cancelled { reason } if reason.contains("different")), "{st:?}");
    assert_eq!(alice.devices().unwrap().len(), 1);
    assert!(matches!(nd.poll().unwrap(), LinkStatus::Cancelled { .. }));
    assert!(!std::path::Path::new(&env.profile("alice-desktop")).exists(), "the half-made profile is gone");
}

#[test]
fn a_swapped_reveal_breaks_the_commitment() {
    let env = Env::new("link-reveal");
    let (mut alice, _bob, _g) = setup(&env);
    let mut nd = start(&env, "alice-desktop");
    let text = nd.link();
    alice.scan_link(&text).unwrap();
    nd.poll().unwrap();
    // The server replaces the revealed nonce (to steer the code).
    let id = link_id(&text);
    let reveal = env.sql_blob("SELECT reveal FROM link_sessions WHERE link_id = ?", &id).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&reveal).unwrap();
    v["nonce"] = json!(tree_core::link::b64url(&[7u8; 32]));
    env.sql_set_blob("UPDATE link_sessions SET reveal = ? WHERE link_id = ?", &serde_json::to_vec(&v).unwrap(), &id);
    assert!(matches!(alice.link_status().unwrap(), LinkStatus::Cancelled { .. }));
    assert!(matches!(nd.poll().unwrap(), LinkStatus::Cancelled { .. }));
    assert_eq!(alice.devices().unwrap().len(), 1);
}

/// F-020: the key packages are committed in the invitation. A server that
/// reorders, repeats or substitutes them after the reveal (to steer the
/// existing device's code toward the one the new device shows for an offer
/// of its own) gets the link cancelled before any code is shown.
#[test]
fn a_reordered_repeated_or_substituted_key_package_list_is_refused() {
    let tamper: [(&str, fn(&mut Vec<serde_json::Value>, serde_json::Value)); 4] = [
        ("swap", |k, _| k.swap(0, 1)),
        ("repeat", |k, _| k[1] = k[0].clone()),
        ("substitute", |k, other| k[2] = other),
        ("drop", |k, _| {
            k.remove(3);
        }),
    ];
    for (what, f) in tamper {
        let env = Env::new(&format!("link-kps-{what}"));
        let (mut alice, _bob, _g) = setup(&env);
        // Another device's valid key package, for the substitution.
        let other = tree_core::Client::new("other").unwrap();
        let foreign = json!(tree_core::link::b64url(&other.key_package().unwrap()));
        let mut nd = start(&env, "alice-desktop");
        let text = nd.link();
        alice.scan_link(&text).unwrap();
        assert!(matches!(nd.poll().unwrap(), LinkStatus::Code { .. }));
        let id = link_id(&text);
        let reveal = env.sql_blob("SELECT reveal FROM link_sessions WHERE link_id = ?", &id).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&reveal).unwrap();
        let mut kps = v["key_packages"].as_array().unwrap().clone();
        assert_eq!(kps.len(), 9, "8 one-time key packages and the last-resort one");
        f(&mut kps, foreign);
        v["key_packages"] = json!(kps);
        env.sql_set_blob("UPDATE link_sessions SET reveal = ? WHERE link_id = ?", &serde_json::to_vec(&v).unwrap(), &id);
        let st = alice.link_status().unwrap();
        assert!(matches!(&st, LinkStatus::Cancelled { reason } if reason.contains("does not match")), "{what}: {st:?}");
        assert!(matches!(nd.poll().unwrap(), LinkStatus::Cancelled { .. }), "{what}");
        assert_eq!(alice.devices().unwrap().len(), 1, "{what}");
    }
}

#[test]
fn refusing_on_either_device_links_nothing() {
    let env = Env::new("link-refuse");
    let (mut alice, _bob, _g) = setup(&env);

    // The new device says no.
    let mut nd = start(&env, "d1");
    alice.scan_link(&nd.link()).unwrap();
    nd.poll().unwrap();
    alice.link_status().unwrap();
    assert!(matches!(nd.confirm(false).unwrap(), LinkStatus::Cancelled { .. }));
    assert!(!std::path::Path::new(&env.profile("d1")).exists());
    // A "match" on the existing device afterwards links nothing either.
    assert!(matches!(alice.confirm_link(true).unwrap(), LinkStatus::Cancelled { .. }));
    assert!(matches!(alice.link_status(), Err(Error::Usage(_))));
    assert_eq!(alice.devices().unwrap().len(), 1);

    // The existing device says no, after the new one confirmed.
    let mut nd = start(&env, "d2");
    alice.scan_link(&nd.link()).unwrap();
    nd.poll().unwrap();
    alice.link_status().unwrap();
    nd.confirm(true).unwrap();
    assert!(matches!(alice.confirm_link(false).unwrap(), LinkStatus::Cancelled { .. }));
    assert!(matches!(nd.poll().unwrap(), LinkStatus::Cancelled { .. }));
    assert_eq!(alice.devices().unwrap().len(), 1);
    assert!(matches!(alice.link_status(), Err(Error::Usage(_))));
}

#[test]
fn expired_and_reused_links_are_refused() {
    let env = Env::new("link-expiry");
    let (mut alice, mut bob, _g) = setup(&env);

    let mut nd = start(&env, "late");
    let text = nd.link();
    alice.scan_link(&text).unwrap();
    nd.poll().unwrap();
    assert_eq!(env.sql("UPDATE link_sessions SET expires_at = 0 WHERE link_id = ?", &link_id(&text)), 1);
    assert!(matches!(nd.poll().unwrap(), LinkStatus::Cancelled { reason } if reason.contains("expired")));
    assert!(matches!(alice.link_status().unwrap(), LinkStatus::Cancelled { .. }));
    // Scanning it again: the link id is used up.
    assert!(matches!(alice.scan_link(&text), Err(Error::Server { status: 409, .. })));

    // A finished link cannot be used again, by the same or another account.
    let nd = start(&env, "desk");
    let text = nd.link();
    let (_desk, _) = link(&mut alice, nd);
    assert!(matches!(alice.scan_link(&text), Err(Error::Server { status: 409, .. })));
    assert!(matches!(bob.scan_link(&text), Err(Error::Server { status: 409, .. })));
    assert_eq!(bob.devices().unwrap().len(), 1);
    // Garbage is not a link.
    assert!(bob.scan_link("tree://join/abc").is_err());
}

#[test]
fn the_server_cannot_add_the_device_without_the_existing_devices_signature() {
    let env = Env::new("link-sig");
    let (mut alice, bob, _g) = setup(&env);
    let mut nd = start(&env, "desk");
    let text = nd.link();
    alice.scan_link(&text).unwrap();
    nd.poll().unwrap();
    alice.link_status().unwrap();
    nd.confirm(true).unwrap();
    let id = link_id(&text);
    let path = format!("/v1/links/{id}/complete");
    let (api, creds) = alice.waiter();
    let st = api.request(&creds.key, &creds.device_id, Method::GET, &format!("/v1/links/{id}"), None).unwrap();
    let hash = st.body["transcript_hash"].as_str().unwrap().to_string();
    let call = |sig: &[u8], h: &str| {
        let body = json!({ "transcript_hash": h, "signature": tree_client::api::b64(sig), "sealed": tree_client::api::b64(b"x") });
        api.request(&creds.key, &creds.device_id, Method::POST, &path, Some(&body)).unwrap()
    };
    // No valid authorisation: refused.
    let r = call(&[0u8; 64], &hash);
    assert_eq!((r.status.as_u16(), r.code()), (403, "LINK_SIGNATURE"));
    // A signature over another hash than the one the new device confirmed.
    let r = call(&[0u8; 64], &tree_client::api::b64(&[1u8; 32]));
    assert_eq!((r.status.as_u16(), r.code()), (403, "TRANSCRIPT_MISMATCH"));
    // Another account cannot complete it.
    let (bapi, bcreds) = bob.waiter();
    let r = bapi
        .request(&bcreds.key, &bcreds.device_id, Method::POST, &path, Some(&json!({ "transcript_hash": hash, "signature": tree_client::api::b64(&[0u8; 64]), "sealed": "eA==" })))
        .unwrap();
    assert_eq!(r.status.as_u16(), 404);
    // The old way of adding a device with no link is gone.
    let r = api.request(&creds.key, &creds.device_id, Method::POST, "/v1/devices", Some(&json!({ "auth_pub": "", "proof": "" }))).unwrap();
    assert_eq!((r.status.as_u16(), r.code()), (410, "LINK_REQUIRED"));
    assert_eq!(alice.devices().unwrap().len(), 1, "nothing was added");

    // With the person's confirmation the real device signs, and it works.
    assert!(matches!(alice.confirm_link(true).unwrap(), LinkStatus::Linked { .. }));
    assert!(matches!(nd.poll().unwrap(), LinkStatus::Linked { .. }));
    assert_eq!(alice.devices().unwrap().len(), 2);
}

#[test]
fn removing_a_linked_device_takes_it_out_of_its_groups() {
    let env = Env::new("link-remove");
    let (mut alice, mut bob, g) = setup(&env);
    // A group of bob's where alice is not an admin.
    let g2 = bob.create_group().unwrap();
    bob.invite(&g2, alice.account_id()).unwrap();
    alice.sync(0).unwrap();

    let (mut desk, _) = link(&mut alice, start(&env, "desk"));
    desk.sync(0).unwrap();
    bob.sync(0).unwrap();
    let dm = desk.member_id();
    assert!(bob.members(&g).unwrap().iter().any(|m| m.id == dm));
    assert!(bob.members(&g2).unwrap().iter().any(|m| m.id == dm), "a member may add its own new device");

    // alice is an admin of g (removed by commit), not of g2 (asks bob).
    let asked = alice.remove_device(desk.device_id()).unwrap();
    assert_eq!(asked, vec![g2.clone()]);
    let ev = bob.sync(0).unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::RemoveDeviceRequested { group, member, .. } if *group == g2 && *member == dm)), "{ev:?}");
    assert!(!bob.members(&g).unwrap().iter().any(|m| m.id == dm), "gone from g");
    bob.remove(&g2, &[dm]).unwrap();
    assert!(!bob.members(&g2).unwrap().iter().any(|m| m.id == dm));
    assert_eq!(alice.devices().unwrap().len(), 1);
    assert!(matches!(desk.sync(0), Err(Error::Server { status: 401, .. })), "cut off on the server");
    // The rest keep talking.
    bob.send_text(&g, "just us").unwrap();
    assert_eq!(texts(&alice.sync(0).unwrap()), vec!["just us"]);
    let own = alice.device_id().to_string();
    assert!(alice.remove_device(&own).is_err());
}
