//! Key refresh schedule (PROTOCOL.md 6.9) through a real server.

mod common;

use common::Env;
use tree_client::refresh::RefreshPolicy;
use tree_client::Event;

fn changed(ev: &[Event]) -> usize {
    ev.iter().filter(|e| matches!(e, Event::Changed { .. })).count()
}

#[test]
fn refreshes_after_joining_with_traffic_and_on_demand() {
    let env = Env::new("refresh");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();

    // Default policy: a joiner waits at least a minute, so nothing happens yet.
    let mut carol = env.device("carol");
    carol.add_contact(alice.account_id()).unwrap();
    alice.invite(&g, carol.account_id()).unwrap();
    carol.sync(0).unwrap();
    assert!(!carol.refresh_due(&g).unwrap());
    let e = carol.epoch(&g).unwrap();
    carol.sync(0).unwrap();
    assert_eq!(carol.epoch(&g).unwrap(), e);

    // bob refreshes right after joining (his leaf key came from a key
    // package that waited on the server).
    bob.set_refresh_policy(RefreshPolicy { interval: 24 * 3600, join_delay_max: 0 });
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap(); // joins, then refreshes in the same sync
    let after_join = bob.epoch(&g).unwrap();
    assert!(!bob.refresh_due(&g).unwrap());
    assert_eq!(changed(&alice.sync(0).unwrap()), 1, "alice sees bob's refresh");
    assert_eq!(alice.epoch(&g).unwrap(), after_join);
    carol.sync(0).unwrap();

    // With traffic and the interval passed, the next sync refreshes.
    bob.set_refresh_policy(RefreshPolicy { interval: 1, join_delay_max: 0 });
    alice.send_text(&g, "hi").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2100));
    bob.sync(0).unwrap();
    assert_eq!(bob.epoch(&g).unwrap(), after_join + 1);
    // Without new traffic, no further refresh.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    bob.sync(0).unwrap();
    assert_eq!(bob.epoch(&g).unwrap(), after_join + 1);

    // A suspected compromise: every group at once.
    let g2 = bob.create_group().unwrap();
    let done = bob.refresh_all().unwrap();
    assert_eq!(done.len(), 2);
    assert!(done.contains(&g) && done.contains(&g2));
    assert_eq!(bob.epoch(&g).unwrap(), after_join + 2);
    alice.sync(0).unwrap();
    carol.sync(0).unwrap();
    // Everyone still agrees on the group state.
    let code = alice.verification_code(&g).unwrap();
    assert_eq!(bob.verification_code(&g).unwrap(), code);
    assert_eq!(carol.verification_code(&g).unwrap(), code);
    let id = carol.send_text(&g, "still here").unwrap();
    assert!(bob.sync(0).unwrap().iter().any(|e| matches!(e, Event::Text { id: i, .. } if *i == id)));
}
