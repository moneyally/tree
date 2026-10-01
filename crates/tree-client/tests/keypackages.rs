//! Key package supply (PROTOCOL.md 5.3): one-time packages topped up during
//! sync, and a last-resort package when they run out.

mod common;

use common::Env;
use tree_client::refresh::RefreshPolicy;
use tree_client::Event;

fn joined(ev: &[Event]) -> usize {
    ev.iter().filter(|e| matches!(e, Event::Joined { .. })).count()
}

#[test]
fn drained_device_can_still_be_added() {
    let env = Env::new("keypackages");
    let mut bob = env.device("bob");
    let mut alice = env.device("alice");
    let mut carol = env.device("carol");
    bob.add_contact(alice.account_id()).unwrap();
    bob.add_contact(carol.account_id()).unwrap();

    // Someone claimed all of bob's one-time key packages.
    let drained = env.sql("DELETE FROM key_packages WHERE device_id = ?", bob.device_id());
    assert_eq!(drained, tree_client::KEY_PACKAGES_TARGET as u64);
    let n = env.sql("UPDATE last_resort_key_packages SET data = data WHERE device_id = ?", bob.device_id());
    assert_eq!(n, 1, "uploaded at sign-up");

    // alice and carol both get the last-resort package and add bob.
    for adder in [&mut alice, &mut carol] {
        let g = adder.create_group().unwrap();
        adder.invite(&g, bob.account_id()).unwrap();
    }
    assert_eq!(joined(&bob.sync(0).unwrap()), 2);
    // That sync also topped the one-time packages up (joining triggers it).
    assert_eq!(env.sql("UPDATE key_packages SET data = data WHERE device_id = ?", bob.device_id()), tree_client::KEY_PACKAGES_TARGET as u64);
}

#[test]
fn sync_tops_up_and_rotates_last_resort() {
    let env = Env::new("kp-rotate");
    let mut bob = env.device("bob");
    let mut alice = env.device("alice");
    bob.add_contact(alice.account_id()).unwrap();
    let count = |env: &Env, bob: &tree_client::Session| env.sql("UPDATE key_packages SET data = data WHERE device_id = ?", bob.device_id());

    // Drained while bob is idle: the next sync does not check yet (checked
    // within the hour), then does once the check is due.
    env.sql("DELETE FROM key_packages WHERE device_id = ?", bob.device_id());
    bob.sync(0).unwrap();
    assert_eq!(count(&env, &bob), 0);
    bob.set_refresh_policy(RefreshPolicy { key_package_check: 0, ..Default::default() });
    bob.sync(0).unwrap();
    assert_eq!(count(&env, &bob), tree_client::KEY_PACKAGES_TARGET as u64);

    // Rotation: the previous last-resort package still opens welcomes
    // (they may be on their way), the one before it no longer does.
    bob.set_refresh_policy(RefreshPolicy { key_package_check: 1000, last_resort_rotate: 0, ..Default::default() });
    let first = env.last_resort(bob.device_id()).unwrap();
    bob.ensure_key_packages().unwrap();
    let second = env.last_resort(bob.device_id()).unwrap();
    assert_ne!(first, second);
    let mut add_with = |kp: &[u8]| {
        env.sql("DELETE FROM key_packages WHERE device_id = ?", bob.device_id());
        env.set_last_resort(bob.device_id(), kp);
        let g = alice.create_group().unwrap();
        alice.invite(&g, bob.account_id()).unwrap();
        joined(&bob.sync(0).unwrap()) // joining rotates again (rotate: 0)
    };
    assert_eq!(add_with(&first), 1, "previous generation still opens");
    // The join rotated: `second` is now the previous one, `first` is gone.
    assert_eq!(add_with(&first), 0, "forgotten");
    assert_eq!(add_with(&second), 1, "second is the previous generation now");
    assert_eq!(add_with(&second), 0, "and forgotten after the next rotation");
}
