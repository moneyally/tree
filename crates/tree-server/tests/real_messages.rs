//! The server's view of real Tree messages (made by tree-core, not by hand).

use tree_core::Client;
use tree_server::wire;

#[test]
fn real_commit_message_and_welcome() {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut g = alice.create_group().unwrap();
    let add = g.add(&alice, &[bob.key_package().unwrap()]).unwrap();

    let h = wire::envelope_header(&add.commit).unwrap();
    assert_eq!((h.group_id, h.epoch, h.content_type), (g.id().as_slice(), 0, wire::COMMIT));
    let welcome = add.welcome.unwrap();
    assert!(wire::is_welcome(&welcome));
    assert!(wire::envelope_header(&welcome).is_err());
    assert!(!wire::is_welcome(&add.commit));

    g.confirm_commit(&alice).unwrap();
    let m = g.send(&alice, b"hi").unwrap();
    let h = wire::envelope_header(&m).unwrap();
    assert_eq!((h.group_id, h.epoch, h.content_type), (g.id().as_slice(), 1, wire::APPLICATION));
    let r = g.refresh_keys(&alice).unwrap();
    let h = wire::envelope_header(&r.commit).unwrap();
    assert_eq!((h.epoch, h.content_type), (1, wire::COMMIT));
}
