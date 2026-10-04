    let (alice, bob, mut a, mut b) = two_person_chat();
    let msgs: Vec<Vec<u8>> = (0..3)
        .map(|i| b.send(&bob, format!("e1 m{i}").as_bytes()).unwrap())
        .collect();
    a.refresh_now(&alice).unwrap(); // epoch 2: epoch 1 is N-1
    assert!(is_message(&a.receive(&alice, &msgs[0]), b"e1 m0"));
    a.refresh_now(&alice).unwrap(); // epoch 3: epoch 1 is N-2
    assert!(is_message(&a.receive(&alice, &msgs[1]), b"e1 m1"));
    a.refresh_now(&alice).unwrap(); // epoch 4: epoch 1 is N-3
    assert!(rejected_with(&a.receive(&alice, &msgs[2]), "seal"));
}

/// The sender of a past-epoch message is named by the members of THAT epoch,
/// even if its leaf now belongs to someone else.
#[test]
fn past_epoch_sender_is_the_member_of_that_epoch() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let eve = Client::new("eve").unwrap();
    let add = a.add_now(&alice, &eve.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut e = eve.join(&add.welcome).unwrap();
    let from_eve = e.send(&eve, b"eve, epoch 2").unwrap();
    // Eve (leaf 2) is removed, dave takes leaf 2.
    a.remove_now(&alice, &[eve.member_id()]).unwrap();
    let dave = Client::new("dave").unwrap();
    a.add_now(&alice, &dave.key_package().unwrap()).unwrap();
    assert_eq!(a.epoch(), 4);
    match a.receive(&alice, &from_eve).unwrap() {
        Incoming::Message { from, name, .. } => {
            assert_eq!(from, eve.member_id());
            assert_eq!(name, "eve");
        }
        other => panic!("{other:?}"),
    }
}

/// A message sealed in epoch N+1 delivered before the commit that creates
/// N+1 is refused (the receiver cannot verify it yet) and is NOT consumed:
/// after the commit arrives, the same bytes are readable.
#[test]
fn message_from_next_epoch_before_commit() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let c = a.refresh_now(&alice).unwrap();
    let early = a.send(&alice, b"epoch 2 message").unwrap();
    assert_eq!(
        b.receive(&bob, &early).unwrap(),
        Incoming::HeldForRetry { epoch: 2 }
    );
    assert_eq!(
        b.receive(&bob, &early).unwrap(),
        Incoming::HeldForRetry { epoch: 2 }
    );
    b.receive(&bob, &c).unwrap();
    let retried = b.retry_held(&bob).unwrap();
    assert_eq!(
        retried,
        vec![Incoming::Message {
            from: alice.member_id(),
            name: "alice".into(),
            body: b"epoch 2 message".to_vec()
        }]
    );
    assert!(b.retry_held(&bob).unwrap().is_empty());
}

/// A removed member's messages of the epoch before its removal stay readable
/// inside the past-epoch window: they are valid epoch-N messages. This
/// includes messages its client creates AFTER the removal if it ignores the
/// removal and keeps sending in epoch N (PROTOCOL.md 6.6, claim C11). Once
/// that epoch leaves the window, nothing from it is accepted.
#[test]
fn removed_members_old_epoch_messages() {
    let (alice, bob, mut a, mut b) = two_person_chat();
    let eve = Client::new("eve").unwrap();
    let add = a.add_now(&alice, &eve.key_package().unwrap()).unwrap();
    b.receive(&bob, &add.commit).unwrap();
    let mut e = eve.join(&add.welcome).unwrap();

    let early = e.send(&eve, b"before removal (1)").unwrap();
    let late = e.send(&eve, b"before removal (2)").unwrap();
    assert!(is_message(&b.receive(&bob, &early), b"before removal (1)"));

    let rm = a.remove_now(&alice, &[eve.member_id()]).unwrap();
    assert!(is_message(&a.receive(&alice, &late), b"before removal (2)"));
    b.receive(&bob, &rm).unwrap();
    assert!(is_message(&b.receive(&bob, &late), b"before removal (2)"));
    // Eve's client ignores the removal and keeps sending in epoch 2.
    let after = e.send(&eve, b"after removal").unwrap();
    assert!(is_message(&b.receive(&bob, &after), b"after removal"));
    // Two more epochs and epoch 2 has left the window.