//! Real end-to-end Tree flow: two/three core clients through the real HTTP server.
//!
//! This test deliberately crosses the same boundary production clients use:
//! MLS bytes are produced by tree-core, authenticated HTTP is used for
//! transport, and tree-core consumes only the returned ciphertext.

mod common;

use common::*;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use reqwest::{Method, StatusCode};
use serde_json::json;
use tree_core::{Client, Incoming};

#[tokio::test]
async fn real_clients_chat_through_server_and_removed_device_is_locked_out() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;

    // Transport identities (what the server authenticates).
    let alice_net = api.signup().await;
    let bob_net = api.signup().await;
    let charlie_net = api.signup().await;

    // MLS identities (what peers authenticate end-to-end).
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let charlie = Client::new("charlie").unwrap();

    // Bob publishes a real one-time key package. Alice claims it from the
    // server just like a production client would.
    let bob_kp = bob.key_package().unwrap();
    let (st, body) = api.upload(&bob_net, &[bob_kp]).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let (st, body) = api.claim(&alice_net, &bob_net.account_id).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claimed = unb64(body["key_packages"][0]["key_package"].as_str().unwrap());

    let mut a = alice.create_group().unwrap();
    let pending = a.add(&alice, &[claimed]).unwrap();
    assert_eq!(pending.epoch, 0);

    // Commit + welcome travel in one authenticated request.
    let commit_body = json!({
        "group_id": b64(&pending.group_id),
        "epoch": pending.epoch,
        "recipients": [],
        "body": b64(&pending.commit),
        "added": [bob_net.device_id],
        "welcome": STANDARD.encode(pending.welcome.as_ref().unwrap()),
        "removed": []
    });
    let (st, v) = api.call(
        &alice_net,
        Method::POST,
        "/v1/commits",
        Some(commit_body),
    ).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    a.confirm_commit(&alice).unwrap();
    let mut b = bob.join(pending.welcome.as_ref().unwrap()).unwrap();

    // Alice -> server -> Bob. The server sees only the Tree envelope bytes.
    let plaintext = b"hello through the real Tree server";
    let ciphertext = a.send(&alice, plaintext).unwrap();
    assert_ne!(ciphertext, plaintext);
    let (st, v) = api.send_raw(&alice_net, &[bob_net.device_id.as_str()], &ciphertext).await;
    assert_eq!(st, StatusCode::OK, "{v}");

    let queued = api.fetch(&bob_net, 0).await;
    assert_eq!(queued.len(), 1);
    let received = unb64(queued[0]["body"].as_str().unwrap());
    match b.receive(&bob, &received).unwrap() {
        Incoming::Message { body, .. } => assert_eq!(body, plaintext),
        other => panic!("expected message, got {other:?}"),
    }
    let id = queued[0]["id"].as_str().unwrap();
    let (st, _) = api.ack(&bob_net, &[id]).await;
    assert_eq!(st, StatusCode::OK);

    // The server blob never contains the plaintext as a contiguous byte
    // sequence. This is a regression guard for accidental server decryption.
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT body FROM blobs ORDER BY id DESC LIMIT 1"
    )
    .fetch_one(&ts.server.state.db)
    .await
    .unwrap();
    assert!(!stored.windows(plaintext.len()).any(|w| w == plaintext));

    // Charlie is added. Bob receives the commit, then Charlie joins from the
    // welcome. This exercises real multi-member MLS traffic.
    let charlie_kp = charlie.key_package().unwrap();
    let (st, v) = api.upload(&charlie_net, &[charlie_kp]).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let (st, v) = api.claim(&alice_net, &charlie_net.account_id).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let charlie_kp = unb64(v["key_packages"][0]["key_package"].as_str().unwrap());

    let p2 = a.add(&alice, &[charlie_kp]).unwrap();
    let body = json!({
        "group_id": b64(&p2.group_id),
        "epoch": p2.epoch,
        "recipients": [bob_net.device_id],
        "body": b64(&p2.commit),
        "added": [charlie_net.device_id],
        "welcome": b64(p2.welcome.as_ref().unwrap()),
        "removed": []
    });
    let (st, v) = api.call(&alice_net, Method::POST, "/v1/commits", Some(body)).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    a.confirm_commit(&alice).unwrap();

    let bob_msgs = api.fetch(&bob_net, 0).await;
    assert_eq!(bob_msgs.len(), 1);
    assert!(matches!(
        b.receive(&bob, &unb64(bob_msgs[0]["body"].as_str().unwrap())).unwrap(),
        Incoming::GroupChanged {
            epoch: 2,
            own_commit_discarded: false,
            ..
        }
    ));
    api.ack(&bob_net, &[bob_msgs[0]["id"].as_str().unwrap()]).await;

    let mut c = charlie.join(p2.welcome.as_ref().unwrap()).unwrap();
    let cmsg = c.send(&charlie, b"charlie is here").unwrap();
    let (st, v) = api.send_raw(
        &charlie_net,
        &[alice_net.device_id.as_str(), bob_net.device_id.as_str()],
        &cmsg,
    ).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    for dev in [&alice_net, &bob_net] {
        let msgs = api.fetch(dev, 0).await;
        assert_eq!(msgs.len(), 1);
        let recv = if dev.device_id == alice_net.device_id { a.receive(&alice, &unb64(msgs[0]["body"].as_str().unwrap())).unwrap() }
                   else { b.receive(&bob, &unb64(msgs[0]["body"].as_str().unwrap())).unwrap() };
        match recv {
            Incoming::Message { body, .. } => assert_eq!(body, b"charlie is here"),
            other => panic!("expected chat message, got {other:?}"),
        }
        api.ack(dev, &[msgs[0]["id"].as_str().unwrap()]).await;
    }

    // Remove Bob. The removal commit must reach Bob even though the server
    // removes Bob from the eligible set in the same transaction.
    let bob_member_id = bob.member_id();
    let p3 = a.remove(&alice, &[bob_member_id]).unwrap();
    let body = json!({
        "group_id": b64(&p3.group_id),
        "epoch": p3.epoch,
        "recipients": [bob_net.device_id, charlie_net.device_id],
        "body": b64(&p3.commit),
        "added": [],
        "removed": [bob_net.device_id]
    });
    let (st, v) = api.call(&alice_net, Method::POST, "/v1/commits", Some(body)).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    a.confirm_commit(&alice).unwrap();

    let bob_msgs = api.fetch(&bob_net, 0).await;
    assert_eq!(bob_msgs.len(), 1);
    assert_eq!(
        b.receive(&bob, &unb64(bob_msgs[0]["body"].as_str().unwrap())).unwrap(),
        Incoming::RemovedFromGroup
    );
    api.ack(&bob_net, &[bob_msgs[0]["id"].as_str().unwrap()]).await;

    // After the removal Bob cannot decrypt future application messages.
    let secret = a.send(&alice, b"only Alice and Charlie").unwrap();
    let (st, v) = api.send_raw(&alice_net, &[charlie_net.device_id.as_str()], &secret).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert!(b.receive(&bob, &secret).is_err());

    let c_msgs = api.fetch(&charlie_net, 0).await;
    assert_eq!(c_msgs.len(), 1);
    match c.receive(&charlie, &unb64(c_msgs[0]["body"].as_str().unwrap())).unwrap() {
        Incoming::Message { body, .. } => assert_eq!(body, b"only Alice and Charlie"),
        other => panic!("expected message, got {other:?}"),
    }

    ts.stop().await;
}
