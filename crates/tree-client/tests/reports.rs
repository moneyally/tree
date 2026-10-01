//! Reporting with message franking (PROTOCOL.md 8.5), through a real server.

mod common;

use common::Env;
use reqwest::Method;
use tree_client::{Error, Event};

#[test]
fn franked_messages_can_be_reported_and_checked() {
    let env = Env::new("reports");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut carol = env.device("carol");
    bob.add_contact(alice.account_id()).unwrap();
    carol.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    alice.invite(&g, carol.account_id()).unwrap();
    bob.sync(0).unwrap();
    carol.sync(0).unwrap();
    bob.sync(0).unwrap();

    let id1 = alice.send_text(&g, "abusive text").unwrap();
    let id2 = alice.send_text(&g, "more of it").unwrap();
    let ev = bob.sync(0).unwrap();
    assert_eq!(ev.iter().filter(|e| matches!(e, Event::Text { .. })).count(), 2, "{ev:?}");
    let m = bob.history(&g, 10).unwrap().into_iter().find(|m| m.id == id1).unwrap();
    assert!(m.franking.is_some(), "received messages keep their franking record");
    // The sender keeps none for its own messages.
    assert!(alice.history(&g, 10).unwrap().iter().all(|m| m.franking.is_none()));

    let r = bob.report(&g, &[&id1, &id2], "harassment").unwrap();
    assert!(r.verified, "{r:?}");

    // An edit is franked too; the report covers the edited text.
    alice.edit(&g, &id1, "edited abuse").unwrap();
    bob.sync(0).unwrap();
    assert!(bob.report(&g, &[&id1], "harassment").unwrap().verified);

    // Not for own messages, mixed senders or unknown ids.
    let own = bob.send_text(&g, "mine").unwrap();
    carol.sync(0).unwrap();
    assert!(matches!(bob.report(&g, &[&own], "x"), Err(Error::Usage(_))));
    assert!(matches!(carol.report(&g, &[&id1, &own], "x"), Err(Error::Usage(_))));
    assert!(matches!(bob.report(&g, &["nope"], "x"), Err(Error::Usage(_))));
    assert!(matches!(bob.report(&g, &[], "x"), Err(Error::Usage(_))));
    // Carol reports bob's message: verified against bob, not alice.
    assert!(carol.report(&g, &[&own], "x").unwrap().verified);

    // A deleted message has no record left: reported, but unverified.
    alice.delete_for_all(&g, &id2).unwrap();
    bob.sync(0).unwrap();
    assert!(!bob.report(&g, &[&id2], "x").unwrap().verified);

    // The operator sees the reports with the reported text and suspends alice.
    let (st, v) = env.operator(Method::GET, "/v1/reports");
    assert_eq!(st, 200);
    let reports = v["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 4);
    let texts: Vec<String> = reports.iter().flat_map(|r| r["messages"].as_array().unwrap().iter().map(|m| m["payload"].as_str().unwrap().to_string())).collect();
    assert!(texts.iter().any(|t| t.contains("abusive text")) && texts.iter().any(|t| t.contains("edited abuse")), "{texts:?}");
    let (st, _) = env.operator(Method::POST, &format!("/v1/accounts/{}/suspend/apply", alice.account_id()));
    assert_eq!(st, 200);
    match alice.send_text(&g, "still here?") {
        Err(Error::Server { code, .. }) => assert_eq!(code, "SUSPENDED"),
        other => panic!("{other:?}"),
    }
    env.operator(Method::POST, &format!("/v1/accounts/{}/suspend/release", alice.account_id()));
    alice.send_text(&g, "back").unwrap();
}
