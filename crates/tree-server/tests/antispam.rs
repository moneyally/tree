//! Limits for new accounts and for accounts with verified reports
//! (design: "new accounts cannot mass-send; accounts with accumulating spam
//! reports are limited automatically"). Both are operator flags with
//! apply/release.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use tree_server::features::{set_applied, NEW_ACCOUNT_LIMITS};

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

async fn many(api: &Api, n: usize) -> Vec<Device> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(api.signup().await);
    }
    v
}

#[tokio::test]
async fn new_accounts_cannot_mass_send() {
    let ts = boot(|c| {
        c.rate_per_sec = 0.001;
        c.rate_burst = 60.0;
    })
    .await;
    let db = &ts.server.state.db;
    set_applied(db, NEW_ACCOUNT_LIMITS, true).await.unwrap();
    let api = &ts.api;
    let a = api.signup().await;
    let targets = many(api, 51).await;
    let ids: Vec<&str> = targets.iter().map(|d| d.device_id.as_str()).collect();
    let (st, v) = api.send_raw(&a, &ids, &app(b"spam")).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LIMITED"), "{v}");
    assert_eq!(api.send_raw(&a, &ids[..50], &app(b"hi")).await.0, StatusCode::OK, "50 is fine");
    // Outreach costs five times: 5 per send; 60 tokens - 1 (refused) - 5 = 54 left.
    for _ in 0..10 {
        assert_eq!(api.send_raw(&a, &ids[..1], &app(b"x")).await.0, StatusCode::OK);
    }
    assert_eq!(api.send_raw(&a, &ids[..1], &app(b"x")).await.0, StatusCode::TOO_MANY_REQUESTS);

    // Older accounts are not limited.
    let old = api.signup().await;
    sqlx::query("UPDATE accounts SET created_day = created_day - 2 WHERE id = ?").bind(&old.account_id).execute(db).await.unwrap();
    assert_eq!(api.send_raw(&old, &ids, &app(b"newsletter")).await.0, StatusCode::OK);

    // The operator can release the limit.
    let b = api.signup().await;
    set_applied(db, NEW_ACCOUNT_LIMITS, false).await.unwrap();
    assert_eq!(api.send_raw(&b, &ids, &app(b"ok")).await.0, StatusCode::OK);
    ts.stop().await;
}

#[tokio::test]
async fn accounts_with_verified_reports_are_limited() {
    let ts = boot(|_| {}).await;
    let db = &ts.server.state.db;
    let api = &ts.api;
    let spammer = api.signup().await;
    let targets = many(api, 25).await;
    let ids: Vec<&str> = targets.iter().map(|d| d.device_id.as_str()).collect();
    let insert = |reporter: String, verified: bool| {
        sqlx::query("INSERT INTO reports (id, reported_account, reporter_account, reason, messages, verified, created_day) VALUES (?, ?, ?, 'spam', '[]', ?, ?)")
            .bind(tree_server::util::new_id())
            .bind(spammer.account_id.clone())
            .bind(reporter)
            .bind(verified)
            .bind(tree_server::util::today())
            .execute(db)
    };
    // Two reporters, or unverified reports, or the same reporter twice: not yet.
    insert(targets[0].account_id.clone(), true).await.unwrap();
    insert(targets[0].account_id.clone(), true).await.unwrap();
    insert(targets[1].account_id.clone(), true).await.unwrap();
    insert(targets[2].account_id.clone(), false).await.unwrap();
    assert_eq!(api.send_raw(&spammer, &ids, &app(b"x")).await.0, StatusCode::OK);
    // A third distinct reporter with a verified report: limited to 20 devices.
    insert(targets[3].account_id.clone(), true).await.unwrap();
    let (st, v) = api.send_raw(&spammer, &ids, &app(b"x")).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LIMITED"));
    assert_eq!(api.send_raw(&spammer, &ids[..20], &app(b"x")).await.0, StatusCode::OK);
    // Reports older than a week no longer count.
    sqlx::query("UPDATE reports SET created_day = created_day - 8").execute(db).await.unwrap();
    assert_eq!(api.send_raw(&spammer, &ids, &app(b"x")).await.0, StatusCode::OK);
    // Commits are limited too (a new group with many people).
    sqlx::query("UPDATE reports SET created_day = created_day + 8").execute(db).await.unwrap();
    let body = json!({
        "group_id": b64(&[7u8; 16]), "epoch": 0,
        "recipients": ids, "body": b64(&commit(&[7u8; 16], 0, b"c")),
    });
    let (st, v) = api.call(&spammer, Method::POST, "/v1/commits", Some(body)).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LIMITED"), "{v}");
    // Exactly the limit is allowed.
    let body = json!({
        "group_id": b64(&[7u8; 16]), "epoch": 0,
        "recipients": ids[..20], "body": b64(&commit(&[7u8; 16], 0, b"c")),
    });
    let (st, v) = api.call(&spammer, Method::POST, "/v1/commits", Some(body)).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    ts.stop().await;
}
