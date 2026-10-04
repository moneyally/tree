//! Commit ordering (PROTOCOL.md 7.4): first commit per (group, epoch) wins.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

const G: [u8; 16] = [0x31; 16];

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

async fn submit(api: &Api, dev: &Device, req: Value) -> (StatusCode, Value) {
    api.call(dev, Method::POST, "/v1/commits", Some(req)).await
}

fn req(epoch: u64, tag: &[u8], recipients: &[&Device]) -> Value {
    json!({
        "group_id": b64(&G),
        "epoch": epoch,
        "recipients": recipients.iter().map(|d| d.device_id.clone()).collect::<Vec<_>>(),
        "body": b64(&commit(&G, epoch, tag)),
    })
}

fn sha_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

#[tokio::test]
async fn first_commit_wins_and_retry_is_idempotent() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (a, b, c) = (api.signup().await, api.signup().await, api.signup().await);

    // a adds c in epoch 0; b is already a member (recipient).
    let mut r = req(0, b"a0", &[&b]);
    r["added"] = json!([c.device_id]);
    r["welcome"] = json!(b64(&welcome(b"for c")));
    let (st, v) = submit(api, &a, r.clone()).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["accepted"].as_bool(),
            v["epoch"].as_u64(),
            v["delivered"].as_u64()
        ),
        (Some(true), Some(0), Some(2))
    );
    let id = v["id"].as_str().unwrap().to_string();

    let got_b = api.fetch(&b, 0).await;
    assert_eq!(
        unb64(got_b[0]["body"].as_str().unwrap()),
        commit(&G, 0, b"a0")
    );
    let got_c = api.fetch(&c, 0).await;
    assert_eq!(unb64(got_c[0]["body"].as_str().unwrap()), welcome(b"for c"));
    assert!(api.fetch(&a, 0).await.is_empty());

    // Retry with the same bytes (lost response): same answer, nothing delivered again.
    let (st, v) = submit(api, &a, r).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        (v["id"].as_str(), v["delivered"].as_u64()),
        (Some(id.as_str()), Some(0))
    );
    assert_eq!(api.fetch(&b, 0).await.len(), 1);

    // A different commit for epoch 0 loses and learns the winner.
    let (st, v) = submit(api, &b, req(0, b"b0", &[&a])).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "COMMIT_CONFLICT"));
    assert_eq!(v["winner_sha256"], json!(sha_hex(&commit(&G, 0, b"a0"))));

    // The next epoch is open to every member, including the one just added.
    let (st, v) = submit(api, &c, req(1, b"c1", &[&a, &b])).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    ts.stop().await;
}

#[tokio::test]
async fn eligibility_and_epoch_rules() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (a, b, outsider) = (api.signup().await, api.signup().await, api.signup().await);
    assert_eq!(
        submit(api, &a, req(0, b"a0", &[&b])).await.0,
        StatusCode::OK
    );

    // An outsider cannot take the next slot (and so cannot freeze the group).
    let (st, v) = submit(api, &outsider, req(1, b"junk", &[&a])).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "NOT_ELIGIBLE"));
    // Skipping an epoch is refused with the current one.
    let (st, v) = submit(api, &b, req(3, b"b3", &[&a])).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "EPOCH_MISMATCH"));
    assert_eq!(v["last_epoch"], 0);

    // a removes b: b may not commit any more.
    let mut r = req(1, b"a1", &[&b]);
    r["removed"] = json!([b.device_id]);
    assert_eq!(submit(api, &a, r).await.0, StatusCode::OK);
    let (st, v) = submit(api, &b, req(2, b"b2", &[&a])).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "NOT_ELIGIBLE"));
    // The removed device still got the commit (it must learn it was removed).
    assert_eq!(api.fetch(&b, 0).await.len(), 2);
    // a alone keeps going; an empty recipient list is fine.
    assert_eq!(submit(api, &a, req(2, b"a2", &[])).await.0, StatusCode::OK);
    ts.stop().await;
}

#[tokio::test]
async fn conflicts_beyond_the_kept_window_have_no_winner_hash() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    for e in 0..70u64 {
        assert_eq!(
            submit(api, &a, req(e, b"x", &[])).await.0,
            StatusCode::OK,
            "epoch {e}"
        );
    }
    let (st, v) = submit(api, &a, req(69, b"other", &[])).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "COMMIT_CONFLICT"));
    assert_eq!(v["winner_sha256"], json!(sha_hex(&commit(&G, 69, b"x"))));
    let (st, v) = submit(api, &a, req(3, b"other", &[])).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "COMMIT_CONFLICT"));
    assert_eq!(
        v["winner_sha256"],
        Value::Null,
        "epoch 3 is older than the last 64"
    );
    // a retry of an accepted commit that old is a conflict too (no hash kept)
    assert_eq!(
        submit(api, &a, req(3, b"x", &[])).await.0,
        StatusCode::CONFLICT
    );
    let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM group_winners")
        .fetch_one(&ts.server.state.db)
        .await
        .unwrap();
    assert_eq!(n.0, 64);
    ts.stop().await;
}

/// Many devices race for the same epoch: exactly one wins, every other one
/// gets a conflict naming that winner.
#[tokio::test]
async fn concurrent_commits_for_one_epoch() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let mut devs = Vec::new();
    for _ in 0..8 {
        devs.push(api.signup().await);
    }
    // epoch 0 by devs[0] makes everyone a member
    let all: Vec<&Device> = devs.iter().collect();
    assert_eq!(
        submit(api, &devs[0], req(0, b"setup", &all[1..])).await.0,
        StatusCode::OK
    );

    let results = futures_join(api, &devs).await;
    let winners: Vec<usize> = results
        .iter()
        .enumerate()
        .filter(|(_, (st, _))| *st == StatusCode::OK)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(winners.len(), 1, "{results:?}");
    let w = winners[0];
    let winner_hash = sha_hex(&commit(&G, 1, format!("d{w}").as_bytes()));
    for (i, (st, v)) in results.iter().enumerate() {
        if i != w {
            assert_eq!((*st, code(v)), (StatusCode::CONFLICT, "COMMIT_CONFLICT"));
            assert_eq!(v["winner_sha256"], json!(winner_hash));
        }
    }
    // Every other device received exactly the winner.
    for (i, d) in devs.iter().enumerate() {
        let msgs = api.fetch(d, 0).await;
        let commits: Vec<Vec<u8>> = msgs
            .iter()
            .map(|m| unb64(m["body"].as_str().unwrap()))
            .filter(|b| b[1 + 32 + 4 + 1 + 16 + 7] == 1)
            .collect();
        if i == w {
            assert!(commits.is_empty());
        } else {
            assert_eq!(
                commits,
                vec![commit(&G, 1, format!("d{w}").as_bytes())],
                "device {i}"
            );
        }
    }
    ts.stop().await;
}

async fn futures_join(api: &Api, devs: &[Device]) -> Vec<(StatusCode, Value)> {
    let mut handles = Vec::new();
    for (i, d) in devs.iter().enumerate() {
        let others: Vec<String> = devs
            .iter()
            .filter(|o| o.device_id != d.device_id)
            .map(|o| o.device_id.clone())
            .collect();
        let body = json!({
            "group_id": b64(&G),
            "epoch": 1,
            "recipients": others,
            "body": b64(&commit(&G, 1, format!("d{i}").as_bytes())),
        });
        let api = api.clone();
        let d = d.clone();
        handles.push(tokio::spawn(async move {
            api.call(&d, Method::POST, "/v1/commits", Some(body)).await
        }));
    }
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}

#[tokio::test]
async fn request_validation() {
    let ts = boot(|c| {
        c.max_commit_bytes = 1000;
        c.max_welcome_bytes = 500;
        c.max_recipients = 3;
    })
    .await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let check = |(st, v): (StatusCode, Value), want: StatusCode, what: &str| {
        assert_eq!(st, want, "{what}: {v}");
    };

    let mut r = req(0, b"x", &[&b]);
    r["body"] = json!(b64(&app(b"not a commit")));
    check(
        submit(api, &a, r).await,
        StatusCode::BAD_REQUEST,
        "application message as commit",
    );
    let mut r = req(0, b"x", &[&b]);
    r["body"] = json!(b64(&envelope(&G, 0, 2, b"proposal")));
    check(
        submit(api, &a, r).await,
        StatusCode::BAD_REQUEST,
        "proposal",
    );
    let mut r = req(0, b"x", &[&b]);
    r["epoch"] = json!(1);
    check(
        submit(api, &a, r).await,
        StatusCode::BAD_REQUEST,
        "epoch differs from header",
    );
    let mut r = req(0, b"x", &[&b]);
    r["group_id"] = json!(b64(&[0x32; 16]));
    check(
        submit(api, &a, r).await,
        StatusCode::BAD_REQUEST,
        "group differs from header",
    );
    let mut r = req(0, b"x", &[&b]);
    r["group_id"] = json!(b64(&[]));
    check(
        submit(api, &a, r).await,
        StatusCode::BAD_REQUEST,
        "empty group id",
    );
    let mut r = req(0, b"x", &[&b]);
    r["body"] = json!(b64(&[1, 2, 3]));
    check(submit(api, &a, r).await, StatusCode::BAD_REQUEST, "garbage");
    let mut r = req(0, b"x", &[&b]);
    r["welcome"] = json!(b64(&welcome(b"w")));
    check(
        submit(api, &a, r).await,
        StatusCode::BAD_REQUEST,
        "welcome without added",
    );
    let mut r = req(0, b"x", &[&b]);
    r["added"] = json!([b.device_id]);
    check(
        submit(api, &a, r).await,
        StatusCode::BAD_REQUEST,
        "added without welcome",
    );
    let mut r = req(0, b"x", &[]);
    r["added"] = json!([b.device_id]);
    r["welcome"] = json!(b64(&app(b"not a welcome")));
    check(
        submit(api, &a, r).await,
        StatusCode::BAD_REQUEST,
        "welcome that is no welcome",
    );
    let mut r = req(0, b"x", &[]);
    r["added"] = json!([b.device_id]);
    r["welcome"] = json!(b64(&welcome(&[0; 497])));
    check(
        submit(api, &a, r).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "welcome too large",
    );
    let r = req(0, &vec![0; 1000], &[&b]);
    check(
        submit(api, &a, r).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "commit too large",
    );
    let mut r = req(0, b"x", &[&b]);
    r["recipients"] = json!([
        "AAAAAAAAAAAAAAAAAAAAAA",
        "BAAAAAAAAAAAAAAAAAAAAA",
        "CAAAAAAAAAAAAAAAAAAAAA",
        "DAAAAAAAAAAAAAAAAAAAAA"
    ]);
    check(
        submit(api, &a, r).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "too many recipients",
    );
    let mut r = req(0, b"x", &[&b]);
    r["removed"] = json!([
        "AAAAAAAAAAAAAAAAAAAAAA",
        "BAAAAAAAAAAAAAAAAAAAAA",
        "CAAAAAAAAAAAAAAAAAAAAA",
        "DAAAAAAAAAAAAAAAAAAAAA"
    ]);
    check(
        submit(api, &a, r).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "too many removed",
    );
    let mut r = req(0, b"x", &[&b]);
    r["recipients"] = json!(["../etc"]);
    check(submit(api, &a, r).await, StatusCode::BAD_REQUEST, "bad id");
    let mut r = req(0, b"x", &[&b]);
    r["epoch"] = json!(u64::MAX);
    r["body"] = json!(b64(&commit(&G, u64::MAX, b"x")));
    check(
        submit(api, &a, r).await,
        StatusCode::BAD_REQUEST,
        "epoch beyond i64",
    );

    // Nothing above created a group.
    let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM groups")
        .fetch_one(&ts.server.state.db)
        .await
        .unwrap();
    assert_eq!(n.0, 0);
    // Largest allowed sizes pass; unknown recipients are reported.
    let mut r = req(0, &vec![0; 1000 - commit(&G, 0, b"").len()], &[&b]);
    r["recipients"] = json!([b.device_id, "AAAAAAAAAAAAAAAAAAAAAA"]);
    r["added"] = json!([b.device_id]);
    r["welcome"] = json!(b64(&welcome(&[0; 496])));
    r["removed"] = json!([
        "BAAAAAAAAAAAAAAAAAAAAA",
        "CAAAAAAAAAAAAAAAAAAAAA",
        "DAAAAAAAAAAAAAAAAAAAAA"
    ]);
    let (st, v) = submit(api, &a, r).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["unknown_devices"], json!(["AAAAAAAAAAAAAAAAAAAAAA"]));
    ts.stop().await;
}

/// `/v1/messages` carries application messages only (PROTOCOL.md 7.4).
#[tokio::test]
async fn messages_endpoint_refuses_commits_proposals_welcomes() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    // Establish the server-side roster before testing application-message routing.
    assert_eq!(
        submit(api, &a, req(0, b"setup", &[&b])).await.0,
        StatusCode::OK
    );
    let setup = api.fetch(&b, 0).await;
    assert_eq!(setup.len(), 1);
    api.ack(&b, &[setup[0]["id"].as_str().unwrap()]).await;

    for (body, why) in [
        (commit(&G, 0, b"c"), "commits must be sent to /v1/commits"),
        (envelope(&G, 0, 2, b"p"), "proposals are not accepted"),
        (welcome(b"w"), "welcomes travel only with their commit"),
        (b"plain bytes".to_vec(), "body: not a Tree envelope"),
        (envelope(&G, 0, 9, b"?"), "body: unknown content type"),
    ] {
        let (st, v) = api.send_raw(&a, &[&b.device_id], &body).await;
        assert_eq!(
            (st, code(&v), v["message"].as_str()),
            (StatusCode::BAD_REQUEST, "BAD_REQUEST", Some(why)),
            "{v}"
        );
    }
    assert!(api.fetch(&b, 0).await.is_empty());
    assert_eq!(
        api.send_raw(&a, &[&b.device_id], &app(b"ok")).await.0,
        StatusCode::OK
    );
    let outsider = api.signup().await;
    let (st, v) = api
        .send_raw(&a, &[&outsider.device_id], &app(b"cross-group"))
        .await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "NOT_ELIGIBLE"));
    assert!(api.fetch(&outsider, 0).await.is_empty());
    ts.stop().await;
}

/// The group record lives while one of its devices exists.
#[tokio::test]
async fn group_record_removed_with_its_last_device() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a1 = api.signup().await;
    let a2 = api.add_device(&a1).await;
    assert_eq!(submit(api, &a2, req(0, b"x", &[])).await.0, StatusCode::OK);
    let count = || async {
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM groups")
            .fetch_one(&ts.server.state.db)
            .await
            .unwrap()
            .0
    };
    tree_server::purge_expired(&ts.server.state, now())
        .await
        .unwrap();
    assert_eq!(count().await, 1);
    let (st, _) = api
        .call(
            &a1,
            Method::DELETE,
            &format!("/v1/devices/{}", a2.device_id),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    tree_server::purge_expired(&ts.server.state, now())
        .await
        .unwrap();
    assert_eq!(count().await, 0);
    ts.stop().await;
}

/// A commit to a few devices costs one rate token, not one per device.
#[tokio::test]
async fn purge_expired_messages_removes_mailbox_rows() {
    let ts = boot(|c| {
        c.message_ttl_secs = 10;
        c.max_mailbox_messages = 1;
    })
    .await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);

    let (st, v) = api.send_raw(&a, &[&b.device_id], &app(b"expired")).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM deliveries WHERE device_id = ?")
            .bind(&b.device_id)
            .fetch_one(&ts.server.state.db)
            .await
            .unwrap()
            .0,
        1
    );

    sqlx::query("UPDATE blobs SET received_at = ?")
        .bind(now() - 20)
        .execute(&ts.server.state.db)
        .await
        .unwrap();

    tree_server::purge_expired(&ts.server.state, now())
        .await
        .unwrap();

    assert_eq!(
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM deliveries WHERE device_id = ?")
            .bind(&b.device_id)
            .fetch_one(&ts.server.state.db)
            .await
            .unwrap()
            .0,
        0
    );

    // The expired entry must not consume the mailbox slot.
    let (st, v) = api.send_raw(&a, &[&b.device_id], &app(b"fresh")).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(api.fetch(&b, 0).await.len(), 1);
    ts.stop().await;
}

#[tokio::test]
async fn small_commits_cost_one_token() {
    let ts = boot(|c| {
        c.rate_per_sec = 0.001;
        c.rate_burst = 3.0;
    })
    .await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let (st, v) = submit(api, &a, req(0, b"x", &[&b])).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let (st, v) = submit(api, &a, req(1, b"y", &[&b])).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    ts.stop().await;
}
