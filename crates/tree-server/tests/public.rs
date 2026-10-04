//! Public spaces (PROTOCOL.md 8.15): public groups and channels over real
//! HTTP. Permissions, bans, listing, handles, limits, the operator flag,
//! reports, cursors, and that nothing here touches private mailboxes.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode as AxStatus;
use axum::routing::post as route_post;
use axum::Router;
use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use tree_server::features::{set_applied, PUBLIC_SPACES};

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

fn pid() -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, random::<16>())
}

async fn create(api: &Api, dev: &Device, kind: &str, handle: &str) -> (StatusCode, Value) {
    api.call(dev, Method::POST, "/v1/public/spaces", Some(json!({ "kind": kind, "name": format!("Name {handle}"), "handle": handle, "description": "hello" })))
        .await
}

async fn space(api: &Api, dev: &Device, kind: &str, handle: &str) -> String {
    let (st, v) = create(api, dev, kind, handle).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert_eq!(v["is_public"], true);
    v["id"].as_str().unwrap().to_string()
}

async fn join(api: &Api, dev: &Device, id: &str) -> (StatusCode, Value) {
    api.call(dev, Method::POST, &format!("/v1/public/spaces/{id}/join"), None).await
}

async fn post(api: &Api, dev: &Device, id: &str, text: &str, reply_to: Option<&str>) -> (StatusCode, Value) {
    api.call(
        dev,
        Method::POST,
        &format!("/v1/public/spaces/{id}/posts"),
        Some(json!({ "id": pid(), "text": text, "reply_to": reply_to, "author_name": "Alice" })),
    )
    .await
}

async fn feature(api: &Api, dev: &Device, id: &str, key: &str, action: &str, option: Option<&str>) -> (StatusCode, Value) {
    let body = option.map(|o| json!({ "option": o }));
    api.call(dev, Method::POST, &format!("/v1/public/spaces/{id}/features/{key}/{action}"), body).await
}

async fn posts(api: &Api, dev: &Device, id: &str, query: &str) -> Vec<Value> {
    let (st, v) = api.call(dev, Method::GET, &format!("/v1/public/spaces/{id}/posts{query}"), None).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    v["posts"].as_array().unwrap().clone()
}

#[tokio::test]
async fn channel_permissions_comments_and_signatures() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (owner, sub, other) = (api.signup().await, api.signup().await, api.signup().await);
    let ch = space(api, &owner, "channel", "@Tree_News").await;
    assert_eq!(join(api, &sub, &ch).await.0, StatusCode::OK);

    // Only admins post in a channel.
    let (st, v) = post(api, &sub, &ch, "not an admin", None).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "NOT_ADMIN"), "{v}");
    let (st, v) = post(api, &other, &ch, "not even a member", None).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "NOT_MEMBER"), "{v}");
    let (st, p1) = post(api, &owner, &ch, "first post", None).await;
    assert_eq!(st, StatusCode::CREATED, "{p1}");
    let p1 = p1["id"].as_str().unwrap().to_string();

    // Comments: refused while channel.comments is released, then allowed.
    let (st, v) = post(api, &sub, &ch, "nice", Some(&p1)).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LOCKED_BY_CHAT"), "{v}");
    assert_eq!(feature(api, &sub, &ch, "channel.comments", "apply", None).await.1["code"], "NOT_ADMIN");
    let (st, v) = feature(api, &owner, &ch, "channel.comments", "apply", None).await;
    assert_eq!((st, v["features"]["channel.comments"].clone()), (StatusCode::OK, json!(true)), "{v}");
    let (st, c1) = post(api, &sub, &ch, "nice", Some(&p1)).await;
    assert_eq!(st, StatusCode::CREATED, "{c1}");
    let (st, v) = post(api, &sub, &ch, "comment on a comment", Some(c1["id"].as_str().unwrap())).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    let pp = posts(api, &sub, &ch, "").await;
    assert_eq!(pp.len(), 1, "a channel's main list holds posts only");
    assert_eq!(pp[0]["comments"], 1);
    let cc = posts(api, &sub, &ch, &format!("?reply_to={p1}")).await;
    assert_eq!(cc.len(), 1);
    assert_eq!(cc[0]["author"], sub.account_id.as_str(), "commenters are shown");
    // Released again: no more comments.
    feature(api, &owner, &ch, "channel.comments", "release", None).await;
    assert_eq!(post(api, &sub, &ch, "late", Some(&p1)).await.0, StatusCode::FORBIDDEN);

    // Signatures: a subscriber sees the posting admin only while applied.
    assert!(pp[0]["author"].is_null() && pp[0]["author_name"].is_null(), "{}", pp[0]);
    assert_eq!(pp[0]["mine"], false);
    let own = posts(api, &owner, &ch, "").await;
    assert_eq!(own[0]["mine"], true);
    feature(api, &owner, &ch, "channel.signatures", "apply", None).await;
    let pp = posts(api, &sub, &ch, "").await;
    assert_eq!((pp[0]["author"].as_str(), pp[0]["author_name"].as_str()), (Some(owner.account_id.as_str()), Some("Alice")));
    feature(api, &owner, &ch, "channel.signatures", "release", None).await;
    assert!(posts(api, &sub, &ch, "").await[0]["author"].is_null());

    // A new admin may post; dropping the role takes it away. The owner stays.
    let (st, v) = api.call(&owner, Method::POST, &format!("/v1/public/spaces/{ch}/admins/{}/apply", sub.account_id), None).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert!(v["admins"].as_array().unwrap().iter().any(|a| a == sub.account_id.as_str()));
    assert_eq!(post(api, &sub, &ch, "now I may", None).await.0, StatusCode::CREATED);
    let (st, _) = api.call(&sub, Method::POST, &format!("/v1/public/spaces/{ch}/admins/{}/release", owner.account_id), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "the owner's role does not change");
    api.call(&owner, Method::POST, &format!("/v1/public/spaces/{ch}/admins/{}/release", sub.account_id), None).await;
    assert_eq!(post(api, &sub, &ch, "not any more", None).await.0, StatusCode::FORBIDDEN);
    // Channel keys only for channels; unknown keys refused.
    assert_eq!(feature(api, &owner, &ch, "chat.nothing", "apply", None).await.0, StatusCode::NOT_FOUND);
    ts.stop().await;
}

#[tokio::test]
async fn bans_slow_mode_edits_and_deletes() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (owner, a, b) = (api.signup().await, api.signup().await, api.signup().await);
    let g = space(api, &owner, "group", "public_square").await;
    join(api, &a, &g).await;
    join(api, &b, &g).await;
    // Everyone posts in a public group.
    let (st, pa) = post(api, &a, &g, "from a", None).await;
    assert_eq!(st, StatusCode::CREATED, "{pa}");
    let pa = pa["id"].as_str().unwrap().to_string();
    let (st, v) = post(api, &b, &g, "reply", Some(&pa)).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert_eq!(v["author"], b.account_id.as_str(), "group members are shown");

    // Only the author edits; the author or an admin deletes.
    let (st, _) = api.call(&b, Method::PUT, &format!("/v1/public/posts/{pa}"), Some(json!({ "text": "hijacked" }))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, v) = api.call(&a, Method::PUT, &format!("/v1/public/posts/{pa}"), Some(json!({ "text": "edited" }))).await;
    assert_eq!((st, v["text"].as_str()), (StatusCode::OK, Some("edited")), "{v}");
    let (st, _) = api.call(&b, Method::DELETE, &format!("/v1/public/posts/{pa}"), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "not b's post");
    let (_, pb) = post(api, &b, &g, "rude", None).await;
    let pb = pb["id"].as_str().unwrap().to_string();
    let (st, _) = api.call(&owner, Method::DELETE, &format!("/v1/public/posts/{pb}"), None).await;
    assert_eq!(st, StatusCode::OK, "an admin deletes any post");
    let live = posts(api, &a, &g, "").await;
    assert!(live.iter().all(|p| p["id"] != pb.as_str()), "deleted posts leave the pages");
    // The since-cursor shows the edit and the deletion as changes.
    let changes = posts(api, &a, &g, "?after_rev=0").await;
    let tomb = changes.iter().find(|p| p["id"] == pb.as_str()).unwrap();
    assert!(tomb["deleted"] == true && tomb.get("text").is_none(), "tombstone without the text: {tomb}");
    let revs: Vec<i64> = changes.iter().map(|p| p["rev"].as_i64().unwrap()).collect();
    assert!(revs.windows(2).all(|w| w[0] < w[1]));
    let last = *revs.last().unwrap();
    assert!(posts(api, &a, &g, &format!("?after_rev={last}")).await.is_empty());

    // A banned member is unsubscribed and can neither post, join nor edit.
    let (st, v) = api.call(&a, Method::POST, &format!("/v1/public/spaces/{g}/bans/{}/apply", b.account_id), None).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "NOT_ADMIN"));
    let (st, v) = api.call(&owner, Method::POST, &format!("/v1/public/spaces/{g}/bans/{}/apply", b.account_id), None).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert!(v["bans"].as_array().unwrap().iter().any(|x| x == b.account_id.as_str()));
    let (st, v) = post(api, &b, &g, "still here?", None).await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "BANNED"));
    assert_eq!(code(&join(api, &b, &g).await.1), "BANNED");
    let (st, _) = api.call(&owner, Method::POST, &format!("/v1/public/spaces/{g}/bans/{}/apply", owner.account_id), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "admins cannot be banned");
    api.call(&owner, Method::POST, &format!("/v1/public/spaces/{g}/bans/{}/release", b.account_id), None).await;
    assert_eq!(join(api, &b, &g).await.0, StatusCode::OK, "unbanned: may join again");

    // Slow mode: non-admins once per interval; admins never wait.
    let (st, v) = feature(api, &owner, &g, "chat.slow_mode", "apply", Some("1h")).await;
    assert_eq!((st, v["features"]["chat.slow_mode"].as_i64()), (StatusCode::OK, Some(3600)), "{v}");
    assert_eq!(feature(api, &owner, &g, "chat.slow_mode", "apply", Some("2h")).await.1["code"], "INVALID_OPTION");
    assert_eq!(feature(api, &owner, &g, "chat.public_listing", "apply", Some("x")).await.1["code"], "INVALID_OPTION");
    let (st, v) = post(api, &a, &g, "again", None).await;
    assert_eq!((st, code(&v)), (StatusCode::TOO_MANY_REQUESTS, "SLOW_MODE"), "a posted before");
    assert_eq!(post(api, &owner, &g, "admin", None).await.0, StatusCode::CREATED);
    assert_eq!(post(api, &owner, &g, "admin again", None).await.0, StatusCode::CREATED);
    feature(api, &owner, &g, "chat.slow_mode", "release", None).await;
    assert_eq!(post(api, &a, &g, "free again", None).await.0, StatusCode::CREATED);

    // Leaving; the owner cannot leave.
    assert_eq!(api.call(&a, Method::POST, &format!("/v1/public/spaces/{g}/leave"), None).await.0, StatusCode::OK);
    assert_eq!(post(api, &a, &g, "gone", None).await.1["code"], "NOT_MEMBER");
    assert_eq!(api.call(&owner, Method::POST, &format!("/v1/public/spaces/{g}/leave"), None).await.1["code"], "OWNER_CANNOT_LEAVE");
    ts.stop().await;
}

#[tokio::test]
async fn idempotent_posts_and_paging() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let owner = api.signup().await;
    let g = space(api, &owner, "group", "pager_test").await;
    let id = pid();
    let body = json!({ "id": id, "text": "once" });
    let (st, first) = api.call(&owner, Method::POST, &format!("/v1/public/spaces/{g}/posts"), Some(body.clone())).await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, again) = api.call(&owner, Method::POST, &format!("/v1/public/spaces/{g}/posts"), Some(body)).await;
    assert_eq!((st, again["replayed"].clone(), again["seq"].clone()), (StatusCode::OK, json!(true), first["seq"].clone()), "a retry is stored once");
    let (st, v) = api.call(&owner, Method::POST, &format!("/v1/public/spaces/{g}/posts"), Some(json!({ "id": id, "text": "other" }))).await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "IDEMPOTENCY_KEY_REUSE"));
    for i in 0..7 {
        post(api, &owner, &g, &format!("n{i}"), None).await;
    }
    let page1 = posts(api, &owner, &g, "?limit=3").await;
    let texts: Vec<&str> = page1.iter().map(|p| p["text"].as_str().unwrap()).collect();
    assert_eq!(texts, ["n6", "n5", "n4"], "newest first");
    let before = page1[2]["seq"].as_i64().unwrap();
    let page2 = posts(api, &owner, &g, &format!("?limit=3&before={before}")).await;
    let texts: Vec<&str> = page2.iter().map(|p| p["text"].as_str().unwrap()).collect();
    assert_eq!(texts, ["n3", "n2", "n1"]);
    // Size limits.
    let (st, _) = post(api, &owner, &g, &"x".repeat(4097), None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(post(api, &owner, &g, &"가".repeat(4096), None).await.0, StatusCode::CREATED, "characters, not bytes");
    assert_eq!(post(api, &owner, &g, "", None).await.0, StatusCode::BAD_REQUEST);
    ts.stop().await;
}

#[tokio::test]
async fn handles_listing_and_directory() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let s = space(api, &a, "group", "rust_lovers").await;
    // Handles are unique over all spaces, after normalising.
    let (st, v) = create(api, &b, "channel", "@RUST_lovers").await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "HANDLE_TAKEN"), "{v}");
    for bad in ["abc", "1abcde", "has space", "dash-dash"] {
        assert_eq!(create(api, &b, "group", bad).await.0, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(api.call(&b, Method::POST, "/v1/public/spaces", Some(json!({ "kind": "mailbox", "name": "x", "handle": "valid_one" }))).await.0, StatusCode::BAD_REQUEST);
    // Found by exact handle, listed or not.
    let (st, v) = api.call(&b, Method::GET, "/v1/public/handles/@Rust_Lovers", None).await;
    assert_eq!((st, v["id"].as_str()), (StatusCode::OK, Some(s.as_str())), "{v}");
    assert!(v.get("admins").is_none(), "admin accounts only for admins");
    // In the directory only while chat.public_listing is applied.
    let b2 = b.clone();
    let dir = |q: &'static str| {
        let b = b2.clone();
        async move {
            let (st, v) = api.call(&b, Method::GET, &format!("/v1/public/directory?q={q}"), None).await;
            assert_eq!(st, StatusCode::OK, "{v}");
            v["spaces"].as_array().unwrap().iter().map(|s| s["handle"].as_str().unwrap().to_string()).collect::<Vec<_>>()
        }
    };
    assert!(dir("rust").await.is_empty(), "unlisted by default");
    feature(api, &a, &s, "chat.public_listing", "apply", None).await;
    assert_eq!(dir("rust").await, ["rust_lovers"], "by handle");
    assert_eq!(dir("Name").await, ["rust_lovers"], "by name");
    assert!(dir("%25").await.is_empty(), "LIKE wildcards are plain characters");
    feature(api, &a, &s, "chat.public_listing", "release", None).await;
    assert!(dir("rust").await.is_empty(), "released: out of the directory");
    // Subscriptions list.
    join(api, &b, &s).await;
    let (_, v) = api.call(&b, Method::GET, "/v1/public/subscriptions", None).await;
    assert_eq!(v["spaces"][0]["role"], "member");
    // Profile changes by admins only; the owner deletes.
    let (st, _) = api.call(&b, Method::POST, &format!("/v1/public/spaces/{s}/profile"), Some(json!({ "name": "mine now" }))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, v) = api.call(&a, Method::POST, &format!("/v1/public/spaces/{s}/profile"), Some(json!({ "description": "new", "avatar": "att#key" }))).await;
    assert_eq!((st, v["description"].as_str(), v["avatar"].as_str()), (StatusCode::OK, Some("new"), Some("att#key")));
    assert_eq!(api.call(&b, Method::DELETE, &format!("/v1/public/spaces/{s}"), None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(api.call(&a, Method::DELETE, &format!("/v1/public/spaces/{s}"), None).await.0, StatusCode::OK);
    assert_eq!(api.call(&b, Method::GET, &format!("/v1/public/spaces/{s}"), None).await.0, StatusCode::NOT_FOUND);
    // The handle is free again.
    assert_eq!(create(api, &b, "channel", "rust_lovers").await.0, StatusCode::CREATED);
    ts.stop().await;
}

#[tokio::test]
async fn flag_off_refuses_everything() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let a = api.signup().await;
    let s = space(api, &a, "group", "flag_test").await;
    set_applied(&ts.server.state.db, PUBLIC_SPACES, false).await.unwrap();
    let paths = [
        (Method::POST, "/v1/public/spaces".to_string(), Some(json!({ "kind": "group", "name": "x", "handle": "another" }))),
        (Method::GET, format!("/v1/public/spaces/{s}"), None),
        (Method::POST, format!("/v1/public/spaces/{s}/join"), None),
        (Method::POST, format!("/v1/public/spaces/{s}/posts"), Some(json!({ "id": pid(), "text": "x" }))),
        (Method::GET, format!("/v1/public/spaces/{s}/posts"), None),
        (Method::GET, "/v1/public/directory".to_string(), None),
        (Method::GET, "/v1/public/subscriptions".to_string(), None),
    ];
    for (m, p, b) in paths {
        let (st, v) = api.call(&a, m, &p, b).await;
        assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LOCKED_BY_SERVER"), "{p}");
    }
    // Operator applies it again: everything is back.
    let (st, _) = api.admin(Some(ADMIN_TOKEN), PUBLIC_SPACES, "apply").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(api.call(&a, Method::GET, &format!("/v1/public/spaces/{s}"), None).await.0, StatusCode::OK);
    ts.stop().await;
}

#[tokio::test]
async fn limits_and_rate() {
    let ts = boot(|c| {
        c.rate_per_sec = 0.001;
        c.rate_burst = 60.0;
    })
    .await;
    let api = &ts.api;
    let db = &ts.server.state.db;
    // New accounts (anti-spam limits applied) cannot open broadcast spaces.
    set_applied(db, tree_server::features::NEW_ACCOUNT_LIMITS, true).await.unwrap();
    let fresh = api.signup().await;
    let (st, v) = create(api, &fresh, "channel", "spam_channel").await;
    assert_eq!((st, code(&v)), (StatusCode::FORBIDDEN, "LIMITED"), "{v}");
    set_applied(db, tree_server::features::NEW_ACCOUNT_LIMITS, false).await.unwrap();
    // Creating costs 21 tokens: two spaces leave 60 - 1 (refused) - 42 = 17.
    assert_eq!(create(api, &fresh, "channel", "first_one").await.0, StatusCode::CREATED);
    assert_eq!(create(api, &fresh, "channel", "second_one").await.0, StatusCode::CREATED);
    let (st, _) = create(api, &fresh, "channel", "third_one").await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "rate limited");
    // At most MAX_OWNED spaces per account.
    let ts2 = boot(|_| {}).await;
    let owner = ts2.api.signup().await;
    for i in 0..tree_server::public::MAX_OWNED {
        assert_eq!(create(&ts2.api, &owner, "group", &format!("owned_{i}")).await.0, StatusCode::CREATED);
    }
    let (st, v) = create(&ts2.api, &owner, "group", "one_too_many").await;
    assert_eq!((st, code(&v)), (StatusCode::CONFLICT, "LIMIT_EXCEEDED"));
    ts2.stop().await;
    ts.stop().await;
}

#[tokio::test]
async fn reports_carry_the_post_and_private_paths_stay_apart() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let g = space(api, &a, "group", "report_me").await;
    join(api, &b, &g).await;
    let (_, p) = post(api, &a, &g, "illegal text", None).await;
    let post_id = p["id"].as_str().unwrap();
    let (st, v) = api.call(&b, Method::POST, "/v1/public/reports", Some(json!({ "post": post_id, "reason": "spam" }))).await;
    assert_eq!((st, v["verified"].clone()), (StatusCode::CREATED, json!(true)), "{v}");
    assert_eq!(api.call(&a, Method::POST, "/v1/public/reports", Some(json!({ "post": post_id, "reason": "x" }))).await.0, StatusCode::BAD_REQUEST, "own post");
    // The operator sees it in the ordinary queue, with the stored text.
    let resp = api.http.get(api.url("/v1/reports")).header("X-Tree-Admin", ADMIN_TOKEN).send().await.unwrap();
    let (_, v) = decode(resp).await;
    let r = &v["reports"][0];
    assert_eq!((r["reported_account"].as_str(), r["messages"][0]["payload"].as_str()), (Some(a.account_id.as_str()), Some("illegal text")));
    assert_eq!(r["messages"][0]["public_post"], post_id);

    // Nothing went into anyone's mailbox, and private group ids are not a
    // way in: a create naming a group is refused (private never becomes public).
    assert!(api.fetch(&a, 0).await.is_empty() && api.fetch(&b, 0).await.is_empty());
    let (st, _) = api
        .call(&a, Method::POST, "/v1/public/spaces", Some(json!({ "kind": "group", "name": "x", "handle": "from_private", "group_id": b64(&[1u8; 16]) })))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "no field turns a private group public");
    let blobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs").fetch_one(&ts.server.state.db).await.unwrap();
    assert_eq!(blobs, 0);
    ts.stop().await;
}

// --- notifications -----------------------------------------------------------

/// (endpoint id, body) of every POST the gateway received.
type Received = Vec<(String, Vec<u8>)>;

#[derive(Clone, Default)]
struct Gateway {
    got: Arc<Mutex<Received>>,
}

async fn receive(State(g): State<Gateway>, Path(id): Path<String>, body: axum::body::Bytes) -> AxStatus {
    g.got.lock().unwrap().push((id, body.to_vec()));
    AxStatus::OK
}

fn count(g: &Gateway, id: &str) -> usize {
    g.got.lock().unwrap().iter().filter(|(i, _)| i == id).count()
}

#[tokio::test]
async fn subscribers_who_asked_are_woken_at_most_once_per_interval() {
    let g = Gateway::default();
    let app = Router::new().route("/up/{id}", route_post(receive)).with_state(g.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let ts = boot(|c| {
        c.push_allowed_hosts = vec![format!("127.0.0.1:{port}")];
        c.push_allow_http = true;
        c.push_interval_secs = 1;
        c.public_push_interval_secs = 3;
    })
    .await;
    let api = &ts.api;
    let (owner, fan, quiet) = (api.signup().await, api.signup().await, api.signup().await);
    for (d, name) in [(&owner, "owner"), (&fan, "fan"), (&quiet, "quiet")] {
        let (st, v) = api.call(d, Method::POST, "/v1/push", Some(json!({ "endpoint": format!("http://127.0.0.1:{port}/up/{name}") }))).await;
        assert_eq!(st, StatusCode::OK, "{v}");
    }
    let ch = space(api, &owner, "channel", "wake_test").await;
    join(api, &fan, &ch).await;
    join(api, &quiet, &ch).await;
    let (st, v) = api.call(&fan, Method::POST, &format!("/v1/public/spaces/{ch}/notify/apply"), None).await;
    assert_eq!((st, v["notify"].clone()), (StatusCode::OK, json!(true)));
    assert_eq!(api.call(&owner, Method::POST, &format!("/v1/public/spaces/{}/notify/apply", pid()), None).await.0, StatusCode::NOT_FOUND);

    // Three posts in a burst: one wake-up.
    for i in 0..3 {
        post(api, &owner, &ch, &format!("p{i}"), None).await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(count(&g, "fan"), 1, "one wake-up for the burst");
    assert_eq!(count(&g, "quiet"), 0, "did not ask for notifications");
    assert_eq!(count(&g, "owner"), 0, "the author is not woken");
    assert!(g.got.lock().unwrap().iter().all(|(_, b)| b == b"wake"), "content-free");
    // More posts within the interval: held back, then one more.
    post(api, &owner, &ch, "p3", None).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(count(&g, "fan"), 1, "within the interval");
    for _ in 0..40 {
        if count(&g, "fan") == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(count(&g, "fan"), 2, "after the interval");
    // Released: no more.
    api.call(&fan, Method::POST, &format!("/v1/public/spaces/{ch}/notify/release"), None).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    post(api, &owner, &ch, "p4", None).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(count(&g, "fan"), 2);
    ts.stop().await;
}
