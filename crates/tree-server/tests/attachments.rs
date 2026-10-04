//! Encrypted attachments: uploads in parts (resumable, in order, by the
//! uploading device only), ranged download by id, size limit, daily quota,
//! purge of unfinished uploads after a day and of files after the TTL.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

const CS: usize = 4096;

/// Attachment sizes a client produces (PROTOCOL.md 6.12): 32 + padded + 16
/// per MiB chunk. `blob_len(1024)` is the smallest, 1072 bytes.
fn blob_len(padded: u64) -> u64 {
    32 + padded + 16 * padded.div_ceil(1 << 20)
}

async fn create(api: &Api, dev: &Device, size: u64) -> (StatusCode, Value) {
    api.call(dev, Method::POST, "/v1/uploads", Some(json!({ "size": size }))).await
}

async fn put(api: &Api, dev: &Device, id: &str, index: u64, bytes: &[u8]) -> (StatusCode, Value) {
    let mut s = Signed::new(Method::PUT, &format!("/v1/uploads/{id}/{index}"), Some(&dev.device_id), None);
    s.body = bytes.to_vec();
    api.send(&s, &dev.key).await
}

async fn status(api: &Api, dev: &Device, id: &str) -> (StatusCode, Value) {
    api.call(dev, Method::GET, &format!("/v1/uploads/{id}"), None).await
}

/// One ranged download: status, bytes and the `X-Tree-Total` header.
async fn get_range(api: &Api, dev: &Device, id: &str, offset: Option<u64>) -> (StatusCode, Vec<u8>, Option<u64>) {
    let path = match offset {
        Some(o) => format!("/v1/attachments/{id}?offset={o}"),
        None => format!("/v1/attachments/{id}"),
    };
    let s = Signed::new(Method::GET, &path, Some(&dev.device_id), None);
    let resp = api
        .http
        .get(api.url(&path))
        .header("X-Tree-Device", &dev.device_id)
        .header("X-Tree-Timestamp", s.ts.to_string())
        .header("X-Tree-Nonce", &s.nonce)
        .header("X-Tree-Signature", s.signature(&dev.key))
        .send()
        .await
        .unwrap();
    let st = resp.status();
    let total = resp.headers().get("x-tree-total").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
    (st, resp.bytes().await.unwrap().to_vec(), total)
}

async fn download_all(api: &Api, dev: &Device, id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let (st, part, total) = get_range(api, dev, id, Some(out.len() as u64)).await;
        assert_eq!(st, StatusCode::OK);
        out.extend(part);
        if out.len() as u64 == total.unwrap() {
            return out;
        }
    }
}

async fn upload_all(api: &Api, dev: &Device, blob: &[u8]) -> String {
    let (st, v) = create(api, dev, blob.len() as u64).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    for (i, part) in blob.chunks(CS).enumerate() {
        assert_eq!(put(api, dev, &id, i as u64, part).await.0, StatusCode::OK);
    }
    id
}

/// The whole path: start, parts in order, a lost answer, resume, finish,
/// ranged download by anyone with the id; nobody else can add parts.
#[tokio::test]
async fn chunked_upload_resume_and_ranged_download() {
    let ts = boot(|c| c.upload_chunk_bytes = CS).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let blob: Vec<u8> = (0..blob_len(16384)).map(|i| (i % 251) as u8).collect();
    let (st, v) = create(api, &a, blob.len() as u64).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert_eq!((v["chunk_size"].as_u64(), v["chunks"].as_u64(), v["received"].as_u64()), (Some(CS as u64), Some(5), Some(0)));
    let id = v["id"].as_str().unwrap().to_string();
    let parts: Vec<&[u8]> = blob.chunks(CS).collect();

    // In order only, exact lengths, only the uploader.
    let (st, v) = put(api, &a, &id, 1, parts[1]).await;
    assert_eq!((st, v["code"].as_str(), v["received"].as_u64()), (StatusCode::CONFLICT, Some("OUT_OF_ORDER"), Some(0)));
    assert_eq!(put(api, &a, &id, 0, &parts[0][1..]).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(put(api, &a, &id, 9, parts[0]).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(put(api, &b, &id, 0, parts[0]).await.0, StatusCode::NOT_FOUND);
    assert_eq!(status(api, &b, &id).await.0, StatusCode::NOT_FOUND);
    let (st, v) = put(api, &a, &id, 0, parts[0]).await;
    assert_eq!((st, v["received"].as_u64(), v["complete"].as_bool()), (StatusCode::OK, Some(1), Some(false)));
    // The answer was lost: the same part again changes nothing.
    assert_eq!(put(api, &a, &id, 0, parts[0]).await.1["received"], 1);
    assert_eq!(put(api, &a, &id, 1, parts[1]).await.1["received"], 2);
    // The app restarts and asks where to resume.
    let (st, v) = status(api, &a, &id).await;
    assert_eq!((st, v["received"].as_u64(), v["complete"].as_bool()), (StatusCode::OK, Some(2), Some(false)));
    // Not downloadable before it is complete.
    assert_eq!(get_range(api, &b, &id, None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(put(api, &a, &id, 2, parts[2]).await.1["received"], 3);
    assert_eq!(put(api, &a, &id, 3, parts[3]).await.1["received"], 4);
    let (st, v) = put(api, &a, &id, 4, parts[4]).await;
    assert_eq!((st, v["complete"].as_bool()), (StatusCode::OK, Some(true)), "{v}");
    // Complete: a repeated last part and a status say so.
    assert_eq!(put(api, &a, &id, 4, parts[4]).await.1["complete"], true);
    assert_eq!(status(api, &b, &id).await.1["complete"], true);

    // Any registered device with the id downloads, one part per request.
    let (st, first, total) = get_range(api, &b, &id, None).await;
    assert_eq!((st, first.len(), total), (StatusCode::OK, CS, Some(blob.len() as u64)));
    let (_, tail, _) = get_range(api, &b, &id, Some(3 * CS as u64 + 50)).await;
    assert_eq!(tail, blob[3 * CS + 50..]);
    assert_eq!(download_all(api, &b, &id).await, blob);
    assert_eq!(get_range(api, &b, &id, Some(blob.len() as u64 + 1)).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(get_range(api, &b, "AAAAAAAAAAAAAAAAAAAAAA", None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(get_range(api, &b, "bad", None).await.0, StatusCode::BAD_REQUEST);

    // Only id, size and minute are stored; no uploader; no upload record left.
    let db = &ts.server.state.db;
    let cols: Vec<(String,)> = sqlx::query_as("SELECT name FROM pragma_table_info('attachments')").fetch_all(db).await.unwrap();
    assert_eq!(cols.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(), vec!["id", "size", "created_at"]);
    let left: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM uploads").fetch_one(db).await.unwrap();
    assert_eq!(left.0, 0);
    let file = ts.dir.join("attachments").join(&id);
    assert_eq!(std::fs::read(&file).unwrap(), blob);

    // The uploader can give up an unfinished upload; its partial file goes.
    let (_, v) = create(api, &a, blob_len(8192)).await;
    let id2 = v["id"].as_str().unwrap().to_string();
    put(api, &a, &id2, 0, &blob[..CS]).await;
    let part = ts.dir.join("attachments").join(format!(".{id2}.part"));
    assert!(part.exists());
    assert_eq!(api.call(&b, Method::DELETE, &format!("/v1/uploads/{id2}"), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.call(&a, Method::DELETE, &format!("/v1/uploads/{id2}"), None).await.0, StatusCode::NO_CONTENT);
    assert!(!part.exists());
    assert_eq!(status(api, &a, &id2).await.0, StatusCode::NOT_FOUND);
    ts.stop().await;
}

/// Size limit per upload and bytes per account per day.
#[tokio::test]
async fn size_limit_and_daily_quota() {
    let ts = boot(|c| {
        c.upload_chunk_bytes = CS;
        c.max_attachment_bytes = 10_000;
        c.upload_quota_bytes_per_day = 20_000;
    })
    .await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let (st, v) = create(api, &a, 10_001).await;
    assert_eq!((st, v["code"].as_str(), v["max_bytes"].as_u64()), (StatusCode::PAYLOAD_TOO_LARGE, Some("TOO_LARGE"), Some(10_000)));
    assert_eq!(create(api, &a, 0).await.0, StatusCode::BAD_REQUEST);
    // A part larger than the part size never reaches the handler.
    let (_, v) = create(api, &a, blob_len(8192)).await;
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(put(api, &a, &id, 0, &vec![0; CS + 1]).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    // 8 240 + 8 240 fit in 20 000; another 8 240 does not, 2 096 does.
    assert_eq!(create(api, &a, blob_len(8192)).await.0, StatusCode::CREATED);
    let (st, v) = create(api, &a, blob_len(8192)).await;
    assert_eq!((st, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("QUOTA_EXCEEDED")));
    assert_eq!(create(api, &a, blob_len(2048)).await.0, StatusCode::CREATED);
    assert_eq!(create(api, &a, blob_len(4096)).await.1["code"], "QUOTA_EXCEEDED");
    // Per account: b has its own.
    assert_eq!(create(api, &b, blob_len(8192)).await.0, StatusCode::CREATED);
    // Another device of the same account shares a's quota.
    let a2 = api.add_device(&a).await;
    assert_eq!(create(api, &a2, blob_len(4096)).await.1["code"], "QUOTA_EXCEEDED");
    // The quota is per day: yesterday's bytes do not count against today's
    // quota (they still count toward what the account holds).
    let db = &ts.server.state.db;
    sqlx::query("UPDATE upload_quota SET day = day - 1").execute(db).await.unwrap();
    assert_eq!(create(api, &a, blob_len(8192)).await.0, StatusCode::CREATED);
    tree_server::purge_expired(&ts.server.state, now()).await.unwrap();
    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM upload_quota WHERE day < ?").bind(now() / 86_400).fetch_one(db).await.unwrap();
    assert_eq!(rows.0, 2, "kept for the attachment lifetime");
    let ttl = ts.server.state.cfg.message_ttl_secs as i64;
    tree_server::purge_expired(&ts.server.state, now() + ttl + 3 * 86_400).await.unwrap();
    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM upload_quota").fetch_one(db).await.unwrap();
    assert_eq!(rows.0, 0);
    ts.stop().await;
}

/// F-026: only sizes a client produces (the smallest is 1072 bytes), a cap
/// on what one account holds, and the server's disk.
#[tokio::test]
async fn sizes_holdings_and_disk_are_bounded() {
    let ts = boot(|c| {
        c.upload_chunk_bytes = CS;
        c.max_live_bytes_per_account = 20_000;
    })
    .await;
    let api = &ts.api;
    let a = api.signup().await;
    for bad in [1, 1071, 1073, 2095, blob_len(1024) + 1, blob_len(8192) - 16, 3 * CS as u64 + 100] {
        let (st, v) = create(api, &a, bad).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    for good in [blob_len(1024), blob_len(2048), blob_len(1 << 20), blob_len(3 << 20), blob_len((1 << 20) + (1 << 16))] {
        assert!(tree_server::attachments::valid_size(good), "{good}");
    }
    // What the account holds: everything started within the lifetime.
    assert_eq!(create(api, &a, blob_len(8192)).await.0, StatusCode::CREATED);
    assert_eq!(create(api, &a, blob_len(8192)).await.0, StatusCode::CREATED);
    let db = &ts.server.state.db;
    sqlx::query("UPDATE upload_quota SET day = day - 5").execute(db).await.unwrap();
    let (st, v) = create(api, &a, blob_len(8192)).await;
    assert_eq!((st, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("STORAGE_LIMIT")), "a new day does not reset it");
    // Once older than the attachment lifetime, those bytes are gone.
    let ttl_days = (ts.server.state.cfg.message_ttl_secs / 86_400) as i64;
    sqlx::query("UPDATE upload_quota SET day = day - ?").bind(ttl_days).execute(db).await.unwrap();
    assert_eq!(create(api, &a, blob_len(8192)).await.0, StatusCode::CREATED);
    ts.stop().await;

    // The disk: below the free-space floor every upload is refused.
    let ts = boot(|c| c.min_free_disk_bytes = u64::MAX / 4).await;
    let a = ts.api.signup().await;
    let (st, v) = create(&ts.api, &a, blob_len(1024)).await;
    assert_eq!((st, v["code"].as_str()), (StatusCode::INSUFFICIENT_STORAGE, Some("INSUFFICIENT_STORAGE")), "{v}");
    ts.stop().await;

    // Without a free-space reading: a total for all attachments and
    // unfinished uploads.
    let ts = boot(|c| {
        c.min_free_disk_bytes = 0;
        c.max_total_attachment_bytes = 10_000;
    })
    .await;
    let a = ts.api.signup().await;
    assert_eq!(create(&ts.api, &a, blob_len(8192)).await.0, StatusCode::CREATED);
    let (st, _) = create(&ts.api, &a, blob_len(2048)).await;
    assert_eq!(st, StatusCode::INSUFFICIENT_STORAGE, "8 240 pending + 2 096 > 10 000");
    assert_eq!(create(&ts.api, &a, blob_len(1024)).await.0, StatusCode::CREATED);
    ts.stop().await;
}

/// Unfinished uploads go after 24 hours with their partial file; finished
/// files stay until the message TTL; partial files left by a deleted device
/// go too.
#[tokio::test]
async fn purge_unfinished_after_a_day() {
    let ts = boot(|c| c.upload_chunk_bytes = CS).await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let blob = vec![7u8; blob_len(8192) as usize];
    let done = upload_all(api, &a, &blob).await;
    let (_, v) = create(api, &a, blob.len() as u64).await;
    let open = v["id"].as_str().unwrap().to_string();
    put(api, &a, &open, 0, &blob[..CS]).await;
    let dir = ts.dir.join("attachments");
    let part = dir.join(format!(".{open}.part"));
    assert!(part.exists());

    // Not yet after 23 hours.
    let state = &ts.server.state;
    assert_eq!(tree_server::purge_expired(state, now() + 23 * 3600).await.unwrap(), 0);
    assert!(part.exists());
    // After 25 hours: the unfinished one (and only it) is gone.
    assert_eq!(tree_server::purge_expired(state, now() + 25 * 3600).await.unwrap(), 1);
    assert!(!part.exists());
    assert_eq!(status(api, &a, &open).await.0, StatusCode::NOT_FOUND);
    assert_eq!(put(api, &a, &open, 1, &blob[CS..2 * CS]).await.0, StatusCode::NOT_FOUND);
    assert_eq!(download_all(api, &b, &done).await, blob);

    // A device deleted mid-upload leaves no partial file behind.
    let c = api.signup().await;
    let (_, v) = create(api, &c, blob.len() as u64).await;
    let cid = v["id"].as_str().unwrap().to_string();
    put(api, &c, &cid, 0, &blob[..CS]).await;
    assert_eq!(api.call(&c, Method::DELETE, "/v1/accounts", None).await.0, StatusCode::OK);
    tree_server::purge_expired(state, now()).await.unwrap();
    assert!(!dir.join(format!(".{cid}.part")).exists());

    // The finished file goes with the message TTL.
    let ttl = state.cfg.message_ttl_secs as i64;
    tree_server::purge_expired(state, now() + ttl + 120).await.unwrap();
    assert!(!dir.join(&done).exists());
    assert_eq!(get_range(api, &b, &done, None).await.0, StatusCode::NOT_FOUND);
    ts.stop().await;
}

/// F-031: many copies of the parts of one upload at once, retries of
/// earlier parts racing later ones: the finished file is exactly the blob
/// (a late retry of part i never truncates part i + 1).
#[tokio::test]
async fn racing_part_retries_keep_the_file_whole() {
    let ts = boot(|c| {
        c.upload_chunk_bytes = CS;
        c.rate_burst = 100_000.0;
    })
    .await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    for round in 0..5u8 {
        let blob: Vec<u8> = (0..blob_len(16384)).map(|i| (i as u8) ^ round).collect();
        let (_, v) = create(api, &a, blob.len() as u64).await;
        let id = v["id"].as_str().unwrap().to_string();
        let parts: Vec<Vec<u8>> = blob.chunks(CS).map(<[u8]>::to_vec).collect();
        // Each part sent many times at once, every part in flight together;
        // keep going until the upload is complete.
        for _ in 0..20 {
            let mut tasks = Vec::new();
            for (i, p) in parts.iter().enumerate() {
                for _ in 0..4 {
                    let (api, a, id, p) = (api.clone(), a.clone(), id.clone(), p.clone());
                    tasks.push(tokio::spawn(async move { put(&api, &a, &id, i as u64, &p).await }));
                }
            }
            let mut done = false;
            for t in tasks {
                done |= t.await.unwrap().1["complete"] == true;
            }
            if done {
                break;
            }
        }
        assert_eq!(download_all(api, &b, &id).await, blob, "round {round}");
    }
    ts.stop().await;
}

/// Each part costs one extra rate token per whole MiB, as uploads did.
#[tokio::test]
async fn upload_cost_per_mib() {
    let ts = boot(|c| {
        c.rate_per_sec = 0.001;
        c.rate_burst = 5.0;
        c.upload_chunk_bytes = 4 * 1024 * 1024;
    })
    .await;
    let api = &ts.api;
    let (a, b) = (api.signup().await, api.signup().await);
    let mib = 1024 * 1024;
    // a: create (1) + part of 3 MiB and a little (1 + 3) = 5 of 5.
    let (_, v) = create(api, &a, blob_len(3 * mib)).await;
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(put(api, &a, &id, 0, &vec![1u8; blob_len(3 * mib) as usize]).await.0, StatusCode::OK, "1 + 3 tokens");
    // b: create (1) + a first part of 4 MiB (1 + 4) = 6 of 5.
    let (_, v) = create(api, &b, blob_len(4 * mib)).await;
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(put(api, &b, &id, 0, &vec![1u8; 4 * mib as usize]).await.0, StatusCode::TOO_MANY_REQUESTS, "1 + 4 tokens");
    ts.stop().await;
}
