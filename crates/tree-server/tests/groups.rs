//! Integration tests for authenticated group roster reads.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::json;

#[tokio::test]
async fn group_roster_is_visible_only_to_known_members() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let bob = api.signup().await;
    let outsider = api.signup().await;

    let body = json!({
        "group_id": b64(&GROUP),
        "epoch": 0,
        "recipients": [bob.device_id],
        "body": b64(&commit(&GROUP, 0, b"first")),
        "added": [],
        "welcome": null,
        "removed": []
    });
    let (st, v) = api.call(&alice, Method::POST, "/v1/commits", Some(body)).await;
    assert_eq!(st, StatusCode::OK, "{v}");

    async fn roster(api: &Api, dev: &Device) -> (StatusCode, serde_json::Value) {
        api.call(
            dev,
            Method::GET,
            &format!("/v1/groups/{}/devices", hex::encode(GROUP)),
            None,
        )
        .await
    }

    let (st, v) = roster(api, &alice).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let devices = v["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().any(|d| d.as_str() == Some(alice.device_id.as_str())));
    assert!(devices.iter().any(|d| d.as_str() == Some(bob.device_id.as_str())));

    let (st, v) = roster(api, &bob).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["group_id"].as_str(), Some(hex::encode(GROUP).as_str()));

    let (st, v) = roster(api, &outsider).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"].as_str(), Some("NOT_ELIGIBLE"));

    let (st, v) = roster(
        api,
        &Device {
            key: new_key(),
            account_id: outsider.account_id.clone(),
            device_id: outsider.device_id.clone(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{v}");

    ts.stop().await;
}
