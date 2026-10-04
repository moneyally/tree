//! Bot registry/token/gateway regression tests.

mod common;

use common::*;
use ed25519_dalek::SigningKey;
use reqwest::{Method, StatusCode};
use serde_json::json;

#[tokio::test]
async fn bot_token_lifecycle_and_gateway_device_are_isolated() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let bob = api.signup().await;

    let (st, created) = api
        .call(
            &alice,
            Method::POST,
            "/v1/bots",
            Some(json!({"name":"Test Bot","description":"hello"})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    let bot_id = created["id"].as_str().unwrap().to_string();
    let token = created["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("tb_"));
    assert!(!token.contains(' '));

    let (st, me) = api.get_bot("/v1/bot/getMe", &token).await;
    assert_eq!(st, StatusCode::OK, "{me}");
    assert_eq!(me["id"].as_str(), Some(bot_id.as_str()));
    assert_eq!(me["name"].as_str(), Some("Test Bot"));

    let gateway_key = SigningKey::from_bytes(&[9u8; 32]);
    let body = json!({
        "auth_pub": b64(gateway_key.verifying_key().as_bytes())
    });
    let (st, registered) = api
        .send_bot_json("/v1/bot/register-device", &token, &body)
        .await;
    assert_eq!(st, StatusCode::CREATED, "{registered}");
    let device_id = registered["device_id"].as_str().unwrap().to_string();

    let (st, again) = api
        .send_bot_json("/v1/bot/register-device", &token, &body)
        .await;
    assert_eq!(st, StatusCode::OK, "{again}");
    assert_eq!(again["device_id"].as_str(), Some(device_id.as_str()));

    let (st, _) = api
        .call(
            &alice,
            Method::POST,
            &format!("/v1/bots/{bot_id}/features/bot.privacy_mode/release"),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = api
        .call(
            &alice,
            Method::POST,
            &format!("/v1/bots/{bot_id}/features/bot.privacy_mode/apply"),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = api
        .call(
            &bob,
            Method::POST,
            &format!("/v1/bots/{bot_id}/revoke"),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _) = api
        .call(
            &alice,
            Method::POST,
            &format!("/v1/bots/{bot_id}/revoke"),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = api.send_bot("/v1/bot/getMe", &token).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    ts.stop().await;
}

#[tokio::test]
async fn bot_commands_are_bounded_and_owner_only() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let bob = api.signup().await;
    let (st, created) = api
        .call(
            &alice,
            Method::POST,
            "/v1/bots",
            Some(json!({"name":"CmdBot"})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    let bot_id = created["id"].as_str().unwrap().to_string();

    let commands = json!({
        "commands": [
            {"command":"start","description":"start bot"},
            {"command":"help_1","description":"help"}
        ]
    });
    let (st, out) = api
        .call(
            &alice,
            Method::PUT,
            &format!("/v1/bots/{bot_id}/commands"),
            Some(commands),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{out}");
    assert_eq!(out["commands"].as_array().unwrap().len(), 2);

    let (st, _) = api
        .call(
            &bob,
            Method::GET,
            &format!("/v1/bots/{bot_id}/commands"),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    ts.stop().await;
}
