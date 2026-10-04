//! Real WebSocket transport regression tests.

mod common;

use base64::Engine;
use common::*;
use futures_util::{SinkExt, StreamExt};
use reqwest::StatusCode;
use serde_json::json;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;

#[tokio::test]
async fn websocket_requires_signed_upgrade_and_delivers_ciphertext_until_ack() {
    let ts = boot(|_| {}).await;
    let api = &ts.api;
    let alice = api.signup().await;
    let bob = api.signup().await;

    // Establish the server-side group roster before testing message delivery.
    // The WebSocket test uses a synthetic envelope, so the transport fixture
    // must still satisfy the server's real membership gate.
    api.seed_fake_group(&alice, &[&bob]).await;

    // A plain HTTP request is not a WebSocket upgrade and is correctly
    // rejected as malformed before authentication is evaluated. To test the
    // authentication boundary itself, send a real unsigned WebSocket
    // handshake and require a 401 response.
    let unsigned = format!("ws://{}/v1/ws", ts.server.addr)
        .into_client_request()
        .unwrap();
    let err = tokio_tungstenite::connect_async(unsigned)
        .await
        .unwrap_err();
    match err {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        other => panic!("expected HTTP 401 for unsigned upgrade, got {other:?}"),
    }

    let signed = Signed::new(reqwest::Method::GET, "/v1/ws", Some(&bob.device_id), None);
    let mut req = format!("ws://{}/v1/ws", ts.server.addr)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("X-Tree-Device", bob.device_id.parse().unwrap());
    req.headers_mut()
        .insert("X-Tree-Timestamp", signed.ts.to_string().parse().unwrap());
    req.headers_mut()
        .insert("X-Tree-Nonce", signed.nonce.parse().unwrap());
    req.headers_mut().insert(
        "X-Tree-Signature",
        signed.signature(&bob.key).parse().unwrap(),
    );

    let (mut ws, response) = tokio_tungstenite::connect_async(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    let ciphertext = app(b"encrypted payload only");
    let (st, body) = api.send_raw(&alice, &[&bob.device_id], &ciphertext).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["delivered"], json!(1));

    let frame = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("websocket did not receive a message")
        .expect("websocket closed")
        .expect("websocket read failed");

    let WsMessage::Text(text) = frame else {
        panic!("expected text JSON message");
    };
    let payload: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(payload["type"], json!("message"));
    let message_id = payload["id"].as_str().unwrap().to_string();
    let returned = base64::engine::general_purpose::STANDARD
        .decode(payload["body"].as_str().unwrap())
        .unwrap();
    assert_eq!(returned, ciphertext);
    assert_ne!(
        text.as_bytes(),
        &b"encrypted payload only"[..],
        "transport must not expose plaintext"
    );

    ws.send(WsMessage::Text(
        json!({"type":"ack","ids":[message_id]}).to_string().into(),
    ))
    .await
    .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let remaining = api.fetch(&bob, 0).await;
    assert!(remaining.is_empty(), "{remaining:?}");

    ws.close(None).await.unwrap();
    ts.stop().await;
}
