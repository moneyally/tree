//! Authenticated WebSocket transport.
//!
//! The HTTP upgrade request is authenticated with the same signed request
//! headers as every other Tree API call. Frames thereafter run inside the
//! authenticated TLS WebSocket and contain only Tree mailbox ciphertexts or
//! ACK commands. Connections are intentionally finite so clients must
//! periodically re-authenticate with a fresh signed upgrade request.

use std::collections::HashSet;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{NoBody, Signed};
use crate::{messages, AppState};

const MAX_CONNECTION_SECS: u64 = 15 * 60;
const MAX_SENT_IDS: usize = 4096;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientFrame {
    Ack { ids: Vec<String> },
}

pub async fn connect(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
    req: Signed<NoBody>,
) -> Response {
    let device_id = req.device.device_id;
    ws.on_upgrade(move |socket| serve(state, device_id, socket))
}

async fn serve(state: AppState, device_id: String, mut socket: WebSocket) {
    let notify = state.waiters.subscribe(&device_id);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(MAX_CONNECTION_SECS);
    let mut sent = HashSet::<String>::new();

    loop {
        if tokio::time::Instant::now() >= deadline {
            let _ = socket.send(Message::Close(None)).await;
            break;
        }

        match messages::load(&state, &device_id).await {
            Ok(page) => {
                for message in page.messages {
                    if sent.len() >= MAX_SENT_IDS && !sent.contains(&message.id) {
                        break;
                    }
                    if sent.insert(message.id.clone()) {
                        let payload = json!({
                            "type": "message",
                            "id": message.id,
                            "body": message.body,
                            "received_at": message.received_at,
                        });
                        if socket
                            .send(Message::Text(payload.to_string().into()))
                            .await
                            .is_err()
                        {
                            state.waiters.unsubscribe(&device_id, notify.clone());
                            return;
                        }
                    }
                }
            }
            Err(_) => {
                let _ = socket
                    .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                        code: axum::extract::ws::close_code::ERROR,
                        reason: "mailbox unavailable".into(),
                    })))
                    .await;
                break;
            }
        }

        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);

        tokio::select! {
            _ = notify.notified() => {},
            _ = &mut sleep => {
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
            frame = socket.next() => {
                match frame {
                    None => break,
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ClientFrame>(&text) {
                            Ok(ClientFrame::Ack { ids }) => {
                                match messages::ack_ids(&state, &device_id, &ids).await {
                                    Ok(_) => {
                                        for id in ids {
                                            sent.remove(&id);
                                        }
                                    }
                                    Err(_) => {
                                        let _ = socket.send(Message::Text(
                                            json!({"type":"error","code":"BAD_ACK"}).to_string().into()
                                        )).await;
                                    }
                                }
                            }
                            Err(_) => {
                                let _ = socket.send(Message::Text(
                                    json!({"type":"error","code":"BAD_FRAME"}).to_string().into()
                                )).await;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Binary(_))) => {
                        let _ = socket.send(Message::Text(
                            json!({"type":"error","code":"TEXT_ONLY"}).to_string().into()
                        )).await;
                    }
                    Some(Err(_)) => break,
                }
            }
        }
    }

    state.waiters.unsubscribe(&device_id, notify);
}
