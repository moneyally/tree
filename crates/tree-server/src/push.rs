//! Push wake-ups without content (docs/PROTOCOL.md 8.8).
//!
//! A device may register an endpoint URL of a push gateway (UnifiedPush
//! style: the gateway forwards an HTTP POST to the app). When something
//! arrives in its mailbox the server POSTs the fixed body `wake` there: no
//! sender, no group, no size, no content. Wake-ups are coalesced to one per
//! device per `PUSH_INTERVAL_SECS`. Only hosts the operator allowed are
//! accepted and contacted, redirects are not followed, so a device cannot
//! make the server call anything else.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use tokio::sync::mpsc;

use crate::auth::{NoBody, Signed};
use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::util::today;
use crate::{json_body, AppState};

pub const BODY: &[u8] = b"wake";
pub const MAX_ENDPOINT: usize = 1024;

/// Checks an endpoint against the configuration; returns it normalised.
pub fn check_endpoint(cfg: &Config, endpoint: &str) -> Result<String, &'static str> {
    if cfg.push_allowed_hosts.is_empty() {
        return Err("push is not enabled on this server");
    }
    if endpoint.len() > MAX_ENDPOINT {
        return Err("endpoint too long");
    }
    let url = reqwest::Url::parse(endpoint).map_err(|_| "endpoint is not a URL")?;
    match url.scheme() {
        "https" => {}
        "http" if cfg.push_allow_http => {}
        _ => return Err("endpoint must use https"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("endpoint must not carry credentials");
    }
    let host = url.host_str().ok_or("endpoint has no host")?.to_ascii_lowercase();
    if !cfg.push_allowed_hosts.contains(&host) {
        return Err("this push gateway is not allowed on this server");
    }
    Ok(url.to_string())
}

#[derive(Deserialize)]
pub struct SetReq {
    pub endpoint: String,
}
json_body!(SetReq, |_cfg| MAX_ENDPOINT + 64);

/// `POST /v1/push` — set this device's endpoint.
pub async fn set(State(state): State<AppState>, req: Signed<SetReq>) -> ApiResult<Json<Value>> {
    let endpoint = check_endpoint(&state.cfg, &req.body.endpoint).map_err(ApiError::bad_request)?;
    sqlx::query(
        "INSERT INTO push_endpoints (device_id, endpoint, set_day) VALUES (?1, ?2, ?3) \
         ON CONFLICT (device_id) DO UPDATE SET endpoint = ?2, set_day = ?3",
    )
    .bind(&req.device.device_id)
    .bind(&endpoint)
    .bind(today())
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "state": "applied" })))
}

/// `DELETE /v1/push` — no more wake-ups for this device.
pub async fn clear(State(state): State<AppState>, req: Signed<NoBody>) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM push_endpoints WHERE device_id = ?")
        .bind(&req.device.device_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "state": "released" })))
}

/// Starts the sender task; returns the queue that [`AppState::wake`] feeds.
pub fn spawn(state: AppState, mut rx: mpsc::UnboundedReceiver<String>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .expect("HTTP client");
        let interval = Duration::from_secs(state.cfg.push_interval_secs);
        let mut dirty: HashSet<String> = HashSet::new();
        let mut last: HashMap<String, Instant> = HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select! {
                d = rx.recv() => match d {
                    Some(d) => { dirty.insert(d); }
                    None => return,
                },
                _ = tick.tick() => {
                    let now = Instant::now();
                    last.retain(|_, t| now.duration_since(*t) < interval);
                    let due: Vec<String> = dirty.iter().filter(|d| !last.contains_key(*d)).cloned().collect();
                    for d in due {
                        dirty.remove(&d);
                        last.insert(d.clone(), now);
                        send(&state, &http, &d).await;
                    }
                }
            }
        }
    })
}

async fn send(state: &AppState, http: &reqwest::Client, device: &str) {
    let endpoint: Option<String> = match sqlx::query("SELECT endpoint FROM push_endpoints WHERE device_id = ?")
        .bind(device)
        .fetch_optional(&state.db)
        .await
    {
        Ok(r) => r.and_then(|r| r.try_get("endpoint").ok()),
        Err(e) => {
            tracing::error!(target: "tree_server::push", error = %e);
            return;
        }
    };
    let Some(endpoint) = endpoint else { return };
    // Re-checked: the allowed hosts may have changed since it was stored.
    if check_endpoint(&state.cfg, &endpoint).is_err() {
        return;
    }
    let r = http.post(&endpoint).header("Content-Type", "text/plain").body(BODY).send().await;
    match r {
        Ok(resp) if resp.status().is_success() => {}
        // The gateway says the endpoint is gone: forget it.
        Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND || resp.status() == reqwest::StatusCode::GONE => {
            let _ = sqlx::query("DELETE FROM push_endpoints WHERE device_id = ? AND endpoint = ?")
                .bind(device)
                .bind(&endpoint)
                .execute(&state.db)
                .await;
        }
        Ok(resp) => tracing::warn!(target: "tree_server::push", status = resp.status().as_u16()),
        Err(_) => tracing::warn!(target: "tree_server::push", "gateway unreachable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_checked() {
        let mut cfg = Config::default();
        assert_eq!(check_endpoint(&cfg, "https://push.example/x"), Err("push is not enabled on this server"));
        cfg.push_allowed_hosts = vec!["push.example".into()];
        assert!(check_endpoint(&cfg, "https://push.example/up/abc?x=1").is_ok());
        assert!(check_endpoint(&cfg, "https://PUSH.example:8443/a").is_ok());
        assert_eq!(check_endpoint(&cfg, "http://push.example/a"), Err("endpoint must use https"));
        assert_eq!(check_endpoint(&cfg, "ftp://push.example/a"), Err("endpoint must use https"));
        assert_eq!(check_endpoint(&cfg, "https://other.example/a"), Err("this push gateway is not allowed on this server"));
        assert_eq!(check_endpoint(&cfg, "https://push.example.evil.test/a"), Err("this push gateway is not allowed on this server"));
        assert_eq!(check_endpoint(&cfg, "https://127.0.0.1/a"), Err("this push gateway is not allowed on this server"));
        assert_eq!(check_endpoint(&cfg, "https://u:p@push.example/a"), Err("endpoint must not carry credentials"));
        assert_eq!(check_endpoint(&cfg, "not a url"), Err("endpoint is not a URL"));
        assert_eq!(check_endpoint(&cfg, &format!("https://push.example/{}", "a".repeat(1024))), Err("endpoint too long"));
        cfg.push_allow_http = true;
        assert!(check_endpoint(&cfg, "http://push.example/a").is_ok());
    }
}
