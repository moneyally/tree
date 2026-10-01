//! `tree-server` binary.
//!
//! ```text
//! tree-server              run the server (configuration from environment variables)
//! tree-server healthcheck  exit 0 if GET /healthz on BIND_ADDR answers 200 (for containers)
//! ```

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use tracing_subscriber::EnvFilter;
use tree_server::Config;

fn healthcheck(cfg: &Config) -> bool {
    let mut addr = cfg.bind_addr;
    if addr.ip().is_unspecified() {
        addr = SocketAddr::new([127, 0, 0, 1].into(), addr.port());
    }
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    if s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 16];
    let n = s.read(&mut buf).unwrap_or(0);
    buf[..n].starts_with(b"HTTP/1.1 200")
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(false)
        .init();

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(if healthcheck(&cfg) { 0 } else { 1 });
    }

    if cfg.admin_token_sha256.is_none() {
        tracing::warn!("ADMIN_TOKEN_SHA256 is not set: operator endpoints are disabled");
    }
    let server = match tree_server::start(cfg).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to start");
            std::process::exit(1);
        }
    };

    shutdown_signal().await;
    tracing::info!("shutting down");
    if let Err(e) = server.shutdown().await {
        tracing::error!(error = %e, "server error");
        std::process::exit(1);
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
