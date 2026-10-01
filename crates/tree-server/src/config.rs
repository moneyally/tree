//! Server configuration, read from environment variables.

use std::net::SocketAddr;
use std::str::FromStr;

/// All tunables. [`Config::default`] is suitable for production except
/// `admin_token_sha256`, which must be set to use the operator endpoints.
#[derive(Debug, Clone)]
pub struct Config {
    /// `DATABASE_URL`, e.g. `sqlite:///data/tree.db`.
    pub database_url: String,
    /// `BIND_ADDR`.
    pub bind_addr: SocketAddr,
    /// `ADMIN_TOKEN_SHA256`: hex SHA-256 of the operator token. Unset = operator endpoints disabled.
    pub admin_token_sha256: Option<[u8; 32]>,
    /// `POW_BITS`: leading zero bits required for signup proof-of-work.
    pub pow_bits: u32,
    /// `MESSAGE_TTL_SECS`: undelivered messages older than this are purged.
    pub message_ttl_secs: u64,
    /// `PURGE_INTERVAL_SECS`: how often the purge task runs.
    pub purge_interval_secs: u64,
    /// `CLOCK_SKEW_SECS`: accepted distance between request timestamp and server time.
    pub clock_skew_secs: u64,
    /// `LONG_POLL_MAX_SECS`: upper bound for `GET /v1/messages?wait=N`.
    pub long_poll_max_secs: u64,
    /// `MAX_DEVICES_PER_ACCOUNT`.
    pub max_devices_per_account: u32,
    /// `MAX_KEY_PACKAGES_PER_DEVICE`: stored, unclaimed key packages per device.
    pub max_key_packages_per_device: u32,
    /// `MAX_KEY_PACKAGES_PER_UPLOAD`.
    pub max_key_packages_per_upload: usize,
    /// `MAX_KEY_PACKAGE_BYTES`: size of one decoded key package.
    pub max_key_package_bytes: usize,
    /// `MAX_MESSAGE_BYTES`: size of one decoded message body.
    pub max_message_bytes: usize,
    /// `MAX_RECIPIENTS`: device mailboxes per send or commit (a 1,000-member
    /// group with two devices each has 2,000).
    pub max_recipients: usize,
    /// `MAX_COMMIT_BYTES`: size of one decoded commit (a cold 2,000-leaf
    /// hybrid commit is about 2.3 MB, docs/BENCHMARKS.md).
    pub max_commit_bytes: usize,
    /// `MAX_WELCOME_BYTES`: size of one decoded welcome (about 2.8 MB at
    /// 2,000 leaves).
    pub max_welcome_bytes: usize,
    /// `ATTACHMENT_DIR`: where encrypted attachments are stored.
    pub attachment_dir: std::path::PathBuf,
    /// `MAX_ATTACHMENT_BYTES`: size of one encrypted attachment.
    pub max_attachment_bytes: usize,
    /// `MAX_MAILBOX_MESSAGES`: pending messages per device mailbox.
    pub max_mailbox_messages: u32,
    /// `FETCH_LIMIT`: messages returned per fetch.
    pub fetch_limit: u32,
    /// `RATE_PER_SEC` / `RATE_BURST`: per-device token bucket.
    pub rate_per_sec: f64,
    pub rate_burst: f64,
    /// `SIGNUP_PER_HOUR` / `SIGNUP_BURST`: per-IP (IPv6: per /64) signup bucket, memory only.
    pub signup_per_hour: f64,
    pub signup_burst: f64,
    /// `TRUST_FORWARDED_FOR`: take the client address from the last
    /// `X-Forwarded-For` entry (set only behind a reverse proxy that overwrites it).
    pub trust_forwarded_for: bool,
    /// `PUSH_ALLOWED_HOSTS`: comma-separated push gateway host names devices
    /// may register endpoints at (PROTOCOL.md 8.8). Empty = push off. Only
    /// these hosts are ever contacted (no server-side request forgery).
    pub push_allowed_hosts: Vec<String>,
    /// `PUSH_ALLOW_HTTP`: accept `http://` endpoints (tests only).
    pub push_allow_http: bool,
    /// `PUSH_INTERVAL_SECS`: at most one wake-up per device this often.
    pub push_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: "sqlite://tree-server.db".into(),
            bind_addr: "127.0.0.1:8080".parse().expect("valid default address"),
            admin_token_sha256: None,
            pow_bits: 20,
            message_ttl_secs: 30 * 24 * 3600,
            purge_interval_secs: 3600,
            clock_skew_secs: 300,
            long_poll_max_secs: 25,
            max_devices_per_account: 10,
            max_key_packages_per_device: 200,
            max_key_packages_per_upload: 100,
            max_key_package_bytes: 16 * 1024,
            max_message_bytes: 256 * 1024,
            max_recipients: 2048,
            max_commit_bytes: 4 * 1024 * 1024,
            max_welcome_bytes: 4 * 1024 * 1024,
            attachment_dir: "attachments".into(),
            max_attachment_bytes: 100 * 1024 * 1024,
            max_mailbox_messages: 10_000,
            fetch_limit: 100,
            rate_per_sec: 20.0,
            rate_burst: 200.0,
            signup_per_hour: 20.0,
            signup_burst: 10.0,
            trust_forwarded_for: false,
            push_allowed_hosts: Vec::new(),
            push_allow_http: false,
            push_interval_secs: 5,
        }
    }
}

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

fn env_parse<T: FromStr>(name: &str, default: T) -> Result<T, ConfigError> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => v
            .trim()
            .parse()
            .map_err(|_| ConfigError(format!("{name} has an invalid value"))),
        _ => Ok(default),
    }
}

/// Parses a hex SHA-256 digest (64 hex characters).
pub fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s.trim()).ok()?;
    bytes.try_into().ok()
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let d = Self::default();
        let admin_token_sha256 = match std::env::var("ADMIN_TOKEN_SHA256") {
            Ok(v) if !v.trim().is_empty() => Some(parse_sha256_hex(&v).ok_or_else(|| {
                ConfigError("ADMIN_TOKEN_SHA256 must be 64 hex characters".into())
            })?),
            _ => None,
        };
        let cfg = Self {
            database_url: env_parse("DATABASE_URL", d.database_url)?,
            bind_addr: env_parse("BIND_ADDR", d.bind_addr)?,
            admin_token_sha256,
            pow_bits: env_parse("POW_BITS", d.pow_bits)?,
            message_ttl_secs: env_parse("MESSAGE_TTL_SECS", d.message_ttl_secs)?,
            purge_interval_secs: env_parse("PURGE_INTERVAL_SECS", d.purge_interval_secs)?,
            clock_skew_secs: env_parse("CLOCK_SKEW_SECS", d.clock_skew_secs)?,
            long_poll_max_secs: env_parse("LONG_POLL_MAX_SECS", d.long_poll_max_secs)?,
            max_devices_per_account: env_parse(
                "MAX_DEVICES_PER_ACCOUNT",
                d.max_devices_per_account,
            )?,
            max_key_packages_per_device: env_parse(
                "MAX_KEY_PACKAGES_PER_DEVICE",
                d.max_key_packages_per_device,
            )?,
            max_key_packages_per_upload: env_parse(
                "MAX_KEY_PACKAGES_PER_UPLOAD",
                d.max_key_packages_per_upload,
            )?,
            max_key_package_bytes: env_parse("MAX_KEY_PACKAGE_BYTES", d.max_key_package_bytes)?,
            max_message_bytes: env_parse("MAX_MESSAGE_BYTES", d.max_message_bytes)?,
            max_recipients: env_parse("MAX_RECIPIENTS", d.max_recipients)?,
            max_commit_bytes: env_parse("MAX_COMMIT_BYTES", d.max_commit_bytes)?,
            max_welcome_bytes: env_parse("MAX_WELCOME_BYTES", d.max_welcome_bytes)?,
            attachment_dir: env_parse("ATTACHMENT_DIR", d.attachment_dir)?,
            max_attachment_bytes: env_parse("MAX_ATTACHMENT_BYTES", d.max_attachment_bytes)?,
            max_mailbox_messages: env_parse("MAX_MAILBOX_MESSAGES", d.max_mailbox_messages)?,
            fetch_limit: env_parse("FETCH_LIMIT", d.fetch_limit)?,
            rate_per_sec: env_parse("RATE_PER_SEC", d.rate_per_sec)?,
            rate_burst: env_parse("RATE_BURST", d.rate_burst)?,
            signup_per_hour: env_parse("SIGNUP_PER_HOUR", d.signup_per_hour)?,
            signup_burst: env_parse("SIGNUP_BURST", d.signup_burst)?,
            trust_forwarded_for: env_parse("TRUST_FORWARDED_FOR", d.trust_forwarded_for)?,
            push_allowed_hosts: std::env::var("PUSH_ALLOWED_HOSTS")
                .unwrap_or_default()
                .split(',')
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
            push_allow_http: env_parse("PUSH_ALLOW_HTTP", d.push_allow_http)?,
            push_interval_secs: env_parse("PUSH_INTERVAL_SECS", d.push_interval_secs)?,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.pow_bits > 40 {
            return Err(ConfigError("POW_BITS must be at most 40".into()));
        }
        if self.fetch_limit == 0
            || self.max_recipients == 0
            || self.max_commit_bytes == 0
            || self.max_welcome_bytes == 0
            || self.max_attachment_bytes == 0
            || self.max_key_packages_per_upload == 0
        {
            return Err(ConfigError("limits must be positive".into()));
        }
        if !(self.rate_per_sec > 0.0 && self.rate_burst >= 1.0) {
            return Err(ConfigError(
                "RATE_PER_SEC must be > 0 and RATE_BURST >= 1".into(),
            ));
        }
        if !(self.signup_per_hour > 0.0 && self.signup_burst >= 1.0) {
            return Err(ConfigError(
                "SIGNUP_PER_HOUR must be > 0 and SIGNUP_BURST >= 1".into(),
            ));
        }
        if self.push_interval_secs == 0 {
            return Err(ConfigError("PUSH_INTERVAL_SECS must be positive".into()));
        }
        if self.purge_interval_secs == 0 {
            return Err(ConfigError("PURGE_INTERVAL_SECS must be positive".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_refuses_unusable_limits() {
        assert!(Config::default().validate().is_ok());
        let bad: Vec<fn(&mut Config)> = vec![
            |c| c.pow_bits = 41,
            |c| c.fetch_limit = 0,
            |c| c.max_recipients = 0,
            |c| c.max_commit_bytes = 0,
            |c| c.max_welcome_bytes = 0,
            |c| c.max_attachment_bytes = 0,
            |c| c.max_key_packages_per_upload = 0,
            |c| c.rate_per_sec = 0.0,
            |c| c.rate_burst = 0.5,
            |c| c.signup_per_hour = 0.0,
            |c| c.signup_burst = 0.5,
            |c| c.purge_interval_secs = 0,
            |c| c.push_interval_secs = 0,
        ];
        for (i, f) in bad.into_iter().enumerate() {
            let mut c = Config::default();
            f(&mut c);
            assert!(c.validate().is_err(), "case {i}");
        }
        assert!(Config { pow_bits: 40, ..Config::default() }.validate().is_ok());
    }
}
