//! In-memory token buckets and the signature replay cache.
//!
//! Nothing here is persisted or logged. Client addresses used for the signup
//! limit live only in this memory and are pruned once their bucket is full again.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token buckets keyed by `K`: `burst` capacity, refilled at `rate` tokens per second.
pub struct RateLimiter<K> {
    buckets: Mutex<HashMap<K, Bucket>>,
    rate: f64,
    burst: f64,
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            rate: rate_per_sec,
            burst,
        }
    }

    /// Takes `cost` tokens. On failure returns the seconds until enough tokens exist.
    pub fn take(&self, key: &K, cost: f64) -> Result<(), u64> {
        let now = Instant::now();
        let cost = cost.min(self.burst);
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let b = map.entry(key.clone()).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.rate).min(self.burst);
        b.last = now;
        if b.tokens >= cost {
            b.tokens -= cost;
            Ok(())
        } else {
            Err(((cost - b.tokens) / self.rate).ceil() as u64)
        }
    }

    /// Drops buckets that have refilled completely (they hold no information).
    pub fn prune(&self) {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, b| {
            b.tokens + now.duration_since(b.last).as_secs_f64() * self.rate < self.burst
        });
    }

    pub fn len(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Key for per-address limits: IPv4 address, or the /64 prefix of an IPv6 address.
pub fn ip_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_ipv6_mapped().octets(),
            None => {
                let mut o = v6.octets();
                o[8..].fill(0);
                o
            }
        },
    }
}

/// Signatures seen within the timestamp window. A second request with an
/// identical signature is a replay.
pub struct ReplayCache {
    seen: Mutex<HashMap<[u8; 64], i64>>,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Records `sig` until `expires_at` (unix seconds). Returns false if it was already present.
    pub fn insert(&self, sig: [u8; 64], expires_at: i64, now: i64) -> bool {
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&sig) {
            Some(&exp) if exp >= now => false,
            _ => {
                map.insert(sig, expires_at);
                true
            }
        }
    }

    pub fn prune(&self, now: i64) {
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, &mut exp| exp >= now);
    }

    pub fn len(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_refuses_after_burst() {
        let rl = RateLimiter::new(1.0, 3.0);
        for _ in 0..3 {
            assert!(rl.take(&1u8, 1.0).is_ok());
        }
        assert_eq!(rl.take(&1u8, 1.0), Err(1));
        assert!(rl.take(&2u8, 1.0).is_ok(), "buckets are per key");
    }

    #[test]
    fn ipv6_grouped_by_prefix() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b));
        assert_ne!(ip_key(a), ip_key(c));
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(ip_key(v4), ip_key(mapped));
    }

    #[test]
    fn replay_cache_rejects_second_use_until_expiry() {
        let rc = ReplayCache::new();
        assert!(rc.insert([7; 64], 100, 50));
        assert!(!rc.insert([7; 64], 100, 60));
        rc.prune(101);
        assert!(rc.is_empty());
        assert!(rc.insert([7; 64], 200, 101));
    }
}


/// Anti-spam limits of an account (design: "new accounts cannot mass-send;
/// accounts with accumulating spam reports are limited automatically").
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AccountLimits {
    /// Every request costs this many rate tokens.
    pub cost_factor: f64,
    /// Devices one message or commit may go to.
    pub max_fanout: Option<usize>,
}

/// Accounts this young (created today or yesterday) are new.
pub const NEW_ACCOUNT_DAYS: i64 = 1;
pub const NEW_FACTOR: f64 = 5.0;
pub const NEW_FANOUT: usize = 50;
/// Distinct reporters with verified reports in the last week that limit an account.
pub const REPORTERS: i64 = 3;
pub const REPORT_WINDOW_DAYS: i64 = 7;
pub const REPORTED_FACTOR: f64 = 10.0;
pub const REPORTED_FANOUT: usize = 20;

pub async fn account_limits(state: &crate::AppState, account: &str, created_day: i64) -> Result<AccountLimits, sqlx::Error> {
    use crate::features::{is_applied, NEW_ACCOUNT_LIMITS, REPORT_LIMITS};
    let today = crate::util::today();
    let mut l = AccountLimits { cost_factor: 1.0, max_fanout: None };
    if today - created_day <= NEW_ACCOUNT_DAYS && is_applied(&state.db, NEW_ACCOUNT_LIMITS).await? {
        l = AccountLimits { cost_factor: NEW_FACTOR, max_fanout: Some(NEW_FANOUT) };
    }
    if is_applied(&state.db, REPORT_LIMITS).await? {
        let reporters: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT reporter_account) FROM reports WHERE reported_account = ? AND verified = 1 AND created_day >= ?",
        )
        .bind(account)
        .bind(today - REPORT_WINDOW_DAYS)
        .fetch_one(&state.db)
        .await?;
        if reporters >= REPORTERS {
            l = AccountLimits { cost_factor: REPORTED_FACTOR, max_fanout: Some(REPORTED_FANOUT) };
        }
    }
    Ok(l)
}
