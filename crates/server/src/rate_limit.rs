//! Per-client rate limits for the HTTPS edge.

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as GovRateLimiter};

// Cap map size so unbounded client IPs cannot grow RAM forever. Many source IPs can churn entries and obtain a fresh burst (classic in-memory limiter tradeoff).
const MAX_LIMITER_ENTRIES: usize = 2_000;
const MAX_LIMITER_IDLE_SECS: u64 = 900;

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct Entry {
    limiter: GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    last_seen_epoch: AtomicU64,
}

/// One per-key GCRA budget: `per_minute` sustained, `burst` spendable at once.
pub struct RateTier {
    quota: Quota,
    clients: DashMap<String, Arc<Entry>>,
}

impl RateTier {
    pub fn new(per_minute: u32, burst: u32) -> Self {
        let nonzero = |n: u32| NonZeroU32::new(n.max(1)).expect("max(1) is nonzero");
        Self {
            quota: Quota::per_minute(nonzero(per_minute)).allow_burst(nonzero(burst)),
            clients: DashMap::new(),
        }
    }

    /// Spend one request from `key`'s budget; `false` when it is exhausted.
    pub fn check(&self, key: &str) -> bool {
        let entry = match self.clients.get(key) {
            Some(entry) => entry.value().clone(),
            None => {
                self.make_room();
                self.clients
                    .entry(key.to_string())
                    .or_insert_with(|| {
                        Arc::new(Entry {
                            limiter: GovRateLimiter::direct(self.quota),
                            last_seen_epoch: AtomicU64::new(0),
                        })
                    })
                    .value()
                    .clone()
            }
        };
        entry
            .last_seen_epoch
            .store(now_epoch_secs(), Ordering::Relaxed);
        entry.limiter.check().is_ok()
    }

    fn make_room(&self) {
        if self.clients.len() < MAX_LIMITER_ENTRIES {
            return;
        }
        self.cleanup_stale();
        if self.clients.len() < MAX_LIMITER_ENTRIES {
            return;
        }
        // Bound by its own statement: `iter()` holds shard guards `remove` needs.
        let oldest = self
            .clients
            .iter()
            .min_by_key(|entry| entry.value().last_seen_epoch.load(Ordering::Relaxed))
            .map(|entry| entry.key().clone());
        if let Some(key) = oldest {
            self.clients.remove(&key);
        }
    }

    pub fn cleanup_stale(&self) {
        let now = now_epoch_secs();
        self.clients.retain(|_, entry| {
            now.saturating_sub(entry.last_seen_epoch.load(Ordering::Relaxed))
                <= MAX_LIMITER_IDLE_SECS
        });
    }
}

/// Per-client limits on the HTTPS edge.
pub struct RateLimiter {
    /// Every request; sized for media clients that fetch many thumbnails at once.
    pub general: RateTier,
    /// Admin login.
    pub auth: RateTier,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            general: RateTier::new(500, 220),
            auth: RateTier::new(40, 15),
        }
    }
}

impl RateLimiter {
    /// Drop idle entries (driven by the proxy maintenance tick).
    pub fn cleanup_stale(&self) {
        self.general.cleanup_stale();
        self.auth.cleanup_stale();
    }
}

/// The rate-limit key for a client: an IPv4 address whole, an IPv6 address by its
/// /64. One IPv6 host holds a whole /64, so keying on the full address would hand it
/// 2^64 fresh budgets.
pub fn client_key(client_ip: &str) -> String {
    let Ok(IpAddr::V6(v6)) = client_ip.parse::<IpAddr>() else {
        return client_ip.to_string();
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return v4.to_string();
    }
    format!("{}/64", Ipv6Addr::from(u128::from(v6) & (!0u128 << 64)))
}

/// Paths under the stricter login limit.
pub fn is_auth_sensitive_path(path: &str) -> bool {
    path.starts_with("/api/auth/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_entry_when_capacity_is_reached() {
        let tier = RateTier::new(60, 1);
        for i in 0..MAX_LIMITER_ENTRIES {
            tier.check(&format!("192.0.2.{i}"));
        }
        let now = now_epoch_secs();
        tier.clients
            .get("192.0.2.1")
            .expect("entry")
            .last_seen_epoch
            .store(now - 5, Ordering::Relaxed);

        tier.check("198.51.100.1");
        assert!(
            !tier.clients.contains_key("192.0.2.1"),
            "the least recent key goes"
        );
        assert!(tier.clients.contains_key("192.0.2.2"));
        assert!(tier.clients.contains_key("198.51.100.1"));
    }

    #[test]
    fn login_tier_caps_burst_independently_of_general_traffic() {
        let limiter = RateLimiter::default();
        let ip = "203.0.113.7";
        for i in 0..15 {
            assert!(limiter.auth.check(ip), "login attempt {i} within burst");
        }
        assert!(!limiter.auth.check(ip), "login burst must be capped");
        assert!(
            limiter.general.check(ip),
            "general traffic keeps its own budget"
        );
    }

    #[test]
    fn client_key_collapses_ipv6_to_its_prefix_only() {
        assert_eq!(client_key("2001:db8:1:2::1"), "2001:db8:1:2::/64");
        assert_eq!(
            client_key("2001:db8:1:2:ffff:ffff:ffff:ffff"),
            "2001:db8:1:2::/64"
        );
        assert_ne!(client_key("2001:db8:1:2::1"), client_key("2001:db8:1:3::1"));
        assert_eq!(client_key("203.0.113.9"), "203.0.113.9");
        assert_eq!(client_key("::ffff:203.0.113.9"), "203.0.113.9");
    }

    #[test]
    fn only_login_paths_draw_the_auth_tier() {
        assert!(is_auth_sensitive_path("/api/auth/login"));
        assert!(!is_auth_sensitive_path("/api/resources"));
    }
}
