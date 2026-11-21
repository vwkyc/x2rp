//! Per-client sharded GCRA rate limits for the HTTPS edge.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;

// Cap map size so unbounded client IPs cannot grow RAM forever. Many source IPs can churn entries and obtain a fresh burst (classic in-memory limiter tradeoff).
const SHARDS: usize = 16;
const SHARD_MAX_ENTRIES: usize = 125; // 16 * 125 = 2_000 total cap
const MAX_LIMITER_IDLE_SECS: u64 = 900;
/// Minimum interval between capacity-triggered expiry sweeps per shard.
const CLEANUP_COOLDOWN_SECS: u64 = 30;
/// Batch eviction size per shard so floods amortize O(N) scans across inserts.
const EVICT_BATCH_SIZE: usize = 8;
const NANOS_PER_MINUTE: u64 = 60_000_000_000;

/// Process-local monotonic origin for GCRA nanosecond timestamps (~584 years in `u64`).
static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Monotonic seconds offset above zero so initial entries are strictly > 0 and the
/// first capacity-triggered expiry sweep is never blocked by `last_cleanup_secs == 0`.
const MONOTONIC_SECS_OFFSET: u64 = 3_600;

fn now_monotonic_secs() -> u64 {
    MONOTONIC_SECS_OFFSET + EPOCH.elapsed().as_secs()
}

/// Zero-allocation rate-limit key: an IPv4 address whole, an IPv6 `/64` prefix,
/// or `Unknown` when the peer address is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKey {
    V4(Ipv4Addr),
    V6Prefix(u64),
    Unknown,
}

impl ClientKey {
    fn shard_index(self) -> usize {
        let mix = match self {
            Self::V4(v4) => (u32::from(v4).wrapping_mul(0x9e37_79b9) >> 28) as usize,
            Self::V6Prefix(prefix) => (prefix.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 60) as usize,
            Self::Unknown => 0,
        };
        mix & (SHARDS - 1)
    }
}

struct Entry {
    /// GCRA Theoretical Arrival Time (ns since `EPOCH`).
    tat_ns: AtomicU64,
    last_seen_secs: AtomicU64,
}

/// Cache-line aligned shard so concurrent worker threads on different IPs never false-share.
#[repr(align(64))]
struct Shard {
    clients: RwLock<HashMap<ClientKey, Entry>>,
    last_cleanup_secs: AtomicU64,
}

impl Shard {
    fn new() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            last_cleanup_secs: AtomicU64::new(0),
        }
    }
}

/// One per-key GCRA budget: `per_minute` sustained, `burst` spendable at once.
pub struct RateTier {
    interval_ns: u64,
    burst_ns: u64,
    shards: [Shard; SHARDS],
}

impl RateTier {
    pub fn new(per_minute: u32, burst: u32) -> Self {
        let interval_ns = (NANOS_PER_MINUTE / u64::from(per_minute.max(1))).max(1);
        let burst_ns = interval_ns.saturating_mul(u64::from(burst.max(1)));
        Self {
            interval_ns,
            burst_ns,
            shards: std::array::from_fn(|_| Shard::new()),
        }
    }

    /// Spend one request from `key`'s budget; `false` when it is exhausted.
    pub fn check(&self, key: ClientKey) -> bool {
        let elapsed = EPOCH.elapsed();
        let now_secs = MONOTONIC_SECS_OFFSET + elapsed.as_secs();
        let now_ns = elapsed.as_nanos() as u64;
        let shard = &self.shards[key.shard_index()];
        {
            let clients = shard.clients.read();
            if let Some(entry) = clients.get(&key) {
                entry.last_seen_secs.store(now_secs, Ordering::Relaxed);
                return self.try_consume(entry, now_ns);
            }
        }

        let mut clients = shard.clients.write();
        if let Some(entry) = clients.get(&key) {
            entry.last_seen_secs.store(now_secs, Ordering::Relaxed);
            return self.try_consume(entry, now_ns);
        }
        Self::make_room_locked(&mut clients, &shard.last_cleanup_secs, now_secs);
        let entry = clients.entry(key).or_insert_with(|| Entry {
            tat_ns: AtomicU64::new(0),
            last_seen_secs: AtomicU64::new(now_secs),
        });
        entry.last_seen_secs.store(now_secs, Ordering::Relaxed);
        self.try_consume(entry, now_ns)
    }

    #[inline]
    fn try_consume(&self, entry: &Entry, now_ns: u64) -> bool {
        entry
            .tat_ns
            .try_update(Ordering::AcqRel, Ordering::Acquire, |tat| {
                let next_tat = tat.max(now_ns).saturating_add(self.interval_ns);
                (next_tat.saturating_sub(now_ns) <= self.burst_ns).then_some(next_tat)
            })
            .is_ok()
    }

    fn make_room_locked(
        clients: &mut HashMap<ClientKey, Entry>,
        last_cleanup_secs: &AtomicU64,
        now: u64,
    ) {
        if clients.len() < SHARD_MAX_ENTRIES {
            return;
        }
        let prev = last_cleanup_secs.load(Ordering::Relaxed);
        if now.saturating_sub(prev) >= CLEANUP_COOLDOWN_SECS {
            last_cleanup_secs.store(now, Ordering::Relaxed);
            clients.retain(|_, entry| {
                now.saturating_sub(entry.last_seen_secs.load(Ordering::Relaxed))
                    <= MAX_LIMITER_IDLE_SECS
            });
            if clients.len() < SHARD_MAX_ENTRIES {
                return;
            }
        }
        let mut entries: Vec<(u64, ClientKey)> = clients
            .iter()
            .map(|(&k, entry)| (entry.last_seen_secs.load(Ordering::Relaxed), k))
            .collect();
        let excess = entries
            .len()
            .saturating_sub(SHARD_MAX_ENTRIES.saturating_sub(EVICT_BATCH_SIZE));
        let remove_count = excess.max(1).min(entries.len());
        if remove_count < entries.len() {
            entries.select_nth_unstable_by_key(remove_count - 1, |(ts, _)| *ts);
        }
        for (_, key) in entries.into_iter().take(remove_count) {
            clients.remove(&key);
        }
    }

    pub fn cleanup_stale(&self) {
        let now = now_monotonic_secs();
        for shard in &self.shards {
            shard.clients.write().retain(|_, entry| {
                now.saturating_sub(entry.last_seen_secs.load(Ordering::Relaxed))
                    <= MAX_LIMITER_IDLE_SECS
            });
        }
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
pub fn client_key(ip: IpAddr) -> ClientKey {
    match ip.to_canonical() {
        IpAddr::V4(v4) => ClientKey::V4(v4),
        IpAddr::V6(v6) => ClientKey::V6Prefix((u128::from(v6) >> 64) as u64),
    }
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
        // Pick keys that all land on shard 0 to exercise shard eviction deterministically.
        let keys: Vec<ClientKey> = (0u32..)
            .map(|n| ClientKey::V4(Ipv4Addr::from(0xc000_0200 + n)))
            .filter(|k| k.shard_index() == 0)
            .take(SHARD_MAX_ENTRIES + 1)
            .collect();
        for &k in &keys[..SHARD_MAX_ENTRIES] {
            tier.check(k);
        }
        let oldest = keys[1];
        let newest = keys[2];
        let incoming = keys[SHARD_MAX_ENTRIES];
        let now = now_monotonic_secs();
        {
            let clients = tier.shards[0].clients.read();
            clients[&oldest]
                .last_seen_secs
                .store(now.saturating_sub(5), Ordering::Relaxed);
            clients[&newest]
                .last_seen_secs
                .store(now + 10, Ordering::Relaxed);
        }

        tier.check(incoming);
        let clients = tier.shards[0].clients.read();
        assert!(!clients.contains_key(&oldest), "the least recent key goes");
        assert!(clients.contains_key(&newest));
        assert!(clients.contains_key(&incoming));
        assert!(clients.len() <= SHARD_MAX_ENTRIES);
    }

    #[test]
    fn login_tier_caps_burst_independently_of_general_traffic() {
        let limiter = RateLimiter::default();
        let ip = client_key("203.0.113.7".parse().expect("ip"));
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
        let ip = |s: &str| s.parse::<IpAddr>().expect("ip");
        assert_eq!(
            client_key(ip("2001:db8:1:2::1")),
            client_key(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"))
        );
        assert_ne!(
            client_key(ip("2001:db8:1:2::1")),
            client_key(ip("2001:db8:1:3::1"))
        );
        assert_eq!(
            client_key(ip("203.0.113.9")),
            client_key(ip("::ffff:203.0.113.9"))
        );
    }

    #[test]
    fn only_login_paths_draw_the_auth_tier() {
        assert!(is_auth_sensitive_path("/api/auth/login"));
        assert!(!is_auth_sensitive_path("/api/resources"));
    }
}
