use std::num::NonZeroU32;

use governor::clock::DefaultClock;
use governor::RateLimiter;

/// Keyed rate limiter type alias wrapping governor's `RateLimiter` with
/// `DefaultKeyedStateStore` and `DefaultClock`.
pub type KeyedLimiter<K> =
    RateLimiter<K, governor::state::keyed::DefaultKeyedStateStore<K>, DefaultClock>;

/// Result of a failed rate limit check.
#[derive(Debug)]
pub struct RateLimitRejection {
    /// Seconds the client should wait before retrying.
    pub retry_after_secs: u64,
    /// Which limiter scope rejected the request (e.g. "per_ip", "per_target", "global").
    pub scope: &'static str,
}

/// Check a keyed rate limiter with the given cost.
///
/// Returns `Ok(())` if the request is within budget, or `Err(RateLimitRejection)`
/// with the appropriate retry-after duration and scope.
///
/// The `metrics_prefix` is used to increment a counter named
/// `{metrics_prefix}_rate_limit_hits_total` with a `scope` label on rejection.
pub fn check_keyed_cost<K: std::hash::Hash + Eq + Clone>(
    limiter: &KeyedLimiter<K>,
    key: &K,
    cost: NonZeroU32,
    scope: &'static str,
    metrics_prefix: &'static str,
) -> Result<(), RateLimitRejection> {
    let retry_secs = match limiter.check_key_n(key, cost) {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(not_until)) => {
            let wait =
                not_until.wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
            wait.as_secs()
        }
        // InsufficientCapacity: cost exceeds burst size entirely.
        Err(_) => 60,
    };
    let counter_name = format!("{metrics_prefix}_rate_limit_hits_total");
    metrics::counter!(counter_name, "scope" => scope).increment(1);
    Err(RateLimitRejection {
        retry_after_secs: retry_secs.max(1),
        scope,
    })
}

/// Check a direct (unkeyed/global) rate limiter with the given cost.
///
/// Returns `Ok(())` if the request is within budget, or `Err(RateLimitRejection)`
/// with scope `"global"`.
pub fn check_direct_cost(
    limiter: &RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        DefaultClock,
    >,
    cost: NonZeroU32,
    metrics_prefix: &'static str,
) -> Result<(), RateLimitRejection> {
    let retry_secs = match limiter.check_n(cost) {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(not_until)) => {
            let wait =
                not_until.wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
            wait.as_secs()
        }
        Err(_) => 60,
    };
    let counter_name = format!("{metrics_prefix}_rate_limit_hits_total");
    metrics::counter!(counter_name, "scope" => "global").increment(1);
    Err(RateLimitRejection {
        retry_after_secs: retry_secs.max(1),
        scope: "global",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use governor::Quota;
    use std::net::IpAddr;

    fn make_keyed_limiter(per_minute: u32, burst: u32) -> KeyedLimiter<IpAddr> {
        RateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(per_minute).unwrap())
                .allow_burst(NonZeroU32::new(burst).unwrap()),
        )
    }

    fn make_direct_limiter(
        per_minute: u32,
        burst: u32,
    ) -> RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, DefaultClock> {
        RateLimiter::direct(
            Quota::per_minute(NonZeroU32::new(per_minute).unwrap())
                .allow_burst(NonZeroU32::new(burst).unwrap()),
        )
    }

    #[test]
    fn keyed_allows_within_budget() {
        let limiter = make_keyed_limiter(30, 10);
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let cost = NonZeroU32::new(5).unwrap();

        assert!(check_keyed_cost(&limiter, &ip, cost, "per_ip", "test").is_ok());
    }

    #[test]
    fn keyed_rejects_when_exhausted() {
        let limiter = make_keyed_limiter(30, 10);
        let ip: IpAddr = "198.51.100.1".parse().unwrap();

        // Exhaust the burst
        let cost = NonZeroU32::new(10).unwrap();
        assert!(check_keyed_cost(&limiter, &ip, cost, "per_ip", "test").is_ok());

        // Next request should be rejected
        let cost = NonZeroU32::new(1).unwrap();
        let err = check_keyed_cost(&limiter, &ip, cost, "per_ip", "test").unwrap_err();
        assert_eq!(err.scope, "per_ip");
        assert!(err.retry_after_secs >= 1);
    }

    #[test]
    fn keyed_independent_keys() {
        let limiter = make_keyed_limiter(30, 10);
        let ip1: IpAddr = "198.51.100.1".parse().unwrap();
        let ip2: IpAddr = "198.51.100.2".parse().unwrap();
        let cost = NonZeroU32::new(10).unwrap();

        assert!(check_keyed_cost(&limiter, &ip1, cost, "per_ip", "test").is_ok());
        assert!(check_keyed_cost(&limiter, &ip2, cost, "per_ip", "test").is_ok());
    }

    #[test]
    fn keyed_insufficient_capacity() {
        let limiter = make_keyed_limiter(30, 10);
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let cost = NonZeroU32::new(11).unwrap();

        let err = check_keyed_cost(&limiter, &ip, cost, "per_ip", "test").unwrap_err();
        assert_eq!(err.retry_after_secs, 60);
    }

    #[test]
    fn direct_allows_within_budget() {
        let limiter = make_direct_limiter(500, 50);
        let cost = NonZeroU32::new(10).unwrap();

        assert!(check_direct_cost(&limiter, cost, "test").is_ok());
    }

    #[test]
    fn direct_rejects_when_exhausted() {
        let limiter = make_direct_limiter(500, 50);

        let cost = NonZeroU32::new(50).unwrap();
        assert!(check_direct_cost(&limiter, cost, "test").is_ok());

        let cost = NonZeroU32::new(1).unwrap();
        let err = check_direct_cost(&limiter, cost, "test").unwrap_err();
        assert_eq!(err.scope, "global");
        assert!(err.retry_after_secs >= 1);
    }

    #[test]
    fn direct_insufficient_capacity() {
        let limiter = make_direct_limiter(500, 50);
        let cost = NonZeroU32::new(51).unwrap();

        let err = check_direct_cost(&limiter, cost, "test").unwrap_err();
        assert_eq!(err.retry_after_secs, 60);
        assert_eq!(err.scope, "global");
    }
}
