//! True sliding-window rate limiter.
//!
//! Tracks individual request timestamps per key (typically client IP) using
//! a `VecDeque<Instant>`. On each call, expired entries are evicted from the
//! front of the deque and the new timestamp is pushed to the back. The
//! request is allowed iff `deque.len() <= max_requests`.
//!
//! This prevents the fixed-window burst problem where 2× the limit can be
//! sent across a window boundary.
//!
//! @implements FR46

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hard cap on the number of distinct keys held in memory. Bounds worst-case
/// memory when keys are attacker-controlled (e.g. a spoofable `X-Forwarded-For`
/// rotating fake IPs) — without it the bucket map grows unbounded within a
/// window. At the cap, the oldest bucket is evicted to make room (LRU-ish).
const MAX_BUCKETS: usize = 100_000;

/// Outcome of a rate-limit check, carrying the numbers needed to emit
/// `Retry-After` / `X-RateLimit-*` headers so clients can back off.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitOutcome {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    /// Seconds until a slot frees / the window resets for this key.
    pub retry_after_secs: u64,
}

pub struct RateLimiter {
    max_requests: u32,
    window: Duration,
    buckets: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window: Duration::from_secs(window_secs),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request from the given key is allowed (bool convenience).
    pub fn check(&self, key: &str) -> bool {
        self.check_detailed(key).allowed
    }

    /// Check a request and return the full outcome (limit / remaining / retry-after).
    pub fn check_detailed(&self, key: &str) -> RateLimitOutcome {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Evict stale keys entirely on every call (cheap — only touches front of each deque)
        buckets.retain(|_, deque| {
            while let Some(front) = deque.front() {
                if now.duration_since(*front) > self.window { deque.pop_front(); } else { break; }
            }
            !deque.is_empty()
        });

        // Bound memory: if inserting a NEW key would exceed the cap, evict the
        // bucket whose oldest entry is furthest in the past (closest to expiry).
        if !buckets.contains_key(key) && buckets.len() >= MAX_BUCKETS {
            if let Some(oldest) = buckets
                .iter()
                .filter_map(|(k, d)| d.front().map(|t| (k.clone(), *t)))
                .min_by_key(|(_, t)| *t)
                .map(|(k, _)| k)
            {
                buckets.remove(&oldest);
            }
        }

        let deque = buckets.entry(key.to_string()).or_default();

        // Evict this key's expired entries
        while let Some(front) = deque.front() {
            if now.duration_since(*front) > self.window { deque.pop_front(); } else { break; }
        }

        // Seconds until the oldest in-window entry expires → when a slot frees.
        let retry_after_secs = deque
            .front()
            .map(|front| self.window.saturating_sub(now.duration_since(*front)).as_secs())
            .unwrap_or(0);

        if deque.len() as u32 >= self.max_requests {
            return RateLimitOutcome {
                allowed: false,
                limit: self.max_requests,
                remaining: 0,
                // At least 1s so a client never busy-loops on `Retry-After: 0`.
                retry_after_secs: retry_after_secs.max(1),
            };
        }

        deque.push_back(now);
        RateLimitOutcome {
            allowed: true,
            limit: self.max_requests,
            remaining: self.max_requests.saturating_sub(deque.len() as u32),
            retry_after_secs,
        }
    }

    pub fn remaining(&self, key: &str) -> u32 {
        let buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match buckets.get(key) {
            Some(deque) => {
                let active = deque.iter().filter(|t| now.duration_since(**t) <= self.window).count() as u32;
                self.max_requests.saturating_sub(active)
            }
            None => self.max_requests,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_limit() {
        let limiter = RateLimiter::new(3, 60);
        assert!(limiter.check("ip1"));
        assert!(limiter.check("ip1"));
        assert!(limiter.check("ip1"));
    }

    #[test]
    fn blocks_over_limit() {
        let limiter = RateLimiter::new(2, 60);
        assert!(limiter.check("ip1"));
        assert!(limiter.check("ip1"));
        assert!(!limiter.check("ip1"));
    }

    #[test]
    fn separate_keys() {
        let limiter = RateLimiter::new(1, 60);
        assert!(limiter.check("ip1"));
        assert!(limiter.check("ip2"));
        assert!(!limiter.check("ip1"));
    }

    #[test]
    fn remaining_count() {
        let limiter = RateLimiter::new(5, 60);
        assert_eq!(limiter.remaining("ip1"), 5);
        limiter.check("ip1");
        limiter.check("ip1");
        assert_eq!(limiter.remaining("ip1"), 3);
    }

    #[test]
    fn detailed_outcome_reports_limit_and_retry_after() {
        let limiter = RateLimiter::new(2, 60);
        let first = limiter.check_detailed("ip1");
        assert!(first.allowed);
        assert_eq!(first.limit, 2);
        assert_eq!(first.remaining, 1);
        limiter.check("ip1"); // exhaust
        let blocked = limiter.check_detailed("ip1");
        assert!(!blocked.allowed);
        assert_eq!(blocked.remaining, 0);
        // Retry-After is at least 1s so a client never busy-loops.
        assert!(blocked.retry_after_secs >= 1);
    }
}
