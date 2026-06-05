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

    /// Check if a request from the given key is allowed.
    pub fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Evict stale keys entirely on every call (cheap — only touches front of each deque)
        buckets.retain(|_, deque| {
            while let Some(front) = deque.front() {
                if now.duration_since(*front) > self.window { deque.pop_front(); } else { break; }
            }
            !deque.is_empty()
        });

        let deque = buckets.entry(key.to_string()).or_insert_with(VecDeque::new);

        // Evict this key's expired entries
        while let Some(front) = deque.front() {
            if now.duration_since(*front) > self.window { deque.pop_front(); } else { break; }
        }

        if deque.len() as u32 >= self.max_requests {
            return false;
        }

        deque.push_back(now);
        true
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
}
