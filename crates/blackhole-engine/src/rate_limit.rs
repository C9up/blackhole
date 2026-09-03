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
/// window. At the cap, an old bucket is evicted to make room (LRU-ish).
const MAX_BUCKETS: usize = 100_000;

/// How often the whole map is swept for expired buckets.
///
/// Sweeping on every request is what makes the limiter cost O(buckets) per
/// request: at the cap that measured ~4ms, and since it all happens under one
/// mutex it caps the whole server at a few hundred requests a second — a denial
/// of service an attacker triggers just by varying the key. Amortising the
/// sweep makes the common path touch one bucket instead of every bucket, and a
/// full pass once a second is far cheaper than the memory it reclaims.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// How many buckets an eviction looks at before choosing a victim.
///
/// The exact oldest bucket would mean scanning the whole map on every new key
/// once it is full — the same O(buckets) cost, in the exact situation an
/// attacker creates. A bounded sample gives approximate-LRU at a fixed price,
/// which is all the cap needs: it exists to bound memory, not to be fair.
const EVICTION_SAMPLE: usize = 64;

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
    state: Mutex<State>,
}

struct State {
    buckets: HashMap<String, VecDeque<Instant>>,
    /// When the map was last swept end to end, so the sweep can be amortised
    /// instead of paid on every request.
    last_sweep: Instant,
}

impl State {
    /// Drop every entry older than the window, and every bucket left empty.
    fn sweep(&mut self, now: Instant, window: Duration) {
        self.buckets.retain(|_, deque| {
            drop_expired(deque, now, window);
            !deque.is_empty()
        });
        self.last_sweep = now;
    }

    /// Evict the oldest bucket among a bounded sample, to make room for a new
    /// key once the map is at its cap.
    fn evict_sampled(&mut self) {
        let victim = self
            .buckets
            .iter()
            .take(EVICTION_SAMPLE)
            .filter_map(|(key, deque)| deque.front().map(|first| (key, *first)))
            .min_by_key(|(_, first)| *first)
            .map(|(key, _)| key.clone());
        if let Some(key) = victim {
            self.buckets.remove(&key);
        }
    }
}

/// Pop the entries that have fallen out of the window. The deque is ordered by
/// arrival, so this only ever touches the front.
fn drop_expired(deque: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while let Some(front) = deque.front() {
        if now.duration_since(*front) > window {
            deque.pop_front();
        } else {
            break;
        }
    }
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window: Duration::from_secs(window_secs),
            state: Mutex::new(State {
                buckets: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Check if a request from the given key is allowed (bool convenience).
    pub fn check(&self, key: &str) -> bool {
        self.check_detailed(key).allowed
    }

    /// Check a request and return the full outcome (limit / remaining / retry-after).
    pub fn check_detailed(&self, key: &str) -> RateLimitOutcome {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Reclaim expired buckets across the whole map, but only now and then:
        // this is the only O(buckets) work here, and paying it per request is
        // what let a varying key stall every other request (see SWEEP_INTERVAL).
        if now.duration_since(state.last_sweep) >= SWEEP_INTERVAL {
            state.sweep(now, self.window);
        }

        // Bound memory: a new key that would push the map past its cap needs
        // room made for it. No sweep here — one has run within the last
        // SWEEP_INTERVAL by the branch above, so expired buckets are already
        // gone and a second full pass would only re-walk 100k live ones.
        if !state.buckets.contains_key(key) && state.buckets.len() >= MAX_BUCKETS {
            state.evict_sampled();
        }

        let window = self.window;
        let deque = state.buckets.entry(key.to_string()).or_default();

        // This key's own expired entries, which the amortised sweep may not
        // have reached yet. Always paid, and only ever touches one bucket.
        drop_expired(deque, now, window);

        // Seconds until the oldest in-window entry expires → when a slot frees.
        let retry_after_secs = deque
            .front()
            .map(|front| {
                self.window
                    .saturating_sub(now.duration_since(*front))
                    .as_secs()
            })
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
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match state.buckets.get(key) {
            Some(deque) => {
                let active = deque
                    .iter()
                    .filter(|t| now.duration_since(**t) <= self.window)
                    .count() as u32;
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
