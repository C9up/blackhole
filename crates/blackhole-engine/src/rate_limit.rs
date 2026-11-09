//! Sliding-window rate limiter, in constant memory per key.
//!
//! Each key holds two counters — the requests of its current window and of the
//! one before — instead of a timestamp per request. The count a request is
//! judged against weighs the previous window by how much of it still overlaps
//! the sliding window, plus all of the current one. That keeps what a true
//! sliding log gives (no 2× burst across a window boundary, which a fixed
//! window allows) at a fixed cost per key.
//!
//! A log of one `Instant` per request made memory grow with `max × keys`: at
//! `max: 1000` the bucket cap alone was several gigabytes, reachable by one
//! client rotating source addresses.
//!
//! @implements FR46

use std::collections::HashMap;
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

/// One key's two windows. Constant size, whatever the limit.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// When the current window began.
    started: Instant,
    /// Requests admitted in the current window.
    current: u32,
    /// Requests admitted in the window just before it.
    previous: u32,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            current: 0,
            previous: 0,
        }
    }

    /// Move the windows forward to the one `now` falls in.
    fn roll(&mut self, now: Instant, window: Duration) {
        let elapsed = now.duration_since(self.started);
        if elapsed >= window * 2 {
            // Both windows are behind us: nothing they counted still weighs.
            *self = Bucket::new(now);
        } else if elapsed >= window {
            self.previous = self.current;
            self.current = 0;
            self.started += window;
        }
    }

    /// Whether neither window can weigh on a request any more.
    fn is_spent(&self, now: Instant, window: Duration) -> bool {
        now.duration_since(self.started) >= window * 2
    }
}

struct State {
    buckets: HashMap<String, Bucket>,
    /// When the map was last swept end to end, so the sweep can be amortised
    /// instead of paid on every request.
    last_sweep: Instant,
}

impl State {
    /// Drop every bucket whose windows have both run out.
    fn sweep(&mut self, now: Instant, window: Duration) {
        self.buckets
            .retain(|_, bucket| !bucket.is_spent(now, window));
        self.last_sweep = now;
    }

    /// Evict the oldest bucket among a bounded sample, to make room for a new
    /// key once the map is at its cap.
    fn evict_sampled(&mut self) {
        let victim = self
            .buckets
            .iter()
            .take(EVICTION_SAMPLE)
            .min_by_key(|(_, bucket)| bucket.started)
            .map(|(key, _)| key.clone());
        if let Some(key) = victim {
            self.buckets.remove(&key);
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

    /// Check a request and return the full outcome (limit / remaining / retry-after).
    pub fn check_detailed(&self, key: &str) -> RateLimitOutcome {
        self.check_at(key, Instant::now())
    }

    /// [`check_detailed`](Self::check_detailed) at a given instant — the clock
    /// is a parameter so the window arithmetic can be tested without sleeping.
    pub fn check_at(&self, key: &str, now: Instant) -> RateLimitOutcome {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Reclaim spent buckets across the whole map, but only now and then:
        // this is the only O(buckets) work here, and paying it per request is
        // what let a varying key stall every other request (see SWEEP_INTERVAL).
        if now.saturating_duration_since(state.last_sweep) >= SWEEP_INTERVAL {
            state.sweep(now, self.window);
        }

        // Bound memory: a new key that would push the map past its cap needs
        // room made for it. No sweep here — one has run within the last
        // SWEEP_INTERVAL by the branch above, so spent buckets are already
        // gone and a second full pass would only re-walk 100k live ones.
        if !state.buckets.contains_key(key) && state.buckets.len() >= MAX_BUCKETS {
            state.evict_sampled();
        }

        let window = self.window;
        let max = self.max_requests;
        let bucket = state
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| Bucket::new(now));
        bucket.roll(now, window);

        let estimate = weighted_count(bucket, now, window);
        if estimate + 1.0 > f64::from(max) {
            return RateLimitOutcome {
                allowed: false,
                limit: max,
                remaining: 0,
                // At least 1s so a client never busy-loops on `Retry-After: 0`.
                retry_after_secs: seconds_until_admitted(bucket, now, window, max).max(1),
            };
        }

        bucket.current = bucket.current.saturating_add(1);
        let used = (estimate + 1.0).ceil();
        RateLimitOutcome {
            allowed: true,
            limit: max,
            remaining: (f64::from(max) - used).max(0.0) as u32,
            retry_after_secs: ceil_secs(window.saturating_sub(now.duration_since(bucket.started))),
        }
    }

    pub fn remaining(&self, key: &str) -> u32 {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match state.buckets.get(key) {
            Some(bucket) => {
                let mut bucket = *bucket;
                bucket.roll(now, self.window);
                let used = weighted_count(&bucket, now, self.window).ceil();
                (f64::from(self.max_requests) - used).max(0.0) as u32
            }
            None => self.max_requests,
        }
    }
}

/// The requests the sliding window holds at `now`: all of the current window,
/// and the share of the previous one the sliding window still overlaps.
fn weighted_count(bucket: &Bucket, now: Instant, window: Duration) -> f64 {
    let elapsed = now.duration_since(bucket.started).as_secs_f64();
    let span = window.as_secs_f64();
    let overlap = ((span - elapsed) / span).clamp(0.0, 1.0);
    f64::from(bucket.previous) * overlap + f64::from(bucket.current)
}

/// Seconds from `now` until one more request fits under `max`.
fn seconds_until_admitted(bucket: &Bucket, now: Instant, window: Duration, max: u32) -> u64 {
    let span = window.as_secs_f64();
    let elapsed = now.duration_since(bucket.started).as_secs_f64();
    let left_in_window = (span - elapsed).max(0.0);
    let room = f64::from(max) - 1.0;
    let current = f64::from(bucket.current);
    let wait = if current <= room {
        // The current window still has room; the previous one has to slide
        // far enough out: previous × (left - t) / span + current ≤ room.
        let previous = f64::from(bucket.previous).max(1.0);
        left_in_window - span * (room - current) / previous
    } else {
        // The current window is full: once it becomes the previous one, it
        // has to slide out until current × (span - t') / span ≤ room.
        left_in_window + span * (1.0 - room / current)
    };
    wait.max(0.0).ceil() as u64
}

fn ceil_secs(duration: Duration) -> u64 {
    duration.as_secs_f64().ceil() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_limit() {
        let limiter = RateLimiter::new(3, 60);
        assert!(limiter.check_detailed("ip1").allowed);
        assert!(limiter.check_detailed("ip1").allowed);
        assert!(limiter.check_detailed("ip1").allowed);
    }

    #[test]
    fn blocks_over_limit() {
        let limiter = RateLimiter::new(2, 60);
        assert!(limiter.check_detailed("ip1").allowed);
        assert!(limiter.check_detailed("ip1").allowed);
        assert!(!limiter.check_detailed("ip1").allowed);
    }

    #[test]
    fn separate_keys() {
        let limiter = RateLimiter::new(1, 60);
        assert!(limiter.check_detailed("ip1").allowed);
        assert!(limiter.check_detailed("ip2").allowed);
        assert!(!limiter.check_detailed("ip1").allowed);
    }

    #[test]
    fn remaining_count() {
        let limiter = RateLimiter::new(5, 60);
        assert_eq!(limiter.remaining("ip1"), 5);
        limiter.check_detailed("ip1");
        limiter.check_detailed("ip1");
        assert_eq!(limiter.remaining("ip1"), 3);
    }

    const WINDOW: Duration = Duration::from_secs(60);

    #[test]
    fn a_full_window_still_weighs_at_the_start_of_the_next() {
        // The fixed-window burst: max at the end of one window, max again at
        // the start of the next. The sliding count refuses the second batch.
        let limiter = RateLimiter::new(10, 60);
        let start = Instant::now();
        for _ in 0..10 {
            assert!(limiter.check_at("k", start).allowed);
        }
        let just_after = start + WINDOW + Duration::from_secs(1);
        assert!(!limiter.check_at("k", just_after).allowed);
        // Half a window later, half of the previous window has slid out.
        let halfway = start + WINDOW + Duration::from_secs(30);
        let admitted = (0..10)
            .filter(|_| limiter.check_at("k", halfway).allowed)
            .count();
        assert_eq!(admitted, 5);
    }

    #[test]
    fn two_idle_windows_forget_the_key() {
        let limiter = RateLimiter::new(1, 60);
        let start = Instant::now();
        assert!(limiter.check_at("k", start).allowed);
        assert!(
            !limiter
                .check_at("k", start + Duration::from_secs(30))
                .allowed
        );
        assert!(limiter.check_at("k", start + WINDOW * 2).allowed);
    }

    #[test]
    fn retry_after_is_when_a_request_is_admitted_again() {
        let limiter = RateLimiter::new(2, 60);
        let start = Instant::now();
        assert!(limiter.check_at("k", start).allowed);
        assert!(limiter.check_at("k", start).allowed);
        let refused = limiter.check_at("k", start + Duration::from_secs(10));
        assert!(!refused.allowed);
        let wait = Duration::from_secs(refused.retry_after_secs);
        // Not admitted a second before Retry-After says…
        assert!(
            !limiter
                .check_at(
                    "k",
                    start + Duration::from_secs(10) + wait - Duration::from_secs(1)
                )
                .allowed
        );
        // …and admitted once it has passed.
        assert!(
            limiter
                .check_at("k", start + Duration::from_secs(10) + wait)
                .allowed
        );
    }

    #[test]
    fn a_bucket_is_constant_size_whatever_the_limit() {
        // The memory a key costs must not grow with `max`: the old log held
        // one Instant per admitted request.
        assert!(std::mem::size_of::<Bucket>() <= 32);
        let limiter = RateLimiter::new(1_000_000, 60);
        let start = Instant::now();
        for _ in 0..10_000 {
            limiter.check_at("k", start);
        }
        let state = limiter.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.buckets.len(), 1);
        assert_eq!(state.buckets.get("k").map(|b| b.current), Some(10_000));
    }

    #[test]
    fn detailed_outcome_reports_limit_and_retry_after() {
        let limiter = RateLimiter::new(2, 60);
        let first = limiter.check_detailed("ip1");
        assert!(first.allowed);
        assert_eq!(first.limit, 2);
        assert_eq!(first.remaining, 1);
        limiter.check_detailed("ip1"); // exhaust
        let blocked = limiter.check_detailed("ip1");
        assert!(!blocked.allowed);
        assert_eq!(blocked.remaining, 0);
        // Retry-After is at least 1s so a client never busy-loops.
        assert!(blocked.retry_after_secs >= 1);
    }
}
