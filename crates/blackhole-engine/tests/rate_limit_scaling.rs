//! The rate limiter's cost must not grow with the number of keys it is holding.
//!
//! It used to: every call swept the whole bucket map, and once the map hit its
//! cap each new key also cloned every key in it to pick an eviction victim.
//! Measured, that took a request from 6µs at a thousand buckets to 4ms at the
//! hundred-thousand cap — and since it all happens under one mutex, that is the
//! ceiling for the whole server, reachable by an attacker who just varies the
//! key (a spoofed `X-Forwarded-For`, or simply many real clients).
//!
//! This asserts the shape of the cost curve rather than any absolute number, so
//! it says the same thing on a slow CI runner as on a workstation.

use blackhole_engine::rate_limit::RateLimiter;
use std::time::{Duration, Instant};

/// Average cost of admitting `probes` previously unseen keys into a limiter
/// already holding `population` of them.
fn cost_per_new_key(population: usize, probes: u32) -> Duration {
    // A limit and window wide enough that nothing is ever refused or expires:
    // this measures bookkeeping, not the decision.
    let limiter = RateLimiter::new(1_000_000, 3_600);
    for i in 0..population {
        limiter.check(&format!("filler-{i}"));
    }

    let start = Instant::now();
    for i in 0..probes {
        limiter.check(&format!("probe-{i}"));
    }
    start.elapsed() / probes
}

#[test]
fn cost_per_request_stays_flat_as_the_bucket_map_fills() {
    let small = cost_per_new_key(1_000, 200);
    let full = cost_per_new_key(100_000, 200);

    // The regression this guards was a factor of ~650. Anything near linear in
    // the bucket count blows through this; ordinary machine noise does not.
    assert!(
        full < small * 100,
        "cost grew with the bucket map: {small:?} at 1k vs {full:?} at the 100k cap"
    );
}

#[test]
fn still_refuses_once_the_limit_is_reached() {
    // The amortised sweep must not let expired-entry bookkeeping drift: a key's
    // own bucket is always pruned before the decision, however long ago the
    // last full sweep ran.
    let limiter = RateLimiter::new(2, 60);
    assert!(limiter.check("client"));
    assert!(limiter.check("client"));
    assert!(!limiter.check("client"));
}
