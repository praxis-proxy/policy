// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A bound on repeated failures for one user-id.
//
// Basic replays a reusable password on every request, so an attacker who can
// reach the route can test guesses as fast as the verifier runs. Hash cost
// alone is not that bound: it sets the price per guess, and an operator who
// lowers the cost to meet a latency budget lowers the price with it.
//
// What this is not: it is per process, so replicas do not share it, and it is
// keyed per user-id, so a spray across many user-ids never fills one counter.
// Both gaps need an edge or shared counter and are stated in the operator
// documentation rather than implied away here.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

use crate::plugins::identity_basic::config::FailureLimitConfig;

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/// Why the limiter refused to admit an attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Refusal {
    /// This user-id has spent its failure budget for the current window.
    Blocked,

    /// Every tracked slot holds a live counter, and this user-id has none.
    ///
    /// Denied rather than admitted. Evicting a counter to make room would let
    /// a flood of fresh user-ids clear a blocked one, which is the bypass the
    /// capacity ceiling exists to stop; admitting without a counter would make
    /// the limiter inert exactly when it is under attack.
    AtCapacity,
}

/// Consecutive-failure counters, keyed on the normalised user-id.
#[derive(Debug)]
pub struct FailureLimiter {
    config: FailureLimitConfig,
    started: Instant,
    counters: RwLock<HashMap<String, Counter>>,
    /// How many attempts were refused for want of a slot.
    ///
    /// Observable without logging a user-id, which is what makes saturation
    /// actionable: a rising count says the capacity is too small for the
    /// traffic, and nothing in it identifies a caller.
    saturations: std::sync::atomic::AtomicU64,
}

impl FailureLimiter {
    /// Build a limiter from its validated configuration.
    pub fn new(config: FailureLimitConfig) -> Self {
        Self {
            config,
            started: Instant::now(),
            counters: RwLock::new(HashMap::new()),
            saturations: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Whether `user_id` may attempt a verification now.
    ///
    /// # Errors
    ///
    /// Returns a [`Refusal`] when the user-id has spent its budget or the
    /// limiter has no slot to track it in.
    ///
    /// [`Refusal`]: Refusal
    pub fn admit(&self, user_id: &str) -> Result<(), Refusal> {
        let now = self.now_ms();
        let Ok(guard) = self.counters.read() else {
            // A poisoned lock means a panic while a counter was being written.
            // Failing closed: the alternative is an unbounded guess rate on
            // the path this type exists to bound.
            return Err(Refusal::Blocked);
        };
        match guard.get(user_id) {
            Some(counter) if counter.live(now) => {
                if counter.failures >= self.config.max_failures {
                    return Err(Refusal::Blocked);
                }
                Ok(())
            },
            // An expired counter is as good as none: the window has passed, so
            // the budget is spent. It is reclaimed on the recording path,
            // which is the one that would otherwise grow the map.
            Some(_) | None => {
                if guard.len() >= self.config.capacity && !guard.contains_key(user_id) {
                    drop(guard);
                    return self.admit_after_reclaim(user_id, now);
                }
                Ok(())
            },
        }
    }

    /// How many attempts have been refused for want of a slot.
    pub fn saturations(&self) -> u64 {
        self.saturations.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record a failed verification for `user_id`.
    pub fn record_failure(&self, user_id: &str) {
        let now = self.now_ms();
        let Ok(mut guard) = self.counters.write() else {
            return;
        };
        let window = self.config.window_secs.saturating_mul(1000);

        if let Some(counter) = guard.get_mut(user_id) {
            if counter.live(now) {
                counter.failures = counter.failures.saturating_add(1);
            } else {
                counter.failures = 1;
            }
            counter.expires_at_ms = now.saturating_add(window);
            return;
        }

        if guard.len() >= self.config.capacity {
            guard.retain(|_, held| held.live(now));
            if guard.len() >= self.config.capacity {
                // No slot, so this failure goes uncounted. The attempt that
                // produced it was already refused by `admit`, which is where
                // the denial comes from; this only declines to displace a
                // counter that is still doing its job.
                return;
            }
        }
        guard.insert(
            user_id.to_owned(),
            Counter {
                failures: 1,
                expires_at_ms: now.saturating_add(window),
            },
        );
    }

    /// Clear `user_id`'s counter after a successful verification.
    pub fn record_success(&self, user_id: &str) {
        if let Ok(mut guard) = self.counters.write() {
            guard.remove(user_id);
        }
    }

    /// How many user-ids are currently tracked.
    pub fn tracked(&self) -> usize {
        self.counters.read().map_or(0, |guard| guard.len())
    }

    /// Admit after reclaiming expired counters, or report saturation.
    ///
    /// Split out so the read-lock path above stays a read: this takes the
    /// write lock, and it only runs once the map is full.
    fn admit_after_reclaim(&self, user_id: &str, now: u64) -> Result<(), Refusal> {
        let Ok(mut guard) = self.counters.write() else {
            return Err(Refusal::Blocked);
        };
        guard.retain(|_, held| held.live(now));
        if guard.len() >= self.config.capacity && !guard.contains_key(user_id) {
            self.saturations
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(Refusal::AtCapacity);
        }
        Ok(())
    }

    fn now_ms(&self) -> u64 {
        self.started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

// -----------------------------------------------------------------------------
// Private types
// -----------------------------------------------------------------------------

/// One user-id's consecutive failures and when they stop counting.
#[derive(Debug)]
struct Counter {
    failures: u32,
    /// Milliseconds since the limiter was built, after which this is expired.
    expires_at_ms: u64,
}

impl Counter {
    /// Whether this counter still bounds attempts.
    fn live(&self, now: u64) -> bool {
        self.expires_at_ms > now
    }
}
