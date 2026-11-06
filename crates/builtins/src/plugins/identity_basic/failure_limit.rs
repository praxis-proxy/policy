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
//
// It is also not an admission controller. The only attempt it refuses is one
// whose own user-id has spent its budget; running out of slots never denies a
// caller, because the callers holding no slot are the ones with no recorded
// failures. `FailureLimiter::admit` carries that reasoning.

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
    ///
    /// The only refusal there is. Saturation deliberately does not produce
    /// one: see [`FailureLimiter::admit`].
    Blocked,
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
    /// Saturation is counted, not enforced. A user-id with no live counter is
    /// one this limiter holds no evidence against, so refusing it would deny
    /// on the absence of evidence -- and because `record_success` drops a
    /// counter, the user-ids holding no slot when the map fills are exactly
    /// the well-behaved ones. Refusing them turned a spray of junk user-ids
    /// into a global outage: at the shipped capacity an attacker could lock
    /// out every legitimate caller for a whole window with cheap requests that
    /// never reached a hash. Admitting instead costs the attacker the full
    /// verification price per guess and leaves the directory's own saturation
    /// ceiling as the bound on concurrency.
    ///
    /// This does not reopen the eviction bypass. A counter is never displaced
    /// to make room: a full map stops *counting* new user-ids (see
    /// [`record_failure`]), and a blocked counter is found and enforced here
    /// whatever the map's occupancy. What saturation costs is new counters,
    /// which is why it is surfaced through [`saturations`] for an operator to
    /// act on by raising `failure_limit.capacity`.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Blocked`] when the user-id has spent its failure
    /// budget for the current window.
    ///
    /// [`record_failure`]: FailureLimiter::record_failure
    /// [`saturations`]: FailureLimiter::saturations
    pub fn admit(&self, user_id: &str) -> Result<(), Refusal> {
        let now = self.now_ms();
        // A poisoned lock means some holder panicked. Recovered rather than
        // treated as a denial, matching the reload lock in `htpasswd`.
        //
        // Poisoning is permanent -- an `RwLock` is never un-poisoned -- so
        // returning `Blocked` here denied *every* user-id for the rest of the
        // process's life, from one panic, on the hook that gates all
        // authentication. That is the outage this crate avoids `panic =
        // "abort"` to prevent, not a safe default. The counters themselves
        // stay sound: every critical section here is map probes, integer
        // compares and `saturating_add`, none of which can panic partway and
        // leave a counter torn, so the worst a recovered guard shows is a
        // count written just before an unrelated panic.
        //
        // Untested on purpose, rather than untested by oversight: `counters`
        // is private and no critical section above can panic, so poisoning is
        // unreachable through this type's API and a test could only fake it.
        // Anyone adding a fallible critical section here owes it a test.
        let guard = self
            .counters
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.get(user_id) {
            Some(counter) if counter.live(now) => {
                if counter.failures >= self.config.max_failures {
                    return Err(Refusal::Blocked);
                }
                Ok(())
            },
            // An expired counter is as good as none: the window has passed,
            // so the budget is restored. Reclaiming it is left to
            // `record_failure`, the path that would otherwise grow the map,
            // which keeps this one a read.
            Some(_) | None => {
                if guard.len() >= self.config.capacity && !guard.contains_key(user_id) {
                    self.saturations
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(())
            },
        }
    }

    /// How many attempts found no slot to be tracked in.
    ///
    /// Those attempts were admitted, not refused: a rising count says new
    /// failures are going uncounted because `failure_limit.capacity` is too
    /// small for the traffic, not that callers were denied.
    pub fn saturations(&self) -> u64 {
        self.saturations.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record a failed verification for `user_id`.
    pub fn record_failure(&self, user_id: &str) {
        let now = self.now_ms();
        // Recovered, not skipped: dropping the write would leave a poisoned
        // limiter counting nothing at all. See `admit`.
        let mut guard = self
            .counters
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                // No slot, so this failure goes uncounted: every counter held
                // is still live, and displacing one would let a flood of fresh
                // user-ids clear a blocked counter. The attempt itself was
                // admitted -- `admit` does not refuse for want of a slot -- so
                // what is lost is the bound on *this* user-id, which is what
                // the saturation count tells an operator to fix.
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
        // Recovered for the same reason as `record_failure`: a poisoned
        // limiter that cannot clear a counter would hold a legitimate user at
        // their spent budget for the whole window.
        self.counters
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(user_id);
    }

    /// How many user-ids are currently tracked.
    pub fn tracked(&self) -> usize {
        self.counters
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
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
