// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A bound on repeated failures for one user-id.
//
// Basic replays a reusable password on every request, so an attacker who can
// reach the route can test guesses as fast as the verifier runs. Hash cost
// alone is not that bound: it sets the price per guess, and an operator who
// lowers the cost to meet a latency budget lowers the price with it.
//
// The bound covers two things an earlier design let through:
//
// - *Concurrency.* A budget read before verification and written after it is
//   no budget at all under load: every parallel guess for one user-id passes
//   the same check before any of them records a failure. An attempt therefore
//   reserves against the budget at admission and releases on its way out, so
//   `max_failures` bounds completed failures *and* attempts in flight.
// - *Saturation.* A full name-keyed map used to stop counting new user-ids
//   entirely, which let an attacker fill it with junk and then guess a fresh
//   target unbounded. Counting now continues in a fixed overflow table that
//   never displaces a named counter.
//
// What this is still not: it is per process, so replicas do not share it, and
// it is keyed per user-id, so a spray across many user-ids never fills one
// counter. Both gaps need an edge or shared counter and are stated in the
// operator documentation rather than implied away here.

use std::collections::HashMap;
use std::hash::BuildHasher as _;
use std::sync::RwLock;
use std::time::Instant;

use crate::plugins::identity_basic::config::FailureLimitConfig;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// How many buckets the overflow table holds.
///
/// Fixed, not configurable: it is a backstop for a saturated name-keyed map,
/// and an operator with a saturation count to act on should raise
/// `failure_limit.capacity` so attempts are counted by name again. A power of
/// two keeps the index a mask.
///
/// 1024 buckets cost about 16 KiB and keep the collision rate low enough that
/// an innocent caller sharing a bucket with an attacker is a rare, window-long
/// denial rather than the routine case.
const OVERFLOW_BUCKETS: usize = 1024;

/// The mask selecting an overflow bucket from a hash.
///
/// Written against the bucket count so the two cannot drift: a mask wider than
/// the table would index past it, and a narrower one would leave buckets
/// unused.
const OVERFLOW_MASK: u64 = (OVERFLOW_BUCKETS - 1) as u64;

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/// A reservation held for one in-flight attempt.
///
/// Obtained from [`FailureLimiter::admit`] and held for as long as the attempt
/// is outstanding. Dropping it releases the reservation, so an attempt that
/// ends in a directory error, a panic or a cancelled future returns its slot
/// to the budget without recording a failure.
///
/// [`FailureLimiter::admit`]: FailureLimiter::admit
#[derive(Debug)]
pub struct Admission<'limiter> {
    limiter: &'limiter FailureLimiter,
    /// Whether the outcome has already been recorded through this guard.
    ///
    /// `record_failure` and `record_success` consume the guard, so the drop
    /// that follows must not release a reservation they have already settled.
    settled: bool,
    /// Which counter `admit` charged this attempt against.
    ///
    /// Carried rather than re-derived at settlement: a named counter can come
    /// and go while an attempt is in flight, so re-probing the map could settle
    /// an overflow attempt on a named counter created after it -- leaking the
    /// overflow reservation, which never expires, and discharging the named
    /// attempt's reservation early.
    slot: Slot,
    user_id: String,
}

impl Admission<'_> {
    /// Record a failed verification and release the reservation.
    pub fn record_failure(mut self) {
        self.settled = true;
        self.limiter.settle_failure(&self.user_id, self.slot);
    }

    /// Clear the user-id's counter after a successful verification.
    pub fn record_success(mut self) {
        self.settled = true;
        self.limiter.settle_success(&self.user_id, self.slot);
    }
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if !self.settled {
            // Neither a failure nor a success: the attempt never produced a
            // verdict on the credential, so it releases its reservation
            // without touching the failure count. A directory that cannot
            // answer must not spend a named victim's budget.
            self.limiter.release(&self.user_id, self.slot);
        }
    }
}

/// Why the limiter refused to admit an attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Refusal {
    /// This user-id has spent its failure budget for the current window.
    ///
    /// Spent by completed failures, attempts in flight, or both: see
    /// [`FailureLimiter::admit`].
    Blocked,
}

/// Consecutive-failure counters, keyed on the normalised user-id.
#[derive(Debug)]
pub struct FailureLimiter {
    config: FailureLimitConfig,
    started: Instant,
    counters: RwLock<Counters>,
    /// How many attempts were counted in the overflow table rather than by
    /// name.
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
            counters: RwLock::new(Counters {
                named: HashMap::new(),
                overflow: std::iter::repeat_with(Counter::default)
                    .take(OVERFLOW_BUCKETS)
                    .collect(),
            }),
            saturations: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Reserve an attempt for `user_id` against its failure budget.
    ///
    /// The returned guard must be held for the whole attempt and settled with
    /// [`Admission::record_failure`] or [`Admission::record_success`] once the
    /// credential has a verdict. Dropping it unsettled releases the
    /// reservation and records nothing, which is what a directory error or a
    /// cancelled request should cost.
    ///
    /// A user-id with no counter in the name-keyed map is counted in a fixed
    /// overflow table instead of going uncounted, so filling the map with junk
    /// user-ids does not buy an attacker an unbounded budget against a fresh
    /// target. A named counter is never displaced to make room, since a flood
    /// of fresh user-ids would then clear a blocked one. What saturation costs
    /// is per-name precision -- colliding user-ids share one bucket -- which is
    /// why it is surfaced through [`saturations`] for an operator to act on by
    /// raising `failure_limit.capacity`.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Blocked`] when the user-id's completed failures and
    /// in-flight attempts together have spent its budget for the current
    /// window.
    ///
    /// [`saturations`]: FailureLimiter::saturations
    pub fn admit(&self, user_id: &str) -> Result<Admission<'_>, Refusal> {
        let now = self.now_ms();
        let window = self.window_ms();
        // A poisoned lock means some holder panicked. Recovered rather than
        // treated as a denial, matching the reload lock in `htpasswd`.
        //
        // Poisoning is permanent -- an `RwLock` is never un-poisoned -- so
        // returning `Blocked` here denied *every* user-id for the rest of the
        // process's life, from one panic, on the hook that gates all
        // authentication. That is the outage this crate avoids `panic =
        // "abort"` to prevent, not a safe default. The counters themselves
        // stay sound: every critical section here is map probes, integer
        // compares and `saturating_*` arithmetic, none of which can panic
        // partway and leave a counter torn.
        //
        // Untested on purpose, rather than untested by oversight: `counters`
        // is private and no critical section above can panic, so poisoning is
        // unreachable through this type's API and a test could only fake it.
        // Anyone adding a fallible critical section here owes it a test.
        let mut guard = self.write();

        if let Some(counter) = guard.named.get_mut(user_id) {
            counter.expire(now);
            if counter.spent(self.config.max_failures) {
                return Err(Refusal::Blocked);
            }
            counter.reserve(now, window);
            return Ok(self.admitted(user_id, Slot::Named));
        }

        // Room for a counter of its own, so the attempt is tracked by name and
        // pays no collision cost.
        if guard.named.len() < self.config.capacity || guard.reclaim(now) {
            let mut counter = Counter::default();
            counter.reserve(now, window);
            guard.named.insert(user_id.to_owned(), counter);
            return Ok(self.admitted(user_id, Slot::Named));
        }

        self.saturations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let bucket = overflow_bucket(user_id);
        let Some(counter) = guard.overflow.get_mut(bucket) else {
            // `overflow_bucket` masks into the table's own length, so this is
            // unreachable; taken rather than indexed because the crate denies
            // `indexing_slicing`, and admitting is the safe side of a bound
            // that cannot be reached anyway. Charged to no counter, so
            // settlement finds nothing to release either.
            return Ok(self.admitted(user_id, Slot::Uncounted));
        };
        counter.expire(now);
        if counter.spent(self.config.max_failures) {
            return Err(Refusal::Blocked);
        }
        counter.reserve(now, window);
        Ok(self.admitted(user_id, Slot::Overflow(bucket)))
    }

    /// How many attempts were counted in the overflow table.
    ///
    /// Those attempts are still bounded, but by a shared bucket rather than by
    /// name: a rising count says `failure_limit.capacity` is too small for the
    /// traffic, so unrelated user-ids may begin to spend each other's budget.
    pub fn saturations(&self) -> u64 {
        self.saturations.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many user-ids are currently tracked by name.
    pub fn tracked(&self) -> usize {
        self.read().named.len()
    }

    fn admitted(&self, user_id: &str, slot: Slot) -> Admission<'_> {
        Admission {
            limiter: self,
            settled: false,
            slot,
            user_id: user_id.to_owned(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Recovered, not skipped: dropping a write would leave a poisoned limiter
    /// counting nothing at all. See `admit`.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Counters> {
        self.counters
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Release an attempt's reservation without recording a verdict.
    fn release(&self, user_id: &str, slot: Slot) {
        let now = self.now_ms();
        let mut guard = self.write();
        guard.with_counter(user_id, slot, |counter| counter.release(now));
    }

    /// Convert an attempt's reservation into a recorded failure.
    fn settle_failure(&self, user_id: &str, slot: Slot) {
        let now = self.now_ms();
        let window = self.window_ms();
        let mut guard = self.write();
        guard.with_counter(user_id, slot, |counter| counter.fail(now, window));
    }

    /// Release an attempt's reservation and clear the user-id's failures.
    ///
    /// A named counter keeps any reservation still outstanding and is removed
    /// only once none is left, so a success does not discharge the guesses
    /// running beside it -- dropping the counter outright would return those
    /// attempts' reservations to an empty budget and let them past it twice.
    ///
    /// An overflow bucket's failures are not cleared at all: the bucket may be
    /// shared, so crediting one caller's success would hand a colliding
    /// attacker a fresh budget.
    fn settle_success(&self, user_id: &str, slot: Slot) {
        let now = self.now_ms();
        let mut guard = self.write();
        match slot {
            Slot::Named => {
                if let Some(counter) = guard.named.get_mut(user_id) {
                    counter.succeed(now);
                    if counter.outstanding == 0 {
                        guard.named.remove(user_id);
                    }
                }
            },
            Slot::Overflow(bucket) => {
                if let Some(counter) = guard.overflow.get_mut(bucket) {
                    counter.release(now);
                }
            },
            Slot::Uncounted => {},
        }
    }

    fn window_ms(&self) -> u64 {
        self.config.window_secs.saturating_mul(1000)
    }

    /// See [`read`]: poisoning is recovered rather than treated as a denial.
    ///
    /// [`read`]: FailureLimiter::read
    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Counters> {
        self.counters
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

// -----------------------------------------------------------------------------
// Private types
// -----------------------------------------------------------------------------

/// Which counter an admitted attempt was charged against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    /// A counter held by name in the map.
    Named,
    /// A bucket in the fixed overflow table, by index.
    Overflow(usize),
    /// Charged to nothing, from the unreachable missing-bucket arm in `admit`.
    Uncounted,
}

/// One user-id's failures, in-flight attempts, and when they stop counting.
#[derive(Debug, Default)]
struct Counter {
    /// Milliseconds since the limiter was built, after which this is expired.
    expires_at_ms: u64,
    failures: u32,
    /// Attempts admitted and not yet settled.
    outstanding: u32,
}

impl Counter {
    /// Whether this counter can be reclaimed or reset.
    ///
    /// An outstanding attempt pins it either way: its reservation is the only
    /// record that the attempt is in flight, so dropping the counter would let
    /// a parallel guess past the budget it was already charged against.
    fn idle(&self, now: u64) -> bool {
        self.outstanding == 0 && !self.live(now)
    }

    /// Drop a stale window's failures, keeping any live reservation.
    fn expire(&mut self, now: u64) {
        if !self.live(now) {
            self.failures = 0;
        }
    }

    /// Settle a reservation as a failure.
    fn fail(&mut self, now: u64, window: u64) {
        self.expire(now);
        self.outstanding = self.outstanding.saturating_sub(1);
        self.failures = self.failures.saturating_add(1);
        self.expires_at_ms = now.saturating_add(window);
    }

    /// Whether this counter still bounds attempts.
    fn live(&self, now: u64) -> bool {
        self.expires_at_ms > now
    }

    /// Settle a reservation without recording a failure.
    fn release(&mut self, now: u64) {
        self.outstanding = self.outstanding.saturating_sub(1);
        self.expire(now);
    }

    /// Charge an admitted attempt against the budget.
    fn reserve(&mut self, now: u64, window: u64) {
        self.outstanding = self.outstanding.saturating_add(1);
        self.expires_at_ms = self.expires_at_ms.max(now.saturating_add(window));
    }

    /// Whether failures and in-flight attempts together have spent `budget`.
    fn spent(&self, budget: u32) -> bool {
        self.failures.saturating_add(self.outstanding) >= budget
    }

    /// Settle a reservation as a success, clearing the recorded failures.
    fn succeed(&mut self, now: u64) {
        self.outstanding = self.outstanding.saturating_sub(1);
        self.failures = 0;
        if self.outstanding == 0 {
            self.expires_at_ms = now;
        }
    }
}

/// The name-keyed counters and the overflow table behind them.
#[derive(Debug)]
struct Counters {
    named: HashMap<String, Counter>,
    /// Fixed-size buckets counting attempts for user-ids the map has no room
    /// to name.
    overflow: Vec<Counter>,
}

impl Counters {
    /// Free at least one named slot, if any counter has gone idle.
    fn reclaim(&mut self, now: u64) -> bool {
        let before = self.named.len();
        self.named.retain(|_, held| !held.idle(now));
        self.named.len() < before
    }

    /// Apply `settle` to the counter `admit` charged this attempt against.
    ///
    /// Directed by the attempt's own `slot` rather than by probing the map
    /// again: the named counter an attempt was charged against may have been
    /// removed and recreated meanwhile, and settling on whatever holds the
    /// user-id now would charge the wrong counter. A named counter that reached
    /// zero on both fields is removed, so settling frees its slot.
    fn with_counter(&mut self, user_id: &str, slot: Slot, settle: impl FnOnce(&mut Counter)) {
        match slot {
            Slot::Named => {
                if let Some(counter) = self.named.get_mut(user_id) {
                    settle(counter);
                    if counter.outstanding == 0 && counter.failures == 0 {
                        self.named.remove(user_id);
                    }
                }
            },
            Slot::Overflow(bucket) => {
                if let Some(counter) = self.overflow.get_mut(bucket) {
                    settle(counter);
                }
            },
            Slot::Uncounted => {},
        }
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Which overflow bucket counts `user_id`.
///
/// `RandomState` is seeded per process, so the bucket a user-id lands in is not
/// predictable from outside and an attacker cannot aim collisions at a chosen
/// victim.
fn overflow_bucket(user_id: &str) -> usize {
    use std::sync::OnceLock;

    static SEED: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();

    let hash = SEED
        .get_or_init(std::collections::hash_map::RandomState::new)
        .hash_one(user_id);
    usize::try_from(hash & OVERFLOW_MASK).unwrap_or(0)
}
