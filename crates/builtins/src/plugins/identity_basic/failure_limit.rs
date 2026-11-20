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
//   never displaces a named counter, and a user-id promoted out of that table
//   carries its recorded failures with it, so a freed slot is not a fresh
//   budget.
// - *Shared-bucket lockout.* An overflow bucket is shared, so refusing on a
//   spent one denied callers for failures that were not theirs. Since a
//   successful login removes its named counter, the callers routed through
//   overflow are exactly the well-behaved ones, which made a junk-user-id
//   spray a blanket authentication outage. A spent bucket still refuses, but
//   recoverably rather than outright: the refusal rests on evidence that is
//   not this caller's, so the attempt is admitted for verification and only a
//   caller who knows the password clears it. Only the caller who knows the
//   password can clear a bucket they share with an attacker.
//
// Where a refusal is decided follows from what it is keyed on, and a counter
// keeps the two kinds of failure apart for as long as it lives. Its own
// failures name one caller, so they refuse outright and cost an attacker
// nothing. Failures inherited from a shared bucket on promotion cannot be
// attributed, so a counter spent only by those refuses recoverably -- the
// unattributable evidence does not stop carrying over just because a named
// slot opened, which is what made promotion a lockout: a user-id that reached
// a counter of its own was judged on a spray's failures and denied without the
// verification that would have cleared it.
//
// A recoverable refusal is still admission-controlled. It carries a
// reservation against a ceiling on concurrent unproven attempts -- sized
// against the backend's verification capacity, so recovery never holds every
// permit an ordinary attempt needs -- because
// the verification it asks for is CPU-bound work an attacker repeats for free:
// without that ceiling a wrong-password spray on one user-id occupied the
// backend's verification permits and turned a bounded refusal into a directory
// outage for every other caller.
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

/// How many unproven verifications may run at once, across all user-ids.
///
/// A recoverable refusal asks the caller to verify the credential anyway, and
/// that verification is the expensive step. The refusal charges no failure
/// budget -- it cannot, since the failures behind it are not the caller's to
/// spend -- so without a ceiling of its own a wrong-password spray on one
/// user-id held every verification permit the directory has and unrelated
/// callers were denied `DIRECTORY_UNAVAILABLE`: a refusal that costs an
/// attacker nothing, turned into an outage for everyone else.
///
/// A concurrency ceiling rather than a per-attempt budget, because the budget
/// would have to live on the shared bucket and a spray would spend it for
/// every colliding caller -- recreating, one layer down, the blanket lockout
/// the recoverable refusal exists to prevent. What has to be bounded is the
/// concurrent CPU this path can hold, not how often a caller may prove
/// itself: a correct password is always served.
///
/// Not configurable but not fixed either: derived from the verifier capacity
/// it has to stay clear of, because the number that matters is how many
/// permits are *left*, not how many recovery slots sound reasonable. A
/// standalone 8 held against the htpasswd default of 32 and failed everywhere
/// below it -- `max_concurrent_verifications` is valid from 1 upward, so at a
/// capacity of 8 or less recovery could occupy every permit the directory has
/// and a caller with an unspent named budget was denied
/// `auth.directory_unavailable`: the ceiling existed to prevent exactly that
/// outage and, below the default, caused it. See
/// [`recovery_ceiling`][FailureLimiter::recovery_ceiling].
const MAX_UNPROVEN_IN_FLIGHT: u32 = 8;

/// The largest share of verifier capacity the recovery path may hold.
///
/// A quarter, so ordinary attempts keep the other three: recovery is the path
/// that costs an attacker nothing to repeat, so it gets the minority share of
/// a contended resource.
const RECOVERY_CAPACITY_DIVISOR: usize = 4;

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
    /// Whether unattributable failures already refused this attempt.
    ///
    /// Set on the recoverable path, where the attempt is charged against the
    /// counter's separate unproven budget rather than its failure budget.
    /// Settlement therefore records no failure and refunds a success.
    unproven: bool,
    user_id: String,
}

impl Admission<'_> {
    /// Whether an unattributable failure count already refused this attempt.
    ///
    /// True for an attempt admitted so that a verified credential can clear a
    /// refusal resting on evidence that is not this caller's. A caller must
    /// verify the credential before serving one, and must deny a failed
    /// verdict as a budget refusal rather than as a wrong password: the
    /// refusal that admitted it still stands.
    pub fn is_unproven(&self) -> bool {
        self.unproven
    }

    /// Record a failed verification and release the reservation.
    ///
    /// A failed *recovery* still charges a named counter. The refusal it
    /// answered rested on evidence that was not the caller's, but the wrong
    /// password it just produced is: a named counter attributes a failure to
    /// one user-id, so it bounds that user-id like any other. Without this the
    /// ceiling bounded only how many recoveries ran at once -- a promoted
    /// counter sat at `Verdict::Unproven` with `failures` pinned at zero, and
    /// sequential guesses reached the verifier until the window expired, with
    /// `max_failures` bounding nothing at all for the one user-id an attacker
    /// had already spent a bucket on.
    ///
    /// A shared bucket is charged nothing, for the reason it never was: its
    /// failures already count whatever spent them, and a second charge is a
    /// budget the colliding caller cannot clear. That caller is bounded by the
    /// ceiling and by its own promotion, once a named slot frees.
    ///
    /// A *successful* recovery still costs nothing, so a legitimate caller
    /// sharing a bucket re-proves itself without limit.
    pub fn record_failure(mut self) {
        self.settled = true;
        if self.unproven {
            self.limiter
                .settle_unproven_failure(&self.user_id, self.slot);
            return;
        }
        self.limiter.settle_failure(&self.user_id, self.slot);
    }

    /// Clear the user-id's counter after a successful verification.
    ///
    /// For an unproven attempt this is the proof its refusal asked for, and is
    /// counted through [`proven`]. The *inherited* failures are left standing:
    /// they may be a colliding attacker's, so crediting this caller's success
    /// would hand that attacker a fresh budget. The caller re-proves itself on
    /// every request for as long as those failures live.
    ///
    /// Failures this caller recorded on its own failed recoveries are cleared,
    /// like any other success clears its counter. They are attributable, so
    /// the proof that clears them is this caller's to spend -- and without
    /// this a caller that mistyped a password once while sharing a spent
    /// bucket was blocked after `max_failures` mistakes however many correct
    /// passwords it sent in between, which is the lockout the recoverable
    /// refusal exists to prevent.
    ///
    /// [`proven`]: FailureLimiter::proven
    pub fn record_success(mut self) {
        self.settled = true;
        if self.unproven {
            self.limiter.settle_proven(&self.user_id, self.slot);
            return;
        }
        self.limiter.settle_success(&self.user_id, self.slot);
    }
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if self.unproven {
            if !self.settled {
                // No reservation against the failure budget to return, but the
                // ceiling slot must come back however the attempt ended: a
                // leaked slot is permanent, and enough of them close the
                // recovery path for the life of the process.
                self.limiter.release_unproven();
            }
            return;
        }
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
    /// The bounded recovery path for unattributable failures is itself full.
    ///
    /// An attempt refused on failures that are not the caller's own is
    /// admitted anyway so the credential can clear it, but only up to a
    /// ceiling on how many such verifications run at once, sized against the
    /// backend's verification capacity. Past that ceiling
    /// the attempt is refused without one, because the verification a
    /// recoverable refusal asks for is CPU-bound work an attacker repeats for
    /// free.
    ///
    /// Denied like [`Blocked`], and kept separate from it so an operator can
    /// tell a user-id that spent its own budget from a saturated map starving
    /// the recovery path. The second is a signal to raise
    /// `failure_limit.capacity`.
    ///
    /// [`Blocked`]: Refusal::Blocked
    Saturated,
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
    /// How many refusals on unattributable failures a verified credential
    /// then cleared.
    proven: std::sync::atomic::AtomicU64,
    /// How many unproven verifications are running right now.
    ///
    /// Global rather than per-counter, and a concurrency count rather than a
    /// spend: see [`MAX_UNPROVEN_IN_FLIGHT`] for why a budget on the shared
    /// bucket would deny the callers this path exists to serve.
    ///
    /// [`MAX_UNPROVEN_IN_FLIGHT`]: MAX_UNPROVEN_IN_FLIGHT
    unproven_in_flight: std::sync::atomic::AtomicU32,
    /// How many unproven verifications may run at once, for this directory.
    ///
    /// Derived at construction from the backend's verification capacity rather
    /// than read from a constant: see
    /// [`recovery_ceiling`][FailureLimiter::recovery_ceiling].
    unproven_ceiling: u32,
}

impl FailureLimiter {
    /// Build a limiter from its validated configuration.
    ///
    /// `verification_capacity` is the backend's concurrent-verification limit,
    /// which the recovery ceiling is sized against so recovery cannot occupy
    /// every permit an ordinary attempt needs.
    pub fn new(config: FailureLimitConfig, verification_capacity: usize) -> Self {
        Self {
            unproven_ceiling: Self::recovery_ceiling(verification_capacity),
            config,
            started: Instant::now(),
            counters: RwLock::new(Counters {
                named: HashMap::new(),
                overflow: std::iter::repeat_with(Counter::default)
                    .take(OVERFLOW_BUCKETS)
                    .collect(),
            }),
            saturations: std::sync::atomic::AtomicU64::new(0),
            proven: std::sync::atomic::AtomicU64::new(0),
            unproven_in_flight: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// How many concurrent unproven verifications `capacity` permits leave
    /// room for.
    ///
    /// A quarter of capacity, capped at [`MAX_UNPROVEN_IN_FLIGHT`] and floored
    /// at one. Each bound answers a different failure:
    ///
    /// - The *share* keeps ordinary attempts the majority of a contended
    ///   resource. A fixed ceiling could not: at the htpasswd default of 32 it
    ///   left 24 permits spare, and at a configured capacity of 8 or less it
    ///   left none, so a caller whose own budget was unspent was denied
    ///   `auth.directory_unavailable` by recovery traffic -- the outage the
    ///   ceiling exists to prevent.
    /// - The *cap* keeps the absolute amount of free CPU work bounded as
    ///   capacity grows. A quarter of a large capacity is still more
    ///   attacker-free verification than this path needs.
    /// - The *floor* keeps recovery reachable at a capacity of one, where a
    ///   quarter rounds to zero. Zero would close the path outright and
    ///   restore the blanket lockout for a saturated map: a legitimate caller
    ///   sharing a bucket could never prove itself. One slot serialises
    ///   recovery against that single permit rather than forbidding it, and an
    ///   operator who configured one permit has already accepted that any two
    ///   concurrent verifications contend.
    ///
    /// [`MAX_UNPROVEN_IN_FLIGHT`]: MAX_UNPROVEN_IN_FLIGHT
    fn recovery_ceiling(capacity: usize) -> u32 {
        let share = capacity / RECOVERY_CAPACITY_DIVISOR;
        let bounded = u32::try_from(share).unwrap_or(MAX_UNPROVEN_IN_FLIGHT);
        bounded.clamp(1, MAX_UNPROVEN_IN_FLIGHT)
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
    /// A guard whose [`is_unproven`] is set was refused on failures that
    /// cannot be attributed to this caller, and admitted so that the
    /// credential can clear the refusal. Such a caller must verify the
    /// credential and deny a failed verdict as a budget refusal rather than as
    /// a wrong password.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Blocked`] when the user-id's own completed failures
    /// and in-flight attempts together have spent its budget for the current
    /// window, and [`Refusal::Saturated`] when the attempt would be
    /// recoverable but the bounded recovery path is already full.
    ///
    /// [`is_unproven`]: Admission::is_unproven
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
            return match counter.verdict(self.config.max_failures) {
                Verdict::Admit => {
                    counter.reserve();
                    Ok(self.admitted(user_id, Slot::Named))
                },
                Verdict::Blocked => Err(Refusal::Blocked),
                // Spent, but only once the failures carried in from a shared
                // bucket are counted. Those are not this caller's to answer
                // for, so the refusal stays recoverable for as long as they
                // live rather than hardening into a block the moment a named
                // slot opened. Charged against the separate unproven budget
                // and not the failure budget: spending the latter would deny
                // this caller for an attacker's guesses, which is the lockout
                // the recoverable refusal exists to prevent.
                Verdict::Unproven => {
                    if self.claim_unproven() {
                        Ok(self.admitted_unproven(user_id, Slot::Named))
                    } else {
                        Err(Refusal::Saturated)
                    }
                },
            };
        }

        // Room for a counter of its own, so the attempt is tracked by name and
        // pays no collision cost.
        if guard.named.len() < self.config.capacity || guard.reclaim(now) {
            // Seeded from the overflow bucket rather than started at zero.
            // The arms otherwise share no failure state, so promoting a
            // user-id out of overflow was a budget reset: a blocked attacker
            // regained a full `max_failures` the moment any slot freed --
            // including one freed by an unrelated caller's successful login,
            // which an attacker needs neither to control nor to observe.
            //
            // `outstanding` is not carried over. Those reservations belong to
            // attempts still in flight, possibly for colliding user-ids, and
            // each settles on the `Slot::Overflow` it was charged against.
            //
            // Over-counting a collision is the imprecision the overflow table
            // already documents, and it fails closed: an inherited count only
            // ever bounds this user-id sooner, never later.
            //
            // Kept in `inherited` rather than folded into `failures`, because
            // the two differ in what they can justify. A shared bucket cannot
            // say which user-id failed, so counting its failures as this
            // caller's own made promotion a lockout: a correct password was
            // denied unverified on a junk-user-id spray's evidence, which is
            // exactly the outage the recoverable refusal exists to prevent.
            // They still bound this user-id, and bound it recoverably.
            let inherited = guard.overflow_failures(user_id, now);
            let mut counter = Counter {
                // Only a counter carrying failures needs a window; a fresh one
                // takes its first from `fail`, as `reserve` opens none.
                expires_at_ms: if inherited == 0 {
                    0
                } else {
                    now.saturating_add(window)
                },
                failures: 0,
                inherited,
                outstanding: 0,
            };
            return match counter.verdict(self.config.max_failures) {
                Verdict::Admit => {
                    counter.reserve();
                    guard.named.insert(user_id.to_owned(), counter);
                    Ok(self.admitted(user_id, Slot::Named))
                },
                // A counter built here records no failures of its own, so its
                // own budget cannot be the thing that is spent.
                Verdict::Blocked => Err(Refusal::Blocked),
                Verdict::Unproven => {
                    // Inserted so the inherited count lives in the named
                    // counter and expires on its own window, rather than being
                    // re-read from a shared bucket a colliding attacker keeps
                    // refreshing. Nothing is reserved on it: the attempt holds
                    // a slot on the unproven ceiling instead.
                    guard.named.insert(user_id.to_owned(), counter);
                    if self.claim_unproven() {
                        Ok(self.admitted_unproven(user_id, Slot::Named))
                    } else {
                        Err(Refusal::Saturated)
                    }
                },
            };
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
            // Refused, but recoverably: the bucket is shared, so its failures
            // may belong to any user-id hashing here. Admitted against the
            // separate unproven budget so a verified credential can clear it,
            // since a spray of junk user-ids can spend every bucket and
            // refusing outright denies every caller the saturated map cannot
            // name. A caller that cannot verify is still denied, and that
            // budget bounds what the attempts themselves cost.
            //
            // Nothing is reserved on the bucket. Its failures already count
            // the attempt that spent it, and a second charge here would be a
            // budget this caller cannot clear -- on a bucket shared with
            // whatever spent it.
            return if self.claim_unproven() {
                Ok(self.admitted_unproven(user_id, Slot::Overflow(bucket)))
            } else {
                Err(Refusal::Saturated)
            };
        }
        counter.reserve();
        Ok(self.admitted(user_id, Slot::Overflow(bucket)))
    }

    /// How many refusals on unattributable failures a verified credential then
    /// cleared.
    ///
    /// A rising count means legitimate callers are being judged on failures
    /// they do not own, which is the signal to raise `failure_limit.capacity`.
    /// Carries no user-id, for the same reason [`saturations`] does not.
    ///
    /// [`saturations`]: FailureLimiter::saturations
    pub fn proven(&self) -> u64 {
        self.proven.load(std::sync::atomic::Ordering::Relaxed)
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
            unproven: false,
            user_id: user_id.to_owned(),
        }
    }

    /// An admission for an attempt unattributable failures already refused.
    fn admitted_unproven(&self, user_id: &str, slot: Slot) -> Admission<'_> {
        Admission {
            limiter: self,
            settled: false,
            slot,
            unproven: true,
            user_id: user_id.to_owned(),
        }
    }

    /// Take a slot on the unproven-verification ceiling, if one is free.
    ///
    /// A compare-exchange loop rather than a fetch-add and a rollback: an add
    /// that overshoots is briefly visible to every other attempt, so a burst
    /// arriving together would refuse each other on slots all about to be
    /// returned.
    fn claim_unproven(&self) -> bool {
        let mut held = self
            .unproven_in_flight
            .load(std::sync::atomic::Ordering::Acquire);
        loop {
            if held >= self.unproven_ceiling {
                return false;
            }
            match self.unproven_in_flight.compare_exchange_weak(
                held,
                held.saturating_add(1),
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(current) => held = current,
            }
        }
    }

    /// Count a verified credential that cleared an unproven refusal.
    fn count_proven(&self) {
        self.proven
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Return a slot to the unproven-verification ceiling.
    fn release_unproven(&self) {
        // Saturating, not wrapping: a count that reached zero and underflowed
        // would read as full and refuse every recovery for the life of the
        // process, which is the outage this path exists to avoid.
        let _ = self.unproven_in_flight.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |held| Some(held.saturating_sub(1)),
        );
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
    /// attacker a fresh budget. Inherited failures in a named counter are left
    /// standing for the same reason, and are what the caller re-proves itself
    /// against on its next request.
    fn settle_success(&self, user_id: &str, slot: Slot) {
        let now = self.now_ms();
        let mut guard = self.write();
        match slot {
            Slot::Named => {
                if let Some(counter) = guard.named.get_mut(user_id) {
                    counter.succeed(now);
                    if counter.outstanding == 0 && counter.inherited == 0 {
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

    /// Settle an unproven attempt whose credential did not verify.
    ///
    /// Returns the ceiling slot and charges the failure where it can be
    /// attributed. A named counter can: the wrong password is this user-id's,
    /// whatever the inherited count that refused the attempt was, so the
    /// failure is recorded and `max_failures` wrong recoveries turn
    /// `Verdict::Unproven` into `Verdict::Blocked`. A shared bucket cannot, so
    /// it is left alone -- charging it would spend a budget on behalf of every
    /// colliding user-id, which is the blanket lockout this path exists to
    /// prevent.
    fn settle_unproven_failure(&self, user_id: &str, slot: Slot) {
        // Before the counter work, so the slot comes back even if the counter
        // the attempt was charged against has since been removed.
        self.release_unproven();
        if slot == Slot::Named {
            self.settle_named_unproven_failure(user_id);
        }
    }

    /// Record a failed recovery against a named counter.
    ///
    /// Reaches the counter directly rather than through `with_counter`: that
    /// helper removes a counter settling to zero on every field, and an
    /// unproven attempt holds no reservation, so a counter carrying only
    /// inherited failures would be removed by the very failure meant to bound
    /// it -- handing the next attempt a fresh budget.
    fn settle_named_unproven_failure(&self, user_id: &str) {
        let now = self.now_ms();
        let window = self.window_ms();
        let mut guard = self.write();
        if let Some(counter) = guard.named.get_mut(user_id) {
            counter.fail_unreserved(now, window);
        }
    }

    /// Settle an unproven attempt whose credential verified.
    ///
    /// Counts the proof, returns the ceiling slot, and clears the failures
    /// this caller recorded on its own failed recoveries. The *inherited*
    /// count is left standing: it may be a colliding attacker's, so clearing
    /// it would hand that attacker a fresh budget, and this caller re-proves
    /// itself on its next request for as long as it lives.
    ///
    /// A shared bucket is left alone for the same reason it is charged
    /// nothing: nothing on it is this caller's to clear.
    fn settle_proven(&self, user_id: &str, slot: Slot) {
        self.count_proven();
        self.release_unproven();
        if slot == Slot::Named {
            self.clear_proven_failures(user_id);
        }
    }

    /// Clear a named counter's own failures after a proven recovery.
    ///
    /// Reaches the counter directly for the reason
    /// [`settle_named_unproven_failure`] does: the attempt holds no
    /// reservation, so `with_counter`'s zero check is not the right test, and
    /// a counter still carrying inherited failures must survive this to keep
    /// bounding the user-id recoverably.
    ///
    /// [`settle_named_unproven_failure`]: FailureLimiter::settle_named_unproven_failure
    fn clear_proven_failures(&self, user_id: &str) {
        let mut guard = self.write();
        let Some(counter) = guard.named.get_mut(user_id) else {
            return;
        };
        counter.clear_own_failures();
        // Nothing left to bound the user-id: no failures of its own, no
        // inherited count, no attempt in flight. Removed so the named slot
        // returns to `capacity` rather than being pinned by an empty counter.
        if counter.outstanding == 0 && counter.inherited == 0 {
            guard.named.remove(user_id);
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

/// What a counter says about one more attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    /// Budget to spare: reserve and verify.
    Admit,
    /// Spent by failures attributed to this user-id. Refuse outright.
    Blocked,
    /// Spent only once failures inherited from a shared bucket are counted.
    ///
    /// Those cannot be attributed, so the refusal they justify is recoverable:
    /// a verified credential is the only evidence separating this caller from
    /// whatever else hashed into the bucket.
    Unproven,
}

/// One user-id's failures, in-flight attempts, and when they stop counting.
#[derive(Debug, Default)]
struct Counter {
    /// Milliseconds since the limiter was built, after which this is expired.
    expires_at_ms: u64,
    failures: u32,
    /// Failures carried in from a shared overflow bucket on promotion.
    ///
    /// Held apart from `failures` because they justify a different refusal.
    /// A shared bucket cannot say which user-id failed, so these bound the
    /// user-id recoverably: they refuse an attempt, and a verified credential
    /// clears that refusal. Folding them into `failures` made promotion out of
    /// overflow a lockout, denying a correct password unverified on evidence
    /// that was not the caller's.
    inherited: u32,
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
    ///
    /// Inherited failures expire on the same window as recorded ones. They are
    /// a shared bucket's evidence against this user-id, and evidence that no
    /// longer bounds the bucket must not keep bounding the caller it was
    /// copied to.
    fn expire(&mut self, now: u64) {
        if !self.live(now) {
            self.failures = 0;
            self.inherited = 0;
        }
    }

    /// Settle a reservation as a failure.
    fn fail(&mut self, now: u64, window: u64) {
        self.expire(now);
        self.outstanding = self.outstanding.saturating_sub(1);
        self.failures = self.failures.saturating_add(1);
        self.expires_at_ms = now.saturating_add(window);
    }

    /// Record a failure for an attempt that holds no reservation.
    ///
    /// The recovery path admits against the unproven ceiling rather than
    /// reserving on the counter, so settling one must not decrement
    /// `outstanding`: that would discharge a *different* attempt's reservation
    /// and let a parallel guess past the budget it was already charged
    /// against. Everything else matches [`fail`] -- the failure counts and
    /// reopens the window from now.
    ///
    /// [`fail`]: Counter::fail
    fn fail_unreserved(&mut self, now: u64, window: u64) {
        self.expire(now);
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
    ///
    /// Deliberately leaves `expires_at_ms` alone: `fail` is the only path that
    /// opens a window, which is what `window_secs` documents -- how long a
    /// counter survives its last *failure*. Pushing it forward on every
    /// admitted attempt instead meant one in-budget attempt per window held a
    /// partial failure count open for as long as the traffic lasted, keeping a
    /// victim permanently one attempt from a block and pinning a named slot
    /// against `capacity` far more cheaply than re-blocking them would.
    ///
    /// The in-flight attempt is still pinned without a window of its own:
    /// `idle` requires `outstanding == 0` before a counter can be reclaimed,
    /// and `expire` clears only `failures`, never `outstanding`.
    fn reserve(&mut self) {
        self.outstanding = self.outstanding.saturating_add(1);
    }

    /// Whether every kind of failure and the attempts in flight have spent
    /// `budget`.
    fn spent(&self, budget: u32) -> bool {
        self.failures
            .saturating_add(self.inherited)
            .saturating_add(self.outstanding)
            >= budget
    }

    /// What this counter says about one more attempt.
    ///
    /// Splits a spent budget by what spent it. Only failures this user-id is
    /// answerable for -- its own, plus the attempts it has in flight -- justify
    /// refusing before a verification; when inherited failures are what tipped
    /// it, the refusal is recoverable instead.
    fn verdict(&self, budget: u32) -> Verdict {
        if !self.spent(budget) {
            Verdict::Admit
        } else if self.failures.saturating_add(self.outstanding) >= budget {
            Verdict::Blocked
        } else {
            Verdict::Unproven
        }
    }

    /// Clear the failures this user-id recorded itself, keeping inherited ones.
    ///
    /// For a proven recovery, which holds no reservation: `outstanding` is
    /// another attempt's and is left alone. The window is not closed either --
    /// an inherited count may still be live, and it is what the caller
    /// re-proves itself against on its next request.
    fn clear_own_failures(&mut self) {
        self.failures = 0;
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
    /// The live failures recorded for a user-id in the overflow table.
    ///
    /// Expires the bucket first, so a stale window contributes nothing. Reads
    /// zero when the index cannot be taken, which `overflow_bucket`'s mask
    /// makes unreachable; the crate denies `indexing_slicing`, so the bound is
    /// taken rather than asserted.
    fn overflow_failures(&mut self, user_id: &str, now: u64) -> u32 {
        let bucket = overflow_bucket(user_id);
        self.overflow.get_mut(bucket).map_or(0, |counter| {
            counter.expire(now);
            counter.failures
        })
    }

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
                    if counter.outstanding == 0 && counter.failures == 0 && counter.inherited == 0 {
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

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use super::{
        Counter, FailureLimiter, MAX_UNPROVEN_IN_FLIGHT, OVERFLOW_BUCKETS, Refusal, Verdict,
        overflow_bucket,
    };
    use crate::plugins::identity_basic::config::FailureLimitConfig;

    /// A verifier capacity whose recovery ceiling is the cap.
    ///
    /// The htpasswd default, so the ceiling tests measure the share an
    /// operator gets without tuning anything.
    const DEFAULT_VERIFICATIONS: usize = 32;

    fn limiter(capacity: usize, max_failures: u32) -> FailureLimiter {
        limiter_with_verifications(capacity, max_failures, DEFAULT_VERIFICATIONS)
    }

    fn limiter_with_verifications(
        capacity: usize,
        max_failures: u32,
        verifications: usize,
    ) -> FailureLimiter {
        FailureLimiter::new(
            FailureLimitConfig {
                capacity,
                max_failures,
                window_secs: 300,
            },
            verifications,
        )
    }

    /// Spend `n` failures for one user-id, ignoring refusals.
    fn fail(limiter: &FailureLimiter, user_id: &str, n: u32) {
        for _ in 0..n {
            if let Ok(admission) = limiter.admit(user_id) {
                admission.record_failure();
            }
        }
    }

    /// The baseline: a user-id blocked by name is refused before verification.
    #[test]
    fn a_named_counter_blocks_once_its_own_budget_is_spent() {
        let limiter = limiter(16, 3);
        fail(&limiter, "alice", 3);

        assert_eq!(
            limiter.admit("alice").err(),
            Some(Refusal::Blocked),
            "three failures against a budget of three must block the fourth attempt outright: \
             a named counter attributes its failures to one caller, so it needs no verification \
             to decide"
        );
    }

    /// Promotion out of overflow must not hand back a fresh budget.
    ///
    /// The defect: `admit`'s arms shared no failure state, so a user-id
    /// counted in overflow got a `Counter::default()` -- zero failures -- the
    /// moment a named slot freed. Any event freeing a slot reset the bound,
    /// including an unrelated caller's successful login, which an attacker
    /// needs neither to control nor to observe.
    #[test]
    fn failures_counted_in_overflow_follow_a_user_id_into_its_named_counter() {
        let limiter = limiter(1, 2);
        fail(&limiter, "squatter", 1);
        assert_eq!(limiter.tracked(), 1, "the squatter holds the only slot");

        fail(&limiter, "attacker", 2);
        assert!(
            limiter.saturations() > 0,
            "the attacker's attempts must have been counted in overflow, or this test is not \
             exercising the promotion path"
        );

        // The squatter's success frees the slot, so the next attempt for
        // `attacker` is tracked by name -- and must carry the overflow count.
        limiter
            .admit("squatter")
            .expect("the squatter is admitted")
            .record_success();

        let promoted = limiter
            .admit("attacker")
            .expect("a spent inherited count refuses recoverably, so the attempt is admitted");
        assert!(
            promoted.is_unproven(),
            "a freed slot must not reset a budget already spent in overflow: promoting onto a \
             zeroed counter made every freed slot a fresh set of guesses, and a trickle of \
             legitimate logins churns the map for an attacker. The inherited count must still \
             bound the attempt, which an unproven admission is: it costs a verification and \
             serves nothing without a correct password"
        );
    }

    /// A promoted user-id must not be blocked on a shared bucket's failures.
    ///
    /// The defect: promotion folded the overflow bucket's failures into
    /// `failures`, so a spent bucket became a spent *named* budget and `admit`
    /// returned `Blocked`. The resolver then denied a correct password without
    /// verifying it, on evidence belonging to whatever else hashed into that
    /// bucket -- the blanket outage the recoverable refusal exists to prevent,
    /// reintroduced by the one path that leaves the bucket behind.
    #[test]
    fn inherited_failures_refuse_recoverably_rather_than_blocking() {
        let limiter = limiter(1, 2);
        fail(&limiter, "squatter", 1);
        fail(&limiter, "sprayer", 2);
        assert!(
            limiter.saturations() > 0,
            "the spray must have been counted in overflow for this to exercise promotion"
        );

        limiter
            .admit("squatter")
            .expect("the squatter is admitted")
            .record_success();

        let victim = limiter
            .admit("sprayer")
            .expect("an inherited count must not refuse before the credential is verified");
        assert!(
            victim.is_unproven(),
            "a refusal resting on a shared bucket's failures must stay recoverable through \
             promotion: blocking here denied a correct password unverified on evidence that \
             could belong to any colliding user-id"
        );

        victim.record_success();
        assert_eq!(
            limiter.proven(),
            1,
            "a verified credential must clear the refusal and be counted, so an operator can \
             see legitimate callers paying for failures they do not own"
        );
    }

    /// Own failures must still block outright, inherited ones notwithstanding.
    ///
    /// The other side of the test above: making promotion recoverable must not
    /// make a user-id's *own* spent budget recoverable too, or the bound costs
    /// a verification per guess instead of refusing before one.
    #[test]
    fn a_counter_spent_by_its_own_failures_blocks_even_while_carrying_inherited_ones() {
        let mut counter = Counter {
            expires_at_ms: 1_000,
            failures: 2,
            inherited: 1,
            outstanding: 0,
        };

        assert_eq!(
            counter.verdict(2),
            Verdict::Blocked,
            "own failures reaching the budget must refuse before a verification, whatever else \
             the counter carries: they name one caller, so no credential is needed to decide"
        );

        counter.failures = 1;
        assert_eq!(
            counter.verdict(2),
            Verdict::Unproven,
            "and once the inherited count is what tips the same budget, the refusal must be \
             recoverable instead: that part of the evidence names no caller"
        );

        counter.inherited = 0;
        assert_eq!(
            counter.verdict(2),
            Verdict::Admit,
            "with the inherited count gone, one own failure against a budget of two still has \
             room, so neither refusal applies"
        );
    }

    /// Inherited failures must expire with the window, like recorded ones.
    ///
    /// Otherwise a single spray left every colliding user-id paying a
    /// verification per request forever, since nothing but a correct password
    /// clears them and `window_secs` is what bounds a failure's lifetime.
    #[test]
    fn inherited_failures_expire_on_the_window() {
        let mut counter = Counter {
            expires_at_ms: 1_000,
            failures: 0,
            inherited: 5,
            outstanding: 0,
        };

        counter.expire(1_001);

        assert_eq!(
            counter.verdict(2),
            Verdict::Admit,
            "a window that no longer bounds the bucket must not keep bounding the user-id its \
             count was copied to"
        );
    }

    /// A promoted counter with no inherited failures starts clean.
    ///
    /// The other side of the test above: inheriting must not block a caller
    /// whose bucket holds nothing.
    #[test]
    fn promotion_without_recorded_failures_admits_normally() {
        let limiter = limiter(1, 2);
        let squatter = limiter.admit("squatter").expect("takes the only slot");
        drop(squatter);

        limiter
            .admit("fresh")
            .expect("a user-id with no recorded failures must be admitted on promotion")
            .record_success();
    }

    /// An admitted attempt must not keep an earlier failure count alive.
    ///
    /// The defect: `reserve` pushed `expires_at_ms` to `now + window` on every
    /// admitted attempt, while `expire` clears failures only once the counter
    /// is not live. One in-budget attempt per window therefore held a partial
    /// count open for as long as the traffic lasted, so an attacker who drove
    /// a victim to `max_failures - 1` and then sent a trickle kept them
    /// permanently one attempt from a block -- and held a named slot against
    /// `capacity` at a fraction of the cost of re-blocking them.
    ///
    /// `window_secs` documents the window as surviving the last *failure*.
    ///
    /// Driven against `Counter` rather than the limiter: the defect is in the
    /// window arithmetic, and `FailureLimiter`'s clock is a real `Instant`
    /// with no injection seam, so a limiter-level test could only reach it by
    /// sleeping out a whole window.
    #[test]
    fn an_admitted_attempt_does_not_extend_the_failure_window() {
        const WINDOW: u64 = 300_000;

        let mut counter = Counter::default();

        // A failure at t=0 opens a window that closes at WINDOW.
        counter.reserve();
        counter.fail(0, WINDOW);
        assert_eq!(counter.failures, 1, "the failure is recorded");

        // An attempt admitted just before that window closes, settled without
        // a verdict. Under the defect its reservation pushed the expiry out to
        // `now + WINDOW`, so the failure below never expired.
        counter.reserve();
        counter.release(WINDOW - 1);

        counter.expire(WINDOW + 1);
        assert_eq!(
            counter.failures, 0,
            "a window must survive the last failure, not the last attempt: extending it on \
             every admitted attempt let a trickle of in-budget traffic hold a partial count \
             open indefinitely, pinning a victim one attempt from a block"
        );
    }

    /// A reservation must still pin its counter with no live window.
    ///
    /// The guard that makes the change above safe: `reserve` no longer opens a
    /// window, so `outstanding` is the only thing keeping an in-flight
    /// attempt's counter from being reclaimed. Dropping it would return that
    /// attempt's reservation to an empty budget and let a parallel guess past
    /// the budget it was already charged against.
    #[test]
    fn an_in_flight_attempt_pins_its_counter_without_a_live_window() {
        let mut counter = Counter::default();
        counter.reserve();

        assert!(
            !counter.idle(1_000_000),
            "an outstanding attempt must pin its counter however long the window has been \
             closed"
        );
        assert!(
            counter.spent(1),
            "and must still count against the budget, which is what bounds parallel guesses"
        );
    }

    /// Concurrent unproven verifications must be bounded.
    ///
    /// The defect: the recoverable path held no admission control at all, so
    /// repeated wrong-password attempts for one user-id reached the
    /// directory's verifier together. They occupied its verification permits
    /// and unrelated callers were denied `DIRECTORY_UNAVAILABLE` -- a refusal
    /// that costs an attacker nothing, converted into an outage for everyone
    /// else.
    ///
    /// The ceiling is on concurrency, not on how often a caller may prove
    /// itself: a per-attempt budget would have to live on the shared bucket,
    /// where a spray would spend it for every colliding caller.
    #[test]
    fn concurrent_unproven_verifications_are_bounded_by_the_ceiling() {
        let limiter = limiter(0, 1);
        fail(&limiter, "sprayer", 1);

        let held: Vec<_> = std::iter::repeat_with(|| {
            let attempt = limiter
                .admit("sprayer")
                .expect("the ceiling must admit this many unproven attempts at once");
            assert!(
                attempt.is_unproven(),
                "a spent shared bucket admits recoverably, which is what this bounds"
            );
            attempt
        })
        .take(usize::try_from(MAX_UNPROVEN_IN_FLIGHT).expect("the ceiling fits a usize"))
        .collect();

        assert_eq!(
            limiter.admit("sprayer").err(),
            Some(Refusal::Saturated),
            "one more concurrent unproven verification must be refused without running: \
             unbounded, they hold every verification permit the directory has and deny \
             unrelated callers as a directory failure"
        );

        drop(held);

        let recovered = limiter
            .admit("sprayer")
            .expect("settling the in-flight attempts must return their slots to the ceiling");
        assert!(
            recovered.is_unproven(),
            "and the recovered attempt is still judged on the bucket it shares"
        );
    }

    /// Proving a credential must stay possible however often it is asked.
    ///
    /// The ceiling bounds concurrency alone. A caller sharing a bucket with a
    /// spray re-proves itself on every request, so a budget that depleted
    /// across requests would cut it off -- the blanket lockout the recoverable
    /// refusal exists to prevent, one layer down.
    #[test]
    fn a_proven_credential_can_be_reproven_without_limit() {
        let limiter = limiter(0, 1);
        fail(&limiter, "sprayer", 1);

        let rounds = MAX_UNPROVEN_IN_FLIGHT.saturating_mul(4);
        for _ in 0..rounds {
            let attempt = limiter
                .admit("sprayer")
                .expect("a correct password must never be refused on a shared bucket's budget");
            assert!(
                attempt.is_unproven(),
                "the bucket is still spent, so each attempt is still unproven"
            );
            attempt.record_success();
        }

        assert_eq!(
            limiter.proven(),
            u64::from(rounds),
            "every cleared refusal must be counted, so an operator can see legitimate callers \
             paying for failures they do not own"
        );
    }

    /// An abandoned unproven attempt must return its ceiling slot.
    ///
    /// A leaked slot is permanent, so enough dropped attempts -- a client
    /// disconnect or an upstream timeout is all it takes -- would close the
    /// recovery path for the life of the process.
    #[test]
    fn a_dropped_unproven_attempt_returns_its_ceiling_slot() {
        let limiter = limiter(0, 1);
        fail(&limiter, "sprayer", 1);

        for _ in 0..MAX_UNPROVEN_IN_FLIGHT.saturating_mul(4) {
            drop(
                limiter
                    .admit("sprayer")
                    .expect("a dropped attempt must not retire a slot permanently"),
            );
        }
    }

    /// A failed recovery must count against a named counter.
    ///
    /// The defect: the recovery path charged nothing on failure, so a promoted
    /// counter sat at `Verdict::Unproven` with `failures` pinned at zero and
    /// every wrong guess took the early return. The ceiling bounds concurrency
    /// alone, so sequential guesses reached the verifier until the window
    /// expired -- `max_failures` bounded nothing at all for the one user-id an
    /// attacker had already spent a shared bucket on, which is the opposite of
    /// what promotion is for.
    ///
    /// The wrong password is this user-id's own, whatever the inherited count
    /// that admitted the attempt was, and a named counter can attribute it.
    #[test]
    fn a_failed_named_recovery_counts_against_the_promoted_counter() {
        let limiter = limiter(1, 2);
        fail(&limiter, "squatter", 1);
        fail(&limiter, "sprayer", 2);
        assert!(
            limiter.saturations() > 0,
            "the spray must have been counted in overflow for this to exercise promotion"
        );

        limiter
            .admit("squatter")
            .expect("the squatter is admitted")
            .record_success();

        // Promotes `sprayer` onto a named counter carrying `inherited == 2`.
        for guess in 0..2_u32 {
            let attempt = limiter
                .admit("sprayer")
                .expect("an inherited count refuses recoverably, so the attempt is admitted");
            assert!(
                attempt.is_unproven(),
                "guess {guess} rests on the inherited count, so it must be recoverable"
            );
            attempt.record_failure();
        }

        assert_eq!(
            limiter.admit("sprayer").err(),
            Some(Refusal::Blocked),
            "two failed recoveries against a budget of two must block outright: a counter \
             whose own failures have spent the budget names one caller, and leaving them \
             uncounted gave a promoted attacker unlimited sequential guesses -- bounded only \
             by the window, with the concurrency ceiling no obstacle to guessing one at a time"
        );
    }

    /// A successful recovery must stay free of the failure budget.
    ///
    /// The other side of the test above: counting failed recoveries must not
    /// start counting the proven ones, or a legitimate caller sharing a bucket
    /// with a spray is cut off after `max_failures` *correct* passwords -- the
    /// blanket lockout the recoverable refusal exists to prevent.
    #[test]
    fn a_proven_recovery_never_charges_the_failure_budget() {
        let limiter = limiter(1, 2);
        fail(&limiter, "squatter", 1);
        fail(&limiter, "sprayer", 2);

        limiter
            .admit("squatter")
            .expect("the squatter is admitted")
            .record_success();

        for round in 0..16_u32 {
            let attempt = limiter
                .admit("sprayer")
                .expect("a correct password must never be refused on a shared bucket's budget");
            assert!(
                attempt.is_unproven(),
                "round {round}: the inherited count still stands, so each attempt re-proves"
            );
            attempt.record_success();
        }
    }

    /// An interleaved wrong guess must not cut off a correct password early.
    ///
    /// The budget has to bound guessing without converting one wrong attempt
    /// into a lockout for the caller who knows the password: a success clears
    /// the recorded failures, so the two must not accumulate against each
    /// other across requests.
    #[test]
    fn a_proven_recovery_clears_an_earlier_failed_one() {
        let limiter = limiter(1, 2);
        fail(&limiter, "squatter", 1);
        fail(&limiter, "sprayer", 2);

        limiter
            .admit("squatter")
            .expect("the squatter is admitted")
            .record_success();

        for round in 0..8_u32 {
            limiter
                .admit("sprayer")
                .expect("one recorded failure leaves budget for another attempt")
                .record_failure();

            let proven = limiter.admit("sprayer").expect(
                "a single failed recovery must not block the caller who knows the password",
            );
            assert!(
                proven.is_unproven(),
                "round {round}: still judged on the bucket it shares"
            );
            proven.record_success();
        }
    }

    /// A failed recovery must not discharge a parallel attempt's reservation.
    ///
    /// An unproven attempt is admitted against the ceiling and reserves
    /// nothing on the counter, so settling one must leave `outstanding` alone.
    /// Decrementing it would return a *different* attempt's reservation and
    /// let a parallel guess past the budget it was already charged against.
    #[test]
    fn a_failed_recovery_leaves_a_parallel_reservation_outstanding() {
        let mut counter = Counter {
            expires_at_ms: 1_000,
            failures: 0,
            inherited: 2,
            outstanding: 1,
        };

        counter.fail_unreserved(500, 300_000);

        assert_eq!(
            counter.outstanding, 1,
            "the in-flight attempt still holds its reservation: an unproven settlement has \
             none of its own to return, so taking one discharges a guess running beside it"
        );
        assert_eq!(
            counter.failures, 1,
            "and the failed recovery is recorded, which is what bounds the next guess"
        );
    }

    /// A failed recovery must not remove the counter that bounds it.
    ///
    /// A counter carrying only inherited failures settles to `failures == 1`
    /// and `outstanding == 0`. Routing the settlement through `with_counter`
    /// would have removed it on the zero check, handing the next attempt a
    /// fresh budget via the promotion path -- the failure meant to bound the
    /// user-id erasing the counter that holds it.
    #[test]
    fn a_failed_recovery_keeps_its_counter_in_the_map() {
        let limiter = limiter(1, 2);
        fail(&limiter, "squatter", 1);
        fail(&limiter, "sprayer", 2);

        limiter
            .admit("squatter")
            .expect("the squatter is admitted")
            .record_success();

        limiter
            .admit("sprayer")
            .expect("the inherited count admits recoverably")
            .record_failure();

        assert_eq!(
            limiter.tracked(),
            1,
            "the counter must survive the failure it just recorded: removing it returns the \
             user-id to the promotion path, where a fresh counter is a fresh budget"
        );
    }

    /// The recovery ceiling must leave ordinary attempts room to verify.
    ///
    /// The defect: the ceiling was a fixed 8 while
    /// `max_concurrent_verifications` is valid from 1 upward. At a configured
    /// capacity of 8 or less, recovery could hold every permit the directory
    /// had, and a caller whose own budget was unspent was denied
    /// `auth.directory_unavailable` -- the outage the ceiling exists to
    /// prevent, caused by the ceiling below the backend's default.
    #[test]
    fn the_recovery_ceiling_is_sized_against_the_verifier_capacity() {
        for capacity in [1_usize, 2, 4, 8, 16, 32, 64, 4096] {
            let ceiling = FailureLimiter::recovery_ceiling(capacity);

            assert!(
                ceiling >= 1,
                "capacity {capacity} must leave a recovery path: zero slots closes it outright \
                 and restores the blanket lockout for a saturated map"
            );
            assert!(
                ceiling <= MAX_UNPROVEN_IN_FLIGHT,
                "capacity {capacity} must not exceed the absolute cap: a share of a large \
                 capacity is still more attacker-free verification than this path needs"
            );
            // A capacity of one cannot both serve an ordinary attempt and a
            // recovery at once; the floor serialises them rather than
            // forbidding recovery.
            if capacity > 1 {
                assert!(
                    usize::try_from(ceiling).expect("the ceiling fits a usize") < capacity,
                    "capacity {capacity} must keep a permit for an attempt whose own budget is \
                     unspent: recovery holding all of them is the directory outage this bounds"
                );
            }
        }
    }

    /// A small verifier capacity must still bound recovery below it.
    ///
    /// Driven through `admit` rather than the helper, so the derived ceiling is
    /// what actually gates admission.
    #[test]
    fn a_small_verifier_capacity_refuses_recovery_before_the_fixed_cap() {
        // A quarter of 8 is 2, well below the former fixed ceiling of 8.
        let limiter = limiter_with_verifications(0, 1, 8);
        fail(&limiter, "sprayer", 1);

        let held: Vec<_> = std::iter::repeat_with(|| {
            limiter
                .admit("sprayer")
                .expect("the derived ceiling must admit its share")
        })
        .take(2)
        .collect();

        assert_eq!(
            limiter.admit("sprayer").err(),
            Some(Refusal::Saturated),
            "a capacity of 8 permits 2 concurrent recoveries, not the 8 a fixed ceiling \
             allowed: the other 6 permits belong to callers whose own budget is unspent"
        );

        drop(held);
        limiter
            .admit("sprayer")
            .expect("settling the in-flight attempts returns their slots");
    }

    /// The bucket index must stay inside the table for any input.
    #[test]
    fn every_user_id_hashes_into_the_table() {
        for user_id in ["", "a", "alice", &"x".repeat(4096), "ünïcödé", "a:b"] {
            assert!(
                overflow_bucket(user_id) < OVERFLOW_BUCKETS,
                "{user_id:?} must index inside the overflow table"
            );
        }
    }
}
