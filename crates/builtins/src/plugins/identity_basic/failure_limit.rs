// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A bound on repeated failures for one user-id.
//
// The resolver keys it on the user-id scoped to the client source when the
// host supplies one, so a guesser spends its own budget rather than the user's.
// This module sees only the key, and calls it a user-id throughout.
//
// Basic replays a reusable password on every request, so an attacker who can
// reach the route can test guesses as fast as the verifier runs. Hash cost
// alone is not that bound: it sets the price per guess, and an operator who
// lowers the cost to meet a latency budget lowers the price with it.
//
// The bound covers three ways a naive per-user counter fails:
//
// - *Concurrency.* A budget read before verification and written after it is
//   no budget at all under load: every parallel guess for one user-id passes
//   the same check before any of them records a failure. An attempt therefore
//   reserves against the budget at admission and releases on its way out, so
//   `max_failures` bounds completed failures *and* attempts in flight.
// - *Saturation.* A full name-keyed map that stops counting new user-ids lets
//   an attacker fill it with junk and then guess a fresh target unbounded.
//   Counting continues in a fixed overflow table that never displaces a named
//   counter, and a user-id promoted out of that table
//   carries its recorded failures with it, so a freed slot is not a fresh
//   budget.
// - *Shared-bucket lockout.* An overflow bucket is shared, so refusing
//   outright on a spent one denies callers for failures that are not theirs.
//   Since a successful login removes its named counter, the callers routed
//   through overflow are exactly the well-behaved ones, so a junk-user-id
//   spray would be a blanket authentication outage. A spent bucket still
//   refuses, but recoverably rather than outright: the refusal rests on
//   evidence that is not this caller's, so the attempt is admitted for
//   verification and only a caller who knows the password clears it. Those
//   recoveries are budgeted per bucket in turn: a failed one is charged, a
//   proven one is not, so `max_failures` wrong recoveries close the bucket's
//   recovery path for a window. Uncharged, a guesser who spent a target's
//   bucket had unlimited sequential guesses against it.
//
// Where a refusal is decided follows from what it is keyed on, and a counter
// keeps the two kinds of failure apart for as long as it lives. Its own
// failures were recorded against its key, so they refuse outright and cost an
// attacker nothing. Failures inherited from a shared bucket on promotion cannot be
// attributed, so a counter spent only by those refuses recoverably -- the
// unattributable evidence does not stop carrying over just because a named
// slot opened, and refusing outright on them would make promotion a lockout: a
// user-id that reached a counter of its own would be judged on a spray's
// failures and denied without the verification that would clear it.
//
// A recoverable refusal is still admission-controlled. It carries a
// reservation against a ceiling on concurrent unproven attempts -- sized
// against the backend's verification capacity, so recovery never holds every
// permit an ordinary attempt needs -- because
// the verification it asks for is CPU-bound work an attacker repeats for free:
// without that ceiling a wrong-password spray on one user-id would occupy the
// backend's verification permits and turn a bounded refusal into a directory
// outage for every other caller. The slot on that ceiling travels with the
// verification as a `RecoveryLease`, so a cancelled request does not return it
// while the hash it admitted is still running. A recovery on a named counter
// also reserves on that counter, so recoveries in flight for one user-id are
// bounded by its own budget, not only by the global ceiling.
//
// What this is still not: it is per process, so replicas do not share it; a
// source-scoped key does not bound one user-id guessed from many sources; and
// a spray across many user-ids never fills one counter. Each gap needs an edge
// or shared counter, and the operator documentation states them.

use std::collections::HashMap;
use std::hash::BuildHasher as _;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, RwLock};
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
/// This bounds the concurrent CPU the path can hold across all user-ids. How
/// many wrong guesses one bucket may take is bounded separately, by its
/// recovery budget in [`Counters::recoveries`], which charges failed
/// recoveries only, so a proven caller is never what spends it.
///
/// [`Counters::recoveries`]: Counters::recoveries
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

/// How long a reclaim scan of the full name-keyed map holds before another
/// may run, in milliseconds.
///
/// A scan visits every counter under the write lock that every admission and
/// settlement waits on. An attacker who keeps the map full of live counters
/// frees nothing by it, so scanning on every unnamed attempt made each one cost
/// `capacity` probes for every caller -- and `capacity` is the setting
/// operators are told to raise. Between scans an unnamed attempt goes straight
/// to the overflow table, which still bounds it; the delay costs at most this
/// long in per-name precision for a counter that has just gone idle.
const RECLAIM_INTERVAL_MS: u64 = 1_000;

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
    /// Set on the recoverable path, where the attempt also holds a slot on
    /// the ceiling of concurrent unproven verifications.
    unproven: bool,
    /// The unproven attempt's ceiling slot, until [`take_lease`] moves it to
    /// the verification.
    ///
    /// [`take_lease`]: Admission::take_lease
    lease: Option<RecoveryLease>,
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

    /// Take the unproven attempt's ceiling slot, to hand to the verification.
    ///
    /// `None` for an ordinary attempt, or once taken. The settlement stays on
    /// the admission, so a cancelled request still records no failure; only
    /// the concurrency slot moves, and it is released when the lease drops.
    pub fn take_lease(&mut self) -> Option<RecoveryLease> {
        self.lease.take()
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
    /// A shared bucket's failure count is left alone: it already counts
    /// whatever spent the bucket, and a second charge there is a budget the
    /// colliding caller cannot clear. The failure is charged to the bucket's
    /// recovery budget instead, which only failed recoveries spend, so
    /// `max_failures` wrong guesses close recovery on that bucket for a window.
    /// While recovery is closed, [`admit`] refuses with [`Refusal::Saturated`]
    /// before the credential is verified, so a colliding caller with a correct
    /// password is refused too.
    ///
    /// A *successful* recovery still costs nothing, so a legitimate caller
    /// sharing a bucket re-proves itself without limit while recovery is open.
    ///
    /// [`admit`]: FailureLimiter::admit
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
        if self.settled {
            return;
        }
        // Neither a failure nor a success: the attempt never produced a
        // verdict on the credential, so it releases its reservation without
        // touching the failure count. A directory that cannot answer must not
        // spend a named victim's budget. A ceiling slot still held here drops
        // with `lease`.
        if self.unproven
            && let Slot::Overflow(_) = self.slot
        {
            self.limiter
                .settle_recovery(self.slot, |recovery, now, _| recovery.release(now));
            return;
        }
        self.limiter.release(&self.user_id, self.slot);
    }
}

/// A slot on the ceiling of concurrent unproven verifications.
///
/// Taken from an unproven [`Admission`] with [`Admission::take_lease`] and
/// moved into whatever runs the verification, so the slot is held for as long
/// as the CPU work it bounds rather than for as long as the request's future.
/// Dropping a `JoinHandle` does not cancel a blocking task: a slot released
/// with the request let a client that disconnected mid-verification start a
/// replacement recovery beside the hash still running, so the recovery path
/// held more verification permits than its ceiling allows.
///
/// [`Admission`]: Admission
/// [`Admission::take_lease`]: Admission::take_lease
#[derive(Debug)]
pub struct RecoveryLease {
    in_flight: Arc<AtomicU32>,
}

impl Drop for RecoveryLease {
    fn drop(&mut self) {
        // Saturating, not wrapping: a count that reached zero and underflowed
        // would read as full and refuse every recovery for the life of the
        // process, which is the outage this path exists to avoid.
        let _ = self.in_flight.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |held| Some(held.saturating_sub(1)),
        );
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
    /// free. Also returned once `max_failures` failed recoveries on one
    /// overflow bucket have spent its recovery budget, until that window
    /// passes.
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
    /// spend: see [`MAX_UNPROVEN_IN_FLIGHT`]. The per-bucket spend is
    /// `Counters::recoveries`. Shared so each [`RecoveryLease`] can return its
    /// slot from the task running the verification.
    ///
    /// [`MAX_UNPROVEN_IN_FLIGHT`]: MAX_UNPROVEN_IN_FLIGHT
    unproven_in_flight: Arc<AtomicU32>,
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
            counters: RwLock::new(Counters::new()),
            saturations: std::sync::atomic::AtomicU64::new(0),
            proven: std::sync::atomic::AtomicU64::new(0),
            unproven_in_flight: Arc::new(AtomicU32::new(0)),
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
    /// recoverable but the bounded recovery path is already full, or the
    /// overflow bucket's failed recoveries have spent its recovery budget.
    ///
    /// [`is_unproven`]: Admission::is_unproven
    /// [`saturations`]: FailureLimiter::saturations
    pub fn admit(&self, user_id: impl Into<String>) -> Result<Admission<'_>, Refusal> {
        let user_id: String = user_id.into();
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
        let now = self.now_ms();

        if let Some(counter) = guard.named.get_mut(user_id.as_str()) {
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
                // slot opened.
                Verdict::Unproven => self
                    .admit_named_recovery(counter, user_id)
                    .ok_or(Refusal::Saturated),
            };
        }

        // Room for a counter of its own, so the attempt is tracked by name and
        // pays no collision cost -- unless the bucket still has attempts in
        // flight, which may be this user-id's. Those settle on the bucket, so
        // promoting past them started the named budget without them and let
        // the user-id run `max_failures` more attempts beside them. The bucket
        // cannot say whose they are, so carrying them over would charge this
        // user-id for a colliding caller's reservations; the user-id stays in
        // overflow, which still bounds it, until they settle.
        if !guard.overflow_busy(&user_id)
            && (guard.named.len() < self.config.capacity || guard.reclaim(now))
        {
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
            //
            // They keep the bucket's expiry, not a window opened here. A fresh
            // window gave a failure about to expire a full new one, and
            // sharing the own-failure window let an ordinary success close it
            // and drop the inherited count early.
            let (inherited, inherited_expires_at_ms) = guard.overflow_failures(&user_id, now);
            let mut counter = Counter {
                // A fresh counter takes its first window from `fail`, as
                // `reserve` opens none.
                expires_at_ms: 0,
                failures: 0,
                inherited,
                inherited_expires_at_ms,
                outstanding: 0,
            };
            return match counter.verdict(self.config.max_failures) {
                Verdict::Admit => {
                    counter.reserve();
                    guard.named.insert(user_id.clone(), counter);
                    Ok(self.admitted(user_id, Slot::Named))
                },
                // A counter built here records no failures of its own, so its
                // own budget cannot be the thing that is spent.
                Verdict::Blocked => Err(Refusal::Blocked),
                Verdict::Unproven => {
                    // Inserted so the inherited count lives in the named
                    // counter and expires with the bucket's window, rather
                    // than being re-read from a shared bucket a colliding
                    // attacker keeps refreshing.
                    let counter = guard.named.entry(user_id.clone()).or_insert(counter);
                    self.admit_named_recovery(counter, user_id)
                        .ok_or(Refusal::Saturated)
                },
            };
        }

        self.saturations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let bucket = overflow_bucket(&user_id);
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
            //
            // The attempt is reserved on the bucket's recovery budget instead,
            // which a proven recovery refunds and a failed one keeps. Without
            // it a guesser who spent a target's bucket had unlimited
            // sequential guesses against it, bounded only by the ceiling on
            // how many ran at once.
            let Some(lease) = self.claim_unproven() else {
                return Err(Refusal::Saturated);
            };
            if !guard.reserve_recovery(bucket, now, self.config.max_failures) {
                return Err(Refusal::Saturated);
            }
            return Ok(self.admitted_unproven(user_id, Slot::Overflow(bucket), lease));
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

    fn admitted(&self, user_id: String, slot: Slot) -> Admission<'_> {
        Admission {
            limiter: self,
            settled: false,
            slot,
            unproven: false,
            lease: None,
            user_id,
        }
    }

    /// An admission for an attempt unattributable failures already refused.
    fn admitted_unproven(
        &self,
        user_id: String,
        slot: Slot,
        lease: RecoveryLease,
    ) -> Admission<'_> {
        Admission {
            limiter: self,
            settled: false,
            slot,
            unproven: true,
            lease: Some(lease),
            user_id,
        }
    }

    /// Admit a recovery on a named counter that inherited failures spent.
    ///
    /// Reserves on the counter as well as on the ceiling. The ceiling bounds
    /// recoveries across all user-ids; the reservation bounds this one's by
    /// its own budget, which a failed recovery spends. Without it every
    /// recovery admitted together passed the same check before any failure
    /// settled, so a budget of two let the whole ceiling's worth of guesses
    /// reach the verifier. The reservation also pins the counter, so expiry
    /// and reclaim cannot replace it before this attempt settles on it.
    ///
    /// `Verdict::Unproven` means own failures and attempts in flight leave
    /// room, so a single recovery can always prove a correct credential.
    fn admit_named_recovery(
        &self,
        counter: &mut Counter,
        user_id: String,
    ) -> Option<Admission<'_>> {
        let lease = self.claim_unproven()?;
        counter.reserve();
        Some(self.admitted_unproven(user_id, Slot::Named, lease))
    }

    /// Take a slot on the unproven-verification ceiling, if one is free.
    ///
    /// A compare-exchange loop rather than a fetch-add and a rollback: an add
    /// that overshoots is briefly visible to every other attempt, so a burst
    /// arriving together would refuse each other on slots all about to be
    /// returned.
    fn claim_unproven(&self) -> Option<RecoveryLease> {
        let mut held = self
            .unproven_in_flight
            .load(std::sync::atomic::Ordering::Acquire);
        loop {
            if held >= self.unproven_ceiling {
                return None;
            }
            match self.unproven_in_flight.compare_exchange_weak(
                held,
                held.saturating_add(1),
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(RecoveryLease {
                        in_flight: Arc::clone(&self.unproven_in_flight),
                    });
                },
                Err(current) => held = current,
            }
        }
    }

    /// Count a verified credential that cleared an unproven refusal.
    fn count_proven(&self) {
        self.proven
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Milliseconds since the limiter started.
    ///
    /// Read with the write lock held. A reading taken before the lock can lose
    /// the race for it, and `fail` would then store its older window end over
    /// a later settlement's, expiring the counter early.
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
        let mut guard = self.write();
        let now = self.now_ms();
        guard.with_counter(user_id, slot, |counter| counter.release(now));
    }

    /// Convert an attempt's reservation into a recorded failure.
    fn settle_failure(&self, user_id: &str, slot: Slot) {
        let window = self.window_ms();
        let mut guard = self.write();
        let now = self.now_ms();
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
        let mut guard = self.write();
        let now = self.now_ms();
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
    /// Charges the failure where it can be attributed. A named counter can:
    /// the wrong password is this user-id's, whatever the inherited count that
    /// refused the attempt was, so the reservation settles as a failure on the
    /// counter that admitted it and `max_failures` wrong recoveries turn
    /// `Verdict::Unproven` into `Verdict::Blocked`. A shared bucket's failure
    /// count cannot, since charging it would spend a budget for every
    /// colliding user-id, so the failure is kept on the bucket's recovery
    /// budget instead, which closes only the recovery path.
    fn settle_unproven_failure(&self, user_id: &str, slot: Slot) {
        if slot == Slot::Named {
            self.settle_failure(user_id, slot);
        }
        self.settle_recovery(slot, Counter::fail);
    }

    /// Settle an unproven attempt's reservation on its overflow bucket's
    /// recovery budget.
    ///
    /// Only an attempt admitted over a shared bucket holds one, so any other
    /// slot is left alone.
    fn settle_recovery(&self, slot: Slot, settle: impl FnOnce(&mut Counter, u64, u64)) {
        let Slot::Overflow(bucket) = slot else {
            return;
        };
        let window = self.window_ms();
        let mut guard = self.write();
        let now = self.now_ms();
        if let Some(recovery) = guard.recoveries.get_mut(bucket) {
            settle(recovery, now, window);
        }
    }

    /// Settle an unproven attempt whose credential verified.
    ///
    /// Counts the proof and settles a named reservation as a success, which
    /// clears the failures this caller recorded on its own failed recoveries.
    /// The *inherited* count is left standing: it may be a colliding
    /// attacker's, so clearing it would hand that attacker a fresh budget, and
    /// this caller re-proves itself on its next request for as long as it
    /// lives.
    ///
    /// A shared bucket's failures are left alone for the same reason they are
    /// never charged: nothing on it is this caller's to clear. Its recovery
    /// budget gets this attempt's reservation back without a failure, so a
    /// caller who proves itself never spends that budget.
    fn settle_proven(&self, user_id: &str, slot: Slot) {
        self.count_proven();
        if slot == Slot::Named {
            self.settle_success(user_id, slot);
        }
        self.settle_recovery(slot, |recovery, now, _| recovery.release(now));
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
    /// When `inherited` stops counting: the bucket's expiry, copied with it.
    ///
    /// Separate from `expires_at_ms`, which is the window of this counter's
    /// own failures. Sharing one let promotion hand an expiring bucket failure
    /// a fresh full window, and let an ordinary success close the window and
    /// drop the inherited count before the bucket's had passed.
    inherited_expires_at_ms: u64,
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
        self.outstanding == 0 && !self.live(now) && self.inherited_expires_at_ms <= now
    }

    /// Drop stale failures, keeping any live reservation.
    ///
    /// Inherited failures expire with the bucket window they were copied
    /// from. They are a shared bucket's evidence against this user-id, and
    /// evidence that no longer bounds the bucket must not keep bounding the
    /// caller it was copied to.
    fn expire(&mut self, now: u64) {
        if !self.live(now) {
            self.failures = 0;
        }
        if self.inherited_expires_at_ms <= now {
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

    /// Whether this counter's own failures still bound attempts.
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

    /// Settle a reservation as a success, clearing the recorded failures.
    ///
    /// Closes only the own-failure window. An inherited count keeps the
    /// bucket's expiry, and is what the caller re-proves itself against on its
    /// next request.
    fn succeed(&mut self, now: u64) {
        self.outstanding = self.outstanding.saturating_sub(1);
        self.failures = 0;
        if self.outstanding == 0 {
            self.expires_at_ms = now;
        }
        self.expire(now);
    }
}

/// The name-keyed counters and the overflow table behind them.
#[derive(Debug)]
struct Counters {
    named: HashMap<String, Counter>,
    /// Fixed-size buckets counting attempts for user-ids the map has no room
    /// to name.
    overflow: Vec<Counter>,
    /// Each overflow bucket's recovery budget, indexed like `overflow`.
    ///
    /// Counts unproven attempts admitted over a spent bucket. A failed
    /// recovery keeps its charge and a proven one is refunded, so a guesser
    /// who has spent a target's bucket gets `max_failures` more guesses per
    /// window rather than unlimited ones. A colliding caller who knows its
    /// password spends none of it, and gets recovery back once a closing
    /// window passes.
    recoveries: Vec<Counter>,
    /// The earliest time another reclaim scan may run. See
    /// [`RECLAIM_INTERVAL_MS`].
    ///
    /// [`RECLAIM_INTERVAL_MS`]: RECLAIM_INTERVAL_MS
    next_reclaim_ms: u64,
}

impl Counters {
    fn new() -> Self {
        Self {
            named: HashMap::new(),
            overflow: std::iter::repeat_with(Counter::default)
                .take(OVERFLOW_BUCKETS)
                .collect(),
            recoveries: std::iter::repeat_with(Counter::default)
                .take(OVERFLOW_BUCKETS)
                .collect(),
            next_reclaim_ms: 0,
        }
    }

    /// Reserve an unproven attempt on a bucket's recovery budget.
    ///
    /// Returns whether there was budget to spare. Refuses when the index
    /// cannot be taken, which `overflow_bucket`'s mask makes unreachable:
    /// unlike the missing-bucket arm in `admit`, this reservation is what
    /// bounds the attempt, so admitting without it would be the open side.
    fn reserve_recovery(&mut self, bucket: usize, now: u64, budget: u32) -> bool {
        let Some(recovery) = self.recoveries.get_mut(bucket) else {
            return false;
        };
        recovery.expire(now);
        if recovery.spent(budget) {
            return false;
        }
        recovery.reserve();
        true
    }

    /// The live failures recorded for a user-id in the overflow table, and
    /// when they expire.
    ///
    /// Expires the bucket first, so a stale window contributes nothing. Reads
    /// zero when the index cannot be taken, which `overflow_bucket`'s mask
    /// makes unreachable; the crate denies `indexing_slicing`, so the bound is
    /// taken rather than asserted.
    fn overflow_failures(&mut self, user_id: &str, now: u64) -> (u32, u64) {
        let bucket = overflow_bucket(user_id);
        self.overflow.get_mut(bucket).map_or((0, 0), |counter| {
            counter.expire(now);
            (counter.failures, counter.expires_at_ms)
        })
    }

    /// Whether a user-id's overflow bucket has attempts still in flight,
    /// ordinary or recovering.
    ///
    /// Reads idle when the index cannot be taken, which `overflow_bucket`'s
    /// mask makes unreachable: promotion then counts the user-id by name,
    /// where the overflow arm would count it nowhere.
    fn overflow_busy(&self, user_id: &str) -> bool {
        let bucket = overflow_bucket(user_id);
        let in_flight =
            |table: &[Counter]| table.get(bucket).is_some_and(|held| held.outstanding > 0);
        in_flight(&self.overflow) || in_flight(&self.recoveries)
    }

    /// Drop idle named counters, at most once per [`RECLAIM_INTERVAL_MS`].
    ///
    /// Returns whether a slot was freed; a scan that is not yet due frees
    /// nothing.
    ///
    /// [`RECLAIM_INTERVAL_MS`]: RECLAIM_INTERVAL_MS
    fn reclaim(&mut self, now: u64) -> bool {
        if now < self.next_reclaim_ms {
            return false;
        }
        self.next_reclaim_ms = now.saturating_add(RECLAIM_INTERVAL_MS);
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
        Admission, Counter, Counters, FailureLimiter, MAX_UNPROVEN_IN_FLIGHT, OVERFLOW_BUCKETS,
        RECLAIM_INTERVAL_MS, Refusal, Verdict, overflow_bucket,
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
            inherited_expires_at_ms: 1_000,
            outstanding: 0,
        };

        assert_eq!(
            counter.verdict(2),
            Verdict::Blocked,
            "own failures reaching the budget must refuse before a verification, whatever else \
             the counter carries: they were recorded against this key, so no credential is \
             needed to decide"
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
            expires_at_ms: 0,
            failures: 0,
            inherited: 5,
            inherited_expires_at_ms: 1_000,
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

    /// Parallel attempts must be bounded at admission, not after verification.
    ///
    /// Every attempt holds its admission across a barrier, standing in for a
    /// verification still running, so none settles before all eight have been
    /// decided. A budget read before verification and written after it would
    /// admit all of them here; reserving at admission admits one.
    #[test]
    fn attempts_admitted_together_cannot_outrun_the_budget() {
        const ATTEMPTS: usize = 8;

        let limiter = limiter(16, 1);
        let barrier = std::sync::Barrier::new(ATTEMPTS);

        let admitted = std::thread::scope(|scope| {
            let running: Vec<_> = std::iter::repeat_with(|| {
                scope.spawn(|| {
                    let attempt = limiter.admit("alice");
                    barrier.wait();
                    attempt.map(Admission::record_failure).is_ok()
                })
            })
            .take(ATTEMPTS)
            .collect();
            running
                .into_iter()
                .map(|handle| handle.join().expect("no attempt thread panics"))
                .filter(|was_admitted| *was_admitted)
                .count()
        });

        assert_eq!(
            admitted, 1,
            "a budget of one must admit one of eight overlapping attempts: the other seven are \
             decided while the first is still in flight, so only a reservation taken at \
             admission can refuse them"
        );
        assert_eq!(
            limiter.admit("alice").err(),
            Some(Refusal::Blocked),
            "and the one admitted failure spends the budget once it settles"
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
        let budget = MAX_UNPROVEN_IN_FLIGHT.saturating_mul(2);
        let limiter = limiter(0, budget);
        fail(&limiter, "sprayer", budget);

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

    #[test]
    fn a_colliding_caller_proves_itself_over_a_bucket_another_key_spent() {
        let limiter = limiter(0, 2);
        let bucket = overflow_bucket("attacker");
        let victim = (0..1_000_000_u32)
            .map(|n| format!("victim{n}"))
            .find(|candidate| overflow_bucket(candidate) == bucket)
            .expect("a million candidates cover a 1024-bucket table");
        fail(&limiter, "attacker", 2);

        let attempt = limiter
            .admit(victim.as_str())
            .expect("a bucket another key spent must refuse recoverably, not block the attempt");
        assert!(
            attempt.is_unproven(),
            "the spent bucket's failures belong to the attacker, so the colliding caller is \
             admitted for a verification rather than served unconditionally"
        );
        attempt.record_success();

        assert_eq!(
            limiter.proven(),
            1,
            "a cleared shared-bucket refusal must be observable, so an operator can see \
             legitimate callers paying for buckets they do not own"
        );

        let again = limiter
            .admit(victim.as_str())
            .expect("the recovery budget still has room, so the caller can prove itself again");
        assert!(
            again.is_unproven(),
            "the bucket is still spent, so the next attempt is a recovery too"
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

    #[test]
    fn failed_recoveries_close_a_spent_buckets_recovery_path() {
        let limiter = limiter(0, 2);
        fail(&limiter, "target", 2);

        let mut recoveries = 0_u32;
        let refusal = loop {
            match limiter.admit("target") {
                Ok(attempt) => {
                    assert!(
                        attempt.is_unproven(),
                        "the bucket is spent, so every attempt past it is a recovery"
                    );
                    recoveries = recoveries.saturating_add(1);
                    attempt.record_failure();
                },
                Err(refusal) => break refusal,
            }
            assert!(
                recoveries <= 2,
                "a budget of two must bound failed recoveries too: when they recorded nothing, a \
                 guesser who spent a target's bucket had unlimited sequential guesses against \
                 it, bounded only by how many ran at once"
            );
        };

        assert_eq!(
            (recoveries, refusal),
            (2, Refusal::Saturated),
            "two failed recoveries against a budget of two must close the bucket's recovery \
             path, refused as `Saturated` since the failures may not be the next caller's own"
        );
    }

    #[test]
    fn recoveries_in_flight_are_charged_to_the_buckets_budget() {
        let limiter = limiter(0, 2);
        fail(&limiter, "target", 2);

        let held: Vec<_> = std::iter::repeat_with(|| {
            limiter
                .admit("target")
                .expect("the bucket's recovery budget admits two at once")
        })
        .take(2)
        .collect();

        assert_eq!(
            limiter.admit("target").err(),
            Some(Refusal::Saturated),
            "two recoveries in flight spend a budget of two, so a third waits for one to settle: \
             charged only at settlement, a burst admitted together would all pass one check"
        );

        drop(held);
        limiter
            .admit("target")
            .expect("abandoned recoveries return their reservation without charging a failure");
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

    /// Promote `sprayer` onto a named counter carrying `inherited == 2`.
    ///
    /// A budget of two, one named slot, and the global recovery ceiling well
    /// above the named budget, so only the named reservation can bound what
    /// the tests below measure.
    fn promoted_sprayer() -> FailureLimiter {
        let limiter = limiter(1, 2);
        fail(&limiter, "squatter", 1);
        fail(&limiter, "sprayer", 2);
        limiter
            .admit("squatter")
            .expect("the squatter is admitted")
            .record_success();
        limiter
    }

    /// Named recoveries in flight must spend the named budget.
    ///
    /// The defect: a named recovery took a slot on the global ceiling but
    /// reserved nothing on its counter, so with `max_failures = 2` and a
    /// ceiling of eight, every recovery admitted together passed the same
    /// check before any failure settled.
    #[test]
    fn named_recoveries_in_flight_are_bounded_by_the_named_budget() {
        let limiter = promoted_sprayer();

        let held: Vec<_> = std::iter::repeat_with(|| {
            let attempt = limiter
                .admit("sprayer")
                .expect("the named budget admits two recoveries at once");
            assert!(attempt.is_unproven(), "each rests on the inherited count");
            attempt
        })
        .take(2)
        .collect();

        assert_eq!(
            limiter.admit("sprayer").err(),
            Some(Refusal::Blocked),
            "two recoveries in flight spend a named budget of two, so a third must be refused \
             before verification even though the global ceiling has room"
        );

        for attempt in held {
            attempt.record_failure();
        }
        assert_eq!(
            limiter.admit("sprayer").err(),
            Some(Refusal::Blocked),
            "and both failures settle on the counter, which then blocks by its own failures"
        );
    }

    /// A single recovery must still be able to prove a correct credential.
    #[test]
    fn one_recovery_proves_a_credential_when_only_inherited_failures_spent_the_budget() {
        let limiter = promoted_sprayer();

        let attempt = limiter
            .admit("sprayer")
            .expect("own failures and attempts in flight leave room, so one recovery is admitted");
        assert!(attempt.is_unproven(), "the inherited count still refuses");
        attempt.record_success();

        assert_eq!(limiter.proven(), 1, "and its proof is counted");
        assert_eq!(
            limiter.tracked(),
            1,
            "the success clears the reservation but leaves the inherited count bounding the key"
        );
    }

    /// A named recovery must settle on the counter that admitted it.
    ///
    /// The reservation pins the counter: an outstanding attempt keeps it out
    /// of reclaim however long its windows have been closed, so it cannot be
    /// removed and recreated under the attempt. Settling after expiry records
    /// the failure on that same counter instead of losing it.
    #[test]
    fn a_named_recovery_pins_its_counter_through_expiry() {
        let mut counters = Counters::new();
        let mut admitted = Counter {
            expires_at_ms: 0,
            failures: 0,
            inherited: 2,
            inherited_expires_at_ms: 1_000,
            outstanding: 0,
        };
        admitted.reserve();
        counters.named.insert("sprayer".to_owned(), admitted);

        let after_expiry = 1_000_u64.saturating_add(RECLAIM_INTERVAL_MS);
        assert!(
            !counters.reclaim(after_expiry),
            "a counter with a recovery in flight must not be reclaimed once its windows close"
        );

        counters.with_counter("sprayer", super::Slot::Named, |counter| {
            counter.fail(after_expiry, 300_000);
        });
        let settled = counters
            .named
            .get("sprayer")
            .expect("the same counter is still held");
        assert_eq!(
            (settled.failures, settled.outstanding, settled.inherited),
            (1, 0, 0),
            "the failed recovery settles on the counter that admitted it, after its inherited \
             count expired"
        );
    }

    /// Promotion must wait for the bucket's attempts in flight to settle.
    ///
    /// The defect: promotion started the named counter with nothing
    /// outstanding while the key's ordinary attempts were still running on its
    /// bucket. Those settled in overflow, so the key ran a fresh named budget
    /// beside them.
    #[test]
    fn promotion_waits_for_the_buckets_attempts_in_flight() {
        let limiter = limiter(1, 2);
        let squatter = limiter.admit("squatter").expect("takes the only slot");

        let in_flight = limiter
            .admit("attacker")
            .expect("the attacker is counted in overflow");
        squatter.record_success();
        assert_eq!(
            limiter.tracked(),
            0,
            "the squatter's success frees the slot"
        );

        let saturations = limiter.saturations();
        let beside = limiter
            .admit("attacker")
            .expect("the bucket has room for a second attempt");
        assert_eq!(
            (limiter.tracked(), limiter.saturations()),
            (0, saturations.saturating_add(1)),
            "with an attempt still in flight on the bucket, the key must stay in overflow \
             rather than take the free slot with a fresh budget"
        );
        let third = limiter
            .admit("attacker")
            .expect("a bucket spent by attempts in flight refuses recoverably");
        assert!(
            third.is_unproven() && limiter.tracked() == 0,
            "two attempts in flight spend the bucket's budget of two, so a third is only a \
             recovery on the bucket, not an ordinary attempt on a fresh named budget"
        );

        drop((in_flight, beside, third));
        limiter
            .admit("attacker")
            .expect("with nothing in flight the key is promoted")
            .record_success();
        assert_eq!(
            limiter.saturations(),
            saturations.saturating_add(2),
            "the promoted attempt is counted by name, not in overflow"
        );
    }

    /// Inherited failures must keep the bucket's expiry.
    ///
    /// The defects: promotion gave an expiring bucket failure a fresh full
    /// window, and an ordinary success closed the shared window and dropped
    /// the inherited count early.
    #[test]
    fn inherited_failures_keep_the_buckets_expiry() {
        let mut counter = Counter {
            expires_at_ms: 0,
            failures: 0,
            inherited: 1,
            inherited_expires_at_ms: 1_000,
            outstanding: 0,
        };

        counter.reserve();
        counter.succeed(500);
        assert_eq!(
            counter.inherited, 1,
            "an ordinary success clears own failures only, not a live inherited count"
        );

        counter.reserve();
        counter.fail(900, 300_000);
        counter.expire(1_000);
        assert_eq!(
            (counter.failures, counter.inherited),
            (1, 0),
            "a later failure extends only the own-failure window; the inherited count still \
             expires with the bucket's"
        );
    }

    /// A recovery's ceiling slot must outlive a cancelled request.
    ///
    /// The defect: dropping the admission released the slot while the blocking
    /// verification it bounded kept running, so a replacement recovery could
    /// take another verification permit beside it.
    #[test]
    fn a_taken_lease_holds_the_ceiling_after_its_admission_drops() {
        let limiter = limiter_with_verifications(0, 1, 4);
        fail(&limiter, "sprayer", 1);

        let mut attempt = limiter
            .admit("sprayer")
            .expect("a capacity of four leaves one recovery slot");
        let lease = attempt
            .take_lease()
            .expect("an unproven attempt holds a lease");
        drop(attempt);

        assert_eq!(
            limiter.admit("sprayer").err(),
            Some(Refusal::Saturated),
            "the lease is still with the verification, so the ceiling of one is still full"
        );

        drop(lease);
        limiter
            .admit("sprayer")
            .expect("the slot returns once the verification's lease drops");
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
        let limiter = limiter_with_verifications(0, 16, 8);
        fail(&limiter, "sprayer", 16);

        let held: Vec<_> = std::iter::repeat_with(|| {
            limiter
                .admit("sprayer")
                .expect("the derived ceiling must admit its share: a quarter of 8, which is 2")
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

    /// A full map of live counters must not be scanned on every attempt.
    ///
    /// The defect: every unnamed attempt against a full map ran `reclaim`,
    /// which visits every counter under the global write lock and, with the
    /// map full of live junk, frees nothing. Each such attempt cost
    /// `capacity` probes while every other admission and settlement waited.
    #[test]
    fn a_reclaim_scan_runs_at_most_once_per_interval() {
        let mut counters = Counters::new();
        counters.named.insert(
            "junk".to_owned(),
            Counter {
                expires_at_ms: 1_000,
                failures: 1,
                inherited: 0,
                inherited_expires_at_ms: 0,
                outstanding: 0,
            },
        );

        assert!(
            !counters.reclaim(500),
            "a live counter is not idle, so the first scan frees nothing"
        );
        assert!(
            !counters.reclaim(
                500_u64
                    .saturating_add(RECLAIM_INTERVAL_MS)
                    .saturating_sub(1)
            ),
            "a second scan inside the interval must not run, even with the counter now idle: \
             that is what bounds how often an attacker holding the map full buys a full scan"
        );
        assert_eq!(counters.named.len(), 1, "so the idle counter is still held");
        assert!(
            counters.reclaim(500_u64.saturating_add(RECLAIM_INTERVAL_MS)),
            "once the interval has passed the scan runs and frees the idle counter"
        );
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
