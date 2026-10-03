// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Operator-facing knobs for the delegated-token cache, and the
// serve-window arithmetic that turns them into "how long may this
// minted token be reused".
//
// Everything here defaults to off. A delegator with no `cache:` block
// behaves exactly as it did before the cache existed: one RFC 8693
// exchange per delegate step.

use std::time::Duration;

use praxis_policy_core::delegation::DelegationSubject;
use serde::{Deserialize, Serialize};

/// See [`CacheConfig::subjects`] for why the default is the narrow pair.
fn default_subjects() -> Vec<DelegationSubject> {
    vec![DelegationSubject::ThisWorkload, DelegationSubject::Client]
}

fn default_max_entries() -> u64 {
    10_000
}

fn default_ttl_ceiling_seconds() -> u64 {
    300
}

fn default_staleness_fraction() -> f64 {
    0.20
}

fn default_staleness_floor_seconds() -> u64 {
    30
}

fn default_staleness_jitter_seconds() -> u64 {
    5
}

/// When a cached token stops being served, expressed relative to its own
/// lifetime rather than as a fixed distance from expiry.
///
/// A fixed margin has two failure modes that a fraction does not. It is
/// meaningless against a token whose whole lifetime is shorter than the
/// margin — the entry is stale the instant it is created, and the cache
/// silently achieves a zero percent hit rate while looking enabled. And
/// it retires every entry minted in the same burst at the same instant,
/// so the stampede the cache exists to prevent reappears one lifetime
/// later.
///
/// `fraction` addresses the first, `jitter` the second. `floor` keeps a
/// long-lived token from being served right up against clock skew
/// between this process and the resource server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StalenessConfig {
    /// Retire an entry once this proportion of its lifetime remains.
    /// `0.20` serves a token for the first 80% of its life. Must be in
    /// `[0.0, 1.0)`.
    #[serde(default = "default_staleness_fraction")]
    pub fraction: f64,

    /// Never serve a token within this many seconds of its expiry,
    /// whatever `fraction` works out to. This is the clock-skew
    /// allowance.
    #[serde(default = "default_staleness_floor_seconds")]
    pub floor_seconds: u64,

    /// Spread retirement over this many seconds so entries minted
    /// together do not all expire together. See
    /// [`CacheConfig::serve_window`] for why this is derived from the
    /// cache key rather than drawn from an RNG.
    #[serde(default = "default_staleness_jitter_seconds")]
    pub jitter_seconds: u64,
}

impl Default for StalenessConfig {
    fn default() -> Self {
        Self {
            fraction: default_staleness_fraction(),
            floor_seconds: default_staleness_floor_seconds(),
            jitter_seconds: default_staleness_jitter_seconds(),
        }
    }
}

/// Delegated-token cache settings, read from `cache:` inside the
/// delegator's `config:` block.
///
/// # Why this is off by default
///
/// Caching a delegated credential changes two things an operator may not
/// expect. A token revoked at the `IdP` stays usable here until it
/// expires, bounded only by [`ttl_ceiling_seconds`]. And a minted token
/// is reused across requests, so the `IdP`'s audit log records one
/// exchange where it previously recorded many. Both are reasonable
/// trade-offs and neither should happen because a default changed.
///
/// [`ttl_ceiling_seconds`]: Self::ttl_ceiling_seconds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Master switch. `false` means no cache is constructed at all, not
    /// merely one that always misses.
    #[serde(default)]
    pub enabled: bool,

    /// Which [`DelegationSubject`] modes may cache. Spelled as in a
    /// delegate step's `subject:` key: `this_workload`, `client`,
    /// `user`, `caller_workload`.
    ///
    /// Defaults to `this_workload` and `client`. Their entry count is
    /// bounded by configuration rather than by the caller population,
    /// and each entry serves the aggregate traffic behind it.
    ///
    /// `user` and `caller_workload` are absent on purpose. Their entry
    /// count grows with the caller population, each entry serves one
    /// principal's traffic rather than the fleet's, and they are where
    /// the cache-flooding concern lives. Enabling them should be a
    /// deliberate act rather than a side effect of turning the cache on.
    #[serde(default = "default_subjects")]
    pub subjects: Vec<DelegationSubject>,

    /// Upper bound on live entries. Eviction is least-recently-used.
    ///
    /// This is the mitigation for cache-key flooding, not a tuning
    /// parameter: a caller able to vary any key component can create
    /// entries, and this is what stops that growing without limit.
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,

    /// Cap on how long any entry may be served, regardless of the
    /// lifetime the `IdP` reported.
    ///
    /// This is the only lever against `IdP`-side revocation: a token
    /// revoked upstream remains usable here until the entry retires.
    /// An `IdP` handing out hour-long tokens does not oblige us to cache
    /// them for an hour.
    #[serde(default = "default_ttl_ceiling_seconds")]
    pub ttl_ceiling_seconds: u64,

    /// When an entry stops being served. See [`StalenessConfig`].
    #[serde(default)]
    pub staleness: StalenessConfig,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            subjects: default_subjects(),
            max_entries: default_max_entries(),
            ttl_ceiling_seconds: default_ttl_ceiling_seconds(),
            staleness: StalenessConfig::default(),
        }
    }
}

impl CacheConfig {
    /// Reject settings that cannot describe a working cache.
    ///
    /// Only checked when [`enabled`] is set: an operator who has left the
    /// cache off should not have a startup failure over a field that is
    /// never read.
    ///
    /// # Errors
    ///
    /// Returns a human-readable description of the first problem found,
    /// which the caller wraps in its own `PluginError::Config`.
    ///
    /// [`enabled`]: Self::enabled
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.subjects.is_empty() {
            return Err(
                "cache.subjects is empty, so the cache would never store anything; either list \
                 the subject modes to cache or set cache.enabled to false"
                    .to_owned(),
            );
        }
        if self.max_entries == 0 {
            return Err(
                "cache.max_entries is 0, so every insert would be evicted immediately; either \
                 raise it or set cache.enabled to false"
                    .to_owned(),
            );
        }
        if !self.staleness.fraction.is_finite()
            || self.staleness.fraction < 0.0
            || self.staleness.fraction >= 1.0
        {
            return Err(format!(
                "cache.staleness.fraction must be in [0.0, 1.0), got {}; at 1.0 or above every \
                 entry is stale the moment it is created",
                self.staleness.fraction
            ));
        }
        if self.ttl_ceiling_seconds == 0 {
            return Err(
                "cache.ttl_ceiling_seconds is 0, so no entry could ever be served".to_owned(),
            );
        }
        // Whether the margin leaves anything to serve. A token minted at
        // the ceiling is the longest-lived one this config will ever
        // hold, and `u8::MAX` is its least favourable jitter draw, so if
        // that entry cannot be served then some share of entries never
        // can, whatever lifetime the `IdP` reports. That is the
        // silent-zero-hit-rate configuration, and it belongs at startup
        // where it is one message rather than at runtime where it is a
        // graph.
        //
        // Probing `serve_window` rather than restating its condition is
        // deliberate: a restatement drifts, and every term has to be in
        // it. Comparing `floor_seconds` against the ceiling alone would
        // admit `floor: 250, jitter: 100, ceiling: 300`, which leaves
        // half of all entries unservable, and would admit a large
        // `fraction` against a small floor for the same reason.
        if self
            .serve_window(Duration::from_secs(self.ttl_ceiling_seconds), u8::MAX)
            .is_none()
        {
            return Err(format!(
                "cache.staleness leaves no window in which to serve a token: fraction {}, \
                 floor_seconds {} and jitter_seconds {} together cover the whole of \
                 cache.ttl_ceiling_seconds ({}), so some or all entries would be stale \
                 before they could be served",
                self.staleness.fraction,
                self.staleness.floor_seconds,
                self.staleness.jitter_seconds,
                self.ttl_ceiling_seconds
            ));
        }
        Ok(())
    }

    /// Whether this subject mode is permitted to cache.
    pub fn caches_subject(&self, subject: &DelegationSubject) -> bool {
        self.enabled && self.subjects.contains(subject)
    }

    /// How long a token with `lifetime` remaining may be served, or
    /// `None` if it may not be cached at all.
    ///
    /// `jitter_byte` is taken from the entry's own cache key rather than
    /// from an RNG. The purpose of the jitter is to decorrelate entries
    /// from each other, not to be unpredictable, and a key byte does that
    /// well: the key is an HMAC output, so the byte is uniform across
    /// entries. It also makes the window a pure function of the entry,
    /// which means a given key retires at the same moment however many
    /// times it is read, and the tests do not need a seeded RNG.
    ///
    /// Returns `None` when the margin consumes the entire lifetime. That
    /// is the case a fixed margin gets silently wrong — the entry would
    /// be created stale and every lookup would miss while the cache
    /// reported itself enabled. Callers treat `None` as "mint, do not
    /// insert" and say so once.
    pub fn serve_window(&self, lifetime: Duration, jitter_byte: u8) -> Option<Duration> {
        let capped = lifetime.min(Duration::from_secs(self.ttl_ceiling_seconds));
        // Via `u32` so the widening is lossless: seconds do not approach
        // the 52-bit mantissa, and a direct `u64 as f64` is a precision
        // cast the workspace denies. `u32::MAX` seconds is 136 years,
        // which is past any lifetime an IdP will report.
        let secs = whole_seconds(capped.as_secs());

        let fractional = secs * self.staleness.fraction;
        let floor = whole_seconds(self.staleness.floor_seconds);
        // The jitter only ever lengthens the margin, never shortens it,
        // so it cannot erode the clock-skew allowance the floor exists
        // to provide.
        let jitter = if self.staleness.jitter_seconds == 0 {
            0.0
        } else {
            f64::from(jitter_byte) / 255.0 * whole_seconds(self.staleness.jitter_seconds)
        };

        let margin = fractional.max(floor) + jitter;
        let window = secs - margin;
        if window <= 0.0 {
            return None;
        }
        Some(Duration::from_secs_f64(window))
    }
}

/// Widen a second count to `f64` losslessly.
///
/// Saturating at `u32::MAX` (136 years) rather than casting `u64`
/// directly, which the workspace denies as a precision loss. No `IdP`
/// reports a lifetime anywhere near the clamp, so saturation is
/// unreachable in practice and total if it ever is not.
fn whole_seconds(value: u64) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests assert on known-good values"
)]
mod tests {
    use super::*;

    fn enabled() -> CacheConfig {
        CacheConfig {
            enabled: true,
            ..CacheConfig::default()
        }
    }

    #[test]
    fn defaults_are_off_and_narrow() {
        let cfg = CacheConfig::default();
        assert!(!cfg.enabled, "the cache must not turn itself on");
        assert_eq!(cfg.subjects, default_subjects());
        assert!(
            !cfg.subjects.contains(&DelegationSubject::User),
            "user mode has an unbounded key space and must be opt-in"
        );
    }

    #[test]
    fn disabled_config_skips_validation() {
        // Nonsense settings are tolerated while the cache is off, so an
        // operator does not get a startup failure over a field nothing
        // reads.
        let cfg = CacheConfig {
            enabled: false,
            max_entries: 0,
            subjects: Vec::new(),
            ..CacheConfig::default()
        };
        cfg.validate()
            .expect("a disabled cache tolerates settings nothing reads");
    }

    #[test]
    fn rejects_a_floor_that_swallows_the_ceiling() {
        let cfg = CacheConfig {
            ttl_ceiling_seconds: 30,
            staleness: StalenessConfig {
                floor_seconds: 30,
                ..StalenessConfig::default()
            },
            ..enabled()
        };
        let err = cfg.validate().expect_err("must be rejected at startup");
        assert!(err.contains("floor_seconds"), "{err}");
    }

    /// Jitter is part of the margin, so a floor that clears the ceiling
    /// on its own can still be pushed past it by the jitter draw. Here
    /// the margin runs 250..350s against a 300s ceiling, so every entry
    /// whose jitter byte is above about half is minted and never served.
    #[test]
    fn rejects_a_floor_the_jitter_pushes_over_the_ceiling() {
        let cfg = CacheConfig {
            ttl_ceiling_seconds: 300,
            staleness: StalenessConfig {
                fraction: 0.20,
                floor_seconds: 250,
                jitter_seconds: 100,
            },
            ..enabled()
        };
        let err = cfg.validate().expect_err("half the entries never serve");
        assert!(err.contains("jitter_seconds"), "{err}");
    }

    /// The same defect reached through `fraction` rather than the floor,
    /// which a check written only against `floor_seconds` would miss.
    #[test]
    fn rejects_a_fraction_the_jitter_pushes_over_the_ceiling() {
        let cfg = CacheConfig {
            ttl_ceiling_seconds: 300,
            staleness: StalenessConfig {
                fraction: 0.99,
                floor_seconds: 30,
                jitter_seconds: 5,
            },
            ..enabled()
        };
        cfg.validate()
            .expect_err("0.99 of the lifetime plus jitter leaves nothing");
    }

    /// The boundary the two tests above sit past. Nothing here is
    /// unservable, so it must not be refused.
    #[test]
    fn accepts_a_margin_that_just_fits() {
        let cfg = CacheConfig {
            ttl_ceiling_seconds: 300,
            staleness: StalenessConfig {
                fraction: 0.20,
                floor_seconds: 250,
                jitter_seconds: 49,
            },
            ..enabled()
        };
        cfg.validate()
            .expect("a 250..299s margin still leaves a second to serve");
        assert!(
            cfg.serve_window(Duration::from_secs(300), u8::MAX)
                .is_some(),
            "the least favourable draw must still be servable"
        );
    }

    #[test]
    fn the_default_config_is_servable() {
        // Guards against a default that validates but caches nothing.
        let cfg = enabled();
        cfg.validate()
            .expect("defaults must describe a usable cache");
        assert!(
            cfg.serve_window(Duration::from_secs(cfg.ttl_ceiling_seconds), u8::MAX)
                .is_some()
        );
    }

    #[test]
    fn rejects_an_out_of_range_fraction() {
        for bad in [1.0, 1.5, -0.1, f64::NAN] {
            let cfg = CacheConfig {
                staleness: StalenessConfig {
                    fraction: bad,
                    ..StalenessConfig::default()
                },
                ..enabled()
            };
            assert!(cfg.validate().is_err(), "fraction {bad} must be rejected");
        }
    }

    #[test]
    fn caches_subject_is_false_while_disabled() {
        let cfg = CacheConfig::default();
        assert!(!cfg.caches_subject(&DelegationSubject::ThisWorkload));
    }

    #[test]
    fn serve_window_uses_the_fraction_for_long_lifetimes() {
        let cfg = CacheConfig {
            ttl_ceiling_seconds: 3600,
            staleness: StalenessConfig {
                fraction: 0.20,
                floor_seconds: 30,
                jitter_seconds: 0,
            },
            ..enabled()
        };
        // 20% of 600s is 120s, which is above the 30s floor, so the
        // fraction wins and we serve for 480s.
        let w = cfg
            .serve_window(Duration::from_secs(600), 0)
            .expect("600s is comfortably cacheable");
        assert_eq!(w.as_secs(), 480);
    }

    #[test]
    fn serve_window_uses_the_floor_for_short_lifetimes() {
        let cfg = CacheConfig {
            ttl_ceiling_seconds: 3600,
            staleness: StalenessConfig {
                fraction: 0.20,
                floor_seconds: 30,
                jitter_seconds: 0,
            },
            ..enabled()
        };
        // 20% of 100s is 20s, below the 30s floor, so the floor wins.
        let w = cfg
            .serve_window(Duration::from_secs(100), 0)
            .expect("100s is still cacheable");
        assert_eq!(w.as_secs(), 70);
    }

    #[test]
    fn serve_window_is_capped_by_the_ttl_ceiling() {
        let cfg = CacheConfig {
            ttl_ceiling_seconds: 300,
            staleness: StalenessConfig {
                fraction: 0.20,
                floor_seconds: 30,
                jitter_seconds: 0,
            },
            ..enabled()
        };
        // An IdP offering an hour does not get to keep a revocable
        // credential alive here for an hour.
        let w = cfg
            .serve_window(Duration::from_secs(3600), 0)
            .expect("cacheable, just not for an hour");
        assert_eq!(w.as_secs(), 240, "capped at 300s, then 20% margin");
    }

    #[test]
    fn serve_window_refuses_a_lifetime_the_margin_swallows() {
        let cfg = CacheConfig {
            ttl_ceiling_seconds: 300,
            staleness: StalenessConfig {
                fraction: 0.20,
                floor_seconds: 30,
                jitter_seconds: 0,
            },
            ..enabled()
        };
        // A 20-second token against a 30-second floor. This is the
        // configuration that silently produces a permanent zero percent
        // hit rate elsewhere; here it is an explicit `None`.
        assert!(cfg.serve_window(Duration::from_secs(20), 0).is_none());
        assert!(cfg.serve_window(Duration::from_secs(30), 0).is_none());
    }

    #[test]
    fn jitter_only_ever_shortens_the_window() {
        let cfg = CacheConfig {
            ttl_ceiling_seconds: 3600,
            staleness: StalenessConfig {
                fraction: 0.20,
                floor_seconds: 30,
                jitter_seconds: 5,
            },
            ..enabled()
        };
        let none = cfg.serve_window(Duration::from_secs(600), 0).unwrap();
        let full = cfg.serve_window(Duration::from_secs(600), 255).unwrap();
        assert!(full < none, "more jitter must retire the entry sooner");
        assert!(
            none.as_secs_f64() - full.as_secs_f64() <= 5.0 + f64::EPSILON,
            "jitter must stay within jitter_seconds"
        );
    }

    #[test]
    fn jitter_is_stable_for_a_given_entry() {
        let cfg = enabled();
        let a = cfg.serve_window(Duration::from_secs(600), 42);
        let b = cfg.serve_window(Duration::from_secs(600), 42);
        assert_eq!(a, b, "the window must be a pure function of the entry");
    }
}
