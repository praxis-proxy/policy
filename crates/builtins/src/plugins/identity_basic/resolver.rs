// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `identity.resolve` handler.
//
// Read the header, decode it per RFC 7617, look the user up, verify the
// password, project the record onto the identity slots. The password is never
// written back: it does not reach `raw_credentials`, so no downstream policy
// step can forward the caller's own password to an upstream that never
// authenticated it. The inbound `Authorization` header itself is still on the
// request -- removing it before an upstream sees it is a host obligation, since
// the identity hook has no request-mutation channel.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use praxis_policy_apl_cmf::constants::DETAIL_HTTP_HEADERS;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::extensions::raw_credentials::TokenRole;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::identity::mapping::{ClaimMapper as _, ConfiguredClaimMap};
use praxis_policy_core::identity::{IdentityHook, IdentityPayload};
use praxis_policy_core::plugin::{OnError, Plugin, PluginConfig, PluginMode};

use crate::plugins::identity_basic::config::{BasicResolverConfig, ProviderConfig};
use crate::plugins::identity_basic::credential::{
    CredentialLocation, DecodeError, ExtractionError, decode_basic,
};
use crate::plugins::identity_basic::directory::{CredentialDirectory, DirectoryError};
use crate::plugins::identity_basic::failure_limit::{FailureLimiter, Refusal};
use crate::plugins::identity_basic::htpasswd::HtpasswdDirectory;
use crate::plugins::identity_basic::record_map::USER_ID_FIELD;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The status a denial from this resolver carries.
const HTTP_UNAUTHORIZED: i64 = 401;

/// How many failures may be logged at warn level per window.
const FAILURE_LOG_BUDGET: u64 = 10;

/// The failure-logging window, in milliseconds.
const FAILURE_LOG_WINDOW_MS: u64 = 10_000; // 10 seconds

/// How many of `log_budget`'s low bits hold the logged count.
///
/// The one place the split is written down. The shift and the mask below are
/// both derived from it, so they cannot drift apart -- which is the defect
/// this replaces: a 40-bit mask paired with a `<< 40` discarded every bit of
/// the window start above the low 24, and the budget stopped limiting after
/// about 4.7 hours of uptime.
///
/// 24 bits holds 16,777,215 against a budget of ten, and leaves 40 bits of
/// milliseconds for the window start: about 34 years of uptime.
const LOG_COUNT_BITS: u32 = 24;

/// The mask selecting `log_budget`'s count field.
const LOG_COUNT_MASK: u64 = (1 << LOG_COUNT_BITS) - 1;

/// Denial codes, which a host maps to a status.
///
/// Two phases, named differently on purpose.
///
/// **Extraction** codes are shared verbatim with the JWT and API-key
/// resolvers. Reading a credential off the wire fails consistently across the
/// identity plugins, so an operator's runbook for `auth.missing_credential`
/// applies to all of them.
///
/// **Lookup** codes are this plugin's own. One of them diverges deliberately
/// from the API-key plugin: that resolver splits "no record matched" from "the
/// directory could not answer" so an operator can act on a denial spike, and
/// that split is kept here for `DIRECTORY_UNAVAILABLE`. It is *not* extended
/// to the unknown-user / wrong-password split, which has no code of its own:
/// telling a client which of the two happened is a username-enumeration
/// oracle. Operators keep that distinction in logs, not on the wire.
pub mod codes {
    /// Nothing was supplied at the configured location.
    pub const MISSING_CREDENTIAL: &str = "auth.missing_credential";
    /// The location held a value and it was empty.
    pub const EMPTY_CREDENTIAL: &str = "auth.empty_credential";
    /// The credential name appeared more than once.
    pub const AMBIGUOUS_CREDENTIAL: &str = "auth.ambiguous_credential";
    /// The credential input is structurally malformed.
    pub const MALFORMED_CREDENTIAL: &str = "auth.malformed_credential";
    /// The user-id is unknown, or the password does not match. One code for
    /// both: see the module documentation.
    pub const INVALID_CREDENTIALS: &str = "auth.invalid_credentials";
    /// A record matched and has expired.
    pub const CREDENTIAL_EXPIRED: &str = "auth.credential_expired";
    /// Too many recent failures for this user-id.
    pub const TOO_MANY_FAILURES: &str = "auth.too_many_failures";
    /// The directory could not answer.
    pub const DIRECTORY_UNAVAILABLE: &str = "auth.directory_unavailable";
    /// A record resolved and the map could not project it.
    pub const MAPPING_FAILED: &str = "auth.mapping_failed";
}

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/// Resolves an HTTP Basic credential to an identity.
#[derive(Debug)]
pub struct BasicIdentityResolver {
    config: PluginConfig,
    settings: BasicResolverConfig,
    directory: Arc<dyn CredentialDirectory>,
    mapper: ConfiguredClaimMap,
    location: CredentialLocation,
    challenge: String,
    limiter: FailureLimiter,
    /// How many failures have been logged in the current window, and when it
    /// closes.
    ///
    /// Packed into one word so the request path pays one atomic rather than a
    /// lock: the window start in the high 40 bits, the count in the low
    /// [`LOG_COUNT_BITS`]. Both the shift and the mask derive from that one
    /// constant, so the halves cannot disagree -- they previously did, and the
    /// budget stopped limiting after about 4.7 hours of uptime.
    ///
    /// [`LOG_COUNT_BITS`]: LOG_COUNT_BITS
    log_budget: AtomicU64,
    started: std::time::Instant,
}

impl BasicIdentityResolver {
    /// Build a resolver from its `config:` block.
    ///
    /// # Errors
    ///
    /// `PluginError::Config` for anything the settings, the record map, or the
    /// directory backend reject. The record file is read here, at config load,
    /// so an unreadable or malformed one stops startup instead of denying
    /// every request as though the passwords were wrong.
    pub fn new(config: PluginConfig) -> Result<Self, Box<PluginError>> {
        if config.mode != PluginMode::Sequential || config.on_error != OnError::Fail {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "{}: an identity resolver needs `mode: sequential` and `on_error: fail`",
                    config.name
                ),
            }));
        }
        let block = config.config.clone().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!("{}: `config:` block is required", config.name),
            })
        })?;
        let settings: BasicResolverConfig =
            serde_json::from_value(block).map_err(|e| PluginError::Config {
                message: format!("{}: {e}", config.name),
            })?;
        // The mapper falls out of validation rather than being compiled a
        // second time from the same block.
        let mapper = settings.validate().map_err(|e| PluginError::Config {
            message: format!("{}: {e}", config.name),
        })?;

        let directory: Arc<dyn CredentialDirectory> = match &settings.provider {
            ProviderConfig::Htpasswd(htpasswd) => {
                // The ceiling goes to the backend rather than being checked
                // once here: `validate` runs before the file is read and so
                // cannot know the scheme, and a check at this point would hold
                // only until the first reload replaced an argon2 file with a
                // bcrypt one. The backend re-checks it on every load.
                let loaded = HtpasswdDirectory::with_password_ceiling(
                    htpasswd.clone(),
                    settings.limits.max_password_bytes,
                )
                .map_err(|e| PluginError::Config {
                    message: format!("{}: {e}", config.name),
                })?;
                Arc::new(loaded)
            },
        };

        Ok(Self {
            location: settings.location(),
            challenge: settings.challenge(),
            limiter: FailureLimiter::new(settings.failure_limit),
            config,
            settings,
            directory,
            mapper,
            log_budget: AtomicU64::new(0),
            started: std::time::Instant::now(),
        })
    }

    /// How many attempts the failure limiter counted in its overflow table
    /// rather than by name.
    pub fn limiter_saturations(&self) -> u64 {
        self.limiter.saturations()
    }

    /// How many user-ids the failure limiter currently tracks by name.
    pub fn limiter_tracked(&self) -> usize {
        self.limiter.tracked()
    }

    /// A denial from this resolver, carrying 401 and the realm challenge.
    ///
    /// Every denial this resolver raises gets one, because every one of them
    /// means the caller may retry with a credential. The challenge rides the
    /// violation's `details` under the established `http.headers` key, which
    /// the host renders on the wire; nothing in this repository reads it, so
    /// delivery is a host obligation rather than something this plugin can
    /// assert end to end.
    fn deny(&self, code: &str, reason: impl Into<String>) -> PluginResult<IdentityPayload> {
        let mut violation = PluginViolation::new(code, reason).with_proto_error_code(
            // Protocol-dependent: a host on an MCP route reads this as a
            // JSON-RPC code, where 401 means nothing. Basic on an MCP route is
            // not a sensible deployment and the operator documentation says
            // so, rather than this plugin pretending the number is portable.
            HTTP_UNAUTHORIZED,
        );
        violation.details.insert(
            DETAIL_HTTP_HEADERS.to_owned(),
            serde_json::json!({ "WWW-Authenticate": self.challenge }),
        );
        PluginResult::deny(violation)
    }

    /// The one denial an unknown user and a wrong password share.
    ///
    /// Byte-identical for both, deliberately: a client that could tell them
    /// apart could enumerate user-ids without ever guessing a password.
    fn deny_invalid(&self) -> PluginResult<IdentityPayload> {
        self.deny(
            codes::INVALID_CREDENTIALS,
            "the credential was not accepted",
        )
    }

    /// Whether a failure may be logged at warn level now.
    ///
    /// Failed Basic authentication is attacker-controlled in volume, so an
    /// unbudgeted warn per attempt is a log-flooding primitive that also
    /// evicts the records an operator needs. Past the budget the attempt is
    /// still denied and still counted; only the line is dropped.
    ///
    /// One budget covers every attacker-driven line, the rejected-credential
    /// path and the provokable [`deny_directory`] variants alike, because they
    /// compete for the same log volume. Splitting them would hand an attacker
    /// two budgets to fill instead of one.
    ///
    /// [`deny_directory`]: BasicIdentityResolver::deny_directory
    fn may_log_failure(&self) -> bool {
        let now = self.now_ms();
        loop {
            let packed = self.log_budget.load(Ordering::Relaxed);
            let window_start = packed >> LOG_COUNT_BITS;
            let count = packed & LOG_COUNT_MASK;
            let elapsed = now.saturating_sub(window_start);
            let (next_start, next_count) = if elapsed >= FAILURE_LOG_WINDOW_MS {
                (now, 1)
            } else if count < FAILURE_LOG_BUDGET {
                (window_start, count.saturating_add(1))
            } else {
                return false;
            };
            // `now_ms` bounds the start to what the field holds and the budget
            // bounds the count far below `LOG_COUNT_MASK`, so neither half can
            // overflow into the other.
            let next = (next_start << LOG_COUNT_BITS) | next_count;
            if self
                .log_budget
                .compare_exchange_weak(packed, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Milliseconds since this resolver was built, bounded to the packed field.
    ///
    /// Truncated to the width the window start actually gets, so the value
    /// stored and the value read back are the same one. That is about 34 years
    /// of uptime, past which the start wraps and one window logs early.
    fn now_ms(&self) -> u64 {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        elapsed & (u64::MAX >> LOG_COUNT_BITS)
    }
}

#[async_trait::async_trait]
impl Plugin for BasicIdentityResolver {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

impl HookHandler<IdentityHook> for BasicIdentityResolver {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        let location = &self.location;

        let extracted = match location.raw_from_ext(payload.headers(), ext) {
            Ok(raw) => raw,
            Err(ExtractionError::Missing) => {
                return self.deny(
                    codes::MISSING_CREDENTIAL,
                    format!("no credential at {}", location.credential),
                );
            },
            Err(ExtractionError::Empty) => {
                return self.deny(
                    codes::EMPTY_CREDENTIAL,
                    format!("{} holds an empty credential", location.credential),
                );
            },
            // Another scheme, so another resolver may serve it. Carry the
            // decline to the executor while leaving the identity slots
            // untouched; denying here would make a Basic resolver and a Bearer
            // resolver on one `Authorization` header impossible.
            //
            // The executor synthesizes its own denial if every resolver
            // declines, and that one carries no challenge: a declining plugin
            // has no channel to contribute one.
            Err(ExtractionError::WrongPrefix) => {
                let mut updated = payload.clone();
                updated.mark_credential_declined();
                return PluginResult::modify_payload(updated);
            },
            Err(ExtractionError::Ambiguous) => {
                return self.deny(
                    codes::AMBIGUOUS_CREDENTIAL,
                    format!("ambiguous credential at {}", location.credential),
                );
            },
            Err(_) => {
                return self.deny(
                    codes::MALFORMED_CREDENTIAL,
                    format!("malformed credential at {}", location.credential),
                );
            },
        };

        // The reason names the location and the shape, never the value: a
        // `DecodeError` carries no credential byte, offset or buffer, which is
        // what makes it safe to format here.
        let credential = match decode_basic(
            extracted,
            self.settings.limits.max_user_id_bytes,
            self.settings.limits.max_password_bytes,
        ) {
            Ok(credential) => credential,
            Err(DecodeError::EmptyHalf) => {
                return self.deny(
                    codes::EMPTY_CREDENTIAL,
                    format!("{} holds an empty user-id or password", location.credential),
                );
            },
            Err(error) => {
                return self.deny(
                    codes::MALFORMED_CREDENTIAL,
                    format!("malformed credential at {}: {error}", location.credential),
                );
            },
        };
        let user_id = credential.user_id();

        // Before the lookup, so a user-id blocked by *name* costs no
        // verification. A user-id the saturated map could not name is admitted
        // over its shared bucket and judged after the verdict instead: that
        // bucket's failures may not be its own, and only a verified credential
        // tells the two apart. See `FailureLimiter::admit`.
        //
        // The limiter keys on the normalised user-id, so two encodings of one
        // name share a bucket rather than getting a budget each.
        //
        // The guard reserves this attempt against the budget for as long as it
        // is held, so parallel guesses for one user-id are bounded by
        // `max_failures` rather than all passing the same pre-verification
        // read. Every path out of this handler either settles it with a verdict
        // or drops it, and a drop releases the reservation without recording a
        // failure -- which is what a directory error or a cancelled request
        // should cost.
        // `None` with `unproven` set means a shared overflow bucket refused
        // the attempt on failures that may not be this caller's. The
        // credential is verified anyway: only a correct password separates
        // this caller from the spray that spent the bucket, and without that
        // step a junk-user-id flood denies every caller the saturated map
        // cannot name. No reservation is held on that path -- the bucket
        // already counts the attempt that spent it, and the verdict below
        // decides whether this one is served.
        let (admission, unproven) = match self.limiter.admit(user_id) {
            Ok(admission) => (Some(admission), false),
            Err(Refusal::Blocked) => {
                return self.deny(
                    codes::TOO_MANY_FAILURES,
                    "too many recent failures for this credential",
                );
            },
            // `Refusal` is `#[non_exhaustive]` for downstream crates, but
            // within this one the compiler sees every variant -- so a variant
            // added later fails to compile here rather than silently falling
            // through to a verification this resolver has not reasoned about.
            // That is the stronger guarantee, so there is no catch-all arm.
            Err(Refusal::Unproven) => (None, true),
        };

        let record = match self.directory.lookup(user_id, ext).await {
            Ok(found) => found,
            Err(error) => return self.deny_directory(&error),
        };

        // Runs for a miss too, against the directory's own worst admitted work
        // factor, so an unknown user-id costs what every known one costs.
        // Passing `None` through rather than returning early is the whole of
        // that property: a `return` here would be the timing oracle.
        let verified = match self
            .directory
            .verify(record.as_ref(), &credential, ext)
            .await
        {
            Ok(verified) => verified,
            Err(error) => return self.deny_directory(&error),
        };

        if !verified || record.is_none() {
            if let Some(admission) = admission {
                admission.record_failure();
            }
            if self.may_log_failure() {
                // Debug, and only debug: a user-id in a warn line reaches
                // every aggregator at default verbosity, where it is an
                // enumeration list for anyone who can read the logs. No metric
                // carries it as a label either, for the same reason.
                tracing::debug!(
                    user_id = %user_id.escape_debug(),
                    directory = self.directory.kind(),
                    "basic: credential rejected",
                );
                tracing::warn!(
                    directory = self.directory.kind(),
                    "basic: credential rejected; raise the log level to debug for the user-id",
                );
            }
            // A shared bucket had already refused this attempt and the
            // credential did not clear it, so the refusal stands and denies
            // for the budget rather than for the credential.
            return if unproven {
                self.deny(
                    codes::TOO_MANY_FAILURES,
                    "too many recent failures for this credential",
                )
            } else {
                self.deny_invalid()
            };
        }

        // `record.is_none()` returned above, so this cannot bind `None`. Kept
        // as a binding rather than an unwrap because the crate denies both.
        let Some(record) = record else {
            return self.deny_invalid();
        };

        // Untested, and not reachable to test today: `.htpasswd` has no native
        // expiry field, so the only backend wired here never sets
        // `expires_at`, and `new` builds its directory from config with no
        // seam to inject one that does. Widening the public API to reach a
        // branch that is dead until the YAML backend lands would be the more
        // expensive mistake, so the gap is recorded here and the test belongs
        // with that backend.
        if let Some(expires_at) = record.expires_at
            && expires_at <= Utc::now()
        {
            if let Some(admission) = admission {
                admission.record_failure();
            }
            return self.deny(
                codes::CREDENTIAL_EXPIRED,
                "the credential's record has expired",
            );
        }

        // The verified user-id, so a record carrying nothing else still
        // projects an anchor. Inserted rather than left to each backend
        // because every backend here is indexed by it.
        let mut fields = record.fields;
        fields.insert(
            USER_ID_FIELD.to_owned(),
            serde_json::Value::String(user_id.to_owned()),
        );

        let mut updated = payload.clone();
        match &self.settings.role {
            TokenRole::User => match self.mapper.map_subject(&fields) {
                Some(subject) => updated.subject = Some(subject),
                None => return self.mapping_failed("subject"),
            },
            TokenRole::Client => match self.mapper.map_client(&fields) {
                Some(client) => updated.client = Some(client),
                None => return self.mapping_failed("client"),
            },
            TokenRole::CallerWorkload => match self.mapper.map_workload(&fields) {
                Some(workload) => updated.caller_workload = Some(workload),
                None => return self.mapping_failed("workload"),
            },
            // `TokenRole` is `#[non_exhaustive]`, and `validate` refuses a role
            // with no section. Surfacing as misconfigured rather than silently
            // authenticating nobody.
            other => {
                return self.deny(
                    "auth.misconfigured",
                    format!("role {other:?} is not supported"),
                );
            },
        }

        match admission {
            Some(admission) => admission.record_success(),
            // Refused by a shared bucket and cleared by the verdict. Counted
            // so an operator can see legitimate callers paying for buckets
            // they do not own.
            None => self.limiter.admit_proven(),
        }
        updated.resolved_at = Some(Utc::now());
        // `raw_credentials` is deliberately not populated. The password stops
        // here, so no downstream step can forward a caller's own password to an
        // upstream that never authenticated it. The inbound `Authorization`
        // header is still on the request: this hook has no request-mutation
        // channel, so removing it is a host obligation.
        PluginResult::modify_payload(updated)
    }
}

impl BasicIdentityResolver {
    /// The denial for a directory that could not answer.
    ///
    /// Deliberately not the code a rejected credential gets. An operator
    /// watching a denial spike cannot act until they know whether the
    /// passwords are wrong or the directory is down.
    ///
    /// No failure is recorded against the user-id, for any variant. None of
    /// them is a verdict on the credential -- they all mean the directory
    /// could not answer -- so counting one would let anyone who can saturate
    /// or stale the directory spend a named victim's budget to zero without
    /// ever guessing a password. That is the targeted-lockout shape the
    /// limiter exists to prevent, so a guess the directory never evaluated
    /// stays uncounted. These paths return without settling the admission
    /// guard, which releases the attempt's reservation rather than charging
    /// it. The cost is honest and bounded: the limiter bounds
    /// *evaluated* guesses, and an attacker who suppresses evaluation gets no
    /// password feedback either.
    fn deny_directory(&self, error: &DirectoryError) -> PluginResult<IdentityPayload> {
        // Budgeted for the variants an attacker can provoke at will.
        // `Saturated` returns before any hashing, so a flood of excess
        // concurrent requests sustains a *higher* log rate than the
        // wrong-password path the budget already protects; `Stale` fires per
        // request for as long as the index is past its ceiling. Both would
        // evict the records an operator needs to diagnose them.
        //
        // `Unavailable` and `Malformed` are not rate-limited: they report a
        // broken file or backend rather than a caller's traffic, they do not
        // repeat per attacker request the way the other two do, and silently
        // dropping them would hide the outage an operator is paged for.
        let budgeted = matches!(error, DirectoryError::Saturated | DirectoryError::Stale);
        if !budgeted || self.may_log_failure() {
            tracing::warn!(
                directory = self.directory.kind(),
                %error,
                "basic: credential directory could not answer",
            );
        }
        self.deny(
            codes::DIRECTORY_UNAVAILABLE,
            "the credential directory could not answer",
        )
    }

    /// The denial for a record the map could not project.
    ///
    /// No failure is charged against the user-id: the password verified, so
    /// the credential is not what is wrong, and charging a misconfiguration to
    /// the caller would lock out everyone presenting a correct one. Returning
    /// without settling the admission guard releases the reservation instead.
    fn mapping_failed(&self, slot: &str) -> PluginResult<IdentityPayload> {
        self.deny(
            codes::MAPPING_FAILED,
            format!(
                "the record map produced no {slot}: no candidate resolved for the anchor, or a \
                 field declaring `on_missing: deny` resolved nothing. Raise the log level to \
                 debug to see which fields and which paths were tried"
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{FAILURE_LOG_BUDGET, LOG_COUNT_BITS, LOG_COUNT_MASK};

    /// The window start must survive a round trip through the packed word.
    ///
    /// The defect this pins was a 40-bit mask paired with a `<< 40`: every bit
    /// of the start above the low 24 was discarded, so past 2^24 ms (~4.66h)
    /// of uptime the stored start read back as a much smaller number, elapsed
    /// always exceeded the window, and every attempt logged. No test caught it
    /// because no test run lives that long -- hence pinning the arithmetic
    /// rather than the clock.
    #[test]
    fn a_window_start_round_trips_past_the_old_truncation_boundary() {
        let bound = u64::MAX >> LOG_COUNT_BITS;
        for start in [
            0,
            1_000,
            (1 << 24) - 1,    // the last value the old split held
            1 << 24,          // ~4.66h: the first it silently truncated
            18_000_000,       // the review's measurement: read back as 1,222,784
            86_400_000 * 365, // a year of uptime
            bound,            // the widest start the field holds
        ] {
            let packed = (start << LOG_COUNT_BITS) | FAILURE_LOG_BUDGET;
            assert_eq!(
                packed >> LOG_COUNT_BITS,
                start,
                "a window start of {start}ms must read back unchanged"
            );
            assert_eq!(
                packed & LOG_COUNT_MASK,
                FAILURE_LOG_BUDGET,
                "the count must not be disturbed by a start of {start}ms"
            );
        }
    }

    /// The count field must hold the budget with room to spare, and the two
    /// fields must not overlap.
    ///
    /// Checked in a `const` block, so a split that lets the count carry into
    /// the window start fails the build rather than a test run.
    #[test]
    fn the_packed_fields_do_not_overlap() {
        const {
            assert!(
                FAILURE_LOG_BUDGET < LOG_COUNT_MASK,
                "the budget must fit the count field without reaching its ceiling, or an \
                 increment would carry into the window start"
            );
            assert!(
                LOG_COUNT_MASK & ((u64::MAX >> LOG_COUNT_BITS) << LOG_COUNT_BITS) == 0,
                "the count mask and the shifted start must not share a bit"
            );
        }
    }
}
