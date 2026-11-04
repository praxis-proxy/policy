// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The config block an operator writes, and what it rejects at load.
//
// Everything checkable is checked here. A resolver that builds and then denies
// every request reads as an outage, and the operator looking at it is reading
// the wrong logs.

use praxis_policy_core::extensions::raw_credentials::{Credential, TokenRole};
use praxis_policy_core::identity::credential::CredentialLocation;
use praxis_policy_core::identity::mapping::{ClaimMapConfig, ClaimsOverrides, ConfiguredClaimMap};
use serde::{Deserialize, Serialize};

use crate::plugins::identity_basic::htpasswd::HtpasswdConfig;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The scheme this resolver services, fixed rather than configurable.
///
/// The gate matches it case-insensitively and consumes the `1*SP` after it,
/// which is the whole of what RFC 7235 asks of a scheme match.
pub const SCHEME_PREFIX: &str = "Basic ";

/// The default user-id length ceiling, in bytes.
const DEFAULT_MAX_USER_ID_BYTES: usize = 255;

/// The default password length ceiling, in bytes.
///
/// 72 is bcrypt's truncation point: a longer password would verify on its
/// 72-byte prefix, so admitting one would accept a credential nobody chose.
/// An argon2-only or sha-crypt-only deployment can raise this.
const DEFAULT_MAX_PASSWORD_BYTES: usize = 72;

/// The default number of consecutive failures one user-id may accumulate.
const DEFAULT_MAX_FAILURES: u32 = 10;

/// The default window a failure counter survives, in seconds.
const DEFAULT_FAILURE_WINDOW_SECS: u64 = 300; // 5 minutes

/// The default number of user-ids the failure limiter tracks at once.
const DEFAULT_FAILURE_CAPACITY: usize = 10_000;

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/// Which backend holds the records.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
#[non_exhaustive]
pub enum ProviderConfig {
    /// Records in an Apache `.htpasswd` file, indexed by user-id.
    Htpasswd(HtpasswdConfig),
}

/// Who enforces a record's expiry.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExpiryPolicy {
    /// Compare `expires_at` here when the record carries one.
    ///
    /// The only policy, unlike the API-key plugin's. `.htpasswd` has no native
    /// expiry and nothing else is positioned to enforce one, so a `directory`
    /// mode would be a knob that either changed nothing or disabled expiry
    /// entirely depending on the backend.
    #[default]
    Enforce,
}

/// How repeated failures for one user-id are bounded.
///
/// Per process, and per user-id. It does not coordinate replicas and does not
/// see a spray across many user-ids; both need an edge or shared counter.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FailureLimitConfig {
    /// How many user-ids are tracked at once.
    ///
    /// At capacity a user-id with no counter is denied rather than admitted:
    /// evicting to make room would let a flood of fresh user-ids clear a
    /// blocked one's counter, which is the bypass this ceiling exists to stop.
    pub capacity: usize,

    /// How many consecutive failures a user-id may accumulate before denial.
    pub max_failures: u32,

    /// How long a counter survives its last failure, in seconds.
    pub window_secs: u64,
}

impl Default for FailureLimitConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_FAILURE_CAPACITY,
            max_failures: DEFAULT_MAX_FAILURES,
            window_secs: DEFAULT_FAILURE_WINDOW_SECS,
        }
    }
}

/// Credential length ceilings, applied before any verification runs.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialLimits {
    /// The longest password this resolver will verify, in bytes.
    pub max_password_bytes: usize,

    /// The longest user-id this resolver will look up, in bytes.
    pub max_user_id_bytes: usize,
}

impl Default for CredentialLimits {
    fn default() -> Self {
        Self {
            max_password_bytes: DEFAULT_MAX_PASSWORD_BYTES,
            max_user_id_bytes: DEFAULT_MAX_USER_ID_BYTES,
        }
    }
}

/// The `config:` block under a `kind: identity/basic` plugin.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BasicResolverConfig {
    /// The protection space name the challenge advertises.
    ///
    /// Required, because RFC 7617 requires the challenge to carry one and
    /// there is no sensible default: the realm is what a client's credential
    /// store keys on.
    pub realm: String,

    /// Whether the challenge advertises `charset="UTF-8"`.
    ///
    /// Advertises the client-side expectation only. The server verifies the
    /// bytes it receives either way.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub charset_utf8: bool,

    /// Which fields the projected claims bag keeps or drops.
    #[serde(default)]
    pub claims: ClaimsOverrides,

    /// Where the credential sits on the request.
    ///
    /// Headers only: see [`validate`].
    ///
    /// [`validate`]: BasicResolverConfig::validate
    pub credential: Credential,

    /// Who enforces a record's expiry.
    #[serde(default)]
    pub expiry: ExpiryPolicy,

    /// How repeated failures for one user-id are bounded.
    #[serde(default)]
    pub failure_limit: FailureLimitConfig,

    /// Credential length ceilings.
    #[serde(default)]
    pub limits: CredentialLimits,

    /// Where the records live.
    pub provider: ProviderConfig,

    /// Record fields onto the identity slots.
    ///
    /// A block omitting this resolver's role section gets one anchoring that
    /// role's identifier on the verified user-id, so the minimal `.htpasswd`
    /// deployment needs no entry here.
    #[serde(default)]
    pub record_map: ClaimMapConfig,

    /// Which identity slot this resolver fills.
    #[serde(default = "default_role")]
    pub role: TokenRole,
}

fn default_role() -> TokenRole {
    TokenRole::User
}

impl BasicResolverConfig {
    /// The location and the fixed scheme prefix, paired as extraction wants
    /// them.
    pub fn location(&self) -> CredentialLocation {
        CredentialLocation::new(self.credential.clone(), Some(SCHEME_PREFIX.to_owned()))
    }

    /// The `WWW-Authenticate` value a denial from this resolver carries.
    ///
    /// The realm is validated at load, so the quoted string cannot be broken
    /// out of here.
    pub fn challenge(&self) -> String {
        let realm = &self.realm;
        if self.charset_utf8 {
            format!("Basic realm=\"{realm}\", charset=\"UTF-8\"")
        } else {
            format!("Basic realm=\"{realm}\"")
        }
    }

    /// Reject what cannot work, before a request depends on it, and return the
    /// mapper the checking produced.
    ///
    /// Compiling the `record_map` *is* most of the validation, so the compiled
    /// map comes back rather than being thrown away and rebuilt: two compiles
    /// is two places that could disagree about what an operator wrote, and the
    /// second one's failure arm could then never be reached or tested.
    ///
    /// Two `identity/basic` resolvers on one route are deliberately *not*
    /// rejected. Doing so needs either a builtin's `kind` string hardcoded
    /// into the engine or a new cross-plugin validation seam; the constraint
    /// is stated in the operator documentation instead.
    ///
    /// # Errors
    ///
    /// A non-header credential location, a realm that cannot be quoted, a
    /// `record_map` the shared compiler refuses, a map with no section for the
    /// configured role, or incoherent limits.
    pub fn validate(&self) -> Result<ConfiguredClaimMap, String> {
        self.location().validate()?;

        // A password in a query string reaches access logs, proxy logs,
        // browser history and `Referer` headers; a cookie-borne one invites
        // CSRF on a credential replayed every request. Basic is header-only in
        // practice, so restricting costs an operator nothing real.
        if !matches!(self.credential, Credential::Header { .. }) {
            return Err(format!(
                "`credential.kind` must be `header` for Basic authentication; {} would put a \
                 password where logs and browser history can read it",
                self.credential
            ));
        }

        validate_realm(&self.realm)?;

        if self.limits.max_password_bytes == 0 || self.limits.max_user_id_bytes == 0 {
            return Err(
                "`limits.max_password_bytes` and `limits.max_user_id_bytes` must be greater \
                 than zero; a zero ceiling rejects every credential"
                    .to_owned(),
            );
        }
        if self.failure_limit.capacity == 0 {
            return Err(
                "`failure_limit.capacity` must be greater than zero; a zero capacity tracks no \
                 user-id and denies every request"
                    .to_owned(),
            );
        }
        if self.failure_limit.max_failures == 0 {
            return Err(
                "`failure_limit.max_failures` must be greater than zero; zero denies a user-id \
                 before its first attempt"
                    .to_owned(),
            );
        }
        if self.failure_limit.window_secs == 0 {
            return Err(
                "`failure_limit.window_secs` must be greater than zero; a zero window expires \
                 every counter before it is read"
                    .to_owned(),
            );
        }

        let mapper = super::record_map::compile(&self.record_map, &self.claims, &self.role)?;
        // A map that declares no section for the role this resolver fills maps
        // nothing, every time, and the resulting `auth.mapping_failed` names a
        // record rather than the config that cannot project one.
        mapper.compiled().role(&self.role).map_err(|e| {
            format!(
                "`record_map` has no section for `role: {:?}`: {e}",
                self.role
            )
        })?;
        Ok(mapper)
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Whether a realm can sit inside the challenge's quoted string.
///
/// Printable ASCII excluding `"` and `\`. A quote would end the string early
/// and a backslash would escape whatever follows it, either of which turns an
/// operator's realm into a header-injection primitive. Rejected at load, where
/// an operator can fix it, rather than escaped at render time, where the
/// challenge would silently not say what they wrote.
fn validate_realm(realm: &str) -> Result<(), String> {
    if realm.is_empty() {
        return Err("`realm` must not be empty".to_owned());
    }
    if realm
        .bytes()
        .any(|b| !(0x20..=0x7e).contains(&b) || b == b'"' || b == b'\\')
    {
        return Err(
            "`realm` must be printable ASCII without `\"` or `\\`: anything else cannot be \
             carried in the challenge's quoted string"
                .to_owned(),
        );
    }
    Ok(())
}
