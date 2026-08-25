// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Typed configuration for `JwtIdentityResolver`. Deserializes from
// the plugin's `PluginConfig.config: Option<JsonValue>` field; the
// resolver's constructor reads this and builds the runtime state
// (DecodingKey instances, claim mapper selection).
//
// Serializable intermediate representations (`DecodingKeySource`)
// stand in for non-serializable runtime types (`DecodingKey`). The
// build step on each type turns the config representation into the
// runtime form.

use std::path::PathBuf;

use jsonwebtoken::{Algorithm, DecodingKey};
use praxis_policy_core::extensions::raw_credentials::TokenRole;
use serde::{Deserialize, Serialize};

use praxis_policy_core::host::{HostServices, HttpRequestError};
use praxis_policy_core::http::HttpRequest;
use praxis_policy_core::http_retry::RetryPolicy;

use super::trusted_issuer::{KeyStore, TrustedIssuer};
use crate::claim_map_config::ClaimMapConfig;

/// Top-level plugin config — what operators write under
/// `plugins[<name>].config:` in unified-config YAML.
///
/// One instance of this plugin handles ONE inbound credential
/// (one header, one role). Wire multiple instances if a deployment
/// expects multiple inbound tokens — e.g. user JWT in
/// `X-User-Token`, OAuth client token in `Authorization`, and a
/// SPIFFE JWT-SVID in `X-Workload-Token`.
///
/// Unknown keys are rejected. Every field here is optional or defaulted, so a
/// misspelling would otherwise deserialize to the default and take effect
/// silently: `claim_maps` would leave the resolver on the standard preset while
/// the operator believed their map was live.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtIdentityResolverConfig {
    /// One or more trusted issuers. At least one required.
    pub trusted_issuers: Vec<TrustedIssuerConfig>,

    /// Which identity slot this resolver fills. Determines:
    ///
    ///   * Which `TokenRole` key the raw token gets stashed under in
    ///     `RawCredentialsExtension.inbound_tokens`.
    ///   * Which `SecurityExtension` slot the mapped identity writes
    ///     into — `User` → `security.subject`, `Client` →
    ///     `security.client`, `Workload` → `security.caller_workload`.
    ///
    /// Default `User` keeps single-resolver deployments backwards-
    /// compatible. Custom roles aren't supported yet — the resolver
    /// errors at construction.
    #[serde(default = "default_role")]
    pub role: TokenRole,

    /// HTTP header name this resolver reads its token from
    /// (e.g. `"Authorization"`, `"X-User-Token"`). The `Bearer `
    /// prefix is stripped if present. Recorded on
    /// `RawInboundToken.source_header` so forwarding plugins can
    /// re-attach (or strip) the credential under the same name.
    /// Default `Authorization` matches the most common case.
    #[serde(default = "default_header")]
    pub header: String,

    /// Which shipped preset to map claims with: `standard`, `keycloak`,
    /// `auth0` or `cognito`. Omitted resolves to `standard`, which reproduces
    /// the OIDC shape this plugin has always mapped. An unknown name fails at
    /// construction and lists the valid ones.
    ///
    /// Each preset's `description` in `src/presets/` records what it covers and
    /// what it deliberately omits, which matters: two of the three providers
    /// namespace or parameterize their roles claim per deployment, so no preset
    /// can carry it. Reach those with [`claim_map`].
    ///
    /// Mutually exclusive with [`claim_map`].
    ///
    /// [`claim_map`]: Self::claim_map
    #[serde(default)]
    pub claim_mapper: Option<String>,

    /// An inline claim map, for a shape no preset covers.
    ///
    /// Mutually exclusive with [`claim_mapper`]; setting both is a config error
    /// rather than a precedence rule.
    ///
    /// See [`ClaimMapConfig`] for the surface and its escaping rules.
    ///
    /// [`claim_mapper`]: Self::claim_mapper
    #[serde(default)]
    pub claim_map: Option<ClaimMapConfig>,

    /// Which claims stay visible to a policy, overriding what the map's declared
    /// paths imply.
    ///
    /// A sibling of [`claim_mapper`] and [`claim_map`] rather than part of either,
    /// so it applies whichever way the map was chosen. `include` accepts any claim
    /// name, registered ones included: `claims: {include: [iss]}` is what makes
    /// gating on the issuing `IdP` expressible, since the subject claims bag is
    /// the only route from a claim to a policy.
    ///
    /// Both lists take top-level claim names rather than paths, because the bag
    /// is keyed by name. A dotted entry is refused at load, and a claim whose own
    /// name holds a dot is written with `\.`. A `caller_workload` resolver has no
    /// claims bag, so the setting is inert there and says so at load.
    ///
    /// Read as a raw value so a malformed one names the field.
    ///
    /// [`claim_mapper`]: Self::claim_mapper
    /// [`claim_map`]: Self::claim_map
    #[serde(default)]
    pub claims: Option<serde_json::Value>,
}

fn default_role() -> TokenRole {
    TokenRole::User
}

/// Default JWKS refresh interval — 10 minutes. High enough that a
/// fleet of gateways isn't constantly hammering the `IdP`; low enough
/// that a routine key rotation propagates within a normal change
/// window. Operators with stricter or laxer needs override per
/// `JwksUrl` via the `refresh_secs` field.
/// Floor between JWKS refresh attempts for one issuer.
///
/// Thirty seconds bounds two things at once: how much load invented
/// `kid`s can drive at an `IdP`, and how long a transient boot failure
/// denies an issuer before the next verify retries.
const fn default_min_refresh_interval_secs() -> u64 {
    30
}

fn default_refresh_secs() -> u64 {
    600
}

fn default_header() -> String {
    "Authorization".to_owned()
}

/// One issuer's config — issuer URL, audiences, decoding key
/// source, accepted algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuerConfig {
    /// Expected `iss` claim value.
    pub issuer: String,

    /// Expected audience(s). Empty list disables `aud` validation.
    #[serde(default)]
    pub audiences: Vec<String>,

    /// Algorithms accepted for signature verification (e.g.,
    /// `RS256`, `ES256`). At least one required.
    pub algorithms: Vec<Algorithm>,

    /// Source of the decoding key. See [`DecodingKeySource`].
    pub decoding_key: DecodingKeySource,

    /// Clock-skew tolerance for `exp` / `nbf` validation, in
    /// seconds. `0` (default) means "use resolver default" — the
    /// constructor applies a sensible value (currently 60s).
    #[serde(default)]
    pub leeway_seconds: u64,
}

/// Where the JWT signing key material comes from. Serializable
/// intermediate; the resolver builds a runtime `DecodingKey` from
/// it at construction time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecodingKeySource {
    /// Inline PEM-encoded public key (RSA / EC). Useful for tests
    /// and dev configs; production deployments usually prefer
    /// `pem_file` so keys don't appear in checked-in configs.
    Pem {
        /// The PEM-encoded key.
        pem: String,
    },

    /// Path to a PEM file. Read at construction time. Path is
    /// resolved relative to the host's working directory unless
    /// absolute.
    PemFile {
        /// Path to a PEM file on disk.
        path: PathBuf,
    },

    /// Inline JWK (JSON Web Key) — full JWK structure as JSON.
    Jwk {
        /// The key as an inline JWK.
        jwk: serde_json::Value,
    },

    /// OIDC JWKS endpoint — the standard way to wire to a real `IdP`
    /// (Keycloak / Auth0 / Cognito / Okta / Authentik …). Fetched
    /// at plugin `initialize_with()` and re-fetched from the verify
    /// path once the key set goes `refresh_secs` stale, so `IdP` key
    /// rolls don't require a gateway restart. Each fetched
    /// signature-use key is indexed by its `kid` so the verify path
    /// can select the right one per token (overlapping rotation
    /// windows work).
    ///
    /// **`insecure_http`** defaults to `false` — `build_async`
    /// rejects `http://` URLs, and that rejection is
    /// [`Fatal`](KeySourceError::Fatal), so a plaintext URL stops the
    /// gateway from starting rather than leaving it running with no
    /// keys. With JWKS over plaintext, anyone on the network path can
    /// swap the key material and forge JWTs the gateway accepts. Set to
    /// `true` only for `http://localhost` docker-compose development;
    /// production must always use https.
    ///
    /// **`refresh_secs`** is how stale the key set may get before a
    /// verify refreshes it proactively. Default 600 (10 minutes) — high
    /// enough that a fleet of gateways doesn't hammer the `IdP`, low
    /// enough that a routine key roll propagates within the same
    /// business hour. A failed refresh keeps the previous `KeyStore`, so
    /// verification continues to work as long as one of the
    /// previously-fetched keys matches the inbound token's `kid`.
    ///
    /// Refresh happens on the verify path, not on a timer. A timer needs
    /// a background task, and a background task binds to whichever
    /// runtime spawned it — for a host that initializes on a short-lived
    /// runtime, that task is cancelled before it ever ticks. Refreshing
    /// from a request needs no runtime of its own, and recovers on the
    /// first token that needs the new key rather than at the next tick.
    ///
    /// **`min_refresh_interval_secs`** is the floor between attempts,
    /// default 30. An unknown `kid` triggers a refresh and is reachable
    /// with an unauthenticated request, so without a floor a stream of
    /// invented `kid`s would be an amplification attack pointed at your
    /// own `IdP`. It is deliberately separate from `refresh_secs`:
    /// reusing that as the floor would make a four-second `IdP` blip at
    /// boot cost ten minutes of denial.
    JwksUrl {
        /// The JWKS endpoint.
        url: String,
        #[serde(default)]
        /// Permits plaintext HTTP, for local development only.
        insecure_http: bool,
        #[serde(default = "default_refresh_secs")]
        /// How stale the key set may get before a verify refreshes it.
        refresh_secs: u64,
        #[serde(default = "default_min_refresh_interval_secs")]
        /// Floor between refresh attempts for this issuer.
        min_refresh_interval_secs: u64,
    },

    /// Symmetric HMAC secret (HS256 / HS384 / HS512 only). Not
    /// recommended for production; signature verifiers need the
    /// same secret, which makes key distribution painful.
    Secret {
        /// The shared secret, for HMAC algorithms.
        secret: String,
    },
}

impl DecodingKeySource {
    /// Whether this source needs network I/O to resolve. Used by
    /// `JwtIdentityResolver` to decide between eager (sync) build at
    /// `new()` and deferred (async) build at `Plugin::initialize()`.
    pub fn needs_async(&self) -> bool {
        matches!(self, Self::JwksUrl { .. })
    }

    /// How long this source's keys stay fresh before a verify should
    /// re-fetch them. `Some(_)` for `JwksUrl` (the only refreshable
    /// variant), `None` for inline sources whose key material is
    /// static for the resolver's lifetime — and `None` is also what
    /// tells the verify path not to attempt a refresh at all.
    pub fn refresh_interval(&self) -> Option<std::time::Duration> {
        match self {
            Self::JwksUrl { refresh_secs, .. } => {
                Some(std::time::Duration::from_secs(*refresh_secs))
            },
            _ => None,
        }
    }

    /// Floor between refresh attempts, for sources that can refresh.
    pub fn min_refresh_interval(&self) -> std::time::Duration {
        match self {
            Self::JwksUrl {
                min_refresh_interval_secs,
                ..
            } => std::time::Duration::from_secs(*min_refresh_interval_secs),
            _ => std::time::Duration::MAX,
        }
    }

    /// Synchronously turn the source into a [`KeyStore`]. Works for
    /// inline / on-disk sources; **errors for `JwksUrl`** — use
    /// [`build_async`] for those. Returns a string error so callers
    /// can wrap into `PluginError::Config` with context.
    ///
    /// Inline sources have no `kid` context, so the resulting store
    /// has a single `fallback` entry usable for any token whose
    /// header omits `kid`. Tokens that DO carry a `kid` against an
    /// inline source resolve to `auth.unknown_kid` at verify time —
    /// the JWKS spec is the source of truth for which kids exist.
    ///
    /// [`build_async`]: Self::build_async
    /// # Errors
    ///
    /// Returns a message when the key material does not parse, when a PEM file
    /// cannot be read, or when the source is `jwks_url`, which needs
    /// [`build_async`].
    ///
    /// [`build_async`]: Self::build_async
    pub fn build(&self) -> Result<KeyStore, String> {
        let key = match self {
            Self::Pem { pem } => build_from_pem_bytes(pem.as_bytes(), "inline PEM")?,
            Self::PemFile { path } => {
                let bytes = std::fs::read(path).map_err(|e| {
                    format!("decoding-key file '{}' unreadable: {e}", path.display())
                })?;
                build_from_pem_bytes(&bytes, &format!("file '{}'", path.display()))?
            },
            Self::Jwk { jwk } => build_from_jwk_value(jwk)?,
            Self::JwksUrl { url, .. } => {
                return Err(format!(
                    "JwksUrl source '{url}' requires async resolution — call build_async()"
                ));
            },
            Self::Secret { secret } => DecodingKey::from_secret(secret.as_bytes()),
        };
        Ok(KeyStore::single_fallback(key))
    }

    /// Asynchronously resolve the source into a [`KeyStore`] —
    /// handles every variant including `JwksUrl` (which does an
    /// async HTTP GET against the `IdP`'s JWKS endpoint and indexes
    /// every signature-use key by its `kid`).
    ///
    /// Called from `JwtIdentityResolver::initialize_with()` so the
    /// host's `PolicyEngine` can drive multiple resolvers' JWKS fetches
    /// concurrently via `futures::join_all`, and again from the verify
    /// path when a rotation makes the held keys stale.
    ///
    /// `budget` bounds the fetch, and which one to pass follows from
    /// what is waiting: [`Startup`] at boot, [`RequestPath`] when a
    /// request is blocked on the answer. A timed-out fetch is
    /// [`Recoverable`], so the caller can soft-fail on it.
    ///
    /// [`Startup`]: JwksFetchBudget::Startup
    /// [`RequestPath`]: JwksFetchBudget::RequestPath
    ///
    /// # Errors
    ///
    /// [`Fatal`] when the URL is one the config forbids, when no transport
    /// is installed, or when the plugin lacks `perform_http` — none of which
    /// a later attempt resolves. [`Recoverable`] when the endpoint is
    /// unreachable, answers with a non-success status, or returns a document
    /// with no usable signature key.
    ///
    /// [`Fatal`]: KeySourceError::Fatal
    /// [`Recoverable`]: KeySourceError::Recoverable
    pub async fn build_async(
        &self,
        svc: &dyn HostServices,
        budget: JwksFetchBudget,
    ) -> Result<KeyStore, KeySourceError> {
        match self.fetch_async(svc, budget, None).await? {
            JwksFetch::Fetched { keys, .. } => Ok(keys),
            // Unconditional request, so there was no validator for the
            // peer to match against and `304` is not an answer to
            // anything we asked. Recoverable rather than fatal: it is a
            // misbehaving endpoint, not a misconfigured deployment.
            JwksFetch::NotModified => Err(KeySourceError::Recoverable(
                "JWKS endpoint answered 304 to a request carrying no \
                 If-None-Match; there is nothing it could be unmodified from"
                    .to_owned(),
            )),
        }
    }

    /// Resolve the source, optionally as a conditional request.
    ///
    /// `if_none_match` is the validator of the document the caller
    /// already holds. Sending it turns an unchanged JWKS into a `304`
    /// with no body, which is what makes refreshing on a request path
    /// affordable: the common refresh — keys stale, `IdP` has not
    /// rotated — costs a round trip instead of a document parse.
    ///
    /// `None` requests unconditionally, which is what a boot fetch does
    /// since it holds nothing to compare against.
    ///
    /// # Errors
    ///
    /// [`Fatal`] when the URL is one the config forbids, when no transport
    /// is installed, or when the plugin lacks `perform_http` — none of which
    /// a later attempt resolves. [`Recoverable`] when the endpoint is
    /// unreachable, answers with an unusable status, or returns a document
    /// with no usable signature key.
    ///
    /// [`Fatal`]: KeySourceError::Fatal
    /// [`Recoverable`]: KeySourceError::Recoverable
    pub async fn fetch_async(
        &self,
        svc: &dyn HostServices,
        budget: JwksFetchBudget,
        if_none_match: Option<&str>,
    ) -> Result<JwksFetch, KeySourceError> {
        match self {
            Self::JwksUrl {
                url, insecure_http, ..
            } => {
                // Reject http:// by default. Fetching JWKS over
                // plaintext lets anyone on the network path swap the
                // signing keys and forge JWTs the gateway accepts.
                //
                // Fatal, and decided without touching the network: the
                // URL either satisfies the config or it does not, and an
                // `IdP` that genuinely serves plaintext is reached by
                // setting `insecure_http`, not by retrying.
                require_https(url, *insecure_http).map_err(KeySourceError::Fatal)?;

                // Bounds travel on the request rather than on a
                // client we own: PPE performs no HTTP itself, so the
                // host's transport does the work and only the caller
                // knows what this particular call can afford. Without
                // both bounds a slow or half-open JWKS endpoint hangs
                // `initialize()` indefinitely.
                let req = HttpRequest::get(url)
                    .timeout(budget.timeout())
                    .connect_timeout(JWKS_CONNECT_TIMEOUT)
                    // A ceiling reqwest never gave us. The document is
                    // a few kilobytes; anything approaching this is a
                    // hostile or broken endpoint, and buffering it
                    // would be the whole point of the limit.
                    .max_response_bytes(JWKS_MAX_BYTES);

                // An unusable validator is dropped rather than failing the
                // fetch. The worst that costs is a full document, whereas
                // refusing to refresh over a header the peer itself gave
                // us would be the more expensive mistake.
                let req = match if_none_match {
                    None => req,
                    Some(validator) => match req.clone().header("if-none-match", validator) {
                        Ok(conditional) => conditional,
                        Err(e) => {
                            tracing::debug!(
                                url = %url,
                                error = %e,
                                "dropping an unusable ETag; refetching in full"
                            );
                            req
                        },
                    },
                };

                let resp = svc.http_request(req, budget.retry()).await.map_err(|e| {
                    let msg = format!("JWKS GET {url} failed: {e}");
                    match e {
                        // No transport wired, or `perform_http` not
                        // granted. The call never left the process and
                        // never will until someone changes config or
                        // host wiring, so this must not look like an
                        // `IdP` that might come back.
                        HttpRequestError::Unavailable(_) => KeySourceError::Fatal(msg),
                        // The transport ran and the call failed.
                        HttpRequestError::Transport(_) => KeySourceError::Recoverable(msg),
                    }
                })?;

                // Before the 2xx check, not after: `304` sits outside the
                // 2xx range, so the reflexive `!is_success()` below would
                // turn every successful revalidation into a fetch failure
                // — and for this plugin that failure is fail-closed.
                if resp.is_not_modified() {
                    return Ok(JwksFetch::NotModified);
                }

                if !resp.is_success() {
                    return Err(KeySourceError::Recoverable(format!(
                        "JWKS GET {url} returned non-2xx: {}",
                        resp.status
                    )));
                }

                // Read before the body is consumed below.
                let etag = resp.etag().map(ToOwned::to_owned);

                // An `IdP` mid-rotation can transiently serve a document
                // we cannot read, so a body we cannot parse is the `IdP`
                // being unhelpful now rather than a settled fault.
                let body = std::str::from_utf8(&resp.body).map_err(|e| {
                    KeySourceError::Recoverable(format!("JWKS GET {url} body is not UTF-8: {e}"))
                })?;

                let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_str(body).map_err(|e| {
                    KeySourceError::Recoverable(format!("JWKS {url} body is not a JWKSet: {e}"))
                })?;

                // Iterate every signature-use key (or every key, if
                // none declared `use: sig`) and index by `kid`.
                // OIDC spec requires JWKS entries to carry a `kid`;
                // any entry missing one is dropped with a clear
                // diagnostic appended to the error string. If NO
                // usable keys remain, treat that as a config error.
                let mut entries: Vec<(String, DecodingKey)> = Vec::new();
                let mut skipped_no_kid: usize = 0;
                let mut skipped_unusable: Vec<String> = Vec::new();
                for k in &jwks.keys {
                    // Filter to sig-use when the IdP labels it; if no
                    // key declares `use`, accept everything (some
                    // older IdPs publish JWKS without the field).
                    let use_field = k.common.public_key_use.as_ref();
                    if use_field
                        .map(|u| *u != jsonwebtoken::jwk::PublicKeyUse::Signature)
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let kid = match k.common.key_id.as_deref() {
                        Some(kid) if !kid.is_empty() => kid.to_owned(),
                        _ => {
                            skipped_no_kid += 1;
                            continue;
                        },
                    };
                    match DecodingKey::from_jwk(k) {
                        Ok(key) => entries.push((kid, key)),
                        Err(e) => skipped_unusable.push(format!("{kid}: {e}")),
                    }
                }
                if entries.is_empty() {
                    // Recoverable, though it reads like a config fault: an
                    // `IdP` mid-rotation can briefly publish a document we
                    // cannot index, and that fixes itself.
                    return Err(KeySourceError::Recoverable(format!(
                        "JWKS at {url} contained no usable signature keys \
                         (skipped {skipped_no_kid} entries with no kid; \
                         {} entries failed to parse: [{}])",
                        skipped_unusable.len(),
                        skipped_unusable.join(", "),
                    )));
                }
                Ok(JwksFetch::Fetched {
                    keys: KeyStore::from_jwks_entries(entries),
                    etag,
                })
            },
            // Non-network variants delegate to the sync path; they
            // don't await anything, so the cost is zero vs. a direct
            // sync call. Every way they fail is a key that does not
            // parse or a file that cannot be read, which no retry fixes.
            // No validator either: an inline key has no document behind
            // it to revalidate.
            other => other
                .build()
                .map(|keys| JwksFetch::Fetched { keys, etag: None })
                .map_err(KeySourceError::Fatal),
        }
    }
}

/// Ceiling on a JWKS response body.
///
/// A JWKS document runs to single-digit kilobytes even for an `IdP`
/// mid-rotation with several overlapping keys. `256 KiB` is far above any
/// legitimate set and far below what would trouble the process, so a
/// hostile or broken endpoint streaming without end is refused rather
/// than buffered. `reqwest` applied no limit here at all.
const JWKS_MAX_BYTES: usize = 256 * 1024;

/// Overall request timeout on the JWKS HTTP GET (includes connect +
/// TLS + response body). 5s is a forgiving upper bound for a healthy
/// `IdP`; anything slower than that is operationally indistinguishable
/// from "JWKS is down."
const JWKS_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// TCP-connect timeout for the JWKS HTTP GET. Separate from the
/// overall timeout so a hostile JWKS endpoint that accepts the
/// connection and then stalls on the response still fails fast.
const JWKS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Overall request timeout for a JWKS fetch a request is waiting on.
///
/// Tighter than [`JWKS_FETCH_TIMEOUT`] because the thing waiting is
/// different. At startup a slow `IdP` delays a boot, which is visible in
/// a deploy and recovers by itself. On the verify path it *is* the
/// request's latency, paid by a caller who asked to authenticate, not to
/// wait on an `IdP` handshake.
const JWKS_REQUEST_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How much wall clock a JWKS fetch may spend, and how hard it may retry.
///
/// Not a tuning preference: the two callers have genuinely different
/// things waiting on them, so they get different bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwksFetchBudget {
    /// The boot fetch. Three attempts at five seconds each, with no
    /// ceiling on the loop, because nothing is waiting on it except
    /// startup and a failure here soft-fails anyway.
    Startup,

    /// A refresh driven by a request already in flight. One attempt at
    /// two seconds, so the worst case a request can inherit is that one
    /// number.
    ///
    /// Retrying within the call is deliberately not done. The retry loop
    /// that matters here is the next request: a refresh that fails leaves
    /// the previous keys in place, and the following verify tries again
    /// once the `min_refresh_interval_secs` floor has passed. Retrying
    /// in-call would multiply one request's latency to buy a retry that
    /// arrives anyway.
    ///
    /// [`RetryPolicy::with_total_budget`] alone would not achieve this.
    /// It stops the loop *starting* another attempt; it never shortens
    /// the attempt already running, so the per-attempt timeout is what
    /// actually bounds a single fetch.
    RequestPath,
}

impl JwksFetchBudget {
    /// The overall deadline for one attempt.
    const fn timeout(self) -> std::time::Duration {
        match self {
            Self::Startup => JWKS_FETCH_TIMEOUT,
            Self::RequestPath => JWKS_REQUEST_FETCH_TIMEOUT,
        }
    }

    /// How the fetch retries.
    ///
    /// A JWKS fetch is a `GET` with no side effect, so it is safe to
    /// repeat — including after a timeout, where a non-idempotent call
    /// would have to stop and treat the outcome as unknown.
    const fn retry(self) -> RetryPolicy {
        match self {
            Self::Startup => RetryPolicy::idempotent(),
            Self::RequestPath => RetryPolicy::idempotent()
                .with_max_attempts(1)
                .with_total_budget(JWKS_REQUEST_FETCH_TIMEOUT),
        }
    }
}

/// PEM helper used by both `Pem` and `PemFile`. Tries RSA, then EC,
/// then `EdDSA` — covers the algorithms `jsonwebtoken` supports.
fn build_from_pem_bytes(bytes: &[u8], origin: &str) -> Result<DecodingKey, String> {
    DecodingKey::from_rsa_pem(bytes)
        .or_else(|_| DecodingKey::from_ec_pem(bytes))
        .or_else(|_| DecodingKey::from_ed_pem(bytes))
        .map_err(|e| format!("{origin} PEM key failed to parse: {e}"))
}

fn build_from_jwk_value(jwk: &serde_json::Value) -> Result<DecodingKey, String> {
    let parsed: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(jwk.clone()).map_err(|e| format!("JWK is not well-formed: {e}"))?;
    DecodingKey::from_jwk(&parsed).map_err(|e| format!("JWK not usable: {e}"))
}

/// What a JWKS fetch came back with.
///
/// The `304` case is the reason this is not just a `KeyStore`. A
/// conditional refresh against an `IdP` that has not rotated returns no
/// document at all, and that is a success — the keys already held are
/// confirmed current. Collapsing it into an error would make the cheap,
/// common refresh look like a failed one.
#[derive(Debug)]
pub enum JwksFetch {
    /// The peer sent a document.
    Fetched {
        /// Keys indexed by `kid`.
        keys: KeyStore,
        /// The document's `ETag`, when the peer sent one. Feed it back
        /// as `If-None-Match` to make the next refresh a round trip.
        etag: Option<String>,
    },
    /// The peer answered `304`: what the caller holds is current.
    NotModified,
}

/// Why resolving a key source failed.
///
/// The split is not "our fault vs. theirs" but **whether waiting can fix
/// it**, because that is what decides whether booting anyway is safe.
///
/// [`Fatal`] is settled before any request leaves the process and stays
/// settled until a human edits something: a `jwks_url` the config
/// forbids, a host that wired no transport, a `perform_http` that was
/// never granted. Soft-failing one of these boots a gateway that denies
/// every token from the issuer for the life of the process, and the
/// `auth.jwks_unavailable` it denies with sends the operator to an `IdP`
/// that was never contacted.
///
/// [`Recoverable`] is the `IdP` being unreachable or unhelpful right
/// now. That is what the soft-fail design exists for: the gateway boots,
/// and the first verify that needs a key tries again.
///
/// [`Fatal`]: KeySourceError::Fatal
/// [`Recoverable`]: KeySourceError::Recoverable
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySourceError {
    /// A misconfiguration or missing host wiring. No retry resolves it.
    Fatal(String),
    /// The fetch ran and did not yield usable keys. A later one may.
    Recoverable(String),
}

impl KeySourceError {
    /// Whether initialization must fail rather than soft-fail.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Fatal(_))
    }

    /// Prefix the message, keeping the variant.
    ///
    /// The variant is the part callers act on, so it has to survive
    /// having context added — the reason this is not `map_err` onto a
    /// `String` the way it used to be.
    #[must_use]
    fn context(self, prefix: &str) -> Self {
        match self {
            Self::Fatal(m) => Self::Fatal(format!("{prefix}: {m}")),
            Self::Recoverable(m) => Self::Recoverable(format!("{prefix}: {m}")),
        }
    }
}

impl std::fmt::Display for KeySourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fatal(m) | Self::Recoverable(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for KeySourceError {}

impl TrustedIssuerConfig {
    /// Validate shape (non-empty issuer, at least one algorithm)
    /// without resolving the key. Used at construction time as a
    /// fast-fail gate so misshapen YAML is rejected before any
    /// network I/O is attempted.
    /// # Errors
    ///
    /// Returns a message when `issuer` is empty or `algorithms` is empty. An
    /// issuer with no accepted algorithm can verify nothing, so it is rejected
    /// here rather than failing every token later.
    pub fn validate(&self) -> Result<(), String> {
        if self.issuer.trim().is_empty() {
            return Err("trusted_issuer.issuer must be non-empty".into());
        }
        if self.algorithms.is_empty() {
            return Err(format!(
                "trusted_issuer '{}' must list at least one algorithm",
                self.issuer
            ));
        }
        Ok(())
    }

    /// Synchronously build a runtime `TrustedIssuer`. Works for
    /// inline / on-disk `decoding_key` sources; **errors when
    /// `decoding_key.kind == jwks_url`** — use [`build_async`] for
    /// those.
    ///
    /// [`build_async`]: Self::build_async
    /// # Errors
    ///
    /// Returns a message when [`Self::validate`] rejects the shape, or when the
    /// decoding key cannot be built. A `jwks_url` source needs
    /// [`build_async`] instead.
    ///
    /// [`build_async`]: Self::build_async
    pub fn build(self) -> Result<TrustedIssuer, String> {
        self.validate()?;
        let keys = self.decoding_key.build().map_err(|e| {
            format!(
                "trusted_issuer '{}' decoding_key build failed: {e}",
                self.issuer
            )
        })?;
        Ok(TrustedIssuer {
            issuer: self.issuer,
            audiences: self.audiences,
            keys: std::sync::Arc::new(std::sync::RwLock::new(keys)),
            algorithms: self.algorithms,
            leeway_seconds: self.leeway_seconds,
            source: self.decoding_key,
            refresh: crate::trusted_issuer::RefreshGate::default(),
        })
    }

    /// Asynchronously build a `TrustedIssuer`, handling every
    /// `decoding_key` variant including `JwksUrl`. Called from
    /// `JwtIdentityResolver::initialize_with()` for sources that
    /// deferred resolution past construction.
    /// # Errors
    ///
    /// [`Fatal`] when [`Self::validate`] rejects the shape, since a
    /// misshapen issuer verifies nothing no matter how often it is retried.
    /// Otherwise whatever [`DecodingKeySource::build_async`] classified it as.
    ///
    /// [`Fatal`]: KeySourceError::Fatal
    pub async fn build_async(
        self,
        svc: &dyn HostServices,
        budget: JwksFetchBudget,
    ) -> Result<TrustedIssuer, KeySourceError> {
        self.validate().map_err(KeySourceError::Fatal)?;
        // Unconditional: a boot fetch holds no document to revalidate
        // against. The validator it comes back with is kept, so the
        // *first* refresh after boot can already be conditional.
        let fetched = self
            .decoding_key
            .fetch_async(svc, budget, None)
            .await
            .map_err(|e| e.context(&format!("trusted_issuer '{}'", self.issuer)))?;
        let (keys, etag) = match fetched {
            JwksFetch::Fetched { keys, etag } => (keys, etag),
            JwksFetch::NotModified => {
                return Err(KeySourceError::Recoverable(format!(
                    "trusted_issuer '{}': JWKS endpoint answered 304 to a \
                     request carrying no If-None-Match",
                    self.issuer
                )));
            },
        };
        let refresh = crate::trusted_issuer::RefreshGate::default();
        refresh.set_etag(etag);
        Ok(TrustedIssuer {
            issuer: self.issuer,
            audiences: self.audiences,
            keys: std::sync::Arc::new(std::sync::RwLock::new(keys)),
            algorithms: self.algorithms,
            leeway_seconds: self.leeway_seconds,
            source: self.decoding_key,
            refresh,
        })
    }
}

/// Reject `http://` URLs for endpoints that carry trust-establishing
/// material. `https://` is always allowed; `http://` is allowed only
/// when `insecure_http` is `true`. Anything else (missing scheme,
/// data URLs, ...) returns Ok and lets the underlying parser surface
/// its own error.
fn require_https(url: &str, insecure_http: bool) -> Result<(), String> {
    let lowered = url.trim_start().to_ascii_lowercase();
    if lowered.starts_with("https://") {
        return Ok(());
    }
    if lowered.starts_with("http://") {
        if insecure_http {
            return Ok(());
        }
        return Err(format!(
            "JWKS URL must use https:// (got '{url}'). Set `insecure_http: true` \
             to allow plaintext for localhost/dev only — never production."
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::http_testing::{FakeTransport, granting};
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn jwks_https_accepted() {
        require_https("https://idp.example/realms/x/jwks", false).unwrap();
    }

    #[test]
    fn jwks_http_rejected_by_default() {
        let err = require_https("http://localhost:8081/jwks", false).unwrap_err();
        assert!(err.contains("https"), "{}", err);
        assert!(err.contains("insecure_http"), "{}", err);
    }

    #[test]
    fn jwks_http_with_explicit_opt_in_allowed() {
        require_https("http://localhost:8081/jwks", true).unwrap();
    }

    #[tokio::test]
    async fn jwks_http_url_rejected_at_build_async() {
        let src = DecodingKeySource::JwksUrl {
            url: "http://idp.example/jwks".into(),
            insecure_http: false,
            refresh_secs: 3600,
            min_refresh_interval_secs: 30,
        };
        // The scheme guard runs before any request is issued, so the
        // transport is never asked for anything — asserting that is the
        // point: a plaintext JWKS URL must not reach the network at all.
        let http = Arc::new(FakeTransport::new());
        match src
            .build_async(&granting(Arc::clone(&http)), JwksFetchBudget::Startup)
            .await
        {
            // Fatal, not recoverable: retrying a URL the config forbids
            // gets the same answer forever, so a deployment must not boot
            // on it and deny every token from the issuer instead.
            Err(e) => {
                assert!(e.is_fatal(), "a forbidden scheme is not recoverable: {e}");
                assert!(e.to_string().contains("https"), "{e}");
            },
            Ok(_) => panic!("http:// JWKS URL must not build by default"),
        }
        assert_eq!(
            http.call_count(),
            0,
            "a rejected scheme must not produce a request"
        );
    }

    #[test]
    fn decoding_key_source_secret_builds() {
        let src = DecodingKeySource::Secret {
            secret: "test-secret".into(),
        };
        src.build().unwrap();
    }

    #[test]
    fn decoding_key_source_pem_rejects_garbage() {
        // `DecodingKey` doesn't implement Debug (it carries key
        // material), so `expect_err` won't compile here — match
        // the Err arm directly instead.
        let src = DecodingKeySource::Pem {
            pem: "not actually pem".into(),
        };
        match src.build() {
            Err(msg) => assert!(msg.contains("failed to parse")),
            Ok(_) => panic!("garbage PEM should have failed"),
        }
    }

    #[test]
    fn config_deserializes_from_json() {
        // The shape operators write in unified-config YAML, just
        // serialized as JSON for the test.
        let raw = json!({
            "trusted_issuers": [{
                "issuer": "https://idp.example.com",
                "audiences": ["my-api"],
                "algorithms": ["HS256"],
                "decoding_key": {
                    "kind": "secret",
                    "secret": "test-secret",
                },
                "leeway_seconds": 30,
            }],
            "claim_mapper": "standard",
        });
        let cfg: JwtIdentityResolverConfig = serde_json::from_value(raw).unwrap();
        assert_eq!(cfg.trusted_issuers.len(), 1);
        assert_eq!(cfg.trusted_issuers[0].issuer, "https://idp.example.com");
        assert_eq!(cfg.claim_mapper.as_deref(), Some("standard"));
    }

    // ---- JWKS documents the IdP might actually serve -----------------------
    //
    // The e2e tests all serve a well-formed JWKS with a valid `kid`, so every
    // rejection path was dark. These are the ones that decide whether a
    // misconfigured or hostile endpoint fails loudly at startup or leaves the
    // resolver holding no usable key, and the message has to say which it was.

    /// The rejection message, having first asserted the rejection is
    /// [`KeySourceError::Recoverable`].
    ///
    /// Every caller below feeds a bad answer from a reachable endpoint,
    /// which is the `IdP` being unhelpful now rather than a settled
    /// fault. Classifying one of them `Fatal` would refuse to boot the
    /// gateway over an `IdP` hiccup, so the classification is checked
    /// here rather than left to whichever test remembers to.
    async fn jwks_err(body: &str, status: u16) -> String {
        let http = Arc::new(FakeTransport::new().json("/jwks", status, body));
        let src = DecodingKeySource::JwksUrl {
            url: "https://idp.example/jwks".into(),
            insecure_http: false,
            refresh_secs: 3600,
            min_refresh_interval_secs: 30,
        };
        match src
            .build_async(&granting(Arc::clone(&http)), JwksFetchBudget::Startup)
            .await
        {
            Ok(_) => panic!("this JWKS document must be rejected"),
            Err(e @ KeySourceError::Fatal(_)) => {
                panic!("a reachable endpoint answering badly is recoverable, got fatal: {e}")
            },
            Err(e) => e.to_string(),
        }
    }

    /// One well-formed RSA signature key. Built as a `Value` so the tests below
    /// can vary a single field structurally; a string replace on serialized JSON
    /// is too easy to get silently wrong, and a replace that misses turns a
    /// rejection test into a no-op that still passes.
    fn rsa_jwk() -> serde_json::Value {
        json!({
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
        })
    }

    fn jwks_of(keys: Vec<serde_json::Value>) -> String {
        json!({ "keys": keys }).to_string()
    }

    #[tokio::test]
    async fn a_well_formed_jwks_is_accepted() {
        // Positive control: without it, every negative test below could be
        // passing for the wrong reason.
        let http = Arc::new(FakeTransport::new().json("/jwks", 200, &jwks_of(vec![rsa_jwk()])));
        let src = DecodingKeySource::JwksUrl {
            url: "https://idp.example/jwks".into(),
            insecure_http: false,
            refresh_secs: 3600,
            min_refresh_interval_secs: 30,
        };
        assert!(
            src.build_async(&granting(Arc::clone(&http)), JwksFetchBudget::Startup)
                .await
                .is_ok(),
            "a valid JWKS must build"
        );

        // The bounds are the caller's to choose, and a regression that
        // dropped them would be invisible against a healthy endpoint.
        let req = http.last_request().expect("one request was issued");
        assert_eq!(req.timeout, JWKS_FETCH_TIMEOUT);
        assert_eq!(req.connect_timeout, Some(JWKS_CONNECT_TIMEOUT));
        assert_eq!(req.max_response_bytes, JWKS_MAX_BYTES);
    }

    #[tokio::test]
    async fn a_non_2xx_jwks_response_is_rejected() {
        let e = jwks_err(r#"{"keys":[]}"#, 500).await;
        assert!(e.contains("non-2xx"), "{e}");
    }

    #[tokio::test]
    async fn a_jwks_body_that_is_not_a_jwkset_is_rejected() {
        let e = jwks_err("not json at all", 200).await;
        assert!(e.contains("not a JWKSet"), "{e}");
    }

    /// An empty key set is the case most likely to slip past: the document
    /// parses, the fetch succeeds, and the resolver would hold nothing.
    #[tokio::test]
    async fn an_empty_jwks_is_rejected_rather_than_accepted_empty() {
        let e = jwks_err(r#"{"keys":[]}"#, 200).await;
        assert!(e.contains("no usable signature keys"), "{e}");
    }

    /// Encryption keys are filtered out, so a JWKS carrying only `use: enc`
    /// leaves nothing to verify with. The count in the message is what tells an
    /// operator the keys were present but skipped.
    #[tokio::test]
    async fn a_jwks_with_only_encryption_keys_is_rejected() {
        let mut k = rsa_jwk();
        k["use"] = json!("enc");
        let e = jwks_err(&jwks_of(vec![k]), 200).await;
        assert!(e.contains("no usable signature keys"), "{e}");
    }

    /// OIDC requires a `kid`. An entry without one is dropped, and the tally has
    /// to appear in the error or the operator cannot tell this case from an
    /// empty document.
    #[tokio::test]
    async fn a_key_with_no_kid_is_skipped_and_counted() {
        let mut k = rsa_jwk();
        k.as_object_mut().unwrap().remove("kid");
        let e = jwks_err(&jwks_of(vec![k]), 200).await;
        assert!(
            e.contains("skipped 1 entries with no kid"),
            "the message must count the dropped entries: {e}"
        );
    }

    /// A key that has a `kid` but unusable material is reported by `kid`, which
    /// is the only handle an operator has to find it in their `IdP`.
    #[tokio::test]
    async fn an_unusable_key_is_reported_by_its_kid() {
        let mut k = rsa_jwk();
        k["kid"] = json!("broken-key");
        k["n"] = json!("!!!not-base64!!!");
        let e = jwks_err(&jwks_of(vec![k]), 200).await;
        assert!(
            e.contains("broken-key"),
            "the message must name the offending kid: {e}"
        );
    }

    // ---- the other key sources --------------------------------------------

    /// `JwksUrl` cannot be resolved synchronously, and the error says which call
    /// to use instead. Anything else would be a confusing failure at startup.
    #[test]
    fn a_jwks_url_rejects_the_synchronous_build_and_points_at_build_async() {
        let src = DecodingKeySource::JwksUrl {
            url: "https://idp.example/jwks".into(),
            insecure_http: false,
            refresh_secs: 3600,
            min_refresh_interval_secs: 30,
        };
        let Err(e) = src.build() else {
            panic!("JwksUrl must not resolve synchronously")
        };
        assert!(e.contains("build_async()"), "{e}");
    }

    #[test]
    fn an_unreadable_pem_file_names_the_path() {
        let src = DecodingKeySource::PemFile {
            path: std::path::PathBuf::from("/nonexistent/ppe-test/key.pem"),
        };
        let Err(e) = src.build() else {
            panic!("a missing file must not build")
        };
        assert!(e.contains("unreadable"), "{e}");
        assert!(e.contains("key.pem"), "the message must name the file: {e}");
    }

    #[test]
    fn a_malformed_jwk_value_is_rejected() {
        let src = DecodingKeySource::Jwk {
            jwk: json!({ "kty": "RSA", "n": "!!!", "e": "AQAB" }),
        };
        assert!(src.build().is_err(), "a malformed JWK must not build");
    }

    /// Only `JwksUrl` refreshes. A non-zero interval on any other source would
    /// start a refresh loop with nothing to re-fetch.
    #[test]
    fn only_a_jwks_url_declares_a_refresh_interval() {
        let jwks = DecodingKeySource::JwksUrl {
            url: "https://idp.example/jwks".into(),
            insecure_http: false,
            refresh_secs: 900,
            min_refresh_interval_secs: 30,
        };
        assert_eq!(
            jwks.refresh_interval(),
            Some(std::time::Duration::from_secs(900))
        );
        for src in [
            DecodingKeySource::Secret { secret: "s".into() },
            DecodingKeySource::Pem { pem: "x".into() },
            DecodingKeySource::Jwk { jwk: json!({}) },
        ] {
            assert!(
                src.refresh_interval().is_none(),
                "{src:?} must not declare a refresh interval"
            );
        }
    }

    /// An issuer with no `issuer` string cannot be matched against a token's
    /// `iss`, so it is refused at config time rather than never matching.
    #[test]
    fn an_empty_issuer_is_rejected() {
        let cfg = TrustedIssuerConfig {
            issuer: String::new(),
            audiences: vec!["a".to_owned()],
            algorithms: vec![Algorithm::HS256],
            decoding_key: DecodingKeySource::Secret { secret: "s".into() },
            leeway_seconds: 0,
        };
        let Err(e) = cfg.validate() else {
            panic!("an empty issuer must not validate")
        };
        assert!(e.contains("issuer"), "{e}");
    }
}
