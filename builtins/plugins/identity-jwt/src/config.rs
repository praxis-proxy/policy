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

use praxis_policy_core::host::HostServices;
use praxis_policy_core::http::HttpRequest;
use praxis_policy_core::http_retry::RetryPolicy;

use super::trusted_issuer::{KeyStore, TrustedIssuer};

/// Top-level plugin config — what operators write under
/// `plugins[<name>].config:` in unified-config YAML.
///
/// One instance of this plugin handles ONE inbound credential
/// (one header, one role). Wire multiple instances if a deployment
/// expects multiple inbound tokens — e.g. user JWT in
/// `X-User-Token`, OAuth client token in `Authorization`, and a
/// SPIFFE JWT-SVID in `X-Workload-Token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Which claim mapper to use. `"standard"` is the OIDC default;
    /// future named mappers (e.g., `"keycloak"`, `"cognito"`) plug
    /// in via the registry pattern in `resolver.rs`. Omitted →
    /// `StandardClaimMap`.
    #[serde(default)]
    pub claim_mapper: Option<String>,
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
    /// at plugin `initialize()` and re-fetched every `refresh_secs`
    /// thereafter so `IdP` key rolls don't require a gateway
    /// restart. Each fetched signature-use key is indexed by its
    /// `kid` so the verify path can select the right one per
    /// token (overlapping rotation windows work).
    ///
    /// **`insecure_http`** defaults to `false` — `build_async`
    /// rejects `http://` URLs. With JWKS over plaintext, anyone on
    /// the network path can swap the key material and forge JWTs
    /// the gateway accepts. Set to `true` only for `http://localhost`
    /// docker-compose development; production must always use https.
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

    /// How often the background refresh task should re-fetch this
    /// source. `Some(_)` for `JwksUrl` (the only refreshable
    /// variant), `None` for inline sources whose key material is
    /// static for the resolver's lifetime.
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
    /// Called from `JwtIdentityResolver::initialize()` so the host's
    /// `PolicyEngine` can drive multiple resolvers' JWKS fetches
    /// concurrently via `futures::join_all`.
    ///
    /// The fetch is bounded by `JWKS_FETCH_TIMEOUT` to prevent a
    /// slow or hostile JWKS endpoint from hanging gateway startup
    /// indefinitely. A timed-out fetch surfaces as an error string
    /// the caller can soft-fail on.
    ///
    /// **v0 caveat:**
    ///
    /// * No automatic rotation — the store is bound at initialize
    ///   time. A background refresh task keeps `IdP` key
    ///   rolls from requiring a gateway restart.
    /// # Errors
    ///
    /// Returns a message when the JWKS endpoint is unreachable, answers with a
    /// non-success status, or returns a document with no usable signature key.
    pub async fn build_async(&self, svc: &dyn HostServices) -> Result<KeyStore, String> {
        match self {
            Self::JwksUrl {
                url, insecure_http, ..
            } => {
                // Reject http:// by default. Fetching JWKS over
                // plaintext lets anyone on the network path swap the
                // signing keys and forge JWTs the gateway accepts.
                require_https(url, *insecure_http)?;

                // Bounds travel on the request rather than on a
                // client we own: PPE performs no HTTP itself, so the
                // host's transport does the work and only the caller
                // knows what this particular call can afford. Without
                // both bounds a slow or half-open JWKS endpoint hangs
                // `initialize()` indefinitely.
                let req = HttpRequest::get(url)
                    .timeout(JWKS_FETCH_TIMEOUT)
                    .connect_timeout(JWKS_CONNECT_TIMEOUT)
                    // A ceiling reqwest never gave us. The document is
                    // a few kilobytes; anything approaching this is a
                    // hostile or broken endpoint, and buffering it
                    // would be the whole point of the limit.
                    .max_response_bytes(JWKS_MAX_BYTES);

                // A JWKS fetch is a `GET` with no side effect, so it is
                // safe to repeat — including after a timeout, where a
                // non-idempotent call would have to stop and treat the
                // outcome as unknown.
                let resp = svc
                    .http_request(req, RetryPolicy::idempotent())
                    .await
                    .map_err(|e| format!("JWKS GET {url} failed: {e}"))?;

                if !resp.is_success() {
                    return Err(format!("JWKS GET {url} returned non-2xx: {}", resp.status));
                }

                let body = std::str::from_utf8(&resp.body)
                    .map_err(|e| format!("JWKS GET {url} body is not UTF-8: {e}"))?;

                let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_str(body)
                    .map_err(|e| format!("JWKS {url} body is not a JWKSet: {e}"))?;

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
                    return Err(format!(
                        "JWKS at {url} contained no usable signature keys \
                         (skipped {skipped_no_kid} entries with no kid; \
                         {} entries failed to parse: [{}])",
                        skipped_unusable.len(),
                        skipped_unusable.join(", "),
                    ));
                }
                Ok(KeyStore::from_jwks_entries(entries))
            },
            // Non-network variants delegate to the sync path; they
            // don't await anything, so the cost is zero vs. a direct
            // sync call.
            other => other.build(),
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
    /// `JwtIdentityResolver::initialize()` for sources that deferred
    /// resolution past construction.
    /// # Errors
    ///
    /// Returns a message when [`Self::validate`] rejects the shape, or when the
    /// decoding key cannot be fetched or parsed.
    pub async fn build_async(self, svc: &dyn HostServices) -> Result<TrustedIssuer, String> {
        self.validate()?;
        let keys = self.decoding_key.build_async(svc).await.map_err(|e| {
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
        assert!(require_https("https://idp.example/realms/x/jwks", false).is_ok());
    }

    #[test]
    fn jwks_http_rejected_by_default() {
        let err = require_https("http://localhost:8081/jwks", false).unwrap_err();
        assert!(err.contains("https"), "{}", err);
        assert!(err.contains("insecure_http"), "{}", err);
    }

    #[test]
    fn jwks_http_with_explicit_opt_in_allowed() {
        assert!(require_https("http://localhost:8081/jwks", true).is_ok());
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
        match src.build_async(&granting(Arc::clone(&http))).await {
            Err(e) => assert!(e.contains("https"), "{}", e),
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
        assert!(src.build().is_ok());
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

    async fn jwks_err(body: &str, status: u16) -> String {
        let http = Arc::new(FakeTransport::new().json("/jwks", status, body));
        let src = DecodingKeySource::JwksUrl {
            url: "https://idp.example/jwks".into(),
            insecure_http: false,
            refresh_secs: 3600,
            min_refresh_interval_secs: 30,
        };
        match src.build_async(&granting(Arc::clone(&http))).await {
            Ok(_) => panic!("this JWKS document must be rejected"),
            Err(e) => e,
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
            src.build_async(&granting(Arc::clone(&http))).await.is_ok(),
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
