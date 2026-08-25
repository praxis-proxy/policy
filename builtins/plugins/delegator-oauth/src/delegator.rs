// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `OAuthDelegator` — `HookHandler<TokenDelegateHook>` that performs
// RFC 8693 OAuth 2.0 Token Exchange against the configured IdP.
//
// # Flow
//
//   1. Read `payload.bearer_token()` (caller's current credential)
//      and `payload.target_audience()` / `required_permissions()` /
//      `route_attenuation` (the narrowing config).
//   2. Build the form-encoded body per RFC 8693:
//        grant_type=urn:ietf:params:oauth:grant-type:token-exchange
//        subject_token=<caller_token>
//        subject_token_type=<configured>
//        audience=<target>
//        scope=<space-separated requested scopes>
//        actor_token=<workload SVID>       (only if payload carries one)
//        actor_token_type=<configured>     (only if actor_token sent)
//   3. POST to the IdP's token endpoint with HTTP Basic auth
//      (client_id / client_secret).
//   4. Parse the JSON response: `{ access_token, token_type,
//      expires_in, scope, issued_token_type }`.
//   5. Construct a `RawDelegatedToken` with the minted credential +
//      computed expiry + effective scopes.
//   6. Return updated payload via `PluginResult::modify_payload`.
//
// # Error handling
//
// Construction errors → `Box<PluginError>` (`PluginError::Config`).
// Runtime errors → `PluginResult::deny(PluginViolation::new(code,
// reason))`:
//   * `delegation.idp_unreachable` — network failure
//   * `delegation.idp_timeout` — exceeded `timeout_seconds`
//   * `delegation.idp_rejected` — IdP returned 4xx/5xx
//   * `delegation.bad_response` — response not valid JSON or
//                                 missing required fields
//   * `delegation.scope_too_broad` — IdP returned a token whose
//                                    scopes don't include all
//                                    requested permissions

use std::borrow::Cow;

use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use zeroize::Zeroizing;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::delegation::{DelegationPayload, DelegationSubject, TokenDelegateHook};
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::extensions::raw_credentials::RawDelegatedToken;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::host::{HostServices, HttpRequestError};
use praxis_policy_core::http::{HttpRequest, HttpTransportError, form_urlencode};
use praxis_policy_core::http_retry::RetryPolicy;
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use super::cache::key::{CacheKey, DelegatorIdentity, derive as derive_cache_key};
use super::cache::store::{DelegatedTokenCache, Mint, Served, Source};
use super::config::OAuthDelegatorConfig;

/// RFC 8693 token-exchange grant type — the value of
/// `grant_type` in the form-encoded request body.
const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 6749 §4.4 client-credentials grant — "give me a token as
/// myself". Used when the delegation subject is `this_workload` (this
/// PPE instance itself): there is no inbound credential to exchange,
/// and its identity is the OAuth client identity it already
/// authenticates with.
const GRANT_TYPE_CLIENT_CREDENTIALS: &str = "client_credentials";

/// Default issued-token-type RFC 8693 returns. We don't rely on it
/// for behavior — it's reported back to operators in audit logs
/// only.
const DEFAULT_ISSUED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Ceiling on a token-endpoint response body.
///
/// A token response is a small JSON object — an access token, a type, an
/// expiry, a scope list. `64 KiB` is far above any legitimate one, and the
/// bound exists because a compromised or broken endpoint would otherwise
/// stream until the process died. `reqwest` applied no limit here.
const TOKEN_RESPONSE_MAX_BYTES: usize = 64 * 1024;

/// OAuth-mediated `TokenDelegate` handler.
pub struct OAuthDelegator {
    cfg: PluginConfig,
    typed: OAuthDelegatorConfig,
    /// Loaded client secret, zeroized on drop.
    client_secret: Zeroizing<String>,
    /// Overall deadline for one token-endpoint call, from config.
    /// The transport itself is the host's and arrives per request.
    timeout: std::time::Duration,
    /// Latches once the best-effort "actor requested but no `act` minted"
    /// warning has fired, so it logs at most once per delegator instead of
    /// on every request (and skips the per-request JWT decode thereafter).
    warned_missing_act: std::sync::atomic::AtomicBool,
    /// Live delegated tokens, when the operator enabled reuse.
    ///
    /// `None` rather than a cache that always misses, so a delegator
    /// with caching off runs the same code it ran before the cache
    /// existed rather than a disabled version of the new code.
    cache: Option<DelegatedTokenCache>,
}

impl std::fmt::Debug for OAuthDelegator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthDelegator")
            .field("cfg", &self.cfg.name)
            .field("token_endpoint", &self.typed.token_endpoint)
            .field("client_id", &self.typed.client_id)
            .field("client_secret", &"<elided>")
            .finish()
    }
}

impl OAuthDelegator {
    /// Build a delegator from a `PluginConfig`. Reads `cfg.config`
    /// into [`OAuthDelegatorConfig`], resolves the client secret,
    /// constructs the shared `reqwest::Client`.
    /// # Errors
    ///
    /// Returns `PluginError::Config` when the `config:` block is absent or does
    /// not deserialize into this plugin's settings, and when a validated field
    /// is out of range.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = cfg.config.as_ref().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-delegator-oauth) requires a `config:` block",
                    cfg.name
                ),
            })
        })?;
        let typed: OAuthDelegatorConfig = serde_json::from_value(raw.clone()).map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-delegator-oauth) config parse failed: {e}",
                    cfg.name
                ),
            })
        })?;

        if typed.token_endpoint.trim().is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-delegator-oauth): token_endpoint must be non-empty",
                    cfg.name
                ),
            }));
        }
        // Reject http:// for token_endpoint by default. The exchange
        // POST sends client_id:client_secret + inbound user JWT;
        // sending these over plaintext defeats the whole flow.
        // `insecure_http: true` is the conscious opt-out for
        // localhost docker-compose demos.
        if let Err(e) = require_https(&typed.token_endpoint, typed.insecure_http) {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-delegator-oauth): token_endpoint {e}",
                    cfg.name,
                ),
            }));
        }
        if typed.client_id.trim().is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-delegator-oauth): client_id must be non-empty",
                    cfg.name
                ),
            }));
        }

        let secret = typed.client_secret_source.resolve().map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-delegator-oauth) client secret resolve failed: {e}",
                    cfg.name
                ),
            })
        })?;

        let timeout = typed.timeout();

        // Built here rather than lazily so a cache an operator cannot
        // have (bad settings, no CSPRNG) fails the config load with a
        // message naming the plugin, instead of failing the first
        // delegation to reach it.
        let cache = DelegatedTokenCache::new(typed.cache.clone()).map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-delegator-oauth) cache: {e}",
                    cfg.name
                ),
            })
        })?;

        Ok(Self {
            cfg,
            typed,
            client_secret: Zeroizing::new(secret),
            timeout,
            warned_missing_act: std::sync::atomic::AtomicBool::new(false),
            cache,
        })
    }

    /// Compose the requested scope set: the target's required
    /// permissions plus any extra capabilities from
    /// `route_attenuation`. Returns a space-separated string per
    /// OAuth conventions.
    fn requested_scopes(payload: &DelegationPayload) -> String {
        let mut scopes: Vec<String> = payload.required_permissions().to_vec();
        if let Some(att) = payload.route_attenuation() {
            for cap in &att.capabilities {
                if !scopes.contains(cap) {
                    scopes.push(cap.clone());
                }
            }
        }
        scopes.join(" ")
    }

    /// Leg 1 of a workload delegation (`subject: caller_workload`):
    /// authenticate the calling agent by presenting its JWT-SVID as an
    /// RFC 7523 client assertion, and return the IdP-issued base token.
    ///
    /// There is no Basic auth and no `client_id` — the assertion *is*
    /// the client credential, and the `IdP` resolves which client from
    /// the SVID's `sub` (draft-ietf-oauth-spiffe-client-auth). The base
    /// token this returns then becomes the `subject_token` of the
    /// ordinary exchange (leg 2), which is where the downstream
    /// audience/scope — the authority the agent itself lacks — is
    /// actually granted. Splitting it this way is what keeps the
    /// Build a token-endpoint POST carrying `form`.
    ///
    /// Encoding lives in `praxis_policy_core::http::form_urlencode` rather
    /// than in a transport, so every transport sends identical bytes.
    fn token_request(&self, form: &[(&str, &str)]) -> Result<HttpRequest, Box<PluginViolation>> {
        HttpRequest::post(&self.typed.token_endpoint, form_urlencode(form))
            .timeout(self.timeout)
            // A token response is a small JSON object. The ceiling stops
            // a compromised or broken endpoint streaming without end;
            // reqwest applied none.
            .max_response_bytes(TOKEN_RESPONSE_MAX_BYTES)
            .header("content-type", "application/x-www-form-urlencoded")
            .and_then(|r| r.header("accept", "application/json"))
            .map_err(|e| {
                Box::new(PluginViolation::new(
                    "delegation.bad_request",
                    format!("could not build the token-endpoint request: {e}"),
                ))
            })
    }

    /// `Authorization: Basic base64(client_id:client_secret)`.
    ///
    /// Built here rather than in the transport for the same reason as
    /// the form body: one encoder, identical bytes everywhere.
    fn basic_auth_header(&self) -> String {
        use base64::Engine as _;
        let raw = format!("{}:{}", self.typed.client_id, self.client_secret.as_str());
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }

    /// Turn a transport failure into the right violation.
    ///
    /// The distinction is not cosmetic. A timeout may mean the exchange
    /// *landed* and only the response was lost, so the mint outcome is
    /// indeterminate and must never be treated as "did not happen" —
    /// assuming otherwise is how a second token gets minted for a
    /// credential that already exists. Anything that provably never
    /// reached the `IdP` is a clean "unreachable".
    /// `leg` names which call failed. Both legs POST to the same
    /// endpoint, so without it an operator reading the violation cannot
    /// tell a failed workload authentication from a failed exchange —
    /// and those have different causes and different fixes.
    fn violation_for(&self, leg: &str, err: &HttpRequestError) -> PluginViolation {
        let endpoint = &self.typed.token_endpoint;
        let err = match err {
            // No transport at all, or this plugin may not use one. A
            // config or wiring problem, not the IdP's.
            HttpRequestError::Unavailable(e) => {
                return PluginViolation::new(
                    "delegation.no_transport",
                    format!("plugin '{}' {e}", self.cfg.name),
                );
            },
            HttpRequestError::Transport(e) => e,
        };
        match err {
            // The host declined to make the call: an egress policy, an
            // SSRF guard, an open circuit. Its own code, because
            // "we declined to try" and "we tried and failed" send an
            // operator to different places — collapsing them turns a
            // blocked destination into a phantom network problem and
            // costs an afternoon in DNS.
            HttpTransportError::Rejected(_) => PluginViolation::new(
                "delegation.egress_denied",
                format!("{leg} to {endpoint} was refused before it left the process: {err}"),
            ),
            e if e.may_have_reached_peer() => PluginViolation::new(
                "delegation.idp_timeout",
                format!("{leg} to {endpoint} did not complete: {err}"),
            ),
            _ => PluginViolation::new(
                "delegation.idp_unreachable",
                format!("{leg} to {endpoint} never reached the IdP: {err}"),
            ),
        }
    }

    /// enforcement point, not the agent, as the holder of downstream authority.
    ///
    /// Errors map to the same `delegation.*` violation codes the
    /// exchange uses, so a failed leg 1 denies the whole delegation.
    async fn mint_base_token(
        &self,
        svid: &str,
        svc: &dyn HostServices,
    ) -> Result<String, PluginViolation> {
        let form = [
            ("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS),
            (
                "client_assertion_type",
                self.typed.workload_assertion_type.as_str(),
            ),
            ("client_assertion", svid),
        ];

        // Minting is not idempotent: repeat one that already landed and
        // the IdP issues a second credential nobody holds. So retry only
        // failures that provably never reached it — a timeout ends the
        // attempt and the caller treats the outcome as indeterminate.
        let response = svc
            .http_request(
                self.token_request(&form).map_err(|v| *v)?,
                RetryPolicy::undelivered_only(),
            )
            .await
            .map_err(|e| self.violation_for("workload client_assertion POST", &e))?;

        let status = response.status;
        if !response.is_success() {
            let body = String::from_utf8_lossy(&response.body).into_owned();
            // Sanitize: surface only the OAuth `error` CODE (a fixed
            // vocabulary — invalid_client, invalid_grant, …), never the
            // free-text `error_description` or the raw body. Leg 1 submits
            // the SVID as a `client_assertion`, and an IdP may echo that
            // credential material back in those fields.
            let reason = match serde_json::from_str::<TokenErrorResponse>(&body) {
                Ok(err) => format!("workload client_assertion rejected: {}", err.error),
                Err(_) => format!("workload client_assertion rejected (HTTP {status})"),
            };
            return Err(PluginViolation::new("delegation.idp_rejected", reason));
        }

        match serde_json::from_slice::<TokenExchangeResponse>(&response.body) {
            Ok(parsed) => Ok(parsed.access_token),
            Err(e) => Err(PluginViolation::new(
                "delegation.bad_response",
                format!("workload client_assertion response wasn't valid token JSON: {e}"),
            )),
        }
    }
}

/// Subset of the RFC 8693 response we care about.
#[derive(Debug, Deserialize)]
struct TokenExchangeResponse {
    access_token: String,
    /// Optional per RFC — defaults to `access_token` issued type.
    #[serde(default)]
    issued_token_type: Option<String>,
    /// Optional in RFC; many `IdPs` send it.
    #[serde(default)]
    expires_in: Option<i64>,
    /// Space-separated effective scopes the `IdP` actually granted.
    /// May be narrower than what we requested.
    #[serde(default)]
    scope: Option<String>,
}

/// Subset of the standard OAuth error response — `error` is the
/// machine-readable code (`invalid_grant`, `invalid_scope`, …).
#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

#[async_trait]
impl Plugin for OAuthDelegator {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl OAuthDelegator {
    /// One RFC 8693 exchange (or RFC 6749 client-credentials grant),
    /// returning the minted credential.
    ///
    /// Split out of `handle` so the cache can wrap it. This is the
    /// expensive, `IdP`-touching part, and it is exactly the unit a
    /// cache hit stands in for. It makes no caching decisions itself,
    /// which is what lets the cached and uncached paths run identical
    /// code.
    ///
    /// Takes `ext` because the transport is reached through it, so this
    /// is also the only part of the delegation that touches the network.
    async fn exchange(
        &self,
        payload: &DelegationPayload,
        ext: &Extensions,
    ) -> Result<Mint, PluginViolation> {
        let as_this_workload = *payload.subject() == DelegationSubject::ThisWorkload;
        let is_workload = *payload.subject() == DelegationSubject::CallerWorkload;
        let bearer = payload.bearer_token();
        let audience = payload.target_audience().unwrap_or("");

        let scope = Self::requested_scopes(payload);

        // Leg 1 (workload only): the SVID in `bearer` authenticates the
        // agent as a client; mint the IdP base token here and let the
        // exchange below run on it. Every other subject exchanges its
        // own `bearer` directly. `Cow` avoids cloning the (already
        // borrowed) bearer on the non-workload path.
        let subject_token: Cow<str> = if is_workload {
            match self.mint_base_token(bearer, ext).await {
                Ok(token) => Cow::Owned(token),
                Err(violation) => return Err(violation),
            }
        } else {
            Cow::Borrowed(bearer)
        };

        // Build the form-encoded body: RFC 6749 §4.4 for this instance
        // acting as itself, RFC 8693 §2.1 for every exchange on behalf
        // of somebody else.
        let mut form: Vec<(&str, &str)> = if as_this_workload {
            vec![
                ("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS),
                ("audience", audience),
            ]
        } else {
            vec![
                ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
                // On the workload path this is the leg-1 base token, not
                // the raw SVID; on every other path it's the caller's
                // own bearer, unchanged.
                ("subject_token", subject_token.as_ref()),
                ("subject_token_type", &self.typed.subject_token_type),
                ("audience", audience),
            ]
        };
        if !scope.is_empty() {
            form.push(("scope", &scope));
        }

        // RFC 8693 §2.1 actor_token. Present only when the invoker
        // attached one (sourced from the inbound SVID in
        // `RawCredentialsExtension[CallerWorkload]`). Including it
        // makes the IdP mint a token carrying `act` = actor alongside
        // `sub` = subject — the delegation is recorded in the token
        // itself. Absent, the exchange stays single-token.
        //
        // Skipped entirely under client_credentials: `actor_token` is
        // a token-exchange parameter and has no meaning in RFC 6749
        // §4.4, so sending it would be malformed. A route that wants
        // this instance as principal *and* the calling agent recorded in
        // `act` needs a real subject credential for this instance —
        // i.e. its own SVID — rather than client_credentials.
        //
        // Also skipped on the workload path: there the workload *is* the
        // subject (via the leg-1 base token), so there is no separate
        // actor to record. `actor_token` belongs to the on-behalf-of
        // shape (a user subject with the calling agent as actor).
        let actor_token = payload.actor_token();
        let actor_requested = !actor_token.is_empty() && !as_this_workload && !is_workload;
        if actor_requested {
            form.push(("actor_token", actor_token));
            form.push(("actor_token_type", &self.typed.actor_token_type));
        }

        // POST to the IdP. Basic auth carries our client credentials.
        //
        // Same non-idempotency as leg 1, and it matters more here: this
        // is the exchange that mints the delegated credential. Retrying a
        // timed-out exchange could leave a live token nobody is tracking.
        let request = match self.token_request(&form) {
            Ok(r) => match r.header("authorization", self.basic_auth_header()) {
                Ok(r) => r,
                Err(e) => {
                    return Err(PluginViolation::new(
                        "delegation.bad_request",
                        format!("could not attach client credentials: {e}"),
                    ));
                },
            },
            Err(v) => return Err(*v),
        };

        let response = match ext
            .http_request(request, RetryPolicy::undelivered_only())
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return Err(self.violation_for("token-exchange POST", &e));
            },
        };

        let status = response.status;
        if !response.is_success() {
            // Try to surface the standard `error` / `error_description`
            // fields from the IdP. Fall back to status code.
            let body = String::from_utf8_lossy(&response.body).into_owned();
            let (code, reason) = match serde_json::from_str::<TokenErrorResponse>(&body) {
                Ok(err) => {
                    let mut reason = err.error.clone();
                    if let Some(desc) = err.error_description {
                        reason.push_str(": ");
                        reason.push_str(&desc);
                    }
                    ("delegation.idp_rejected", reason)
                },
                Err(_) => (
                    "delegation.idp_rejected",
                    format!("IdP returned {status}: {body}"),
                ),
            };
            return Err(PluginViolation::new(code, reason));
        }

        let parsed = match serde_json::from_slice::<TokenExchangeResponse>(&response.body) {
            Ok(p) => p,
            Err(e) => {
                return Err(PluginViolation::new(
                    "delegation.bad_response",
                    format!("IdP response wasn't valid token-exchange JSON: {e}"),
                ));
            },
        };

        // Compute effective scopes. IdP's `scope` field wins (it
        // reflects what was actually granted, possibly narrower
        // than what we asked for); fall back to the requested set
        // if the IdP didn't send one.
        let effective_scopes: Vec<String> = if let Some(s) = &parsed.scope {
            s.split_whitespace().map(String::from).collect()
        } else if !scope.is_empty() {
            scope.split_whitespace().map(String::from).collect()
        } else {
            Vec::new()
        };

        // Enforce requested ⊆ effective. Without this check, a route
        // that asked for `read write` and got back `read` would
        // proceed as if the broader grant had succeeded — downstream
        // calls would fail in policy-author-unobservable ways. We
        // compare only when the IdP explicitly sent a `scope` field
        // (otherwise we just used the requested set above, so the
        // subset relationship is trivially true). The required
        // permissions come straight off the DelegationPayload; route
        // attenuation capabilities are advisory extras and not
        // checked here.
        if parsed.scope.is_some() {
            let granted: std::collections::HashSet<&str> =
                effective_scopes.iter().map(String::as_str).collect();
            let missing: Vec<&str> = payload
                .required_permissions()
                .iter()
                .filter(|req| !granted.contains(req.as_str()))
                .map(String::as_str)
                .collect();
            if !missing.is_empty() {
                return Err(PluginViolation::new(
                    "delegation.scope_too_broad",
                    format!(
                        "IdP granted narrower scopes than requested. \
                         requested=[{}] granted=[{}] missing=[{}]",
                        payload.required_permissions().join(" "),
                        effective_scopes.join(" "),
                        missing.join(" "),
                    ),
                ));
            }
        }

        // Compute expiry. Most IdPs send `expires_in` (seconds);
        // if missing, default to 5 minutes — short enough that a
        // misconfigured-but-no-expiry IdP doesn't mint long-lived
        // tokens by accident.
        let ttl_secs = parsed.expires_in.unwrap_or(300);
        // Route attenuation may shorten further.
        let ttl_secs = if let Some(att) = payload.route_attenuation() {
            if let Some(hint) = att.ttl_seconds {
                // Saturating: attenuation only ever shortens, so a hint too
                // large for an i64 means "no further shortening". Wrapping would
                // turn it negative and `min` would pick it, producing a
                // negative lifetime for the delegated token.
                ttl_secs.min(i64::try_from(hint).unwrap_or(i64::MAX))
            } else {
                ttl_secs
            }
        } else {
            ttl_secs
        };
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs);

        // Best-effort interop check. We asked the IdP to record the calling
        // agent in `act` (RFC 8693 delegation semantics). If the minted token
        // is a JWT that carries no `act`, the IdP did impersonation instead —
        // it accepted the exchange but silently dropped the actor (Keycloak's
        // Standard Token Exchange behaves this way). The scoped token is still
        // valid and returned; we only surface the gap so it isn't a silent
        // no-op the policy author never notices.
        //
        // Throttled to once per delegator via `warned_missing_act`: the
        // `!load` short-circuit skips the per-request JWT decode entirely
        // once we've warned, so a token service that always drops `act`
        // doesn't spend a decode + a log line on every request.
        use std::sync::atomic::Ordering;
        if actor_requested
            && !self.warned_missing_act.load(Ordering::Relaxed)
            && jwt_payload_omits_act(&parsed.access_token)
            && !self.warned_missing_act.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                target: "praxis_policy::delegation",
                token_endpoint = %self.typed.token_endpoint,
                "actor was requested (RFC 8693 actor_token) but the minted token carries no `act` claim; \
                 the token service may implement impersonation only (e.g. Keycloak Standard Token Exchange) \
                 and ignored the actor — the acting agent will not appear downstream. \
                 (Further occurrences on this delegator are suppressed.)",
            );
        }

        let token = RawDelegatedToken::new(
            parsed.access_token,
            self.typed.default_outbound_header.clone(),
            audience.to_owned(),
            effective_scopes,
            expires_at,
        );

        Ok(Mint {
            token,
            issued_token_type: parsed
                .issued_token_type
                .unwrap_or_else(|| DEFAULT_ISSUED_TOKEN_TYPE.to_owned()),
        })
    }

    /// The cache and the key to use for this delegation, or `None` when
    /// it must not be cached.
    ///
    /// Three ways to get `None`, and they are deliberately not
    /// distinguished by the caller: no cache configured, a subject mode
    /// the operator did not opt in, or a payload the key derivation
    /// refuses. All three mean the same thing here — go to the `IdP` —
    /// and only the third is worth a log line.
    fn cache_for(&self, payload: &DelegationPayload) -> Option<(&DelegatedTokenCache, CacheKey)> {
        let cache = self.cache.as_ref()?;
        if !cache.config().caches_subject(payload.subject()) {
            return None;
        }
        let identity = DelegatorIdentity {
            instance: &self.cfg.name,
            token_endpoint: &self.typed.token_endpoint,
            client_id: &self.typed.client_id,
        };
        match derive_cache_key(cache.secret(), identity, payload) {
            Ok(key) => Some((cache, key)),
            Err(reason) => {
                tracing::debug!(
                    target: "praxis_policy::delegation",
                    plugin = %self.cfg.name,
                    target_name = %payload.target_name(),
                    ?reason,
                    "delegation is not cacheable; minting",
                );
                None
            },
        }
    }
}

impl HookHandler<TokenDelegateHook> for OAuthDelegator {
    async fn handle(
        &self,
        payload: &DelegationPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<DelegationPayload> {
        // `subject: this_workload` means *we* are the principal. There
        // is no inbound credential to exchange — this instance's identity
        // is its OAuth client identity, which it already proves via the
        // Basic auth header below. The standard grant for "give me a
        // token as myself" is client_credentials, not token exchange.
        let as_this_workload = *payload.subject() == DelegationSubject::ThisWorkload;

        let bearer = payload.bearer_token();
        if bearer.is_empty() && !as_this_workload {
            return PluginResult::deny(PluginViolation::new(
                "delegation.bad_request",
                "DelegationPayload carried an empty bearer_token — outbound \
                 caller didn't populate the credential before invoking the hook",
            ));
        }
        let audience = payload.target_audience().unwrap_or("");
        if audience.is_empty() {
            return PluginResult::deny(PluginViolation::new(
                "delegation.bad_request",
                "target_audience missing — RFC 8693 token exchange requires \
                 an audience to scope the minted credential",
            ));
        }

        // The cached and uncached paths differ only in whether the
        // exchange runs behind the cache. Both end with a `Served`, so
        // everything below this is the same code it was before.
        let served = match self.cache_for(payload) {
            Some((cache, key)) => match cache.get_or_mint(key, self.exchange(payload, ext)).await {
                Ok(served) => served,
                // One failed exchange may be reported to several
                // coalesced waiters, hence the `Arc`. Nothing was
                // cached: `get_or_mint` does not store an `Err`.
                Err(violation) => return PluginResult::deny((*violation).clone()),
            },
            None => match self.exchange(payload, ext).await {
                Ok(mint) => Served {
                    mint,
                    source: Source::Mint,
                    minted_at: Utc::now(),
                },
                Err(violation) => return PluginResult::deny(violation),
            },
        };

        let mut updated = payload.clone();
        updated.delegated_token = Some(served.mint.token);
        updated.delegation_mode = Some(payload.subject().default_mode());
        // From the mint, not from now. A cached token that claimed to
        // have been minted on every request it served would put a false
        // timestamp in the audit trail.
        updated.minted_at = Some(served.minted_at);
        updated.metadata.insert(
            "issued_token_type".into(),
            serde_json::Value::String(served.mint.issued_token_type),
        );
        // So a hit rate is observable without a debug build.
        updated.metadata.insert(
            "delegated_token_source".into(),
            serde_json::Value::String(
                match served.source {
                    Source::Cache => "cache",
                    Source::Mint => "mint",
                }
                .to_owned(),
            ),
        );

        PluginResult::modify_payload(updated)
    }
}

/// Best-effort: does `access_token` decode as a JWT whose payload has no
/// `act` claim? Returns `true` only when we can *positively* see a JWT
/// payload object that lacks `act`. Anything we can't inspect — an opaque
/// token, a non-base64url segment, a non-JSON payload — returns `false`,
/// so a caller using this to warn never fires on a token it couldn't read.
///
/// The signature is deliberately not verified: this token just came back
/// from our own trusted `IdP` roundtrip, and we're only reading a claim to
/// decide whether to log, not making a trust decision.
fn jwt_payload_omits_act(access_token: &str) -> bool {
    use base64::Engine as _;
    // JWT is `header.payload.signature`; the claims are the middle segment.
    let Some(payload_b64) = access_token.split('.').nth(1) else {
        return false;
    };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64) else {
        return false;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    // Treat both a missing `act` and an explicit `"act": null` as absent —
    // a null claim records no actor.
    claims.is_object() && claims.get("act").is_none_or(serde_json::Value::is_null)
}

/// Reject `http://` for endpoints that carry credentials. Allows
/// `https://` unconditionally and `http://` only when the operator
/// explicitly set `insecure_http: true`. Empty / un-parseable URLs
/// are returned as-is to whatever validator already exists upstream
/// — this helper only owns the scheme check.
///
/// Returns a short fragment ("must use https://…") that the caller
/// prepends with the field name + plugin name for the full error
/// message.
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
            "must use https:// (got '{url}'). Set `insecure_http: true` \
             to allow plaintext for localhost/dev only — never production."
        ));
    }
    // Anything else (missing scheme, bad scheme): defer to the
    // upstream URL parser. We're not the URL validator, just the
    // scheme gate.
    Ok(())
}

/// Construction-time rejections.
///
/// Every one of these is a config an operator can write, and each has to fail
/// at load rather than register a delegator that would fail on every request.
/// None of them reaches the network: `new` resolves config and builds an HTTP
/// client, it does not call the token endpoint.
#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod construction_tests {
    use super::OAuthDelegator;
    use praxis_policy_core::plugin::PluginConfig;
    use serde_json::json;

    fn cfg(config: Option<serde_json::Value>) -> PluginConfig {
        PluginConfig {
            name: "oauth".into(),
            kind: "delegator/oauth".into(),
            config,
            ..Default::default()
        }
    }

    fn valid() -> serde_json::Value {
        json!({
            "token_endpoint": "https://idp.example/token",
            "client_id": "gateway-client",
            "client_secret_source": { "kind": "literal", "secret": "s3cret" },
        })
    }

    fn err_of(config: serde_json::Value) -> String {
        let Err(e) = OAuthDelegator::new(cfg(Some(config))) else {
            panic!("this config must be rejected")
        };
        e.to_string()
    }

    #[test]
    fn the_valid_baseline_builds() {
        // Guards the negative tests below: without this, a typo in `valid()`
        // would make all of them pass for the wrong reason.
        OAuthDelegator::new(cfg(Some(valid()))).unwrap();
    }

    #[test]
    fn a_missing_config_block_is_rejected() {
        let Err(e) = OAuthDelegator::new(cfg(None)) else {
            panic!("no config block must not build")
        };
        let err = e.to_string();
        assert!(err.contains("`config:`"), "{err}");
    }

    #[test]
    fn a_config_block_of_the_wrong_shape_is_rejected() {
        let err = err_of(json!({ "token_endpoint": 42 }));
        assert!(err.contains("parse failed"), "{err}");
    }

    #[test]
    fn an_empty_token_endpoint_is_rejected() {
        let mut c = valid();
        c["token_endpoint"] = json!("   ");
        let err = err_of(c);
        assert!(err.contains("token_endpoint must be non-empty"), "{err}");
    }

    /// The exchange POST carries the client secret and the inbound user JWT, so
    /// a plaintext endpoint defeats the whole flow. It is refused unless the
    /// operator opts in by name.
    #[test]
    fn a_plaintext_token_endpoint_is_rejected_without_the_opt_in() {
        let mut c = valid();
        c["token_endpoint"] = json!("http://idp.example/token");
        let err = err_of(c.clone());
        assert!(err.contains("must use https"), "{err}");
        assert!(
            err.contains("insecure_http"),
            "the message must name the opt-out: {err}"
        );

        c["insecure_http"] = json!(true);
        assert!(
            OAuthDelegator::new(cfg(Some(c))).is_ok(),
            "the explicit opt-in must be honored"
        );
    }

    #[test]
    fn an_empty_client_id_is_rejected() {
        let mut c = valid();
        c["client_id"] = json!("");
        let err = err_of(c);
        assert!(err.contains("client_id must be non-empty"), "{err}");
    }

    /// A secret sourced from an environment variable that is not set must fail
    /// at load. Registering the delegator would leave it authenticating with an
    /// empty secret against the token endpoint.
    #[test]
    fn an_unresolvable_client_secret_is_rejected() {
        let mut c = valid();
        c["client_secret_source"] = json!({
            "kind": "env_var",
            "name": "PPE_TEST_SECRET_THAT_IS_NOT_SET",
        });
        let err = err_of(c);
        assert!(err.contains("client secret resolve failed"), "{err}");
    }

    /// The `Debug` impl exists so a delegator can be logged without leaking the
    /// client secret. That is a security property, so it is asserted rather
    /// than assumed.
    #[test]
    fn debug_shows_the_endpoint_and_elides_the_secret() {
        let d = OAuthDelegator::new(cfg(Some(valid()))).unwrap();
        let s = format!("{d:?}");
        assert!(s.contains("https://idp.example/token"), "{s}");
        assert!(s.contains("gateway-client"), "{s}");
        assert!(s.contains("<elided>"), "{s}");
        assert!(
            !s.contains("s3cret"),
            "the secret must never be printed: {s}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod scheme_tests {
    use super::require_https;

    #[test]
    fn https_always_ok() {
        require_https("https://idp.example/oauth/token", false).unwrap();
        require_https("HTTPS://IDP.EXAMPLE/", false).unwrap();
    }

    #[test]
    fn http_default_rejected() {
        let err = require_https("http://localhost:8081/oauth/token", false).unwrap_err();
        assert!(err.contains("must use https"), "{}", err);
        assert!(err.contains("insecure_http"), "mentions opt-out: {err}");
    }

    #[test]
    fn http_with_explicit_opt_in_allowed() {
        require_https("http://localhost:8081/oauth/token", true).unwrap();
    }

    #[test]
    fn http_with_leading_whitespace_still_rejected() {
        // A trailing newline or leading whitespace from sloppy YAML
        // shouldn't smuggle a plaintext URL past the gate.
        let err = require_https("  http://idp/", false).unwrap_err();
        assert!(err.contains("must use https"));
    }
}

#[cfg(test)]
mod act_claim_tests {
    use super::jwt_payload_omits_act;
    use base64::Engine as _;

    // Build a `header.payload.sig` JWT string from a payload JSON literal.
    fn jwt(payload: &str) -> String {
        let b = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes());
        format!("{}.{}.{}", b(r#"{"alg":"none"}"#), b(payload), "sig")
    }

    #[test]
    fn payload_with_act_is_not_flagged() {
        // Delegation honored: `act` present → no warning.
        let token = jwt(r#"{"sub":"user","act":{"sub":"agent"}}"#);
        assert!(!jwt_payload_omits_act(&token));
    }

    #[test]
    fn payload_without_act_is_flagged() {
        // Impersonation: subject only, no `act` → this is the case we warn on.
        let token = jwt(r#"{"sub":"user","aud":"workday-api"}"#);
        assert!(jwt_payload_omits_act(&token));
    }

    #[test]
    fn payload_with_null_act_is_flagged() {
        // `"act": null` records no actor — treated as absent, same as missing.
        let token = jwt(r#"{"sub":"user","act":null}"#);
        assert!(jwt_payload_omits_act(&token));
    }

    #[test]
    fn opaque_token_is_not_flagged() {
        // Not a JWT (no dots): we can't inspect it, so never warn.
        assert!(!jwt_payload_omits_act("opaque-reference-token"));
    }

    #[test]
    fn non_base64_payload_is_not_flagged() {
        // Right shape, but the middle segment isn't valid base64url.
        assert!(!jwt_payload_omits_act("aaa.!!!not-base64!!!.sig"));
    }

    #[test]
    fn non_json_payload_is_not_flagged() {
        // Decodes as base64url but isn't JSON claims — can't tell, don't warn.
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
        assert!(!jwt_payload_omits_act(&format!("aaa.{b}.sig")));
    }
}
