// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `JwtIdentityResolver` — `HookHandler<IdentityHook>` that validates
// inbound JWTs and populates the request's `IdentityPayload`.
//
// # Construction
//
// Single entry point: `JwtIdentityResolver::new(cfg: PluginConfig)`.
// Reads `cfg.config` (the typed plugin-specific config field) and
// deserializes it into [`JwtIdentityResolverConfig`], builds the
// runtime `TrustedIssuer` list and the `ClaimMapper`. No alternate
// constructors that bypass the config-driven path — tests
// construct a `PluginConfig` with the right `config` value and go
// through `new` like production code does.
//
// # Runtime flow
//
//   1. Peek at the `iss` claim *without* validating to pick the
//      right trusted issuer config.
//   2. Validate the token (signature + exp + nbf + aud + iss) using
//      that issuer's `DecodingKey`. `iss` is re-checked here as
//      defense-in-depth.
//   3. Map validated claims to a `SubjectExtension` via the
//      configured claim mapper.
//   4. Stash the raw token in `RawCredentialsExtension.inbound_tokens`
//      under `TokenRole::User` for forwarding plugins downstream.
//   5. Return the updated payload via `PluginResult::modify_payload`.
//
// # Error handling
//
// Construction errors → `Box<PluginError>` (`PluginError::Config`).
// Runtime token rejections → `PluginResult::deny(PluginViolation::new(code, reason))`.
// Stable codes for runtime denials:
//
//   * `auth.malformed_header` — JWT structure wrong / empty token
//   * `auth.untrusted_issuer` — `iss` not in trusted list
//   * `auth.signature_invalid` — signature failed
//   * `auth.token_expired` — `exp` in the past
//   * `auth.token_not_yet_valid` — `nbf` in the future
//   * `auth.audience_mismatch` — `aud` didn't include any configured aud
//   * `auth.algorithm_mismatch` — token uses unaccepted algo
//   * `auth.mapping_failed` — claim mapper rejected the claims
//   * `auth.token_invalid` — any other validation failure

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use jsonwebtoken::{Validation, decode};
use serde_json::Value;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::extensions::raw_credentials::{RawInboundToken, TokenKind, TokenRole};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::identity::{IdentityHook, IdentityPayload};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use super::claim_map::{ClaimMap, ClaimMapper};
use super::claim_map_config::{ClaimsOverrides, CompiledClaimsOverrides};
use super::config::{JwtIdentityResolverConfig, TrustedIssuerConfig};
use super::configured_mapper::ConfiguredClaimMap;
use super::presets;
use super::trusted_issuer::{KeyStore, TrustedIssuer};

/// Default clock-skew tolerance, in seconds. Matches what most OIDC
/// clients use as a sane default for `exp` / `nbf`.
const DEFAULT_LEEWAY_SECONDS: u64 = 60;

/// JWT-based identity resolver. See module docs.
///
/// # Async key resolution
///
/// Trusted-issuer keys come in two flavors:
///
/// * **Inline / on-disk** (`Pem`, `PemFile`, `Jwk`, `Secret`) — built
///   eagerly during `new()`. They appear in `trusted_issuers`
///   immediately after construction.
/// * **`JwksUrl`** — deferred to `Plugin::initialize()`. The configs
///   sit in `pending_jwks` until `initialize()` runs; that hook
///   fetches all pending JWKS endpoints **concurrently** via
///   `futures::join_all` and merges the resolved issuers into the
///   `trusted_issuers` vec under the `RwLock`.
///
/// The split keeps construction synchronous (matches the existing
/// `PluginFactory::create` trait surface across the workspace) while
/// putting the network I/O on the natural async hook the host
/// already drives via `PolicyEngine::initialize().await`.
#[derive(Debug)]
pub struct JwtIdentityResolver {
    cfg: PluginConfig,
    trusted_issuers: std::sync::RwLock<Vec<TrustedIssuer>>,
    /// Issuer configs whose `decoding_key` is a `JwksUrl` —
    /// resolved during `initialize()`. Empty in deployments with
    /// only inline sources.
    pending_jwks: Vec<TrustedIssuerConfig>,
    claim_mapper: Arc<dyn ClaimMapper>,
    /// Which identity slot this resolver fills. Drives
    /// `IdentityPayload` slot selection and the `TokenRole` key under
    /// which the raw token gets stashed in
    /// `RawCredentialsExtension.inbound_tokens`.
    role: TokenRole,
    /// HTTP header this resolver reads its token from
    /// (e.g. `X-User-Token`). Plugins that share a request extract
    /// from different headers; the value lands on
    /// `RawInboundToken.source_header` so forwarding plugins know
    /// where to put it (or strip it) on the upstream call.
    header: String,
    /// Background JWKS-refresh tasks, one per `JwksUrl` issuer.
    /// Spawned during `initialize()`. Aborted in the resolver's
    /// `Drop` impl — without that, tokio `JoinHandles` silently
    /// detach the task and the refresh loop runs forever (until
    /// the runtime shuts down or it panics).
    refresh_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl JwtIdentityResolver {
    /// Build a resolver from a `PluginConfig`. Reads `cfg.config`
    /// (the plugin-specific config field — `Option<JsonValue>`),
    /// deserializes it into [`JwtIdentityResolverConfig`], builds
    /// the runtime `TrustedIssuer` list, and resolves the claim
    /// mapper by name.
    ///
    /// Returns `PluginError::Config` for any config-time failure:
    /// missing config block, malformed JSON, no trusted issuers,
    /// unparsable decoding key, unknown claim mapper, etc.
    /// # Errors
    ///
    /// Returns `PluginError::Config` when the `config:` block is absent or does
    /// not deserialize into this plugin's settings, and when a validated field
    /// is out of range.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw_config = cfg.config.as_ref().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-identity-jwt) requires a `config:` block — \
                     missing trusted_issuers etc.",
                    cfg.name
                ),
            })
        })?;

        let typed: JwtIdentityResolverConfig =
            serde_json::from_value(raw_config.clone()).map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (praxis-policy-plugin-identity-jwt) config parse failed: {e}",
                        cfg.name
                    ),
                })
            })?;

        if typed.trusted_issuers.is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-identity-jwt) requires at least one \
                     entry in `trusted_issuers`",
                    cfg.name
                ),
            }));
        }

        // Partition issuer configs:
        //   * Inline / on-disk decoding keys (Pem, PemFile, Jwk,
        //     Secret) → eagerly built into TrustedIssuers here.
        //   * JwksUrl decoding keys → deferred to initialize() so
        //     the host's PolicyEngine can drive the HTTP fetches
        //     concurrently across all resolvers.
        let mut trusted_issuers: Vec<TrustedIssuer> = Vec::new();
        let mut pending_jwks: Vec<TrustedIssuerConfig> = Vec::new();
        for raw in typed.trusted_issuers {
            // Validate shape eagerly so bad YAML fails at load_config
            // rather than at the async initialize() boundary.
            raw.validate().map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (praxis-policy-plugin-identity-jwt): {e}",
                        cfg.name
                    ),
                })
            })?;
            if raw.decoding_key.needs_async() {
                pending_jwks.push(raw);
            } else {
                let built = raw.build().map_err(|e| {
                    Box::new(PluginError::Config {
                        message: format!(
                            "plugin '{}' (praxis-policy-plugin-identity-jwt): {e}",
                            cfg.name
                        ),
                    })
                })?;
                trusted_issuers.push(built);
            }
        }

        // Reject `role: Custom(...)` at construction — the framework
        // has slots for User / Client / Workload (the three named
        // entries on SecurityExtension). Custom roles would write to
        // `inbound_tokens` only, with no SecurityExtension home, so
        // downstream `subject.*` / `client.*` predicates wouldn't see
        // them. If we ever want custom slots, that's its own slice.
        if matches!(typed.role, TokenRole::Custom(_)) {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-identity-jwt): role: Custom(...) is not \
                     yet supported — pick one of `user`, `client`, `workload`",
                    cfg.name
                ),
            }));
        }

        // Resolve the claim map: an inline `claim_map`, a preset named by
        // `claim_mapper`, or the standard preset. Unknown names and malformed
        // maps are config errors rather than silent fallbacks, so an operator's
        // typo fails at load rather than denying every request.
        let config_error = |message: String| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-identity-jwt): {message}",
                    cfg.name
                ),
            })
        };

        let claims_overrides: CompiledClaimsOverrides = match typed.claims.as_ref() {
            Some(value) => {
                let parsed: ClaimsOverrides =
                    serde_json::from_value(value.clone()).map_err(|e| {
                        config_error(format!(
                            "`claims` takes `exclude` and `include` lists of claim names: {e}"
                        ))
                    })?;
                parsed.compile().map_err(&config_error)?
            },
            None => CompiledClaimsOverrides::default(),
        };

        // A workload identity carries no claims bag, so the overrides would sit
        // there doing nothing. Same treatment as the undeclared anchor below:
        // the condition is static, so say it once at load.
        if matches!(typed.role, TokenRole::CallerWorkload) && !claims_overrides.is_empty() {
            tracing::warn!(
                plugin = %cfg.name,
                "`claims` has no effect under `role: caller_workload`, which carries no claims \
                 bag; the overrides will be ignored",
            );
        }

        let compiled = match (typed.claim_map.as_ref(), typed.claim_mapper.as_deref()) {
            (Some(_), Some(named)) => {
                return Err(config_error(format!(
                    "`claim_map` and `claim_mapper: {named}` are both set; pick one, an inline \
                     map or a preset by name"
                )));
            },
            (Some(inline), None) => inline
                .compile()
                .map_err(|e| config_error(format!("`claim_map` is not usable: {e}")))?,
            (None, named) => presets::lookup(named.unwrap_or(presets::DEFAULT_PRESET))
                .map_err(&config_error)?
                .into_claim_map(),
        };

        let compiled = compiled.with_claims(claims_overrides);

        // Require the section matching the configured role now, so a
        // misconfigured pairing is a startup failure rather than a resolver that
        // denies every request.
        let section = compiled.role(&typed.role).map_err(&config_error)?;

        // A section that declares no path for its anchor compiles, because
        // declaring the role is what the section check asks. It then denies every
        // token, so say so at load rather than leaving it to be discovered one
        // denial at a time.
        let anchor = match typed.role {
            TokenRole::Client => "client_id",
            TokenRole::CallerWorkload => "spiffe_id",
            _ => "id",
        };
        if section.field(anchor).is_none() {
            tracing::warn!(
                plugin = %cfg.name,
                role = ?typed.role,
                field = anchor,
                "claim map declares no path for its anchor, so every token will be declined",
            );
        }

        let claim_mapper: Arc<dyn ClaimMapper> = Arc::new(ConfiguredClaimMap::new(compiled));

        if typed.header.trim().is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-identity-jwt): `header:` must be a \
                     non-empty HTTP header name",
                    cfg.name
                ),
            }));
        }

        Ok(Self {
            cfg,
            trusted_issuers: std::sync::RwLock::new(trusted_issuers),
            pending_jwks,
            claim_mapper,
            role: typed.role,
            header: typed.header,
            refresh_tasks: std::sync::Mutex::new(Vec::new()),
        })
    }
}

impl Drop for JwtIdentityResolver {
    /// Stop every background refresh task when the resolver drops.
    /// Without this, `tokio::task::JoinHandle` *detaches* on drop
    /// — the refresh loop keeps running until the tokio runtime
    /// shuts down. That's harmless for the program-lifetime
    /// singleton case but creates orphan tasks during plugin
    /// hot-reload or in tests that construct/discard resolvers
    /// repeatedly.
    fn drop(&mut self) {
        let mut tasks = match self.refresh_tasks.lock() {
            Ok(t) => t,
            Err(poisoned) => poisoned.into_inner(),
        };
        for handle in tasks.drain(..) {
            handle.abort();
        }
    }
}

#[async_trait]
impl Plugin for JwtIdentityResolver {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }

    /// Resolve any `JwksUrl` decoding keys deferred at construction,
    /// then spawn a background task per `JwksUrl` issuer to refresh
    /// the `KeyStore` on a periodic schedule (default 10 min,
    /// configurable per-issuer via `refresh_secs`).
    ///
    /// **Soft-fail semantics:** an unreachable / slow /
    /// malformed JWKS at startup logs a warning and leaves the
    /// issuer's `KeyStore` *empty*. The plugin still loads, the
    /// gateway still boots, and the background refresh task gets
    /// spawned anyway — so a transient `IdP` outage during boot
    /// recovers on its own as soon as refresh succeeds. Verify-time
    /// requests against an issuer with an empty `KeyStore` receive
    /// `auth.jwks_unavailable` rather than crashing the request.
    ///
    /// Initial fetches happen concurrently — N pending issuers
    /// → one `join_all`, not N sequential round-trips — so the
    /// time-to-ready scales with the slowest `IdP`, not the sum.
    ///
    /// The `PolicyEngine` drives this once per plugin lifetime
    /// (before any hooks fire). Idempotent: if `pending_jwks` is
    /// empty (no `JwksUrl` sources) this is a free no-op.
    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        if self.pending_jwks.is_empty() {
            return Ok(());
        }

        // 1. Initial concurrent fetch. Each result is (config,
        //    outcome) — we keep the config alongside the result
        //    so the soft-fail path can construct an empty
        //    KeyStore *and* still spawn refresh for that issuer.
        let fetches = self.pending_jwks.iter().cloned().map(|cfg| async move {
            let outcome = cfg.clone().build_async().await;
            (cfg, outcome)
        });
        let resolved: Vec<(TrustedIssuerConfig, Result<TrustedIssuer, String>)> =
            futures::future::join_all(fetches).await;

        let mut issuers = self
            .trusted_issuers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut new_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        for (cfg, outcome) in resolved {
            // Get the shared store: from the successful fetch's
            // TrustedIssuer if we have one, else an empty store
            // bound to a freshly-constructed TrustedIssuer shell.
            // Either way we end up with one TrustedIssuer in
            // `issuers` and a clone of its `Arc<RwLock<KeyStore>>`
            // captured by the refresh task.
            let (shared, plugin_name) = (self.cfg.name.clone(), cfg.issuer.clone());
            let issuer = match outcome {
                Ok(iss) => iss,
                Err(e) => {
                    tracing::warn!(
                        plugin = %shared,
                        issuer = %plugin_name,
                        error = %e,
                        "initial JWKS fetch failed; soft-fail. Verify requests \
                         against this issuer will receive auth.jwks_unavailable \
                         until refresh succeeds."
                    );
                    // Build a TrustedIssuer with an empty KeyStore
                    // so the refresh task can swap a fresh store in
                    // without re-running validation logic.
                    TrustedIssuer {
                        issuer: cfg.issuer.clone(),
                        audiences: cfg.audiences.clone(),
                        keys: Arc::new(std::sync::RwLock::new(KeyStore::empty())),
                        algorithms: cfg.algorithms.clone(),
                        leeway_seconds: cfg.leeway_seconds,
                    }
                },
            };

            // Spawn refresh task. The closure owns:
            //   - a clone of the source (cfg.decoding_key) for
            //     re-fetching
            //   - a clone of the Arc<RwLock<KeyStore>> for atomic
            //     whole-store replacement on success
            //   - plugin / issuer names for diagnostic logging
            if let Some(interval) = cfg.decoding_key.refresh_interval() {
                let source = cfg.decoding_key.clone();
                let shared_store = Arc::clone(&issuer.keys);
                let plugin_label = self.cfg.name.clone();
                let issuer_label = cfg.issuer.clone();
                let handle = tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(interval);
                    // Skip the first immediate tick — the initial
                    // fetch already ran synchronously above. The
                    // first refresh fires at `now + interval`.
                    ticker.tick().await;
                    loop {
                        ticker.tick().await;
                        match source.build_async().await {
                            Ok(new_store) => {
                                // Whole-store replacement. The
                                // old store drops when the write
                                // completes — bounded steady-state
                                // memory regardless of how many
                                // rotations have happened.
                                match shared_store.write() {
                                    Ok(mut g) => *g = new_store,
                                    Err(poisoned) => *poisoned.into_inner() = new_store,
                                }
                                tracing::info!(
                                    plugin = %plugin_label,
                                    issuer = %issuer_label,
                                    "JWKS refresh succeeded"
                                );
                            },
                            Err(e) => {
                                tracing::warn!(
                                    plugin = %plugin_label,
                                    issuer = %issuer_label,
                                    error = %e,
                                    "JWKS refresh failed; keeping previous KeyStore"
                                );
                            },
                        }
                    }
                });
                new_tasks.push(handle);
            }

            issuers.push(issuer);
        }

        // Park the handles so Drop can abort them. Held under a
        // std::sync::Mutex because the resolver's outer methods are
        // a mix of sync and async; we don't await while holding it.
        let mut tasks = self
            .refresh_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.extend(new_tasks);

        Ok(())
    }
}

impl HookHandler<IdentityHook> for JwtIdentityResolver {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        // Read OUR configured header from the request's full header
        // map. HTTP headers are case-insensitive (RFC 7230 §3.2);
        // we lowercase the configured name to match the canonical
        // form hosts use when populating the map. Fall back to
        // `payload.raw_token()` only when no header map is populated
        // — covers single-resolver back-compat for hosts that still
        // pre-extract one token.
        let header_lc = self.header.to_ascii_lowercase();
        let header_value = payload.headers().get(header_lc.as_str());
        let raw_token: String = match header_value {
            Some(v) => v.strip_prefix("Bearer ").unwrap_or(v).to_owned(),
            None if !payload.raw_token().is_empty() => payload.raw_token().to_owned(),
            None => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.malformed_header",
                    format!(
                        "header '{}' missing from request (resolver '{}' / role '{:?}')",
                        self.header, self.cfg.name, self.role
                    ),
                ));
            },
        };
        if raw_token.is_empty() {
            return PluginResult::deny(PluginViolation::new(
                "auth.malformed_header",
                format!("header '{}' is present but empty", self.header),
            ));
        }

        // 1. Peek at `iss` to find the matching TrustedIssuer config.
        let iss = match peek_issuer(&raw_token) {
            Some(iss) => iss,
            None => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.malformed_header",
                    "JWT not well-formed or missing `iss` claim",
                ));
            },
        };
        // Read-lock the issuer list. After `initialize()` it's
        // immutable for the resolver's lifetime; reads are cheap.
        // Recover from a poisoned lock (a panic somewhere else
        // while holding the write lock) — the data is still valid.
        let issuers = self
            .trusted_issuers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let issuer = match issuers.iter().find(|i| i.issuer == iss) {
            Some(i) => i,
            None => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.untrusted_issuer",
                    format!("issuer '{iss}' is not in the trusted-issuer list"),
                ));
            },
        };

        // 2. Validate signature + standard claims, after kid-driven
        //    key selection. Three distinct deny codes so operators
        //    can tell:
        //      - rotation lag (`auth.unknown_kid`): the IdP rolled
        //        and our refresh hasn't yet pulled the new key.
        //      - JWKS-unavailable (`auth.jwks_unavailable`): the
        //        initial fetch failed and refresh hasn't recovered
        //        — the gateway didn't crash by design, but it
        //        also can't verify tokens for this issuer right now.
        //      - forgery / corruption (`auth.signature_invalid` and
        //        friends): the standard jsonwebtoken outcomes.
        let token_data = match validate_token(&raw_token, issuer) {
            Ok(td) => td,
            Err(ValidateError::KeysUnavailable) => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.jwks_unavailable",
                    format!(
                        "issuer '{iss}' has no signing keys available — \
                         initial JWKS fetch failed and refresh has not \
                         yet succeeded; check upstream IdP reachability"
                    ),
                ));
            },
            Err(ValidateError::UnknownKid(kid)) => {
                let reason = match kid {
                    Some(k) => format!(
                        "token's header `kid` = '{k}' did not match any key in issuer's JWKS"
                    ),
                    None => "token has no `kid` header; issuer's JWKS keys all require kid match"
                        .to_owned(),
                };
                return PluginResult::deny(PluginViolation::new("auth.unknown_kid", reason));
            },
            Err(ValidateError::NoAlgorithms) => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.no_algorithms",
                    format!(
                        "issuer '{iss}' accepts no signature algorithms, so no \
                         token from it can be verified; this is a configuration \
                         fault rather than a problem with the token"
                    ),
                ));
            },
            Err(ValidateError::Jwt(e)) => {
                let (code, reason) = classify_jwt_error(&e);
                return PluginResult::deny(PluginViolation::new(code, reason));
            },
        };

        // 3. Build the updated payload by mapping claims into the
        //    typed slot for our configured role.
        let mut updated = payload.clone();
        match &self.role {
            TokenRole::User => match self.claim_mapper.map_subject(&token_data.claims) {
                Some(s) => updated.subject = Some(s),
                None => {
                    return PluginResult::deny(PluginViolation::new(
                        "auth.mapping_failed",
                        "the claim map produced no subject: no candidate resolved for the \
                         subject id, or a field declaring `on_missing: deny` resolved \
                         nothing. Raise the log level to debug to see which fields and \
                         which paths were tried",
                    ));
                },
            },
            TokenRole::Client => match self.claim_mapper.map_client(&token_data.claims) {
                Some(c) => updated.client = Some(c),
                None => {
                    return PluginResult::deny(PluginViolation::new(
                        "auth.mapping_failed",
                        "the claim map produced no client: no candidate resolved for the \
                         client id, or a field declaring `on_missing: deny` resolved \
                         nothing. Raise the log level to debug to see which fields and \
                         which paths were tried",
                    ));
                },
            },
            TokenRole::CallerWorkload => match self.claim_mapper.map_workload(&token_data.claims) {
                Some(w) => updated.caller_workload = Some(w),
                None => {
                    return PluginResult::deny(PluginViolation::new(
                        "auth.mapping_failed",
                        "the claim map produced no workload: no candidate resolved to a \
                         `spiffe://` identity carrying a trust domain, which every \
                         candidate must, or a field declaring `on_missing: deny` resolved \
                         nothing. Raise the log level to debug to see which fields and \
                         which paths were tried",
                    ));
                },
            },
            TokenRole::Custom(_) => {
                // Filtered out at construction; defense in depth.
                return PluginResult::deny(PluginViolation::new(
                    "auth.misconfigured",
                    "role: Custom(...) is not supported",
                ));
            },
            // TokenRole is #[non_exhaustive]; future variants must be
            // explicitly handled. Until then, treat unknown roles the
            // same as Custom — surface as misconfigured rather than
            // silently dropping the token.
            _ => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.misconfigured",
                    "unsupported TokenRole variant",
                ));
            },
        }

        // 4. Stash the raw token for forwarding plugins. Key the
        //    stash by the resolver's configured role so multi-token
        //    deployments (user + client + workload) keep each
        //    credential addressable.
        //
        //    Record the wire format accurately. A Workload token that
        //    reached this point has already been through
        //    `map_workload`, which only succeeds on a SPIFFE-shaped
        //    `sub` — so by construction it is a JWT-SVID, not a
        //    generic JWT. Consumers that branch on `TokenKind` (audit
        //    attribution, SPIFFE-aware validation) get the truth
        //    rather than having to re-parse the token to discover it.
        let kind = match self.role {
            TokenRole::CallerWorkload => TokenKind::SpiffeJwt,
            _ => TokenKind::Jwt,
        };
        let mut raw_creds = updated.raw_credentials.clone().unwrap_or_default();
        raw_creds.inbound_tokens.insert(
            self.role.clone(),
            RawInboundToken::new(raw_token, self.header.clone(), kind),
        );
        updated.raw_credentials = Some(raw_creds);
        updated.resolved_at = Some(chrono::Utc::now());
        // Pass the full claim map through `raw_claims` so audit /
        // downstream policy that wants uncategorized claims has them.
        // For multi-resolver chains, the last resolver wins; if
        // operators need per-role raw claims they should read from
        // the typed slots (subject.claims / client.claims) instead.
        updated.raw_claims = token_data.claims;

        PluginResult::modify_payload(updated)
    }
}

/// Pull the `iss` claim out of a JWT *without* verifying the
/// signature. Used purely to look up which trusted issuer config
/// to validate against next.
///
/// **Security note:** the value returned here is untrusted until
/// the subsequent validation pass succeeds. We use it only to
/// select the right `DecodingKey`; validation re-enforces `iss`
/// against the matched config.
fn peek_issuer(token: &str) -> Option<String> {
    // Exactly three dot-separated segments, matching the previous length check.
    let mut segments = token.split('.');
    let (Some(_header), Some(payload_b64), Some(_signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return None;
    };
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let value: Value = serde_json::from_slice(&payload_bytes).ok()?;
    value.get("iss")?.as_str().map(String::from)
}

/// Reason `validate_token` couldn't verify the JWT. Wraps the
/// usual `jsonwebtoken::errors::Error` plus the kid-selection
/// and JWKS-availability cases.
enum ValidateError {
    /// The JWT's header `kid` didn't match any key the issuer's
    /// `KeyStore` knows about. Distinct from `InvalidSignature` so
    /// the verify path can surface `auth.unknown_kid` with the
    /// specific kid that was missing — operators can match this
    /// against their `IdP`'s currently-published JWKS to confirm
    /// rotation propagated.
    UnknownKid(Option<String>),
    /// The issuer's `KeyStore` is empty: initial JWKS fetch failed
    /// at `initialize()`, refresh task hasn't yet succeeded. The
    /// gateway didn't crash (soft-fail by design), but it also
    /// can't verify any token from this issuer until refresh
    /// catches up. Surfaces as `auth.jwks_unavailable` so
    /// operators see "JWKS issue at `IdP` X" rather than the more
    /// alarming `auth.signature_invalid` they'd see if we
    /// silently fell back to e.g. an empty key.
    KeysUnavailable,
    /// The issuer carries no accepted algorithms, so there is nothing to
    /// verify a signature against.
    ///
    /// `TrustedIssuerConfig::validate` rejects an empty list, and every
    /// construction path inside this crate runs it, so a configured issuer
    /// cannot reach this. It stays reachable because `algorithms` is a public
    /// field: a caller holding `&mut TrustedIssuer` can empty it after a valid
    /// build. Rejecting the token is the only safe response. Treating an empty
    /// list as "accept any algorithm" would let an attacker pick the algorithm,
    /// which is the classic JWT confusion attack.
    NoAlgorithms,
    /// jsonwebtoken's own validation outcome (signature, exp,
    /// nbf, iss, aud, algorithm).
    Jwt(jsonwebtoken::errors::Error),
}

/// Validate the token against the matched issuer's config:
/// `kid`-driven key selection, then signature, exp, nbf, aud, iss.
///
/// Two-step lookup:
///   1. Decode just the JWT header (no signature check yet) to
///      read the `kid` claim. We don't trust the result for
///      authorization decisions — we use it only to pick a
///      candidate key from the issuer's `KeyStore`.
///   2. If a key is found, run jsonwebtoken's full validation
///      against it. Failure modes (bad sig, expired, etc.) flow
///      through unchanged.
///   3. If no key matches, return `UnknownKid` — distinct from
///      `InvalidSignature` so operators can tell rotation lag
///      from a forgery attempt at the audit layer.
fn validate_token(
    token: &str,
    issuer: &TrustedIssuer,
) -> Result<jsonwebtoken::TokenData<ClaimMap>, ValidateError> {
    let header = jsonwebtoken::decode_header(token).map_err(ValidateError::Jwt)?;
    let kid = header.kid.as_deref();

    // Acquire a read guard on the issuer's KeyStore. The guard is
    // held for the duration of `decode()` below — sync, no .await
    // between acquire and release, so no risk of deadlock against
    // the refresh task's write lock. Refresh writes block until
    // outstanding readers release; a verify in flight when refresh
    // fires waits a few µs at most.
    let keys = issuer
        .keys
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if keys.is_empty() {
        return Err(ValidateError::KeysUnavailable);
    }

    let key = match keys.select(kid) {
        Some(k) => k,
        None => return Err(ValidateError::UnknownKid(kid.map(String::from))),
    };

    let Some(&primary) = issuer.algorithms.first() else {
        return Err(ValidateError::NoAlgorithms);
    };
    let mut validation = Validation::new(primary);
    validation.algorithms = issuer.algorithms.clone();
    validation.set_issuer(&[&issuer.issuer]);
    // `nbf` is off by default in jsonwebtoken, unlike `exp`. Leaving it off
    // accepts a token whose own issuer says it is not valid yet, which is how a
    // credential minted ahead of time becomes usable the moment it is minted.
    // The same `leeway` below covers clock skew between us and the IdP.
    validation.validate_nbf = true;
    validation.leeway = if issuer.leeway_seconds == 0 {
        DEFAULT_LEEWAY_SECONDS
    } else {
        issuer.leeway_seconds
    };
    if issuer.audiences.is_empty() {
        validation.validate_aud = false;
    } else {
        let aud_refs: Vec<&str> = issuer.audiences.iter().map(String::as_str).collect();
        validation.set_audience(&aud_refs);
    }
    decode::<ClaimMap>(token, key, &validation).map_err(ValidateError::Jwt)
}

/// Map jsonwebtoken errors to stable violation codes.
fn classify_jwt_error(e: &jsonwebtoken::errors::Error) -> (&'static str, String) {
    use jsonwebtoken::errors::ErrorKind;
    let code = match e.kind() {
        ErrorKind::ExpiredSignature => "auth.token_expired",
        ErrorKind::InvalidSignature => "auth.signature_invalid",
        ErrorKind::ImmatureSignature => "auth.token_not_yet_valid",
        ErrorKind::InvalidAudience => "auth.audience_mismatch",
        ErrorKind::InvalidIssuer => "auth.untrusted_issuer",
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => "auth.algorithm_mismatch",
        ErrorKind::Base64(_) | ErrorKind::Json(_) => "auth.malformed_header",
        _ => "auth.token_invalid",
    };
    (code, e.to_string())
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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    fn jwt_with_payload(payload_json: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fake-signature");
        format!("{header}.{payload}.{sig}")
    }

    /// Name a `ValidateError` variant for an assertion message. The enum
    /// carries no `Debug`, and "the error was wrong" without saying which error
    /// is the difference between a one-minute and a ten-minute diagnosis.
    fn variant_of(e: &ValidateError) -> String {
        match e {
            ValidateError::UnknownKid(kid) => format!("UnknownKid({kid:?})"),
            ValidateError::KeysUnavailable => "KeysUnavailable".to_owned(),
            ValidateError::NoAlgorithms => "NoAlgorithms".to_owned(),
            ValidateError::Jwt(inner) => format!("Jwt({inner})"),
        }
    }

    fn cfg_with_config(name: &str, config: Value) -> PluginConfig {
        PluginConfig {
            name: name.into(),
            config: Some(config),
            ..Default::default()
        }
    }

    /// An issuer whose accepted-algorithm list has been emptied after a valid
    /// build must reject every token rather than abort, and rejecting is the
    /// only safe answer: an empty list read as "any algorithm is acceptable"
    /// hands algorithm choice to whoever minted the token.
    ///
    /// `TrustedIssuerConfig::validate` blocks this at configuration time, so
    /// the state is only reachable through the public `algorithms` field. The
    /// test constructs it directly for that reason.
    #[test]
    fn empty_algorithm_list_rejects_the_token() {
        let issuer = TrustedIssuer {
            issuer: "https://idp.example".into(),
            audiences: vec![],
            keys: std::sync::Arc::new(std::sync::RwLock::new(KeyStore::single_fallback(
                jsonwebtoken::DecodingKey::from_secret(b"secret"),
            ))),
            algorithms: vec![],
            leeway_seconds: 0,
        };
        let token = jwt_with_payload(r#"{"iss":"https://idp.example","sub":"alice"}"#);

        let err = validate_token(&token, &issuer)
            .expect_err("an issuer with no algorithms cannot verify anything");
        assert!(
            matches!(err, ValidateError::NoAlgorithms),
            "an empty algorithm list must surface as NoAlgorithms, not as a \
             signature or kid failure that hides the configuration fault"
        );
    }

    #[test]
    fn new_rejects_missing_config_block() {
        let cfg = PluginConfig {
            name: "jwt".into(),
            config: None,
            ..Default::default()
        };
        let err = JwtIdentityResolver::new(cfg).expect_err("missing config should fail");
        assert!(format!("{err}").contains("config"));
    }

    #[test]
    fn new_rejects_empty_trusted_issuers() {
        let cfg = cfg_with_config("jwt", json!({ "trusted_issuers": [] }));
        let err = JwtIdentityResolver::new(cfg).expect_err("empty trusted_issuers should fail");
        assert!(format!("{err}").contains("trusted_issuers"));
    }

    /// A config carrying the test issuer plus whatever mapper settings the case
    /// needs. Every claim-map test goes through `new` like production does.
    fn cfg_with_mapper(settings: Value) -> PluginConfig {
        let mut config = json!({
            "trusted_issuers": [{
                "issuer": "https://idp.example.com",
                "algorithms": ["HS256"],
                "decoding_key": { "kind": "secret", "secret": "x" },
            }],
        });
        if let (Some(target), Some(extra)) = (config.as_object_mut(), settings.as_object()) {
            for (key, value) in extra {
                target.insert(key.clone(), value.clone());
            }
        }
        cfg_with_config("jwt", config)
    }

    fn build_err(settings: Value) -> String {
        format!(
            "{}",
            JwtIdentityResolver::new(cfg_with_mapper(settings))
                .expect_err("this config must not build")
        )
    }

    #[test]
    fn new_rejects_unknown_claim_mapper() {
        let err = build_err(json!({"claim_mapper": "made-up-mapper"}));
        assert!(err.contains("claim_mapper"), "{err}");
        assert!(err.contains("made-up-mapper"), "{err}");
        for name in presets::names() {
            assert!(err.contains(name), "'{name}' missing from: {err}");
        }
    }

    /// The two mapper settings are alternatives, not layers, so setting both is
    /// a mistake with no coherent reading. The message names both.
    /// Every field in this config is optional or defaulted, so a misspelling
    /// would deserialize to the default and take effect silently. `claim_maps`
    /// is the one that matters most: the resolver would stay on the standard
    /// preset while the operator believed their map was live.
    #[test]
    fn new_rejects_a_misspelled_config_key_and_names_it() {
        for typo in [
            "claim_maps",
            "claim_mappers",
            "roles",
            "headers",
            "trusted_issuer",
        ] {
            let err = build_err(json!({typo: "whatever"}));
            assert!(
                err.contains(typo),
                "a misspelled `{typo}` must be named, not ignored: {err}"
            );
        }
    }

    /// The same hole one level down, and this one is a validation bypass rather
    /// than a surprise: `audiences` is defaulted and an empty list turns audience
    /// checking off, so a misspelling would silently accept a token minted for
    /// any audience.
    #[test]
    fn new_rejects_a_misspelled_issuer_key_rather_than_dropping_audience_validation() {
        let err = format!(
            "{}",
            JwtIdentityResolver::new(cfg_with_config(
                "jwt",
                json!({
                    "trusted_issuers": [{
                        "issuer": "https://idp.example.com",
                        "audience": ["my-api"],
                        "algorithms": ["HS256"],
                        "decoding_key": { "kind": "secret", "secret": "x" },
                    }],
                }),
            ))
            .expect_err("a misspelled `audiences` must not silently disable aud validation")
        );
        assert!(err.contains("audience"), "{err}");
    }

    /// The rejection must not be so eager that a valid config stops building.
    #[test]
    fn every_documented_config_key_is_still_accepted() {
        JwtIdentityResolver::new(cfg_with_config(
            "jwt",
            json!({
                "trusted_issuers": [{
                    "issuer": "https://idp.example.com",
                    "audiences": ["my-api"],
                    "algorithms": ["HS256"],
                    "decoding_key": { "kind": "secret", "secret": "x" },
                    "leeway_seconds": 30,
                }],
                "role": "client",
                "header": "X-Client-Token",
                "claim_mapper": "keycloak",
            }),
        ))
        .expect("every documented key together must still build");
    }

    /// A dotted override entry matches nothing, so the resolver refuses it at
    /// load rather than starting with a claim the operator meant to drop still
    /// visible to policy.
    #[test]
    fn new_rejects_a_dotted_claim_override() {
        let err = build_err(json!({"claims": {"exclude": ["realm_access.roles"]}}));
        assert!(err.contains("realm_access.roles"), "{err}");
        assert!(err.contains("exclude"), "{err}");
    }

    /// A workload identity has no claims bag, so the overrides cannot do
    /// anything. Building still succeeds, with a warning, which is how the
    /// undeclared anchor is handled one field over.
    #[test]
    fn a_workload_resolver_still_builds_with_claims_overrides_it_cannot_use() {
        JwtIdentityResolver::new(cfg_with_mapper(json!({
            "role": "caller_workload",
            "claims": {"include": ["iss"]},
        })))
        .expect("the overrides are inert here, not a config error");
    }

    #[test]
    fn new_rejects_both_claim_mapper_and_claim_map() {
        let err = build_err(json!({
            "claim_mapper": "keycloak",
            "claim_map": {"subject": {"id": "sub"}},
        }));
        assert!(err.contains("claim_mapper"), "{err}");
        assert!(err.contains("claim_map"), "{err}");
    }

    /// An absent setting and the `standard` name are the same thing, and both
    /// have to keep working: an upgrading deployment changes neither.
    /// The claims-bag overrides are a sibling of the two mapper fields, so they
    /// build alongside either one.
    #[test]
    fn claims_overrides_build_with_a_preset_and_with_an_inline_map() {
        for settings in [
            json!({"claim_mapper": "keycloak", "claims": {"include": ["iss"]}}),
            json!({
                "claim_map": {"subject": {"id": "sub"}},
                "claims": {"exclude": ["internal_debug"]},
            }),
            json!({"claims": {"include": ["iss"], "exclude": ["jti"]}}),
        ] {
            JwtIdentityResolver::new(cfg_with_mapper(settings.clone()))
                .unwrap_or_else(|e| panic!("{settings} must build: {e}"));
        }
    }

    /// A malformed or incoherent overrides block fails at load naming `claims`,
    /// rather than quietly dropping the overrides an operator asked for.
    #[test]
    fn a_bad_claims_block_is_refused_at_load_and_names_the_field() {
        for settings in [
            json!({"claims": {"exclude": "iss"}}),
            json!({"claims": {"include": 42}}),
            json!({"claims": ["iss"]}),
            json!({"claims": {"excludes": ["iss"]}}),
            json!({"claims": {"exclude": ["tenant"], "include": ["tenant"]}}),
        ] {
            let err = build_err(settings.clone());
            assert!(err.contains("claims"), "{settings}: {err}");
        }
    }

    /// The claim named in both lists is the one the message has to identify.
    #[test]
    fn a_claim_in_both_override_lists_is_named() {
        let err = build_err(json!({
            "claims": {"exclude": ["tenant", "jti"], "include": ["tenant"]}
        }));
        assert!(err.contains("tenant"), "{err}");
        assert!(err.contains("exclude") && err.contains("include"), "{err}");
    }

    #[test]
    fn an_absent_mapper_and_the_standard_name_both_build() {
        for settings in [json!({}), json!({"claim_mapper": "standard"})] {
            JwtIdentityResolver::new(cfg_with_mapper(settings.clone()))
                .unwrap_or_else(|e| panic!("{settings} must build: {e}"));
        }
    }

    #[test]
    fn every_shipped_preset_builds_a_resolver_for_a_role_it_declares() {
        for name in presets::names() {
            JwtIdentityResolver::new(cfg_with_mapper(json!({"claim_mapper": name})))
                .unwrap_or_else(|e| panic!("'{name}' must build for the default role: {e}"));
            JwtIdentityResolver::new(cfg_with_mapper(json!({
                "claim_mapper": name, "role": "client",
            })))
            .unwrap_or_else(|e| panic!("'{name}' must build for role: client: {e}"));
        }
    }

    /// `keycloak` is the case that motivated the work: it was rejected before,
    /// because only `standard` was a name the resolver knew.
    #[test]
    fn a_provider_preset_builds_where_it_previously_failed() {
        JwtIdentityResolver::new(cfg_with_mapper(json!({"claim_mapper": "keycloak"})))
            .expect("keycloak must build");
    }

    /// No provider preset has a workload shape, so pairing one with
    /// `role: workload` fails at load naming the role, which beats a section of
    /// guesses about a shape the provider does not mint.
    #[test]
    fn a_preset_without_a_workload_section_refuses_the_workload_role() {
        for name in ["auth0", "cognito", "keycloak"] {
            let err = build_err(json!({"claim_mapper": name, "role": "workload"}));
            assert!(err.contains("workload"), "'{name}': {err}");
        }
        JwtIdentityResolver::new(cfg_with_mapper(json!({
            "claim_mapper": "standard", "role": "workload",
        })))
        .expect("standard declares a workload section");
    }

    #[test]
    fn an_inline_claim_map_builds() {
        JwtIdentityResolver::new(cfg_with_mapper(json!({
            "claim_map": {
                "subject": {
                    "id": "sub",
                    "roles": {
                        "paths": ["realm_access.roles", "resource_access.my-api.roles"],
                        "merge": "union",
                    },
                }
            }
        })))
        .expect("an inline map must build");
    }

    /// A map that declares the wrong section fails at load rather than denying
    /// every request, which is the whole point of checking at construction.
    #[test]
    fn an_inline_claim_map_missing_the_configured_role_names_the_role() {
        let err = build_err(json!({
            "claim_map": {"subject": {"id": "sub"}},
            "role": "client",
        }));
        assert!(err.contains("client"), "{err}");
    }

    #[test]
    fn a_malformed_path_in_an_inline_claim_map_names_the_field_and_the_path() {
        let err = build_err(json!({
            "claim_map": {"subject": {"id": "sub", "roles": "realm_access..roles"}}
        }));
        assert!(err.contains("subject.roles"), "{err}");
        assert!(err.contains("realm_access..roles"), "{err}");
    }

    /// A map of the wrong JSON shape entirely fails at construction, not at the
    /// first request.
    #[test]
    fn an_inline_claim_map_of_the_wrong_shape_is_refused_at_load() {
        for map in [
            json!({"claim_map": "standard"}),
            json!({"claim_map": {"subjekt": {"id": "sub"}}}),
            json!({"claim_map": {"subject": {"id": 42}}}),
            json!({"claim_map": {"subject": {"id": "sub"}, "claims": {"exclude": "iss"}}}),
        ] {
            let Err(err) = JwtIdentityResolver::new(cfg_with_mapper(map.clone())) else {
                panic!("{map} must not build");
            };
            let err = format!("{err}");
            assert!(
                err.contains("praxis-policy-plugin-identity-jwt"),
                "{map}: the message must name the plugin: {err}"
            );
        }
    }

    #[test]
    fn new_accepts_well_formed_config() {
        let cfg = cfg_with_config(
            "jwt",
            json!({
                "trusted_issuers": [{
                    "issuer": "https://idp.example.com",
                    "audiences": ["my-api"],
                    "algorithms": ["HS256"],
                    "decoding_key": { "kind": "secret", "secret": "test-secret" },
                    "leeway_seconds": 30,
                }],
                "claim_mapper": "standard",
            }),
        );
        let resolver = JwtIdentityResolver::new(cfg).expect("should construct");
        let issuers = resolver.trusted_issuers.read().unwrap();
        assert_eq!(issuers.len(), 1);
        assert_eq!(issuers[0].issuer, "https://idp.example.com");
        // Secret source resolves eagerly — no pending JWKS work.
        assert!(resolver.pending_jwks.is_empty());
    }

    #[test]
    fn peek_issuer_extracts_iss() {
        let token = jwt_with_payload(r#"{"sub":"alice","iss":"https://idp.example.com"}"#);
        assert_eq!(
            peek_issuer(&token),
            Some("https://idp.example.com".to_owned()),
        );
    }

    #[test]
    fn peek_issuer_returns_none_for_malformed_token() {
        assert!(peek_issuer("not.a-jwt").is_none());
        assert!(peek_issuer("a.b.c.d").is_none());
        assert!(peek_issuer("").is_none());
    }

    #[test]
    fn peek_issuer_returns_none_when_iss_missing() {
        let token = jwt_with_payload(r#"{"sub":"alice"}"#);
        assert!(peek_issuer(&token).is_none());
    }

    #[test]
    fn classify_picks_expected_codes() {
        use jsonwebtoken::errors::{Error, ErrorKind};
        let cases = [
            (ErrorKind::ExpiredSignature, "auth.token_expired"),
            (ErrorKind::InvalidSignature, "auth.signature_invalid"),
            (ErrorKind::ImmatureSignature, "auth.token_not_yet_valid"),
            (ErrorKind::InvalidAudience, "auth.audience_mismatch"),
            (ErrorKind::InvalidIssuer, "auth.untrusted_issuer"),
        ];
        for (kind, expected_code) in cases {
            let err = Error::from(kind);
            let (code, _reason) = classify_jwt_error(&err);
            assert_eq!(code, expected_code);
        }
    }

    // ---- where the token comes from ---------------------------------------
    //
    // Every existing test hands the resolver a populated `raw_token`, so the
    // header-resolution branch was never exercised. It is what decides whether
    // this resolver finds its credential at all, and each failure has to deny
    // rather than fall through: a resolver that returned Allow on a missing
    // header would leave the identity slot empty and any downstream
    // `require(authenticated)` reading as satisfied-by-absence.

    use praxis_policy_core::identity::TokenSource;
    use std::collections::HashMap;

    /// A resolver reading a non-default header, so the tests below can control
    /// exactly which key it looks for.
    fn resolver_on_header(header: &str) -> JwtIdentityResolver {
        let cfg = cfg_with_config(
            "jwt",
            serde_json::json!({
                "trusted_issuers": [{
                    "issuer": "https://idp.example",
                    "audiences": ["test-aud"],
                    "algorithms": ["HS256"],
                    "decoding_key": { "kind": "secret", "secret": "test-secret" },
                }],
                "header": header,
                "claim_mapper": "standard",
            }),
        );
        JwtIdentityResolver::new(cfg).expect("a valid resolver config")
    }

    async fn deny_code_for(resolver: &JwtIdentityResolver, payload: IdentityPayload) -> String {
        let r = resolver
            .handle(&payload, &Extensions::default(), &mut PluginContext::new())
            .await;
        assert!(
            !r.continue_processing,
            "this input must deny, not fall through to allow"
        );
        r.violation.expect("a deny carries a violation").code
    }

    #[tokio::test]
    async fn a_missing_header_and_no_fallback_token_denies() {
        let resolver = resolver_on_header("X-User-Token");
        // Headers populated but not with ours, and no pre-extracted token, so
        // neither source yields a credential.
        let payload = IdentityPayload::new("", TokenSource::Bearer)
            .with_headers(HashMap::from([("other".to_owned(), "v".to_owned())]));
        assert_eq!(
            deny_code_for(&resolver, payload).await,
            "auth.malformed_header"
        );
    }

    /// Present but empty is its own case: the header map has the key, so the
    /// missing-header branch does not fire and an empty token would otherwise
    /// reach the parser.
    #[tokio::test]
    async fn a_present_but_empty_header_denies() {
        let resolver = resolver_on_header("x-user-token");
        let payload = IdentityPayload::new("", TokenSource::Bearer)
            .with_headers(HashMap::from([("x-user-token".to_owned(), String::new())]));
        assert_eq!(
            deny_code_for(&resolver, payload).await,
            "auth.malformed_header"
        );
    }

    /// Header lookup is case-insensitive per RFC 7230, so a config naming
    /// `X-User-Token` has to match a map keyed `x-user-token`. Getting this wrong
    /// means the credential is never found in a host that canonicalises keys.
    #[tokio::test]
    async fn the_configured_header_is_matched_case_insensitively() {
        let resolver = resolver_on_header("X-User-Token");
        let payload =
            IdentityPayload::new("", TokenSource::Bearer).with_headers(HashMap::from([(
                "x-user-token".to_owned(),
                jwt_with_payload(r#"{"iss":"https://nobody.example","sub":"alice"}"#),
            )]));
        // The token is found (so not malformed_header) and rejected later for
        // its issuer, which is what proves the lookup matched.
        assert_eq!(
            deny_code_for(&resolver, payload).await,
            "auth.untrusted_issuer",
            "a case-differing header must still be found"
        );
    }

    /// The `Bearer ` prefix is stripped. Without that, the token handed to the
    /// parser starts with "Bearer " and fails as malformed rather than being
    /// evaluated.
    #[tokio::test]
    async fn a_bearer_prefix_is_stripped_from_the_header_value() {
        let resolver = resolver_on_header("authorization");
        let token = jwt_with_payload(r#"{"iss":"https://nobody.example","sub":"alice"}"#);
        let payload =
            IdentityPayload::new("", TokenSource::Bearer).with_headers(HashMap::from([(
                "authorization".to_owned(),
                format!("Bearer {token}"),
            )]));
        assert_eq!(
            deny_code_for(&resolver, payload).await,
            "auth.untrusted_issuer",
            "the prefix must be stripped so the token itself is parsed"
        );
    }

    /// The documented fallback: with no header map populated, a host that
    /// pre-extracted one token still works. This is the back-compat path.
    #[tokio::test]
    async fn a_pre_extracted_token_is_used_when_no_header_map_is_populated() {
        let resolver = resolver_on_header("X-User-Token");
        let token = jwt_with_payload(r#"{"iss":"https://nobody.example","sub":"alice"}"#);
        let payload = IdentityPayload::new(token, TokenSource::Bearer);
        assert_eq!(
            deny_code_for(&resolver, payload).await,
            "auth.untrusted_issuer",
            "the fallback must supply the token rather than denying on the header"
        );
    }

    /// A token with no `iss` cannot be matched to a trusted issuer, so it is
    /// refused rather than checked against an arbitrary one.
    ///
    /// The code is `auth.malformed_header`, which the source shares between "not
    /// a well-formed JWT" and "no `iss` claim". Pinned as measured rather than as
    /// expected: it is arguably the wrong code for a structurally valid token
    /// that merely lacks a claim, and if that is ever split this test is where
    /// the change surfaces.
    #[tokio::test]
    async fn a_token_with_no_issuer_claim_denies() {
        let resolver = resolver_on_header("authorization");
        let payload =
            IdentityPayload::new(jwt_with_payload(r#"{"sub":"alice"}"#), TokenSource::Bearer);
        assert_eq!(
            deny_code_for(&resolver, payload).await,
            "auth.malformed_header"
        );
    }

    /// Garbage that is not a JWT at all takes the same branch, which is why the
    /// two cases currently share a code.
    #[tokio::test]
    async fn a_token_that_is_not_a_jwt_denies() {
        let resolver = resolver_on_header("authorization");
        let payload = IdentityPayload::new("not-a-jwt", TokenSource::Bearer);
        assert_eq!(
            deny_code_for(&resolver, payload).await,
            "auth.malformed_header"
        );
    }

    // ---- configuration the resolver has to refuse -------------------------

    /// Config mistakes an operator can actually make, each of which has to be
    /// refused at load rather than at the first request.
    ///
    /// The stakes differ per case but point the same way. A resolver that
    /// constructs with no usable key would deny every request in production
    /// with a message about the token instead of about the config, and one that
    /// constructs with a blank `header:` would look for a header no client can
    /// send. Failing at load turns both into a gateway that refuses to start.
    #[test]
    fn each_malformed_config_is_refused_at_load_with_a_message_naming_the_fault() {
        let cases: [(&str, Value, &str); 5] = [
            (
                "trusted_issuers is not a list",
                json!({ "trusted_issuers": "https://idp.example" }),
                "parse failed",
            ),
            (
                "an issuer entry lists no algorithms",
                json!({
                    "trusted_issuers": [{
                        "issuer": "https://idp.example",
                        "algorithms": [],
                        "decoding_key": { "kind": "secret", "secret": "x" },
                    }],
                }),
                "at least one algorithm",
            ),
            (
                "an issuer's decoding key cannot be built",
                json!({
                    "trusted_issuers": [{
                        "issuer": "https://idp.example",
                        "algorithms": ["RS256"],
                        "decoding_key": { "kind": "pem", "pem": "not a pem document" },
                    }],
                }),
                "decoding_key build failed",
            ),
            (
                "role names a host-defined slot the framework has no home for",
                json!({
                    "trusted_issuers": [{
                        "issuer": "https://idp.example",
                        "algorithms": ["HS256"],
                        "decoding_key": { "kind": "secret", "secret": "x" },
                    }],
                    "role": "auditor",
                }),
                "not yet supported",
            ),
            (
                "header is blank",
                json!({
                    "trusted_issuers": [{
                        "issuer": "https://idp.example",
                        "algorithms": ["HS256"],
                        "decoding_key": { "kind": "secret", "secret": "x" },
                    }],
                    "header": "   ",
                }),
                "non-empty HTTP header name",
            ),
        ];

        for (label, config, expected) in cases {
            let err = JwtIdentityResolver::new(cfg_with_config("jwt", config))
                .err()
                .map(|e| format!("{e}"))
                .unwrap_or_else(|| panic!("{label}: this config must not load"));
            assert!(
                err.contains(expected),
                "{label}: the message must contain {expected:?}, got: {err}"
            );
            assert!(
                err.contains("jwt"),
                "{label}: and must name the plugin instance, got: {err}"
            );
        }
    }

    /// An unrecognized `role:` string deserializes into `TokenRole::Custom`
    /// rather than failing to parse, because the variant is `untagged`. That is
    /// what makes the construction-time check above the only thing standing
    /// between a typo and a token written nowhere a `subject.*` predicate can
    /// see it. This pins the deserialization half of that pair.
    #[test]
    fn an_unrecognized_role_string_becomes_a_custom_role() {
        let role: TokenRole = serde_json::from_value(json!("auditor"))
            .expect("an untagged variant accepts any string");
        assert_eq!(role, TokenRole::Custom("auditor".to_owned()));
    }

    // ---- verify-time denials, against real signatures ---------------------

    /// Sign a claim set the way the trusted issuer in these tests expects.
    /// Tokens elsewhere in this file carry a fake signature, which is enough to
    /// test the paths that reject before verification but cannot reach anything
    /// past it.
    fn sign_with(secret: &[u8], claims: &Value) -> String {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            claims,
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .expect("signing a test token")
    }

    fn seconds_from_now(offset: i64) -> i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_secs();
        i64::try_from(now).expect("a timestamp that fits in i64") + offset
    }

    /// A well-formed token for the test issuer, plus whatever extra claims the
    /// caller merges in.
    fn valid_claims(extra: Value) -> Value {
        let mut claims = json!({
            "iss": "https://idp.example",
            "aud": "test-aud",
            "sub": "alice",
            "exp": seconds_from_now(3_600),
        });
        let map = claims.as_object_mut().expect("an object");
        for (k, v) in extra.as_object().expect("extra claims must be an object") {
            map.insert(k.clone(), v.clone());
        }
        claims
    }

    /// A resolver for the test issuer under a given token role.
    fn resolver_for_role(role: &str) -> JwtIdentityResolver {
        JwtIdentityResolver::new(cfg_with_config(
            "jwt",
            json!({
                "trusted_issuers": [{
                    "issuer": "https://idp.example",
                    "audiences": ["test-aud"],
                    "algorithms": ["HS256"],
                    "decoding_key": { "kind": "secret", "secret": "test-secret" },
                }],
                "header": "authorization",
                "role": role,
                "claim_mapper": "standard",
            }),
        ))
        .expect("a valid resolver config")
    }

    async fn result_for(
        resolver: &JwtIdentityResolver,
        token: &str,
    ) -> PluginResult<IdentityPayload> {
        let payload = IdentityPayload::new(token, TokenSource::Bearer);
        resolver
            .handle(&payload, &Extensions::default(), &mut PluginContext::new())
            .await
    }

    /// The control for everything below: a correctly signed token is accepted,
    /// the subject is populated, and the raw token is stashed under the
    /// configured role. Without this, a denial in any test below could be
    /// coming from the fixture rather than from the case under test.
    #[tokio::test]
    async fn a_correctly_signed_token_is_accepted_and_populates_the_subject() {
        let resolver = resolver_for_role("user");
        let token = sign_with(b"test-secret", &valid_claims(json!({})));
        let result = result_for(&resolver, &token).await;

        assert!(
            result.continue_processing,
            "a valid token must be accepted: {:?}",
            result.violation
        );
        let updated = result
            .modified_payload
            .expect("an accepted token replaces the payload");
        let subject = updated.subject.expect("the subject slot must be filled");
        assert_eq!(subject.id.as_deref(), Some("alice"));
        assert_eq!(
            updated
                .raw_credentials
                .expect("the raw token is stashed for forwarding plugins")
                .inbound_tokens
                .get(&TokenRole::User)
                .map(|t| t.token.as_str()),
            Some(token.as_str()),
            "the stash is keyed by the configured role"
        );
    }

    /// Signature, expiry and audience failures each get their own code. They are
    /// separated because an operator reading `auth.audience_mismatch` looks at
    /// the audience config, and one reading `auth.signature_invalid` looks at
    /// keys; collapsing them into one code sends them to the wrong place.
    #[tokio::test]
    async fn each_verification_failure_reports_its_own_code() {
        let resolver = resolver_for_role("user");

        let cases: [(&str, String, &str); 4] = [
            (
                "signed with the wrong key",
                sign_with(b"not-the-secret", &valid_claims(json!({}))),
                "auth.signature_invalid",
            ),
            (
                "already expired",
                sign_with(
                    b"test-secret",
                    &valid_claims(json!({ "exp": seconds_from_now(-3_600) })),
                ),
                "auth.token_expired",
            ),
            (
                "minted for another audience",
                sign_with(
                    b"test-secret",
                    &valid_claims(json!({ "aud": "some-other-api" })),
                ),
                "auth.audience_mismatch",
            ),
            (
                "not valid until later",
                sign_with(
                    b"test-secret",
                    &valid_claims(json!({ "nbf": seconds_from_now(3_600) })),
                ),
                "auth.token_not_yet_valid",
            ),
        ];

        for (label, token, expected) in cases {
            let payload = IdentityPayload::new(&token, TokenSource::Bearer);
            assert_eq!(
                deny_code_for(&resolver, payload).await,
                expected,
                "a token {label} must deny as {expected}"
            );
        }
    }

    /// A token whose `nbf` is barely in the future is still accepted, because
    /// the issuer's clock is not ours and the leeway exists for exactly that.
    ///
    /// This is the other half of the `nbf` case above, and the reason it is
    /// worth its own test: the obvious response to a skew complaint from
    /// production is to stop validating `nbf` at all, which would silently
    /// restore accepting a token its issuer says is not yet valid. Widening the
    /// leeway is the fix; this test fails if the check is removed instead.
    #[tokio::test]
    async fn a_token_whose_nbf_is_within_the_leeway_is_accepted() {
        let resolver = resolver_for_role("user");
        let token = sign_with(
            b"test-secret",
            &valid_claims(json!({ "nbf": seconds_from_now(30) })),
        );
        let result = result_for(&resolver, &token).await;
        assert!(
            result.continue_processing,
            "30 seconds of skew is inside the {DEFAULT_LEEWAY_SECONDS}s default \
             leeway and must be tolerated: {:?}",
            result.violation
        );
    }

    /// A token whose `iss` matches no configured issuer is refused before any
    /// key is consulted, since there is no key to consult. The signature here is
    /// valid for the test secret, so only the issuer mismatch can cause this.
    #[tokio::test]
    async fn a_token_from_an_unconfigured_issuer_denies() {
        let resolver = resolver_for_role("user");
        let token = sign_with(
            b"test-secret",
            &valid_claims(json!({ "iss": "https://attacker.example" })),
        );
        assert_eq!(
            deny_code_for(&resolver, IdentityPayload::new(&token, TokenSource::Bearer)).await,
            "auth.untrusted_issuer"
        );
    }

    /// Each role reads a different claim to build its principal, and a token
    /// that verifies but carries the wrong claims cannot fill the slot. Denying
    /// is the only safe answer: continuing would leave `subject.*` unset while
    /// the request looks authenticated, so a rule requiring a subject would pass
    /// a request that has none.
    #[tokio::test]
    async fn a_verified_token_missing_the_claims_its_role_needs_denies() {
        // `sub` is what the user role maps; an empty override drops it.
        let mut without_sub = valid_claims(json!({}));
        without_sub
            .as_object_mut()
            .expect("an object")
            .remove("sub");

        let cases: [(&str, &str, Value); 3] = [
            ("user", "no `sub` claim", without_sub),
            (
                "client",
                "no `client_id` or `azp` claim",
                valid_claims(json!({})),
            ),
            (
                "caller_workload",
                "a `sub` that is not a SPIFFE id",
                valid_claims(json!({ "sub": "alice" })),
            ),
        ];

        for (role, label, claims) in cases {
            let resolver = resolver_for_role(role);
            let token = sign_with(b"test-secret", &claims);
            assert_eq!(
                deny_code_for(&resolver, IdentityPayload::new(&token, TokenSource::Bearer)).await,
                "auth.mapping_failed",
                "role {role} with {label} must deny as a mapping failure"
            );
        }
    }

    /// The counterpart to the case above: given the claims each role does need,
    /// the matching slot is filled. Without this the test above would pass even
    /// if every role mapped nothing at all.
    #[tokio::test]
    async fn each_role_fills_its_own_slot_when_the_claims_are_present() {
        let client = result_for(
            &resolver_for_role("client"),
            &sign_with(
                b"test-secret",
                &valid_claims(json!({ "client_id": "gateway-app" })),
            ),
        )
        .await
        .modified_payload
        .expect("a verified client token is accepted");
        assert_eq!(
            client.client.map(|c| c.client_id),
            Some("gateway-app".to_owned())
        );

        let workload = result_for(
            &resolver_for_role("caller_workload"),
            &sign_with(
                b"test-secret",
                &valid_claims(json!({ "sub": "spiffe://example.org/ns/default/sa/api" })),
            ),
        )
        .await
        .modified_payload
        .expect("a verified workload token is accepted");
        assert!(
            workload.caller_workload.is_some(),
            "a SPIFFE-shaped sub must fill the caller workload slot"
        );
    }

    /// An issuer whose `KeyStore` is empty is the soft-fail boot state: the
    /// initial JWKS fetch failed and the refresh task has not yet recovered.
    /// That must report as unavailable keys rather than as a bad token, because
    /// the token is fine and the fault is upstream.
    #[test]
    fn an_issuer_with_no_keys_reports_unavailable_rather_than_blaming_the_token() {
        let issuer = TrustedIssuer {
            issuer: "https://idp.example".into(),
            audiences: vec![],
            keys: std::sync::Arc::new(std::sync::RwLock::new(KeyStore::empty())),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            leeway_seconds: 0,
        };
        let token = sign_with(b"test-secret", &valid_claims(json!({})));
        let err = validate_token(&token, &issuer).expect_err("no keys, no verification");
        assert!(
            matches!(err, ValidateError::KeysUnavailable),
            "an empty KeyStore must surface as KeysUnavailable, got {}",
            variant_of(&err)
        );
    }

    /// With a kid-indexed store, a token whose `kid` matches nothing is a
    /// distinct failure from a bad signature: it usually means the issuer
    /// rotated and the refresh has not landed. Conflating it with
    /// `signature_invalid` would point an operator at the wrong thing.
    #[test]
    fn a_token_whose_kid_matches_no_key_is_reported_as_an_unknown_kid() {
        let issuer = TrustedIssuer {
            issuer: "https://idp.example".into(),
            audiences: vec![],
            keys: std::sync::Arc::new(std::sync::RwLock::new(KeyStore::from_jwks_entries([(
                "key-1".to_owned(),
                jsonwebtoken::DecodingKey::from_secret(b"test-secret"),
            )]))),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            leeway_seconds: 0,
        };

        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("key-2".to_owned());
        let token = jsonwebtoken::encode(
            &header,
            &valid_claims(json!({})),
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .expect("signing a test token");

        let err = validate_token(&token, &issuer).expect_err("kid key-2 is not in the store");
        assert!(
            matches!(err, ValidateError::UnknownKid(Some(ref k)) if k == "key-2"),
            "the unknown kid must be named so an operator can compare it against \
             the issuer's JWKS, got {}",
            variant_of(&err)
        );

        // The control: the kid that is in the store verifies, so the failure
        // above is attributable to the kid and not to the fixture.
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("key-1".to_owned());
        let good = jsonwebtoken::encode(
            &header,
            &valid_claims(json!({})),
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .expect("signing a test token");
        assert!(
            validate_token(&good, &issuer).is_ok(),
            "the kid present in the store must verify"
        );
    }
}
