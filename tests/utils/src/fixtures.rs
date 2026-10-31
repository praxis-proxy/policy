// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The ported demo policies, one per PDP, and the fixtures that extend them.
//!
//! Documents live in `tests/integration/fixtures/` and are embedded at build
//! time. Each one's header records how it departs from the demo. Every
//! document here is hermetic: endpoints name the fake hosts in
//! [`crate::idp`] and sessions use the memory store. Live mode rewrites
//! only endpoints, the session store and the Vault provider, through
//! [`Fixture::live`] and [`Targets::rewrite`], rather than keeping a second
//! set of documents.

use praxis_policy_core::http_testing::FakeTransport;

use crate::live::Targets;

/// One demo policy, named by the PDP its `search_repos` route consults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fixture {
    /// `policy.yaml`: a `cedar-direct` PDP.
    Cedar,
    /// `policy-cel.yaml`: an inline CEL expression.
    Cel,
    /// `policy-opa.yaml`: a Rego module evaluated in-process.
    Opa,
}

impl Fixture {
    /// Every variant, for a scenario that runs against all three.
    pub const ALL: [Self; 3] = [Self::Cedar, Self::Cel, Self::Opa];

    /// The PDP name, for labeling a failure.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Cedar => "cedar",
            Self::Cel => "cel",
            Self::Opa => "opa",
        }
    }

    /// The violation code the PDP step denies with.
    #[must_use]
    pub fn deny_violation(self) -> &'static str {
        match self {
            Self::Cedar => "cedar.default_deny",
            Self::Cel => "cel.policy_denied",
            Self::Opa => "opa.policy_denied",
        }
    }

    /// The document, pointed at the fake hosts.
    #[must_use]
    pub fn hermetic(self) -> &'static str {
        match self {
            Self::Cedar => include_str!("../../integration/fixtures/policy-cedar.yaml"),
            Self::Cel => include_str!("../../integration/fixtures/policy-cel.yaml"),
            Self::Opa => include_str!("../../integration/fixtures/policy-opa.yaml"),
        }
    }

    /// The document, pointed at the live `targets`.
    #[must_use]
    pub fn live(self, targets: Targets<'_>) -> String {
        targets.rewrite(self.hermetic())
    }
}

/// The `praxis-gateway` client secret every demo delegator and the CIBA
/// approver authenticate with.
pub const CLIENT_SECRET: &str = "praxis-gateway-secret";

/// A policy asserting `x-api-key` from the Vault secret [`SECRET_NAME`], with
/// a header-probe plugin on `get_directory` in both phases.
pub const SECRET_HEADER: &str = include_str!("../../integration/fixtures/secret-header.yaml");

/// The `secrets.values` name [`SECRET_HEADER`] asserts.
pub const SECRET_NAME: &str = "hr_api_key";

/// Script the Vault behind [`SECRET_HEADER`] to answer an `AppRole` login
/// and serve `api_key` as the secret's value.
#[must_use]
pub fn vault(transport: FakeTransport, api_key: &str) -> FakeTransport {
    let kv = serde_json::json!({ "data": { "data": { "api_key": api_key } } });
    transport
        .json(
            "https://vault.test/v1/auth/approle/login",
            200,
            r#"{"auth":{"client_token":"hvs.ppe-tests","lease_duration":3600,"renewable":true}}"#,
        )
        .json(
            "https://vault.test/v1/secret/data/hr-mcp",
            200,
            &kv.to_string(),
        )
}

/// Calls one client address may make through the edge limiter of
/// [`rate_limit`], with or without a valid token.
#[cfg(feature = "experimental-ratelimit")]
pub const EDGE_LIMIT: u64 = 5; // requests per client address per minute

/// Calls one subject may make through the per-user limiter of
/// [`rate_limit`].
#[cfg(feature = "experimental-ratelimit")]
pub const USER_LIMIT: u64 = 3; // requests per subject per minute

/// Calls one subject may make to `get_directory`, whose route stacks its own
/// limiter on the global ones in [`rate_limit`].
#[cfg(feature = "experimental-ratelimit")]
pub const DIRECTORY_LIMIT: u64 = 1; // requests per subject per minute

/// The demo identity plugins under a global `rate_limits:` list, at the
/// default limits.
#[cfg(feature = "experimental-ratelimit")]
#[must_use]
pub fn rate_limit() -> String {
    rate_limit_with(EDGE_LIMIT, USER_LIMIT)
}

/// [`rate_limit`] with its edge and per-user limits replaced.
///
/// `edge-limits` runs at `ratelimit.pre_identity` and counts per
/// `http.client_address`; `user-limits` runs at `ratelimit.post_identity` and
/// counts per `subject.id`. A `tool: get_directory` route adds
/// `directory-limits` at [`DIRECTORY_LIMIT`]. Every other tool matches no
/// route and runs on global policy, which allows it.
#[cfg(feature = "experimental-ratelimit")]
#[must_use]
pub fn rate_limit_with(edge_limit: u64, user_limit: u64) -> String {
    format!(
        r#"
engine_settings:
  dispatch: policy

plugins:
  - name: jwt-user
    capabilities: [perform_http]
    kind: identity/jwt
    hooks: [identity.resolve]
    mode: sequential
    on_error: fail
    config:
      role: user
      credential:
        kind: header
        name: X-User-Token
      trusted_issuers:
        - issuer: "{issuer}"
          audiences: ["{audience}"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "{jwks}"
          leeway_seconds: 60
      claim_mapper: standard

  - name: jwt-client
    capabilities: [perform_http]
    kind: identity/jwt
    hooks: [identity.resolve]
    mode: sequential
    on_error: fail
    config:
      role: client
      credential:
        kind: header
        name: Authorization
      trusted_issuers:
        - issuer: "{issuer}"
          audiences: ["{audience}"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "{jwks}"
          leeway_seconds: 60
      claim_mapper: standard

  - name: edge-limits
    kind: ratelimit/limitador
    hooks: [ratelimit.pre_identity]
    capabilities: [read_headers]
    config:
      namespace: edge-namespace
      bindings:
        client: http.client_address
      limits:
        - max: {edge_limit}
          seconds: 60
          variables: [client]

  - name: user-limits
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject]
    config:
      namespace: user-namespace
      bindings:
        subject_id: subject.id
      limits:
        - max: {user_limit}
          seconds: 60
          variables: [subject_id]

  - name: directory-limits
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject]
    config:
      namespace: directory-namespace
      bindings:
        subject_id: subject.id
      limits:
        - max: {DIRECTORY_LIMIT}
          seconds: 60
          variables: [subject_id]

global:
  authentication:
    - jwt-user
    - jwt-client
  rate_limits:
    - edge-limits
    - user-limits

routes:
  - tool: get_directory
    rate_limits: [directory-limits]
"#,
        issuer = crate::idp::ISSUER,
        audience = crate::idp::GATEWAY_AUDIENCE,
        jwks = crate::idp::JWKS_URL,
    )
}
