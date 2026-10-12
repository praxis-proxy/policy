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
