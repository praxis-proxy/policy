// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::error::Error;
use std::sync::Arc;

use praxis_policy_apl_core::step::PdpResolver;
use praxis_policy_core::http::HttpTransport;

// -----------------------------------------------------------------------------
// PdpFactory
// -----------------------------------------------------------------------------

/// Build a [`PdpResolver`] from a unified-config block.
///
/// Implemented per PDP backend (cedar-direct, opa, …) and registered through
/// [`AplOptions::pdp_factories`], so a config document can declare a PDP
/// without the host constructing it in code. When the visitor finds a
/// `global.pdp[].kind` matching a factory's [`kind`](Self::kind), it calls
/// [`build`](Self::build) with the rest of that block and the host services
/// the engine has installed.
///
/// [`AplOptions::pdp_factories`]: crate::AplOptions::pdp_factories
pub trait PdpFactory: Send + Sync {
    /// The `kind:` this factory handles, in kebab-case matching the published
    /// PDP product name (`"cedar-direct"`, `"opa"`, …).
    fn kind(&self) -> &str;

    /// Build a resolver from the rest of the PDP config block (everything at
    /// the same map level as `kind`).
    ///
    /// A resolver that needs a host service it is not given fails here, so a
    /// misconfigured host is a config-load error rather than a denial on
    /// every request.
    ///
    /// # Errors
    ///
    /// Returns the implementation's own error when a field of its config
    /// block is missing or malformed, or when a host service it needs is
    /// absent.
    fn build(
        &self,
        config: &serde_yaml::Value,
        services: &PdpHostServices,
    ) -> Result<Arc<dyn PdpResolver>, Box<dyn Error + Send + Sync>>;
}

// -----------------------------------------------------------------------------
// PdpHostServices
// -----------------------------------------------------------------------------

/// Host services a [`PdpFactory`] may hand to the resolver it builds.
///
/// Every service is optional. A host that installs none still loads any
/// policy whose decision points do not need one.
///
/// ```
/// use praxis_policy_apl_runtime::PdpHostServices;
///
/// let services = PdpHostServices::default();
/// assert!(services.http.is_none());
/// ```
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct PdpHostServices {
    /// The host's outbound HTTP transport, for a decision point that calls
    /// an external authorizer.
    pub http: Option<Arc<dyn HttpTransport>>,
}

impl PdpHostServices {
    /// Services carrying the host's HTTP transport.
    #[must_use]
    pub fn with_http(mut self, transport: Arc<dyn HttpTransport>) -> Self {
        self.http = Some(transport);
        self
    }
}
