// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `CedarDirectPdpFactory` — the `PdpFactory` implementation that lets
// the praxis-policy-apl-runtime visitor instantiate `CedarDirectResolver` from a
// unified-config YAML block:
//
// ```yaml
// global:
//   apl:
//     pdp:
//       - kind: cedar-direct
//         dialect: cedar          # optional, defaults to PdpDialect::Cedar
//         policy_text: |          # required (or policy_file)
//           @id("owner-override")
//           permit(...);
// ```
//
// Hosts register an instance of this factory in `AplOptions.pdp_factories`;
// the visitor matches it to the block by `kind` and dispatches.

use std::sync::Arc;

use praxis_policy_apl_core::step::{PdpFactory, PdpResolver};

use crate::resolver::CedarDirectResolver;

/// Factory for `CedarDirectResolver`. Reports `kind() = "cedar-direct"`;
/// builds resolvers from the unified-config block via
/// [`CedarDirectResolver::from_config`].
#[derive(Default)]
pub struct CedarDirectPdpFactory;

impl CedarDirectPdpFactory {
    /// A new instance with nothing registered or stored yet.
    pub fn new() -> Self {
        Self
    }
}

impl PdpFactory for CedarDirectPdpFactory {
    fn kind(&self) -> &str {
        "cedar-direct"
    }

    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<Arc<dyn PdpResolver>, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = CedarDirectResolver::from_config(config)?;
        Ok(Arc::new(resolver))
    }
}
