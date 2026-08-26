// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `CelPdpFactory` — the `PdpFactory` implementation that lets the praxis-policy-apl-runtime
// visitor instantiate `CelResolver` from a unified-config YAML block:
//
// ```yaml
// global:
//   apl:
//     pdp:
//       - kind: cel
//         on_error: deny          # optional; deny | allow, default deny
// ```
//
// The CEL expression itself lives in each route's `cel: { expr: "..." }`
// step, not in this block — so the global config usually just declares the
// resolver exists. Hosts register an instance of this factory in
// `AplOptions.pdp_factories`; the visitor matches it to the block by `kind`.

use std::sync::Arc;

use praxis_policy_apl_core::step::{PdpFactory, PdpResolver};

use crate::resolver::CelResolver;

/// Factory for `CelResolver`. Reports `kind() = "cel"`; builds resolvers
/// from the unified-config block via [`CelResolver::from_config`].
#[derive(Default)]
pub struct CelPdpFactory;

impl CelPdpFactory {
    /// A new instance with nothing registered or stored yet.
    pub fn new() -> Self {
        Self
    }
}

impl PdpFactory for CelPdpFactory {
    fn kind(&self) -> &str {
        "cel"
    }

    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<Arc<dyn PdpResolver>, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = CelResolver::from_config(config)?;
        Ok(Arc::new(resolver))
    }
}
