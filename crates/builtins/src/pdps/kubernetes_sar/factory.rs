// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use praxis_policy_apl_core::step::PdpResolver;
use praxis_policy_apl_runtime::{PdpFactory, PdpHostServices};

use crate::pdps::kubernetes_sar::config::SubjectAccessReviewConfig;
use crate::pdps::kubernetes_sar::resolver::SubjectAccessReviewResolver;

/// The `kind:` of the `global.pdp[]` block this factory builds.
pub const KIND: &str = "kubernetes-sar";

/// Builds a [`SubjectAccessReviewResolver`] from a `kind: kubernetes-sar`
/// block. Needs the host's HTTP transport.
#[derive(Default)]
pub struct SubjectAccessReviewPdpFactory;

impl SubjectAccessReviewPdpFactory {
    /// A factory for `kind: kubernetes-sar` blocks.
    pub fn new() -> Self {
        Self
    }
}

impl PdpFactory for SubjectAccessReviewPdpFactory {
    fn kind(&self) -> &str {
        KIND
    }

    fn build(
        &self,
        config: &serde_yaml::Value,
        services: &PdpHostServices,
    ) -> Result<Arc<dyn PdpResolver>, Box<dyn std::error::Error + Send + Sync>> {
        let transport = services.http.clone().ok_or(
            "kubernetes-sar needs the host HTTP transport: call `set_http_transport` before \
             `load_config_yaml`",
        )?;
        let mut block = config.clone();
        if let Some(map) = block.as_mapping_mut() {
            map.remove("kind");
        }
        let config: SubjectAccessReviewConfig = serde_yaml::from_value(block)?;
        Ok(Arc::new(SubjectAccessReviewResolver::new(
            config, transport,
        )?))
    }
}
