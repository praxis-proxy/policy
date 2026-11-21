// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PluginFactory` for the Kubernetes `TokenReview` resolver.
//
// Operators declare it as:
//
//     plugins:
//       - name: k8s-identity
//         kind: identity/kubernetes-token-review
//         hooks: [identity.resolve]
//         capabilities: [perform_http]
//         config:
//           credential:
//             kind: header
//             name: Authorization
//           prefix: "Bearer "
//           api_server:
//             url: https://kubernetes.default.svc
//             reviewer_token:
//               kind: file
//               path: /var/run/secrets/kubernetes.io/serviceaccount/token
//           audiences: [praxis-gateway]
//           record_map:
//             subject:
//               id: username
//               roles: groups
//           cache:
//             ttl_secs: 30
//             negative_ttl_secs: 5
//
// The `kind: identity/kubernetes-token-review` string is part of this crate's
// public API.

use std::sync::Arc;

use praxis_policy_core::{
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    identity::{HOOK_IDENTITY_RESOLVE, IdentityHook},
    plugin::PluginConfig,
};

use crate::plugins::identity_kubernetes::TokenReviewIdentityResolver;

/// The plugin `kind:` string operators write in PPE YAML.
pub const KIND: &str = "identity/kubernetes-token-review";

/// Builds [`TokenReviewIdentityResolver`] from a config block.
pub struct TokenReviewIdentityFactory;

impl PluginFactory for TokenReviewIdentityFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let resolver = Arc::new(TokenReviewIdentityResolver::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(
            &resolver,
        )));
        Ok(PluginInstance {
            plugin: resolver,
            handlers: vec![(HOOK_IDENTITY_RESOLVE, handler)],
        })
    }
}
