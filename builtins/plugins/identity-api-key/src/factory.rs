// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PluginFactory` for the API key resolver, so every host wires it the same
// way.
//
// Operators declare it as:
//
//     plugins:
//       - name: maas-keys
//         kind: identity/api-key
//         hooks: [identity.resolve]
//         config:
//           credential:
//             kind: header
//             name: Authorization
//           prefix: "Bearer sk-oai-"
//           provider:
//             kind: file
//             path: /etc/ppe/keys.yaml
//             index: sha256
//             refresh_secs: 30
//           record_map:
//             subject:
//               id: user
//               roles: groups
//           claims:
//             include: [tenant]
//
// The `kind: identity/api-key` string is part of this crate's public API.

use std::sync::Arc;

use praxis_policy_core::{
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    identity::{HOOK_IDENTITY_RESOLVE, IdentityHook},
    plugin::PluginConfig,
};

use crate::ApiKeyIdentityResolver;

/// The plugin `kind:` string operators write in PPE YAML.
pub const KIND: &str = "identity/api-key";

/// Factory for `kind: identity/api-key` plugins.
pub struct ApiKeyIdentityFactory;

impl PluginFactory for ApiKeyIdentityFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let resolver = Arc::new(ApiKeyIdentityResolver::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(
            &resolver,
        )));
        Ok(PluginInstance {
            plugin: resolver,
            handlers: vec![(HOOK_IDENTITY_RESOLVE, handler)],
        })
    }
}
