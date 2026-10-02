// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PluginFactory` for the ForwardAuth resolver, so every host wires it the same
// way.
//
// Operators declare it as:
//
//     plugins:
//       - name: dashboard-session
//         kind: identity/forward_auth
//         hooks: [identity.resolve]
//         on_error: fail
//         capabilities: [perform_http]
//         config:
//           endpoint: http://127.0.0.1:4180/oauth2/auth
//           forward_headers: [cookie]
//           claim_map:
//             subject:
//               id: x-auth-request-user
//               teams: x-auth-request-groups
//           claims:
//             include: [x-auth-request-email]
//
// The `kind: identity/forward_auth` string is part of this crate's public API.

use std::sync::Arc;

use praxis_policy_core::{
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    identity::{HOOK_IDENTITY_RESOLVE, IdentityHook},
    plugin::PluginConfig,
};

use crate::plugins::identity_forward_auth::ForwardAuthResolver;

/// The plugin `kind:` string operators write in PPE YAML.
pub const KIND: &str = "identity/forward_auth";

/// Factory for `kind: identity/forward_auth` plugins.
pub struct ForwardAuthFactory;

impl PluginFactory for ForwardAuthFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let resolver = Arc::new(ForwardAuthResolver::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(
            &resolver,
        )));
        Ok(PluginInstance {
            plugin: resolver,
            handlers: vec![(HOOK_IDENTITY_RESOLVE, handler)],
        })
    }
}
