// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PluginFactory` for the Basic resolver, so every host wires it the same way.
//
// Operators declare it as:
//
//     plugins:
//       - name: ops-basic
//         kind: identity/basic
//         hooks: [identity.resolve]
//         config:
//           realm: "ops"
//           credential:
//             kind: header
//             name: Authorization
//           provider:
//             kind: htpasswd
//             path: /etc/ppe/htpasswd
//             refresh_secs: 30
//             max_staleness_secs: 300
//           record_map:
//             subject:
//               id: user_id
//
// The `kind: identity/basic` string is part of this crate's public API.
//
// One such resolver per route. Two of them means "try each directory by
// user-id" with order-dependent results, and the engine offers no seam to
// reject that at load without hardcoding a builtin's `kind` into the engine,
// so the constraint is stated in the operator documentation instead.

use std::sync::Arc;

use praxis_policy_core::{
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    identity::{HOOK_IDENTITY_RESOLVE, IdentityHook},
    plugin::PluginConfig,
};

use crate::plugins::identity_basic::BasicIdentityResolver;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The plugin `kind:` string operators write in PPE YAML.
pub const KIND: &str = "identity/basic";

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/// Factory for `kind: identity/basic` plugins.
pub struct BasicIdentityFactory;

impl PluginFactory for BasicIdentityFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let resolver = Arc::new(BasicIdentityResolver::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(
            &resolver,
        )));
        Ok(PluginInstance {
            plugin: resolver,
            handlers: vec![(HOOK_IDENTITY_RESOLVE, handler)],
        })
    }
}
