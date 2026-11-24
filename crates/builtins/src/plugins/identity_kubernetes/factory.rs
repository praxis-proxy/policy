// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

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
///
/// [`TokenReviewIdentityResolver`]: crate::plugins::identity_kubernetes::TokenReviewIdentityResolver
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
