// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use praxis_policy_core::error::PluginError;
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::TypedHandlerAdapter;
use praxis_policy_core::http_hook::{HOOK_HTTP_REQUEST, HttpHook};
use praxis_policy_core::plugin::PluginConfig;
use praxis_policy_core::registry::AnyHookHandler;

use super::handler::RateLimit;

/// The `kind:` value for the embedded request limiter.
pub const KIND: &str = "ratelimit/limitador";

/// Constructs an in-memory Limitador instance for one configured plugin.
pub struct RateLimitFactory;

impl PluginFactory for RateLimitFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let core = Arc::new(RateLimit::new(config.clone())?);
        let handler: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<HttpHook, _>::new(Arc::clone(&core)));
        Ok(PluginInstance {
            plugin: core,
            handlers: vec![(HOOK_HTTP_REQUEST, handler)],
        })
    }
}
