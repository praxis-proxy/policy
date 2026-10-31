// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use praxis_policy_core::error::PluginError;
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::TypedHandlerAdapter;
use praxis_policy_core::http_hook::HttpHook;
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};
use praxis_policy_core::registry::AnyHookHandler;

use super::config::Stage;
use super::handler::{RateLimit, config_error};

/// The `kind:` value for the embedded request limiter.
pub const KIND: &str = "ratelimit/limitador";

/// Constructs an in-memory Limitador instance for one configured plugin.
///
/// The instance registers on the one rate-limit hook its `hooks:` declares.
pub struct RateLimitFactory;

impl PluginFactory for RateLimitFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let stage = check_dispatch(config)?;
        let core = Arc::new(RateLimit::new(config.clone(), stage)?);
        let handler: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<HttpHook, _>::new(Arc::clone(&core)));
        Ok(PluginInstance {
            plugin: core,
            handlers: vec![(stage.hook(), handler)],
        })
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// The stage `config` runs at, once settings that could admit an unchecked
/// request are refused.
fn check_dispatch(config: &PluginConfig) -> Result<Stage, Box<PluginError>> {
    let name = config.name.as_str();
    // Limitador 0.14 panics on a condition evaluation error. The handler
    // contains that panic as a denial, which an aborting build cannot do.
    if cfg!(panic = "abort") {
        return Err(config_error(
            name,
            "this build aborts on panic, and Limitador panics on a condition evaluation \
             error; build the host with `panic = \"unwind\"` to use this kind",
        ));
    }
    let stage = Stage::from_hooks(&config.hooks).map_err(|message| config_error(name, message))?;
    if config.on_error != OnError::Fail {
        return Err(config_error(
            name,
            format!(
                "`on_error: {}` would admit a request the limiter could not check; remove it \
                 or set `on_error: fail`",
                config.on_error
            ),
        ));
    }
    if config.mode != PluginMode::Sequential {
        return Err(config_error(
            name,
            format!(
                "`mode: {}` cannot enforce a limit; remove it or set `mode: sequential`",
                config.mode
            ),
        ));
    }
    Ok(stage)
}
