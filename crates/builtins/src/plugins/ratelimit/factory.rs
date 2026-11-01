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
    check_dispatch_with(config, cfg!(panic = "abort"))
}

/// Validate the stage using the supplied panic behavior.
fn check_dispatch_with(config: &PluginConfig, aborts: bool) -> Result<Stage, Box<PluginError>> {
    let name = config.name.as_str();
    // Limitador 0.14 panics on a condition evaluation error. The handler
    // contains that panic as a denial, which an aborting build cannot do.
    if aborts {
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use praxis_policy_core::factory::PluginFactory as _;
    use praxis_policy_core::plugin::PluginConfig;
    use praxis_policy_core::ratelimit_hook::{
        HOOK_RATELIMIT_POST_IDENTITY, HOOK_RATELIMIT_PRE_IDENTITY,
    };

    use super::{KIND, RateLimitFactory, check_dispatch_with};
    use crate::plugins::ratelimit::config::Stage;

    #[test]
    fn create_registers_one_handler_on_the_declared_stage() {
        for hook in [HOOK_RATELIMIT_PRE_IDENTITY, HOOK_RATELIMIT_POST_IDENTITY] {
            let config = PluginConfig {
                name: "app-ratelimit".to_owned(),
                kind: KIND.to_owned(),
                hooks: vec![hook.to_owned()],
                config: Some(serde_json::json!({
                    "namespace": "factory-unit",
                    "bindings": {"http_method": "http.method"},
                    "limits": [{"max": 1, "seconds": 60, "conditions": ["http_method == 'GET'"]}],
                })),
                ..Default::default()
            };

            let instance = RateLimitFactory.create(&config);
            assert!(instance.is_ok(), "{hook}: a valid config builds");
            let Ok(instance) = instance else { return };
            let hooks: Vec<&str> = instance.handlers.iter().map(|(name, _)| *name).collect();
            assert_eq!(
                hooks,
                [hook],
                "{hook}: one handler on the declared stage only"
            );
            assert_eq!(
                instance.plugin.config().name,
                "app-ratelimit",
                "{hook}: the instance reports the config it was built from"
            );
        }
    }

    #[test]
    fn create_refuses_an_invalid_limit_config() {
        let config = PluginConfig {
            name: "app-ratelimit".to_owned(),
            kind: KIND.to_owned(),
            hooks: vec![HOOK_RATELIMIT_POST_IDENTITY.to_owned()],
            config: Some(serde_json::json!({"namespace": "factory-unit", "limits": []})),
            ..Default::default()
        };

        let error = RateLimitFactory
            .create(&config)
            .err()
            .map(|error| error.to_string());
        assert!(
            error
                .as_deref()
                .is_some_and(|error| error.contains("app-ratelimit")),
            "a config with no limits is refused, naming the plugin: {error:?}"
        );
    }

    #[test]
    fn an_aborting_build_refuses_to_load() {
        let config = PluginConfig {
            name: "app-ratelimit".to_owned(),
            kind: KIND.to_owned(),
            hooks: vec![HOOK_RATELIMIT_POST_IDENTITY.to_owned()],
            ..Default::default()
        };

        let aborting = check_dispatch_with(&config, true).map_err(|error| error.to_string());
        assert!(
            matches!(&aborting, Err(error) if error.contains("app-ratelimit")
                && error.contains("panic = \"unwind\"")),
            "an aborting build cannot contain a Limitador panic: {aborting:?}"
        );
        let unwinding = check_dispatch_with(&config, false).map_err(|error| error.to_string());
        assert_eq!(
            unwinding,
            Ok(Stage::PostIdentity),
            "an unwinding build loads at the declared stage"
        );
    }
}
