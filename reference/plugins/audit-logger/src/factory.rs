// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use praxis_policy_core::{
    cmf::CmfHook,
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
};

use crate::logger::AuditLogger;

/// `kind:` string operators write in PPE YAML to declare an audit
/// logger instance.
pub const KIND: &str = "audit/logger";

/// Constructs an [`AuditLogger`] from config.
///
/// [`AuditLogger`]: crate::logger::AuditLogger
pub struct AuditLoggerFactory;

impl PluginFactory for AuditLoggerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let logger = Arc::new(AuditLogger::new(config.clone())?);

        // No `hooks:` means sink mode: the logger registers no CMF handlers
        // and instead attaches to the executor's verdict path, where it sees
        // denied requests too. Listing hooks keeps the post-hook observer,
        // which only ever sees traffic that was allowed through.
        if config.hooks.is_empty() {
            tracing::info!(
                plugin = %config.name,
                "audit-logger '{}' running as a decision sink (no `hooks:` listed)",
                config.name,
            );
        } else {
            tracing::info!(
                plugin = %config.name,
                hooks = ?config.hooks,
                "audit-logger '{}' running as a CMF post-hook observer on {:?}",
                config.name,
                config.hooks,
            );
        }

        let handlers: Vec<_> = config
            .hooks
            .iter()
            .map(|h| -> (&'static str, _) {
                let leaked: &'static str = Box::leak(h.clone().into_boxed_str());
                let adapter: Arc<dyn praxis_policy_core::registry::AnyHookHandler> =
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&logger)));
                (leaked, adapter)
            })
            .collect();

        Ok(PluginInstance {
            plugin: logger,
            handlers,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::plugin::{OnError, PluginMode};

    /// A config the factory accepts, with `hooks` left to the caller so each
    /// test can vary the one thing it is about.
    fn cfg(hooks: Vec<String>) -> PluginConfig {
        PluginConfig {
            name: "audit".into(),
            kind: KIND.into(),
            hooks,
            mode: PluginMode::Sequential,
            priority: 50,
            on_error: OnError::Fail,
            config: Some(serde_json::json!({ "destination": "stderr" })),
            ..Default::default()
        }
    }

    #[test]
    fn one_hook_yields_one_handler_registered_under_that_hook_name() {
        let inst = AuditLoggerFactory
            .create(&cfg(vec!["cmf.tool_pre_invoke".into()]))
            .expect("a config with one hook must build");
        assert_eq!(inst.handlers.len(), 1, "one hook, one handler");
        assert_eq!(
            inst.handlers[0].0, "cmf.tool_pre_invoke",
            "the handler must be registered under the hook name from config"
        );
    }

    /// The handler list is built by mapping over `hooks`, so a single-hook test
    /// cannot distinguish "one per hook" from "exactly one, always".
    #[test]
    fn every_configured_hook_gets_its_own_handler() {
        let hooks = vec![
            "cmf.tool_pre_invoke".to_owned(),
            "cmf.tool_post_invoke".to_owned(),
            "cmf.prompt_pre_fetch".to_owned(),
        ];
        let inst = AuditLoggerFactory
            .create(&cfg(hooks.clone()))
            .expect("a config with three hooks must build");
        let names: Vec<&str> = inst.handlers.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, hooks, "one handler per hook, in config order");
    }

    /// No `hooks:` means sink mode: the logger registers no per-hook handlers
    /// and instead attaches to the executor's verdict path. The reason an
    /// empty list is no longer a config error is that this is now the
    /// recommended way to run it, and the mode that sees denied requests.
    #[test]
    fn empty_hooks_builds_a_sink_with_no_per_hook_handlers() {
        let Ok(inst) = AuditLoggerFactory.create(&cfg(vec![])) else {
            panic!("no hooks is sink mode, not an error");
        };
        assert!(
            inst.handlers.is_empty(),
            "sink mode registers no per-hook handlers"
        );
        assert!(
            inst.plugin.clone().as_audit_handler().is_some(),
            "and attaches as a decision sink instead"
        );
    }

    /// The sink-mode config in `docs/content/auditing.md`, built through the factory
    /// the way the engine would. A documented example that does not construct
    /// is a bug report waiting to be filed.
    #[test]
    fn the_documented_sink_config_builds_a_sink() {
        let config = PluginConfig {
            name: "audit".into(),
            kind: KIND.into(),
            hooks: Vec::new(),
            mode: PluginMode::Audit,
            config: Some(serde_json::json!({
                "destination": "stderr",
                "source": "gateway-eu-1",
            })),
            ..Default::default()
        };

        let Ok(inst) = AuditLoggerFactory.create(&config) else {
            panic!("the documented sink config must build");
        };
        assert!(
            inst.handlers.is_empty(),
            "sink mode registers no hook handlers"
        );
        assert!(
            inst.plugin.clone().as_audit_handler().is_some(),
            "and attaches as a decision sink"
        );
    }
}
