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

use crate::scanner::TranscriptScanner;

/// `kind:` string operators write in PPE YAML to declare a transcript
/// scanner instance.
pub const KIND: &str = "validator/transcript-scan";

/// Factory for `kind: validator/transcript-scan`. Instantiates a
/// `TranscriptScanner` from the `config:` block and registers a handler for
/// every CMF hook name listed in `cfg.hooks`. Operators typically wire it on
/// `cmf.llm_input`, where the history is the context the model is about to
/// read, and on `cmf.tool_pre_invoke` when a tool call should not go ahead
/// on the back of a tainted conversation.
pub struct TranscriptScannerFactory;

impl PluginFactory for TranscriptScannerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let scanner = Arc::new(TranscriptScanner::new(config.clone())?);

        // A scanner wired to no hooks would load and never inspect anything.
        if config.hooks.is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-transcript-scanner): `hooks:` must list \
                     at least one CMF hook to scan on (e.g. cmf.llm_input)",
                    config.name
                ),
            }));
        }

        let handlers: Vec<_> = config
            .hooks
            .iter()
            .map(|h| -> (&'static str, _) {
                // The handler registry stores hook names as `'static`. Configs
                // are read once at startup, so the leak is bounded by the
                // number of plugin × hook pairs in config.
                let leaked: &'static str = Box::leak(h.clone().into_boxed_str());
                let adapter: Arc<dyn praxis_policy_core::registry::AnyHookHandler> =
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&scanner)));
                (leaked, adapter)
            })
            .collect();

        Ok(PluginInstance {
            plugin: scanner,
            handlers,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use praxis_policy_core::plugin::{OnError, PluginMode};

    fn cfg(hooks: Vec<String>) -> PluginConfig {
        PluginConfig {
            name: "transcript-scan".into(),
            kind: KIND.into(),
            hooks,
            mode: PluginMode::Sequential,
            priority: 10,
            on_error: OnError::Fail,
            capabilities: ["read_agent".to_owned()].into(),
            config: Some(serde_json::json!({
                "patterns": [{ "name": "x", "regex": "x" }],
            })),
            ..Default::default()
        }
    }

    #[test]
    fn every_configured_hook_gets_its_own_handler() {
        let hooks = vec!["cmf.llm_input".to_owned(), "cmf.tool_pre_invoke".to_owned()];
        let inst = TranscriptScannerFactory
            .create(&cfg(hooks.clone()))
            .expect("a config with two hooks must build");
        let names: Vec<&str> = inst.handlers.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, hooks, "one handler per hook, in config order");
    }

    #[test]
    fn empty_hooks_is_rejected_and_the_message_names_the_key() {
        // `.err()` rather than `expect_err`: PluginInstance is not Debug.
        let err = TranscriptScannerFactory
            .create(&cfg(vec![]))
            .err()
            .expect("no hooks must not build");
        assert!(
            matches!(*err, PluginError::Config { .. }),
            "expected a config error, got {err:?}"
        );
        assert!(err.to_string().contains("hooks:"), "{err}");
    }
}
