// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Factory: registers the emitter under every CMF hook the operator lists
// in `hooks:`, or, with none listed, hands it back with no handlers so the
// engine attaches it as an audit sink. Structurally identical to the
// audit-logger factory (`TypedHandlerAdapter<CmfHook, _>` per hook name).

//! Plugin factory for the `audit/ocsf` kind.

use std::sync::Arc;

use praxis_policy_core::{
    cmf::CmfHook,
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
};

use crate::emitter::OcsfAuditEmitter;

/// `kind:` string operators write in the plugin config to declare an OCSF
/// audit emitter instance.
pub const KIND: &str = "audit/ocsf";

/// Builds [`OcsfAuditEmitter`] instances from plugin config entries.
pub struct OcsfAuditFactory;

impl PluginFactory for OcsfAuditFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        // The engine retains its authoritative PluginConfig after this
        // call, independently of the copy held by the emitter. Reject an
        // inline private key before cloning: redacting the emitter's copy
        // cannot remove the key from PluginRef::trusted_config or the
        // engine's policy snapshot.
        if config
            .config
            .as_ref()
            .and_then(|raw| raw.get("signing_key_pem"))
            .is_some()
        {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-ocsf-audit): signing_key_pem is not \
                     accepted through the factory; use signing_key_pem_path so the engine does \
                     not retain an inline private key",
                    config.name
                ),
            }));
        }
        let emitter = Arc::new(OcsfAuditEmitter::new(config.clone())?);

        // Make the inferred mode explicit in the startup log (as the
        // audit-logger factory does): the audit-only sink is the recommended
        // mode, but an operator who meant to list hooks and lost them to a
        // YAML slip should be able to catch it here.
        if config.hooks.is_empty() {
            // Audit-only sink mode: no CMF post-hook handlers; the plugin
            // attaches as a decision-audit sink instead (see
            // `Plugin::as_audit_handler` in emitter.rs) and fires at every
            // pipeline verdict, denials included.
            tracing::info!(
                plugin = %config.name,
                "ocsf-audit '{}' running in audit-only sink mode (no `hooks:` listed): \
                 attaches to the executor verdict path; if you meant to observe \
                 specific CMF hooks, list them under `hooks:`",
                config.name,
            );
            return Ok(PluginInstance {
                plugin: emitter,
                handlers: Vec::new(),
            });
        }
        tracing::info!(
            plugin = %config.name,
            hooks = ?config.hooks,
            "ocsf-audit '{}' running as a CMF post-hook observer on {:?}: this path \
             sees allowed traffic only; audit-only sink mode (no `hooks:`) also \
             records denials. (Avoid cmf.prompt_post_fetch: the runtime dispatches \
             cmf.prompt_post_invoke; a handler on the _fetch name silently never fires.)",
            config.name,
            config.hooks,
        );

        let handlers: Vec<_> = config
            .hooks
            .iter()
            .map(|h| -> (&'static str, _) {
                let leaked: &'static str = Box::leak(h.clone().into_boxed_str());
                let adapter: Arc<dyn praxis_policy_core::registry::AnyHookHandler> =
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&emitter)));
                (leaked, adapter)
            })
            .collect();

        Ok(PluginInstance {
            plugin: emitter,
            handlers,
        })
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::cmf::{Message, MessagePayload, Role};
    use praxis_policy_core::config::parse_config;
    use praxis_policy_core::context::PluginContext;
    use praxis_policy_core::engine::PolicyEngine;
    use praxis_policy_core::error::PluginViolation;
    use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
    use praxis_policy_core::plugin::{OnError, PluginMode};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A config the factory accepts, with `hooks` left to the caller so each
    /// test can vary the one thing it is about.
    fn cfg(hooks: Vec<String>) -> PluginConfig {
        PluginConfig {
            name: "ocsf-audit".into(),
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
        let inst = OcsfAuditFactory
            .create(&cfg(vec!["cmf.tool_post_invoke".into()]))
            .expect("a config with one hook must build");
        assert_eq!(inst.handlers.len(), 1, "one hook, one handler");
        assert_eq!(
            inst.handlers[0].0, "cmf.tool_post_invoke",
            "the handler must be registered under the hook name from config"
        );
    }

    /// The handler list is built by mapping over `hooks`, so a single-hook
    /// test cannot distinguish "one per hook" from "exactly one, always".
    #[test]
    fn every_configured_hook_gets_its_own_handler() {
        let hooks = vec![
            "cmf.tool_pre_invoke".to_owned(),
            "cmf.tool_post_invoke".to_owned(),
            "cmf.prompt_pre_fetch".to_owned(),
        ];
        let inst = OcsfAuditFactory
            .create(&cfg(hooks.clone()))
            .expect("a config with three hooks must build");
        let names: Vec<&str> = inst.handlers.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, hooks, "one handler per hook, in config order");
    }

    /// No `hooks:` is the recommended mode: the emitter registers no
    /// per-hook handlers and attaches to the executor's verdict path
    /// instead, which is the only path that sees denials.
    #[test]
    fn empty_hooks_builds_a_sink_with_no_per_hook_handlers() {
        let Ok(inst) = OcsfAuditFactory.create(&cfg(vec![])) else {
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

    /// The chained, unsigned shape from the README's wiring section, built
    /// through the factory the way the engine would. A documented config
    /// that does not construct is a bug report waiting to be filed. The
    /// signed form needs a key on disk, which `emitter`'s own tests cover.
    #[test]
    fn the_documented_sink_config_builds_a_sink() {
        let config = PluginConfig {
            name: "ocsf-audit".into(),
            kind: KIND.into(),
            hooks: Vec::new(),
            mode: PluginMode::Audit,
            config: Some(serde_json::json!({
                "destination": "stderr",
                "chain": true,
                "authority_uid": "org-f3576cf6",
                "chain_uid": "gw-1-2026-10-12",
            })),
            ..Default::default()
        };

        let Ok(inst) = OcsfAuditFactory.create(&config) else {
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

    /// Config errors surface from the factory rather than being swallowed:
    /// the emitter refuses `signing: dsse` without a key, and the factory
    /// is the caller that an operator's startup sees.
    #[test]
    fn a_config_the_emitter_refuses_fails_the_factory() {
        let mut config = cfg(vec![]);
        config.config = Some(serde_json::json!({ "signing": "dsse" }));
        let Err(err) = OcsfAuditFactory.create(&config) else {
            panic!("signing=dsse with no key must not build");
        };
        let msg = format!("{err}");
        assert!(msg.contains("requires a key"), "unexpected error: {msg}");
    }

    #[test]
    fn inline_key_is_rejected_before_the_engine_can_retain_it() {
        for signing in ["none", "dsse"] {
            let mut config = cfg(vec![]);
            config.config = Some(serde_json::json!({
                "signing": signing,
                "signing_key_pem": "private-key-marker",
            }));
            let Err(err) = OcsfAuditFactory.create(&config) else {
                panic!("an inline key must be rejected even when signing is off");
            };
            let message = err.to_string();
            assert!(message.contains("signing_key_pem_path"), "{message}");
            assert!(!message.contains("private-key-marker"), "{message}");
        }
    }

    struct TogglePlugin {
        cfg: PluginConfig,
        calls: AtomicUsize,
    }

    impl praxis_policy_core::plugin::Plugin for TogglePlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    impl HookHandler<CmfHook> for TogglePlugin {
        async fn handle(
            &self,
            _payload: &MessagePayload,
            _ext: &praxis_policy_core::extensions::Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<MessagePayload> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                PluginResult::allow()
            } else {
                PluginResult::deny(PluginViolation::new("denied", "second request"))
            }
        }
    }

    struct ToggleFactory;

    impl PluginFactory for ToggleFactory {
        fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
            let plugin = Arc::new(TogglePlugin {
                cfg: config.clone(),
                calls: AtomicUsize::new(0),
            });
            let handler: Arc<dyn praxis_policy_core::registry::AnyHookHandler> =
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)));
            Ok(PluginInstance {
                plugin,
                handlers: vec![("cmf.tool_pre_invoke", handler)],
            })
        }
    }

    /// The configured exporter runs through the factory and engine audit
    /// seam for both verdicts, then survives a graceful shutdown on disk.
    #[tokio::test]
    async fn file_exporter_records_allow_and_deny_through_the_engine() {
        struct TempDir(std::path::PathBuf);
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir = TempDir(
            std::env::temp_dir().join(format!("ocsf-engine-export-{}", uuid::Uuid::new_v4())),
        );
        std::fs::create_dir_all(&dir.0).expect("temp directory exists");
        let path = dir.0.join("audit.ndjson");
        let yaml = format!(
            "engine_settings:\n  dispatch: hooks\nplugins:\n  - name: toggle\n    kind: test/toggle\n    hooks: [cmf.tool_pre_invoke]\n    mode: sequential\n    priority: 10\n    on_error: fail\n  - name: ocsf-audit\n    kind: audit/ocsf\n    mode: audit\n    config:\n      chain: true\n      exporters:\n        - {{ kind: file, path: {}, fsync: batch }}\n",
            path.display()
        );
        let config = parse_config(&yaml).expect("exporter config parses");
        let engine = PolicyEngine::default();
        engine.register_factory("test/toggle", Box::new(ToggleFactory));
        engine.register_factory(KIND, Box::new(OcsfAuditFactory));
        engine.load_config(config).expect("plugins load");
        engine.initialize().await.expect("plugins initialize");

        for should_deny in [false, true] {
            let payload = MessagePayload {
                message: Message::with_content(Role::Tool, vec![]),
            };
            let (result, _background) = engine
                .invoke_named::<CmfHook>(
                    "cmf.tool_pre_invoke",
                    payload,
                    praxis_policy_core::extensions::Extensions::default(),
                    None,
                )
                .await;
            assert_eq!(result.is_denied(), should_deny);
        }
        engine.shutdown().await;

        let written = std::fs::read_to_string(&path).expect("file exporter wrote records");
        let events: Vec<serde_json::Value> = written
            .lines()
            .map(|line| serde_json::from_str(line).expect("valid OCSF JSON line"))
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["action_id"], 1);
        assert_eq!(events[1]["action_id"], 2);
    }
}
