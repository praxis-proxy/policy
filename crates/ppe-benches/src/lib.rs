// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared fixtures for the Criterion suite (issue #19).
//!
//! Setup (YAML load, Cedar compile, plugin factory registration) runs
//! **outside** Criterion iters. Timed loops only call the hot path:
//! [`PolicyEngine::invoke_named`], `PdpResolver::evaluate`, or
//! `SessionStore` ops.
//!
//! Patterns mirror `visitor_e2e` / `visitor_pdp_config` so the benches
//! exercise the same wiring operators use in production.

#![allow(
    missing_docs,
    trivial_casts,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_raw_string_hashes,
    reason = "benchmark harness — panics surface misconfiguration immediately"
)]

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use praxis_policy_apl_runtime::{AplOptions, DispatchCache, MemorySessionStore, register_apl};
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, Message, MessagePayload};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError as CoreError;
use praxis_policy_core::extensions::{
    AgentExtension, MetaExtension, SecurityExtension, SubjectExtension, SubjectType,
};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig, PluginMode};
use praxis_policy_core::registry::AnyHookHandler;
use praxis_policy_pdp_cedar_direct::CedarDirectPdpFactory;

/// Hook name used by every engine-level bench. Matches the CMF tool
/// pre-invocation phase Praxis hits on the request path.
pub const HOOK_TOOL_PRE: &str = "cmf.tool_pre_invoke";

/// Tool name baked into the fixture YAML routes.
pub const TOOL_NAME: &str = "get_document";

// =====================================================================
// No-op plugin — zero work inside `handle`, so Criterion attributes
// wall time to the executor / registry path rather than plugin logic.
// =====================================================================

/// Pass-through plugin used to measure dispatch cost in isolation.
pub struct NoopPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for NoopPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for NoopPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

/// Factory for [`NoopPlugin`]. Kind string is `"noop"`.
pub struct NoopFactory;

impl PluginFactory for NoopFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(NoopPlugin {
            cfg: config.clone(),
        });
        let handlers = hooks_for(config, Arc::clone(&plugin));
        Ok(PluginInstance { plugin, handlers })
    }
}

fn hooks_for(
    config: &PluginConfig,
    plugin: Arc<NoopPlugin>,
) -> Vec<(&'static str, Arc<dyn AnyHookHandler>)> {
    // `PluginInstance` requires `&'static str` hook names. Bench fixtures only
    // ever use `HOOK_TOOL_PRE`, so map to that constant instead of `Box::leak`.
    let names: Vec<&'static str> = if config.hooks.is_empty() {
        vec![HOOK_TOOL_PRE]
    } else {
        config
            .hooks
            .iter()
            .map(|s| {
                assert_eq!(
                    s.as_str(),
                    HOOK_TOOL_PRE,
                    "NoopFactory bench fixtures only support {HOOK_TOOL_PRE}"
                );
                HOOK_TOOL_PRE
            })
            .collect()
    };
    names
        .into_iter()
        .map(|name| {
            let adapter: Arc<dyn AnyHookHandler> =
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)));
            (name, adapter)
        })
        .collect()
}

/// Build a [`PluginConfig`] for a no-op registered under `name`.
pub fn noop_config(name: &str, mode: PluginMode, priority: i32) -> PluginConfig {
    PluginConfig {
        name: name.to_owned(),
        kind: "noop".to_owned(),
        hooks: vec![HOOK_TOOL_PRE.to_owned()],
        mode,
        priority,
        ..Default::default()
    }
}

// =====================================================================
// Request fixtures
// =====================================================================

/// Minimal CMF text payload for tool-pre benches.
pub fn cmf_payload(text: &str) -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, text),
    }
}

/// Route-matching meta for [`TOOL_NAME`].
pub fn meta_for_tool(name: &str) -> MetaExtension {
    MetaExtension {
        entity_type: Some("tool".to_owned()),
        entity_name: Some(name.to_owned()),
        ..Default::default()
    }
}

/// Security subject with the given id and roles (Cedar / CEL bags lift these).
pub fn security_with_roles(id: &str, roles: &[&str]) -> SecurityExtension {
    SecurityExtension {
        subject: Some(SubjectExtension {
            id: Some(id.to_owned()),
            subject_type: Some(SubjectType::User),
            roles: roles
                .iter()
                .map(|r| (*r).to_owned())
                .collect::<HashSet<_>>(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Extensions for a Cedar-allowing reader hitting [`TOOL_NAME`].
pub fn extensions_reader() -> Extensions {
    Extensions {
        meta: Some(Arc::new(meta_for_tool(TOOL_NAME))),
        security: Some(Arc::new(security_with_roles("alice", &["reader"]))),
        ..Default::default()
    }
}

/// Extensions with an agent `session_id` so APL session hydrate/persist runs.
pub fn extensions_with_session(session_id: &str) -> Extensions {
    let mut ext = extensions_reader();
    ext.agent = Some(Arc::new(AgentExtension {
        session_id: Some(session_id.to_owned()),
        ..Default::default()
    }));
    ext
}

// =====================================================================
// Engine builders — all load/compile work is here (un-timed setup)
// =====================================================================

fn apl_options_with_cedar(session: Arc<MemorySessionStore>) -> AplOptions {
    AplOptions {
        dispatch_cache: Arc::new(DispatchCache::new()),
        session_store: session,
        pdps: Vec::new(),
        pdp_factories: vec![Arc::new(CedarDirectPdpFactory::new())],
        session_store_factories: Vec::new(),
        base_capabilities: None,
    }
}

/// Engine with N no-op plugins on the hook, **no** APL visitor.
///
/// Isolates plugin-executor overhead: registry lookup + mode scheduling +
/// `HookHandler::handle`. Used by `hook_overhead` and the concurrent
/// half of `throughput`.
///
/// Registers via [`PolicyEngine::register_handler_for_names`] on
/// [`HOOK_TOOL_PRE`] (not `register_handler`, which would bind under
/// `CmfHook::NAME` = `"cmf"` and never run when we invoke the tool-pre hook).
///
/// # Panics
///
/// Panics if a handler fails to register, if `count` does not fit in `i32`
/// (bench sizes are tiny), if engine initialization fails, or if a registered
/// plugin is missing from the tool-pre hook (fixture guard).
pub async fn engine_plugins_only(count: usize, mode: PluginMode) -> Arc<PolicyEngine> {
    let mgr = Arc::new(PolicyEngine::default());
    for i in 0..count {
        let name = format!("noop-{i}");
        let priority = i32::try_from(i).expect("bench plugin count fits i32");
        let cfg = noop_config(&name, mode, priority);
        let plugin = Arc::new(NoopPlugin { cfg: cfg.clone() });
        mgr.register_handler_for_names::<CmfHook, _>(plugin, cfg, &[HOOK_TOOL_PRE])
            .expect("register_handler_for_names");
    }
    mgr.initialize().await.expect("initialize");
    // Guard: empty-registry early-return looks like a fast bench. Fail loud if
    // plugins landed on the wrong hook name.
    for i in 0..count {
        let name = format!("noop-{i}");
        let entries = mgr.find_plugin_entries(&name);
        assert_eq!(
            entries.len(),
            1,
            "{name}: expected one hook entry, got {} hooks {:?}",
            entries.len(),
            entries.iter().map(|(h, _)| h.as_str()).collect::<Vec<_>>()
        );
        assert_eq!(
            entries[0].0.as_str(),
            HOOK_TOOL_PRE,
            "{name}: registered under {:?}, want {HOOK_TOOL_PRE}",
            entries[0].0
        );
    }
    mgr
}

/// YAML: one Cedar PDP + one route with a `cedar:` step (no plugins).
pub const YAML_CEDAR_ONLY: &str = r#"
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
          @id("reader-permit")
          permit(principal, action == Action::"read", resource)
          when { principal.roles.contains("reader") };
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - cedar:
            action: 'Action::"read"'
            resource:
              type: Document
              id: doc-42
"#;

/// YAML: noop plugin step only (APL path, no PDP) — plugin-via-APL cost.
pub const YAML_PLUGIN_ONLY: &str = r#"
plugins:
  - name: noop-0
    kind: noop
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - "run(noop-0)"
"#;

/// YAML: plugin then Cedar — full decision path operators actually run.
pub const YAML_PLUGIN_THEN_CEDAR: &str = r#"
plugins:
  - name: noop-0
    kind: noop
    hooks: [cmf.tool_pre_invoke]
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
          @id("reader-permit")
          permit(principal, action == Action::"read", resource)
          when { principal.roles.contains("reader") };
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - "run(noop-0)"
        - cedar:
            action: 'Action::"read"'
            resource:
              type: Document
              id: doc-42
"#;

/// APL + Cedar YAML with `n_policies` Cedar rules (first matches `reader`).
///
/// Used by memory benches to sweep **policy size** (compile/eval footprint).
///
/// # Panics
///
/// Panics if `n_policies` is zero.
pub fn yaml_cedar_policy_count(n_policies: usize) -> String {
    assert!(n_policies > 0, "need at least one Cedar policy");
    let mut policy_text = String::from(
        r#"
          @id("reader-permit")
          permit(principal, action == Action::"read", resource)
          when { principal.roles.contains("reader") };
"#,
    );
    for i in 1..n_policies {
        policy_text.push_str(&format!(
            r#"
          @id("filler-{i}")
          permit(principal, action == Action::"read", resource)
          when {{ principal.roles.contains("role-{i}") }};
"#
        ));
    }
    format!(
        r#"
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
{policy_text}
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - cedar:
            action: 'Action::"read"'
            resource:
              type: Document
              id: doc-42
"#
    )
}

/// YAML: several concurrent-mode plugins on an APL route.
pub const YAML_CONCURRENT_PLUGINS: &str = r#"
plugins:
  - name: noop-0
    kind: noop
    hooks: [cmf.tool_pre_invoke]
    mode: concurrent
  - name: noop-1
    kind: noop
    hooks: [cmf.tool_pre_invoke]
    mode: concurrent
  - name: noop-2
    kind: noop
    hooks: [cmf.tool_pre_invoke]
    mode: concurrent
  - name: noop-3
    kind: noop
    hooks: [cmf.tool_pre_invoke]
    mode: concurrent
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - "run(noop-0)"
        - "run(noop-1)"
        - "run(noop-2)"
        - "run(noop-3)"
"#;

/// Load YAML, register noop + Cedar factories, initialize.
///
/// Returns `(engine, session_store)` so memory benches can inspect taint.
///
/// # Panics
///
/// Panics if YAML fails to load or engine initialization fails. Bench
/// fixtures treat that as a broken harness rather than a soft error.
pub async fn engine_from_yaml(
    yaml: &str,
    session: Option<Arc<MemorySessionStore>>,
) -> (Arc<PolicyEngine>, Arc<MemorySessionStore>) {
    let session = session.unwrap_or_else(|| Arc::new(MemorySessionStore::new()));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory("noop", Box::new(NoopFactory));
    register_apl(&mgr, apl_options_with_cedar(Arc::clone(&session)));
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    (mgr, session)
}

/// One `invoke_named` on the tool-pre hook (caller-supplied extensions).
///
/// Returns `continue_processing` so callers can `black_box` a real value
/// (empty `black_box(())` does not pin work).
///
/// # Panics
///
/// Panics if the fixture denies. Criterion must not silently time a deny
/// path when the harness expected allow.
pub async fn invoke_once(mgr: &PolicyEngine, ext: Extensions) -> bool {
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(HOOK_TOOL_PRE, cmf_payload("bench"), ext, None)
        .await;
    // Fail loud if a fixture drifts into deny — otherwise Criterion
    // silently times the deny path and baselines become meaningless.
    assert!(
        result.continue_processing,
        "fixture must allow; violation={:?}",
        result.violation
    );
    result.continue_processing
}
