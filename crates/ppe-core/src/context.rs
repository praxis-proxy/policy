// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Execution context types.
//
// Provides PluginContext — the per-plugin, per-invocation execution
// context carrying transient state (counters, caches, intermediate
// results). All data needed for policy evaluation comes from the
// payload's extensions (filtered by capabilities), not from context.
//
// PluginContext has two state maps:
//   - local_state: private to this plugin, this invocation
//   - global_state: shared across plugins in a pipeline
//
// Identity, request metadata, tenant scope, etc. live in extensions
// (MetaExtension, SecurityExtension), not in the context.
//
// Mirrors the spec's PluginContext.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Per-plugin, per-invocation execution context.
///
/// Each plugin receives its own `PluginContext` with:
///
/// - `local_state` — private to this plugin, this invocation. Fresh
///   each time. Used for per-plugin counters, caches, scratch data.
/// - `global_state` — shared across all plugins in a pipeline. The
///   executor merges changes back after serial phases so subsequent
///   plugins see contributions from earlier ones.
///
/// All data needed for policy evaluation (identity, tenant, request
/// metadata) comes from the payload's extensions, capability-gated
/// per plugin. Context is purely for transient execution state.
///
/// ```text
/// PluginContext
/// ├── local_state: HashMap    # Per-plugin, per-request. Private.
/// └── global_state: HashMap   # Shared across plugins. Use with care.
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    /// Plugin-local state. Private to this plugin, this invocation.
    #[serde(default)]
    pub local_state: HashMap<String, Value>,

    /// Shared state across all plugins in the pipeline.
    /// The executor merges changes back after each serial-phase plugin.
    #[serde(default)]
    pub global_state: HashMap<String, Value>,
}

impl PluginContext {
    /// Create a new empty plugin context.
    pub fn new() -> Self {
        Self {
            local_state: HashMap::new(),
            global_state: HashMap::new(),
        }
    }

    /// Create a plugin context with pre-populated global state.
    pub fn with_global_state(global_state: HashMap<String, Value>) -> Self {
        Self {
            local_state: HashMap::new(),
            global_state,
        }
    }

    /// Get a value from local state.
    pub fn get_local(&self, key: &str) -> Option<&Value> {
        self.local_state.get(key)
    }

    /// Set a value in local state.
    pub fn set_local(&mut self, key: impl Into<String>, value: Value) {
        self.local_state.insert(key.into(), value);
    }

    /// Get a value from global state.
    pub fn get_global(&self, key: &str) -> Option<&Value> {
        self.global_state.get(key)
    }

    /// Set a value in global state.
    pub fn set_global(&mut self, key: impl Into<String>, value: Value) {
        self.global_state.insert(key.into(), value);
    }
}

impl Default for PluginContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Threaded execution state carried from one hook invocation to the next
/// within a single request lifecycle (e.g., `pre_invoke` → `post_invoke`).
///
/// The table holds the canonical pipeline state in two parts:
///
/// - `global_state` — a single shared map across all plugins. The executor
///   clones this into each plugin's `PluginContext.global_state` at the
///   start of a run, then commits the plugin's possibly-modified copy back
///   when the run completes (last-writer-wins for serial phases).
/// - `local_states` — per-plugin private state, indexed by plugin ID.
///   Persists across hook invocations so a plugin's `pre_invoke` can stash
///   data its `post_invoke` will read.
///
/// Storing `global_state` once (rather than copying it inside every per-plugin
/// `PluginContext`) makes the canonical state explicit and removes the
/// non-deterministic "pick an arbitrary plugin's snapshot" pattern that was
/// previously needed to recover it.
///
/// Returned by the executor in `PipelineResult` and passed back into the
/// next hook call. On the first hook call pass `None` — the executor
/// creates a fresh table.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginContextTable {
    /// Authoritative shared state across all plugins in the pipeline.
    #[serde(default)]
    pub global_state: HashMap<String, Value>,

    /// Per-plugin local state, indexed by plugin ID (`Uuid`).
    #[serde(default)]
    pub local_states: HashMap<Uuid, HashMap<String, Value>>,

    /// Whether this request has reached `ratelimit.pre_identity`. Set by the
    /// engine and out of plugin reach, so a plugin cannot hide a skipped stage.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pre_identity_rate_limited: bool,
}

impl PluginContextTable {
    /// Create an empty context table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a `PluginContext` for the given plugin, *removing* its stored
    /// `local_state` from the table and seeding it with a fresh clone of the
    /// canonical `global_state`. Use in serial phases where the plugin will
    /// commit its `local_state` changes back via `store_context`.
    ///
    /// If the plugin has no stored `local_state` yet, its context starts
    /// empty (first invocation in the request lifecycle).
    pub fn take_context(&mut self, plugin_id: Uuid) -> PluginContext {
        PluginContext {
            local_state: self.local_states.remove(&plugin_id).unwrap_or_default(),
            global_state: self.global_state.clone(),
        }
    }

    /// Build a `PluginContext` for the given plugin without mutating the
    /// table — the `local_state` is *cloned* and the `global_state` is cloned.
    /// Use in read-only phases (audit, concurrent, fire-and-forget) where
    /// per-plugin mutations should not influence subsequent plugins.
    pub fn snapshot_context(&self, plugin_id: Uuid) -> PluginContext {
        PluginContext {
            local_state: self
                .local_states
                .get(&plugin_id)
                .cloned()
                .unwrap_or_default(),
            global_state: self.global_state.clone(),
        }
    }

    /// Commit a plugin's context back into the table after it ran. Replaces
    /// the canonical `global_state` with the plugin's possibly-modified copy
    /// (move, no clone) and stores the plugin's `local_state` for next time.
    pub fn store_context(&mut self, plugin_id: Uuid, ctx: PluginContext) {
        self.global_state = ctx.global_state;
        self.local_states.insert(plugin_id, ctx.local_state);
    }

    /// Number of plugins with stored `local_state` in the table.
    pub fn len(&self) -> usize {
        self.local_states.len()
    }

    /// Whether the table holds no per-plugin `local_state`.
    pub fn is_empty(&self) -> bool {
        self.local_states.is_empty()
    }

    /// Whether `ratelimit.pre_identity` was dispatched with this table.
    pub(crate) fn pre_identity_rate_limited(&self) -> bool {
        self.pre_identity_rate_limited
    }

    /// Record that `ratelimit.pre_identity` was dispatched with this table.
    pub(crate) fn mark_pre_identity_rate_limited(&mut self) {
        self.pre_identity_rate_limited = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn plugin_context_new() {
        let ctx = PluginContext::new();
        assert!(ctx.local_state.is_empty());
        assert!(ctx.global_state.is_empty());
    }

    #[test]
    fn plugin_context_default() {
        let ctx = PluginContext::default();
        assert!(ctx.local_state.is_empty());
        assert!(ctx.global_state.is_empty());
    }

    #[test]
    fn plugin_context_set_local() {
        let mut ctx = PluginContext::new();
        ctx.set_local("key", json!("value"));
        assert_eq!(ctx.get_local("key"), Some(&json!("value")));
    }

    #[test]
    fn plugin_context_set_global() {
        let mut ctx = PluginContext::new();
        ctx.set_global("key", json!(42));
        assert_eq!(ctx.get_global("key"), Some(&json!(42)));
    }

    #[test]
    fn plugin_context_get_local_missing() {
        let ctx = PluginContext::new();
        assert_eq!(ctx.get_local("missing"), None);
    }

    #[test]
    fn plugin_context_get_global_missing() {
        let ctx = PluginContext::new();
        assert_eq!(ctx.get_global("missing"), None);
    }

    #[test]
    fn plugin_context_with_global_state() {
        let mut global = HashMap::new();
        global.insert("shared".to_owned(), json!("state"));

        let ctx = PluginContext::with_global_state(global);
        assert_eq!(ctx.get_global("shared"), Some(&json!("state")));
        assert!(ctx.local_state.is_empty());
    }

    #[test]
    fn plugin_context_separate_local_and_global() {
        let mut ctx = PluginContext::new();
        ctx.set_local("local_key", json!("local"));
        ctx.set_global("global_key", json!("global"));

        assert_eq!(ctx.get_local("local_key"), Some(&json!("local")));
        assert_eq!(ctx.get_global("global_key"), Some(&json!("global")));
        assert_eq!(ctx.get_local("global_key"), None);
        assert_eq!(ctx.get_global("local_key"), None);
    }

    #[test]
    fn plugin_context_serialization() {
        let mut ctx = PluginContext::new();
        ctx.set_local("local", json!("value"));
        ctx.set_global("global", json!(123));

        let json = serde_json::to_string(&ctx).expect("serialize");
        let deserialized: PluginContext = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.get_local("local"), Some(&json!("value")));
        assert_eq!(deserialized.get_global("global"), Some(&json!(123)));
    }

    #[test]
    fn plugin_context_table_new() {
        let table = PluginContextTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(!table.pre_identity_rate_limited());
    }

    #[test]
    fn plugin_context_table_default() {
        let table = PluginContextTable::default();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn plugin_context_table_take_context_first_time() {
        let mut table = PluginContextTable::new();
        let plugin_id = Uuid::nil();

        let ctx = table.take_context(plugin_id);
        assert!(ctx.local_state.is_empty());
        assert!(ctx.global_state.is_empty());
    }

    #[test]
    fn plugin_context_table_take_context_with_stored_state() {
        let mut table = PluginContextTable::new();
        let plugin_id = Uuid::nil();

        let mut stored = HashMap::new();
        stored.insert("stored_key".to_owned(), json!("stored_value"));
        table.local_states.insert(plugin_id, stored);

        let ctx = table.take_context(plugin_id);
        assert_eq!(ctx.get_local("stored_key"), Some(&json!("stored_value")));
    }

    #[test]
    fn plugin_context_table_snapshot_context() {
        let mut table = PluginContextTable::new();
        let plugin_id = Uuid::nil();

        table.global_state.insert("global".to_owned(), json!("state"));
        let mut stored = HashMap::new();
        stored.insert("local".to_owned(), json!("state"));
        table.local_states.insert(plugin_id, stored);

        let ctx = table.snapshot_context(plugin_id);
        assert_eq!(ctx.get_local("local"), Some(&json!("state")));
        assert_eq!(ctx.get_global("global"), Some(&json!("state")));

        // Table should still have the data (not removed)
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn plugin_context_table_store_context() {
        let mut table = PluginContextTable::new();
        let plugin_id = Uuid::new_v4();

        let mut ctx = PluginContext::new();
        ctx.set_local("local", json!("value"));
        ctx.set_global("global", json!("value"));

        table.store_context(plugin_id, ctx);

        assert_eq!(table.len(), 1);
        assert_eq!(table.global_state.get("global"), Some(&json!("value")));
        assert_eq!(
            table.local_states.get(&plugin_id).and_then(|s| s.get("local")),
            Some(&json!("value"))
        );
    }

    #[test]
    fn plugin_context_table_pre_identity_rate_limited() {
        let mut table = PluginContextTable::new();
        assert!(!table.pre_identity_rate_limited());

        table.mark_pre_identity_rate_limited();
        assert!(table.pre_identity_rate_limited());
    }

    #[test]
    fn plugin_context_table_len_and_is_empty() {
        let mut table = PluginContextTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let plugin_id = Uuid::nil();
        let mut stored = HashMap::new();
        stored.insert("key".to_owned(), json!("value"));
        table.local_states.insert(plugin_id, stored);

        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn plugin_context_table_multiple_plugins() {
        let mut table = PluginContextTable::new();
        let plugin1 = Uuid::new_v4();
        let plugin2 = Uuid::new_v4();

        let mut ctx1 = PluginContext::new();
        ctx1.set_local("plugin1_key", json!("value1"));

        let mut ctx2 = PluginContext::new();
        ctx2.set_local("plugin2_key", json!("value2"));

        table.store_context(plugin1, ctx1);
        table.store_context(plugin2, ctx2);

        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());

        // Global state should be from last context stored
        assert_eq!(table.local_states.len(), 2);
    }

    #[test]
    fn plugin_context_table_global_state_propagation() {
        let mut table = PluginContextTable::new();
        let plugin1 = Uuid::new_v4();
        let plugin2 = Uuid::new_v4();

        let mut ctx1 = PluginContext::new();
        ctx1.set_global("shared", json!("from_plugin1"));
        table.store_context(plugin1, ctx1);

        let ctx2 = table.take_context(plugin2);
        assert_eq!(ctx2.get_global("shared"), Some(&json!("from_plugin1")));
    }

    #[test]
    fn plugin_context_table_serialization() {
        let mut table = PluginContextTable::new();
        table.global_state.insert("global".to_owned(), json!("state"));
        table.mark_pre_identity_rate_limited();

        let json = serde_json::to_string(&table).expect("serialize");
        let deserialized: PluginContextTable = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.global_state.get("global"), Some(&json!("state")));
        assert!(deserialized.pre_identity_rate_limited());
    }

    #[test]
    fn plugin_context_multiple_values() {
        let mut ctx = PluginContext::new();
        ctx.set_local("key1", json!("value1"));
        ctx.set_local("key2", json!("value2"));
        ctx.set_local("key3", json!("value3"));
        ctx.set_global("gkey1", json!(1));
        ctx.set_global("gkey2", json!(2));

        assert_eq!(ctx.get_local("key1"), Some(&json!("value1")));
        assert_eq!(ctx.get_local("key2"), Some(&json!("value2")));
        assert_eq!(ctx.get_local("key3"), Some(&json!("value3")));
        assert_eq!(ctx.get_global("gkey1"), Some(&json!(1)));
        assert_eq!(ctx.get_global("gkey2"), Some(&json!(2)));
    }

    #[test]
    fn plugin_context_overwrite_local() {
        let mut ctx = PluginContext::new();
        ctx.set_local("key", json!("initial"));
        assert_eq!(ctx.get_local("key"), Some(&json!("initial")));

        ctx.set_local("key", json!("updated"));
        assert_eq!(ctx.get_local("key"), Some(&json!("updated")));
    }

    #[test]
    fn plugin_context_overwrite_global() {
        let mut ctx = PluginContext::new();
        ctx.set_global("key", json!("initial"));
        assert_eq!(ctx.get_global("key"), Some(&json!("initial")));

        ctx.set_global("key", json!("updated"));
        assert_eq!(ctx.get_global("key"), Some(&json!("updated")));
    }

    #[test]
    fn plugin_context_table_take_removes_local_state() {
        let mut table = PluginContextTable::new();
        let plugin_id = Uuid::new_v4();

        let mut stored = HashMap::new();
        stored.insert("key".to_owned(), json!("value"));
        table.local_states.insert(plugin_id, stored);

        assert_eq!(table.len(), 1);
        let _ctx = table.take_context(plugin_id);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn plugin_context_table_snapshot_does_not_remove_state() {
        let mut table = PluginContextTable::new();
        let plugin_id = Uuid::new_v4();

        let mut stored = HashMap::new();
        stored.insert("key".to_owned(), json!("value"));
        table.local_states.insert(plugin_id, stored);

        assert_eq!(table.len(), 1);
        let _ctx = table.snapshot_context(plugin_id);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn plugin_context_table_replace_global_state() {
        let mut table = PluginContextTable::new();
        let plugin1 = Uuid::new_v4();

        let mut ctx1 = PluginContext::new();
        ctx1.set_global("key", json!("value1"));
        table.store_context(plugin1, ctx1);

        assert_eq!(table.global_state.get("key"), Some(&json!("value1")));

        let mut ctx2 = PluginContext::new();
        ctx2.set_global("key", json!("value2"));
        table.store_context(plugin1, ctx2);

        assert_eq!(table.global_state.get("key"), Some(&json!("value2")));
    }
}
