// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `AplConfigVisitor` — the praxis-policy-core `ConfigVisitor` implementation that
// stacks the unified-config hierarchy (global → defaults → tag bundles
// → routes) into a single `CompiledRoute` per route and installs an
// [`AplRouteHandler`] for each phase via `PolicyEngine::annotate_route`.
//
// # Hierarchy stacking
//
// Each `visit_*` call carries a single block of raw YAML. The visitor
// collects the policy terms written on it (if any), compiles them to a
// `CompiledRoute`, and stashes it in interior state:
//
//   visit_global       → state.global_layer
//   visit_default      → state.default_layers[entity_type]
//   visit_policy_bundle → state.tag_layers[tag]
//   visit_route        → build effective route by layering and annotate.
//
// At `visit_route` we layer least-to-most-specific:
//
//   effective = global
//   effective.apply_layer(default_layer_for(entity_type))
//   for name in route_bundle_names(route) { effective.apply_layer(tag_layer(name)) }
//   effective.apply_layer(route_policy_block)
//
// then construct one `AplRouteHandler` per phase (Pre, Post) and call
// `annotate_route` for each `(entity_type, entity_name, scope, hook)`.
//
// The `(entity_type, entity_name)` pairs come from
// `praxis_policy_core::config::route_entity_identity`, the one place a
// route maps to the names it is known by, so the key annotated here is
// the key a request resolves to. The bundle names come from
// `route_bundle_names` for the same reason: it is the one place a route maps to
// the bundles it joins, so the policy chain and the authentication chain cannot
// disagree about the membership or the order it stacks in.
//
// # A policy body replaces the route's plugin chain
//
// An annotated route dispatches its compiled body instead of the plugin
// lineup praxis-policy-core would have resolved, so the `all` group, the
// entity-type defaults, tag bundles, and the route's own `plugins:` list only
// run for those requests when a policy step names them. That has always held
// for entity routes, and an `http:` route carrying a body is the same
// substitution. `visit_route` names each `http:` route whose own `plugins:`
// list that silences, so a specific configuration reports it rather than
// leaving an operator to find this paragraph.
//
// # Hook names per entity type
//
// Each entity type binds to its own hook pair:
//
//   * `tool:`     → `cmf.tool_pre_invoke`     / `cmf.tool_post_invoke`
//   * `llm:`      → `cmf.llm_input`           / `cmf.llm_output`
//   * `prompt:`   → `cmf.prompt_pre_invoke`   / `cmf.prompt_post_invoke`
//   * `resource:` → `cmf.resource_pre_fetch`  / `cmf.resource_post_fetch`
//   * `http:`     → `http.request`            / `http.response`
//
// The global HTTP catch-all installs under the same pair, under the
// reserved global name rather than a route's own. An `http:` route
// resolves only under `engine_settings.dispatch: policy`, which is
// the default; the global catch-all installs either way.
//
// The mapping lives in [`hook_pair_for_entity`]. Hosts fire
// `mgr.invoke_named::<CmfHook>("cmf.llm_input", ...)` for LLM
// invocations; the visitor's annotation on `cmf.llm_input` for the
// matching route's entity_name is what AplRouteHandler intercepts.
//
// `HOOK_PRE` / `HOOK_POST` are exposed as legacy aliases for the
// tool-family pair, for callers that wired against the v0 constants.
// The per-entity dispatch is the load-bearing path now.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, Weak};

use praxis_policy_core::cmf::constants::{
    ENTITY_HTTP, ENTITY_LLM, ENTITY_NAME_GLOBAL, ENTITY_PROMPT, ENTITY_RESOURCE, ENTITY_TOOL,
    HOOK_CMF_LLM_INPUT, HOOK_CMF_LLM_OUTPUT, HOOK_CMF_PROMPT_POST_INVOKE,
    HOOK_CMF_PROMPT_PRE_INVOKE, HOOK_CMF_RESOURCE_POST_FETCH, HOOK_CMF_RESOURCE_PRE_FETCH,
    HOOK_CMF_TOOL_POST_INVOKE, HOOK_CMF_TOOL_PRE_INVOKE,
};
use praxis_policy_core::config::{
    PluginRouteRef, RouteEntry, route_bundle_names, route_entity_identity,
};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::http_hook::{HOOK_HTTP_REQUEST, HOOK_HTTP_RESPONSE};
use praxis_policy_core::identity::HOOK_IDENTITY_RESOLVE;
use praxis_policy_core::plugin::PluginConfig;
use praxis_policy_core::visitor::{ConfigVisitor, VisitorError};

use praxis_policy_apl_core::attribute_source::{AttributeSource as _, AttributeTree};
use praxis_policy_apl_core::parser::compile_policy_block_value;
use praxis_policy_apl_core::plugin_decl::{PluginDeclaration, PluginRegistry};
use praxis_policy_apl_core::rules::{CompiledRoute, DenyResponse};
use praxis_policy_apl_core::step::{PdpFactory, PdpResolver};

use crate::dispatch_plan::DispatchCache;
use crate::pdp_router::PdpRouter;
use crate::route_handler::{AplRouteHandler, HookFamily, Phase};
use crate::session_store::{SessionStore, SessionStoreFactory};

/// Legacy alias for the tool-family pre hook. Kept exported for
/// callers that wired against the v0 visitor constants — the
/// per-entity-type dispatch via `hook_pair_for_entity` is the
/// load-bearing path now.
pub const HOOK_PRE: &str = HOOK_CMF_TOOL_PRE_INVOKE;
/// Legacy alias for the tool-family post hook. See `HOOK_PRE`.
pub const HOOK_POST: &str = HOOK_CMF_TOOL_POST_INVOKE;

/// Resolve the (pre, post) hook pair for an `entity_type`. Drives
/// per-entity `annotate_route` calls so an `llm:` route annotates on
/// `cmf.llm_input` / `cmf.llm_output` rather than the tool-family
/// hooks. Returns `None` for unknown entity types — the visitor logs
/// + skips those routes.
///
/// Every install site reads this and passes `Phase::Pre` for the first
/// element and `Phase::Post` for the second, so the phase a hook is
/// installed under is decided in one place. A test asserts the pairs
/// agree with what `praxis-policy-core`'s metadata table records.
pub fn hook_pair_for_entity(entity_type: &str) -> Option<(&'static str, &'static str)> {
    match entity_type {
        ENTITY_TOOL => Some((HOOK_CMF_TOOL_PRE_INVOKE, HOOK_CMF_TOOL_POST_INVOKE)),
        ENTITY_LLM => Some((HOOK_CMF_LLM_INPUT, HOOK_CMF_LLM_OUTPUT)),
        ENTITY_PROMPT => Some((HOOK_CMF_PROMPT_PRE_INVOKE, HOOK_CMF_PROMPT_POST_INVOKE)),
        ENTITY_RESOURCE => Some((HOOK_CMF_RESOURCE_PRE_FETCH, HOOK_CMF_RESOURCE_POST_FETCH)),
        ENTITY_HTTP => Some((HOOK_HTTP_REQUEST, HOOK_HTTP_RESPONSE)),
        _ => None,
    }
}

/// Interior state accumulated as the engine walks the visitor.
/// `plugin_registry` is populated by `visit_plugins` (called once per
/// load); the layer fields are populated as the visitor walks
/// `global` / `defaults` / `policies` / `routes`; `pdp_router` is
/// populated by both code-supplied resolvers (`register_pdp`) and
/// unified-config-driven entries under `global.pdp[]` (built
/// during `visit_global`).
#[derive(Default)]
struct VisitorState {
    plugin_registry: PluginRegistry,
    global_layer: Option<CompiledRoute>,
    default_layers: HashMap<String, CompiledRoute>,
    tag_layers: HashMap<String, CompiledRoute>,
    pdp_router: PdpRouter,
    /// Each declared plugin's name against the hooks its own `hooks:` names.
    /// Filled by `visit_plugins`, which runs before any section is walked.
    declared_plugin_hooks: HashMap<String, Vec<String>>,
    /// Each plugin a policy reaches, against the hooks it is reached under.
    /// Filled as routes are walked, where the entity family fixes the hook pair,
    /// and read by `visit_complete` for the narrowing report only.
    reached_plugin_hooks: HashMap<String, HashSet<String>>,
    /// Every plugin any policy names, whatever the scope. Reachability reads
    /// this rather than `reached_plugin_hooks`, because a `global:`,
    /// `global.defaults:`, or bundle layer reaches its plugins even in a config
    /// with no `routes:` for it to stack onto, and no hook is known there.
    reached_plugin_names: HashSet<String>,
}

/// APL implementation of [`praxis_policy_core::visitor::ConfigVisitor`]. Construct
/// once per host with the shared infrastructure (dispatch cache, session
/// store, engine handle) and register with `PolicyEngine::register_visitor`
/// before calling `load_config_yaml`.
///
/// PDPs come from two sources, both feeding the same internal
/// [`PdpRouter`]:
///
/// 1. **Code-supplied** via `register_pdp` (or `AplOptions.pdps`) —
///    the host built the resolver in code and hands it in.
/// 2. **Config-supplied** via `global.pdp[]` blocks in the unified
///    config — the visitor sees the block, looks up a factory by
///    `kind`, and constructs the resolver during `visit_global`.
///
/// Factories are registered up front by `kind` name (`"cedar-direct"`,
/// `"opa"`, …). The visitor knows nothing about specific PDP
/// backends; everything dispatches through `PdpFactory`.
pub struct AplConfigVisitor {
    state: RwLock<VisitorState>,
    dispatch_cache: Arc<DispatchCache>,
    /// Active session store. Behind a `RwLock` because a
    /// `global.session_store` block can swap it during the
    /// config walk (`visit_global`), which runs before route handlers
    /// capture the store in `visit_route`. Only touched during the
    /// single-threaded config walk — never on the request hot path,
    /// where each handler holds its own cloned `Arc`.
    session_store: RwLock<Arc<dyn SessionStore>>,
    /// Static `data.*` attribute tree, shared into every installed
    /// handler. Set once before the config walk via
    /// [`Self::set_attribute_tree`]; defaults to empty. Behind a `RwLock`
    /// only because it's set after construction — like `session_store`,
    /// it's touched only during the single-threaded config walk, never on
    /// the request hot path (handlers hold their own cloned `Arc`).
    attribute_tree: RwLock<Arc<AttributeTree>>,
    engine: Weak<PolicyEngine>,
    /// Baseline capabilities granted to every synthetic `AplRouteHandler`
    /// the visitor installs. Unioned with the per-route plugin
    /// capability set so APL predicates that touch extensions
    /// (`require(authenticated)` needs `read_subject`, etc.) work even
    /// when no plugins are referenced. Hosts that want strict gating
    /// can set this to an empty set.
    base_capabilities: std::collections::HashSet<String>,
    /// Factories the visitor consults when it encounters a
    /// `global.pdp[]` entry. Keyed by the factory's `kind()` —
    /// matches the `kind:` field in the YAML block.
    pdp_factories: HashMap<String, Arc<dyn PdpFactory>>,
    /// Factories the visitor consults for a `global.session_store`
    /// block. Keyed by the factory's `kind()`. Empty by default, in
    /// which case the constructor-supplied store (typically
    /// `MemorySessionStore`) stays active.
    session_store_factories: HashMap<String, Arc<dyn SessionStoreFactory>>,
}

impl AplConfigVisitor {
    /// A visitor with the given options and no compiled routes yet.
    pub fn new(
        dispatch_cache: Arc<DispatchCache>,
        session_store: Arc<dyn SessionStore>,
        engine: Weak<PolicyEngine>,
    ) -> Self {
        Self {
            state: RwLock::new(VisitorState::default()),
            dispatch_cache,
            session_store: RwLock::new(session_store),
            attribute_tree: RwLock::new(Arc::new(AttributeTree::empty())),
            engine,
            base_capabilities: default_base_capabilities(),
            pdp_factories: HashMap::new(),
            session_store_factories: HashMap::new(),
        }
    }

    /// Register a code-supplied PDP resolver. Equivalent to declaring a
    /// PDP in the unified config but for hosts that prefer wiring
    /// resolvers in Rust. Resolvers are pushed into the internal
    /// `PdpRouter`; the first registration per dialect wins (matches
    /// `PdpRouter::register` semantics).
    pub fn register_pdp(&self, resolver: Arc<dyn PdpResolver>) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.pdp_router.register(resolver);
    }

    /// Install the static `data.*` attribute tree. Call after
    /// `register_apl` and **before** `load_config_yaml` (handlers capture
    /// the tree during the config walk). Load it from any
    /// [`praxis_policy_apl_core::AttributeSource`] — e.g.
    /// `FileAttributeSource::new(paths).load()?` — or hand-build one.
    /// Replacing a previously-set tree is allowed (last set wins).
    pub fn set_attribute_tree(&self, tree: AttributeTree) {
        let mut slot = self
            .attribute_tree
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = Arc::new(tree);
    }

    /// Register a PDP factory by its `kind()`. Called during
    /// `register_apl` setup; the visitor uses these to instantiate
    /// resolvers from `global.pdp[]` config blocks.
    pub fn register_pdp_factory(&mut self, factory: Arc<dyn PdpFactory>) {
        self.pdp_factories
            .insert(factory.kind().to_owned(), factory);
    }

    /// Register a `SessionStoreFactory` by its `kind()`. Called during
    /// `register_apl` setup; the visitor uses these to swap in the
    /// config-selected session store when it sees a
    /// `global.session_store` block.
    pub fn register_session_store_factory(&mut self, factory: Arc<dyn SessionStoreFactory>) {
        self.session_store_factories
            .insert(factory.kind().to_owned(), factory);
    }

    /// Parse the optional `global.session_store` block and swap the
    /// active store. Looks up the factory by `kind`, builds the store,
    /// and replaces the constructor-supplied default. Runs during
    /// `visit_global` — before `visit_route` clones the store into each
    /// handler — so the selected store is the one handlers capture.
    /// Absent block → no-op (the default store stays active).
    fn build_session_store_from_config(
        &self,
        block: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        let map = block.as_mapping().ok_or_else(|| {
            "global.session_store must be a mapping with a `kind:` field".to_owned()
        })?;
        let kind = map
            .get(serde_yaml::Value::String("kind".to_owned()))
            .and_then(|v| v.as_str())
            .ok_or_else(|| "global.session_store missing required `kind:` field".to_owned())?;
        let factory = self.session_store_factories.get(kind).ok_or_else(|| {
            format!(
                "global.session_store declared kind='{kind}' but no factory is registered for that \
                 kind — host must call register_session_store_factory(...) before load_config_yaml"
            )
        })?;
        let store = factory
            .build(block)
            .map_err(|e| format!("global.session_store (kind='{kind}') failed to build: {e}"))?;
        *self
            .session_store
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = store;
        Ok(())
    }

    /// Load the static `data.*` tree from a `global.attribute_files`
    /// list and install it. Paths resolve relative to the process CWD
    /// (the config is loaded from a string, so there is no config-file
    /// directory to anchor to). Fail-fast: a missing file or a same-leaf
    /// merge conflict aborts config load.
    ///
    /// Precedence: a tree injected via
    /// [`AplConfigVisitor::set_attribute_tree`] before the config walk
    /// wins — declarative `attribute_files` is skipped when a non-empty
    /// tree is already present (injected > `attribute_files` > none).
    fn build_attribute_tree_from_config(
        &self,
        entries: &serde_yaml::Sequence,
    ) -> Result<(), VisitorError> {
        {
            let current = self
                .attribute_tree
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !current.is_empty() {
                tracing::info!(
                    "global.attribute_files present but an attribute tree was already \
                     injected via set_attribute_tree — keeping the injected tree \
                     (injected > attribute_files)"
                );
                return Ok(());
            }
        }

        let mut paths = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            let s = entry
                .as_str()
                .ok_or_else(|| format!("global.attribute_files[{i}] must be a string path"))?;
            paths.push(std::path::PathBuf::from(s));
        }
        if paths.is_empty() {
            return Ok(());
        }

        let tree = crate::attribute_source::FileAttributeSource::new(paths)
            .load()
            .map_err(|e| format!("global.attribute_files failed to load: {e}"))?;
        *self
            .attribute_tree
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(tree);
        Ok(())
    }

    /// Replace the baseline capability set granted to every installed
    /// `AplRouteHandler`. Default covers read-only attributes APL
    /// predicates commonly touch (subject, role, labels, delegation,
    /// agent). Tighten this when the deployment's policy plugins
    /// don't need broad reads — every cap removed is one fewer
    /// extension slot a buggy predicate can leak through.
    pub fn with_base_capabilities(mut self, caps: std::collections::HashSet<String>) -> Self {
        self.base_capabilities = caps;
        self
    }

    /// Parse one entry from `global.pdp[]`. Reads `kind`, dispatches
    /// to the matching factory, installs the resulting resolver into
    /// the internal `PdpRouter`. Called per entry during `visit_global`.
    ///
    /// `index` is used only for diagnostics — operators see "the third
    /// pdp entry failed" rather than a generic "a pdp entry failed."
    fn build_pdp_from_config(
        &self,
        entry: &serde_yaml::Value,
        index: usize,
    ) -> Result<(), VisitorError> {
        let map = entry
            .as_mapping()
            .ok_or_else(|| format!("global.pdp[{index}] must be a mapping with a `kind:` field"))?;
        let kind = map
            .get(serde_yaml::Value::String("kind".to_owned()))
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("global.pdp[{index}] missing required `kind:` field"))?;
        let factory = self.pdp_factories.get(kind).ok_or_else(|| {
            format!(
                "global.pdp[{index}] declared kind='{kind}' but no factory is registered for that kind — \
                 host must call register_pdp_factory(...) before load_config_yaml"
            )
        })?;
        let resolver = factory
            .build(entry)
            .map_err(|e| format!("global.pdp[{index}] (kind='{kind}') failed to build: {e}"))?;
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.pdp_router.register(resolver);
        Ok(())
    }

    /// Snapshot the request-time dispatch state — plugin registry, PDP
    /// router, and active session store — each `Arc`-wrapped for a handler
    /// to capture. Reads the visitor's `RwLock`s once through a single
    /// poison-recovery path shared by both handler-install sites
    /// (`visit_global`'s entity-less HTTP handler and `visit_route`'s
    /// per-entity handlers) so the policy can't diverge between them.
    fn snapshot_dispatch_state(
        &self,
    ) -> (
        Arc<PluginRegistry>,
        Arc<dyn PdpResolver>,
        Arc<dyn SessionStore>,
    ) {
        let (plugin_registry, pdp_router_arc) = {
            let state = self
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                Arc::new(state.plugin_registry.clone()),
                Arc::new(state.pdp_router.clone()),
            )
        };
        let session_store = self
            .session_store
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        (plugin_registry, pdp_router_arc, session_store)
    }
}

/// The plugin names an `authentication:` block on a section lists.
///
/// praxis-policy-core parses this block for its own resolution and hands the
/// visitor only raw YAML for `global:` and `groups.<tag>:`, so reading the
/// reference set means re-reading the key. The two accepted shapes are a list
/// of steps and an object carrying `steps:`, and a step is a bare name or a map
/// with `name:` — spelled out here rather than deserialized, because the type
/// that models the block derives only the object shape and its two-shape
/// reader is private to praxis-policy-core.
///
/// A shape this does not recognize yields nothing. That is safe in the
/// direction that matters: praxis-policy-core has already rejected a malformed
/// block by the time a visitor runs, so an unreadable one here is a shape that
/// parsed, and the worst case is naming a plugin as unreached that something
/// does reach. The tests below pin both shapes for that reason.
fn authentication_step_names(yaml: &serde_yaml::Value) -> Vec<String> {
    let Some(block) = yaml.get("authentication") else {
        return Vec::new();
    };
    let steps = match block {
        serde_yaml::Value::Sequence(items) => items,
        serde_yaml::Value::Mapping(_) => match block.get("steps") {
            Some(serde_yaml::Value::Sequence(items)) => items,
            _ => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    steps
        .iter()
        .filter_map(|step| match step {
            serde_yaml::Value::String(name) => Some(name.clone()),
            serde_yaml::Value::Mapping(_) => step
                .get("name")
                .and_then(serde_yaml::Value::as_str)
                .map(ToOwned::to_owned),
            _ => None,
        })
        .collect()
}

/// Read-only baseline for APL predicates: enough to make
/// `authenticated`, `role.*`, `perm.*`, `subject.*`, `claim.*`,
/// `subject.teams`, `security.labels`, `delegated`, `delegation.*`,
/// and `agent.*` evaluate correctly. Excludes all *write* capabilities
/// — those are granted on demand by the per-route plugin union when a
/// plugin declares `append_labels` / `append_delegation` /
/// `write_headers`.
///
/// `read_subject` alone unlocks only `subject.id` / `subject.type`;
/// roles, permissions, teams, and claims are each gated by their own
/// capability (`read_roles` / `read_permissions` / `read_teams` /
/// `read_claims`). PDP-driven policies routinely read principal.roles /
/// principal.claims, so the baseline grants all four — tightening
/// further would surprise APL authors whose `cedar:` policies suddenly
/// see empty role sets in deployments with no plugin-declared caps.
/// Hosts that want strict subject access override this via
/// `AplOptions.base_capabilities`.
fn default_base_capabilities() -> std::collections::HashSet<String> {
    [
        "read_subject",
        "read_roles",
        "read_permissions",
        "read_teams",
        "read_claims",
        "read_labels",
        "read_delegation",
        "read_agent",
        "read_meta",
    ]
    .iter()
    .map(std::string::ToString::to_string)
    .collect()
}

impl AplConfigVisitor {
    /// Tally the plugins a compiled route reaches, against the hook each half
    /// installs under.
    ///
    /// Called with the fully stacked route, so a plugin a `global:`,
    /// `global.defaults:`, or bundle layer names is counted for every route
    /// that layer reached. That is the whole point: a step under
    /// `global.authorization:` reaches a plugin exactly by stacking onto the
    /// routes below it.
    fn record_reached_plugins(&self, route: &CompiledRoute, hook_pre: &str, hook_post: &str) {
        let (pre, post) = crate::dispatch_plan::collect_plugin_names_by_half(route);
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (names, hook) in [(pre, hook_pre), (post, hook_post)] {
            for name in names {
                state.reached_plugin_names.insert(name.clone());
                state
                    .reached_plugin_hooks
                    .entry(name)
                    .or_default()
                    .insert(hook.to_owned());
            }
        }
    }

    /// Tally the plugins a layer's steps name, without a hook.
    ///
    /// One caller: `visit_global`. Its layer is the exception, because it is the
    /// one scope that installs a handler of its own, the entity-less HTTP
    /// catch-all, and so governs every request that resolves no route. A config
    /// with no `routes:` at all still reaches those plugins, which is why this
    /// cannot wait for a route.
    ///
    /// `global.defaults.<entity>:` and a bundle install nothing and match nothing:
    /// they only stack onto routes, and `visit_route` records what the *effective*
    /// route reaches, layers included. They used to record here too, which made
    /// an orphan group or an unused entity default report its plugins as
    /// reachable when no dispatch path existed. The hook pair is unknown here
    /// either way, since it is fixed by the route's entity family.
    ///
    /// The reference set is [`crate::dispatch_plan::collect_plugin_names_by_half`]'s,
    /// merged: a layer has no hook to split the halves by, but it has to name
    /// the same plugins a route's tally would. The union collector beside it
    /// omits delegation and elicitation, which is right for a dispatch plan
    /// (those resolve under their own hook families and live in their own maps)
    /// and wrong here, where a `delegate(...)` in a `global:` block with no
    /// route under it was reported as reaching nothing and failed the load.
    fn record_reached_layer_names(&self, route: &CompiledRoute) {
        let (pre, post) = crate::dispatch_plan::collect_plugin_names_by_half(route);
        let names: Vec<String> = pre.into_iter().chain(post).collect();
        if names.is_empty() {
            return;
        }
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.reached_plugin_names.extend(names);
    }

    /// Tally the plugins an `authentication:` block names. Those reach the
    /// identity hook, which no policy step installs under.
    fn record_authentication_names(&self, names: &[String]) {
        if names.is_empty() {
            return;
        }
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for name in names {
            state.reached_plugin_names.insert(name.clone());
            state
                .reached_plugin_hooks
                .entry(name.clone())
                .or_default()
                .insert(HOOK_IDENTITY_RESOLVE.to_owned());
        }
    }

    /// Fail the load for a declared plugin no policy reaches, and warn for one
    /// reached on fewer hooks than it declares. Policy dispatch only.
    ///
    /// The report is per plugin rather than per config: a config declaring
    /// three plugins and naming one reaches *something*, and a config-wide
    /// "reaches nothing" test would pass it while two plugins sit inert. Under
    /// `dispatch: policy` an unreached plugin never runs, so an operator who
    /// declared it is looking at a gap in enforcement with nothing to read.
    ///
    /// Narrowing is a warning, not an error: a plugin declaring three hooks
    /// and named by a step on one may be exactly what was meant. It is
    /// reported because it is equally often not.
    fn report_unreachable_plugins(&self, mgr: &Arc<PolicyEngine>) -> Result<(), VisitorError> {
        // Hook dispatch fires each plugin at the hooks its own `hooks:` names,
        // so a plugin no step reaches is what that mode looks like rather than a
        // fault. Both checks below only mean anything under `policy`.
        if !mgr.dispatch_mode().is_policy() {
            return Ok(());
        }
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let mut unreached: Vec<&str> = state
            .declared_plugin_hooks
            .keys()
            .filter(|name| !state.reached_plugin_names.contains(*name))
            .map(String::as_str)
            .collect();
        if !unreached.is_empty() {
            unreached.sort_unstable();
            return Err(format!(
                "`engine_settings.dispatch: policy` reaches a plugin only from a step that names \
                 it, and no step names `{}`, so it can never run. Add a `run(name)` step under an \
                 `authorization:` block, name it in an `authentication:` list, or drop the \
                 declaration",
                unreached.join("`, `")
            )
            .into());
        }

        for (name, declared) in &state.declared_plugin_hooks {
            let Some(reached) = state.reached_plugin_hooks.get(name) else {
                continue;
            };
            let uncovered: Vec<&str> = declared
                .iter()
                .filter(|hook| !reached.contains(*hook))
                .map(String::as_str)
                .collect();
            if !uncovered.is_empty() {
                tracing::warn!(
                    alarm = "plugin_narrowed_by_policy",
                    plugin = %name,
                    uncovered = ?uncovered,
                    "this plugin declares hooks no policy step reaches it under, so it no longer \
                     runs there. Under `dispatch: hooks` it would fire at every hook it declares. \
                     Add a step on the uncovered hooks if the coverage was meant to be wider, or \
                     narrow the plugin's own `hooks:` to match what the policy asks for",
                );
            }
        }
        Ok(())
    }
}

impl ConfigVisitor for AplConfigVisitor {
    fn name(&self) -> &str {
        "apl"
    }

    fn visit_plugins(
        &self,
        _mgr: &Arc<PolicyEngine>,
        plugins: &[PluginConfig],
    ) -> Result<(), VisitorError> {
        // Translate praxis-policy-core's typed PluginConfig into praxis-policy-apl-core's
        // PluginDeclaration. Field-for-field except `capabilities` is a
        // `HashSet` on the engine side and a `Vec` on the APL side, and
        // `config` is wrapped in `serde_yaml::Value::Mapping` to match
        // praxis-policy-apl-core's opaque shape. praxis-policy-core has already validated
        // uniqueness by this point so we don't re-check.
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.plugin_registry.clear();
        // A load starts the reachability tally over. `visit_plugins` runs once
        // per load before any section, so it is the only place that can.
        state.declared_plugin_hooks.clear();
        state.reached_plugin_hooks.clear();
        state.reached_plugin_names.clear();
        for cfg in plugins {
            state
                .declared_plugin_hooks
                .insert(cfg.name.clone(), cfg.hooks.clone());
            let decl = PluginDeclaration {
                name: cfg.name.clone(),
                kind: cfg.kind.clone(),
                hooks: cfg.hooks.clone(),
                capabilities: cfg.capabilities.iter().cloned().collect(),
                config: plugin_config_to_yaml(cfg.config.as_ref()),
                on_error: Some(on_error_to_string(&cfg.on_error)),
                extra: HashMap::new(),
            };
            state.plugin_registry.insert(cfg.name.clone(), decl);
        }
        Ok(())
    }

    fn visit_complete(&self, mgr: &Arc<PolicyEngine>) -> Result<(), VisitorError> {
        self.report_unreachable_plugins(mgr)
    }

    fn visit_global(
        &self,
        mgr: &Arc<PolicyEngine>,
        yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        self.record_authentication_names(&authentication_step_names(yaml));
        let Some(apl_block) = apl_subblock(yaml) else {
            // No policy term on the section — there is nothing to compile or
            // install. But a bare `global: { response: {...} }` (a denyWith
            // with no accompanying policy) would otherwise be dropped here
            // silently, before the `response_subblock` read below ever runs.
            // Warn so this fail-open-by-omission case gets the same signal as
            // the no-steps case handled further down, rather than vanishing
            // without a trace.
            if response_yaml_block(yaml).is_some_and(|v| !v.is_null()) {
                tracing::warn!(
                    "APL visitor: global.response is set but global declares no authorization \
                     block — the entity-less HTTP catch-all handler will not install, so this response can never fire",
                );
            }
            return Ok(());
        };

        // Process `global.pdp[]` before stacking the pre/post-invocation
        // layer — route handlers that reference PDPs need them
        // resolvable by the time `visit_route` runs.
        if let Some(pdp_entries) = apl_block.get("pdp").and_then(|v| v.as_sequence()) {
            for (i, entry) in pdp_entries.iter().enumerate() {
                self.build_pdp_from_config(entry, i)?;
            }
        }

        // Process an optional `global.session_store` block: swap the
        // active store before `visit_route` clones it into handlers.
        if let Some(block) = apl_block.get("session_store") {
            self.build_session_store_from_config(block)?;
        }

        // Process an optional `global.attribute_files` list: load +
        // merge the static `data.*` tree before `visit_route` clones it
        // into handlers. A tree already injected via `set_attribute_tree`
        // takes precedence (injected > attribute_files > none).
        if let Some(files) = apl_block.get("attribute_files") {
            let entries = files
                .as_sequence()
                .ok_or_else(|| "global.attribute_files must be a list of file paths".to_owned())?;
            self.build_attribute_tree_from_config(entries)?;
        }

        // The wiring keys aren't APL terms; strip them before handing the
        // block to `compile_policy_block_value` so the compiler only sees
        // what it models.
        let policy_only = strip_wiring_keys(&apl_block);
        let mut compiled = compile_policy_block_value("global", &policy_only)
            .map_err(|e| -> VisitorError { Box::new(e) })?;
        // A `response:` block at the global scope is the catch-all denyWith.
        compiled.response = response_subblock(yaml, "global");

        // Install catch-all handlers so the global policy also evaluates for
        // generic (non-MCP/A2A) HTTP requests, which carry no entity.
        // Entity routes still stack `global` via apply_layer in visit_route;
        // this is the *entity-less* evaluation path. Each half installs only
        // when the policy declares steps for it: authorization is an
        // admission check with nothing to say on the way out, and response
        // filtering has nothing to say on the way in.
        //
        // The pair, and which half is Pre and which is Post, come from the
        // same mapping the entity routes below read, so the phase a hook
        // installs under is decided in one place. `None` is unreachable for
        // ENTITY_HTTP; skipping rather than crashing matches visit_routes.
        let installs_pre_handler = declares_pre_phase(&compiled);
        let installs_post_handler = declares_post_phase(&compiled);
        if !installs_pre_handler && !installs_post_handler && compiled.response.is_some() {
            tracing::warn!(
                "APL visitor: global.response is set but global declares no steps \
                 (`pre_invocation:` for the request half, `post_invocation:` for the response \
                 half), so no entity-less HTTP handler installs and this response can never fire",
            );
        }
        if (installs_pre_handler || installs_post_handler)
            && let Some((hook_request, hook_response)) = hook_pair_for_entity(ENTITY_HTTP)
        {
            let (plugin_registry, pdp_router_arc, session_store) = self.snapshot_dispatch_state();
            // Snapshot the static attribute tree (built above from
            // `attribute_files`, or pre-injected). The entity-less HTTP
            // catch-all handler resolves `data.*` refs against the same
            // tree the entity routes do.
            let attribute_tree = self
                .attribute_tree
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let route_arc = Arc::new(compiled.clone());
            // `read_headers` (for `http.*`) is granted to every synthetic policy
            // handler in `install_handler`, so the baseline is passed as-is here.
            if installs_pre_handler {
                install_handler(
                    mgr,
                    ENTITY_HTTP,
                    ENTITY_NAME_GLOBAL,
                    None,
                    hook_request,
                    Phase::Pre,
                    Arc::clone(&route_arc),
                    &plugin_registry,
                    &self.dispatch_cache,
                    &session_store,
                    &self.engine,
                    Some(Arc::clone(&pdp_router_arc)),
                    &self.base_capabilities,
                    Arc::clone(&attribute_tree),
                );
            }
            if installs_post_handler {
                install_handler(
                    mgr,
                    ENTITY_HTTP,
                    ENTITY_NAME_GLOBAL,
                    None,
                    hook_response,
                    Phase::Post,
                    route_arc,
                    &plugin_registry,
                    &self.dispatch_cache,
                    &session_store,
                    &self.engine,
                    Some(pdp_router_arc),
                    &self.base_capabilities,
                    attribute_tree,
                );
            }
        }

        self.record_reached_layer_names(&compiled);
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .global_layer = Some(compiled);
        Ok(())
    }

    fn visit_default(
        &self,
        _mgr: &Arc<PolicyEngine>,
        entity_type: &str,
        yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        let source = format!("global.defaults.{entity_type}");
        // Before the early return, the way a bundle and a route both do: an
        // entity default's `authentication:` list reaches its plugins whether
        // or not the block carries a policy body.
        self.record_authentication_names(&authentication_step_names(yaml));
        warn_if_response_at_unsupported_scope(yaml, &source);
        let Some(apl_block) = apl_subblock(yaml) else {
            return Ok(());
        };
        let compiled = compile_policy_block_value(&source, &apl_block)
            .map_err(|e| -> VisitorError { Box::new(e) })?;
        // A default layer reaches only its own entity type, so a field stage
        // declared here for `http` is as unreadable as one on the route.
        reject_field_stages_without_fields(entity_type, &source, &compiled)?;
        // No reachability tally here. This installs no handler and matches no
        // request: it stacks onto routes, and `visit_route` records what the
        // effective route reaches. Recording at compile time meant a default for
        // an entity type no route declares reported its plugins as reachable.
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .default_layers
            .insert(entity_type.to_owned(), compiled);
        Ok(())
    }

    fn visit_policy_bundle(
        &self,
        _mgr: &Arc<PolicyEngine>,
        tag: &str,
        yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        let source = format!("groups.{tag}");
        self.record_authentication_names(&authentication_step_names(yaml));
        warn_if_response_at_unsupported_scope(yaml, &source);
        let Some(apl_block) = apl_subblock(yaml) else {
            return Ok(());
        };
        let compiled = compile_policy_block_value(&source, &apl_block)
            .map_err(|e| -> VisitorError { Box::new(e) })?;
        // No reachability tally here, for the reason in `visit_default`. A group
        // installs no handler and matches no request on its own: a route has to
        // carry its name. Recording at compile time meant an orphan group nothing
        // joins reported its plugins as reachable, which is the fail-open the
        // per-plugin check exists to close.
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tag_layers
            .insert(tag.to_owned(), compiled);
        Ok(())
    }

    fn visit_route(
        &self,
        mgr: &Arc<PolicyEngine>,
        yaml: &serde_yaml::Value,
        parsed: &RouteEntry,
    ) -> Result<(), VisitorError> {
        // Before any early return: an `authentication:` list reaches its
        // plugins whether or not the route carries a policy body, so a route
        // that contributes no APL block still contributes references. Read off
        // the typed route here, which praxis-policy-core has already resolved
        // to both shapes.
        if let Some(identity) = parsed.authentication.as_ref() {
            let names: Vec<String> = identity.steps.iter().map(|s| s.name.clone()).collect();
            self.record_authentication_names(&names);
        }

        // Extract the route's APL block (if any) and the entity identity
        // we need for annotate_route. A route without an APL block AND
        // without inherited layers contributes nothing — skip.
        let route_apl = apl_subblock(yaml);
        let Some((entity_type, entity_names)) = route_entity_identity(parsed) else {
            tracing::warn!(
                "APL visitor: route declares no tool/resource/prompt/llm/http selector, skipping",
            );
            return Ok(());
        };
        let scope = parsed.meta.as_ref().and_then(|m| m.scope.clone());
        // Both membership spellings, in the order their layers stack. This read
        // `parsed.meta.tags` alone, so a route joining a bundle through `groups:`
        // inherited the bundle's `authentication:` (which praxis-policy-core
        // resolves through the same ordered stream) and none of its
        // `authorization:`. With the activation lists gone that was a fail-open
        // rather than a metadata asymmetry: no layer contributed anything, so the
        // route installed no handler and was governed by nothing.
        let bundles: Vec<String> = route_bundle_names(parsed);

        // Snapshot the dispatch state once outside the per-entity loop.
        // `visit_plugins` populated the registry before any `visit_route`
        // call; the router + session store were finalized in `visit_global`.
        // Routes share all three, so cloning each into an `Arc` once and
        // handing clones to each handler is cheaper than re-reading the
        // RwLocks per entity. Cloning `PdpRouter` is refcount bumps on each
        // inner resolver — cheap.
        let (plugin_registry, pdp_router_arc, session_store) = self.snapshot_dispatch_state();

        // Route-level denial response (transpiled `denyWith`) — parsed once;
        // its input (`yaml`) is loop-invariant across the entity names this
        // route matches, so hoisting avoids re-deserializing (and
        // re-warning) once per entity. `response` is scope-local: an entity
        // route carries only its own block, never an inherited `global` one.
        let route_response = response_subblock(yaml, &format!("routes.{entity_type}"));

        for (idx, entity_name) in entity_names.iter().enumerate() {
            // route_key is what `DispatchCache` keys on, so it must
            // disambiguate scoped vs unscoped routes for the same
            // entity — otherwise two same-named annotations share one
            // cached plan and the second's overrides leak into the first.
            let route_key = match &scope {
                Some(s) => format!("{entity_type}:{entity_name}@{s}"),
                None => format!("{entity_type}:{entity_name}"),
            };
            let state = self
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            // Stack least-to-most-specific. Each apply_layer call appends
            // pre/post-invocation steps and merges args/result/plugin_overrides
            // by field; the resulting CompiledRoute represents the route's
            // effective policy in evaluation order.
            let mut effective = CompiledRoute::new(&route_key);
            if let Some(layer) = state.global_layer.clone() {
                effective.apply_layer(layer);
            }
            if let Some(layer) = state.default_layers.get(entity_type).cloned() {
                effective.apply_layer(layer);
            }
            for bundle in &bundles {
                if let Some(layer) = state.tag_layers.get(bundle).cloned() {
                    effective.apply_layer(layer);
                }
            }
            drop(state);

            if let Some(block) = &route_apl {
                let source = format!("routes.{route_key}");
                let route_layer = compile_policy_block_value(&source, block)
                    .map_err(|e| -> VisitorError { Box::new(e) })?;
                reject_field_stages_without_fields(
                    entity_type,
                    &format!("route '{route_key}'"),
                    &route_layer,
                )?;
                effective.apply_layer(route_layer);
            }

            // Route-level denial response (transpiled `denyWith`), parsed
            // above the loop. Route scope is most-specific and inheritance
            // was removed, so this is the only source of `response` for an
            // entity route — a malformed or absent block leaves it `None`
            // (host default denial), never a leaked `global` response.
            effective.response = route_response.clone();

            // Load-time lint, once per route: flag any APL `plugins:`
            // override declared for a plugin that no policy / delegate step
            // references. Checked on the fully-stacked `effective` route so
            // an override consumed by an inherited (global / default / tag)
            // policy is not falsely flagged. The overrides and referenced
            // names are entity-independent, so the first entity is
            // representative — guarding on `idx == 0` keeps it to one pass.
            if idx == 0 {
                warn_unreferenced_plugin_overrides(&effective);
            }

            // No layers contributed anything? Don't install a handler — the
            // route falls back to praxis-policy-core's plugin-chain execution.
            if effective.declared_phases().is_empty() {
                continue;
            }

            // Load-time soundness check: a route that delegates the
            // caller's own credential but resolves no identity for it.
            // Per entity name rather than once per route, because
            // identity resolution is keyed on the same
            // (type, name, scope) triple the annotation is. Run here,
            // during the config walk, rather than in
            // `RouteDispatchPlan::build`, which a route reaches only on
            // its first request — the route nobody has called yet is
            // precisely the one this is for. `load_config` has already
            // installed the policy config on the engine snapshot by the
            // time visitors run, so the identity lookup sees the config
            // being loaded.
            crate::dispatch_plan::warn_if_delegating_without_identity(
                &effective,
                entity_type,
                entity_name,
                scope.as_deref(),
                mgr.as_ref(),
            );

            // A handler is about to install, so the substitution is certain
            // from here. Reported once per route: the body and the `plugins:`
            // list are the same for every name the selector contributes.
            if idx == 0 {
                let displaced = displaced_plugin_chain(entity_type, parsed);
                if !displaced.is_empty() {
                    tracing::warn!(
                        route = %route_key,
                        plugins = %displaced.join(", "),
                        "APL visitor: this `http:` route's policy body dispatches in place of its \
                         plugin chain, so the plugins it lists run only where a policy step names \
                         them",
                    );
                }
            }

            // Plugin-mode validation for `parallel:` blocks.
            // `praxis-policy-apl-core::Effect::validate_parallel_purity` already rejected
            // FieldOp / Delegate at parse time; this pass checks that every
            // `run(X)` inside a `parallel:` must reference a plugin whose
            // mode admits concurrent execution (Audit / Concurrent /
            // FireAndForget). Sequential / Transform plugins would silently
            // lose their mutations inside cloned branches. This is about
            // scheduling correctness only.
            //
            // Modes are looked up through the praxis-policy-core PolicyEngine,
            // which holds the authoritative registration state, via the
            // `PluginModeLookup` trait it implements. That trait and the check
            // called below both live in the sibling parallel-safety module.
            //
            // Module paths are spelled in prose here on purpose: clippy reads a
            // comment containing that module's name followed by a colon as a
            // memory-safety justification and rejects it on safe code.
            if let Err(msg) =
                crate::parallel_safety::validate_parallel_plugin_modes(&effective, mgr.as_ref())
            {
                let err_msg = format!("route '{route_key}': parallel-safety: {msg}");
                return Err(err_msg.into());
            }

            // Repeat elicitation validation after stacking to catch duplicates
            // introduced across global, group, and route layers.
            for (phase, effects) in [
                ("pre_invocation", &effective.pre_invocation),
                ("post_invocation", &effective.post_invocation),
            ] {
                let elicits: usize = effects
                    .iter()
                    .map(praxis_policy_apl_core::rules::Effect::count_elicits)
                    .sum();
                if elicits > 1 {
                    let err_msg = format!(
                        "route '{route_key}': {phase} reaches {elicits} elicitation steps; at \
                         most one elicitation per phase is supported (they would share one retry \
                         id and resolve against each other)"
                    );
                    return Err(err_msg.into());
                }
            }

            // Each half installs only when the effective route declares steps
            // for it, the way the global catch-all already decides.
            let installs_pre = declares_pre_phase(&effective);
            let installs_post = declares_post_phase(&effective);

            let route_arc = Arc::new(effective);

            // Resolve the entity-specific hook pair. `route_entity_identity`
            // only names entity types this maps, but hook_pair_for_entity
            // returning None would just skip the annotation rather than crash,
            // as defense in depth.
            let (hook_pre, hook_post) = if let Some(pair) = hook_pair_for_entity(entity_type) {
                pair
            } else {
                tracing::warn!(
                    entity_type,
                    entity_name,
                    "APL visitor: no hook pair for entity_type — skipping route",
                );
                continue;
            };

            // Tally what this route reaches, for the load-time report in
            // `visit_complete`. Once per route rather than per entity name:
            // the steps and the hook pair are the same for every name a route
            // contributes, so the first is representative.
            if idx == 0 {
                self.record_reached_plugins(&route_arc, hook_pre, hook_post);
            }

            // Snapshot the static attribute tree (set before the walk).
            // Each handler captures its own `Arc` clone — shared, not copied.
            let attribute_tree = self
                .attribute_tree
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();

            // Install the halves the route declares. Each handler instance is
            // bound to ONE phase so the executor can pick the right entry-point
            // off the (entity_type, entity_name, scope, hook_name) key. The two
            // predicates cover all four phases between them, so a route that
            // reached here declares at least one and installs at least one
            // handler.
            if installs_pre {
                install_handler(
                    mgr,
                    entity_type,
                    entity_name,
                    scope.clone(),
                    hook_pre,
                    Phase::Pre,
                    Arc::clone(&route_arc),
                    &plugin_registry,
                    &self.dispatch_cache,
                    &session_store,
                    &self.engine,
                    Some(Arc::clone(&pdp_router_arc)),
                    &self.base_capabilities,
                    Arc::clone(&attribute_tree),
                );
            }
            if installs_post {
                install_handler(
                    mgr,
                    entity_type,
                    entity_name,
                    scope.clone(),
                    hook_post,
                    Phase::Post,
                    route_arc,
                    &plugin_registry,
                    &self.dispatch_cache,
                    &session_store,
                    &self.engine,
                    Some(Arc::clone(&pdp_router_arc)),
                    &self.base_capabilities,
                    attribute_tree,
                );
            }
        }

        Ok(())
    }
}

/// Refuse an `args:` or `result:` block declared at a scope that reaches only
/// a payload with no fields. Today that is the `http:` selector: an HTTP
/// exchange reaches a policy through its extensions, and `HttpPayload` has
/// nothing for a field path to address, so such a stage would read nothing and
/// rewrite nothing.
///
/// `scope` is the label the refusal names, already spelled the way its caller
/// names the declaration. Called for each scope whose reach is one entity type,
/// which is what gives it a payload to check: a route's own block and
/// `global.defaults.<entity>`. A bundle is shared by routes of several entity
/// types, and `global:` accepts neither block at all.
fn reject_field_stages_without_fields(
    entity_type: &str,
    scope: &str,
    layer: &CompiledRoute,
) -> Result<(), VisitorError> {
    if entity_type != ENTITY_HTTP {
        return Ok(());
    }
    let block = if !layer.args.is_empty() {
        "args"
    } else if !layer.result.is_empty() {
        "result"
    } else {
        return Ok(());
    };
    Err(format!(
        "{scope}: an `http:` route cannot declare a `{block}:` block, because a \
         generic HTTP request carries no message for a field path to address. Read the request \
         from the `http.*` attributes under `pre_invocation:` (or `post_invocation:`) instead."
    )
    .into())
}

#[allow(clippy::too_many_arguments)]
fn install_handler(
    mgr: &Arc<PolicyEngine>,
    entity_type: &str,
    entity_name: &str,
    scope: Option<String>,
    hook_name: &str,
    phase: Phase,
    route: Arc<CompiledRoute>,
    plugin_registry: &Arc<PluginRegistry>,
    dispatch_cache: &Arc<DispatchCache>,
    session_store: &Arc<dyn SessionStore>,
    engine: &Weak<PolicyEngine>,
    pdp: Option<Arc<dyn PdpResolver>>,
    base_capabilities: &std::collections::HashSet<String>,
    attribute_tree: Arc<AttributeTree>,
) {
    // The family decides which payload the handler accepts, and it is read off
    // the same entity type that chose the hook name, so the two cannot
    // disagree. An entity type with no family has no hook pair either, so the
    // install sites never reach this; skipping and logging matches what they
    // already do when `hook_pair_for_entity` returns `None`.
    let Some(family) = HookFamily::for_entity(entity_type) else {
        tracing::warn!(
            entity_type,
            entity_name,
            hook_name,
            "APL visitor: no hook family for entity_type — skipping handler install",
        );
        return;
    };

    // Capability gating at the synthetic-handler boundary. praxis-policy-core's
    // executor calls `filter_extensions(&ext, &caps)` before every
    // handler invoke — including this one. If the synthetic handler
    // has fewer capabilities than its downstream plugins need, the
    // executor strips extensions on the way in (so APL predicates and
    // downstream plugins see empty views) and rejects mutations on the
    // way out (label / delegation appends fail monotonicity checks).
    //
    // Granted caps = union of every plugin's caps (with per-route
    // overrides applied) ∪ host-supplied baseline. The baseline
    // typically covers read-only attributes APL predicates touch
    // (`subject.*`, `role.*`, `delegated`, …) even when no plugins are
    // referenced.
    let mut capabilities = base_capabilities.clone();
    capabilities.extend(crate::dispatch_plan::route_capability_union(
        &route,
        plugin_registry,
    ));
    // Every synthetic policy handler (the entity-less HTTP catch-all, per-entity
    // routes, and defaults) is granted `read_headers` so `http.*` request
    // attributes are available to policy evaluation wherever the host attaches
    // an `HttpExtension`. This lets an entity-route rule combine `http.*` with
    // entity/`args.*` predicates in one evaluation. It is a no-op for hosts that
    // never populate the HTTP extension (nothing to read).
    capabilities.insert("read_headers".to_owned());
    // The APL engine emits the backend candidate constraint (the `restrict`
    // effect's output) into `Extensions.candidate_constraint`. That slot is
    // write-gated in the executor, so the synthetic handler holds the write
    // capability intrinsically — emitting its own routing output, the same
    // way it emits taints. No other plugin can overwrite or drop it without
    // this capability. See `praxis_policy_core::extensions::CAP_WRITE_CANDIDATE_CONSTRAINT`.
    capabilities.insert(praxis_policy_core::extensions::CAP_WRITE_CANDIDATE_CONSTRAINT.to_owned());

    let plugin_config = PluginConfig {
        name: format!(
            "apl::{}::{}::{}",
            entity_type,
            entity_name,
            if phase == Phase::Pre { "pre" } else { "post" }
        ),
        kind: "builtin".to_owned(),
        // The annotated handler covers exactly one hook name.
        hooks: vec![hook_name.to_owned()],
        capabilities,
        ..Default::default()
    };
    let mut handler = AplRouteHandler::new(
        plugin_config.clone(),
        route,
        phase,
        family,
        Arc::clone(plugin_registry),
        Arc::clone(dispatch_cache),
        Arc::clone(session_store),
        engine.clone(),
    )
    .with_attribute_tree(attribute_tree);
    if let Some(pdp) = pdp {
        handler = handler.with_pdp(pdp);
    }
    let replaced = mgr.annotate_route(
        entity_type.to_owned(),
        entity_name.to_owned(),
        scope.clone(),
        hook_name.to_owned(),
        Arc::new(handler),
        plugin_config,
    );
    if replaced {
        // A handler already stood at these coordinates and has just been
        // dropped. Nothing in the table records where it came from, so saying
        // so is the only way an operator learns one policy body silently lost
        // to another.
        tracing::warn!(
            entity_type,
            entity_name,
            scope = scope.as_deref(),
            hook_name,
            "APL visitor: replaced an existing policy handler at these route \
             coordinates; only the later one evaluates",
        );
    }
}

/// The `plugins:` an `http:` route lists that its compiled policy body stands
/// in for. Empty for every other selector and for a route listing none, so a
/// configuration declaring no `http:` route gains no diagnostic.
///
/// Called where a handler is about to install, which is what makes the
/// substitution certain rather than possible.
fn displaced_plugin_chain<'a>(entity_type: &str, route: &'a RouteEntry) -> Vec<&'a str> {
    if entity_type != ENTITY_HTTP {
        return Vec::new();
    }
    route.plugins.iter().map(PluginRouteRef::name).collect()
}

/// Load-time lint: warn when an APL `plugins:` override is declared for a
/// plugin that no `run(...)` / `run(...)` policy step (or `delegate(...)`
/// step) in the effective route references. The `plugins:` map only
/// *configures* a plugin — policy steps do the *activating* — so an
/// unreferenced override has no effect and is almost always a typo or a
/// leftover. Inspects the fully-stacked route, so an override consumed by an
/// inherited (global / default / tag) policy is not falsely flagged. Called
/// once per route from `visit_route` at config-load time, never per request.
fn warn_unreferenced_plugin_overrides(route: &CompiledRoute) {
    if route.plugin_overrides.is_empty() {
        return;
    }
    let mut referenced: std::collections::HashSet<String> =
        crate::dispatch_plan::collect_plugin_names(route)
            .into_iter()
            .collect();
    referenced.extend(crate::dispatch_plan::collect_delegate_plugin_names(route));
    for name in route.plugin_overrides.keys() {
        if !referenced.contains(name) {
            tracing::warn!(
                plugin = %name,
                route = %route.route_key,
                "APL `plugins:` override declared for a plugin no policy step references \
                 — the override has no effect (the `plugins:` map configures; policy steps activate)",
            );
        }
    }
}

/// Strip the engine wiring keys
/// ([`praxis_policy_core::config::global_wiring_keys`]) from a section's policy
/// block so the remainder can be handed to `compile_policy_block_value`, which
/// models PDP, session-store, and attribute-file declarations nowhere. Returns
/// a clone of the mapping with those keys removed; the original is left intact.
fn strip_wiring_keys(apl_block: &serde_yaml::Value) -> serde_yaml::Value {
    let Some(map) = apl_block.as_mapping() else {
        return apl_block.clone();
    };
    let mut cloned = map.clone();
    for key in praxis_policy_core::config::global_wiring_keys() {
        cloned.remove(serde_yaml::Value::String(key.name.to_owned()));
    }
    serde_yaml::Value::Mapping(cloned)
}

/// Bridge praxis-policy-core's JSON-based `Option<serde_json::Value>` config slot
/// into praxis-policy-apl-core's `Option<serde_yaml::Value>` shape. JSON is a strict
/// subset of YAML's value model so this is round-trip safe; failure
/// here would only happen if `serde_yaml::to_value` rejects a value
/// `serde_json::Value` already accepted (in practice: never).
fn plugin_config_to_yaml(cfg: Option<&serde_json::Value>) -> Option<serde_yaml::Value> {
    cfg.and_then(|val| serde_yaml::to_value(val).ok())
}

/// Map praxis-policy-core's `OnError` enum onto the string shape praxis-policy-apl-core's
/// `PluginDeclaration` carries (kept stringly-typed there because the
/// APL spec also allows custom orchestrator-defined error modes).
fn on_error_to_string(on_err: &praxis_policy_core::plugin::OnError) -> String {
    on_err.to_string()
}

/// Assemble a section's APL block from the terms written directly on it.
///
/// One path: the recognized
/// [`praxis_policy_core::config::section_apl_block_keys`] present on the
/// container are copied into a synthetic block, plus `plugins` when (and only
/// when) it is a *mapping* — the apl-override shape. A structural `plugins:`
/// *list* (`RouteEntry` / `PolicyGroup`) is left untouched. Returns `None`
/// when the section carries no APL key at all — callers treat that as "no
/// contribution from this section" and move on.
fn apl_subblock(yaml: &serde_yaml::Value) -> Option<serde_yaml::Value> {
    // Copy only the unambiguous APL keys so structural keys
    // (tool / authentication / defaults / ...) are never misread.
    let mut block = serde_yaml::Mapping::new();
    for key in praxis_policy_core::config::section_apl_block_keys() {
        if let Some(value) = yaml.get(key.name) {
            block.insert(
                serde_yaml::Value::String(key.name.to_owned()),
                value.clone(),
            );
        }
    }
    // `plugins` only in its apl-override (map) shape; a list is the
    // structural plugin-ref form and belongs to the section's own parse.
    if let Some(value) = yaml.get("plugins")
        && value.is_mapping()
    {
        block.insert(
            serde_yaml::Value::String("plugins".to_owned()),
            value.clone(),
        );
    }

    if block.is_empty() {
        None
    } else {
        Some(serde_yaml::Value::Mapping(block))
    }
}

/// Whether a compiled layer declares Pre-phase steps, which is what decides
/// whether the Pre-phase handler installs. Read for the entity-less HTTP
/// catch-all and, in `visit_routes`, for every route's own effective layers,
/// so one rule decides both. Gate on both Pre-phase steps (`args` +
/// `pre_invocation`, via [`CompiledRoute::declared_phases`]), not
/// `pre_invocation` alone: a route whose
/// only Pre-phase declaration is an `args:` field pipeline must still get a
/// handler, or its request half silently bypasses the policy entirely
/// (fail-open by omission).
fn declares_pre_phase(compiled: &CompiledRoute) -> bool {
    let declared = compiled.declared_phases();
    declared.contains(praxis_policy_apl_core::rules::Phase::Args)
        || declared.contains(praxis_policy_apl_core::rules::Phase::PreInvocation)
}

/// Whether a compiled layer declares Post-phase steps. The mirror of
/// [`declares_pre_phase`] on the post side, gating on `result` +
/// `post_invocation`, so a layer that only authorizes gets no post handler and
/// a host that never fires the post hook sees no change either way.
fn declares_post_phase(compiled: &CompiledRoute) -> bool {
    let declared = compiled.declared_phases();
    declared.contains(praxis_policy_apl_core::rules::Phase::Result)
        || declared.contains(praxis_policy_apl_core::rules::Phase::PostInvocation)
}

/// A section's `response:` block, the transpiled `denyWith`. Not an APL term:
/// it never enters the constructive set [`apl_subblock`] copies, because the
/// policy compiler does not model it. It sits beside the policy terms on the
/// section, and one spelling is the only spelling.
fn response_yaml_block(yaml: &serde_yaml::Value) -> Option<&serde_yaml::Value> {
    yaml.get("response")
}

/// Warn when a `response:` block appears at a scope that never renders it.
/// A custom denial response is honored only at `global` (the entity-less
/// HTTP path) or on a route; at `default` / policy-bundle scope it is inert
/// — there is no propagation path to a handler. Mirrors the existing
/// global-only-key lint so a misplaced `response:` fails loud, not silent.
fn warn_if_response_at_unsupported_scope(yaml: &serde_yaml::Value, scope: &str) {
    if response_yaml_block(yaml).is_some_and(|v| !v.is_null()) {
        tracing::warn!(
            scope,
            "APL visitor: `response:` is honored only at `global` or route scope; ignoring here",
        );
    }
}

/// Extract a route-level `response:` block — the transpiled `denyWith`.
/// praxis-policy-core tolerates this out-of-band key on the route; here we
/// deserialize it into a [`DenyResponse`]. A malformed block is logged
/// and skipped (best-effort) rather than failing the whole config.
fn response_subblock(yaml: &serde_yaml::Value, route_key: &str) -> Option<DenyResponse> {
    let block = response_yaml_block(yaml)?;
    if block.is_null() {
        return None;
    }
    match serde_yaml::from_value::<DenyResponse>(block.clone()) {
        Ok(resp) => Some(resp),
        Err(e) => {
            tracing::warn!(route = route_key, error = %e, "APL visitor: ignoring malformed route `response:` block");
            None
        },
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use super::{
        AplConfigVisitor, ConfigVisitor as _, DispatchCache, ENTITY_HTTP, ENTITY_NAME_GLOBAL,
        ENTITY_TOOL, HOOK_CMF_TOOL_PRE_INVOKE, HOOK_HTTP_REQUEST, HOOK_HTTP_RESPONSE, PluginConfig,
        PluginRouteRef, PolicyEngine, RouteEntry, apl_subblock, declares_post_phase,
        declares_pre_phase, displaced_plugin_chain, response_subblock,
    };
    use crate::session_store::MemorySessionStore;
    use praxis_policy_apl_core::pipeline::{FieldRule, Pipeline, Stage, TypeCheck};
    use praxis_policy_apl_core::rules::{CompiledRoute, Effect};
    use praxis_policy_core::cmf::enums::Role;
    use praxis_policy_core::cmf::{CmfHook, Message, MessagePayload};
    use praxis_policy_core::config::{HttpSelector, Pattern, StringOrList};
    use praxis_policy_core::error::PluginViolation;
    use praxis_policy_core::extensions::{Extensions, HttpExtension, MetaExtension};
    use praxis_policy_core::factory::{PluginFactory, PluginInstance};
    use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
    use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
    use praxis_policy_core::http_hook::{HttpHook, HttpPayload};

    fn yaml(s: &str) -> serde_yaml::Value {
        serde_yaml::from_str(s).expect("valid yaml")
    }

    fn deny_effect() -> Effect {
        Effect::Deny {
            reason: None,
            code: None,
        }
    }

    fn field_rule(field: &str) -> FieldRule {
        FieldRule {
            field: field.to_owned(),
            pipeline: Pipeline {
                stages: vec![Stage::Type(TypeCheck::Str)],
            },
            source: "test".to_owned(),
        }
    }

    #[test]
    fn http_catchall_installs_for_args_only_global_block() {
        // Regression for the fail-open-by-omission gap: a `global:` block with
        // only `args:` (no steps) must still get the entity-less HTTP
        // catch-all installed. Before the fix this gated on
        // `!compiled.pre_invocation.is_empty()` alone, so an args-only admission
        // block silently disabled authorization for all entity-less HTTP
        // traffic.
        let mut route = CompiledRoute::new("global");
        route.args.push(field_rule("http.method"));
        assert!(
            declares_pre_phase(&route),
            "an args-only global block must still install the catch-all handler"
        );
    }

    #[test]
    fn http_catchall_installs_for_policy_only_global_block() {
        let mut route = CompiledRoute::new("global");
        route.pre_invocation.push(deny_effect());
        assert!(declares_pre_phase(&route));
    }

    #[test]
    fn http_catchall_does_not_install_for_empty_or_post_only_global_block() {
        let empty = CompiledRoute::new("global");
        assert!(
            !declares_pre_phase(&empty),
            "an empty global block has nothing to evaluate; installing would be a no-op handler"
        );

        let mut post_only = CompiledRoute::new("global");
        post_only.post_invocation.push(deny_effect());
        assert!(
            !declares_pre_phase(&post_only),
            "post_invocation never runs on the Pre-phase-only catch-all, so it must not gate installation"
        );
    }

    /// Every `Phase` must be claimed by exactly one install predicate, or a
    /// route declaring only that phase installs no handler and evaluates
    /// nothing. The match below is exhaustive, so a fifth variant fails to
    /// compile here instead of silently installing nothing.
    #[test]
    fn every_phase_is_claimed_by_exactly_one_install_predicate() {
        use praxis_policy_apl_core::rules::Phase;
        for phase in [
            Phase::Args,
            Phase::PreInvocation,
            Phase::Result,
            Phase::PostInvocation,
        ] {
            let mut route = CompiledRoute::new("r");
            let is_pre = match phase {
                Phase::Args => {
                    route.args.push(field_rule("a"));
                    true
                },
                Phase::PreInvocation => {
                    route.pre_invocation.push(deny_effect());
                    true
                },
                Phase::Result => {
                    route.result.push(field_rule("r"));
                    false
                },
                Phase::PostInvocation => {
                    route.post_invocation.push(deny_effect());
                    false
                },
            };
            assert_eq!(declares_pre_phase(&route), is_pre, "pre for {phase:?}");
            assert_eq!(declares_post_phase(&route), !is_pre, "post for {phase:?}");
        }
    }

    #[test]
    fn response_subblock_parses_denywith() {
        let v = yaml(
            "tool: \"*\"\nresponse:\n  status: 403\n  body: \"{\\\"error\\\":\\\"forbidden\\\"}\"\n  headers:\n    WWW-Authenticate: \"Bearer\"\n",
        );
        let resp = response_subblock(&v, "tool:*").expect("response present");
        assert_eq!(resp.status, Some(403));
        assert_eq!(resp.body.as_deref(), Some("{\"error\":\"forbidden\"}"));
        assert_eq!(
            resp.headers.get("WWW-Authenticate").map(String::as_str),
            Some("Bearer")
        );
    }

    #[test]
    fn response_subblock_absent_is_none() {
        let v = yaml("tool: \"*\"\npolicy:\n  - \"deny\"\n");
        assert!(response_subblock(&v, "tool:*").is_none());
    }

    /// One spelling, one precedence rule: `response:` is read from the section
    /// and nowhere else, so a nested one is an unknown key rather than a
    /// second-choice source.
    #[test]
    fn response_subblock_reads_the_section_and_nothing_nested() {
        let v = yaml(
            "tool: \"*\"\nauthorization:\n  pre_invocation:\n    - \"deny\"\nresponse:\n  status: 403\n",
        );
        let resp = response_subblock(&v, "tool:*").expect("response present");
        assert_eq!(resp.status, Some(403));
    }

    #[test]
    fn response_subblock_malformed_is_none_not_propagated() {
        // `status` must deserialize as a u16; a string value fails to parse.
        // A malformed block must be dropped (warn-only), never bubble up an
        // error that fails the whole config load.
        let v = yaml("tool: \"*\"\nresponse:\n  status: \"not-a-number\"\n");
        assert!(
            response_subblock(&v, "tool:*").is_none(),
            "malformed response: block must be ignored, not panic or propagate an error"
        );
    }

    /// The report an operator gets for the one case where something they wrote
    /// stops firing: an `http:` route whose policy body stands in for the
    /// `plugins:` it also lists.
    #[test]
    fn an_http_route_listing_plugins_names_them_as_displaced() {
        let route = RouteEntry {
            http: Some(HttpSelector::prefix("/v1/files")),
            plugins: vec![
                PluginRouteRef::Name("corp-jwt".to_owned()),
                PluginRouteRef::Name("audit".to_owned()),
            ],
            ..RouteEntry::default()
        };
        assert_eq!(
            displaced_plugin_chain(ENTITY_HTTP, &route),
            ["corp-jwt", "audit"],
            "the report names what stops firing, in the order it was written"
        );
    }

    /// Nothing an operator wrote is displaced, so there is nothing to say.
    #[test]
    fn an_http_route_listing_no_plugins_displaces_nothing() {
        let route = RouteEntry {
            http: Some(HttpSelector::exact("/healthz")),
            ..RouteEntry::default()
        };
        assert!(displaced_plugin_chain(ENTITY_HTTP, &route).is_empty());
    }

    /// The substitution is as old as entity routes, so reporting it for one
    /// would be new noise on a configuration nobody edited.
    #[test]
    fn an_entity_route_listing_plugins_is_not_reported() {
        let route = RouteEntry {
            tool: Some(StringOrList::Single(Pattern::new("get_compensation"))),
            plugins: vec![PluginRouteRef::Name("corp-jwt".to_owned())],
            ..RouteEntry::default()
        };
        assert!(displaced_plugin_chain(ENTITY_TOOL, &route).is_empty());
    }

    #[test]
    fn warn_if_response_at_unsupported_scope_is_a_safe_noop() {
        use super::warn_if_response_at_unsupported_scope;
        // The helper only emits a tracing event; it must never panic whether
        // `response:` is present or absent at a scope that can't render it.
        let with_response = yaml("policy:\n  - \"deny\"\nresponse:\n  status: 403\n");
        let without = yaml("policy:\n  - \"deny\"\n");
        warn_if_response_at_unsupported_scope(&with_response, "global.defaults.tool");
        warn_if_response_at_unsupported_scope(&with_response, "groups.some-tag");
        warn_if_response_at_unsupported_scope(&without, "global.defaults.tool");
    }

    #[test]
    fn a_policy_term_on_the_section_is_collected() {
        let v = yaml("tool: get_weather\nauthorization:\n  pre_invocation:\n    - \"deny\"\n");
        let block = apl_subblock(&v).expect("authorization recognized");
        assert!(
            block.get("authorization").is_some(),
            "the `authorization:` block is lifted into the synthetic block"
        );
        assert!(
            block.get("tool").is_none(),
            "structural keys must not leak into the apl block",
        );
    }

    #[test]
    fn a_session_store_on_the_section_is_collected() {
        // `session_store:` on `global:` is lifted into the block so
        // `visit_global` can act on it, the same way `pdp:` is.
        let v = yaml("session_store:\n  kind: valkey\n  endpoint: localhost:6379\n");
        let block = apl_subblock(&v).expect("session_store recognized");
        let ss = block
            .get("session_store")
            .expect("session_store lifted into the block");
        assert_eq!(
            ss.get("kind").and_then(|k| k.as_str()),
            Some("valkey"),
            "the session_store mapping is preserved intact",
        );
    }

    /// `attribute_files:` has no wrapper to hide behind any more, so the block
    /// is the only path by which `visit_global` can reach it.
    #[test]
    fn attribute_files_on_the_section_is_collected() {
        let v = yaml("attribute_files:\n  - attrs.yaml\n");
        let block = apl_subblock(&v).expect("attribute_files recognized");
        assert_eq!(
            block
                .get("attribute_files")
                .and_then(|f| f.as_sequence())
                .map(Vec::len),
            Some(1),
            "the attribute_files list is preserved intact",
        );
    }

    /// The wiring keys reach `visit_global` through the block but must never
    /// reach the policy compiler.
    #[test]
    fn the_wiring_keys_are_stripped_before_compilation() {
        use super::strip_wiring_keys;
        let block = yaml(
            "authorization:\n  pre_invocation:\n    - \"deny\"\npdp:\n  - kind: cel\nsession_store:\n  kind: valkey\nattribute_files:\n  - attrs.yaml\n",
        );
        let stripped = strip_wiring_keys(&block);
        for key in ["pdp", "session_store", "attribute_files"] {
            assert!(
                stripped.get(key).is_none(),
                "`{key}` must not reach the policy compiler"
            );
        }
        assert!(
            stripped.get("authorization").is_some(),
            "the policy terms survive the strip"
        );
    }

    #[test]
    fn flat_plugins_map_included_but_list_excluded() {
        // Map shape is the apl-override form → kept.
        let m = yaml("plugins:\n  audit:\n    on_error: ignore\n");
        let block = apl_subblock(&m).expect("plugins map is an apl term");
        assert!(block.get("plugins").is_some(), "plugins map is kept");

        // List shape is structural plugin-refs → not an apl block; with no
        // other APL keys present, the section contributes nothing.
        let l = yaml("plugins:\n  - audit\n");
        assert!(
            apl_subblock(&l).is_none(),
            "structural plugins list must not be treated as an apl block",
        );
    }

    #[test]
    fn section_without_apl_terms_is_none() {
        let v = yaml("tool: get_weather\n");
        assert!(
            apl_subblock(&v).is_none(),
            "no APL terms => no contribution"
        );
    }

    /// A stale `apl:` wrapper contributes nothing: it is not a policy term, so
    /// the block is assembled from the section's own terms and the wrapper's
    /// contents are the loader's to reject.
    #[test]
    fn a_stale_apl_wrapper_is_not_a_policy_term() {
        let v = yaml("apl:\n  authorization:\n    pre_invocation:\n      - \"allow\"\n");
        assert!(
            apl_subblock(&v).is_none(),
            "`apl:` is no longer a key the block is built from"
        );
    }

    #[test]
    fn unreferenced_plugin_override_is_detectable_and_lint_is_safe() {
        use super::{compile_policy_block_value, warn_unreferenced_plugin_overrides};
        // A route configures two plugins but its pre_invocation only activates one:
        // `used` is referenced by a `run(...)` step, `unused` is only
        // configured. The lint relies on `collect_plugin_names` seeing the
        // referenced set; verify that linkage, then that the helper runs.
        let block = yaml(
            "authorization:\n  pre_invocation:\n    - \"run(used)\"\n\
             plugins:\n  used:\n    on_error: ignore\n  unused:\n    on_error: ignore\n",
        );
        let route = compile_policy_block_value("test", &block).expect("compiles");

        let referenced = crate::dispatch_plan::collect_plugin_names(&route);
        assert!(
            referenced.contains(&"used".to_owned()),
            "pre_invocation step is referenced"
        );
        assert!(
            !referenced.contains(&"unused".to_owned()),
            "config-only override is not a reference",
        );
        assert!(
            route.plugin_overrides.contains_key("unused"),
            "override was compiled in"
        );

        // Must not panic; it warns on `unused` and stays silent on `used`.
        warn_unreferenced_plugin_overrides(&route);
    }

    /// A route naming no selector has no name to annotate under, so the visitor
    /// reports it and moves on rather than installing a handler nothing can
    /// reach. Observed through the engine generation, which only an annotation
    /// bumps.
    #[test]
    fn a_route_with_no_selector_is_skipped_rather_than_annotated() {
        let engine = Arc::new(PolicyEngine::default());
        let visitor = AplConfigVisitor::new(
            Arc::new(DispatchCache::new()),
            Arc::new(MemorySessionStore::new()),
            Arc::downgrade(&engine),
        );
        let before = engine.config_generation();

        visitor
            .visit_route(
                &engine,
                &yaml("authorization:\n  pre_invocation:\n    - \"deny\"\n"),
                &RouteEntry::default(),
            )
            .expect("a selector-less route is skipped, not a load failure");

        assert_eq!(
            engine.config_generation(),
            before,
            "nothing may be annotated for a route with no name"
        );
    }

    // -- Dispatch end to end --
    //
    // A compiled policy body reaches a request through the annotation the
    // visitor installed, so these drive a real engine rather than inspecting
    // the visitor's own state. Every fixture sets
    // `engine_settings.dispatch: policy` explicitly, which the `http:`
    // selector requires and which is also the default.

    /// A plugin that denies whatever reaches it, so a structural chain that
    /// runs when it should not is visible as a denial with this code.
    const CHAIN_VIOLATION: &str = "test.structural.chain.fired";

    struct ChainDeny {
        cfg: PluginConfig,
    }

    #[async_trait::async_trait]
    impl praxis_policy_core::plugin::Plugin for ChainDeny {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    impl HookHandler<HttpHook> for ChainDeny {
        async fn handle(
            &self,
            _payload: &HttpPayload,
            _extensions: &praxis_policy_core::extensions::Extensions,
            _ctx: &mut praxis_policy_core::context::PluginContext,
        ) -> PluginResult<HttpPayload> {
            PluginResult::deny(PluginViolation::new(
                CHAIN_VIOLATION,
                "the route's plugin chain ran",
            ))
        }
    }

    struct ChainDenyFactory;

    impl PluginFactory for ChainDenyFactory {
        fn create(
            &self,
            config: &PluginConfig,
        ) -> Result<PluginInstance, Box<praxis_policy_core::error::PluginError>> {
            let plugin = Arc::new(ChainDeny {
                cfg: config.clone(),
            });
            let handler: Arc<dyn praxis_policy_core::registry::AnyHookHandler> =
                Arc::new(TypedHandlerAdapter::<HttpHook, _>::new(Arc::clone(&plugin)));
            Ok(PluginInstance {
                plugin,
                handlers: vec![(HOOK_HTTP_REQUEST, handler)],
            })
        }
    }

    /// An initialized engine with the APL visitor walked over `yaml`.
    async fn engine_with(yaml: &str) -> Arc<PolicyEngine> {
        let mgr = Arc::new(PolicyEngine::default());
        mgr.register_factory("test/chain-deny", Box::new(ChainDenyFactory));
        crate::register_apl(&mgr, crate::AplOptions::in_process());
        mgr.load_config_yaml(yaml).expect("the fixture must load");
        mgr.initialize().await.expect("initialize");
        mgr
    }

    fn payload() -> MessagePayload {
        MessagePayload {
            message: Message::text(Role::User, "hi"),
        }
    }

    /// A generic HTTP request as a host presents one: the reserved entity
    /// coordinates plus the request line on its own slot.
    fn http_request(method: &str, path: Option<&str>) -> Extensions {
        Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some(ENTITY_HTTP.to_owned()),
                entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
                ..Default::default()
            })),
            http: Some(Arc::new(HttpExtension {
                method: Some(method.to_owned()),
                path: path.map(str::to_owned),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn tool_request(name: &str) -> Extensions {
        Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some(ENTITY_TOOL.to_owned()),
                entity_name: Some(name.to_owned()),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    /// Two `http:` routes, one carrying a body and one carrying nothing.
    const HTTP_ROUTE_BODIES: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "http.method == 'DELETE': deny"
  - http: /healthz
"#;

    #[tokio::test]
    async fn an_http_prefix_route_evaluates_its_policy_body() {
        let mgr = engine_with(HTTP_ROUTE_BODIES).await;

        let (denied, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request("DELETE", Some("/v1/files/q3.pdf")),
                None,
            )
            .await;
        assert!(
            !denied.continue_processing,
            "the route's body must evaluate for a path its prefix matches"
        );

        let (allowed, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request("GET", Some("/v1/files/q3.pdf")),
                None,
            )
            .await;
        assert!(
            allowed.continue_processing,
            "the body allows a GET; violation = {:?}",
            allowed.violation
        );
    }

    #[tokio::test]
    async fn an_exact_http_route_with_no_body_inherits_nothing() {
        let mgr = engine_with(HTTP_ROUTE_BODIES).await;

        let (result, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request("DELETE", Some("/healthz")),
                None,
            )
            .await;
        assert!(
            result.continue_processing,
            "the exact route resolved and carries nothing, so the sibling \
             route's body must not reach it; violation = {:?}",
            result.violation
        );
    }

    /// A declared plugin no route names. Under policy dispatch this no longer
    /// loads at all, which is a stronger guarantee than the request-time one it
    /// used to carry: nothing has to run for the gap to be reported.
    const HTTP_ROUTE_WITHOUT_A_STEP: &str = "
engine_settings:
  dispatch: policy
plugins:
  - name: chain-deny
    kind: test/chain-deny
    hooks: [http.request]
    mode: sequential
routes:
  - http:
      path_prefix: /v1/files
";

    /// The same plugin, invoked by the route's own policy body.
    const HTTP_ROUTE_WITH_A_RUN_STEP: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: chain-deny
    kind: test/chain-deny
    hooks: [http.request]
    mode: sequential
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "run(chain-deny)"
"#;

    /// A declared plugin runs because a policy step names it, and a config where
    /// nothing names it does not load.
    ///
    /// The unreached half used to be asserted at request time, by observing that
    /// a deny-always plugin let the request through. It is a load error now, so
    /// the assertion moved to the load: an operator finds the gap without
    /// serving a request against it first.
    #[tokio::test]
    async fn a_route_reaches_a_plugin_only_through_a_run_step() {
        let mgr = Arc::new(PolicyEngine::default());
        mgr.register_factory("test/chain-deny", Box::new(ChainDenyFactory));
        crate::register_apl(&mgr, crate::AplOptions::in_process());
        let message = mgr
            .load_config_yaml(HTTP_ROUTE_WITHOUT_A_STEP)
            .expect_err("no step names the plugin, so the config cannot dispatch it")
            .to_string();
        assert!(
            message.contains("chain-deny"),
            "the load error must name the plugin nothing reaches: {message}"
        );

        let with = engine_with(HTTP_ROUTE_WITH_A_RUN_STEP).await;
        let (denied, _bg) = with
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request("GET", Some("/v1/files/q3.pdf")),
                None,
            )
            .await;
        let violation = denied.violation.expect("the step's plugin denies");
        assert_eq!(
            violation.code, CHAIN_VIOLATION,
            "a `run(name)` step is what activates a plugin in policy mode"
        );
    }

    /// A glob route under one of the four MCP selectors. The annotation is
    /// installed under the pattern as written, and the lookup is exact
    /// equality, so a request named by a glob never reaches the body.
    const GLOB_TOOL_ROUTE: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - tool: "hr-*"
    authorization:
      pre_invocation:
        - "deny"
"#;

    #[tokio::test]
    async fn a_glob_tool_route_still_does_not_evaluate_its_policy_body() {
        let mgr = engine_with(GLOB_TOOL_ROUTE).await;

        let (allowed, _bg) = mgr
            .invoke_named::<CmfHook>(
                HOOK_CMF_TOOL_PRE_INVOKE,
                payload(),
                tool_request("hr-lookup"),
                None,
            )
            .await;
        assert!(
            allowed.continue_processing,
            "a name the glob matches does not equal the pattern the handler is \
             installed under, so the body does not evaluate; violation = {:?}",
            allowed.violation
        );

        // The handler exists and its body denies, so the line above is the
        // lookup and not a missing installation.
        let (denied, _bg) = mgr
            .invoke_named::<CmfHook>(
                HOOK_CMF_TOOL_PRE_INVOKE,
                payload(),
                tool_request("hr-*"),
                None,
            )
            .await;
        assert!(
            !denied.continue_processing,
            "the body is installed under the pattern as written"
        );
    }

    /// A list selector contributes one name per element.
    const LIST_TOOL_ROUTE: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - tool: [alpha, beta]
    authorization:
      pre_invocation:
        - "deny"
"#;

    #[tokio::test]
    async fn a_list_tool_route_dispatches_for_every_element() {
        let mgr = engine_with(LIST_TOOL_ROUTE).await;

        for name in ["alpha", "beta"] {
            let (denied, _bg) = mgr
                .invoke_named::<CmfHook>(
                    HOOK_CMF_TOOL_PRE_INVOKE,
                    payload(),
                    tool_request(name),
                    None,
                )
                .await;
            assert!(
                !denied.continue_processing,
                "{name} is one of the names the list contributes"
            );
        }

        let (allowed, _bg) = mgr
            .invoke_named::<CmfHook>(
                HOOK_CMF_TOOL_PRE_INVOKE,
                payload(),
                tool_request("gamma"),
                None,
            )
            .await;
        assert!(
            allowed.continue_processing,
            "a name the list does not contain reaches no handler; violation = {:?}",
            allowed.violation
        );
    }

    /// One `http:` route declaring both halves.
    const HTTP_ROUTE_BOTH_HALVES: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "http.method == 'DELETE': deny"
      post_invocation:
        - "http.method == 'TRACE': deny"
"#;

    #[tokio::test]
    async fn both_http_halves_resolve_the_same_route() {
        let mgr = engine_with(HTTP_ROUTE_BOTH_HALVES).await;
        assert!(
            mgr.has_hooks_for(HOOK_HTTP_REQUEST) && mgr.has_hooks_for(HOOK_HTTP_RESPONSE),
            "a route declaring both halves installs both"
        );

        let (denied_in, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request("DELETE", Some("/v1/files/q3.pdf")),
                None,
            )
            .await;
        assert!(!denied_in.continue_processing, "the request half enforces");

        let (denied_out, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_RESPONSE,
                HttpPayload,
                http_request("TRACE", Some("/v1/files/q3.pdf")),
                None,
            )
            .await;
        assert!(
            !denied_out.continue_processing,
            "the response half resolves the same route given the request line"
        );
    }

    #[tokio::test]
    async fn a_response_invocation_without_the_request_line_behaves_as_before() {
        let mgr = engine_with(HTTP_ROUTE_BOTH_HALVES).await;

        let (result, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_RESPONSE,
                HttpPayload,
                http_request("TRACE", None),
                None,
            )
            .await;
        assert!(
            result.continue_processing,
            "with no request line nothing resolves and the global policy \
             governs, which is what a host that never set it gets today; \
             violation = {:?}",
            result.violation
        );
    }

    /// A global HTTP policy alongside an explicit catch-all route. The two
    /// occupy different annotation keys, and each rule below belongs to only
    /// one of them.
    const GLOBAL_PLUS_CATCHALL_ROUTE: &str = r#"
engine_settings:
  dispatch: policy
global:
  authorization:
    pre_invocation:
      - "http.method == 'PATCH': deny"
routes:
  - http:
      path_prefix: /
    authorization:
      pre_invocation:
        - "http.method == 'DELETE': deny"
"#;

    #[tokio::test]
    async fn an_explicit_catchall_route_and_the_global_policy_both_survive() {
        let mgr = engine_with(GLOBAL_PLUS_CATCHALL_ROUTE).await;

        let (denied, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request("DELETE", Some("/anything/at/all")),
                None,
            )
            .await;
        assert!(
            !denied.continue_processing,
            "the route governs every path it resolves"
        );

        // Nothing resolves without a request line, which is where the
        // implicit install under the reserved name applies. Its own rule
        // still fires there, so the route did not replace its handler.
        let (denied_global, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request("PATCH", None),
                None,
            )
            .await;
        assert!(
            !denied_global.continue_processing,
            "the implicit catch-all still governs what resolves nothing"
        );

        let (allowed, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request("DELETE", None),
                None,
            )
            .await;
        assert!(
            allowed.continue_processing,
            "the route's rule is the route's alone; violation = {:?}",
            allowed.violation
        );
    }
}
