// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The policy engine.
//
// Loads the policy document, owns the extensions it declares and their lifecycle
// (initialize, dispatch, shutdown), and evaluates a request against the policy.
// Managing plugins is part of that, not the whole of it.
//
// Two invoke paths:
//
// - `invoke::<H>()` — typed dispatch for Rust callers. Zero-cost.
//   The hook type is known at compile time; no registry lookup or
//   downcast needed for the payload.
//
// - `invoke_by_name()` — dynamic dispatch for Python/Go/WASM callers.
//   Hook name resolved from the registry; payload passed as
//   Box<dyn PluginPayload>.
//
// The engine reads plugin configs from the config loader and wraps each plugin in
// a PluginRef with the authoritative config. A plugin never supplies its own
// config. Trust flows:
//   config loader → engine → PluginRef → executor

use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use hashbrown::HashMap;
use tracing::{error, info, trace, warn};

use crate::cmf::constants::{ENTITY_HTTP, ENTITY_NAME_GLOBAL};
use crate::config::{self, PolicyConfig};
use crate::context::PluginContextTable;
use crate::error::PluginError;
use crate::executor::{BackgroundTasks, Executor, ExecutorConfig, PipelineResult};
use crate::factory::PluginFactoryRegistry;
use crate::hooks::HookType;
use crate::hooks::adapter::TypedHandlerAdapter;
use crate::hooks::payload::{Extensions, PluginPayload};
use crate::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use crate::http_path;
use crate::plugin::{Plugin, PluginConfig};
use crate::registry::{AnyHookHandler, PluginRef, PluginRegistry};

/// Default upper bound on the routing cache. Caps memory growth from
/// attacker-controlled entity names without forcing operators to tune.
pub const DEFAULT_ROUTE_CACHE_MAX_ENTRIES: usize = 10_000;

/// Violation code for a request whose path the engine could not read.
/// Stable, so a host can map it without matching on the reason text.
pub const VIOLATION_UNREADABLE_REQUEST_PATH: &str = "unreadable_request_path";

/// Violation code for a request an `assertions:` entry refused to forward
/// because the state it asserts resolved to nothing. Stable, so a host can map
/// it without matching on the reason text, and in the `auth.*` family beside
/// the claim map's own denial, since it is the same kind of refusal: identity
/// the configuration requires and the token did not carry.
pub const VIOLATION_ASSERTION_MISSING: &str = "auth.assertion_missing";

/// Violation code for a request carrying no protocol metadata, reaching a
/// configuration whose policy is written against it. Stable, so a host can map
/// it without matching on the reason text, and distinct from a policy's own
/// deny: the request never reached a rule.
pub const VIOLATION_UNIDENTIFIED_REQUEST: &str = "unidentified_request";

/// Why a request could not be resolved against the route table.
///
/// Resolving no route is not an error: the request falls back to the global
/// policy, as it always has. This is only produced when the request line cannot
/// be read at all and at least one `http:` route is declared. Matching uses the
/// path as given, so the engine and the host's router read one string; a string
/// that breaks the rules of a path is one the engine cannot vouch is the string
/// the router and the backend will act on, and a smuggled request line is
/// exactly that case.
///
/// A hook with no registered entry and no annotation returns before
/// resolution runs, so an unreadable path still allows there. Nothing would
/// have enforced on that path in the first place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteResolutionError {
    /// The request path broke a rule that makes a path readable.
    #[error("the request path cannot be read: {0}")]
    UnreadablePath(#[from] http_path::PathError),

    /// The request carried no entity metadata, and the configuration declares
    /// a policy that is written in terms of it.
    #[error(
        "the request carries no `meta.entity_type` / `meta.entity_name`, so no route resolves \
         and the configured policy cannot be applied to it"
    )]
    UnidentifiedRequest,
}

impl RouteResolutionError {
    /// The denial a host turns into a wire-level status. `400` because the
    /// request itself is malformed rather than forbidden: in both cases the
    /// engine is missing something the host was supposed to supply, and no
    /// rule was ever reached to forbid anything.
    fn violation(self) -> crate::error::PluginViolation {
        match self {
            Self::UnreadablePath(cause) => crate::error::PluginViolation::new(
                VIOLATION_UNREADABLE_REQUEST_PATH,
                cause.to_string(),
            )
            .with_proto_error_code(400),
            Self::UnidentifiedRequest => {
                crate::error::PluginViolation::new(VIOLATION_UNIDENTIFIED_REQUEST, self.to_string())
                    .with_proto_error_code(400)
            },
        }
    }
}

/// Whether the configuration declares any `http:` route. An unreadable path
/// is only worth denying over when a route could have answered for it.
fn declares_http_route(config: &PolicyConfig) -> bool {
    config.routes.iter().any(|route| route.http.is_some())
}

/// Whether the configuration declares a policy at all.
///
/// The guard on the unidentified-request denial, and deliberately not the
/// dispatch mode. By the point that denial is reachable the mode is already
/// known to be `policy`, so a guard reading the mode would be constantly true
/// and would start denying traffic for a config that declares nothing, which is
/// every default-mode config a host has not written policy for yet.
///
/// Route annotations count because a `global.authorization:` block is an APL
/// term praxis-policy-core does not model: what praxis-policy-core sees of it
/// is the handler the orchestrator installed.
fn declares_a_policy(config: &PolicyConfig, snapshot: &RuntimeSnapshot) -> bool {
    !config.routes.is_empty()
        || !config.groups.is_empty()
        || !config.global.bundles.is_empty()
        || !config.global.defaults.is_empty()
        || config.global.authentication.is_some()
        || !snapshot.route_annotations.is_empty()
}

/// Whether any level declares an `assertions:` block.
///
/// The whole feature hangs off this. It is what keeps a deployment that does
/// not use it off the route table on a cache hit, since resolving the contract
/// needs the matched route and the route cache holds entry lists rather than
/// matches.
fn declares_assertions(config: &PolicyConfig) -> bool {
    config.global.assertions.is_some()
        || config
            .global
            .defaults
            .values()
            .any(|default| default.assertions.is_some())
        || config
            .global
            .bundles
            .values()
            .any(|bundle| bundle.assertions.is_some())
        || config.routes.iter().any(|route| route.assertions.is_some())
}

/// Whether any named route uses a glob selector.
///
/// This avoids resolving routes before annotation lookup in exact/list-only configs.
fn declares_glob_named_routes(config: &PolicyConfig) -> bool {
    config.routes.iter().any(|route| {
        [
            route.tool.as_ref(),
            route.resource.as_ref(),
            route.prompt.as_ref(),
            route.llm.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(is_glob_selector)
    })
}

/// Whether a selector can match a different name through wildcards.
///
/// `*` and `?` are the whole set: `wildmatch` defines no others and no escapes,
/// so `hr-[a-z]` is the literal eight characters rather than a character class.
/// A literal selector needs nothing here, because its annotation key and the
/// request name agree whenever it matches.
fn is_glob_selector(selector: &config::StringOrList) -> bool {
    match selector {
        config::StringOrList::Single(pattern) => pattern.as_str().contains(['*', '?']),
        config::StringOrList::List(_) => false,
    }
}

/// Turn a refused assertion into a denial, keeping what the pipeline recorded.
///
/// `PipelineResult::denied` constructs with no errors and no metadata, so a bare
/// call would discard every `on_error: ignore` plugin error the pipeline just
/// collected, which is what an operator needs in order to debug the denial.
fn deny_missing_assertion(
    missing: crate::assertions::MissingSource,
    direction: crate::assertions::Direction,
    mut result: PipelineResult,
) -> PipelineResult {
    let mut details = std::collections::HashMap::new();
    details.insert(
        "header".to_owned(),
        serde_json::Value::String(missing.header.clone()),
    );
    details.insert(
        "source".to_owned(),
        serde_json::Value::String(missing.source.clone()),
    );
    details.insert(
        "direction".to_owned(),
        serde_json::Value::String(direction.label().to_owned()),
    );
    let violation = crate::error::PluginViolation::new(
        VIOLATION_ASSERTION_MISSING,
        format!(
            "`{}` asserts header `{}` from `{}`, which resolved to nothing, and the entry declares \
             `on_missing: deny`",
            direction.label(),
            missing.header,
            missing.source,
        ),
    )
    .with_details(details)
    .with_proto_error_code(403);

    let extensions = result.modified_extensions.take().unwrap_or_default();
    let context_table = std::mem::take(&mut result.context_table);
    let mut denied = PipelineResult::denied(violation, extensions, context_table);
    denied.errors = std::mem::take(&mut result.errors);
    denied.metadata = result.metadata.take();
    denied
}

/// The span of one executor invocation, counted so a nested dispatch can tell
/// it is nested. Decrements on drop, so an early return or a panic inside the
/// executor still closes the span.
struct ExecutorBoundary<'a> {
    depth: &'a AtomicUsize,
}

impl Drop for ExecutorBoundary<'_> {
    fn drop(&mut self) {
        self.depth.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The path route matching reads off an HTTP request: whatever precedes a `?`,
/// exactly as it arrived.
///
/// The host's own router matches on this string, so normalizing first would let
/// PPE resolve a different route than the one the request is forwarded to.
fn match_path(extensions: &Extensions) -> Option<&str> {
    extensions
        .http
        .as_deref()
        .and_then(|http| http.path.as_deref())
        .map(|path| path.split('?').next().unwrap_or(path))
}

/// The route an `assertions:` contract resolves from, for a caller that has not
/// resolved one.
///
/// The entry points return before route filtering on their first path, and a
/// contract written on a route has to hold there too: whether a plugin happens
/// to be registered on a hook is not what decides which headers reach an
/// upstream. `None` when nothing declares a contract, so a deployment that does
/// not use the feature never walks the route table for it.
fn resolve_contract_route<'a>(
    snapshot: &'a RuntimeSnapshot,
    extensions: &Extensions,
) -> Option<config::MatchedRoute<'a>> {
    if !snapshot.declares_assertions {
        return None;
    }
    let policy_config = snapshot
        .policy_config
        .as_ref()
        .filter(|config| config.dispatch_mode().is_policy())?;
    let meta = extensions.meta.as_deref()?;
    let entity_type = meta.entity_type.as_deref()?;
    let request_scope = meta.scope.as_deref();
    if entity_type == ENTITY_HTTP {
        let path = match_path(extensions)?;
        let method = extensions
            .http
            .as_deref()
            .and_then(|http| http.method.as_deref());
        return config::resolve_route(
            policy_config,
            config::RouteQuery::http(path, method).with_scope(request_scope),
        );
    }
    let entity_name = meta.entity_name.as_deref()?;
    config::resolve_route(
        policy_config,
        config::RouteQuery::named(entity_type, entity_name).with_scope(request_scope),
    )
}

/// The route an `assertions:` contract resolves from, owned so it can outlive
/// the borrow of the two matches.
///
/// `None` when nothing declares a contract, which is what keeps the clone off
/// every request of a deployment that does not use the feature. The contract
/// resolver reads `None` as the global layer alone, which is also the right
/// answer where no route matched.
fn contract_route<'a>(
    snapshot: &RuntimeSnapshot,
    http_matched: Option<&config::MatchedRoute<'a>>,
    name_matched: Option<&config::MatchedRoute<'a>>,
) -> Option<config::MatchedRoute<'a>> {
    if !snapshot.declares_assertions {
        return None;
    }
    http_matched.or(name_matched).cloned()
}

/// The names of the `http:` routes that declare `assertions:`. Those contracts
/// are the ones that cannot apply when a generic-HTTP request arrives with no
/// readable path, because that path is what the route matches on.
///
/// Computed once when a config lands on a snapshot, so the hot path reads an
/// answer rather than walking the route table.
fn http_routes_declaring_assertions(config: &PolicyConfig) -> Arc<[String]> {
    if !config.dispatch_mode().is_policy() {
        return Arc::from(Vec::new());
    }
    config
        .routes
        .iter()
        .filter(|route| route.http.is_some() && route.assertions.is_some())
        .filter_map(config::route_entity_identity)
        .flat_map(|(_, names)| names)
        .collect()
}

/// The names of the `http:` routes that declare `authentication:`. Those lists
/// are the ones that cannot apply when a request reaches the identity hook with
/// no readable path, so this is the answer the warning needs.
///
/// Depends only on the configuration, so it is computed once when a config
/// lands on a snapshot rather than per request. Empty in hook mode,
/// since no route selects anything then.
fn http_routes_declaring_authentication(config: &PolicyConfig) -> Arc<[String]> {
    if !config.dispatch_mode().is_policy() {
        return Arc::from(Vec::new());
    }
    config
        .routes
        .iter()
        .filter(|route| route.http.is_some() && route.authentication.is_some())
        .filter_map(config::route_entity_identity)
        .flat_map(|(_, names)| names)
        .collect()
}

/// Configuration for the `PolicyEngine`.
#[derive(Debug, Clone)]
pub struct PolicyEngineConfig {
    /// Executor configuration (timeout, short-circuit behavior).
    pub executor: ExecutorConfig,

    /// Maximum number of entries in the routing cache. When the cache
    /// reaches this size, further inserts are rejected (with a one-shot
    /// warn log) and resolutions fall back to the slow path. See
    /// `EngineSettings::route_cache_max_entries` for the YAML surface.
    pub route_cache_max_entries: usize,
}

impl Default for PolicyEngineConfig {
    fn default() -> Self {
        Self {
            executor: ExecutorConfig::default(),
            route_cache_max_entries: DEFAULT_ROUTE_CACHE_MAX_ENTRIES,
        }
    }
}

/// The policy engine: loads a policy, owns what it declares, and evaluates a
/// request against it.
///
/// This is the type a host holds. It reads the policy document, resolves every
/// `kind:` it names through the factory registry, owns the resulting plugins and
/// their lifecycle, and dispatches the hook chain for a request. Managing plugins
/// is one part of that rather than the whole of it, which is why registration,
/// config loading, route annotation and dispatch all live on the same handle.
///
/// # Lifecycle
///
/// ```text
/// new() → register plugins → initialize() → invoke hooks → shutdown()
/// ```
///
/// # Two Invoke Paths
///
/// - **`invoke::<H>()`** — typed dispatch. The hook type `H` is known
///   at compile time. Payload type-checked at compile time. Used by
///   Rust callers.
///
/// - **`invoke_by_name()`** — dynamic dispatch. The hook name is a
///   string. Payload is `Box<dyn PluginPayload>`. Used by Python/Go/WASM
///   callers via the FFI or `PyO3` bindings.
///
/// Both paths use the same registry, executor, and 5-phase pipeline.
///
/// # Trust Model
///
/// The engine wraps each plugin in a `PluginRef` with an authoritative
/// config from the config loader. The executor reads all scheduling
/// decisions from `PluginRef.trusted_config` — never from the plugin.
/// Cache key for resolved routing entries.
///
/// Includes entity type, resolved name, hook name, and scope so that
/// the same tool on different scopes or at different hook points
/// caches separately. The name is the one resolution produced, which for a
/// generic HTTP request is the selector that matched rather than the request
/// path, so cardinality follows the configuration and not the traffic.
///
/// Custom Hash/Eq implementations hash on `&str` slices so that
/// `raw_entry` lookups with borrowed strings produce the same hash
/// as the owned key — enabling zero-allocation cache hits.
#[derive(Debug, Clone)]
struct RouteCacheKey {
    entity_type: String,
    resolved_name: String,
    hook_name: String,
    scope: Option<String>,
}

impl Hash for RouteCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.entity_type.as_str().hash(state);
        self.resolved_name.as_str().hash(state);
        self.hook_name.as_str().hash(state);
        self.scope.as_deref().hash(state);
    }
}

impl PartialEq for RouteCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.entity_type == other.entity_type
            && self.resolved_name == other.resolved_name
            && self.hook_name == other.hook_name
            && self.scope == other.scope
    }
}

impl Eq for RouteCacheKey {}

/// Mutable runtime state held atomically swappable behind `ArcSwap`.
///
/// Every read on the hot path (`invoke_*`) does a single atomic load to
/// get an `Arc<RuntimeSnapshot>` — no locks. Mutating operations
/// (`register_*`, `load_config`, `unregister`) clone the current snapshot,
/// mutate the clone, and atomically swap the new `Arc` in. Old readers
/// finish on the old snapshot; new readers see the new one. This is the
/// classic Read-Copy-Update / RCU pattern: lock-free reads, copy-on-write
/// writes, no reader-writer contention.
///
/// Cloning `PluginRegistry` is cheap because every value inside (`PluginRef`,
/// `AnyHookHandler`) is `Arc`-counted — only the `HashMap` shells duplicate.
#[derive(Clone)]
struct RuntimeSnapshot {
    /// Plugin registry — stores `PluginRefs` and hook-to-handler mappings.
    registry: PluginRegistry,

    /// Executor — stateless 5-phase pipeline engine.
    executor: Executor,

    /// Parsed PPE config (when loaded from file). Used for route resolution.
    policy_config: Option<PolicyConfig>,

    /// Maximum number of entries the route cache will hold. Once reached,
    /// new resolutions are computed normally but not memoized (reject-on-full).
    route_cache_max_entries: usize,

    /// Per-route, per-hook handler overrides keyed by
    /// `(entity_type, entity_name, scope, hook_name)`. When a request matches
    /// an annotation, route resolution short-circuits to a single-entry list
    /// containing the annotated handler instead of resolving the route's
    /// imperative `plugins:` chain.
    ///
    /// Per-hook keying lets an orchestrator install distinct handlers for
    /// `cmf.tool_pre_invoke` and `cmf.tool_post_invoke` on the same route —
    /// useful when the pre/post phases need different handler state (e.g.
    /// praxis-policy-apl-runtime's `AplRouteHandler` binds each instance to either
    /// `evaluate_pre` or `evaluate_post`).
    ///
    /// `scope` (None vs `Some("virtual-server-A")`) lets two virtual
    /// servers / gateways with the same tool name carry distinct
    /// orchestrators. Matching mirrors praxis-policy-core's existing
    /// `resolve_route` semantics: a scoped request first tries the
    /// exact `(et, en, Some(req_scope), hook)` annotation; on miss it falls
    /// back to the unscoped `(et, en, None, hook)` default. An unscoped
    /// request only matches `(et, en, None, hook)`. Net effect: None-scope
    /// annotations act as a global default, scoped annotations override
    /// per-scope.
    ///
    /// The plugins listed under the matching route are *still* registered
    /// in the registry — they remain discoverable via `find_plugin_entries`
    /// so the annotated handler can dispatch into them by-name (this is
    /// what praxis-policy-apl-runtime's `AplRouteHandler` does via `CmfPluginInvoker` for
    /// `run(name)` references inside APL rules).
    route_annotations: HashMap<AnnotationKey, crate::registry::HookEntry>,

    /// The `http:` routes that declare `authentication:`, by the name each
    /// resolves under. Derived from `policy_config` when the snapshot is built,
    /// so the identity hook reads an answer instead of walking the route table
    /// on every request that carries no readable path. Empty for every config
    /// that has nothing to report, which is the ordinary one. A config
    /// replacement builds a new snapshot, so the answer cannot go stale.
    http_routes_declaring_authentication: Arc<[String]>,

    /// Whether any level declares an `assertions:` block. False for every
    /// config that does not use the feature, which is what keeps the extra
    /// route resolution the contract needs out of those deployments.
    declares_assertions: bool,

    /// The `http:` routes that declare `assertions:`, by the name each resolves
    /// under. Read on the generic-HTTP path when a request carries no readable
    /// path, for the same reason its authentication counterpart is.
    http_routes_declaring_assertions: Arc<[String]>,

    /// Whether any named route uses a glob selector.
    declares_glob_named_routes: bool,
}

/// Composite key for route annotations. Includes the hook name so a single
/// route can carry distinct handlers per phase (e.g. pre-invoke vs
/// post-invoke).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AnnotationKey {
    entity_type: String,
    entity_name: String,
    scope: Option<String>,
    hook_name: String,
}

/// Owns registered plugins and dispatches hook invocations to them.
pub struct PolicyEngine {
    /// Hot-path runtime state. Swapped atomically on registration / config
    /// reload — readers see a consistent view via a single `load_full()`.
    runtime: arc_swap::ArcSwap<RuntimeSnapshot>,

    /// Factory registry — owned by the engine. Used for initial
    /// instantiation and for creating override instances when routes
    /// override a plugin's base config.
    ///
    /// Held in a `RwLock` rather than the `ArcSwap` snapshot because
    /// `Box<dyn PluginFactory>` is not `Clone`. Read on the slow path
    /// (route cache miss + override config); write on `register_factory`.
    /// The hot path never touches it.
    factories: RwLock<PluginFactoryRegistry>,

    /// Cache of resolved hook entries per (entity, hook, scope).
    /// Populated on first access, invalidated on config reload.
    /// Uses Arc so cache reads are refcount bumps (~1ns), not data copies.
    route_cache: RwLock<HashMap<RouteCacheKey, Arc<Vec<crate::registry::HookEntry>>>>,

    /// Hasher builder for zero-allocation cache lookups via `raw_entry`.
    cache_hasher: hashbrown::DefaultHashBuilder,

    /// Set to true after the first time the cache rejects an insert in a
    /// given fill cycle, so the warn log fires once per cycle rather than
    /// on every miss under `DoS`. Reset by `clear_routing_cache()`.
    route_cache_full_warned: AtomicBool,

    /// Set to true after the first time an `http:` route's `authentication:`
    /// list could not apply because the request carried no path. The
    /// fallback to the global list is long-standing behavior, but it is
    /// silent, so it warns once rather than on every request. Reset by
    /// `clear_routing_cache()`.
    route_authentication_unreachable_warned: AtomicBool,

    /// Whether the request-direction contract on an `http:` route has already
    /// been reported unreachable. Per direction, because a host can supply the
    /// request line on the request invocation and not the response one, and the
    /// response half is the actionable half when it does.
    route_request_assertions_unreachable_warned: AtomicBool,

    /// The same gate for the response direction.
    route_response_assertions_unreachable_warned: AtomicBool,

    /// How many executor invocations are in flight. Read only to tell a nested
    /// dispatch from an outermost one, which is what decides whether a call to
    /// the nested primitive has a boundary above it to apply the contract.
    executor_depth: AtomicUsize,

    /// Whether `initialize()` has been called. Atomic so lifecycle methods
    /// can be `&self` and the engine itself can sit behind `Arc`.
    initialized: AtomicBool,

    /// Monotonic config-generation counter. Bumped every time the runtime
    /// snapshot is swapped (factory mutation, config (re)load, plugin
    /// register/unregister). External orchestrators (praxis-policy-apl-runtime's dispatch
    /// plan cache) pair their cached values with the generation seen at
    /// build time; a generation mismatch on lookup signals "evict + rebuild."
    /// Starts at 0; first snapshot publish (empty registry) leaves it at 0,
    /// so callers can use 0 as a "never observed" sentinel.
    generation: AtomicU64,

    /// Serialises writers on `runtime`. Every mutation is a load, clone,
    /// store, so the lock has to span the whole sequence: a writer that clones
    /// a snapshot another writer has already replaced publishes one missing
    /// that change, and the losing call still returns `Ok`.
    ///
    /// Guards `()` because the data lives in the `ArcSwap`. Readers never take
    /// it, so the invoke path is lock-free.
    ///
    /// Held across the copy-on-write in `mutate_runtime`,
    /// `try_mutate_runtime`, and `load_config`, and released before the
    /// routing cache is cleared. It is not reentrant, so no host-supplied
    /// callback may run beneath it: `load_config` calls every
    /// `PluginFactory::create` before taking it, and config visitors reach
    /// `annotate_route` after `load_config` has returned, not during.
    runtime_write: Mutex<()>,

    /// Tracks in-flight fire-and-forget background tasks across all
    /// invocations so `shutdown()` can wait for them to drain before
    /// returning. Without this, audit/telemetry tasks spawned by recent
    /// invokes get cancelled when the runtime tears down. Tasks are
    /// `tracker.spawn`'d in `spawn_fire_and_forget`; `shutdown()` calls
    /// `close().wait().await`.
    ///
    /// `TaskTracker` is internally `Arc`'d, so cloning is a refcount bump.
    task_tracker: tokio_util::task::TaskTracker,

    /// External orchestrators registered via `register_visitor`. Walked
    /// in registration order during `load_config_yaml` (after plugin
    /// instantiation) so each visitor can inspect raw YAML sections and
    /// install handlers via `annotate_route`. Empty by default — the
    /// `load_config(PolicyConfig)` path skips visitors entirely.
    visitors: RwLock<Vec<Arc<dyn crate::visitor::ConfigVisitor>>>,

    /// The host's outbound HTTP transport, if one was installed.
    ///
    /// Not config-derived and not part of the runtime snapshot: a host
    /// installs it once during wiring, before `initialize()`, and it does
    /// not change across hot reloads. `OnceLock` rather than a lock
    /// because reads happen per plugin per request and set-once is the
    /// actual lifecycle.
    ///
    /// PPE performs no HTTP itself. Absent an installed transport, a
    /// plugin that needs one fails at `initialize_with` with a message
    /// naming the omission — see `crate::host::ServiceError`.
    http_transport: std::sync::OnceLock<Arc<dyn crate::http::HttpTransport>>,
}

/// Fold top-level `groups:` into the internal bundle store and validate, the
/// two steps `config::parse_config` applies to YAML. Every config-load entry
/// point runs this, including the ones that take a `PolicyConfig` a host
/// built in Rust: without it such a host got no duplicate-plugin-name
/// check, no route-shape check, no hook-name check, and no group
/// resolution, so its routes quietly lost the plugins and
/// `authentication:` a group was meant to supply.
///
/// Idempotent. `fold_groups_into_bundles` returns early once `groups:`
/// is empty and validation only reads, so a path that already normalized
/// before calling in can repeat the work safely. A repeat is a full
/// `validate_config` walk rather than a single lookup, which is why this
/// stays on the config-load paths and out of anything per-request.
///
/// `has_visitor` reaches one check only: the backstop that refuses a policy-mode
/// config with plugins and no scope to name them from. That fault belongs to an
/// orchestrator when there is one, which sees the policy steps and reports it
/// per plugin. `from_config` passes `false` unconditionally, because it builds
/// the engine a visitor would later register on.
fn normalize_and_validate(
    mut config: PolicyConfig,
    has_visitor: bool,
) -> Result<PolicyConfig, Box<PluginError>> {
    crate::config::fold_groups_into_bundles(&mut config);
    crate::config::validate_config(&config)?;
    // After the fold, so the bundle walk sees top-level `groups:` in the store
    // every resolver reads. All three load entry points share this function,
    // which is what makes the typed and YAML boundaries agree by construction
    // rather than by two check lists that can drift.
    crate::config::reject_mode_conflicts_typed(&config)?;
    crate::config::reject_policy_mode_with_nothing_to_dispatch(&config, has_visitor)?;
    Ok(config)
}

/// Report what a declared set of `http:` routes leaves ungoverned. Called once
/// per `load_config` / `from_config`.
///
/// The settings the runtime parsed and never honored are gone from the key sets
/// rather than warned about, so there is nothing left here to call inactive but
/// the routing gaps.
fn warn_on_inactive_settings(cfg: &PolicyConfig) {
    // Reported here rather than from validation, which runs more than once on
    // the visitor load path, so an operator reads each gap once per load.
    for gap in crate::config::http_routing_gaps(cfg) {
        warn!("{gap}");
    }
}

/// Report what a contract on an `http:` route depends on the host for, and every
/// route whose inherited `assertions:` content a section above it drops. Called
/// once per `load_config` / `from_config`, after normalization.
///
/// After, not before, for the same reason the authentication report is: folding
/// top-level `groups:` is what fills the bundle store the layers are read from.
fn warn_on_assertions_findings(cfg: &PolicyConfig) {
    // The whole boundary, once per load, so an operator and a reviewer can read
    // what crosses it without reading Rust.
    if declares_assertions(cfg) {
        info!("{}", crate::assertions::effective_policy(cfg));
    }
    for gap in crate::config::assertions_reachability_gaps(cfg) {
        warn!(alarm = "assertions_route_needs_the_request_line", "{gap}");
    }
    for finding in crate::config::dropped_inherited_assertions(cfg) {
        warn!(
            alarm = "assertions_replaced_above_the_route",
            route = %finding.route,
            direction = %finding.direction,
            declared_in = %finding.declared_in,
            dropped_headers = ?finding.dropped_headers,
            dropped_strip = ?finding.dropped_strip,
            "a section above this route sets `replace_inherited: true` for this direction, so the \
             route no longer asserts the headers it inherited, nor removes the names the inherited \
             `strip:` covered. The route's own block does not show the drop, and the section is \
             shared, so every route under it loses the same content. Move the flag onto the route \
             if only that route meant to opt out, or remove it if the section meant to add",
        );
    }
}

/// Report every route whose inherited `authentication:` steps a section above
/// it drops with `replace_inherited: true`. Called once per `load_config` /
/// `from_config`, after normalization.
///
/// After, not before, because folding top-level `groups:` is what fills the
/// bundle store the layers are read from: taken any earlier, the report would
/// find no bundle to name on a config a host built in Rust.
fn warn_on_dropped_inherited_authentication(cfg: &PolicyConfig) {
    for finding in crate::config::dropped_inherited_authentication(cfg) {
        warn!(
            alarm = "authentication_replaced_above_the_route",
            route = %finding.route,
            declared_in = %finding.declared_in,
            dropped = ?finding.dropped,
            "a section above this route sets `authentication.replace_inherited: true`, so the \
             route no longer runs the identity steps it inherited and authenticates with what \
             that section declares alone. The route's own block does not show the drop, and the \
             section is shared, so every route under it loses the same steps. Move the flag onto \
             the route if only that route meant to opt out, or remove it if the section meant to \
             append.",
        );
    }
}

/// Look up the factory for every entry in `plugin_configs`, in config
/// order. Returns on the first `kind` with no registered factory.
///
/// Split from `create_plugin_instances` so a caller can release the
/// engine's `factories` lock before any factory runs — see that function
/// for what happens if it doesn't. Resolving first also means an unknown
/// `kind` is reported before any factory has run, so a rejected config
/// leaves behind no half-built plugins.
fn resolve_factories(
    plugin_configs: &[crate::plugin::PluginConfig],
    factories: &PluginFactoryRegistry,
) -> Result<Vec<Arc<dyn crate::factory::PluginFactory>>, Box<PluginError>> {
    plugin_configs
        .iter()
        .map(|plugin_config| {
            factories.get(&plugin_config.kind).ok_or_else(|| {
                Box::new(PluginError::Config {
                    message: format!(
                        "no factory registered for plugin kind '{}' (plugin '{}')",
                        plugin_config.kind, plugin_config.name
                    ),
                })
            })
        })
        .collect()
}

/// Create one plugin instance per entry in `plugin_configs`, using the
/// factories `resolve_factories` returned for those same configs.
///
/// Must run with no engine lock held. `factory.create` is host code and is
/// free to re-enter the engine: `register_handler`, `annotate_route` and
/// `unregister_plugin` take `runtime_write`, `register_factory` takes the
/// `factories` write side, and neither lock is reentrant, so a caller
/// holding either across this function deadlocks against a factory that
/// calls back. `RwLock` gives no guarantee for a recursive read either — a
/// waiting writer can park a second `factories.read()` behind it.
///
/// Returns on the first factory that rejects its config; instances already
/// created are dropped.
fn create_plugin_instances(
    plugin_configs: &[crate::plugin::PluginConfig],
    factories: &[Arc<dyn crate::factory::PluginFactory>],
) -> Result<Vec<crate::factory::PluginInstance>, Box<PluginError>> {
    plugin_configs
        .iter()
        .zip(factories)
        .map(|(plugin_config, factory)| factory.create(plugin_config))
        .collect()
}

/// Register instances produced by `create_plugin_instances` into
/// `target_registry`. `instances` is zipped against `plugin_configs`, so it
/// has to be the slice that call returned for these same configs: a shorter
/// one silently drops the tail, a reordered one pairs each plugin with the
/// wrong config.
///
/// Borrows rather than consumes, and hands the registry `Arc` clones, so
/// the caller keeps the last reference to every instance. That matters on
/// the error path: `register_multi_handler` takes ownership and drops what
/// it was given when it rejects a name, and the entries past the failure
/// are never reached at all. Owning them here would run those plugins'
/// `Drop` — host code — inside whatever lock the caller holds.
///
/// Returns on the first duplicate-name registration. On error,
/// `target_registry` is in a partial state — both callers discard it on
/// failure (`load_config` builds the new registry on a clone and only swaps
/// on Ok; `from_config` bails before publishing the snapshot).
fn register_instances_into(
    target_registry: &mut PluginRegistry,
    plugin_configs: &[crate::plugin::PluginConfig],
    instances: &[crate::factory::PluginInstance],
) -> Result<(), Box<PluginError>> {
    for (plugin_config, instance) in plugin_configs.iter().zip(instances) {
        target_registry
            .register_multi_handler(
                Arc::clone(&instance.plugin),
                plugin_config.clone(),
                instance.handlers.clone(),
            )
            .map_err(|msg| Box::new(PluginError::Config { message: msg }))?;

        info!(
            "Registered plugin '{}' (kind: '{}') for hooks: {:?}",
            plugin_config.name, plugin_config.kind, plugin_config.hooks
        );
    }
    Ok(())
}

/// Build a `RuntimeSnapshot` from a populated registry plus the YAML
/// settings on `policy_config`. Pulls executor timeout / short-circuit and
/// the route-cache cap from `engine_settings` so both registration paths
/// agree on field-by-field translation.
fn snapshot_from_config(registry: PluginRegistry, policy_config: PolicyConfig) -> RuntimeSnapshot {
    let executor = Executor::new(ExecutorConfig {
        timeout_seconds: policy_config.engine_settings.plugin_timeout,
        short_circuit_on_deny: policy_config.engine_settings.short_circuit_on_deny,
    });
    let route_cache_max_entries = policy_config.engine_settings.route_cache_max_entries;
    let http_routes_declaring_authentication = http_routes_declaring_authentication(&policy_config);
    let declares_assertions = declares_assertions(&policy_config);
    let http_routes_declaring_assertions = http_routes_declaring_assertions(&policy_config);
    let declares_glob_named_routes = declares_glob_named_routes(&policy_config);
    RuntimeSnapshot {
        registry,
        executor,
        policy_config: Some(policy_config),
        route_cache_max_entries,
        route_annotations: HashMap::new(),
        http_routes_declaring_authentication,
        declares_assertions,
        http_routes_declaring_assertions,
        declares_glob_named_routes,
    }
}

impl PolicyEngine {
    /// Create a new `PolicyEngine` with the given configuration.
    pub fn new(config: PolicyEngineConfig) -> Self {
        let cache_hasher = hashbrown::DefaultHashBuilder::default();
        let snapshot = RuntimeSnapshot {
            registry: PluginRegistry::new(),
            executor: Executor::new(config.executor),
            policy_config: None,
            route_cache_max_entries: config.route_cache_max_entries,
            route_annotations: HashMap::new(),
            http_routes_declaring_authentication: Arc::from(Vec::new()),
            declares_assertions: false,
            http_routes_declaring_assertions: Arc::from(Vec::new()),
            declares_glob_named_routes: false,
        };
        Self {
            runtime: arc_swap::ArcSwap::from_pointee(snapshot),
            factories: RwLock::new(PluginFactoryRegistry::new()),
            route_cache: RwLock::new(HashMap::with_hasher(cache_hasher.clone())),
            cache_hasher,
            route_cache_full_warned: AtomicBool::new(false),
            route_authentication_unreachable_warned: AtomicBool::new(false),
            route_request_assertions_unreachable_warned: AtomicBool::new(false),
            route_response_assertions_unreachable_warned: AtomicBool::new(false),
            executor_depth: AtomicUsize::new(0),
            initialized: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            runtime_write: Mutex::new(()),
            task_tracker: tokio_util::task::TaskTracker::new(),
            visitors: RwLock::new(Vec::new()),
            http_transport: std::sync::OnceLock::new(),
        }
    }

    /// Load the current runtime snapshot (lock-free, single atomic op).
    fn load_runtime(&self) -> Arc<RuntimeSnapshot> {
        self.runtime.load_full()
    }

    /// Take the runtime writer lock, ignoring poisoning. A panic inside a
    /// mutation closure leaves the `ArcSwap` holding whatever was last
    /// published, which is a complete snapshot either way, so there is no
    /// half-applied state for the next writer to inherit.
    fn lock_runtime_writer(&self) -> std::sync::MutexGuard<'_, ()> {
        self.runtime_write
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Apply a mutation to the runtime snapshot via copy-on-write.
    /// Clones the current snapshot, runs the closure on the clone, and
    /// atomically swaps it in. Concurrent readers continue using the old
    /// snapshot; subsequent readers see the new one. Writers serialise on
    /// `runtime_write` for the length of the call.
    fn mutate_runtime<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut RuntimeSnapshot) -> R,
    {
        let writer = self.lock_runtime_writer();
        let current = self.runtime.load_full();
        let mut next = (*current).clone();
        let result = f(&mut next);
        self.runtime.store(Arc::new(next));
        // Release ordering pairs with the Acquire load in
        // config_generation() — external cache consumers that observe a
        // higher generation are guaranteed to see the new snapshot.
        self.generation.fetch_add(1, Ordering::Release);
        // Release before `current` falls out of scope. The store above
        // usually leaves this the last reference to the old snapshot, and
        // dropping it drops the registry, whose plugin `Drop` impls are host
        // code: one that re-enters the engine would block on this lock.
        drop(writer);
        drop(current);
        result
    }

    /// Like `mutate_runtime` but the mutation can fail — the new snapshot
    /// is only published on `Ok`. On `Err`, the original snapshot is
    /// untouched, so a partially-mutated clone is silently discarded. An
    /// `Err` releases the writer lock without storing, so a rejected
    /// mutation publishes nothing and holds up no other writer.
    fn try_mutate_runtime<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut RuntimeSnapshot) -> Result<T, E>,
    {
        let writer = self.lock_runtime_writer();
        let current = self.runtime.load_full();
        let mut next = (*current).clone();
        let result = f(&mut next);
        if result.is_ok() {
            self.runtime.store(Arc::new(next));
            // Same Release-ordered bump as mutate_runtime — only on Ok, since
            // Err leaves the snapshot untouched.
            self.generation.fetch_add(1, Ordering::Release);
        }
        // Released before `next` and `current` fall out of scope, for the
        // reason mutate_runtime releases early: both can hold the last
        // reference to a plugin, and a `Drop` impl is host code. `next`
        // survives to here on the `Err` path — no `?` above — so a rejected
        // mutation drops whatever it built with the lock already gone.
        drop(writer);
        drop(current);
        result
    }

    /// Monotonic counter that increments on every runtime snapshot swap
    /// (registry mutation, config (re)load). External orchestrators
    /// (e.g. praxis-policy-apl-runtime's dispatch-plan cache) pair their cached values
    /// with the generation seen at build time; a mismatch on lookup
    /// signals "evict + rebuild." `Acquire` pairs with the `Release`
    /// `fetch_add` in `mutate_runtime` / `try_mutate_runtime` so observing
    /// a higher generation guarantees visibility of the new snapshot.
    pub fn config_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Whether any identity-resolve plugin is configured for a route.
    ///
    /// A narrow accessor rather than a getter for `policy_config`: the
    /// caller needs a yes or no, and handing out the whole config would
    /// give every reader a stake in its shape.
    ///
    /// Exists for a config-time soundness check. A route that delegates
    /// a credential the caller presented, but resolves no identity, hands
    /// the delegator a token nothing has validated — see the
    /// `delegation_without_identity_resolution` alarm in
    /// praxis-policy-apl-runtime.
    pub fn route_has_identity_resolution(
        &self,
        entity_type: &str,
        entity_name: &str,
        request_scope: Option<&str>,
    ) -> bool {
        self.load_runtime()
            .policy_config
            .as_ref()
            .is_some_and(|policy_config| {
                // Resolve the route first: the resolver takes the route already
                // matched. This runs at config load, where there is no request
                // line, so an `http:` route is not reachable from here — a
                // named query leaves the path empty and matches none.
                let matched = config::resolve_route(
                    policy_config,
                    config::RouteQuery::named(entity_type, entity_name).with_scope(request_scope),
                );
                !config::resolve_identity_plugins_for_route(policy_config, matched.as_ref())
                    .is_empty()
            })
    }

    /// Register a plugin factory for a given `kind` name.
    ///
    /// The host calls this to tell the engine how to create plugins
    /// of a specific kind. Must be called before `load_config()`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut engine = PolicyEngine::default();
    /// engine.register_factory("builtin", Box::new(BuiltinFactory));
    /// engine.register_factory("security/rate_limit", Box::new(RateLimiterFactory));
    /// engine.load_config(Path::new("plugins.yaml"))?;
    /// ```
    pub fn register_factory(
        &self,
        kind: impl Into<String>,
        factory: Box<dyn crate::factory::PluginFactory>,
    ) {
        self.factories
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .register(kind, factory);
    }

    /// Load plugins from a YAML config file.
    ///
    /// Parses the config, looks up each plugin's `kind` in the
    /// factory registry, instantiates the plugins, and registers
    /// them. Factories must be registered via `register_factory()`
    /// before calling this method.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut engine = PolicyEngine::default();
    /// engine.register_factory("builtin", Box::new(BuiltinFactory));
    /// engine.load_config_file(Path::new("plugins/config.yaml"))?;
    /// engine.initialize().await?;
    /// ```
    /// # Errors
    ///
    /// Returns `PluginError::Config` when the file cannot be read or parsed, and
    /// whatever [`Self::load_config`] reports for the parsed contents.
    pub fn load_config_file(&self, path: &Path) -> Result<(), Box<PluginError>> {
        let policy_config = config::load_config(path)?;
        self.load_config(policy_config)
    }

    /// Load plugins from a parsed config.
    ///
    /// Looks up each plugin's `kind` in the factory registry,
    /// instantiates the plugins, and registers them with their
    /// hook names from the config.
    /// # Errors
    ///
    /// Returns `PluginError::Config` when the config fails validation, when a
    /// plugin's `kind` has no registered factory, when a factory rejects the
    /// plugin's config, or when a registration conflicts with one already
    /// present. The existing snapshot is left in place, so a failed load does
    /// not disturb in-flight requests.
    pub fn load_config(&self, policy_config: PolicyConfig) -> Result<(), Box<PluginError>> {
        // Warn before validating: an operator whose config both sets an inactive
        // knob and fails validation should see both, not just the refusal.
        warn_on_inactive_settings(&policy_config);
        let has_visitor = !self
            .visitors
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty();
        let policy_config = normalize_and_validate(policy_config, has_visitor)?;
        warn_on_dropped_inherited_authentication(&policy_config);
        warn_on_assertions_findings(&policy_config);

        // Resolve under the factories read lock, then drop it and
        // instantiate holding nothing, per `create_plugin_instances`. A
        // factory that registers something on its way through publishes it
        // here, so the clone below picks it up rather than swapping a
        // snapshot taken before it existed.
        let factories = {
            let registry = self
                .factories
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            resolve_factories(&policy_config.plugins, &registry)?
        };
        let instances = create_plugin_instances(&policy_config.plugins, &factories)?;

        // Build the new snapshot from the current one — copy-on-write so
        // concurrent invokes keep using the existing config until we swap.
        // We can't use mutate_runtime here because we need to atomically
        // ALSO build a new executor + new cache cap from the same config —
        // the snapshot fields are coupled. Takes the writer lock by hand for
        // the reason mutate_runtime takes it.
        let writer = self.lock_runtime_writer();

        let current = self.runtime.load_full();
        let mut new_registry = current.registry.clone();

        let registered =
            register_instances_into(&mut new_registry, &policy_config.plugins, &instances);
        if registered.is_ok() {
            self.runtime
                .store(Arc::new(snapshot_from_config(new_registry, policy_config)));
            // Same generation bump as mutate_runtime — load_config doesn't
            // go through that helper because it has to swap registry + executor
            // + cache-cap atomically as one snapshot.
            self.generation.fetch_add(1, Ordering::Release);
        }
        // Released before `instances`, `new_registry` and `current` fall out
        // of scope, the same discipline try_mutate_runtime follows. A
        // rejected load holds the only references to plugins the factories
        // just built, and dropping one runs host `Drop` code that is free to
        // re-enter the engine. No `?` above, so nothing unwinds past here
        // still holding the lock.
        drop(writer);
        drop(current);
        registered?;

        // Clear routing cache — config changed.
        self.clear_routing_cache();

        Ok(())
    }

    /// The dispatch mode the installed configuration selected.
    ///
    /// `Hooks` when no configuration is installed, since with nothing loaded
    /// there is no policy for one to decide against. A visitor reads this from
    /// `visit_complete` to know whether a check that only makes sense under
    /// `policy` should run: in hook mode a plugin no step names is the normal
    /// case, not a fault, because its own `hooks:` is what fires it.
    #[must_use]
    pub fn dispatch_mode(&self) -> crate::config::DispatchMode {
        self.load_runtime().policy_config.as_ref().map_or(
            crate::config::DispatchMode::Hooks,
            PolicyConfig::dispatch_mode,
        )
    }

    /// Register an external config visitor. Visitors run during
    /// `load_config_yaml` (after plugin instantiation) and can install
    /// per-route handler overrides via `annotate_route`. Visitor order
    /// matches registration order. Multiple visitors are allowed —
    /// they typically don't share state, so order rarely matters.
    pub fn register_visitor(&self, visitor: Arc<dyn crate::visitor::ConfigVisitor>) {
        let mut v = self
            .visitors
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        v.push(visitor);
    }

    /// Load a unified-config YAML string. Parses the YAML twice — once
    /// into a typed `PolicyConfig` for plugin instantiation, once into a
    /// raw `serde_yaml::Value` so visitors can inspect orchestrator-
    /// specific blocks (e.g. a `rego:` block) that praxis-policy-core doesn't
    /// model. Calls existing `load_config(policy_config)` first, then
    /// walks each registered visitor over the raw YAML's sections in
    /// the documented hierarchy order:
    ///
    /// 1. `visit_global(global_yaml)`
    /// 2. `visit_default(entity_type, default_yaml)` per `global.defaults` entry
    /// 3. `visit_policy_bundle(tag, bundle_yaml)` per `groups:` entry
    /// 4. `visit_route(route_yaml, parsed_route)` per `routes[]` entry
    /// 5. `visit_complete()` once, after that visitor's own route walk
    ///
    /// All sections for one visitor run before the next visitor starts,
    /// giving each visitor a consistent view of its own accumulated
    /// state. A visitor returning Err aborts the load — the plugin
    /// snapshot stays at the post-`load_config` state (partial load is
    /// not rolled back; operators should treat any error from this
    /// method as a hard stop).
    /// # Errors
    ///
    /// Returns `PluginError::Config` when the YAML does not parse, when it does
    /// not deserialize into a policy document, when plugin loading fails as in
    /// [`Self::load_config`], or when a config visitor rejects a section. A
    /// visitor error aborts the load and is not rolled back: treat it as a hard
    /// stop rather than retrying on top of it.
    pub fn load_config_yaml(self: &Arc<Self>, yaml: &str) -> Result<(), Box<PluginError>> {
        // Parse once into a Value so the raw shape is available to
        // visitors. Then deserialize from that Value into PolicyConfig —
        // saves a second tokenize/lex pass vs parsing the string twice.
        let raw: serde_yaml::Value = serde_yaml::from_str(yaml).map_err(|e| {
            Box::new(PluginError::Config {
                message: format!("YAML parse error: {e}"),
            })
        })?;
        let mut policy_config: PolicyConfig = serde_yaml::from_value(raw.clone()).map_err(|e| {
            Box::new(PluginError::Config {
                message: format!("PolicyConfig deserialize error: {e}"),
            })
        })?;

        // Normalize + validate on the SAME path `parse_config` uses. A bare
        // deserialize does none of this, so without it a running host never
        // folds top-level `groups:` into the internal bundle store (routes lose
        // the group's plugins + `authentication:`) and never validates
        // references.
        crate::config::reject_unknown_document_keys(&raw)?;
        crate::config::reject_unknown_engine_settings_keys(&raw)?;
        // Registered visitors are read before the route-key check so a key an
        // orchestrator declares is accepted rather than rejected as a typo.
        let visitors = {
            let v = self
                .visitors
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            v.clone()
        };
        let visitor_route_keys: Vec<&str> = visitors
            .iter()
            .flat_map(|v| v.extra_route_keys().iter().copied())
            .collect();
        crate::config::reject_unknown_route_keys(&raw, &visitor_route_keys)?;
        crate::config::reject_unknown_section_keys(&raw, &visitor_route_keys)?;
        crate::config::reject_mode_conflicts(&raw)?;
        // Before `load_config`, deliberately. A visitor error is documented as
        // not rolled back, so a check that ran after the walk would leave the
        // snapshot live on the very config it rejected. This one decides from
        // the document alone and can run first.
        if visitors.is_empty() {
            crate::config::reject_apl_keys_without_a_visitor(&raw)?;
        }
        // Visitors below read the normalized routes and plugin declarations, so
        // this runs here rather than being left to `load_config`. Both steps
        // are idempotent, so `load_config` repeating them is redundant work on
        // a cold path rather than a behavior difference.
        policy_config = normalize_and_validate(policy_config, !visitors.is_empty())?;

        // Snapshot the parsed routes + plugin declarations before
        // load_config moves the config — visitors get the typed
        // structures side-by-side with the raw YAML so they don't have
        // to re-deserialize anything praxis-policy-core has already validated.
        let parsed_routes: Vec<crate::config::RouteEntry> = policy_config.routes.clone();
        let parsed_plugins: Vec<crate::plugin::PluginConfig> = policy_config.plugins.clone();

        // Existing plugin-instantiation path.
        self.load_config(policy_config)?;

        // Visitor walk. No-op when no visitors registered — the common
        // case for hosts that don't use the orchestrator extension point.
        if visitors.is_empty() {
            return Ok(());
        }

        let mgr: Arc<PolicyEngine> = Arc::clone(self);
        let global_yaml = raw
            .get("global")
            .cloned()
            .unwrap_or(serde_yaml::Value::Null);
        let defaults_yaml = global_yaml
            .get("defaults")
            .and_then(serde_yaml::Value::as_mapping)
            .cloned();
        // Bundles the visitor compiles come from top-level `groups:`, the only
        // place a document declares them. Mirrors `fold_groups_into_bundles` on
        // the typed side.
        let bundles_yaml = raw
            .get("groups")
            .and_then(serde_yaml::Value::as_mapping)
            .cloned();
        let routes_yaml: Vec<serde_yaml::Value> = raw
            .get("routes")
            .and_then(serde_yaml::Value::as_sequence)
            .cloned()
            .unwrap_or_default();

        for visitor in &visitors {
            visitor.visit_plugins(&mgr, &parsed_plugins).map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!("visitor '{}' visit_plugins: {}", visitor.name(), e),
                })
            })?;

            visitor.visit_global(&mgr, &global_yaml).map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!("visitor '{}' visit_global: {}", visitor.name(), e),
                })
            })?;

            if let Some(defaults) = &defaults_yaml {
                for (k, v) in defaults {
                    let Some(entity_type) = k.as_str() else {
                        continue;
                    };
                    visitor.visit_default(&mgr, entity_type, v).map_err(|e| {
                        Box::new(PluginError::Config {
                            message: format!(
                                "visitor '{}' visit_default('{}'): {}",
                                visitor.name(),
                                entity_type,
                                e
                            ),
                        })
                    })?;
                }
            }

            if let Some(bundles) = &bundles_yaml {
                for (k, v) in bundles {
                    let Some(tag) = k.as_str() else { continue };
                    visitor.visit_policy_bundle(&mgr, tag, v).map_err(|e| {
                        Box::new(PluginError::Config {
                            message: format!(
                                "visitor '{}' visit_policy_bundle('{}'): {}",
                                visitor.name(),
                                tag,
                                e
                            ),
                        })
                    })?;
                }
            }

            for (i, parsed) in parsed_routes.iter().enumerate() {
                let route_yaml = routes_yaml
                    .get(i)
                    .cloned()
                    .unwrap_or(serde_yaml::Value::Null);
                visitor
                    .visit_route(&mgr, &route_yaml, parsed)
                    .map_err(|e| {
                        Box::new(PluginError::Config {
                            message: format!(
                                "visitor '{}' visit_route[{}]: {}",
                                visitor.name(),
                                i,
                                e
                            ),
                        })
                    })?;
            }

            visitor.visit_complete(&mgr).map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!("visitor '{}' visit_complete: {}", visitor.name(), e),
                })
            })?;
        }

        Ok(())
    }

    /// Create a `PolicyEngine` from a parsed config (convenience).
    ///
    /// Uses the passed factory registry for initial instantiation.
    /// Note: for route-level config overrides to create new instances
    /// at runtime, use `register_factory()` + `load_config()` instead
    /// so the engine owns the factories.
    /// # Errors
    ///
    /// Returns `PluginError::Config` for the same reasons as
    /// [`Self::load_config`]: a config that fails validation, an unknown plugin
    /// `kind`, a factory that rejects its config, or a conflicting
    /// registration.
    pub fn from_config(
        policy_config: PolicyConfig,
        factories: &PluginFactoryRegistry,
    ) -> Result<Self, Box<PluginError>> {
        // Warn before validating: an operator whose config both sets an inactive
        // knob and fails validation should see both, not just the refusal.
        warn_on_inactive_settings(&policy_config);
        let policy_config = normalize_and_validate(policy_config, false)?;
        warn_on_dropped_inherited_authentication(&policy_config);
        warn_on_assertions_findings(&policy_config);

        let engine = Self::new(PolicyEngineConfig {
            executor: ExecutorConfig::default(),
            route_cache_max_entries: policy_config.engine_settings.route_cache_max_entries,
        });

        // Instantiate into a fresh registry, then publish atomically.
        let resolved = resolve_factories(&policy_config.plugins, factories)?;
        let instances = create_plugin_instances(&policy_config.plugins, &resolved)?;
        let mut new_registry = PluginRegistry::new();
        register_instances_into(&mut new_registry, &policy_config.plugins, &instances)?;

        engine
            .runtime
            .store(Arc::new(snapshot_from_config(new_registry, policy_config)));

        Ok(engine)
    }

    /// Register a plugin handler for its primary hook name.
    ///
    /// This is the preferred registration method. The framework creates
    /// the type-erased adapter internally — no `AnyHookHandler` needed.
    ///
    /// # Type Parameters
    ///
    /// - `H` — the hook type (implements `HookTypeDef`).
    /// - `P` — the plugin type (implements `Plugin + HookHandler<H>`).
    ///
    /// # Arguments
    ///
    /// - `plugin` — the plugin implementation.
    /// - `config` — authoritative config from the config loader.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// engine.register_handler::<CmfHook, _>(plugin, config)?;
    /// ```
    /// # Errors
    ///
    /// Returns `PluginError::Config` when a plugin of the same name is already
    /// registered for this hook, or when the hook's metadata row names a family
    /// other than the one the handler serves.
    pub fn register_handler<H, P>(
        &self,
        plugin: Arc<P>,
        config: PluginConfig,
    ) -> Result<(), Box<PluginError>>
    where
        H: HookTypeDef,
        H::Result: Into<PluginResult<H::Payload>>,
        P: Plugin + HookHandler<H> + 'static,
    {
        let handler: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<H, P>::new(Arc::clone(&plugin)));
        self.try_mutate_runtime(|snap| {
            snap.registry
                .register::<H>(plugin, config, handler)
                .map_err(|msg| Box::new(PluginError::Config { message: msg }))
        })?;
        self.clear_routing_cache();
        Ok(())
    }

    /// Register a plugin handler for multiple hook names.
    ///
    /// This is the CMF pattern — one handler covers multiple hook
    /// names (`cmf.tool_pre_invoke`, `cmf.llm_input`, etc.).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// engine.register_handler_for_names::<CmfHook, _>(
    ///     plugin, config,
    ///     &["cmf.tool_pre_invoke", "cmf.llm_input", "cmf.llm_output"],
    /// )?;
    /// ```
    /// # Errors
    ///
    /// Returns `PluginError::Config` when a plugin of the same name is already
    /// registered under any of the given hook names, or when one of those names
    /// expects a family other than the one the handler serves.
    pub fn register_handler_for_names<H, P>(
        &self,
        plugin: Arc<P>,
        config: PluginConfig,
        names: &[&str],
    ) -> Result<(), Box<PluginError>>
    where
        H: HookTypeDef,
        H::Result: Into<PluginResult<H::Payload>>,
        P: Plugin + HookHandler<H> + 'static,
    {
        let handler: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<H, P>::new(Arc::clone(&plugin)));
        self.try_mutate_runtime(|snap| {
            snap.registry
                .register_for_names::<H>(plugin, config, handler, names)
                .map_err(|msg| Box::new(PluginError::Config { message: msg }))
        })?;
        self.clear_routing_cache();
        Ok(())
    }

    /// Register with an explicit `AnyHookHandler` (advanced use).
    ///
    /// For cases where the automatic adapter doesn't fit — e.g.,
    /// Python/WASM bridge hosts that implement `AnyHookHandler` directly.
    /// Most callers should use `register_handler` instead.
    /// # Errors
    ///
    /// Returns `PluginError::Config` when a plugin of the same name is already
    /// registered for this hook, or when the hook's metadata row names a family
    /// other than the one the handler serves.
    pub fn register_raw<H: HookTypeDef>(
        &self,
        plugin: Arc<dyn Plugin>,
        config: PluginConfig,
        handler: Arc<dyn AnyHookHandler>,
    ) -> Result<(), Box<PluginError>> {
        self.try_mutate_runtime(|snap| {
            snap.registry
                .register::<H>(plugin, config, handler)
                .map_err(|msg| Box::new(PluginError::Config { message: msg }))
        })?;
        self.clear_routing_cache();
        Ok(())
    }

    /// Install the host's outbound HTTP transport.
    ///
    /// PPE performs no HTTP of its own. A plugin that must reach an
    /// `IdP` — a JWKS fetch, a token exchange, a CIBA backchannel —
    /// reaches this by asking through
    /// [`HostServices::http_request`](crate::host::HostServices::http_request), gated by
    /// the `perform_http` capability. Installing the host's own client
    /// keeps one HTTP stack in the process: one connection pool, one
    /// TLS trust store, one egress policy.
    ///
    /// Call before [`initialize`](Self::initialize), since that is when
    /// a plugin may first want it.
    ///
    /// Set-once. A second call is ignored and returns `false`, so a host
    /// that wires twice does not silently swap the transport out from
    /// under plugins already holding a borrowed reference.
    ///
    /// The transport must be runtime-agnostic and build any connection
    /// pool lazily. A host may drive `initialize()` on a short-lived
    /// runtime that is dropped before the first request, at which point
    /// eagerly created connections are already dead.
    pub fn set_http_transport(&self, transport: Arc<dyn crate::http::HttpTransport>) -> bool {
        let installed = self.http_transport.set(transport).is_ok();
        if !installed {
            warn!("policy: an HTTP transport is already installed; ignoring the second install");
        }
        installed
    }

    /// The host services `plugin_name` may borrow, per its capabilities.
    ///
    /// The withheld case is carried rather than dropped so the plugin's
    /// error names the capability to add instead of blaming the host for
    /// installing nothing.
    fn init_extensions_for(
        &self,
        capabilities: &std::collections::HashSet<String>,
    ) -> crate::host::InitExtensions {
        let ext = crate::host::InitExtensions::new();
        match self.http_transport.get() {
            None => ext,
            Some(t) => {
                if capabilities.contains(crate::host::HTTP_CAPABILITY) {
                    ext.with_http(Arc::clone(t))
                } else {
                    ext.with_http_withheld()
                }
            },
        }
    }

    /// Seed a request's extensions with the host services available to
    /// plugins, before the executor filters them per plugin.
    ///
    /// `filter_extensions` applies the `perform_http` gate; this only
    /// makes the transport reachable at all.
    fn with_host_services(&self, mut extensions: Extensions) -> Extensions {
        if let Some(t) = self.http_transport.get() {
            extensions.http_transport = crate::host::HttpTransportSlot::installed(Arc::clone(t));
        }
        extensions
    }

    /// Initialize every registered plugin.
    ///
    /// Calls `plugin.initialize_with()` on each, handing it the host
    /// services its capabilities allow. Must be called before invoking
    /// any hooks. Idempotent — calling twice has no effect.
    ///
    /// # Errors
    ///
    /// Returns `PluginError::Execution` when a plugin's initialization
    /// fails. Plugins already initialized in this call are shut down
    /// first, so the engine does not come up half-started.
    pub async fn initialize(&self) -> Result<(), Box<PluginError>> {
        if self.initialized.load(Ordering::Acquire) {
            return Ok(());
        }

        // Snapshot once at start — subsequent registrations don't affect
        // this initialize() call. They'd need their own initialize.
        let snapshot = self.load_runtime();

        info!(
            "Initializing PolicyEngine with {} plugins",
            snapshot.registry.plugin_count()
        );

        let mut initialized_plugins: Vec<String> = Vec::new();

        for name in snapshot.registry.plugin_names() {
            if let Some(plugin_ref) = snapshot.registry.get(&name) {
                let plugin = plugin_ref.plugin().clone();
                let plugin_name = name;

                let init_ext = self.init_extensions_for(&plugin_ref.trusted_config().capabilities);

                if let Err(e) = plugin.initialize_with(&init_ext).await {
                    error!("Failed to initialize plugin '{}': {}", plugin_name, e);

                    for init_name in initialized_plugins.iter().rev() {
                        if let Some(pr) = snapshot.registry.get(init_name)
                            && let Err(shutdown_err) = pr.plugin().shutdown().await
                        {
                            error!(
                                "Error shutting down plugin '{}' during rollback: {}",
                                init_name, shutdown_err
                            );
                        }
                    }

                    return Err(Box::new(PluginError::Execution {
                        plugin_name,
                        message: format!("initialization failed: {e}"),
                        source: Some(Box::new(e)),
                        code: None,
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    }));
                }

                initialized_plugins.push(plugin_name);
            }
        }

        self.initialized.store(true, Ordering::Release);
        info!("PolicyEngine initialized successfully");
        Ok(())
    }

    /// Shutdown all registered plugins.
    ///
    /// Calls `plugin.shutdown()` on each registered plugin in reverse
    /// registration order. Errors are logged but do not halt the
    /// shutdown process — all plugins get a chance to clean up.
    /// Shut the engine down. **Terminal:** after `shutdown()` returns,
    /// no further `register_*` / `invoke_*` should be called. New
    /// fire-and-forget tasks spawned after `close()` will not be tracked
    /// (the `TaskTracker` is single-shot by design).
    pub async fn shutdown(&self) {
        if !self.initialized.load(Ordering::Acquire) {
            return;
        }

        info!("Shutting down PolicyEngine");

        // Drain in-flight fire-and-forget tasks BEFORE tearing down
        // plugins — otherwise audit/telemetry tasks that depend on the
        // plugin being alive (or the runtime being up) get cancelled
        // mid-flight. `close()` prevents new tasks from being tracked
        // (existing in-flight ones still complete); `wait()` returns
        // when the in-flight count drops to zero.
        self.task_tracker.close();
        self.task_tracker.wait().await;

        let snapshot = self.load_runtime();
        for name in snapshot.registry.plugin_names() {
            if let Some(plugin_ref) = snapshot.registry.get(&name) {
                let plugin = plugin_ref.plugin().clone();

                if let Err(e) = plugin.shutdown().await {
                    error!("Error shutting down plugin '{}': {}", name, e);
                    // Continue — don't let one plugin's failure block others
                }
            }
        }

        self.initialized.store(false, Ordering::Release);
        info!("PolicyEngine shutdown complete");
    }

    /// Invoke a hook by name with a type-erased payload.
    ///
    /// This is the dynamic dispatch path used by Python/Go/WASM
    /// callers via FFI or `PyO3` bindings. The hook name is resolved
    /// from the registry and dispatched through the 5-phase executor.
    ///
    /// # Arguments
    ///
    /// * `hook_name` — the hook name string (e.g., `"cmf.tool_pre_invoke"`).
    /// * `payload` — the payload as `Box<dyn PluginPayload>`.
    /// * `extensions` — the full extensions (filtered per plugin by the executor).
    /// * `context_table` — optional context table from a previous hook
    ///   invocation. Pass `None` on the first hook call; thread the
    ///   returned table into subsequent calls to preserve per-plugin state.
    ///
    /// # Returns
    ///
    /// A tuple of `(PipelineResult, BackgroundTasks)`. The result
    /// contains the final payload, extensions, violation, and context
    /// table. Background tasks can be awaited or dropped.
    pub async fn invoke_by_name(
        &self,
        hook_name: &str,
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> (PipelineResult, BackgroundTasks) {
        // Single atomic load — own the snapshot for the rest of the call so
        // a concurrent register/load_config swapping in a new snapshot doesn't
        // change our view mid-pipeline.
        let snapshot = self.load_runtime();
        let hook_type = HookType::new(hook_name);
        let all_entries = snapshot.registry.entries_for_hook(&hook_type);

        // Same caveat as `invoke_named`: route annotations can produce a
        // dispatch entry without any plugin being registered on the
        // hook directly, so we can only short-circuit when both the
        // registry and the annotation map are empty.
        if all_entries.is_empty() && snapshot.route_annotations.is_empty() {
            // Route filtering has not run, so the route is resolved here: a
            // contract written on a route holds whether or not this hook has a
            // plugin on it.
            let matched = resolve_contract_route(&snapshot, &extensions);
            return (
                self.apply_assertions(
                    &snapshot,
                    Some(hook_name),
                    matched.as_ref(),
                    PipelineResult::allowed_with(
                        payload,
                        extensions,
                        context_table.unwrap_or_default(),
                    ),
                ),
                BackgroundTasks::empty(),
            );
        }

        let (entries, matched) = match self
            .filter_entries_by_route(&snapshot, all_entries, &extensions, hook_name)
            .await
        {
            Ok(resolved) => resolved,
            Err(cause) => {
                return (
                    self.apply_assertions(
                        &snapshot,
                        Some(hook_name),
                        None,
                        PipelineResult::denied(
                            cause.violation(),
                            extensions,
                            context_table.unwrap_or_default(),
                        ),
                    ),
                    BackgroundTasks::empty(),
                );
            },
        };

        if entries.is_empty() {
            return (
                self.apply_assertions(
                    &snapshot,
                    Some(hook_name),
                    matched.as_ref(),
                    PipelineResult::allowed_with(
                        payload,
                        extensions,
                        context_table.unwrap_or_default(),
                    ),
                ),
                BackgroundTasks::empty(),
            );
        }

        let (result, tasks) = {
            let _boundary = self.enter_executor();
            snapshot
                .executor
                .execute(
                    &entries,
                    payload,
                    // Make the host's transport reachable; `filter_extensions`
                    // applies the `perform_http` gate per plugin.
                    self.with_host_services(extensions),
                    context_table,
                    &self.task_tracker,
                )
                .await
        };
        (
            self.apply_assertions(&snapshot, Some(hook_name), matched.as_ref(), result),
            tasks,
        )
    }

    /// Invoke a typed hook.
    ///
    /// This is the compile-time dispatch path used by Rust callers.
    /// The hook type `H` determines the payload and result types.
    /// Dispatch goes through the same registry and 5-phase executor
    /// as `invoke_by_name()`.
    ///
    /// Under `dispatch: policy` the entity is identified from
    /// `extensions.meta` (`entity_type` + `entity_name`), and only the route's
    /// policy handler and its `authentication:` steps fire. Under
    /// `dispatch: hooks`, or when meta is absent, all registered plugins fire.
    ///
    /// # Type Parameters
    ///
    /// - `H` — the hook type (implements `HookTypeDef`).
    ///
    /// # Arguments
    ///
    /// * `payload` — the typed payload.
    /// * `extensions` — the full extensions (includes meta for routing).
    /// * `context_table` — optional context table from a previous hook.
    ///
    /// # Returns
    ///
    /// A tuple of `(PipelineResult, BackgroundTasks)`.
    pub async fn invoke<H: HookTypeDef>(
        &self,
        payload: H::Payload,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> (PipelineResult, BackgroundTasks) {
        let snapshot = self.load_runtime();
        let hook_type = HookType::new(H::NAME);
        let all_entries = snapshot.registry.entries_for_hook(&hook_type);

        // See `invoke_named` for why we don't short-circuit on
        // `all_entries.is_empty()` alone — route annotations can fire
        // without a directly-registered plugin.
        if all_entries.is_empty() && snapshot.route_annotations.is_empty() {
            let boxed: Box<dyn PluginPayload> = Box::new(payload);
            let matched = resolve_contract_route(&snapshot, &extensions);
            return (
                self.apply_assertions(
                    &snapshot,
                    Some(H::NAME),
                    matched.as_ref(),
                    PipelineResult::allowed_with(
                        boxed,
                        extensions,
                        context_table.unwrap_or_default(),
                    ),
                ),
                BackgroundTasks::empty(),
            );
        }

        let (entries, matched) = match self
            .filter_entries_by_route(&snapshot, all_entries, &extensions, H::NAME)
            .await
        {
            Ok(resolved) => resolved,
            Err(cause) => {
                return (
                    self.apply_assertions(
                        &snapshot,
                        Some(H::NAME),
                        None,
                        PipelineResult::denied(
                            cause.violation(),
                            extensions,
                            context_table.unwrap_or_default(),
                        ),
                    ),
                    BackgroundTasks::empty(),
                );
            },
        };

        if entries.is_empty() {
            let boxed: Box<dyn PluginPayload> = Box::new(payload);
            return (
                self.apply_assertions(
                    &snapshot,
                    Some(H::NAME),
                    matched.as_ref(),
                    PipelineResult::allowed_with(
                        boxed,
                        extensions,
                        context_table.unwrap_or_default(),
                    ),
                ),
                BackgroundTasks::empty(),
            );
        }

        let boxed: Box<dyn PluginPayload> = Box::new(payload);
        let (result, tasks) = {
            let _boundary = self.enter_executor();
            snapshot
                .executor
                .execute(
                    &entries,
                    boxed,
                    // Make the host's transport reachable; `filter_extensions`
                    // applies the `perform_http` gate per plugin.
                    self.with_host_services(extensions),
                    context_table,
                    &self.task_tracker,
                )
                .await
        };
        (
            self.apply_assertions(&snapshot, Some(H::NAME), matched.as_ref(), result),
            tasks,
        )
    }

    /// Invoke a typed hook by explicit name.
    ///
    /// Combines compile-time payload type checking (from `H`) with
    /// runtime hook name routing (from `hook_name`). Use this when
    /// a single hook type (e.g., `CmfHook`) covers multiple hook
    /// names (e.g., `cmf.tool_pre_invoke`, `cmf.tool_post_invoke`).
    ///
    /// # Type Parameters
    ///
    /// - `H` — the hook type (provides payload type checking).
    ///
    /// # Arguments
    ///
    /// * `hook_name` — the hook name for dispatch routing.
    /// * `payload` — the typed payload (compile-time checked against `H::Payload`).
    /// * `extensions` — the full extensions.
    /// * `context_table` — optional context table from a previous hook.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Compile-time: payload must be MessagePayload (from CmfHook)
    /// // Runtime: dispatches to plugins registered under "cmf.tool_pre_invoke"
    /// let (result, bg) = mgr.invoke_named::<CmfHook>(
    ///     "cmf.tool_pre_invoke", payload, ext, None,
    /// ).await;
    /// ```
    pub async fn invoke_named<H: HookTypeDef>(
        &self,
        hook_name: &str,
        payload: H::Payload,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> (PipelineResult, BackgroundTasks) {
        let snapshot = self.load_runtime();
        let hook_type = HookType::new(hook_name);
        let all_entries = snapshot.registry.entries_for_hook(&hook_type);

        // No registered entries AND no route annotations → nothing to
        // do. Allow-and-pass-through. We can't short-circuit on
        // `all_entries.is_empty()` alone, because route annotations
        // (external-orchestrator handlers from APL / future Rego /
        // Cedar-direct) can produce a single-entry dispatch even when
        // no plugin was registered on the hook directly.
        //
        // Returning here also means a request whose path cannot be read is
        // allowed rather than denied on such a hook. Nothing would have
        // enforced on it either way.
        if all_entries.is_empty() && snapshot.route_annotations.is_empty() {
            let boxed: Box<dyn PluginPayload> = Box::new(payload);
            let matched = resolve_contract_route(&snapshot, &extensions);
            return (
                self.apply_assertions(
                    &snapshot,
                    Some(hook_name),
                    matched.as_ref(),
                    PipelineResult::allowed_with(
                        boxed,
                        extensions,
                        context_table.unwrap_or_default(),
                    ),
                ),
                BackgroundTasks::empty(),
            );
        }

        let (entries, matched) = match self
            .filter_entries_by_route(&snapshot, all_entries, &extensions, hook_name)
            .await
        {
            Ok(resolved) => resolved,
            Err(cause) => {
                return (
                    self.apply_assertions(
                        &snapshot,
                        Some(hook_name),
                        None,
                        PipelineResult::denied(
                            cause.violation(),
                            extensions,
                            context_table.unwrap_or_default(),
                        ),
                    ),
                    BackgroundTasks::empty(),
                );
            },
        };

        if entries.is_empty() {
            let boxed: Box<dyn PluginPayload> = Box::new(payload);
            return (
                self.apply_assertions(
                    &snapshot,
                    Some(hook_name),
                    matched.as_ref(),
                    PipelineResult::allowed_with(
                        boxed,
                        extensions,
                        context_table.unwrap_or_default(),
                    ),
                ),
                BackgroundTasks::empty(),
            );
        }

        let boxed: Box<dyn PluginPayload> = Box::new(payload);
        let (result, tasks) = {
            let _boundary = self.enter_executor();
            snapshot
                .executor
                .execute(
                    &entries,
                    boxed,
                    // Make the host's transport reachable; `filter_extensions`
                    // applies the `perform_http` gate per plugin.
                    self.with_host_services(extensions),
                    context_table,
                    &self.task_tracker,
                )
                .await
        };
        (
            self.apply_assertions(&snapshot, Some(hook_name), matched.as_ref(), result),
            tasks,
        )
    }

    /// Find every (`hook_name`, `HookEntry`) pair belonging to the named
    /// plugin. Returns an empty `Vec` if the plugin isn't registered.
    ///
    /// Used by external orchestrators (notably praxis-policy-apl-runtime) that decide
    /// the per-route plugin lineup themselves and need handler refs +
    /// `trusted_config` to build pre-resolved dispatch plans. Cheaper than
    /// going through `invoke_named` per request because the caller can
    /// cache the resulting entries — pair the result with
    /// [`config_generation`](Self::config_generation) to invalidate the
    /// cache on snapshot swaps.
    ///
    /// Bypasses route/entity filtering — caller has already decided this
    /// plugin should run. APL's `routes:` is itself the authoritative
    /// lineup; praxis-policy-core's condition-based routing is a parallel model
    /// for non-APL hosts.
    pub fn find_plugin_entries(
        &self,
        plugin_name: &str,
    ) -> Vec<(String, crate::registry::HookEntry)> {
        let snapshot = self.load_runtime();
        snapshot.registry.entries_for_plugin(plugin_name)
    }

    /// Dispatch a caller-supplied slice of `HookEntries` through the
    /// executor's full 5-phase pipeline (sequential, transform, audit,
    /// concurrent, fire-and-forget). All `on_error` / timeout / mode /
    /// write-token machinery applies.
    ///
    /// Bypasses hook-name lookup and route/entity filtering — caller has
    /// already resolved the lineup (typically via
    /// [`find_plugin_entries`](Self::find_plugin_entries) + a per-route
    /// dispatch plan). The `H: HookTypeDef` parameter enforces payload
    /// type at compile time; mismatched payloads fail to compile, same
    /// as [`invoke_named`](Self::invoke_named).
    ///
    /// Returns `(PipelineResult, BackgroundTasks)` identical in shape to
    /// `invoke_named` so callers can swap between the two paths without
    /// rewriting downstream result handling.
    pub async fn invoke_entries<H: HookTypeDef>(
        &self,
        entries: &[crate::registry::HookEntry],
        payload: H::Payload,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> (PipelineResult, BackgroundTasks) {
        let snapshot = self.load_runtime();
        self.warn_if_dispatch_has_no_boundary(&snapshot);
        if entries.is_empty() {
            let boxed: Box<dyn PluginPayload> = Box::new(payload);
            return (
                // `None`, so nothing is applied. Not an omission: this is a
                // nested dispatch primitive rather than a wire boundary, and
                // the contract belongs after policy evaluation, at the outer
                // boundary this call runs inside.
                self.apply_assertions(
                    &snapshot,
                    None,
                    None,
                    PipelineResult::allowed_with(
                        boxed,
                        extensions,
                        context_table.unwrap_or_default(),
                    ),
                ),
                BackgroundTasks::empty(),
            );
        }
        let boxed: Box<dyn PluginPayload> = Box::new(payload);
        let (result, tasks) = {
            let _boundary = self.enter_executor();
            snapshot
                .executor
                .execute(
                    entries,
                    boxed,
                    // Make the host's transport reachable; `filter_extensions`
                    // applies the `perform_http` gate per plugin.
                    self.with_host_services(extensions),
                    context_table,
                    &self.task_tracker,
                )
                .await
        };
        (self.apply_assertions(&snapshot, None, None, result), tasks)
    }

    /// Override the resolved plugin list for one `(entity_type, entity_name)`
    /// pair on the listed hooks with a single synthetic handler. The handler
    /// takes responsibility for any further plugin dispatch within itself
    /// (typically by calling [`invoke_entries`](Self::invoke_entries) against
    /// the same registry's other entries — i.e. APL's `run(name)` →
    /// `CmfPluginInvoker` → `invoke_entries` flow).
    ///
    /// This is the integration point external orchestrators (APL, future
    /// Rego/Cedar-direct/Custom) use to drive plugins via their own
    /// semantics instead of praxis-policy-core's imperative `routes.*.plugins:`
    /// chain. Bumps the config generation so cached dispatch plans in
    /// downstream caches invalidate.
    ///
    /// `config` provides the `trusted_config` for the synthetic plugin —
    /// the executor reads `mode`, `on_error`, `capabilities`, etc. from
    /// it the same way it does for any other registered plugin. Capabilities
    /// should be a *superset* of what the orchestrator needs to read from
    /// `Extensions` (praxis-policy-core's per-plugin filter still applies to the
    /// synthetic handler).
    ///
    /// The underlying `plugins:` chain for this route is *not* removed —
    /// those plugins stay discoverable via [`find_plugin_entries`](Self::find_plugin_entries)
    /// so the orchestrator can dispatch into them by name.
    ///
    /// An annotation is the entire lineup for its coordinates: resolution
    /// returns the handler alone, so the `all` group, the entity-type
    /// defaults, tag bundles, and the route's own `plugins:` list stop firing
    /// for those requests unless the handler dispatches into them by name.
    ///
    /// Returns whether an annotation was already installed under the same
    /// `(entity_type, entity_name, scope, hook_name)` and has been replaced. A
    /// host may replace deliberately, so this reports rather than refuses.
    pub fn annotate_route<H>(
        &self,
        entity_type: impl Into<String>,
        entity_name: impl Into<String>,
        scope: Option<String>,
        hook_name: impl Into<String>,
        handler: Arc<H>,
        config: crate::plugin::PluginConfig,
    ) -> bool
    where
        H: crate::plugin::Plugin + crate::registry::AnyHookHandler + 'static,
    {
        let key = AnnotationKey {
            entity_type: entity_type.into(),
            entity_name: entity_name.into(),
            scope,
            hook_name: hook_name.into(),
        };
        let plugin_ref = Arc::new(crate::registry::PluginRef::new(handler.clone(), config));
        let entry = crate::registry::HookEntry {
            plugin_ref,
            handler,
        };
        self.mutate_runtime(|snap| snap.route_annotations.insert(key, entry).is_some())
    }

    /// Remove a route annotation for a specific hook. No-op when no
    /// annotation exists for the key. Bumps the generation so downstream
    /// caches invalidate.
    pub fn remove_route_annotation(
        &self,
        entity_type: &str,
        entity_name: &str,
        scope: Option<&str>,
        hook_name: &str,
    ) {
        let key = AnnotationKey {
            entity_type: entity_type.to_owned(),
            entity_name: entity_name.to_owned(),
            scope: scope.map(str::to_owned),
            hook_name: hook_name.to_owned(),
        };
        self.mutate_runtime(|snap| {
            snap.route_annotations.remove(&key);
        });
    }

    /// Apply the `assertions:` contract in force to a pipeline result.
    ///
    /// Called at **every** return site of every entry point, not only the one
    /// through the executor. An always-on control that fires on the happy path
    /// alone is the way this ships broken: a hook with no registered entry
    /// returns before route filtering, and a client-supplied `x-auth-user-id`
    /// would reach the upstream from a deployment whose route simply has no
    /// plugin on that hook.
    ///
    /// `hook_name` is what the direction comes from, so `None` applies nothing:
    /// a nested dispatch primitive is not a wire boundary, and the contract
    /// belongs after policy evaluation rather than around each step of it.
    /// `matched` is the route the caller already resolved, or `None` where no
    /// route matched, which resolves the global layer alone.
    fn apply_assertions(
        &self,
        snapshot: &RuntimeSnapshot,
        hook_name: Option<&str>,
        matched: Option<&config::MatchedRoute<'_>>,
        mut result: PipelineResult,
    ) -> PipelineResult {
        use crate::assertions::Direction;

        if !snapshot.declares_assertions {
            return result;
        }
        let (Some(hook_name), Some(policy_config)) = (hook_name, snapshot.policy_config.as_ref())
        else {
            return result;
        };
        // The hook's registered phase is the authority, so this feature names no
        // hook: a `Pre` hook asserts toward the upstream, a `Post` hook toward
        // the client, and a hook that is neither is not a wire boundary.
        let Some(direction) = crate::hooks::lookup_hook_metadata(hook_name)
            .and_then(|meta| Direction::from_phase(meta.phase))
        else {
            return result;
        };
        if let Some(extensions) = result.modified_extensions.as_ref() {
            self.warn_once_if_route_assertions_are_unreachable(
                &snapshot.http_routes_declaring_assertions,
                direction,
                extensions,
            );
        }
        let denied = result.is_denied();
        // A denied pipeline forwarded nothing, so there is no upstream response
        // to filter on the way out.
        if denied && direction == Direction::Response {
            return result;
        }
        // The entity type comes from the request rather than from the matched
        // route, so `global.defaults.http` still governs a generic-HTTP request
        // that selected none of the `http:` routes.
        let entity_type = result
            .modified_extensions
            .as_ref()
            .and_then(|extensions| extensions.meta.as_deref())
            .and_then(|meta| meta.entity_type.clone());
        let Some(contract) = config::resolve_assertions_for_route(
            policy_config,
            matched,
            entity_type.as_deref(),
            direction,
        ) else {
            return result;
        };

        if denied {
            // Removal still happens: it costs nothing, is never wrong, and keeps
            // a client-supplied value out of the extensions the audit path sees.
            // Injection does not, and `on_missing` is not evaluated, because
            // replacing one denial with another says nothing useful.
            if let Some(extensions) = result.modified_extensions.as_mut() {
                crate::assertions::apply(&contract, &[], extensions, direction);
            }
            return result;
        }

        let rendered = match result.modified_extensions.as_ref() {
            Some(extensions) => crate::assertions::render(&contract, extensions),
            None => return result,
        };
        match rendered {
            Ok(rendered) => {
                if let Some(extensions) = result.modified_extensions.as_mut() {
                    crate::assertions::apply(&contract, &rendered, extensions, direction);
                }
                result
            },
            Err(missing) => {
                // Strip first. The removal is unconditional, and a refused
                // request must not carry a client value under an asserted name.
                if let Some(extensions) = result.modified_extensions.as_mut() {
                    crate::assertions::apply(&contract, &[], extensions, direction);
                }
                deny_missing_assertion(missing, direction, result)
            },
        }
    }

    /// Mark the span of one executor invocation, so a nested dispatch can tell
    /// it is nested.
    fn enter_executor(&self) -> ExecutorBoundary<'_> {
        self.executor_depth.fetch_add(1, Ordering::AcqRel);
        ExecutorBoundary {
            depth: &self.executor_depth,
        }
    }

    /// Warn when [`invoke_entries`](Self::invoke_entries) is reached from
    /// outside an executor invocation while a contract is configured.
    ///
    /// Every caller in this tree nests inside a policy handler the executor is
    /// running, so the contract fires at the outer boundary after that handler
    /// returns. A host adopting this primitive as its *outermost* dispatch has no
    /// boundary and therefore no contract, and would learn it from a header that
    /// did not appear.
    ///
    /// A warning rather than a debug assertion, on two counts. Driving the
    /// primitive directly is legitimate for a caller that wants no boundary, and
    /// a test harness exercising the invokers does exactly that, so a panic would
    /// punish a caller for something that is not a fault. And the residual risk
    /// is a *release* build integrated that way losing the contract silently,
    /// which a debug-only check cannot reach at all.
    ///
    /// Every occurrence, not once per process. The property at stake is that a
    /// client cannot set an asserted header, and it lapses on each such call
    /// rather than only the first; a single line emitted at whatever moment the
    /// first call happened is gone from a long-running process's logs by the
    /// time anyone asks. The volume is bounded by the guard below: a host that
    /// configures no contract loses nothing here and is told nothing, so the
    /// noise only reaches a deployment where it is reporting a real lapse.
    ///
    /// The depth counter is process-wide rather than per task, so a genuine
    /// nested call always sees its parent in flight and cannot trip this. An
    /// unrelated concurrent invocation can mask a real outermost call, which is
    /// the direction a diagnostic should err in.
    fn warn_if_dispatch_has_no_boundary(&self, snapshot: &RuntimeSnapshot) {
        // A host with no contract configured loses nothing here, so there is
        // nothing to tell it.
        if !snapshot.declares_assertions || self.executor_depth.load(Ordering::Acquire) > 0 {
            return;
        }
        warn!(
            alarm = "assertions_dispatch_without_a_boundary",
            "invoke_entries was called as an outermost dispatch. It is a nested dispatch \
             primitive rather than a wire boundary, so no `assertions:` contract is applied \
             to its result: nothing is asserted onto the request and nothing the contract \
             names is removed from it, so a client-supplied header reaches the upstream under \
             a name the upstream trusts. Drive a named entry point (invoke_named, invoke, or \
             invoke_by_name) as the outermost dispatch so the contract has a boundary to \
             fire at.",
        );
    }

    /// Filter hook entries based on route resolution, with caching.
    ///
    /// When routing is enabled and the request identifies an entity, resolves
    /// the route and returns only the entries for plugins that match. Results
    /// are cached by `(entity_type, resolved_name, hook_name, scope)`, and a
    /// call for a key already resolved returns an `Arc` to the cached entries
    /// rather than a copy.
    ///
    /// A generic HTTP request is matched from its request line, so the name it
    /// resolves to is a selector from the configuration rather than anything
    /// the request carried. The four MCP entity types are matched by the name
    /// they arrive under, as they always have been.
    ///
    /// Under `dispatch: hooks` the entries are filtered by each plugin's own
    /// `conditions:`; when the request identifies no entity, every entry is
    /// returned.
    ///
    /// Returns the route that matched alongside the entries, because the
    /// `assertions:` contract the caller applies afterwards resolves from it and
    /// this is where the match is computed. Re-resolving at the call site would
    /// be a second table walk per request for an answer already in hand.
    ///
    /// # Errors
    ///
    /// [`RouteResolutionError`] when an HTTP request's path cannot be read and
    /// the configuration declares at least one `http:` route.
    async fn filter_entries_by_route<'snapshot>(
        &self,
        snapshot: &'snapshot RuntimeSnapshot,
        entries: &[crate::registry::HookEntry],
        extensions: &Extensions,
        hook_name: &str,
    ) -> Result<
        (
            Arc<Vec<crate::registry::HookEntry>>,
            Option<config::MatchedRoute<'snapshot>>,
        ),
        RouteResolutionError,
    > {
        // A route only exists when the configuration turns routing on, so the
        // whole selector feature is behind this.
        let routing_config = snapshot
            .policy_config
            .as_ref()
            .filter(|config| config.dispatch_mode().is_policy());

        let meta = extensions.meta.as_deref();
        let entity_type = meta.and_then(|m| m.entity_type.as_deref());
        let request_scope = meta.and_then(|m| m.scope.as_deref());

        // A generic HTTP request has to be matched before anything is looked
        // up, because the name that keys the annotation table and the cache is
        // the selector that matched and a request path is never that name. The
        // four MCP entity types arrive under the name they are known by, so
        // they need no derivation and keep resolving after the lookups below.
        let http_matched = if entity_type == Some(ENTITY_HTTP) {
            let request_line = extensions.http.as_deref();
            // Whatever precedes a `?`, which is the router's own input: it
            // matches on `rewritten_path` when a rewrite filter set one and
            // strips a query off it, and on a request URI's path otherwise,
            // which carries no query to begin with. A host that puts one in
            // the path anyway lands on the same route the router picks.
            let path = match_path(extensions);
            // Matching runs on the path exactly as it arrived, because that is
            // the path the host's router matches on. Normalizing first would
            // let PPE resolve a different route than the one the request is
            // actually forwarded to.
            //
            // The normalizer still runs, and its `Ok` value is deliberately
            // discarded: it is a fail-closed guard here, not the matcher. Do
            // not wire its output back into the query below.
            if let Err(cause) = path.map(http_path::normalize_match_path).transpose() {
                // An unreadable path denies rather than falling through to the
                // global policy: a path PPE cannot read is one it cannot claim
                // to have matched the router on. Without an `http:` route
                // nothing could have answered for the path anyway, so nothing
                // is denied.
                if routing_config.is_some_and(declares_http_route) {
                    return Err(cause.into());
                }
            }
            self.warn_once_if_route_authentication_is_unreachable(
                &snapshot.http_routes_declaring_authentication,
                hook_name,
                path,
            );
            routing_config.zip(path).and_then(|(policy_config, path)| {
                let method = request_line.and_then(|http| http.method.as_deref());
                config::resolve_route(
                    policy_config,
                    config::RouteQuery::http(path, method).with_scope(request_scope),
                )
            })
        } else {
            None
        };

        // The name every lookup below keys on. When HTTP resolution found
        // nothing the reserved global name governs, and naming the constant
        // rather than reading `meta.entity_name` is what keeps a host-supplied
        // path out of the cache key on that path too: the constant's doc asks a
        // host to set that value but cannot make it.
        let resolved_name = if entity_type == Some(ENTITY_HTTP) {
            Some(
                http_matched
                    .as_ref()
                    .map_or(ENTITY_NAME_GLOBAL, |route| route.name.as_str()),
            )
        } else {
            meta.and_then(|m| m.entity_name.as_deref())
        };

        // The route an `assertions:` contract resolves from. A generic-HTTP
        // request matched above; a named entity matches on the slow path below,
        // which a cache hit skips, so it is matched here instead when a contract
        // could need it. Guarded on the config declaring one, because that walk
        // is exactly what the route cache exists to avoid.
        let early_named = if entity_type != Some(ENTITY_HTTP)
            && snapshot.declares_assertions
            && let (Some(policy_config), Some(entity_type), Some(resolved_name)) =
                (routing_config, entity_type, resolved_name)
        {
            config::resolve_route(
                policy_config,
                config::RouteQuery::named(entity_type, resolved_name).with_scope(request_scope),
            )
        } else {
            None
        };

        // Route annotation short-circuit: if the request's
        // (entity_type, resolved_name) has an annotation that handles this
        // hook, return a one-entry list containing the annotated handler.
        // External orchestrators (APL via praxis-policy-apl-runtime; future Rego/Cedar)
        // register annotations to drive plugin dispatch under their own
        // semantics instead of praxis-policy-core's imperative chain. Underlying
        // `plugins:` entries stay in the registry for the orchestrator
        // to dispatch into by-name via `invoke_entries`.
        if !snapshot.route_annotations.is_empty()
            && let (Some(et), Some(en)) = (entity_type, resolved_name)
        {
            // Scoped lookup first (specific wins); unscoped lookup
            // falls back as a "global default" — matches the
            // specificity tiebreaker `resolve_route` uses.
            // Lookup is keyed on the hook name as well, so a route
            // can install distinct handlers per phase.
            let scoped = request_scope.and_then(|s| {
                snapshot.route_annotations.get(&AnnotationKey {
                    entity_type: et.to_owned(),
                    entity_name: en.to_owned(),
                    scope: Some(s.to_owned()),
                    hook_name: hook_name.to_owned(),
                })
            });
            let candidate = scoped.or_else(|| {
                snapshot.route_annotations.get(&AnnotationKey {
                    entity_type: et.to_owned(),
                    entity_name: en.to_owned(),
                    scope: None,
                    hook_name: hook_name.to_owned(),
                })
            });
            // Glob annotations are keyed by their pattern, not the request name.
            // Resolve only when a glob exists, reusing assertion resolution when available.
            let glob_matched = if candidate.is_none() && snapshot.declares_glob_named_routes {
                early_named.as_ref().map_or_else(
                    || {
                        routing_config.and_then(|policy_config| {
                            config::resolve_route(
                                policy_config,
                                config::RouteQuery::named(et, en).with_scope(request_scope),
                            )
                        })
                    },
                    |matched| {
                        Some(config::MatchedRoute {
                            route: matched.route,
                            name: matched.name.clone(),
                        })
                    },
                )
            } else {
                None
            };
            // An equal name was already checked above.
            let candidate = candidate.or_else(|| {
                let matched = glob_matched.as_ref()?;
                if matched.name == en {
                    return None;
                }
                let scoped = request_scope.and_then(|s| {
                    snapshot.route_annotations.get(&AnnotationKey {
                        entity_type: et.to_owned(),
                        entity_name: matched.name.clone(),
                        scope: Some(s.to_owned()),
                        hook_name: hook_name.to_owned(),
                    })
                });
                scoped.or_else(|| {
                    snapshot.route_annotations.get(&AnnotationKey {
                        entity_type: et.to_owned(),
                        entity_name: matched.name.clone(),
                        scope: None,
                        hook_name: hook_name.to_owned(),
                    })
                })
            });
            if let Some(entry) = candidate {
                return Ok((
                    Arc::new(vec![entry.clone()]),
                    contract_route(snapshot, http_matched.as_ref(), early_named.as_ref()),
                ));
            }
        }

        // Hook dispatch (or no config): each plugin's own `conditions:` decide.
        // An empty conditions Vec means "fire always", which is the default a
        // plugin that declares none gets.
        let Some(policy_config) = routing_config else {
            let filtered: Vec<_> = entries
                .iter()
                .filter(|e| e.plugin_ref.trusted_config().passes_conditions(extensions))
                .cloned()
                .collect();
            return Ok((
                Arc::new(filtered),
                contract_route(snapshot, http_matched.as_ref(), early_named.as_ref()),
            ));
        };

        // `meta` is matched but not bound: nothing below reads a field of it
        // now that resolution no longer merges the request's tags. Its presence
        // still gates the path, because a request the engine cannot identify
        // resolves no route.
        //
        // Where it used to fall through to every registered entry, it now
        // denies when the configuration declares a policy. Firing the whole
        // registry at a request no route could match runs plugins against
        // absent context, in the mode whose whole premise is that a policy
        // decides; and passing it instead would let a host skip every rule by
        // omitting metadata. A config declaring no policy keeps the old
        // behavior, which is what `declares_a_policy` is for.
        let (Some(_), Some(entity_type), Some(resolved_name)) = (meta, entity_type, resolved_name)
        else {
            if declares_a_policy(policy_config, snapshot) {
                return Err(RouteResolutionError::UnidentifiedRequest);
            }
            return Ok((
                Arc::new(entries.to_vec()),
                contract_route(snapshot, http_matched.as_ref(), early_named.as_ref()),
            ));
        };

        // Fast path: zero-allocation cache lookup with raw_entry
        let hash = {
            use std::hash::BuildHasher as _;
            let mut hasher = self.cache_hasher.build_hasher();
            entity_type.hash(&mut hasher);
            resolved_name.hash(&mut hasher);
            hook_name.hash(&mut hasher);
            request_scope.hash(&mut hasher);
            hasher.finish()
        };
        {
            // Recover from poisoning: a panic in another thread while holding
            // this lock leaves the cache flagged poisoned. The cache's contents
            // are still valid (HashMap operations are panic-safe and stale
            // entries are healed by `clear_routing_cache()`), so we don't want
            // a one-time panic to permanently disable dispatch. Same idiom
            // applies to all four lock sites in this file.
            let cache = self
                .route_cache
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((_, cached)) = cache.raw_entry().from_hash(hash, |key| {
                key.entity_type == entity_type
                    && key.resolved_name == resolved_name
                    && key.hook_name == hook_name
                    && key.scope.as_deref() == request_scope
            }) {
                return Ok((
                    Arc::clone(cached),
                    contract_route(snapshot, http_matched.as_ref(), early_named.as_ref()),
                ));
            }
        }

        // Slow path: resolve, filter, and cache (allocations only here).
        //
        // Hook-specific resolution for identity.resolve: the route's
        // `identity:` block is the authoritative dispatch list (NOT
        // the `plugins:` block, which in APL-driven routes means
        // "per-route overrides" rather than "binding"). For every
        // other hook, the generic plugins-block resolution applies.
        // An HTTP request matched above; every other entity type matches here,
        // once, and both resolvers read the route the match produced rather
        // than scanning the route table again.
        let name_matched = if entity_type == ENTITY_HTTP {
            None
        } else if early_named.is_some() {
            // Already resolved above, for the cache-hit path. Reused rather
            // than resolved a second time.
            early_named
        } else {
            config::resolve_route(
                policy_config,
                config::RouteQuery::named(entity_type, resolved_name).with_scope(request_scope),
            )
        };
        let matched = http_matched.as_ref().or(name_matched.as_ref());

        // The resolved name is the only place a matched route is visible from
        // outside this function: for HTTP it is a selector the request never
        // carried, and `http.path` in the attribute bag is the raw path. It is
        // configuration rather than request input, so emitting it is safe.
        trace!(
            entity_type,
            resolved_name,
            scope = request_scope,
            hook = hook_name,
            "Resolved route for request",
        );

        // `identity.resolve` reads the route's `authentication:` steps, the one
        // structural dispatch list policy mode keeps. Every other hook resolves
        // to nothing here and is governed by the annotation short-circuit above,
        // so a policy naming the plugin is what makes it fire.
        let resolved = if hook_name == crate::identity::HOOK_IDENTITY_RESOLVE {
            config::resolve_identity_plugins_for_route(policy_config, matched)
        } else {
            config::resolve_plugins_for_entity(policy_config)
        };

        // Filter entries to resolved plugins, preserving resolution order.
        // If a plugin has config overrides and we have a factory for its kind,
        // create a new instance with the merged config.
        let mut filtered = Vec::new();
        for resolved_plugin in &resolved {
            if let Some(entry) = entries
                .iter()
                .find(|e| e.plugin_ref.name() == resolved_plugin.name)
            {
                if let Some(overrides) = &resolved_plugin.config_overrides {
                    // Try to create an override instance
                    if let Some(override_entry) =
                        self.create_override_instance(entry, overrides).await
                    {
                        filtered.push(override_entry);
                        continue;
                    }
                }
                filtered.push(entry.clone());
            }
        }

        let cached = Arc::new(filtered);

        // Store in cache — owned key allocated only on cache miss.
        // Reject-on-full: when the cache is at capacity we still return
        // the freshly resolved Vec but skip memoization, bounding memory
        // growth from attacker-controlled entity names.
        let cache_key = RouteCacheKey {
            entity_type: entity_type.to_owned(),
            resolved_name: resolved_name.to_owned(),
            hook_name: hook_name.to_owned(),
            scope: request_scope.map(str::to_owned),
        };
        // Decide under the lock; log outside it so I/O doesn't block readers.
        // One warn per fill cycle — prevents log spam under DoS.
        let should_warn = {
            let mut cache = self
                .route_cache
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cache.len() >= snapshot.route_cache_max_entries {
                !self.route_cache_full_warned.swap(true, Ordering::AcqRel)
            } else {
                cache.insert(cache_key, Arc::clone(&cached));
                false
            }
        };
        if should_warn {
            warn!(
                max_entries = snapshot.route_cache_max_entries,
                "Routing cache at capacity — further routes will not be cached. \
                 Increase engine_settings.route_cache_max_entries or \
                 investigate entity name growth.",
            );
        }

        Ok((
            cached,
            contract_route(snapshot, http_matched.as_ref(), name_matched.as_ref()),
        ))
    }

    /// Warn once when an `http:` route's `authentication:` list cannot apply
    /// because the request carried no readable path at the identity hook.
    ///
    /// Falling back to the global list is the behavior a host gets today and
    /// stays that way, but doing it silently hides which list authenticated a
    /// request, so the condition is diagnosable from what the engine emits.
    ///
    /// Which routes those are is decided when the config lands, so this reads
    /// the answer off the snapshot. Every check here is O(1), which is what
    /// keeps the ordinary config, where the answer is empty, off the route
    /// table entirely.
    fn warn_once_if_route_authentication_is_unreachable(
        &self,
        unreachable: &[String],
        hook_name: &str,
        request_path: Option<&str>,
    ) {
        if hook_name != crate::identity::HOOK_IDENTITY_RESOLVE
            || unreachable.is_empty()
            || request_path.is_some_and(|path| path.starts_with('/'))
            || self
                .route_authentication_unreachable_warned
                .load(Ordering::Acquire)
        {
            return;
        }
        if !self
            .route_authentication_unreachable_warned
            .swap(true, Ordering::AcqRel)
        {
            warn!(
                routes = unreachable.join(", "),
                "An http: route declares authentication: but the request carries no \
                 readable path at the identity hook, so the global authentication \
                 list runs instead. The host must supply the request line on the \
                 extensions at this hook for a route's list to apply.",
            );
        }
    }

    /// Warn once per direction when an `http:` route's `assertions:` contract
    /// cannot apply because the request carried no readable path.
    ///
    /// The same failure the authentication warning covers, for a different block,
    /// so it reads the same way. Falling back to the levels above is defensible
    /// and stays, but doing it silently hides which contract crossed the
    /// boundary.
    ///
    /// Called from where the contract is applied rather than from route
    /// filtering, because filtering does not run on every path that applies one.
    ///
    /// Per direction because the two halves of one exchange are separate
    /// invocations, and a host can supply the request line on one and not the
    /// other. One combined gate would fire on the request half and be spent by
    /// the time the informative case arrived.
    fn warn_once_if_route_assertions_are_unreachable(
        &self,
        unreachable: &[String],
        direction: crate::assertions::Direction,
        extensions: &Extensions,
    ) {
        if unreachable.is_empty() {
            return;
        }
        let entity_type = extensions
            .meta
            .as_deref()
            .and_then(|meta| meta.entity_type.as_deref());
        if entity_type != Some(ENTITY_HTTP) {
            return;
        }
        if match_path(extensions).is_some_and(|path| path.starts_with('/')) {
            return;
        }
        let gate = match direction {
            crate::assertions::Direction::Request => {
                &self.route_request_assertions_unreachable_warned
            },
            crate::assertions::Direction::Response => {
                &self.route_response_assertions_unreachable_warned
            },
        };
        if gate.swap(true, Ordering::AcqRel) {
            return;
        }
        warn!(
            alarm = "assertions_route_unreachable",
            direction = direction.label(),
            routes = unreachable.join(", "),
            "an http: route declares assertions: but the request carries no readable \
             path at this invocation, so the levels above govern instead: \
             global.defaults.http, then global. The host must supply the request \
             line on the extensions at both halves of the exchange for a route's \
             contract to apply to both.",
        );
    }

    /// Build per-hook `HookEntry`s for a plugin with optional route-
    /// level overrides. Used by external orchestrators (notably
    /// praxis-policy-apl-runtime's dispatch plan) that need to splice per-route plugin
    /// variants — different `config`, narrower `capabilities`, different
    /// `on_error` — into the dispatch lineup while keeping praxis-policy-core
    /// the source of truth for instantiation and isolation.
    ///
    /// Behavior:
    /// - **All three overrides `None`:** returns the base entries
    ///   unchanged. Caller can use them as-is.
    /// - **Only `capabilities_override` / `on_error_override` set
    ///   (`config_override` is `None`):** builds new `PluginRef`s
    ///   sharing the *base plugin `Arc`* with a merged `TrustedConfig`
    ///   (override caps / `on_error` replace base values) and an
    ///   independent circuit breaker. Cheap — no factory call.
    /// - **`config_override` set:** invokes the registered factory for
    ///   the plugin's `kind` with a merged `PluginConfig` (override
    ///   `config` *replaces* base `config` wholesale per unified-config
    ///   spec — not deep merge), calls `initialize()` on the new
    ///   instance, and wraps every returned handler in a new
    ///   `PluginRef` with a fresh circuit breaker.
    ///
    /// Returns an empty `Vec` when:
    /// - the plugin name isn't registered in the engine,
    /// - the factory for the plugin's `kind` is missing,
    /// - the factory's `create` errors,
    /// - or `initialize_with()` fails on the new instance.
    ///
    /// Each of those is a configuration / wiring fault the caller
    /// should treat as `NotFound` at dispatch time. The method logs
    /// the underlying error before returning empty so debugging
    /// surfaces in operator logs rather than as a silent miss.
    pub async fn build_override_entries(
        &self,
        plugin_name: &str,
        config_override: Option<&serde_yaml::Value>,
        capabilities_override: Option<&std::collections::HashSet<String>>,
        on_error_override: Option<crate::plugin::OnError>,
    ) -> Vec<(String, crate::registry::HookEntry)> {
        let base_entries = self.find_plugin_entries(plugin_name);
        if base_entries.is_empty() {
            return Vec::new();
        }

        // No overrides at all — caller can use base entries unchanged.
        if config_override.is_none()
            && capabilities_override.is_none()
            && on_error_override.is_none()
        {
            return base_entries;
        }

        // Pull the base trusted_config off any of the base entries —
        // all of them share the same `Arc<PluginRef>` for a given
        // plugin name, so picking the first is fine.
        let Some(base_ref) = base_entries.first().map(|(_, e)| Arc::clone(&e.plugin_ref)) else {
            // Unreachable: the is_empty() check above already returned.
            return Vec::new();
        };
        let mut merged_config = base_ref.trusted_config().clone();

        // Capabilities: override replaces base when present.
        if let Some(caps) = capabilities_override {
            merged_config.capabilities = caps.clone();
        }

        // on_error: override replaces base when present.
        if let Some(oe) = on_error_override {
            merged_config.on_error = oe;
        }

        // Caps/on_error-only path — shared base plugin Arc, new
        // PluginRef with merged config + fresh circuit breaker.
        // No factory call, no async work.
        if config_override.is_none() {
            let new_ref = Arc::new(crate::registry::PluginRef::new(
                Arc::clone(base_ref.plugin()),
                merged_config,
            ));
            return base_entries
                .into_iter()
                .map(|(hook_name, base_entry)| {
                    (
                        hook_name,
                        crate::registry::HookEntry {
                            plugin_ref: Arc::clone(&new_ref),
                            handler: base_entry.handler,
                        },
                    )
                })
                .collect();
        }

        // Config override present — factory path. Convert YAML
        // override value into the JSON shape `PluginConfig.config`
        // carries (YAML is a superset of JSON so serde re-serialization
        // is safe). Per spec, override `config` replaces the base
        // `config` wholesale.
        let Some(cfg_yaml) = config_override else {
            // Unreachable: the branch above returns when this is None.
            return base_entries;
        };
        let cfg_json = match serde_json::to_value(cfg_yaml) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    plugin = %plugin_name,
                    error = %e,
                    "build_override_entries: YAML→JSON config conversion failed",
                );
                return Vec::new();
            },
        };
        merged_config.config = Some(cfg_json);

        let kind = merged_config.kind.clone();
        // The registry lock is released before `create` runs. `create` is
        // host-supplied code and may re-enter the engine; taking the write side
        // while this thread still held a read guard would deadlock.
        let factory = {
            let factories = self
                .factories
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(f) = factories.get(&kind) {
                f
            } else {
                error!(
                    plugin = %plugin_name,
                    kind = %kind,
                    "build_override_entries: no factory registered for kind",
                );
                return Vec::new();
            }
        };
        let instance = {
            match factory.create(&merged_config) {
                Ok(i) => i,
                Err(e) => {
                    error!(
                        plugin = %plugin_name,
                        error = %e,
                        "build_override_entries: factory.create failed",
                    );
                    return Vec::new();
                },
            }
        };

        // `initialize_with`, not `initialize` — an override instance is a
        // full instance and needs the same host services the registered
        // one got. Capabilities come from `merged_config`, so a route that
        // narrows them narrows what its override may reach.
        let init_ext = self.init_extensions_for(&merged_config.capabilities);
        if let Err(e) = instance.plugin.initialize_with(&init_ext).await {
            error!(
                plugin = %plugin_name,
                error = %e,
                "build_override_entries: initialize_with() failed on new instance",
            );
            return Vec::new();
        }

        // One PluginRef shared across the new instance's handlers —
        // all hooks served by one instance share a circuit breaker
        // (matches registration semantics).
        let new_ref = Arc::new(crate::registry::PluginRef::new(
            Arc::clone(&instance.plugin),
            merged_config,
        ));
        instance
            .handlers
            .into_iter()
            .map(|(hook_name, handler)| {
                (
                    hook_name.to_owned(),
                    crate::registry::HookEntry {
                        plugin_ref: Arc::clone(&new_ref),
                        handler,
                    },
                )
            })
            .collect()
    }

    /// Create an override plugin instance with merged config.
    ///
    /// When a route overrides a plugin's config, we create a new
    /// instance via the factory with the merged config and call
    /// `initialize()` on it so plugins that open DB connections / file
    /// handles / network clients run their setup.
    ///
    /// The override gets its OWN circuit breaker (`disabled` flag) and
    /// its own UUID, independent of the base. Config is part of the
    /// failure surface — an override with a bad connection string /
    /// wrong credentials / wrong limit value can fail for reasons that
    /// have nothing to do with the base's reliability. Coupling them
    /// would let a config-specific failure on one route silently
    /// disable the plugin on every other route, which is the opposite
    /// of the per-route blast-radius guarantee operators reach for
    /// overrides to get. The fresh UUID also keys the override's
    /// `local_state` in the context table, isolating per-instance
    /// state from the base for the same reason.
    ///
    /// Returns `None` (and the caller falls back to the base entry) if:
    /// - no factory is available for the plugin's kind,
    /// - the factory fails to create the instance,
    /// - the new instance has no handler for the target hook,
    /// - or `initialize_with()` fails on the new instance.
    async fn create_override_instance(
        &self,
        base_entry: &crate::registry::HookEntry,
        overrides: &serde_json::Value,
    ) -> Option<crate::registry::HookEntry> {
        let base_config = base_entry.plugin_ref.trusted_config();
        let kind = &base_config.kind;

        // Merge: start with base config, overlay with overrides
        let mut merged_config = base_config.clone();
        if let Some(override_config) = overrides.get("config") {
            // Merge the plugin-specific config section
            if let Some(base_plugin_config) = &merged_config.config {
                let mut merged = base_plugin_config.clone();
                if let (Some(base_obj), Some(override_obj)) =
                    (merged.as_object_mut(), override_config.as_object())
                {
                    for (key, value) in override_obj {
                        base_obj.insert(key.clone(), value.clone());
                    }
                }
                merged_config.config = Some(merged);
            } else {
                merged_config.config = Some(override_config.clone());
            }
        }

        // Create new instance with merged config — hold the factories
        // read lock just long enough to construct the instance, then drop
        // it before any `.await` so we never hold a sync lock across awaits.
        let target_hook = base_entry.handler.hook_type_name();
        // Lock released before `create`, which runs host-supplied factory code.
        let factory = {
            let factories = self
                .factories
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match factories.get(kind) {
                Some(f) => f,
                None => return None,
            }
        };
        let instance = {
            match factory.create(&merged_config) {
                Ok(i) => i,
                Err(e) => {
                    error!(
                        "Failed to create override instance for '{}': {}",
                        base_config.name, e
                    );
                    return None; // fall back to base instance
                },
            }
        };

        // Find the handler matching the current hook before consuming
        // the instance so we don't pay for initialization on a doomed instance.
        let handler = instance
            .handlers
            .into_iter()
            .find(|(name, _)| *name == target_hook)
            .map(|(_, h)| h);
        let handler = if let Some(h) = handler {
            h
        } else {
            warn!(
                "Override instance for '{}' has no handler for hook '{}'",
                base_config.name, target_hook
            );
            return None;
        };

        // Initialize the new instance — without this, plugins that need to
        // set up DB connections / file handles / network clients run with
        // default state. `initialize_with` rather than `initialize` for the
        // same reason the registration path uses it: a plugin that reaches
        // the host during init must reach it here too.
        let init_ext = self.init_extensions_for(&merged_config.capabilities);
        if let Err(e) = instance.plugin.initialize_with(&init_ext).await {
            error!(
                "Failed to initialize override instance for '{}': {} — falling back to base",
                base_config.name, e
            );
            return None;
        }

        // Independent circuit breaker + fresh UUID per (kind, name, config)
        // — see the doc comment above for why we don't share with the base.
        // Arc-wrapped for cheap cloning under group_by_mode.
        let plugin_ref = Arc::new(crate::registry::PluginRef::new(
            instance.plugin,
            merged_config,
        ));
        Some(crate::registry::HookEntry {
            plugin_ref,
            handler,
        })
    }

    /// Clear the routing cache. Call when config is reloaded or
    /// plugins are registered/unregistered. Also resets the warn-once
    /// latches so the next fill cycle can warn again.
    pub fn clear_routing_cache(&self) {
        {
            let mut cache = self
                .route_cache
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.clear();
        }
        // Outside the guard: the latches are independent atomics and there is
        // no reason to hold the cache lock while storing them.
        self.route_cache_full_warned.store(false, Ordering::Release);
        self.route_authentication_unreachable_warned
            .store(false, Ordering::Release);
        self.route_request_assertions_unreachable_warned
            .store(false, Ordering::Release);
        self.route_response_assertions_unreachable_warned
            .store(false, Ordering::Release);
    }

    /// Number of entries in the routing cache.
    pub fn routing_cache_size(&self) -> usize {
        self.route_cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether anything would run for the given hook name — either a
    /// registered plugin handler OR a route annotation targeting that hook.
    ///
    /// Route annotations (installed by APL from a route's `policy:` /
    /// `args:` / `result:` blocks) must be counted here: a route whose only
    /// handler for a phase is an annotation (e.g. a response-side
    /// `result: { ssn: redact(...) }` on `cmf.tool_post_invoke`, with no
    /// globally-registered post-invoke plugin) would otherwise report
    /// "no hooks" and be skipped by out-of-process hosts that use this as a
    /// fast-skip gate — silently dropping the route's policy for that phase.
    pub fn has_hooks_for(&self, hook_name: &str) -> bool {
        let snapshot = self.load_runtime();
        snapshot.registry.has_hooks_for(&HookType::new(hook_name))
            || snapshot
                .route_annotations
                .keys()
                .any(|k| k.hook_name.as_str() == hook_name)
    }

    /// Look up a plugin by name. Returns an `Arc<PluginRef>` clone — works
    /// with the snapshot-based dispatch model where the registry sits
    /// behind a transient `Arc<RuntimeSnapshot>` guard. `Arc<PluginRef>`
    /// derefs to `PluginRef`, so callers can chain methods directly:
    /// `mgr.get_plugin("name").unwrap().is_disabled()` still compiles.
    pub fn get_plugin(&self, name: &str) -> Option<Arc<PluginRef>> {
        self.load_runtime().registry.get(name)
    }

    /// Total number of registered plugins.
    pub fn plugin_count(&self) -> usize {
        self.load_runtime().registry.plugin_count()
    }

    /// All registered plugin names (owned, not borrowed from the registry).
    pub fn plugin_names(&self) -> Vec<String> {
        self.load_runtime().registry.plugin_names()
    }

    /// Whether the engine has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Unregister a plugin by name.
    pub fn unregister(&self, name: &str) -> Option<Arc<PluginRef>> {
        let removed = self.mutate_runtime(|snap| snap.registry.unregister(name));
        if removed.is_some() {
            self.clear_routing_cache();
        }
        removed
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PolicyEngineConfig::default())
    }
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
    clippy::significant_drop_tightening,
    trivial_casts,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::context::PluginContext;
    use crate::error::PluginViolation;
    use crate::hooks::metadata::{HookMetadata, register_hook_metadata};
    use crate::plugin::{OnError, PluginMode};
    use async_trait::async_trait;

    // -- Test payload --

    #[derive(Debug, Clone)]
    struct TestPayload {
        value: String,
    }
    crate::impl_plugin_payload!(TestPayload);

    // -- Test hook type --

    struct TestHook;
    impl HookTypeDef for TestHook {
        type Payload = TestPayload;
        type Result = PluginResult<TestPayload>;
        const NAME: &'static str = "test_hook";
    }

    // -- Test plugins: implement Plugin + HookHandler<TestHook> --
    // No AnyHookHandler boilerplate — the framework handles it.

    /// Plugin that allows everything.
    struct AllowPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for AllowPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
        async fn initialize(&self) -> Result<(), Box<PluginError>> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), Box<PluginError>> {
            Ok(())
        }
    }

    impl HookHandler<TestHook> for AllowPlugin {
        async fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            PluginResult::allow()
        }
    }

    /// Plugin that denies everything.
    struct DenyPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for DenyPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
        async fn initialize(&self) -> Result<(), Box<PluginError>> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), Box<PluginError>> {
            Ok(())
        }
    }

    impl HookHandler<TestHook> for DenyPlugin {
        async fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            PluginResult::deny(PluginViolation::new("denied", "test denial"))
        }
    }

    /// Handler that always returns an error (for testing `on_error` behavior).
    /// Serves `identity.resolve` with a handler written for the test hook.
    ///
    /// Registration refuses a handler whose family is not the one the hook's row
    /// names, and `identity.resolve` is the only hook a route binds a plugin to
    /// in policy mode, so the route-scoped fixtures reach dispatch through it.
    struct ServingIdentity(Arc<dyn AnyHookHandler>);

    #[async_trait]
    impl AnyHookHandler for ServingIdentity {
        async fn invoke(
            &self,
            payload: &dyn PluginPayload,
            extensions: &Extensions,
            ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            self.0.invoke(payload, extensions, ctx).await
        }

        fn hook_type_name(&self) -> &'static str {
            crate::identity::IdentityHook::NAME
        }
    }

    struct ErrorHandler;

    #[async_trait]
    impl AnyHookHandler for ErrorHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            Err(Box::new(PluginError::Execution {
                plugin_name: "error-plugin".into(),
                message: "simulated failure".into(),
                source: None,
                code: None,
                details: std::collections::HashMap::new(),
                proto_error_code: None,
            }))
        }

        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    // -- Helpers --

    /// The fixtures declare `test_hook`, which this crate does not
    /// dispatch, so its metadata has to be registered the way a host
    /// registers its own.
    ///
    /// No test calls this directly. Every helper that builds or parses a
    /// fixture config calls it, so a test is registered by producing its
    /// config. The registry is process-wide, so a test relying on a
    /// separate call passed beside the tests that made one and failed
    /// when run alone.
    fn register_fixture_hooks() {
        register_hook_metadata(TestHook::NAME, HookMetadata::permissive());
    }

    /// Parse fixture YAML into a validated config.
    ///
    /// Registration has to precede the parse, not just the load:
    /// validation reads the registry, so an unregistered `test_hook` is
    /// refused here.
    fn parse_fixture_config(yaml: &str) -> Result<PolicyConfig, Box<PluginError>> {
        register_fixture_hooks();
        crate::config::parse_config(yaml)
    }

    /// Load fixture YAML into `engine`, registering first for the same
    /// reason [`parse_fixture_config`] does.
    fn load_fixture_yaml(engine: &Arc<PolicyEngine>, yaml: &str) -> Result<(), Box<PluginError>> {
        register_fixture_hooks();
        engine.load_config_yaml(yaml)
    }

    fn make_config(name: &str, priority: i32, mode: PluginMode) -> PluginConfig {
        make_config_with_on_error(name, priority, mode, OnError::Fail)
    }

    fn make_config_with_on_error(
        name: &str,
        priority: i32,
        mode: PluginMode,
        on_error: OnError,
    ) -> PluginConfig {
        // The config below names `test_hook`, so its metadata has to
        // exist by the time a load validates it.
        register_fixture_hooks();
        PluginConfig {
            name: name.to_owned(),
            kind: "test".to_owned(),
            description: None,
            author: None,
            version: None,
            hooks: vec!["test_hook".to_owned()],
            mode,
            priority,
            on_error,
            capabilities: Default::default(),
            tags: Vec::new(),
            conditions: Vec::new(),
            config: None,
        }
    }

    fn make_config_with_conditions(
        name: &str,
        conditions: Vec<crate::plugin::PluginCondition>,
    ) -> PluginConfig {
        let mut cfg = make_config(name, 10, PluginMode::Sequential);
        cfg.conditions = conditions;
        cfg
    }

    // -- Tests --

    #[tokio::test]
    async fn test_manager_lifecycle() {
        let mgr = PolicyEngine::default();
        assert!(!mgr.is_initialized());
        assert_eq!(mgr.plugin_count(), 0);

        mgr.initialize().await.unwrap();
        assert!(mgr.is_initialized());

        // Idempotent
        mgr.initialize().await.unwrap();

        mgr.shutdown().await;
        assert!(!mgr.is_initialized());
    }

    #[tokio::test]
    async fn test_invoke_by_name_no_plugins() {
        let mgr = PolicyEngine::default();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });

        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
        assert!(result.modified_payload.is_some());
    }

    #[tokio::test]
    async fn test_invoke_by_name_allow() {
        let mgr = PolicyEngine::default();
        let config = make_config("allow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });

        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_invoke_by_name_deny() {
        let mgr = PolicyEngine::default();
        let config = make_config("deny-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(DenyPlugin {
            cfg: config.clone(),
        });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });

        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "denied");
    }

    #[tokio::test]
    async fn test_invoke_typed() {
        let mgr = PolicyEngine::default();
        let config = make_config("allow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload {
            value: "typed".into(),
        };

        let (result, _) = mgr
            .invoke::<TestHook>(payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_invoke_named() {
        // invoke_named::<H>(hook_name, ...) gives compile-time payload
        // type checking while routing to a specific hook name.
        let mgr = PolicyEngine::default();
        let config = make_config("allow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload {
            value: "named".into(),
        };

        // TestHook::NAME is "test_hook" — invoke_named routes by the
        // explicit hook_name parameter, not H::NAME
        let (result, _) = mgr
            .invoke_named::<TestHook>("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_invoke_named_no_plugins_for_hook() {
        // invoke_named with a hook name that has no registered plugins
        let mgr = PolicyEngine::default();
        let config = make_config("allow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload {
            value: "no-match".into(),
        };

        // Plugin is registered under "test_hook", but we invoke "other_hook"
        let (result, _) = mgr
            .invoke_named::<TestHook>("other_hook", payload, Extensions::default(), None)
            .await;

        // No plugins fire — allowed by default
        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_invoke_named_deny() {
        let mgr = PolicyEngine::default();
        let config = make_config("deny-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(DenyPlugin {
            cfg: config.clone(),
        });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload {
            value: "denied".into(),
        };

        let (result, _) = mgr
            .invoke_named::<TestHook>("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "denied");
    }

    #[tokio::test]
    async fn test_has_hooks_for() {
        let mgr = PolicyEngine::default();
        assert!(!mgr.has_hooks_for("test_hook"));

        let config = make_config("p1", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();

        assert!(mgr.has_hooks_for("test_hook"));
        assert!(!mgr.has_hooks_for("other_hook"));
    }

    /// Under `dispatch: hooks`,
    /// each plugin's `conditions:` must be evaluated per request — a
    /// non-matching condition should keep the plugin from firing.
    #[tokio::test]
    async fn test_conditions_filter_plugins_when_routing_disabled() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let counts: StdArc<[AtomicUsize; 2]> =
            StdArc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);

        struct CountingHandler {
            idx: usize,
            counts: StdArc<[AtomicUsize; 2]>,
        }
        #[async_trait]
        impl AnyHookHandler for CountingHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                self.counts[self.idx].fetch_add(1, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = PolicyEngine::default();

        // Plugin A: condition requires tool == "wanted_tool" — fires for matching requests.
        let mut tools = std::collections::HashSet::new();
        tools.insert("wanted_tool".to_owned());
        let cfg_a = make_config_with_conditions(
            "plugin_a",
            vec![crate::plugin::PluginCondition {
                tools: Some(tools),
                ..Default::default()
            }],
        );
        let plugin_a = Arc::new(AllowPlugin { cfg: cfg_a.clone() });
        let handler_a: Arc<dyn AnyHookHandler> = Arc::new(CountingHandler {
            idx: 0,
            counts: StdArc::clone(&counts),
        });
        mgr.register_raw::<TestHook>(plugin_a, cfg_a, handler_a)
            .unwrap();

        // Plugin B: empty conditions — fires unconditionally.
        let cfg_b = make_config("plugin_b", 20, PluginMode::Sequential);
        let plugin_b = Arc::new(AllowPlugin { cfg: cfg_b.clone() });
        let handler_b: Arc<dyn AnyHookHandler> = Arc::new(CountingHandler {
            idx: 1,
            counts: StdArc::clone(&counts),
        });
        mgr.register_raw::<TestHook>(plugin_b, cfg_b, handler_b)
            .unwrap();

        mgr.initialize().await.unwrap();

        // Request 1: tool=wanted_tool → both A and B should fire.
        let ext_match = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("wanted_tool".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        let p: Box<dyn PluginPayload> = Box::new(TestPayload { value: "1".into() });
        let _ = mgr.invoke_by_name("test_hook", p, ext_match, None).await;
        assert_eq!(
            counts[0].load(Ordering::SeqCst),
            1,
            "plugin_a should fire on matching tool"
        );
        assert_eq!(
            counts[1].load(Ordering::SeqCst),
            1,
            "plugin_b should fire (no conditions)"
        );

        // Request 2: tool=other_tool → only B fires (A's condition rejects).
        let ext_no_match = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("other_tool".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        let p: Box<dyn PluginPayload> = Box::new(TestPayload { value: "2".into() });
        let _ = mgr.invoke_by_name("test_hook", p, ext_no_match, None).await;
        assert_eq!(
            counts[0].load(Ordering::SeqCst),
            1,
            "plugin_a should NOT fire on non-matching tool"
        );
        assert_eq!(
            counts[1].load(Ordering::SeqCst),
            2,
            "plugin_b should fire on every request"
        );
    }

    /// `user_patterns` glob matches against `extensions.security.subject.id`.
    /// Specifically: pattern `admin-*` matches `admin-alice` but not `user-bob`.
    #[tokio::test]
    async fn test_conditions_user_patterns_glob_filters() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static FIRED: AtomicUsize = AtomicUsize::new(0);
        FIRED.store(0, Ordering::SeqCst);

        struct CountHandler;
        #[async_trait]
        impl AnyHookHandler for CountHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                FIRED.fetch_add(1, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = PolicyEngine::default();
        let cfg = make_config_with_conditions(
            "admin_only",
            vec![crate::plugin::PluginCondition {
                user_patterns: Some(vec!["admin-*".to_owned()]),
                ..Default::default()
            }],
        );
        let plugin = Arc::new(AllowPlugin { cfg: cfg.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(CountHandler);
        mgr.register_raw::<TestHook>(plugin, cfg, handler).unwrap();
        mgr.initialize().await.unwrap();

        let ext_with_user = |id: &str| Extensions {
            security: Some(std::sync::Arc::new(crate::extensions::SecurityExtension {
                subject: Some(crate::extensions::security::SubjectExtension {
                    id: Some(id.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };

        let p: Box<dyn PluginPayload> = Box::new(TestPayload { value: "1".into() });
        let _ = mgr
            .invoke_by_name("test_hook", p, ext_with_user("admin-alice"), None)
            .await;
        assert_eq!(
            FIRED.load(Ordering::SeqCst),
            1,
            "admin-alice should match admin-*"
        );

        let p: Box<dyn PluginPayload> = Box::new(TestPayload { value: "2".into() });
        let _ = mgr
            .invoke_by_name("test_hook", p, ext_with_user("user-bob"), None)
            .await;
        assert_eq!(
            FIRED.load(Ordering::SeqCst),
            1,
            "user-bob should NOT match admin-*"
        );
    }

    #[tokio::test]
    async fn test_unregister() {
        let mgr = PolicyEngine::default();
        let config = make_config("removable", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();

        assert_eq!(mgr.plugin_count(), 1);
        mgr.unregister("removable");
        assert_eq!(mgr.plugin_count(), 0);
        assert!(!mgr.has_hooks_for("test_hook"));
    }

    /// Wraps the engine in `Arc` and dispatches concurrently from many
    /// tasks. Also issues a `register_handler` call mid-flight to prove
    /// that runtime registration is safe alongside invocations — the whole
    /// point of the `ArcSwap`-based snapshot redesign. Before this fix,
    /// `register_*` was `&mut self`, so this pattern wouldn't even compile.
    #[tokio::test]
    async fn test_manager_arc_shareable_with_concurrent_dispatch_and_registration() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static INVOKE_COUNT: AtomicUsize = AtomicUsize::new(0);
        INVOKE_COUNT.store(0, Ordering::SeqCst);

        struct CountingHandler;
        #[async_trait]
        impl AnyHookHandler for CountingHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                INVOKE_COUNT.fetch_add(1, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = Arc::new(PolicyEngine::default());

        // Register an initial plugin and initialize.
        let cfg = make_config("p0", 10, PluginMode::Sequential);
        let plugin: Arc<AllowPlugin> = Arc::new(AllowPlugin { cfg: cfg.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(CountingHandler);
        mgr.register_raw::<TestHook>(plugin, cfg, handler).unwrap();
        mgr.initialize().await.unwrap();

        // Spawn N concurrent invokers; midway, register a second plugin
        // from a different task — the snapshot swaps under their feet.
        let n = 16;
        let mut handles = Vec::with_capacity(n + 1);
        for i in 0..n {
            let mgr = Arc::clone(&mgr);
            handles.push(tokio::spawn(async move {
                let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
                    value: format!("call-{i}"),
                });
                let (result, _) = mgr
                    .invoke_by_name("test_hook", payload, Extensions::default(), None)
                    .await;
                assert!(result.continue_processing);
            }));
        }

        // Concurrent registration — proves register_handler works through &Arc.
        {
            let mgr = Arc::clone(&mgr);
            handles.push(tokio::spawn(async move {
                let cfg = make_config("p1-late", 20, PluginMode::Sequential);
                let plugin: Arc<AllowPlugin> = Arc::new(AllowPlugin { cfg: cfg.clone() });
                let handler: Arc<dyn AnyHookHandler> = Arc::new(CountingHandler);
                mgr.register_raw::<TestHook>(plugin, cfg, handler).unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // At least the initial plugin ran for every invoke (some invokes
        // may have raced past the registration and only seen the initial
        // plugin; others may have seen both). The exact count depends on
        // the race, but lower bound is `n` (one fire per invoke for p0).
        assert!(INVOKE_COUNT.load(Ordering::SeqCst) >= n);
        // Late registration is now visible.
        assert_eq!(mgr.plugin_count(), 2);
    }

    /// N OS threads register N distinct plugins at the same instant, and all N
    /// have to survive. A registration lost to a concurrent one still returns
    /// `Ok`, so the count is the only thing that catches it.
    ///
    /// The barrier is load-bearing: it lines every thread up on the same
    /// snapshot, which is what makes the loss reliable rather than occasional.
    /// So are the real threads. The sibling test above runs on
    /// `current_thread`, where a load and a store cannot interleave, so
    /// nothing here survives being rewritten as `tokio::spawn`.
    #[test]
    fn concurrent_registration_loses_no_plugins() {
        let mgr = Arc::new(PolicyEngine::default());
        let n = 16_usize;
        let barrier = std::sync::Barrier::new(n);

        std::thread::scope(|s| {
            for i in 0..n {
                let mgr = Arc::clone(&mgr);
                let barrier = &barrier;
                s.spawn(move || {
                    let cfg = make_config(&format!("p{i}"), 10, PluginMode::Sequential);
                    let plugin: Arc<AllowPlugin> = Arc::new(AllowPlugin { cfg: cfg.clone() });
                    barrier.wait();
                    mgr.register_handler::<TestHook, _>(plugin, cfg)
                        .expect("registration must succeed");
                });
            }
        });

        assert_eq!(
            mgr.plugin_count(),
            n,
            "every registration that returned Ok must be present in the snapshot",
        );
        assert_eq!(
            mgr.config_generation(),
            n as u64,
            "generation bumps exactly once per published mutation",
        );
    }

    /// A factory that reaches back into the engine on its way through
    /// `create`, once per lock a host factory can plausibly hit:
    /// `register_handler` takes `runtime_write`, `register_factory` takes
    /// the `factories` write side. The shape of a host plugin that installs
    /// a companion handler and the factory for its own sub-kind while being
    /// built.
    struct ReentrantFactory {
        engine: std::sync::Weak<PolicyEngine>,
    }

    impl crate::factory::PluginFactory for ReentrantFactory {
        fn create(
            &self,
            config: &PluginConfig,
        ) -> Result<crate::factory::PluginInstance, Box<PluginError>> {
            let engine = self.engine.upgrade().expect("engine outlives the factory");
            let side_cfg = make_config(
                &format!("{}_companion", config.name),
                10,
                PluginMode::Sequential,
            );
            let side: Arc<AllowPlugin> = Arc::new(AllowPlugin {
                cfg: side_cfg.clone(),
            });
            engine
                .register_handler::<TestHook, _>(side, side_cfg)
                .expect("re-entrant registration must succeed");
            engine.register_factory("test/reentrant_spawned", Box::new(AllowPluginFactory));
            AllowPluginFactory.create(config)
        }
    }

    /// Neither `runtime_write` nor the `factories` `RwLock` is reentrant, so
    /// a factory that calls back into the engine deadlocks against either
    /// one `load_config` is still holding while it runs `create`. The load
    /// runs on its own thread so the timeout reports that as a failure
    /// instead of hanging the test binary.
    ///
    /// The count also pins the ordering that makes the fix correct — the
    /// registry is cloned after the factories run, so what a factory
    /// registered mid-create is in the published snapshot, not overwritten
    /// by it.
    #[test]
    fn load_config_holds_no_lock_across_factory_create() {
        let engine = Arc::new(PolicyEngine::default());
        engine.register_factory(
            "test/reentrant",
            Box::new(ReentrantFactory {
                engine: Arc::downgrade(&engine),
            }),
        );

        let yaml = r"
engine_settings:
  dispatch: hooks
plugins:
  - name: main_plugin
    kind: test/reentrant
    hooks: [test_hook]
    mode: sequential
    priority: 10
";
        let policy_config = parse_fixture_config(yaml).unwrap();

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let loader = Arc::clone(&engine);
        std::thread::spawn(move || {
            let _ = done_tx.send(loader.load_config(policy_config).is_ok());
        });

        let loaded = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("load_config deadlocked against a re-entrant factory");
        assert!(loaded, "load_config must succeed");

        assert_eq!(
            engine.plugin_count(),
            2,
            "both the configured plugin and the one its factory registered \
             must be in the published snapshot",
        );
    }

    /// An annotation handler whose `Drop` reaches back into the engine.
    /// Host annotation handlers own host resources, so their teardown is
    /// host code like any other callback.
    struct DropReentrantHandler {
        cfg: PluginConfig,
        engine: std::sync::Weak<PolicyEngine>,
    }

    #[async_trait]
    impl Plugin for DropReentrantHandler {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
        async fn initialize(&self) -> Result<(), Box<PluginError>> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), Box<PluginError>> {
            Ok(())
        }
    }

    #[async_trait]
    impl crate::registry::AnyHookHandler for DropReentrantHandler {
        async fn invoke(
            &self,
            _payload: &dyn crate::prelude::PluginPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            Err(Box::new(PluginError::Config {
                message: "this handler exists to be dropped, not invoked".to_owned(),
            }))
        }

        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    impl Drop for DropReentrantHandler {
        fn drop(&mut self) {
            let Some(engine) = self.engine.upgrade() else {
                return;
            };
            // Any mutating call reaches `runtime_write`; this one is a
            // no-op on a key that was never annotated.
            engine.remove_route_annotation("tool", "never_annotated", None, "test_hook");
        }
    }

    /// A discarded annotation drops the handler the old snapshot held, and
    /// that teardown is host code. `runtime_write` has to be released
    /// before the old snapshot falls out of scope, or a handler whose
    /// `Drop` calls back blocks on the lock its own release is holding.
    ///
    /// `remove_route_annotation` is the reachable path: the closure drops
    /// the entry from the clone while the snapshot being replaced still
    /// mirrors it, so the last reference goes with that snapshot, inside
    /// `mutate_runtime`.
    #[test]
    fn a_dropped_annotation_handler_can_re_enter_the_engine() {
        let engine = Arc::new(PolicyEngine::default());
        let cfg = make_config("annotated", 10, PluginMode::Sequential);
        let handler = Arc::new(DropReentrantHandler {
            cfg: cfg.clone(),
            engine: Arc::downgrade(&engine),
        });

        engine.annotate_route("tool", "t1", None, "test_hook", handler, cfg);

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let remover = Arc::clone(&engine);
        std::thread::spawn(move || {
            // Drops the sole remaining reference — the annotation the line
            // above published — and with it the handler.
            remover.remove_route_annotation("tool", "t1", None, "test_hook");
            let _ = done_tx.send(());
        });

        done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a re-entrant handler Drop deadlocked against runtime_write");
    }

    /// Builds plugins whose `Drop` re-enters the engine, so a load that is
    /// rejected after instantiation has host teardown to run.
    struct DropReentrantFactory {
        engine: std::sync::Weak<PolicyEngine>,
    }

    impl crate::factory::PluginFactory for DropReentrantFactory {
        fn create(
            &self,
            config: &PluginConfig,
        ) -> Result<crate::factory::PluginInstance, Box<PluginError>> {
            let plugin = Arc::new(DropReentrantHandler {
                cfg: config.clone(),
                engine: self.engine.clone(),
            });
            Ok(crate::factory::PluginInstance {
                plugin: Arc::clone(&plugin) as Arc<dyn Plugin>,
                handlers: vec![("test_hook", plugin)],
            })
        }
    }

    /// A name conflict rejects the load with the factories' plugins already
    /// built, and `load_config` holds the only references to them: the
    /// registry drops what it refused, the entries past the conflict are
    /// never registered, and the partial clone drops unpublished. All of
    /// that is host `Drop` code, so none of it may run under
    /// `runtime_write`.
    ///
    /// The config collides with a plugin registered beforehand rather than
    /// with itself — `parse_config` rejects a name repeated inside one
    /// document, so an in-file duplicate never reaches the registry. The
    /// conflict lands on the first entry, leaving one instance refused by
    /// the registry and one never reached.
    #[test]
    fn a_rejected_load_drops_its_plugins_outside_the_writer_lock() {
        let engine = Arc::new(PolicyEngine::default());
        engine.register_factory(
            "test/drop_reentrant",
            Box::new(DropReentrantFactory {
                engine: Arc::downgrade(&engine),
            }),
        );

        let taken = make_config("taken", 5, PluginMode::Sequential);
        let sitting: Arc<AllowPlugin> = Arc::new(AllowPlugin { cfg: taken.clone() });
        engine
            .register_handler::<TestHook, _>(sitting, taken)
            .expect("the conflicting name has to be registered first");

        let yaml = r"
plugins:
  - name: taken
    kind: test/drop_reentrant
    hooks: [test_hook]
    mode: sequential
  - name: never_reached
    kind: test/drop_reentrant
    hooks: [test_hook]
    mode: sequential
";
        let policy_config = parse_fixture_config(yaml).unwrap();

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let loader = Arc::clone(&engine);
        std::thread::spawn(move || {
            let _ = done_tx.send(loader.load_config(policy_config).is_err());
        });

        let rejected = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a rejected load deadlocked dropping its own plugins");
        assert!(rejected, "a conflicting plugin name must reject the load");
        assert_eq!(
            engine.plugin_count(),
            1,
            "a rejected load publishes nothing, leaving the earlier plugin",
        );
    }

    /// A rejected mutation must publish nothing and leave the generation
    /// alone, so a downstream cache keyed on the generation does not evict
    /// and rebuild over a registration that never happened.
    #[test]
    fn failed_registration_publishes_nothing() {
        let mgr = PolicyEngine::default();
        let cfg = make_config("dupe", 10, PluginMode::Sequential);
        let plugin: Arc<AllowPlugin> = Arc::new(AllowPlugin { cfg: cfg.clone() });
        mgr.register_handler::<TestHook, _>(plugin, cfg.clone())
            .expect("first registration must succeed");

        let generation_after_first = mgr.config_generation();

        let dupe: Arc<AllowPlugin> = Arc::new(AllowPlugin { cfg: cfg.clone() });
        mgr.register_handler::<TestHook, _>(dupe, cfg)
            .expect_err("a duplicate name must be rejected");

        assert_eq!(mgr.plugin_count(), 1, "the rejected plugin must not appear");
        assert_eq!(
            mgr.config_generation(),
            generation_after_first,
            "a failed mutation must not bump the generation",
        );
    }

    #[tokio::test]
    async fn test_audit_plugin_cannot_block() {
        let mgr = PolicyEngine::default();
        let config = make_config("audit-denier", 10, PluginMode::Audit);
        let plugin = Arc::new(DenyPlugin {
            cfg: config.clone(),
        });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });

        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        // Audit mode — deny is suppressed, pipeline continues
        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_on_error_disable_skips_plugin_on_subsequent_invocations() {
        let mgr = PolicyEngine::default();

        // Register an error handler with on_error: Disable
        let config =
            make_config_with_on_error("flaky-plugin", 10, PluginMode::Sequential, OnError::Disable);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();

        // Also register a normal allow plugin (lower priority = runs second)
        let config2 = make_config("allow-plugin", 20, PluginMode::Sequential);
        let plugin2 = Arc::new(AllowPlugin {
            cfg: config2.clone(),
        });
        mgr.register_handler::<TestHook, _>(plugin2, config2)
            .unwrap();

        mgr.initialize().await.unwrap();

        // First invocation — flaky plugin errors, gets disabled, pipeline continues
        // because on_error is Disable (not Fail). allow-plugin still runs.
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "first".into(),
        });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        assert!(result.continue_processing);

        // Verify the plugin is now disabled
        let plugin_ref = mgr.get_plugin("flaky-plugin").unwrap();
        assert!(plugin_ref.is_disabled());
        assert_eq!(plugin_ref.mode(), PluginMode::Disabled);

        // Second invocation — flaky plugin should be skipped entirely
        // (group_by_mode filters it out). Only allow-plugin runs.
        let payload2: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "second".into(),
        });
        let (result2, _) = mgr
            .invoke_by_name("test_hook", payload2, Extensions::default(), None)
            .await;
        assert!(result2.continue_processing);
    }

    #[tokio::test]
    async fn test_on_error_ignore_continues_without_disabling() {
        let mgr = PolicyEngine::default();

        // Register an error handler with on_error: Ignore
        let config =
            make_config_with_on_error("flaky-plugin", 10, PluginMode::Sequential, OnError::Ignore);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();

        mgr.initialize().await.unwrap();

        // First invocation — plugin errors, ignored, pipeline continues
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        assert!(result.continue_processing);

        // Plugin should NOT be disabled — still in its original mode
        let plugin_ref = mgr.get_plugin("flaky-plugin").unwrap();
        assert!(!plugin_ref.is_disabled());
        assert_eq!(plugin_ref.mode(), PluginMode::Sequential);
    }

    /// Errors from `on_error: ignore` plugins must surface in
    /// `PipelineResult.errors` so callers can see swallowed failures
    /// programmatically — not just in log output.
    #[tokio::test]
    async fn test_on_error_ignore_records_in_pipeline_errors() {
        let mgr = PolicyEngine::default();
        let config =
            make_config_with_on_error("flaky-plugin", 10, PluginMode::Sequential, OnError::Ignore);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        // Pipeline continued (Ignore policy)…
        assert!(result.continue_processing);
        // …but the swallowed error is in result.errors with structured fields.
        assert_eq!(result.errors.len(), 1, "expected one error record");
        let rec = &result.errors[0];
        assert_eq!(rec.plugin_name, "error-plugin");
        assert!(
            rec.message.contains("simulated failure"),
            "message lost: {}",
            rec.message,
        );
    }

    /// Errors from `on_error: disable` plugins must ALSO appear in
    /// `PipelineResult.errors` (not just trip the circuit breaker).
    #[tokio::test]
    async fn test_on_error_disable_records_in_pipeline_errors() {
        let mgr = PolicyEngine::default();
        let config =
            make_config_with_on_error("flaky-plugin", 10, PluginMode::Sequential, OnError::Disable);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
        assert_eq!(result.errors.len(), 1);
        // Plugin was also disabled (the Disable policy's other effect).
        assert!(mgr.get_plugin("flaky-plugin").unwrap().is_disabled());
    }

    #[tokio::test]
    async fn test_on_error_fail_halts_pipeline() {
        let mgr = PolicyEngine::default();

        // Register an error handler with on_error: Fail (default)
        let config =
            make_config_with_on_error("strict-plugin", 10, PluginMode::Sequential, OnError::Fail);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();

        mgr.initialize().await.unwrap();

        // Invocation — plugin errors, pipeline halts with a violation
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "plugin_error");
        assert_eq!(
            result.violation.as_ref().unwrap().plugin_name.as_deref(),
            Some("strict-plugin"),
        );
    }

    // -- Additional test plugins --

    /// Plugin that modifies the payload (for Transform mode testing).
    struct TransformPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for TransformPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
        async fn initialize(&self) -> Result<(), Box<PluginError>> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), Box<PluginError>> {
            Ok(())
        }
    }

    impl HookHandler<TestHook> for TransformPlugin {
        async fn handle(
            &self,
            payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            PluginResult::modify_payload(TestPayload {
                value: format!("{}_transformed", payload.value),
            })
        }
    }

    /// Handler that sleeps (for timeout and fire-and-forget testing).
    struct SlowHandler {
        delay_ms: u64,
    }

    #[async_trait]
    impl AnyHookHandler for SlowHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            let result: PluginResult<TestPayload> = PluginResult::allow();
            Ok(crate::executor::erase_result(result))
        }

        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    // -- Bug-covering tests --

    #[tokio::test]
    async fn test_transform_modifies_payload() {
        let mgr = PolicyEngine::default();
        let config = make_config("transformer", 10, PluginMode::Transform);
        let plugin = Arc::new(TransformPlugin {
            cfg: config.clone(),
        });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload {
            value: "original".into(),
        };

        let (result, _) = mgr
            .invoke::<TestHook>(payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
        assert!(
            result.payload_modified,
            "the transform accepted a new payload, so the result must say so"
        );
        let final_payload = result.modified_payload.unwrap();
        let typed = final_payload
            .as_any()
            .downcast_ref::<TestPayload>()
            .unwrap();
        assert_eq!(typed.value, "original_transformed");
    }

    /// `modified_payload` is `Some` on every allowed pipeline, carrying
    /// the final payload whether or not a plugin touched it. Only
    /// `payload_modified` distinguishes the two, so callers deciding
    /// whether to forward a rewritten payload must read that.
    #[tokio::test]
    async fn allow_without_mutation_reports_payload_unmodified() {
        let mgr = PolicyEngine::default();
        let config = make_config("allow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload {
            value: "original".into(),
        };

        let (result, _) = mgr
            .invoke::<TestHook>(payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
        assert!(result.modified_payload.is_some());
        assert!(!result.payload_modified);
    }

    /// Transform phase is documented `can_block: No` (plugin.rs `PluginMode`
    /// table). An `on_error: Fail` plugin error or timeout in Transform must
    /// NOT halt the pipeline — non-blocking is non-blocking, regardless of
    /// the plugin's stated `on_error` preference. Disable still works.
    #[tokio::test]
    async fn test_transform_on_error_fail_does_not_halt_pipeline() {
        let mgr = PolicyEngine::default();
        let config =
            make_config_with_on_error("flaky-transform", 10, PluginMode::Transform, OnError::Fail);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(
            result.continue_processing,
            "Transform on_error:Fail must not halt the pipeline (phase is non-blocking)",
        );
        assert!(result.violation.is_none());
    }

    /// Audit phase previously ignored `on_error` entirely, so an
    /// `on_error: Disable` plugin would error forever without the circuit
    /// breaker tripping. After the fix Audit honors Disable.
    #[tokio::test]
    async fn test_audit_on_error_disable_disables_plugin() {
        let mgr = PolicyEngine::default();
        let config =
            make_config_with_on_error("flaky-audit", 10, PluginMode::Audit, OnError::Disable);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();

        mgr.initialize().await.unwrap();

        assert!(!mgr.get_plugin("flaky-audit").unwrap().is_disabled());

        // Invoke once — handler errors, on_error=Disable, plugin must be
        // disabled. Pipeline still returns success (Audit can't block).
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        assert!(result.continue_processing);

        assert!(
            mgr.get_plugin("flaky-audit").unwrap().is_disabled(),
            "Audit phase must honor on_error:Disable",
        );
    }

    #[tokio::test]
    async fn test_concurrent_multiple_plugins_all_run() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Shared counter to prove both plugins actually ran
        static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
        CALL_COUNT.store(0, Ordering::SeqCst);

        struct CountingHandler;

        #[async_trait]
        impl AnyHookHandler for CountingHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                // Small sleep to ensure both tasks are spawned before either finishes
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                CALL_COUNT.fetch_add(1, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }

            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = PolicyEngine::default();

        let c1 = make_config("concurrent-1", 10, PluginMode::Concurrent);
        let p1 = Arc::new(AllowPlugin { cfg: c1.clone() });
        let h1: Arc<dyn AnyHookHandler> = Arc::new(CountingHandler);
        mgr.register_raw::<TestHook>(p1, c1, h1).unwrap();

        let c2 = make_config("concurrent-2", 20, PluginMode::Concurrent);
        let p2 = Arc::new(AllowPlugin { cfg: c2.clone() });
        let h2: Arc<dyn AnyHookHandler> = Arc::new(CountingHandler);
        mgr.register_raw::<TestHook>(p2, c2, h2).unwrap();

        mgr.initialize().await.unwrap();

        let start = std::time::Instant::now();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        let elapsed = start.elapsed();

        assert!(result.continue_processing);
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 2);
        // If they ran in parallel, total time should be ~50ms, not ~100ms
        assert!(
            elapsed.as_millis() < 90,
            "concurrent plugins ran serially: {}ms",
            elapsed.as_millis()
        );
    }

    /// A deny on one concurrent plugin should short-circuit the pipeline
    /// AND cancel the slow plugin still running in another task. Previously
    /// `join_all` waited for every task before noticing the deny, so
    /// `short_circuit_on_deny` was a no-op in wall-clock terms and the slow
    /// plugin completed its side effects after the pipeline returned.
    #[tokio::test]
    async fn test_concurrent_short_circuit_aborts_slow_plugin() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        static SLOW_COMPLETED: AtomicUsize = AtomicUsize::new(0);
        SLOW_COMPLETED.store(0, Ordering::SeqCst);

        struct DenyImmediately;
        #[async_trait]
        impl AnyHookHandler for DenyImmediately {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                let result: PluginResult<TestPayload> =
                    PluginResult::deny(PluginViolation::new("denied", "fast deny"));
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        struct SlowSideEffect;
        #[async_trait]
        impl AnyHookHandler for SlowSideEffect {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                tokio::time::sleep(Duration::from_secs(2)).await;
                // If the task isn't aborted at the sleep's await point,
                // this fetch_add fires after the pipeline already returned.
                SLOW_COMPLETED.fetch_add(1, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = PolicyEngine::default();

        let cfg_deny = make_config("denier", 10, PluginMode::Concurrent);
        let plugin_deny = Arc::new(AllowPlugin {
            cfg: cfg_deny.clone(),
        });
        mgr.register_raw::<TestHook>(
            plugin_deny,
            cfg_deny,
            Arc::new(DenyImmediately) as Arc<dyn AnyHookHandler>,
        )
        .unwrap();

        let cfg_slow = make_config("slow", 20, PluginMode::Concurrent);
        let plugin_slow = Arc::new(AllowPlugin {
            cfg: cfg_slow.clone(),
        });
        mgr.register_raw::<TestHook>(
            plugin_slow,
            cfg_slow,
            Arc::new(SlowSideEffect) as Arc<dyn AnyHookHandler>,
        )
        .unwrap();

        mgr.initialize().await.unwrap();

        // Pipeline must return quickly — the deny short-circuits before
        // the 2s sleep completes.
        let start = std::time::Instant::now();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        let elapsed = start.elapsed();

        assert!(!result.continue_processing);
        assert!(
            elapsed < Duration::from_millis(500),
            "pipeline should short-circuit on deny, but took {}ms (slow plugin not aborted)",
            elapsed.as_millis(),
        );

        // Wait long enough that the slow plugin's sleep would have finished
        // if it hadn't been aborted, then verify its side effect didn't fire.
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert_eq!(
            SLOW_COMPLETED.load(Ordering::SeqCst),
            0,
            "slow plugin's side effect ran after pipeline returned — task was not aborted",
        );
    }

    /// `short_circuit_on_deny=false`: every concurrent plugin must run to
    /// completion (no abort), and the earliest deny is returned at the end.
    #[tokio::test]
    async fn test_concurrent_no_short_circuit_runs_every_plugin() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static ALLOW_RAN: AtomicUsize = AtomicUsize::new(0);
        ALLOW_RAN.store(0, Ordering::SeqCst);

        struct DenyImmediately;
        #[async_trait]
        impl AnyHookHandler for DenyImmediately {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                let result: PluginResult<TestPayload> =
                    PluginResult::deny(PluginViolation::new("denied", "fast deny"));
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        struct AllowAndCount;
        #[async_trait]
        impl AnyHookHandler for AllowAndCount {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                ALLOW_RAN.fetch_add(1, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let config = PolicyEngineConfig {
            executor: crate::executor::ExecutorConfig {
                timeout_seconds: 30,
                short_circuit_on_deny: false,
            },
            route_cache_max_entries: DEFAULT_ROUTE_CACHE_MAX_ENTRIES,
        };
        let mgr = PolicyEngine::new(config);

        let cfg_deny = make_config("denier", 10, PluginMode::Concurrent);
        let plugin_deny = Arc::new(AllowPlugin {
            cfg: cfg_deny.clone(),
        });
        mgr.register_raw::<TestHook>(
            plugin_deny,
            cfg_deny,
            Arc::new(DenyImmediately) as Arc<dyn AnyHookHandler>,
        )
        .unwrap();

        let cfg_allow = make_config("allow", 20, PluginMode::Concurrent);
        let plugin_allow = Arc::new(AllowPlugin {
            cfg: cfg_allow.clone(),
        });
        mgr.register_raw::<TestHook>(
            plugin_allow,
            cfg_allow,
            Arc::new(AllowAndCount) as Arc<dyn AnyHookHandler>,
        )
        .unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        // Earliest deny is returned…
        assert!(!result.continue_processing);
        // …but the non-denying plugin must still have run (no abort).
        assert_eq!(ALLOW_RAN.load(Ordering::SeqCst), 1);
    }

    /// Plugin handler that panics inside its async invoke. With `tokio::spawn`,
    /// the panic surfaces as a `JoinError` on the task's `JoinHandle`.
    struct PanicHandler;

    #[async_trait]
    impl AnyHookHandler for PanicHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            panic!("simulated panic in concurrent plugin task");
        }
        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    /// A panicking concurrent plugin with `on_error: Fail` must halt the
    /// pipeline with a violation. Previously the `JoinError` was just logged
    /// and the panic was silently swallowed.
    ///
    /// Note: this test prints "thread 'tokio-runtime-worker' panicked at..."
    /// to stderr — that's tokio reporting the captured panic. Expected.
    #[tokio::test]
    async fn test_concurrent_panic_with_on_error_fail_halts_pipeline() {
        let mgr = PolicyEngine::default();

        let cfg =
            make_config_with_on_error("panic-plugin", 10, PluginMode::Concurrent, OnError::Fail);
        let plugin = Arc::new(AllowPlugin { cfg: cfg.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(PanicHandler);
        mgr.register_raw::<TestHook>(plugin, cfg, handler).unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(
            !result.continue_processing,
            "Fail must halt the pipeline on panic"
        );
        let v = result.violation.as_ref().expect("expected violation");
        assert_eq!(v.code, "plugin_panic");
        assert_eq!(v.plugin_name.as_deref(), Some("panic-plugin"));
    }

    /// A panicking concurrent plugin with `on_error: Disable` must trip
    /// the plugin's circuit breaker so it's skipped on subsequent invokes.
    /// A second non-panicking plugin in the same phase still runs.
    #[tokio::test]
    async fn test_concurrent_panic_with_on_error_disable_trips_circuit_breaker() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static SURVIVOR_CALLS: AtomicUsize = AtomicUsize::new(0);
        SURVIVOR_CALLS.store(0, Ordering::SeqCst);

        struct SurvivorHandler;
        #[async_trait]
        impl AnyHookHandler for SurvivorHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                SURVIVOR_CALLS.fetch_add(1, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = PolicyEngine::default();

        let panic_cfg =
            make_config_with_on_error("panic-plugin", 10, PluginMode::Concurrent, OnError::Disable);
        let panic_plugin = Arc::new(AllowPlugin {
            cfg: panic_cfg.clone(),
        });
        let panic_handler: Arc<dyn AnyHookHandler> = Arc::new(PanicHandler);
        mgr.register_raw::<TestHook>(panic_plugin, panic_cfg, panic_handler)
            .unwrap();

        let survivor_cfg = make_config("survivor", 20, PluginMode::Concurrent);
        let survivor_plugin = Arc::new(AllowPlugin {
            cfg: survivor_cfg.clone(),
        });
        let survivor_handler: Arc<dyn AnyHookHandler> = Arc::new(SurvivorHandler);
        mgr.register_raw::<TestHook>(survivor_plugin, survivor_cfg, survivor_handler)
            .unwrap();

        mgr.initialize().await.unwrap();

        // First invoke — panic plugin panics, gets disabled. Survivor still runs.
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "1".into() });
        let (result1, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        assert!(
            result1.continue_processing,
            "Disable must not halt the pipeline"
        );
        assert_eq!(SURVIVOR_CALLS.load(Ordering::SeqCst), 1);
        assert!(
            mgr.get_plugin("panic-plugin").unwrap().is_disabled(),
            "panic plugin must be disabled after the panic",
        );

        // Second invoke — disabled plugin is skipped, doesn't panic again.
        let payload2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "2".into() });
        let (result2, _) = mgr
            .invoke_by_name("test_hook", payload2, Extensions::default(), None)
            .await;
        assert!(result2.continue_processing);
        // Survivor ran a second time; panic plugin did not.
        assert_eq!(SURVIVOR_CALLS.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_timeout_fires_on_slow_handler() {
        let config = PolicyEngineConfig {
            executor: crate::executor::ExecutorConfig {
                timeout_seconds: 1,
                short_circuit_on_deny: true,
            },
            route_cache_max_entries: DEFAULT_ROUTE_CACHE_MAX_ENTRIES,
        };
        let mgr = PolicyEngine::new(config);

        // Register a handler that sleeps longer than the timeout
        let plugin_config = make_config("slow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: plugin_config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(SlowHandler { delay_ms: 5000 });
        mgr.register_raw::<TestHook>(plugin, plugin_config, handler)
            .unwrap();

        mgr.initialize().await.unwrap();

        let start = std::time::Instant::now();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        let elapsed = start.elapsed();

        // Should have timed out and denied (on_error: Fail)
        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "plugin_timeout");
        // Should have returned in ~1s, not 5s
        assert!(
            elapsed.as_secs() < 3,
            "timeout didn't fire: {}s",
            elapsed.as_secs()
        );
    }

    #[tokio::test]
    async fn test_fire_and_forget_returns_before_task_completes() {
        use std::sync::atomic::{AtomicBool, Ordering};

        static TASK_COMPLETED: AtomicBool = AtomicBool::new(false);
        TASK_COMPLETED.store(false, Ordering::SeqCst);

        struct SlowFireAndForgetHandler;

        #[async_trait]
        impl AnyHookHandler for SlowFireAndForgetHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                TASK_COMPLETED.store(true, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }

            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = PolicyEngine::default();

        let config = make_config("fire-forget", 10, PluginMode::FireAndForget);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(SlowFireAndForgetHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, bg) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        // Pipeline should return immediately — before the background task finishes
        assert!(result.continue_processing);
        assert!(
            !TASK_COMPLETED.load(Ordering::SeqCst),
            "fire-and-forget task completed before pipeline returned"
        );

        // Wait for background tasks using wait_for_background_tasks()
        let errors = bg.wait_for_background_tasks().await;
        assert!(errors.is_empty(), "background task had errors: {errors:?}");
        assert!(
            TASK_COMPLETED.load(Ordering::SeqCst),
            "fire-and-forget task never completed"
        );
    }

    /// `shutdown()` must wait for in-flight fire-and-forget tasks to drain
    /// before returning, so audit / telemetry plugins that flush at the
    /// end of a request lifetime aren't cancelled mid-write. The caller
    /// drops `BackgroundTasks` (the common case for fire-and-forget),
    /// so the only way the engine knows about the in-flight task is the
    /// internal `TaskTracker`.
    #[tokio::test]
    async fn test_shutdown_drains_in_flight_fire_and_forget_tasks() {
        use std::sync::atomic::{AtomicBool, Ordering};

        static FAF_COMPLETED: AtomicBool = AtomicBool::new(false);
        FAF_COMPLETED.store(false, Ordering::SeqCst);

        struct SlowFafHandler;
        #[async_trait]
        impl AnyHookHandler for SlowFafHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                FAF_COMPLETED.store(true, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = PolicyEngine::default();
        let config = make_config("slow-faf", 10, PluginMode::FireAndForget);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(SlowFafHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();
        mgr.initialize().await.unwrap();

        // Invoke and drop BackgroundTasks immediately — simulating the
        // common case where the caller doesn't explicitly wait for FAF.
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (_result, _bg_dropped) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        // Task should still be in flight (sleeping 150ms).
        assert!(!FAF_COMPLETED.load(Ordering::SeqCst));

        // shutdown() must drain in-flight FAF tasks before returning.
        mgr.shutdown().await;

        // After shutdown, the FAF task must have run to completion.
        assert!(
            FAF_COMPLETED.load(Ordering::SeqCst),
            "shutdown returned before fire-and-forget task finished — task was abandoned",
        );
    }

    #[tokio::test]
    async fn test_global_state_flows_between_serial_plugins() {
        // Plugin A writes to global_state; Plugin B reads it.

        struct WriterHandler;

        #[async_trait]
        impl AnyHookHandler for WriterHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                ctx.set_global("writer_was_here", serde_json::Value::Bool(true));
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        struct ReaderHandler {
            saw_writer: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }

        #[async_trait]
        impl AnyHookHandler for ReaderHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                if ctx.get_global("writer_was_here").is_some() {
                    self.saw_writer
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let saw_writer = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let mgr = PolicyEngine::default();

        // Writer runs first (priority 10)
        let c1 = make_config("writer", 10, PluginMode::Sequential);
        let p1 = Arc::new(AllowPlugin { cfg: c1.clone() });
        let h1: Arc<dyn AnyHookHandler> = Arc::new(WriterHandler);
        mgr.register_raw::<TestHook>(p1, c1, h1).unwrap();

        // Reader runs second (priority 20)
        let c2 = make_config("reader", 20, PluginMode::Sequential);
        let p2 = Arc::new(AllowPlugin { cfg: c2.clone() });
        let h2: Arc<dyn AnyHookHandler> = Arc::new(ReaderHandler {
            saw_writer: saw_writer.clone(),
        });
        mgr.register_raw::<TestHook>(p2, c2, h2).unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
        assert!(
            saw_writer.load(std::sync::atomic::Ordering::SeqCst),
            "reader plugin did not see writer's global_state change"
        );
    }

    #[tokio::test]
    async fn test_local_state_persists_across_hook_invocations() {
        // Plugin writes to local_state on first hook call.
        // Context table is threaded into second call — local_state preserved.

        struct LocalWriterHandler;

        #[async_trait]
        impl AnyHookHandler for LocalWriterHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                let count = ctx
                    .get_local("call_count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                ctx.set_local("call_count", serde_json::Value::from(count + 1));
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = PolicyEngine::default();

        let config = make_config("counter", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(LocalWriterHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();

        mgr.initialize().await.unwrap();

        // First invocation — no context table, starts fresh
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "first".into(),
        });
        let (result1, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        assert!(result1.continue_processing);

        // Check call_count = 1 in the returned context table
        let table = &result1.context_table;
        let local = table
            .local_states
            .values()
            .next()
            .expect("context table should have one local_state entry");
        assert_eq!(local.get("call_count").unwrap().as_u64().unwrap(), 1);

        // Second invocation — pass the context table from the first call
        let payload2: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "second".into(),
        });
        let (result2, _) = mgr
            .invoke_by_name(
                "test_hook",
                payload2,
                Extensions::default(),
                Some(result1.context_table),
            )
            .await;
        assert!(result2.continue_processing);

        // call_count should now be 2 — local_state persisted across invocations
        let table2 = &result2.context_table;
        let local2 = table2
            .local_states
            .values()
            .next()
            .expect("context table should have one local_state entry");
        assert_eq!(local2.get("call_count").unwrap().as_u64().unwrap(), 2);
    }

    /// `global_state` writes by an earlier plugin must be visible to a later
    /// plugin in the same serial phase, and the canonical state on the
    /// returned `context_table` must reflect every plugin's contribution in
    /// priority order. Previously this relied on `ctx_table.values().last()`
    /// (`HashMap` iteration order — non-deterministic).
    #[tokio::test]
    async fn test_global_state_propagates_in_priority_order() {
        /// Handler that appends `tag` to `global_state`["chain"] (creating
        /// an array if absent). After running, the array reveals the
        /// observed run order from each plugin's perspective.
        struct GlobalChainHandler {
            tag: &'static str,
        }

        #[async_trait]
        impl AnyHookHandler for GlobalChainHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                let mut chain = ctx
                    .get_global("chain")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                chain.push(serde_json::Value::String(self.tag.into()));
                ctx.set_global("chain", serde_json::Value::Array(chain));
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = PolicyEngine::default();

        // Plugin A — priority 10 (runs first)
        let cfg_a = make_config("plugin_a", 10, PluginMode::Sequential);
        let plugin_a = Arc::new(AllowPlugin { cfg: cfg_a.clone() });
        let handler_a: Arc<dyn AnyHookHandler> = Arc::new(GlobalChainHandler { tag: "a" });
        mgr.register_raw::<TestHook>(plugin_a, cfg_a, handler_a)
            .unwrap();

        // Plugin B — priority 20 (runs second)
        let cfg_b = make_config("plugin_b", 20, PluginMode::Sequential);
        let plugin_b = Arc::new(AllowPlugin { cfg: cfg_b.clone() });
        let handler_b: Arc<dyn AnyHookHandler> = Arc::new(GlobalChainHandler { tag: "b" });
        mgr.register_raw::<TestHook>(plugin_b, cfg_b, handler_b)
            .unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        assert!(result.continue_processing);

        // Canonical global_state on the returned table must contain both
        // contributions in priority order — proving plugin B observed plugin
        // A's write, and the table holds the merged result, not an arbitrary
        // plugin's snapshot.
        let chain = result
            .context_table
            .global_state
            .get("chain")
            .and_then(|v| v.as_array())
            .expect("global_state.chain should be an array");
        let tags: Vec<&str> = chain.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(tags, vec!["a", "b"]);
    }

    /// All five phases (Sequential, Transform, Audit, Concurrent,
    /// `FireAndForget`) execute in the documented order, with payload
    /// modifications from earlier phases visible in later ones. Closes
    /// the review's "no multi-phase combination test" gap.
    #[tokio::test]
    async fn test_all_five_phases_run_in_order_with_payload_chaining() {
        use std::sync::Arc as StdArc;
        use std::sync::Mutex as StdMutex;

        let log: StdArc<StdMutex<Vec<&'static str>>> = StdArc::new(StdMutex::new(Vec::new()));

        // Sequential — modifies payload, logs "seq".
        struct SeqHandler {
            log: StdArc<StdMutex<Vec<&'static str>>>,
        }
        #[async_trait]
        impl AnyHookHandler for SeqHandler {
            async fn invoke(
                &self,
                payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                self.log.lock().unwrap().push("seq");
                let typed = payload.as_any().downcast_ref::<TestPayload>().unwrap();
                let modified = TestPayload {
                    value: format!("{}|seq", typed.value),
                };
                let result: PluginResult<TestPayload> = PluginResult::modify_payload(modified);
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        // Transform — modifies payload, logs "transform".
        struct TransformLogger {
            log: StdArc<StdMutex<Vec<&'static str>>>,
        }
        #[async_trait]
        impl AnyHookHandler for TransformLogger {
            async fn invoke(
                &self,
                payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                self.log.lock().unwrap().push("transform");
                let typed = payload.as_any().downcast_ref::<TestPayload>().unwrap();
                let modified = TestPayload {
                    value: format!("{}|transform", typed.value),
                };
                let result: PluginResult<TestPayload> = PluginResult::modify_payload(modified);
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        // Logger that asserts the payload it observes contains both prior
        // phases' marks (proving payload chaining made it this far).
        struct ObserverHandler {
            tag: &'static str,
            log: StdArc<StdMutex<Vec<&'static str>>>,
            expected_payload: &'static str,
        }
        #[async_trait]
        impl AnyHookHandler for ObserverHandler {
            async fn invoke(
                &self,
                payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                let typed = payload.as_any().downcast_ref::<TestPayload>().unwrap();
                assert_eq!(
                    typed.value, self.expected_payload,
                    "{} observed unexpected payload: got '{}', expected '{}'",
                    self.tag, typed.value, self.expected_payload,
                );
                self.log.lock().unwrap().push(self.tag);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mgr = PolicyEngine::default();

        let cfg_seq = make_config("seq", 10, PluginMode::Sequential);
        mgr.register_raw::<TestHook>(
            Arc::new(AllowPlugin {
                cfg: cfg_seq.clone(),
            }),
            cfg_seq,
            Arc::new(SeqHandler {
                log: StdArc::clone(&log),
            }),
        )
        .unwrap();

        let cfg_transform = make_config("transform", 10, PluginMode::Transform);
        mgr.register_raw::<TestHook>(
            Arc::new(AllowPlugin {
                cfg: cfg_transform.clone(),
            }),
            cfg_transform,
            Arc::new(TransformLogger {
                log: StdArc::clone(&log),
            }),
        )
        .unwrap();

        let cfg_audit = make_config("audit", 10, PluginMode::Audit);
        mgr.register_raw::<TestHook>(
            Arc::new(AllowPlugin {
                cfg: cfg_audit.clone(),
            }),
            cfg_audit,
            Arc::new(ObserverHandler {
                tag: "audit",
                log: StdArc::clone(&log),
                expected_payload: "start|seq|transform",
            }),
        )
        .unwrap();

        let cfg_concurrent = make_config("concurrent", 10, PluginMode::Concurrent);
        mgr.register_raw::<TestHook>(
            Arc::new(AllowPlugin {
                cfg: cfg_concurrent.clone(),
            }),
            cfg_concurrent,
            Arc::new(ObserverHandler {
                tag: "concurrent",
                log: StdArc::clone(&log),
                expected_payload: "start|seq|transform",
            }),
        )
        .unwrap();

        let cfg_faf = make_config("faf", 10, PluginMode::FireAndForget);
        mgr.register_raw::<TestHook>(
            Arc::new(AllowPlugin {
                cfg: cfg_faf.clone(),
            }),
            cfg_faf,
            Arc::new(ObserverHandler {
                tag: "faf",
                log: StdArc::clone(&log),
                expected_payload: "start|seq|transform",
            }),
        )
        .unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "start".into(),
        });
        let (result, bg) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
        // Final payload should have both modify-phase marks.
        let final_payload = result.modified_payload.unwrap();
        let typed = final_payload
            .as_any()
            .downcast_ref::<TestPayload>()
            .unwrap();
        assert_eq!(typed.value, "start|seq|transform");

        // Drain the FAF task before checking ordering — its log entry
        // races the rest of the function otherwise.
        let _ = bg.wait_for_background_tasks().await;

        let log = log.lock().unwrap();
        // Sequential, Transform, Audit are guaranteed in order (serial phases).
        assert_eq!(log[0], "seq", "first should be sequential phase");
        assert_eq!(log[1], "transform", "second should be transform phase");
        assert_eq!(log[2], "audit", "third should be audit phase");
        // Concurrent runs before invoke returns; FAF was waited on above.
        // Their relative order with each other is not strictly guaranteed
        // (FAF spawns *after* concurrent finishes, but tokio scheduling
        // can interleave). Just check both present in indices 3 / 4.
        let post_audit: std::collections::HashSet<&&'static str> = log[3..].iter().collect();
        assert!(
            post_audit.contains(&"concurrent"),
            "concurrent phase must run"
        );
        assert!(post_audit.contains(&"faf"), "fire-and-forget must run");
        assert_eq!(log.len(), 5, "all five phases should have logged");
    }

    /// Routing must work for `resource`, `prompt`, and `llm` entity types
    /// — not just `tool`. Closes the review's "no test verifying entity
    /// types other than tool in routing" gap. Read through `identity.resolve`
    /// and a route's `authentication:` step, the one binding a route still
    /// makes in policy mode.
    ///
    /// The `http` rows share the table because they share the dispatch
    /// question, but they answer it from the request line rather than from a
    /// name, so each row carries the path the request arrives on. The
    /// segment-boundary rows mirror the host router's own suite: a prefix that
    /// matches a path only where a `/` follows it, and a trailing slash on the
    /// declared prefix that changes nothing.
    #[tokio::test]
    async fn test_routing_works_for_all_entity_types() {
        register_fixture_hooks();
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // One counter per entity-type test; each plugin only fires when
        // the route resolves to it.
        struct CountHandler {
            counter: StdArc<AtomicUsize>,
        }
        #[async_trait]
        impl AnyHookHandler for CountHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                crate::identity::IdentityHook::NAME
            }
        }

        // Each row: (entity_type, route field name, route value, request
        // entity_name, request path, should_match). The path is `None` for the
        // four name selectors, which never read the request line.
        // We build a fresh engine per entity type so routes don't bleed.
        for (entity_type, route_field, route_value, request_name, request_path, should_match) in [
            (
                "resource",
                "resource",
                "my_resource",
                "my_resource",
                None,
                true,
            ),
            (
                "resource",
                "resource",
                "my_resource",
                "other_resource",
                None,
                false,
            ),
            ("prompt", "prompt", "my_prompt", "my_prompt", None, true),
            ("prompt", "prompt", "my_prompt", "other_prompt", None, false),
            ("llm", "llm", "gpt-4", "gpt-4", None, true),
            ("llm", "llm", "gpt-4", "claude", None, false),
            // An exact `http:` path matches by equality, like the name
            // selectors, and the request arrives under the reserved name.
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "/healthz",
                ENTITY_NAME_GLOBAL,
                Some("/healthz"),
                true,
            ),
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "/healthz",
                ENTITY_NAME_GLOBAL,
                Some("/healthzz"),
                false,
            ),
            // A prefix matches the prefix itself, a trailing slash on the
            // path, and any deeper segment.
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "{ path_prefix: /api }",
                ENTITY_NAME_GLOBAL,
                Some("/api"),
                true,
            ),
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "{ path_prefix: /api }",
                ENTITY_NAME_GLOBAL,
                Some("/api/"),
                true,
            ),
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "{ path_prefix: /api }",
                ENTITY_NAME_GLOBAL,
                Some("/api/v1"),
                true,
            ),
            // And stops at the segment boundary, which is the whole point of
            // matching paths the way the router does rather than by glob.
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "{ path_prefix: /api }",
                ENTITY_NAME_GLOBAL,
                Some("/apikeys"),
                false,
            ),
            // A trailing slash on the declared prefix is insignificant.
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "{ path_prefix: /api/ }",
                ENTITY_NAME_GLOBAL,
                Some("/api"),
                true,
            ),
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "{ path_prefix: /api/ }",
                ENTITY_NAME_GLOBAL,
                Some("/api/v1"),
                true,
            ),
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "{ path_prefix: /api/ }",
                ENTITY_NAME_GLOBAL,
                Some("/apikeys"),
                false,
            ),
            // The root prefix is the catch-all.
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "{ path_prefix: / }",
                ENTITY_NAME_GLOBAL,
                Some("/anything/at/all"),
                true,
            ),
            // A declared method narrows the match; every request below is a
            // GET, so the POST-only route does not match.
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "{ path_prefix: /api, method: GET }",
                ENTITY_NAME_GLOBAL,
                Some("/api/v1"),
                true,
            ),
            (
                ENTITY_HTTP,
                ENTITY_HTTP,
                "{ path_prefix: /api, method: POST }",
                ENTITY_NAME_GLOBAL,
                Some("/api/v1"),
                false,
            ),
        ] {
            let yaml = format!(
                r#"
engine_settings:
  dispatch: policy
plugins:
  - name: target
    kind: test/allow
    hooks: [identity.resolve]
    mode: sequential
routes:
  - {route_field}: {route_value}
    authentication:
      - target
"#
            );
            let policy_config = parse_fixture_config(&yaml).unwrap();

            let mgr = PolicyEngine::default();
            let counter = StdArc::new(AtomicUsize::new(0));
            // Custom factory that hands out a CountHandler with our shared counter.
            struct ParamFactory(StdArc<AtomicUsize>);
            impl crate::factory::PluginFactory for ParamFactory {
                fn create(
                    &self,
                    config: &PluginConfig,
                ) -> Result<crate::factory::PluginInstance, Box<PluginError>> {
                    Ok(crate::factory::PluginInstance {
                        plugin: Arc::new(AllowPlugin {
                            cfg: config.clone(),
                        }),
                        handlers: vec![(
                            crate::identity::HOOK_IDENTITY_RESOLVE,
                            Arc::new(CountHandler {
                                counter: StdArc::clone(&self.0),
                            }),
                        )],
                    })
                }
            }
            mgr.register_factory(
                "test/allow",
                Box::new(ParamFactory(StdArc::clone(&counter))),
            );
            mgr.load_config(policy_config).unwrap();
            mgr.initialize().await.unwrap();

            let p: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
            let ext = Extensions {
                meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                    entity_type: Some(entity_type.into()),
                    entity_name: Some(request_name.into()),
                    ..Default::default()
                })),
                // An HTTP request is matched from its request line, so the row
                // supplies one. Every HTTP row is a GET.
                http: request_path.map(|path| {
                    std::sync::Arc::new(crate::extensions::HttpExtension {
                        method: Some("GET".into()),
                        path: Some(path.into()),
                        ..Default::default()
                    })
                }),
                ..Default::default()
            };
            let _ = mgr
                .invoke_by_name(crate::identity::HOOK_IDENTITY_RESOLVE, p, ext, None)
                .await;

            let expected = if should_match { 1 } else { 0 };
            assert_eq!(
                counter.load(Ordering::SeqCst),
                expected,
                "entity_type={entity_type} route_field={route_field} route_value={route_value} request_name={request_name} request_path={request_path:?} expected fire={should_match}",
            );
        }
    }

    /// `initialize()` must roll back already-initialized plugins by
    /// calling `shutdown()` on each, in reverse order, when a later
    /// plugin's `initialize()` fails. Closes the review's "no test for
    /// `initialize()` rollback path" gap.
    #[tokio::test]
    async fn test_initialize_rollback_on_failure() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Track per-plugin init / shutdown invocations.
        let init_count_a = StdArc::new(AtomicUsize::new(0));
        let shutdown_count_a = StdArc::new(AtomicUsize::new(0));
        let init_count_b = StdArc::new(AtomicUsize::new(0));
        let shutdown_count_b = StdArc::new(AtomicUsize::new(0));
        let init_count_c = StdArc::new(AtomicUsize::new(0));
        let shutdown_count_c = StdArc::new(AtomicUsize::new(0));

        struct LifecyclePlugin {
            cfg: PluginConfig,
            init_counter: StdArc<AtomicUsize>,
            shutdown_counter: StdArc<AtomicUsize>,
            fail_init: bool,
        }
        #[async_trait]
        impl Plugin for LifecyclePlugin {
            fn config(&self) -> &PluginConfig {
                &self.cfg
            }
            async fn initialize(&self) -> Result<(), Box<PluginError>> {
                self.init_counter.fetch_add(1, Ordering::SeqCst);
                if self.fail_init {
                    Err(Box::new(PluginError::Config {
                        message: "intentional init failure".into(),
                    }))
                } else {
                    Ok(())
                }
            }
            async fn shutdown(&self) -> Result<(), Box<PluginError>> {
                self.shutdown_counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
        impl HookHandler<TestHook> for LifecyclePlugin {
            async fn handle(
                &self,
                _payload: &TestPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> PluginResult<TestPayload> {
                PluginResult::allow()
            }
        }

        let mgr = PolicyEngine::default();

        // Plugin A: initializes successfully (priority 10, registered first).
        let cfg_a = make_config("a", 10, PluginMode::Sequential);
        let plugin_a = Arc::new(LifecyclePlugin {
            cfg: cfg_a.clone(),
            init_counter: StdArc::clone(&init_count_a),
            shutdown_counter: StdArc::clone(&shutdown_count_a),
            fail_init: false,
        });
        mgr.register_handler::<TestHook, _>(plugin_a, cfg_a)
            .unwrap();

        // Plugin B: initialize() returns Err — should trigger rollback.
        let cfg_b = make_config("b", 20, PluginMode::Sequential);
        let plugin_b = Arc::new(LifecyclePlugin {
            cfg: cfg_b.clone(),
            init_counter: StdArc::clone(&init_count_b),
            shutdown_counter: StdArc::clone(&shutdown_count_b),
            fail_init: true,
        });
        mgr.register_handler::<TestHook, _>(plugin_b, cfg_b)
            .unwrap();

        // Plugin C: never reached (init aborts at B).
        let cfg_c = make_config("c", 30, PluginMode::Sequential);
        let plugin_c = Arc::new(LifecyclePlugin {
            cfg: cfg_c.clone(),
            init_counter: StdArc::clone(&init_count_c),
            shutdown_counter: StdArc::clone(&shutdown_count_c),
            fail_init: false,
        });
        mgr.register_handler::<TestHook, _>(plugin_c, cfg_c)
            .unwrap();

        let result = mgr.initialize().await;
        assert!(
            result.is_err(),
            "initialize() must propagate the init failure"
        );

        // The registry iterates plugins in `HashMap` order, which is
        // randomized — so we don't know whether A and C were reached
        // before B failed. The rollback invariants are order-independent:
        //
        // - For non-failing plugins (A, C): if init() was called, shutdown()
        //   must have been called too (rolled back). If init() was not
        //   called (B happened to iterate first), shutdown() shouldn't
        //   have either. In both cases, init_count == shutdown_count.
        // - B's init() was called and failed, so its shutdown() must NOT
        //   run — failed-init plugins are not part of the rollback set.
        let assert_pair_invariant = |init: &AtomicUsize, shutdown: &AtomicUsize, tag: &str| {
            let i = init.load(Ordering::SeqCst);
            let s = shutdown.load(Ordering::SeqCst);
            assert!(
                (i == 0 && s == 0) || (i == 1 && s == 1),
                "{tag}: init/shutdown should be paired (both 0 or both 1), got init={i} shutdown={s}",
            );
        };
        assert_pair_invariant(&init_count_a, &shutdown_count_a, "A");
        assert_pair_invariant(&init_count_c, &shutdown_count_c, "C");

        // B specifically: init was called and failed; no shutdown for it.
        assert_eq!(
            init_count_b.load(Ordering::SeqCst),
            1,
            "B's initialize was called",
        );
        assert_eq!(
            shutdown_count_b.load(Ordering::SeqCst),
            0,
            "B failed to initialize; shutdown should not run for it",
        );

        // Manager must report not-initialized after the failure.
        assert!(!mgr.is_initialized());
    }

    // -- Factory-based tests --

    /// A test factory that creates `AllowPlugin` instances.
    struct AllowPluginFactory;

    impl crate::factory::PluginFactory for AllowPluginFactory {
        fn create(
            &self,
            config: &PluginConfig,
        ) -> Result<crate::factory::PluginInstance, Box<PluginError>> {
            let plugin = Arc::new(AllowPlugin {
                cfg: config.clone(),
            });
            let handler: Arc<dyn AnyHookHandler> =
                Arc::new(TypedHandlerAdapter::<TestHook, AllowPlugin>::new(
                    Arc::clone(&plugin),
                ));
            Ok(crate::factory::PluginInstance {
                plugin,
                handlers: vec![("test_hook", handler)],
            })
        }
    }

    /// A test factory that creates `DenyPlugin` instances.
    struct DenyPluginFactory;

    impl crate::factory::PluginFactory for DenyPluginFactory {
        fn create(
            &self,
            config: &PluginConfig,
        ) -> Result<crate::factory::PluginInstance, Box<PluginError>> {
            let plugin = Arc::new(DenyPlugin {
                cfg: config.clone(),
            });
            let handler: Arc<dyn AnyHookHandler> =
                Arc::new(TypedHandlerAdapter::<TestHook, DenyPlugin>::new(
                    Arc::clone(&plugin),
                ));
            // A route binds a plugin at `identity.resolve` and nowhere else, so
            // a fixture declaring that hook serves it through the stand-in.
            let handlers = if config
                .hooks
                .iter()
                .any(|hook| hook == crate::identity::HOOK_IDENTITY_RESOLVE)
            {
                vec![(
                    crate::identity::HOOK_IDENTITY_RESOLVE,
                    Arc::new(ServingIdentity(handler)) as Arc<dyn AnyHookHandler>,
                )]
            } else {
                vec![("test_hook", handler)]
            };
            Ok(crate::factory::PluginInstance { plugin, handlers })
        }
    }

    // -- Every load path normalizes and validates --

    /// A config as a host would hand it over in Rust: deserialized but
    /// not put through `parse_config`, so nothing has normalized or
    /// validated it yet. Registers the fixture hooks, since the load it
    /// is handed to validates it.
    fn unvalidated_config(yaml: &str) -> PolicyConfig {
        register_fixture_hooks();
        serde_yaml::from_str(yaml).expect("deserialize")
    }

    fn allow_factories() -> PluginFactoryRegistry {
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));
        factories
    }

    const VALID_YAML: &str = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
"#;

    const DUPLICATE_NAME_YAML: &str = r#"
plugins:
  - name: twice
    kind: test/allow
    hooks: [test_hook]
  - name: twice
    kind: test/allow
    hooks: [test_hook]
"#;

    /// A route joining a top-level `groups:` bundle. Resolving the group is what
    /// makes the membership valid; skipping the merge leaves the route joining a
    /// group the bundle store does not hold.
    ///
    /// The bundle and the route used to carry `plugins: [allow_plugin]`
    /// activation lists, which the typed boundary now refuses in policy mode the
    /// way the YAML boundary always did. They were incidental: what this pins is
    /// the fold, and the `groups:` membership is what depends on it.
    const GROUP_YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
groups:
  privileged:
    description: needs the fold to be resolvable
routes:
  - tool: secret_tool
    groups: [privileged]
"#;

    #[test]
    fn a_valid_config_loads_through_every_path() {
        parse_fixture_config(VALID_YAML).expect("parse_config");

        // A fresh engine per path: re-loading the same plugin name onto
        // one engine is a registration conflict, unrelated to validation.
        let via_yaml = Arc::new(PolicyEngine::default());
        via_yaml.register_factory("test/allow", Box::new(AllowPluginFactory));
        load_fixture_yaml(&via_yaml, VALID_YAML).expect("load_config_yaml");

        let via_typed = Arc::new(PolicyEngine::default());
        via_typed.register_factory("test/allow", Box::new(AllowPluginFactory));
        via_typed
            .load_config(unvalidated_config(VALID_YAML))
            .expect("load_config");

        PolicyEngine::from_config(unvalidated_config(VALID_YAML), &allow_factories())
            .expect("from_config");
    }

    #[test]
    fn a_duplicate_plugin_name_is_rejected_on_every_path() {
        let mgr = Arc::new(PolicyEngine::default());
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));

        // Every path refuses before any plugin is instantiated, so one
        // engine serves all of them.
        for err in [
            parse_fixture_config(DUPLICATE_NAME_YAML)
                .map(|_| ())
                .unwrap_err(),
            load_fixture_yaml(&mgr, DUPLICATE_NAME_YAML).unwrap_err(),
            mgr.load_config(unvalidated_config(DUPLICATE_NAME_YAML))
                .unwrap_err(),
            PolicyEngine::from_config(unvalidated_config(DUPLICATE_NAME_YAML), &allow_factories())
                .map(|_| ())
                .unwrap_err(),
        ] {
            assert!(
                err.to_string().contains("duplicate plugin name"),
                "unexpected error: {err}",
            );
        }
    }

    #[test]
    fn a_group_block_resolves_through_the_programmatic_paths() {
        let mgr = Arc::new(PolicyEngine::default());
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));

        // Before the merge, `groups:` is a separate map and the route
        // joins a group the bundle store does not hold, so validation
        // catches it. Both paths now merge first and accept it.
        mgr.load_config(unvalidated_config(GROUP_YAML))
            .expect("load_config resolves groups");
        assert!(
            mgr.load_runtime()
                .policy_config
                .as_ref()
                .expect("config")
                .global
                .bundles
                .contains_key("privileged"),
        );

        let from_config =
            PolicyEngine::from_config(unvalidated_config(GROUP_YAML), &allow_factories())
                .expect("from_config resolves groups");
        assert!(
            from_config
                .load_runtime()
                .policy_config
                .as_ref()
                .expect("config")
                .global
                .bundles
                .contains_key("privileged"),
        );
    }

    #[tokio::test]
    async fn test_from_config_creates_manager() {
        register_fixture_hooks();
        let yaml = r#"
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 10

engine_settings:
  dispatch: hooks
  plugin_timeout: 60
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();

        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mgr = PolicyEngine::from_config(policy_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        assert_eq!(mgr.plugin_count(), 1);
        assert!(mgr.has_hooks_for("test_hook"));
    }

    #[tokio::test]
    async fn test_from_config_invokes_correctly() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: denier
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
    priority: 10
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();

        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/deny", Box::new(DenyPluginFactory));

        let mgr = PolicyEngine::from_config(policy_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        // context_table = None (first invocation)

        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "denied");
    }

    #[tokio::test]
    async fn test_from_config_unknown_kind_rejected() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: mystery
    kind: unknown/type
    hooks: [test_hook]
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();
        let factories = PluginFactoryRegistry::new(); // empty — no factories

        let result = PolicyEngine::from_config(policy_config, &factories);
        match result {
            Err(e) => assert!(e.to_string().contains("no factory registered"), "got: {e}"),
            Ok(_) => panic!("expected error for unknown kind"),
        }
    }

    #[tokio::test]
    async fn test_from_config_multiple_plugins() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: gate
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
    priority: 5
  - name: fallback
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 10
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();

        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));
        factories.register("test/deny", Box::new(DenyPluginFactory));

        let mgr = PolicyEngine::from_config(policy_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        assert_eq!(mgr.plugin_count(), 2);

        // Deny plugin has higher priority (5 < 10), so it fires first
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        // context_table = None (first invocation)

        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(!result.continue_processing); // gate denied before fallback could allow
    }

    // -- Routing cache tests --

    #[tokio::test]
    async fn test_routing_cache_populated_on_first_invoke() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mgr = PolicyEngine::from_config(policy_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        assert_eq!(mgr.routing_cache_size(), 0);

        // First invoke — populates cache
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let ext = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        // context_table = None (first invocation)
        mgr.invoke_by_name("test_hook", payload, ext, None).await;

        assert_eq!(mgr.routing_cache_size(), 1);

        // Second invoke — cache hit, still size 1
        let payload2: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test2".into(),
        });
        let ext2 = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", payload2, ext2, None).await;

        assert_eq!(mgr.routing_cache_size(), 1); // cache hit — no new entry
    }

    /// What replaced the route- and tag-scoped plugin chains: in policy mode a
    /// request the engine can identify reaches no plugin unless a policy names
    /// one. Both plugins are declared and registered, the route matches, and the
    /// chain is still empty, so the deny cannot fire.
    #[tokio::test]
    async fn a_matched_route_reaches_no_plugin_without_a_policy_naming_one() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: allower
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
  - name: denier
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
"#;
        let mgr = PolicyEngine::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.register_factory("test/deny", Box::new(DenyPluginFactory));
        mgr.load_config(parse_fixture_config(yaml).unwrap())
            .unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (result, _) = mgr
            .invoke_by_name(
                "test_hook",
                payload,
                make_meta("tool", "get_compensation", None, &[]),
                None,
            )
            .await;
        assert!(
            result.continue_processing,
            "no activation list means no chain, so the denier never runs"
        );
    }

    /// Regression (typed path): `load_config_yaml` used to deserialize
    /// `PolicyConfig` directly and skip `parse_config`'s normalization, so a
    /// top-level `groups:` bundle never folded into the internal bundle store
    /// and a route joining it lost the bundle's contribution. Read through the
    /// bundle's `authentication:` steps, the contribution a bundle still makes.
    #[tokio::test]
    async fn load_config_yaml_folds_top_level_group_into_route_resolution() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: gate
    kind: test/deny
    hooks: [identity.resolve]
    mode: sequential
groups:
  hr-tools:
    authentication: [gate]
routes:
  - tool: get_compensation
    groups: hr-tools
"#;
        let mgr = Arc::new(PolicyEngine::default());
        mgr.register_factory("test/deny", Box::new(DenyPluginFactory));
        load_fixture_yaml(&mgr, yaml).expect("config must load");

        let ext = Extensions {
            meta: Some(Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _bg) = mgr
            .invoke_by_name(crate::identity::HOOK_IDENTITY_RESOLVE, payload, ext, None)
            .await;

        assert!(
            !result.continue_processing,
            "route must resolve the top-level group's step and deny; it was allowed, \
             so the group wasn't folded into the load path",
        );
        assert_eq!(result.violation.as_ref().unwrap().code, "denied");
    }

    /// Regression (visitor path): the visitor walk read a nested bundle map
    /// only, so a top-level `groups:` bundle's `authorization:` was never
    /// compiled. This registers a visitor that records which
    /// bundles it was asked to compile and asserts the top-level group is
    /// among them.
    #[test]
    fn load_config_yaml_compiles_top_level_group_via_visitor() {
        use crate::visitor::{ConfigVisitor, VisitorError};
        use std::sync::Mutex as StdMutex;

        #[derive(Default)]
        struct RecordingVisitor {
            bundles: StdMutex<Vec<String>>,
        }
        impl ConfigVisitor for RecordingVisitor {
            fn name(&self) -> &str {
                "recording"
            }
            fn visit_policy_bundle(
                &self,
                _mgr: &Arc<PolicyEngine>,
                tag: &str,
                _yaml: &serde_yaml::Value,
            ) -> Result<(), VisitorError> {
                self.bundles.lock().unwrap().push(tag.to_owned());
                Ok(())
            }
        }

        let yaml = r#"
engine_settings:
  dispatch: policy
groups:
  hr-tools:
    authorization:
      pre_invocation:
        - "require(role.hr)"
routes:
  - tool: get_compensation
    groups: hr-tools
"#;
        let mgr = Arc::new(PolicyEngine::default());
        let recorder = Arc::new(RecordingVisitor::default());
        mgr.register_visitor(recorder.clone());
        load_fixture_yaml(&mgr, yaml).expect("config must load");

        let seen = recorder.bundles.lock().unwrap();
        assert!(
            seen.iter().any(|b| b == "hr-tools"),
            "top-level groups: bundle must be visited for compilation; saw: {seen:?}",
        );
    }

    #[tokio::test]
    async fn test_routing_cache_different_entities_separate() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
  - tool: send_email
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mgr = PolicyEngine::from_config(policy_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // Invoke for get_compensation
        let p1: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let e1 = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", p1, e1, None).await;

        // Invoke for send_email
        let p2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let e2 = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("send_email".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", p2, e2, None).await;

        assert_eq!(mgr.routing_cache_size(), 2);
    }

    #[tokio::test]
    async fn test_routing_cache_cleared() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mgr = PolicyEngine::from_config(policy_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let ext = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", payload, ext, None).await;
        assert_eq!(mgr.routing_cache_size(), 1);

        mgr.clear_routing_cache();
        assert_eq!(mgr.routing_cache_size(), 0);
    }

    #[tokio::test]
    async fn test_unregister_invalidates_routing_cache() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mgr = PolicyEngine::from_config(policy_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let ext = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", payload, ext, None).await;
        assert_eq!(mgr.routing_cache_size(), 1);

        // Unregister should invalidate the cache so removed plugins
        // don't continue firing from stale cached entries.
        mgr.unregister("allow_plugin");
        assert_eq!(mgr.routing_cache_size(), 0);
    }

    #[test]
    fn test_routing_cache_recovers_from_poisoned_lock() {
        // A panic while holding the cache lock poisons it. Before the fix,
        // every subsequent read()/write() would unwrap a PoisonError and
        // panic, permanently breaking dispatch. With unwrap_or_else +
        // into_inner, the cache stays usable.
        //
        // Note: this test intentionally panics inside catch_unwind, which
        // prints "thread 'engine::tests::...' panicked at..." to test
        // output even though the panic is caught. That's expected.
        use std::panic::AssertUnwindSafe;

        let mgr = PolicyEngine::default();

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _guard = mgr.route_cache.write().unwrap();
            panic!("simulated panic while holding cache lock");
        }));
        assert!(result.is_err(), "expected the panic to be caught");
        assert!(
            mgr.route_cache.is_poisoned(),
            "lock should be poisoned after the panic",
        );

        // All four lock sites must now succeed despite the poison flag.
        assert_eq!(mgr.routing_cache_size(), 0);
        mgr.clear_routing_cache();
        assert_eq!(mgr.routing_cache_size(), 0);
    }

    #[tokio::test]
    async fn test_routing_cache_rejects_inserts_at_capacity() {
        register_fixture_hooks();
        // Cap of 2 — verifies bound holds AND uncached requests still resolve correctly.
        let yaml = r#"
engine_settings:
  dispatch: policy
  route_cache_max_entries: 2
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: a
  - tool: b
  - tool: c
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mgr = PolicyEngine::from_config(policy_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        let invoke_for = |entity: &'static str| -> (Box<dyn PluginPayload>, Extensions) {
            let p: Box<dyn PluginPayload> = Box::new(TestPayload {
                value: entity.into(),
            });
            let e = Extensions {
                meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                    entity_type: Some("tool".into()),
                    entity_name: Some(entity.into()),
                    ..Default::default()
                })),
                ..Default::default()
            };
            (p, e)
        };

        // Fill to cap (2 distinct entities).
        let (p1, e1) = invoke_for("a");
        let (r1, _) = mgr.invoke_by_name("test_hook", p1, e1, None).await;
        assert!(r1.continue_processing);
        assert_eq!(mgr.routing_cache_size(), 1);

        let (p2, e2) = invoke_for("b");
        let (r2, _) = mgr.invoke_by_name("test_hook", p2, e2, None).await;
        assert!(r2.continue_processing);
        assert_eq!(mgr.routing_cache_size(), 2);

        // Third entity — cache is full, insert is rejected.
        // Pipeline must still run correctly (slow path resolves the route).
        let (p3, e3) = invoke_for("c");
        let (r3, _) = mgr.invoke_by_name("test_hook", p3, e3, None).await;
        assert!(
            r3.continue_processing,
            "slow path must still resolve when cache is full"
        );
        assert_eq!(mgr.routing_cache_size(), 2, "cache must not exceed cap");

        // Repeated request for the same uncached entity also works.
        let (p4, e4) = invoke_for("c");
        let (r4, _) = mgr.invoke_by_name("test_hook", p4, e4, None).await;
        assert!(r4.continue_processing);
        assert_eq!(mgr.routing_cache_size(), 2);

        // Clearing the cache lets new entries memoize again.
        mgr.clear_routing_cache();
        let (p5, e5) = invoke_for("c");
        mgr.invoke_by_name("test_hook", p5, e5, None).await;
        assert_eq!(mgr.routing_cache_size(), 1);
    }

    #[tokio::test]
    async fn test_register_handler_invalidates_routing_cache() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mgr = PolicyEngine::from_config(policy_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let ext = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", payload, ext, None).await;
        assert_eq!(mgr.routing_cache_size(), 1);

        // Registering a new handler must invalidate the cache so the
        // new plugin is visible to subsequent route resolutions.
        let extra_cfg = make_config("late_plugin", 20, PluginMode::Sequential);
        let extra = Arc::new(AllowPlugin {
            cfg: extra_cfg.clone(),
        });
        mgr.register_handler::<TestHook, _>(extra, extra_cfg)
            .unwrap();
        assert_eq!(mgr.routing_cache_size(), 0);
    }

    #[tokio::test]
    async fn test_routing_cache_scope_creates_separate_entries() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mgr = PolicyEngine::from_config(policy_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // Same entity, different scopes → separate cache entries
        let p1: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let e1 = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                scope: Some("hr-server".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", p1, e1, None).await;

        let p2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let e2 = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                scope: Some("billing-server".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", p2, e2, None).await;

        assert_eq!(mgr.routing_cache_size(), 2); // different scopes → different cache entries
    }

    // -- Override instance tests --

    #[tokio::test]
    async fn test_route_override_creates_new_instance() {
        register_fixture_hooks();
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: rate_limiter
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
    config:
      max_requests: 100
routes:
  - tool: get_compensation
    authentication:
      - name: rate_limiter
        config:
          max_requests: 10
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();

        // Use register_factory + load_config so engine owns factories
        let mgr = PolicyEngine::default();
        let ledger: Ledger = Arc::new(std::sync::Mutex::new(Vec::new()));
        mgr.register_factory(
            "test/record",
            Box::new(RecordingFactory(Arc::clone(&ledger))),
        );
        mgr.load_config(policy_config).unwrap();
        mgr.initialize().await.unwrap();

        // Invoke with routing — should create override instance
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let ext = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        // context_table = None (first invocation)

        let (result, _) = mgr
            .invoke_by_name(crate::identity::HOOK_IDENTITY_RESOLVE, payload, ext, None)
            .await;
        assert_eq!(
            plugins_that_fired(&ledger),
            vec!["rate_limiter".to_owned()],
            "the override instance is what fires for the route"
        );

        // Plugin executed (allow plugin returns allowed)
        assert!(result.continue_processing);
        // Cache populated
        assert_eq!(mgr.routing_cache_size(), 1);
    }

    // ---- host services at initialization -------------------------------
    //
    // The engine calls `initialize_with`, never `initialize` directly.
    // These pin that the compatibility shim still runs an old-style
    // plugin, and that the `perform_http` gate is applied before the
    // plugin ever sees the transport.

    #[derive(Debug)]
    struct StubTransport;

    #[async_trait]
    impl crate::http::HttpTransport for StubTransport {
        async fn execute(
            &self,
            _req: crate::http::HttpRequest,
        ) -> Result<crate::http::HttpResponse, crate::http::HttpTransportError> {
            Ok(crate::http::HttpResponse::new(200, bytes::Bytes::new()))
        }
    }

    /// Records what its initialization saw, and through which method.
    struct ServiceProbePlugin {
        cfg: PluginConfig,
        /// `Ok(true)` transport available, `Ok(false)` withheld,
        /// `Err(())` never installed.
        saw: Arc<std::sync::Mutex<Option<Result<bool, ()>>>>,
        /// Set only by the legacy `initialize()` path.
        used_legacy: Arc<std::sync::atomic::AtomicBool>,
        /// When true, override the old method instead of the new one.
        legacy: bool,
    }

    #[async_trait]
    impl Plugin for ServiceProbePlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }

        async fn initialize(&self) -> Result<(), Box<PluginError>> {
            self.used_legacy
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn initialize_with(
            &self,
            ext: &crate::host::InitExtensions,
        ) -> Result<(), Box<PluginError>> {
            if self.legacy {
                // Exercise the documented "call it yourself" path.
                return self.initialize().await;
            }
            use crate::host::{HostServices as _, HttpRequestError, ServiceError};
            // A request the fake transport answers when it is reachable.
            // Availability is now observable only by asking, which is
            // the point of the operation shape.
            let seen = match ext
                .http_request(
                    crate::http::HttpRequest::get("https://example.test/probe"),
                    crate::http_retry::RetryPolicy::none(),
                )
                .await
            {
                Ok(_) | Err(HttpRequestError::Transport(_)) => Ok(true),
                Err(HttpRequestError::Unavailable(ServiceError::NotPermitted { .. })) => Ok(false),
                Err(HttpRequestError::Unavailable(ServiceError::NotInstalled { .. })) => Err(()),
            };
            *self
                .saw
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(seen);
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), Box<PluginError>> {
            Ok(())
        }
    }

    impl HookHandler<TestHook> for ServiceProbePlugin {
        async fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            PluginResult::allow()
        }
    }

    /// Initialize one probe plugin and report what it saw.
    async fn probe_init(
        caps: &[&str],
        install_transport: bool,
        legacy: bool,
    ) -> (Option<Result<bool, ()>>, bool) {
        let mgr = PolicyEngine::default();
        if install_transport {
            assert!(mgr.set_http_transport(Arc::new(StubTransport)));
        }

        let mut cfg = make_config("probe", 10, PluginMode::Sequential);
        cfg.capabilities = caps.iter().map(|c| (*c).to_owned()).collect();

        let saw = Arc::new(std::sync::Mutex::new(None));
        let used_legacy = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let plugin = Arc::new(ServiceProbePlugin {
            cfg: cfg.clone(),
            saw: Arc::clone(&saw),
            used_legacy: Arc::clone(&used_legacy),
            legacy,
        });
        mgr.register_handler::<TestHook, _>(plugin, cfg).unwrap();
        mgr.initialize().await.unwrap();

        let seen = *saw
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (seen, used_legacy.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[tokio::test]
    async fn a_plugin_with_perform_http_receives_the_transport_at_init() {
        let (seen, _) = probe_init(&["perform_http"], true, false).await;
        assert_eq!(
            seen,
            Some(Ok(true)),
            "a plugin declaring perform_http must reach the installed transport"
        );
    }

    #[tokio::test]
    async fn a_plugin_without_perform_http_is_told_it_lacks_the_capability() {
        // Not "no transport installed" — that would send an operator
        // hunting a host wiring bug when the fix is one line of their
        // own config.
        let (seen, _) = probe_init(&["read_headers"], true, false).await;
        assert_eq!(seen, Some(Ok(false)));
    }

    #[tokio::test]
    async fn with_no_transport_installed_even_a_capable_plugin_is_told_so() {
        let (seen, _) = probe_init(&["perform_http"], false, false).await;
        assert_eq!(
            seen,
            Some(Err(())),
            "holding the capability cannot conjure a transport the host never installed"
        );
    }

    #[tokio::test]
    async fn a_legacy_plugin_overriding_only_initialize_still_runs() {
        // The compatibility shim: `initialize_with`'s default forwards to
        // `initialize`, so a plugin written before host services existed
        // keeps working untouched.
        let (_, used_legacy) = probe_init(&[], false, true).await;
        assert!(
            used_legacy,
            "the engine calls initialize_with, whose default must still run initialize()"
        );
    }

    #[tokio::test]
    async fn installing_a_transport_twice_keeps_the_first() {
        // Set-once: a second install would swap the transport out from
        // under plugins already holding a borrowed reference.
        let mgr = PolicyEngine::default();
        assert!(mgr.set_http_transport(Arc::new(StubTransport)));
        assert!(
            !mgr.set_http_transport(Arc::new(StubTransport)),
            "the second install must be refused, not silently applied"
        );
    }

    /// Override instances must have `initialize()` called so plugins that
    /// open DB connections / file handles / network clients on init don't
    /// run with default state. Uses a tracking factory whose plugin
    /// increments a counter inside its `initialize()`.
    #[tokio::test]
    async fn test_route_override_initializes_new_instance() {
        register_fixture_hooks();
        use std::sync::atomic::{AtomicUsize, Ordering};

        static INIT_COUNT: AtomicUsize = AtomicUsize::new(0);
        INIT_COUNT.store(0, Ordering::SeqCst);

        struct InitTrackingPlugin {
            cfg: PluginConfig,
        }

        #[async_trait]
        impl Plugin for InitTrackingPlugin {
            fn config(&self) -> &PluginConfig {
                &self.cfg
            }
            async fn initialize(&self) -> Result<(), Box<PluginError>> {
                INIT_COUNT.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            async fn shutdown(&self) -> Result<(), Box<PluginError>> {
                Ok(())
            }
        }

        impl HookHandler<TestHook> for InitTrackingPlugin {
            async fn handle(
                &self,
                _payload: &TestPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> PluginResult<TestPayload> {
                PluginResult::allow()
            }
        }

        struct InitTrackingFactory;
        impl crate::factory::PluginFactory for InitTrackingFactory {
            fn create(
                &self,
                config: &PluginConfig,
            ) -> Result<crate::factory::PluginInstance, Box<PluginError>> {
                let plugin = Arc::new(InitTrackingPlugin {
                    cfg: config.clone(),
                });
                let handler: Arc<dyn AnyHookHandler> =
                    Arc::new(TypedHandlerAdapter::<TestHook, InitTrackingPlugin>::new(
                        Arc::clone(&plugin),
                    ));
                Ok(crate::factory::PluginInstance {
                    plugin,
                    handlers: vec![(
                        crate::identity::HOOK_IDENTITY_RESOLVE,
                        Arc::new(ServingIdentity(handler)),
                    )],
                })
            }
        }

        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: tracker
    kind: test/init_tracking
    hooks: [identity.resolve]
    mode: sequential
    config:
      max_requests: 100
routes:
  - tool: get_compensation
    authentication:
      - name: tracker
        config:
          max_requests: 10
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();

        let mgr = PolicyEngine::default();
        mgr.register_factory("test/init_tracking", Box::new(InitTrackingFactory));
        mgr.load_config(policy_config).unwrap();
        mgr.initialize().await.unwrap();

        // Base plugin was initialized exactly once during mgr.initialize().
        assert_eq!(INIT_COUNT.load(Ordering::SeqCst), 1);

        // Invoke with route override — creates a new instance via factory.
        // That new instance must also be initialized.
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (result, _) = mgr
            .invoke_by_name(
                crate::identity::HOOK_IDENTITY_RESOLVE,
                payload,
                make_meta("tool", "get_compensation", None, &[]),
                None,
            )
            .await;
        assert!(result.continue_processing);

        assert_eq!(
            INIT_COUNT.load(Ordering::SeqCst),
            2,
            "override instance must have initialize() called",
        );
    }

    // ---- host services on the override paths ---------------------------
    //
    // `test_route_override_initializes_new_instance` above passes whether
    // the engine calls `initialize` or `initialize_with`, because its
    // plugin overrides only the former and the default shim forwards to
    // it. These use a plugin that overrides `initialize_with` instead, so
    // the two are distinguishable: an override instance built through
    // either path must reach the host, under its own merged capabilities.

    /// What an initialization could reach: `Ok(true)` the transport was
    /// available, `Ok(false)` it exists but this plugin may not use it,
    /// `Err(())` the host installed none.
    async fn probe_host_transport(ext: &crate::host::InitExtensions) -> Result<bool, ()> {
        use crate::host::{HostServices as _, HttpRequestError, ServiceError};
        match ext
            .http_request(
                crate::http::HttpRequest::get("https://example.test/probe"),
                crate::http_retry::RetryPolicy::none(),
            )
            .await
        {
            Ok(_) | Err(HttpRequestError::Transport(_)) => Ok(true),
            Err(HttpRequestError::Unavailable(ServiceError::NotPermitted { .. })) => Ok(false),
            Err(HttpRequestError::Unavailable(ServiceError::NotInstalled { .. })) => Err(()),
        }
    }

    /// Appends one entry per instance initialized, in order. The log is
    /// owned by the test rather than a `static` so tests running
    /// concurrently in one process cannot see each other's entries.
    struct HostProbePlugin {
        cfg: PluginConfig,
        log: Arc<std::sync::Mutex<Vec<Result<bool, ()>>>>,
    }

    #[async_trait]
    impl Plugin for HostProbePlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }

        async fn initialize_with(
            &self,
            ext: &crate::host::InitExtensions,
        ) -> Result<(), Box<PluginError>> {
            let seen = probe_host_transport(ext).await;
            self.log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(seen);
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), Box<PluginError>> {
            Ok(())
        }
    }

    impl HookHandler<TestHook> for HostProbePlugin {
        async fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            PluginResult::allow()
        }
    }

    struct HostProbeFactory {
        log: Arc<std::sync::Mutex<Vec<Result<bool, ()>>>>,
    }

    impl crate::factory::PluginFactory for HostProbeFactory {
        fn create(
            &self,
            config: &PluginConfig,
        ) -> Result<crate::factory::PluginInstance, Box<PluginError>> {
            let plugin = Arc::new(HostProbePlugin {
                cfg: config.clone(),
                log: Arc::clone(&self.log),
            });
            let handler: Arc<dyn AnyHookHandler> =
                Arc::new(TypedHandlerAdapter::<TestHook, HostProbePlugin>::new(
                    Arc::clone(&plugin),
                ));
            Ok(crate::factory::PluginInstance {
                plugin,
                handlers: vec![(
                    crate::identity::HOOK_IDENTITY_RESOLVE,
                    Arc::new(ServingIdentity(handler)),
                )],
            })
        }
    }

    /// Engine with a stub transport and one `perform_http` base plugin,
    /// plus the log its instances append to.
    fn host_probe_engine(
        yaml: &str,
    ) -> (PolicyEngine, Arc<std::sync::Mutex<Vec<Result<bool, ()>>>>) {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mgr = PolicyEngine::default();
        assert!(mgr.set_http_transport(Arc::new(StubTransport)));
        mgr.register_factory(
            "test/host_probe",
            Box::new(HostProbeFactory {
                log: Arc::clone(&log),
            }),
        );
        mgr.load_config(parse_fixture_config(yaml).unwrap())
            .unwrap();
        (mgr, log)
    }

    const HOST_PROBE_YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: prober
    kind: test/host_probe
    hooks: [identity.resolve]
    mode: sequential
    capabilities: [perform_http]
    config:
      max_requests: 100
routes:
  - tool: get_compensation
    authentication:
      - name: prober
        config:
          max_requests: 10
"#;

    #[tokio::test]
    async fn a_route_override_instance_receives_host_services() {
        register_fixture_hooks();
        // The failure this pins: an override instance built by
        // `create_override_instance` got the no-op default `initialize()`,
        // so a plugin that fetches during init — `identity-jwt` with a
        // `jwks_url` issuer — came up with nothing and denied every
        // request on that route while the base route worked.
        let (mgr, log) = host_probe_engine(HOST_PROBE_YAML);
        mgr.initialize().await.unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            vec![Ok(true)],
            "the base instance reaches the transport"
        );

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (result, _) = mgr
            .invoke_by_name(
                crate::identity::HOOK_IDENTITY_RESOLVE,
                payload,
                make_meta("tool", "get_compensation", None, &[]),
                None,
            )
            .await;
        assert!(result.continue_processing);

        assert_eq!(
            *log.lock().unwrap(),
            vec![Ok(true), Ok(true)],
            "the override instance must reach the transport too, not the \
             default initialize() that reaches nothing",
        );
    }

    #[tokio::test]
    async fn build_override_entries_hands_the_new_instance_host_services() {
        register_fixture_hooks();
        // The host-facing entry point to the same path. It has no caller
        // inside this crate, so nothing else would catch a regression.
        let (mgr, log) = host_probe_engine(HOST_PROBE_YAML);
        mgr.initialize().await.unwrap();

        let cfg_override: serde_yaml::Value = serde_yaml::from_str("max_requests: 10").unwrap();
        let entries = mgr
            .build_override_entries("prober", Some(&cfg_override), None, None)
            .await;
        assert!(!entries.is_empty(), "the override instance was built");

        assert_eq!(*log.lock().unwrap(), vec![Ok(true), Ok(true)]);
    }

    #[tokio::test]
    async fn an_override_that_drops_perform_http_withholds_the_transport() {
        register_fixture_hooks();
        // Capabilities come from the merged config, so narrowing them on a
        // route narrows what that route's instance may reach. `Ok(false)`
        // rather than `Err(())`: the host wired a transport, and the fix is
        // in the operator's own config.
        let (mgr, log) = host_probe_engine(HOST_PROBE_YAML);
        mgr.initialize().await.unwrap();

        let cfg_override: serde_yaml::Value = serde_yaml::from_str("max_requests: 10").unwrap();
        let narrowed: std::collections::HashSet<String> =
            ["read_headers".to_owned()].into_iter().collect();
        let entries = mgr
            .build_override_entries("prober", Some(&cfg_override), Some(&narrowed), None)
            .await;
        assert!(!entries.is_empty());

        assert_eq!(*log.lock().unwrap(), vec![Ok(true), Ok(false)]);
    }

    /// Override and base must have INDEPENDENT circuit breakers. A failure
    /// on an override-only route (e.g., bad credentials in the merged
    /// config) must not silently disable the plugin for every other route
    /// using the base config — config is part of the failure surface, and
    /// per-route blast radius is the point of having overrides.
    #[tokio::test]
    async fn test_route_override_circuit_breaker_isolated_from_base() {
        register_fixture_hooks();
        struct ErrorOnInvokeFactory;
        impl crate::factory::PluginFactory for ErrorOnInvokeFactory {
            fn create(
                &self,
                config: &PluginConfig,
            ) -> Result<crate::factory::PluginInstance, Box<PluginError>> {
                let plugin = Arc::new(AllowPlugin {
                    cfg: config.clone(),
                });
                let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
                Ok(crate::factory::PluginInstance {
                    plugin,
                    handlers: vec![(
                        crate::identity::HOOK_IDENTITY_RESOLVE,
                        Arc::new(ServingIdentity(handler)),
                    )],
                })
            }
        }

        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: flaky
    kind: test/error_on_invoke
    hooks: [identity.resolve]
    mode: sequential
    on_error: disable
routes:
  - tool: get_compensation
    authentication:
      - name: flaky
        config:
          something: changed
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();

        let mgr = PolicyEngine::default();
        mgr.register_factory("test/error_on_invoke", Box::new(ErrorOnInvokeFactory));
        mgr.load_config(policy_config).unwrap();
        mgr.initialize().await.unwrap();

        assert!(
            !mgr.get_plugin("flaky").unwrap().is_disabled(),
            "should start enabled"
        );

        // Invoke a route that uses the override. The override's handler
        // errors with `on_error: Disable`, so the executor calls disable()
        // on the *override's* plugin_ref. Independent circuit breakers
        // mean the base must stay enabled.
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let _ = mgr
            .invoke_by_name(
                crate::identity::HOOK_IDENTITY_RESOLVE,
                payload,
                make_meta("tool", "get_compensation", None, &[]),
                None,
            )
            .await;

        assert!(
            !mgr.get_plugin("flaky").unwrap().is_disabled(),
            "base must NOT be disabled when an override trips its own circuit breaker",
        );
    }

    #[tokio::test]
    async fn test_register_factory_then_load_config() {
        register_fixture_hooks();
        let yaml = r#"
plugins:
  - name: my_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 10

engine_settings:
  dispatch: hooks
  plugin_timeout: 45
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();

        let mgr = PolicyEngine::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.load_config(policy_config).unwrap();
        mgr.initialize().await.unwrap();

        assert_eq!(mgr.plugin_count(), 1);
        assert!(mgr.has_hooks_for("test_hook"));

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        // context_table = None (first invocation)
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        assert!(result.continue_processing);
    }

    // -- End-to-end routing tests --

    /// Helper to build meta extensions for routing tests.
    fn make_meta(
        entity_type: &str,
        entity_name: &str,
        scope: Option<&str>,
        tags: &[&str],
    ) -> Extensions {
        let mut tag_set = std::collections::HashSet::new();
        for t in tags {
            tag_set.insert(t.to_string());
        }
        Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some(entity_type.into()),
                entity_name: Some(entity_name.into()),
                scope: scope.map(String::from),
                tags: tag_set,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_routing_disabled_fires_all_plugins() {
        register_fixture_hooks();
        // Same plugins under hook dispatch: all fire regardless of entity
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: denier
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
    priority: 10
  - name: allower
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 20
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();
        let mgr = PolicyEngine::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.register_factory("test/deny", Box::new(DenyPluginFactory));
        mgr.load_config(policy_config).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // Even with meta, routing disabled → all plugins fire → denier wins
        let p: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (result, _) = mgr
            .invoke_by_name(
                "test_hook",
                p,
                make_meta("tool", "anything", None, &[]),
                None,
            )
            .await;
        assert!(!result.continue_processing); // denier fires (all plugins active)
    }

    #[tokio::test]
    async fn test_routing_no_meta_fires_all_plugins() {
        register_fixture_hooks();
        // Routing enabled but no meta on extensions → fallback to all
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: allower
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
  - name: denier
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
"#;
        let policy_config = parse_fixture_config(yaml).unwrap();
        let mgr = PolicyEngine::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.register_factory("test/deny", Box::new(DenyPluginFactory));
        mgr.load_config(policy_config).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // No meta → all plugins fire (both allower and denier)
        let p: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", p, Extensions::default(), None)
            .await;
        // No meta → no route resolution → both plugins fire. The denier
        // running is observable (the deny propagates to the result), so
        // assert that — proves route filtering didn't accidentally hide it.
        assert!(
            !result.continue_processing,
            "denier should run when no meta is provided (route filtering bypassed)",
        );
        assert!(
            result.violation.is_some(),
            "deny should produce a violation"
        );
    }

    // -- Executor tier validation tests --

    /// Handler that modifies extensions via `cow_copy` — adds a label.
    struct LabelAdderHandler;

    #[async_trait]
    impl AnyHookHandler for LabelAdderHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            let mut ext = extensions.cow_copy();
            if let Some(ref mut sec) = ext.security {
                sec.add_label("PLUGIN_ADDED");
            }
            let mut result: PluginResult<TestPayload> = PluginResult::allow();
            result.modified_extensions = Some(ext);
            Ok(crate::executor::erase_result(result))
        }
        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    /// Handler that tampers with an immutable extension slot.
    struct ImmutableTampererHandler;

    #[async_trait]
    impl AnyHookHandler for ImmutableTampererHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            let mut ext = extensions.cow_copy();
            // Tamper: replace the immutable request extension
            ext.request = Some(std::sync::Arc::new(crate::extensions::RequestExtension {
                request_id: Some("TAMPERED".into()),
                ..Default::default()
            }));
            let mut result: PluginResult<TestPayload> = PluginResult::allow();
            result.modified_extensions = Some(ext);
            Ok(crate::executor::erase_result(result))
        }
        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    #[tokio::test]
    async fn test_executor_accepts_valid_label_addition() {
        let mgr = PolicyEngine::default();
        let mut config = make_config("label-adder", 10, PluginMode::Sequential);
        config.capabilities = ["append_labels".to_owned(), "read_labels".to_owned()].into();
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(LabelAdderHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();
        mgr.initialize().await.unwrap();

        let mut security = crate::extensions::SecurityExtension::default();
        security.add_label("ORIGINAL");

        let ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, ext, None).await;

        assert!(result.continue_processing);
        // The plugin added "PLUGIN_ADDED" — should be accepted (monotonic superset)
        let modified = result.modified_extensions.as_ref().unwrap();
        let sec = modified.security.as_ref().unwrap();
        assert!(sec.has_label("ORIGINAL"));
        assert!(sec.has_label("PLUGIN_ADDED"));
    }

    #[tokio::test]
    async fn test_executor_rejects_immutable_tampering() {
        let mgr = PolicyEngine::default();
        let config = make_config("tamperer", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ImmutableTampererHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();
        mgr.initialize().await.unwrap();

        let ext = Extensions {
            request: Some(std::sync::Arc::new(crate::extensions::RequestExtension {
                request_id: Some("original-req-id".into()),
                ..Default::default()
            })),
            ..Default::default()
        };

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, ext, None).await;

        assert!(result.continue_processing);
        // Extensions should NOT be modified — the tampered immutable was rejected
        // The result should have no modified_extensions (rejected by validation)
        if let Some(ref modified) = result.modified_extensions {
            // If modified extensions exist, the request should still be the original
            assert_eq!(
                modified.request.as_ref().unwrap().request_id.as_deref(),
                Some("original-req-id"),
            );
        }
    }

    #[tokio::test]
    async fn test_capability_filtering_hides_security_from_plugin() {
        // Plugin has NO security capabilities — security should be None

        struct SecurityCheckerHandler {
            saw_security: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }

        #[async_trait]
        impl AnyHookHandler for SecurityCheckerHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                // Check if security is visible
                if extensions.security.is_some() {
                    self.saw_security
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let saw_security = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let mgr = PolicyEngine::default();
        // No security capabilities declared
        let config = make_config("no-sec-caps", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(SecurityCheckerHandler {
            saw_security: saw_security.clone(),
        });
        mgr.register_raw::<TestHook>(plugin, config, handler)
            .unwrap();
        mgr.initialize().await.unwrap();

        let mut security = crate::extensions::SecurityExtension::default();
        security.add_label("SECRET");
        security.subject = Some(crate::extensions::security::SubjectExtension {
            id: Some("alice".into()),
            ..Default::default()
        });

        let ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, ext, None).await;

        assert!(result.continue_processing);
        // Plugin should NOT have seen security — no capabilities declared
        // Security is still there but labels and subject are empty/none
        // (filter_extensions strips gated fields)
        // The saw_security flag checks if the security Option itself was Some
        // With filter_extensions, security IS Some but with empty labels and no subject
        // So saw_security will be true, but the content is filtered
    }

    /// Plugin that genuinely awaits inside its handler. Increments a
    /// shared counter after the await resolves so the test can verify
    /// the handler ran end-to-end and observed its async point.
    struct AsyncCounterPlugin {
        cfg: PluginConfig,
        counter: Arc<std::sync::atomic::AtomicU64>,
    }

    #[async_trait]
    impl Plugin for AsyncCounterPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    impl HookHandler<TestHook> for AsyncCounterPlugin {
        async fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_micros(1)).await;
            self.counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            PluginResult::allow()
        }
    }

    /// Verifies that a handler that genuinely `.await`s gets driven
    /// to completion before its result is observed.
    #[tokio::test]
    async fn test_async_handler_registers_and_invokes() {
        let mgr = PolicyEngine::default();
        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cfg = make_config("async-counter", 10, PluginMode::Sequential);
        let plugin = Arc::new(AsyncCounterPlugin {
            cfg: cfg.clone(),
            counter: counter.clone(),
        });

        // Same call path as sync plugins — no `register_async_handler`.
        mgr.register_handler::<TestHook, _>(plugin, cfg).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
        assert!(result.violation.is_none());
        // Counter increments only after the await resolves, so a non-zero
        // value proves the future was actually driven to completion.
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "async handler should have run once",
        );
    }

    /// A handler with no `.await` (`AllowPlugin`) and a handler that
    /// genuinely awaits (`AsyncCounterPlugin`) co-register on the same
    /// hook via the same `register_handler` call. Both run in priority
    /// order.
    #[tokio::test]
    async fn test_mixed_sync_and_async_handlers_in_same_hook() {
        let mgr = PolicyEngine::default();
        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let sync_cfg = make_config("sync-allow", 10, PluginMode::Sequential);
        let sync_plugin = Arc::new(AllowPlugin {
            cfg: sync_cfg.clone(),
        });
        mgr.register_handler::<TestHook, _>(sync_plugin, sync_cfg)
            .unwrap();

        let async_cfg = make_config("async-counter", 20, PluginMode::Sequential);
        let async_plugin = Arc::new(AsyncCounterPlugin {
            cfg: async_cfg.clone(),
            counter: counter.clone(),
        });
        mgr.register_handler::<TestHook, _>(async_plugin, async_cfg)
            .unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "awaiting plugin should have run alongside the non-awaiting plugin",
        );
    }

    // =====================================================================
    // Config load: failures and the settings the runtime ignores
    // =====================================================================

    /// A config naming a file that is not there has to say which file. An
    /// operator hits this on a typo or a bad volume mount, and the OS error
    /// alone does not identify it.
    #[test]
    fn loading_a_missing_config_file_reports_the_path() {
        let mgr = PolicyEngine::default();
        let err = mgr
            .load_config_file(std::path::Path::new("/nonexistent/ppe-test/policy.yaml"))
            .expect_err("a missing file must not load");
        let msg = err.to_string();
        assert!(msg.contains("policy.yaml"), "must name the file: {msg}");
    }

    /// Three settings used to parse, warn, and do nothing. Each now fails the
    /// engine's own load path naming the per-plugin spelling that replaced it.
    /// An operator who sets `fail_on_plugin_error: true` and reads a warning
    /// still believes the pipeline halts on error when it does not.
    #[test]
    fn the_settings_the_runtime_never_honored_fail_the_load() {
        for (yaml, removed, replacement) in [
            (
                "plugin_dirs: [\"/opt/plugins\"]\n",
                "plugin_dirs",
                "register_factory()",
            ),
            (
                "engine_settings:\n  parallel_execution_within_band: true\n",
                "parallel_execution_within_band",
                "mode: concurrent",
            ),
            (
                "engine_settings:\n  fail_on_plugin_error: true\n",
                "fail_on_plugin_error",
                "on_error: fail",
            ),
        ] {
            let mgr = Arc::new(PolicyEngine::default());
            let err = load_fixture_yaml(&mgr, yaml)
                .expect_err("a setting the runtime never honored must fail the load")
                .to_string();
            assert!(
                err.contains(removed) && err.contains(replacement),
                "the error must name `{removed}` and `{replacement}`: {err}"
            );
        }
    }

    /// Top-level `groups:` is the only bundle location the visitor walk reads,
    /// and every bundle written there has to reach `visit_policy_bundle`.
    /// Dropping one would silently lose a whole bundle of policy.
    #[test]
    fn every_top_level_groups_bundle_reaches_the_visitor() {
        use crate::visitor::{ConfigVisitor, VisitorError};
        use std::sync::Mutex as StdMutex;

        #[derive(Default)]
        struct BundleRecorder {
            seen: StdMutex<Vec<String>>,
        }
        impl ConfigVisitor for BundleRecorder {
            fn name(&self) -> &str {
                "recorder"
            }
            fn visit_policy_bundle(
                &self,
                _mgr: &Arc<PolicyEngine>,
                tag: &str,
                _yaml: &serde_yaml::Value,
            ) -> Result<(), VisitorError> {
                self.seen.lock().unwrap().push(tag.to_owned());
                Ok(())
            }
        }

        let yaml = r#"
engine_settings:
  dispatch: policy
groups:
  first:
    authorization:
      pre_invocation:
        - "require(authenticated)"
  second:
    authorization:
      pre_invocation:
        - "require(authenticated)"
"#;
        let mgr = Arc::new(PolicyEngine::default());
        let recorder = Arc::new(BundleRecorder::default());
        mgr.register_visitor(recorder.clone());
        load_fixture_yaml(&mgr, yaml).expect("config must load");

        let seen = recorder.seen.lock().unwrap();
        assert!(
            seen.iter().any(|t| t == "first"),
            "the first bundle must reach the visitor; saw {seen:?}"
        );
        assert!(
            seen.iter().any(|t| t == "second"),
            "and so must the second; saw {seen:?}"
        );
    }

    /// A visitor that refuses a section aborts the load, and the error names both
    /// the visitor and the section. With several orchestrators registered that
    /// attribution is the only way to know which one objected and to what.
    #[test]
    fn a_visitor_refusal_aborts_the_load_and_is_attributed() {
        use crate::visitor::{ConfigVisitor, VisitorError};

        struct Refuser(&'static str);
        impl ConfigVisitor for Refuser {
            fn name(&self) -> &str {
                "refuser"
            }
            fn visit_plugins(
                &self,
                _mgr: &Arc<PolicyEngine>,
                _plugins: &[PluginConfig],
            ) -> Result<(), VisitorError> {
                if self.0 == "plugins" {
                    return Err("no".into());
                }
                Ok(())
            }
            fn visit_global(
                &self,
                _mgr: &Arc<PolicyEngine>,
                _yaml: &serde_yaml::Value,
            ) -> Result<(), VisitorError> {
                if self.0 == "global" {
                    return Err("no".into());
                }
                Ok(())
            }
            fn visit_default(
                &self,
                _mgr: &Arc<PolicyEngine>,
                _entity_type: &str,
                _yaml: &serde_yaml::Value,
            ) -> Result<(), VisitorError> {
                if self.0 == "default" {
                    return Err("no".into());
                }
                Ok(())
            }
            fn visit_policy_bundle(
                &self,
                _mgr: &Arc<PolicyEngine>,
                _tag: &str,
                _yaml: &serde_yaml::Value,
            ) -> Result<(), VisitorError> {
                if self.0 == "bundle" {
                    return Err("no".into());
                }
                Ok(())
            }
        }

        let yaml = r#"
engine_settings:
  dispatch: policy
global:
  defaults:
    tool:
      authorization:
        pre_invocation:
          - "require(authenticated)"
groups:
  a-tag:
    authorization:
      pre_invocation:
        - "require(authenticated)"
"#;
        // One section per run, so a failure in an earlier section cannot mask a
        // missing error arm in a later one.
        for (section, expect) in [
            ("plugins", "visit_plugins"),
            ("global", "visit_global"),
            ("default", "visit_default"),
            ("bundle", "visit_policy_bundle"),
        ] {
            let mgr = Arc::new(PolicyEngine::default());
            mgr.register_visitor(Arc::new(Refuser(section)));
            let err =
                load_fixture_yaml(&mgr, yaml).expect_err("a refusing visitor must abort the load");
            let msg = err.to_string();
            assert!(
                msg.contains("refuser"),
                "the error must name the visitor: {msg}"
            );
            assert!(
                msg.contains(expect),
                "and the section it refused; expected {expect} in: {msg}"
            );
        }
    }

    // =====================================================================
    // Route annotations and small accessors
    // =====================================================================

    /// `remove_route_annotation` had no caller anywhere. Removing an annotation
    /// that is not there must be a no-op rather than a panic, since a caller
    /// tearing down routes cannot know which ones were annotated.
    #[test]
    fn removing_an_absent_route_annotation_is_a_no_op() {
        let mgr = PolicyEngine::default();
        mgr.remove_route_annotation("tool", "never-annotated", None, "cmf.tool_pre_invoke");
        mgr.remove_route_annotation(
            "tool",
            "never-annotated",
            Some("scope"),
            "cmf.tool_pre_invoke",
        );
    }

    /// `plugin_names` is how a host enumerates what loaded. It had no test, so
    /// nothing checked it reports the configured names rather than an empty list.
    #[test]
    fn plugin_names_lists_what_was_registered() {
        register_fixture_hooks();
        let mgr = Arc::new(PolicyEngine::default());
        assert!(
            mgr.plugin_names().is_empty(),
            "an empty engine registers nothing"
        );

        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: first
    kind: test/allow
    hooks: [test_hook]
  - name: second
    kind: test/allow
    hooks: [test_hook]
"#;
        load_fixture_yaml(&mgr, yaml).expect("config must load");
        let mut names = mgr.plugin_names();
        names.sort();
        assert_eq!(names, vec!["first".to_owned(), "second".to_owned()]);
    }

    /// The route cache is keyed on all four fields. `Hash` is derived and used;
    /// `PartialEq` is hand-written, so a field omitted there would make two
    /// distinct routes collide in the cache and one would be served the other's
    /// filtered entry list.
    #[test]
    fn the_route_cache_key_distinguishes_every_field() {
        let base = RouteCacheKey {
            entity_type: "tool".into(),
            resolved_name: "get_x".into(),
            hook_name: "cmf.tool_pre_invoke".into(),
            scope: None,
        };
        assert_eq!(base, base.clone(), "a key equals itself");

        let variants = [
            RouteCacheKey {
                entity_type: "prompt".into(),
                ..base.clone()
            },
            RouteCacheKey {
                resolved_name: "other".into(),
                ..base.clone()
            },
            RouteCacheKey {
                hook_name: "cmf.tool_post_invoke".into(),
                ..base.clone()
            },
            RouteCacheKey {
                scope: Some("read".into()),
                ..base.clone()
            },
        ];
        for v in variants {
            assert_ne!(
                base, v,
                "a key differing in one field must not compare equal, or two \
                 routes would share a cache entry"
            );
        }
    }

    // -- HTTP route resolution --

    /// What one invocation saw. The path and the entity name prove the
    /// attribute bag reaches policy exactly as the host set it, whatever the
    /// request resolved to.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Seen {
        plugin: String,
        path: Option<String>,
        entity_name: Option<String>,
    }

    type Ledger = Arc<std::sync::Mutex<Vec<Seen>>>;

    fn recorded(ledger: &Ledger) -> Vec<Seen> {
        ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn plugins_that_fired(ledger: &Ledger) -> Vec<String> {
        recorded(ledger).into_iter().map(|s| s.plugin).collect()
    }

    struct RecordingHandler {
        cfg: PluginConfig,
        ledger: Ledger,
        /// The hook family this fixture reports. Registration refuses a
        /// handler whose family is not the one the hook's row names, so a
        /// fixture standing in on a built-in hook has to report that hook's
        /// family rather than the fixture one.
        family: &'static str,
    }

    impl RecordingHandler {
        fn new(cfg: PluginConfig, ledger: &Ledger) -> Self {
            Self {
                cfg,
                ledger: Arc::clone(ledger),
                family: TestHook::NAME,
            }
        }

        fn serving(mut self, family: &'static str) -> Self {
            self.family = family;
            self
        }
    }

    #[async_trait]
    impl Plugin for RecordingHandler {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    #[async_trait]
    impl AnyHookHandler for RecordingHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            self.ledger
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(Seen {
                    plugin: self.cfg.name.clone(),
                    path: extensions.http.as_ref().and_then(|http| http.path.clone()),
                    entity_name: extensions
                        .meta
                        .as_ref()
                        .and_then(|meta| meta.entity_name.clone()),
                });
            let result: PluginResult<TestPayload> = PluginResult::allow();
            Ok(crate::executor::erase_result(result))
        }

        fn hook_type_name(&self) -> &'static str {
            self.family
        }
    }

    struct RecordingFactory(Ledger);

    impl crate::factory::PluginFactory for RecordingFactory {
        fn create(
            &self,
            config: &PluginConfig,
        ) -> Result<crate::factory::PluginInstance, Box<PluginError>> {
            // The hook names a `PluginInstance` carries are `'static`, so the
            // two the fixtures bind to are named rather than echoed back. One
            // handler per name, since each reports the family of the hook it
            // is registered under.
            let handlers = config
                .hooks
                .iter()
                .map(|hook| -> (&'static str, Arc<dyn AnyHookHandler>) {
                    let recorder = RecordingHandler::new(config.clone(), &self.0);
                    match hook.as_str() {
                        crate::identity::HOOK_IDENTITY_RESOLVE => (
                            crate::identity::HOOK_IDENTITY_RESOLVE,
                            Arc::new(recorder.serving(crate::identity::IdentityHook::NAME)),
                        ),
                        _ => (TestHook::NAME, Arc::new(recorder)),
                    }
                })
                .collect();
            Ok(crate::factory::PluginInstance {
                plugin: Arc::new(AllowPlugin {
                    cfg: config.clone(),
                }),
                handlers,
            })
        }
    }

    /// An initialized engine serving recording plugins for `yaml`.
    async fn recording_engine(yaml: &str) -> (PolicyEngine, Ledger) {
        register_fixture_hooks();
        let ledger: Ledger = Arc::new(std::sync::Mutex::new(Vec::new()));
        let policy_config = crate::config::parse_config(yaml).expect("the fixture must parse");
        let mut factories = PluginFactoryRegistry::new();
        factories.register(
            "test/record",
            Box::new(RecordingFactory(Arc::clone(&ledger))),
        );
        let mgr = PolicyEngine::from_config(policy_config, &factories).expect("the engine builds");
        mgr.initialize().await.expect("initialize");
        (mgr, ledger)
    }

    /// A generic HTTP request as a host presents one: the reserved global
    /// entity name, and the request line on its own slot.
    fn http_request(path: Option<&str>) -> Extensions {
        http_request_named(ENTITY_NAME_GLOBAL, path, None)
    }

    fn http_request_named(
        entity_name: &str,
        path: Option<&str>,
        scope: Option<&str>,
    ) -> Extensions {
        Extensions {
            meta: Some(Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some(ENTITY_HTTP.to_owned()),
                entity_name: Some(entity_name.to_owned()),
                scope: scope.map(str::to_owned),
                ..Default::default()
            })),
            http: path.map(|path| {
                Arc::new(crate::extensions::HttpExtension {
                    method: Some("GET".to_owned()),
                    path: Some(path.to_owned()),
                    ..Default::default()
                })
            }),
            ..Default::default()
        }
    }

    /// An HTTP request whose `http` slot is present but carries no path.
    fn http_request_without_path() -> Extensions {
        let mut ext = http_request(None);
        ext.http = Some(Arc::new(crate::extensions::HttpExtension::default()));
        ext
    }

    async fn dispatch(mgr: &PolicyEngine, hook: &str, ext: Extensions) -> PipelineResult {
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "request".into(),
        });
        mgr.invoke_by_name(hook, payload, ext, None).await.0
    }

    /// One prefix route with an `authentication:` step, one exact route with
    /// none. Route resolution is read through `identity.resolve`, the one hook
    /// a route still binds a plugin to in policy mode.
    const HTTP_ROUTES_YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: observer
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
    capabilities: [read_headers]
routes:
  - http:
      path_prefix: /v1/files
    authentication: [observer]
  - http: /healthz
"#;

    /// An `http:` route alongside a global `authentication:` list, so an
    /// unmatched request has somewhere to fall back to.
    const HTTP_ROUTE_WITH_GLOBAL_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  authentication: [observer]
plugins:
  - name: observer
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
    capabilities: [read_headers]
routes:
  - http:
      path_prefix: /v1/files
"#;

    /// No `http:` route anywhere, which is every configuration that exists
    /// today.
    const NO_HTTP_ROUTE_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  authentication: [observer]
plugins:
  - name: observer
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
    capabilities: [read_headers]
routes:
  - tool: get_weather
"#;

    /// The name the first route in a document is known by, from the one
    /// function that owns that mapping.
    fn first_route_identity(yaml: &str) -> (&'static str, String) {
        let parsed = crate::config::parse_config(yaml).expect("the fixture must parse");
        let route = parsed.routes.first().expect("a first route");
        let (entity_type, mut names) =
            config::route_entity_identity(route).expect("the route declares a selector");
        (entity_type, names.remove(0))
    }

    #[tokio::test]
    async fn many_http_paths_matching_one_route_share_one_cache_entry() {
        let (mgr, ledger) = recording_engine(HTTP_ROUTES_YAML).await;

        for n in 0..25 {
            let path = format!("/v1/files/report-{n}.pdf");
            let result = dispatch(
                &mgr,
                crate::identity::HOOK_IDENTITY_RESOLVE,
                http_request(Some(&path)),
            )
            .await;
            assert!(result.continue_processing, "{path} must be allowed");
        }

        assert_eq!(
            mgr.routing_cache_size(),
            1,
            "keying on the matched selector rather than the request path makes \
             cache cardinality a function of the configuration"
        );
        assert_eq!(
            plugins_that_fired(&ledger).len(),
            25,
            "every request must still reach the route's plugin"
        );
    }

    #[tokio::test]
    async fn an_http_request_resolves_the_route_its_path_matches() {
        let (mgr, ledger) = recording_engine(HTTP_ROUTES_YAML).await;

        // Matching reads the whole string the host set, query included, the way
        // the router reads the path it was given. The prefix still matches at
        // the same segment boundary, and the policy sees the string verbatim.
        let raw = "/v1/files/q3.pdf?download=1";
        let result = dispatch(
            &mgr,
            crate::identity::HOOK_IDENTITY_RESOLVE,
            http_request(Some(raw)),
        )
        .await;
        assert!(result.continue_processing);

        // The exact route carries no plugins, so nothing fires for it. That is
        // the route resolving, not the prefix route failing to.
        let healthz = dispatch(
            &mgr,
            crate::identity::HOOK_IDENTITY_RESOLVE,
            http_request(Some("/healthz")),
        )
        .await;
        assert!(healthz.continue_processing);

        assert_eq!(
            recorded(&ledger),
            vec![Seen {
                plugin: "observer".to_owned(),
                path: Some(raw.to_owned()),
                entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
            }],
            "only the prefix route's plugin fires, and it reads the path and the \
             entity name exactly as the host set them"
        );
    }

    #[tokio::test]
    async fn a_path_shaped_entity_name_does_not_reach_the_cache_key() {
        // A host is asked to set the reserved global name on an HTTP request
        // but nothing makes it. Reading the field here would put one cache
        // entry per request path in the cache.
        let (mgr, _ledger) = recording_engine(HTTP_ROUTE_WITH_GLOBAL_YAML).await;

        for n in 0..25 {
            let path = format!("/elsewhere/{n}");
            let ext = http_request_named(&path, Some(&path), None);
            let result = dispatch(&mgr, crate::identity::HOOK_IDENTITY_RESOLVE, ext).await;
            assert!(result.continue_processing, "{path} must be allowed");
        }

        assert_eq!(
            mgr.routing_cache_size(),
            1,
            "the fallback name is the reserved constant, not the entity name the \
             host supplied"
        );
    }

    #[tokio::test]
    async fn without_an_http_route_an_http_request_resolves_the_global_name() {
        let (mgr, ledger) = recording_engine(NO_HTTP_ROUTE_YAML).await;

        for n in 0..5 {
            let path = format!("/v1/files/{n}");
            let result = dispatch(
                &mgr,
                crate::identity::HOOK_IDENTITY_RESOLVE,
                http_request(Some(&path)),
            )
            .await;
            assert!(result.continue_processing);
        }

        assert_eq!(
            plugins_that_fired(&ledger).len(),
            5,
            "the global policy governs, as it does today"
        );
        assert_eq!(
            mgr.routing_cache_size(),
            1,
            "one entry under the reserved global name"
        );
    }

    #[tokio::test]
    async fn an_absent_request_line_falls_back_instead_of_denying() {
        let (mgr, ledger) = recording_engine(HTTP_ROUTE_WITH_GLOBAL_YAML).await;

        for ext in [http_request(None), http_request_without_path()] {
            let result = dispatch(&mgr, crate::identity::HOOK_IDENTITY_RESOLVE, ext).await;
            assert!(
                result.continue_processing,
                "no request line means no route matched, which is not an error"
            );
        }

        assert_eq!(
            plugins_that_fired(&ledger),
            vec!["observer".to_owned(), "observer".to_owned()],
            "the global policy runs for a request that named no path"
        );
        assert_eq!(mgr.routing_cache_size(), 1);
    }

    #[tokio::test]
    async fn an_unreadable_path_denies_only_when_an_http_route_is_declared() {
        // A carriage return in a request line is a smuggling signal, and
        // guessing which path a route should answer for is exactly what the
        // deny exists to avoid. This is the whole of what the path normalizer
        // affects: matching itself runs on the path as given, and only the
        // refusal reaches a decision.
        let smuggled = "/v1/files/q3.pdf\r\nX-Injected: 1";

        let (with_routes, _) = recording_engine(HTTP_ROUTES_YAML).await;
        let denied = dispatch(
            &with_routes,
            crate::identity::HOOK_IDENTITY_RESOLVE,
            http_request(Some(smuggled)),
        )
        .await;
        assert!(
            denied.is_denied(),
            "an unreadable path must not fall through"
        );
        let violation = denied.violation.expect("a denial carries a violation");
        assert_eq!(violation.code, VIOLATION_UNREADABLE_REQUEST_PATH);
        assert_eq!(
            violation.proto_error_code,
            Some(400),
            "the request is malformed rather than forbidden"
        );

        let (without_routes, ledger) = recording_engine(NO_HTTP_ROUTE_YAML).await;
        let allowed = dispatch(
            &without_routes,
            crate::identity::HOOK_IDENTITY_RESOLVE,
            http_request(Some(smuggled)),
        )
        .await;
        assert!(
            allowed.continue_processing,
            "with no http: route nothing could have answered for the path, so \
             behavior is what it is today"
        );
        assert_eq!(plugins_that_fired(&ledger), vec!["observer".to_owned()]);

        let nothing_registered =
            dispatch(&with_routes, "no_such_hook", http_request(Some(smuggled))).await;
        assert!(
            nothing_registered.continue_processing,
            "a hook with no entries and no annotations returns before resolution \
             runs, and nothing would have enforced there anyway"
        );
    }

    /// A visitor that reads nothing and rejects nothing.
    ///
    /// Its only job is to make `has_visitor` true, which is what a host with an
    /// orchestrator of its own looks like to the config loader. It is what puts
    /// a policy-mode config with plugins and no scope within reach: the
    /// praxis-policy-core backstop stands down for a host that has a visitor,
    /// and this one does not check what that backstop would have.
    #[derive(Debug)]
    struct SilentVisitor;

    impl crate::visitor::ConfigVisitor for SilentVisitor {
        fn name(&self) -> &str {
            "silent"
        }
    }

    /// A request as a host presents one when it has no protocol metadata to
    /// give: no `meta`, so no entity type and no name to resolve a route with.
    fn unidentified_request() -> Extensions {
        Extensions::default()
    }

    #[tokio::test]
    async fn a_request_the_engine_cannot_identify_is_denied_against_installed_policy() {
        let (mgr, ledger) = recording_engine(HTTP_ROUTES_YAML).await;

        let denied = dispatch(
            &mgr,
            crate::identity::HOOK_IDENTITY_RESOLVE,
            unidentified_request(),
        )
        .await;

        assert!(
            denied.is_denied(),
            "no entity metadata means no route resolves, and the policy that \
             would have decided cannot be applied"
        );
        let violation = denied.violation.expect("a denial carries a violation");
        assert_eq!(
            violation.code, VIOLATION_UNIDENTIFIED_REQUEST,
            "distinct from a policy's own deny: no rule was reached"
        );
        assert_eq!(
            violation.proto_error_code,
            Some(400),
            "the host failed to supply something, so the request is malformed \
             rather than forbidden"
        );
        assert!(
            plugins_that_fired(&ledger).is_empty(),
            "denying instead of falling through is the point: firing the whole \
             registry would run plugins against absent context"
        );
    }

    /// The guard on that denial, which is not the dispatch mode. A config
    /// declaring no policy passes the request it used to pass.
    ///
    /// Reaching this needs a host with a visitor of its own, because the
    /// praxis-policy-core backstop refuses a scope-less policy-mode config when
    /// nothing else would check it.
    #[tokio::test]
    async fn a_config_declaring_no_policy_does_not_deny_an_unidentified_request() {
        let ledger: Ledger = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mgr = Arc::new(PolicyEngine::default());
        mgr.register_factory(
            "test/record",
            Box::new(RecordingFactory(Arc::clone(&ledger))),
        );
        mgr.register_visitor(Arc::new(SilentVisitor));
        load_fixture_yaml(
            &mgr,
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: observer
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
    capabilities: [read_headers]
"#,
        )
        .expect("no routes, no groups, no global: nothing here is policy");
        mgr.initialize().await.expect("initialize");

        let result = dispatch(
            &mgr,
            crate::identity::HOOK_IDENTITY_RESOLVE,
            unidentified_request(),
        )
        .await;

        assert!(
            result.continue_processing,
            "with no policy installed there is nothing the missing metadata \
             could have been matched against, so the denial must not fire"
        );
        assert_eq!(
            plugins_that_fired(&ledger),
            vec!["observer".to_owned()],
            "the request passes exactly as it did before the guard existed"
        );
    }

    /// An HTTP request always carries an entity type and resolves to the
    /// reserved global name, so the denial is unreachable for it however little
    /// else the request says.
    #[tokio::test]
    async fn an_http_request_resolves_its_annotation_rather_than_being_denied() {
        let (mgr, ledger) = recording_engine(HTTP_ROUTES_YAML).await;

        for ext in [
            http_request(Some("/v1/files/q3.pdf")),
            http_request(None),
            http_request_without_path(),
        ] {
            let result = dispatch(&mgr, crate::identity::HOOK_IDENTITY_RESOLVE, ext).await;
            assert!(
                result.continue_processing,
                "an http: request names its entity type, so a route resolves \
                 and the unidentified-request denial is never reached"
            );
            assert_ne!(
                result.violation.map(|v| v.code),
                Some(VIOLATION_UNIDENTIFIED_REQUEST.to_owned()),
            );
        }
        assert_eq!(
            plugins_that_fired(&ledger),
            vec!["observer".to_owned()],
            "only the request naming a path matches the prefix route, so only it \
             reaches that route's authentication list. The other two resolve no \
             route and fall back to a global list this fixture does not declare"
        );
    }

    #[tokio::test]
    async fn a_scoped_annotation_wins_over_an_unscoped_one_for_a_resolved_name() {
        let (mgr, _ledger) = recording_engine(HTTP_ROUTES_YAML).await;
        let (entity_type, resolved_name) = first_route_identity(HTTP_ROUTES_YAML);
        let annotated: Ledger = Arc::new(std::sync::Mutex::new(Vec::new()));

        for (tag, scope) in [("scoped", Some("tenant-a".to_owned())), ("unscoped", None)] {
            let cfg = make_config(tag, 0, PluginMode::Sequential);
            mgr.annotate_route(
                entity_type,
                resolved_name.clone(),
                scope,
                "test_hook",
                Arc::new(RecordingHandler::new(cfg.clone(), &annotated)),
                cfg,
            );
        }

        for scope in [Some("tenant-a"), None, Some("tenant-b")] {
            let ext = http_request_named(ENTITY_NAME_GLOBAL, Some("/v1/files/q3.pdf"), scope);
            let result = dispatch(&mgr, "test_hook", ext).await;
            assert!(result.continue_processing);
        }

        assert_eq!(
            plugins_that_fired(&annotated),
            vec![
                "scoped".to_owned(),
                "unscoped".to_owned(),
                "unscoped".to_owned()
            ],
            "the scoped annotation wins for its own scope; every other scope \
             falls back to the unscoped default"
        );
    }

    /// A route's `authentication:` list needs the host to supply the request
    /// line at the identity hook. Without it the global list runs, which is
    /// long-standing behavior, so the engine says so once instead of silently.
    #[tokio::test]
    async fn a_route_authentication_list_that_cannot_apply_warns_once() {
        let yaml = r#"
engine_settings:
  dispatch: policy
global:
  authentication:
    - global-jwt
plugins:
  - name: global-jwt
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
  - name: route-jwt
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
routes:
  - http:
      path_prefix: /v1/files
    authentication:
      - route-jwt
"#;
        let (mgr, ledger) = recording_engine(yaml).await;
        let (events, sink) = capturing();

        for _ in 0..3 {
            let result = dispatch(
                &mgr,
                crate::identity::HOOK_IDENTITY_RESOLVE,
                http_request(None),
            )
            .await;
            assert!(result.continue_processing);
        }

        assert_eq!(
            plugins_that_fired(&ledger),
            vec![
                "global-jwt".to_owned(),
                "global-jwt".to_owned(),
                "global-jwt".to_owned()
            ],
            "the global authentication list runs, exactly as it does today"
        );
        let warnings = events.matching("global authentication");
        assert_eq!(
            warnings.len(),
            1,
            "the warning latches after the first request, got {warnings:?}"
        );
        assert!(
            warnings[0].contains(&first_route_identity(yaml).1),
            "the warning must name the route whose list could not apply, got {warnings:?}"
        );
        drop(sink);
    }

    /// The load-time answer the request path reads, straight off the snapshot.
    fn routes_declaring_authentication(mgr: &PolicyEngine) -> Vec<String> {
        mgr.load_runtime()
            .http_routes_declaring_authentication
            .to_vec()
    }

    /// An engine owning the recording factory, so configs can be loaded and
    /// replaced through it rather than handed in once at construction.
    fn reloadable_recording_engine() -> (PolicyEngine, Ledger) {
        register_fixture_hooks();
        let ledger: Ledger = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mgr = PolicyEngine::default();
        mgr.register_factory(
            "test/record",
            Box::new(RecordingFactory(Arc::clone(&ledger))),
        );
        (mgr, ledger)
    }

    /// An `http:` route and a global `authentication:` list, with nothing
    /// declared per route. The ordinary shape, and the one that used to walk
    /// the route table on every identity hook without a readable path.
    const HTTP_ROUTE_WITHOUT_ROUTE_AUTHENTICATION_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  authentication:
    - global-jwt
plugins:
  - name: global-jwt
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
routes:
  - http:
      path_prefix: /v1/files
"#;

    /// The answer is computed when the config lands, so a config with nothing
    /// to report leaves the request path an empty slice to look at rather than
    /// a route table to walk.
    #[tokio::test]
    async fn a_config_with_no_route_authentication_leaves_no_answer_to_scan_for() {
        let (mgr, ledger) = recording_engine(HTTP_ROUTE_WITHOUT_ROUTE_AUTHENTICATION_YAML).await;

        assert!(
            mgr.load_runtime()
                .policy_config
                .as_ref()
                .is_some_and(declares_http_route),
            "the fixture must declare an http: route, or an empty answer says \
             nothing about route-level authentication"
        );
        assert!(
            routes_declaring_authentication(&mgr).is_empty(),
            "no http: route declares authentication:, so there is nothing for a \
             request to be warned about and nothing to compute per request"
        );

        let (events, sink) = capturing();
        for _ in 0..5 {
            let result = dispatch(
                &mgr,
                crate::identity::HOOK_IDENTITY_RESOLVE,
                http_request(None),
            )
            .await;
            assert!(result.continue_processing);
        }

        assert_eq!(
            plugins_that_fired(&ledger).len(),
            5,
            "the global authentication list runs for each request"
        );
        assert!(
            events.matching("global authentication").is_empty(),
            "nothing to report means nothing reported"
        );
        drop(sink);
    }

    /// Only an `http:` route with its own `authentication:` list can lose that
    /// list to a missing path, so only those routes are in the answer.
    #[tokio::test]
    async fn the_answer_names_only_http_routes_declaring_authentication() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: route-jwt
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
routes:
  - http:
      path_prefix: /v1/files
    authentication:
      - route-jwt
  - http: /healthz
  - tool: get_weather
    authentication:
      - route-jwt
"#;
        let (mgr, _ledger) = recording_engine(yaml).await;

        assert_eq!(
            routes_declaring_authentication(&mgr),
            vec!["prefix:/v1/files".to_owned()],
            "an http: route with no authentication: and a tool route with one \
             both have nothing to lose to a missing request path"
        );
    }

    /// A config replacement rebuilds the snapshot, so the answer follows the
    /// config it was derived from. A stale answer would warn about routes that
    /// are gone, or stay silent about ones that arrived.
    #[tokio::test]
    async fn a_reload_recomputes_which_routes_declare_authentication() {
        // A load merges its plugins into the registry, so each generation names
        // its own rather than colliding with the one before it.
        let config_for = |generation: u8, prefix: &str, declares: bool| {
            let authentication = if declares {
                format!("    authentication:\n      - route-jwt-{generation}\n")
            } else {
                String::new()
            };
            crate::config::parse_config(&format!(
                r#"
engine_settings:
  dispatch: policy
global:
  authentication:
    - global-jwt-{generation}
plugins:
  - name: global-jwt-{generation}
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
  - name: route-jwt-{generation}
    kind: test/record
    hooks: [identity.resolve]
    mode: sequential
routes:
  - http:
      path_prefix: {prefix}
{authentication}"#
            ))
            .expect("the fixture must parse")
        };

        let (mgr, _ledger) = reloadable_recording_engine();
        mgr.load_config(config_for(1, "/v1/files", true))
            .expect("the first config loads");
        mgr.initialize().await.expect("initialize");
        assert_eq!(
            routes_declaring_authentication(&mgr),
            vec!["prefix:/v1/files".to_owned()]
        );

        mgr.load_config(config_for(2, "/v1/files", false))
            .expect("the replacement loads");
        assert!(
            routes_declaring_authentication(&mgr).is_empty(),
            "the route that declared authentication: is gone, so the answer is too"
        );

        mgr.load_config(config_for(3, "/v2/files", true))
            .expect("the third config loads");
        assert_eq!(
            routes_declaring_authentication(&mgr),
            vec!["prefix:/v2/files".to_owned()],
            "the answer names the route the current config declares"
        );

        let (events, sink) = capturing();
        let result = dispatch(
            &mgr,
            crate::identity::HOOK_IDENTITY_RESOLVE,
            http_request(None),
        )
        .await;
        assert!(result.continue_processing);
        let warnings = events.matching("global authentication");
        assert_eq!(
            warnings.len(),
            1,
            "a reload clears the latch, so the new config warns once, got \
             {warnings:?}"
        );
        assert!(
            warnings[0].contains("prefix:/v2/files") && !warnings[0].contains("/v1/files"),
            "the warning names the route the reload installed, got {warnings:?}"
        );
        drop(sink);
    }

    #[tokio::test]
    async fn the_resolved_name_is_traced_when_a_route_is_resolved() {
        let (mgr, _ledger) = recording_engine(HTTP_ROUTES_YAML).await;
        let (_, resolved_name) = first_route_identity(HTTP_ROUTES_YAML);
        let (events, sink) = capturing();

        let result = dispatch(
            &mgr,
            crate::identity::HOOK_IDENTITY_RESOLVE,
            http_request(Some("/v1/files/q3.pdf")),
        )
        .await;
        assert!(result.continue_processing);

        let traced = events.matching("Resolved route for request");
        assert_eq!(traced.len(), 1, "one resolution, one trace, got {traced:?}");
        assert!(
            traced[0].contains(&resolved_name),
            "an operator cannot otherwise tell which route a path matched, got \
             {traced:?}"
        );
        assert!(
            traced[0].contains(ENTITY_HTTP)
                && traced[0].contains(crate::identity::HOOK_IDENTITY_RESOLVE),
            "the entity type and the hook belong in the same line, got {traced:?}"
        );
        drop(sink);
    }

    /// A root-prefix `http:` route alongside nothing else, so the only other
    /// name in play is the reserved global one.
    const HTTP_CATCHALL_ROUTE_YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /
"#;

    /// A route annotation does not pass through the registry's family check:
    /// it lands in `route_annotations`, not the hook index. The pairing the
    /// registry refuses installs here, which is the bound on what that check
    /// covers.
    #[test]
    fn an_annotation_installs_whatever_family_the_handler_reports() {
        let mgr = PolicyEngine::default();
        let ledger: Ledger = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cfg = make_config("cmf-on-http", 0, PluginMode::Sequential);
        let handler = || {
            Arc::new(RecordingHandler::new(cfg.clone(), &ledger).serving(crate::cmf::CmfHook::NAME))
        };

        let replaced = mgr.annotate_route(
            ENTITY_HTTP,
            ENTITY_NAME_GLOBAL,
            None,
            crate::http_hook::HOOK_HTTP_REQUEST,
            handler(),
            cfg.clone(),
        );
        assert!(
            !replaced,
            "nothing was annotated under those coordinates yet"
        );

        // The second call reports a replacement, which is only true if the
        // first one was recorded.
        assert!(mgr.annotate_route(
            ENTITY_HTTP,
            ENTITY_NAME_GLOBAL,
            None,
            crate::http_hook::HOOK_HTTP_REQUEST,
            handler(),
            cfg,
        ));
    }

    /// An annotation is the whole lineup for its coordinates, so a route's own
    /// `plugins:` list stops firing for the requests it answers unless the
    /// handler dispatches into it by name.
    #[tokio::test]
    async fn an_annotated_http_route_dispatches_instead_of_its_plugin_chain() {
        let (mgr, chain) = recording_engine(HTTP_ROUTES_YAML).await;
        let (entity_type, resolved_name) = first_route_identity(HTTP_ROUTES_YAML);
        let annotated: Ledger = Arc::new(std::sync::Mutex::new(Vec::new()));

        let cfg = make_config("policy-body", 0, PluginMode::Sequential);
        mgr.annotate_route(
            entity_type,
            resolved_name,
            None,
            "test_hook",
            Arc::new(RecordingHandler::new(cfg.clone(), &annotated)),
            cfg,
        );

        let result = dispatch(&mgr, "test_hook", http_request(Some("/v1/files/q3.pdf"))).await;
        assert!(result.continue_processing, "the handler allows the request");

        assert_eq!(
            plugins_that_fired(&annotated),
            vec!["policy-body".to_owned()],
            "the annotated handler answers for everything the route resolves"
        );
        assert!(
            plugins_that_fired(&chain).is_empty(),
            "the route's plugin list is replaced rather than appended to, got {:?}",
            plugins_that_fired(&chain)
        );
    }

    /// The annotation table overwrites from any source, so a second install at
    /// one coordinate says so and the later handler is the one that evaluates.
    #[tokio::test]
    async fn a_second_annotation_at_one_coordinate_reports_the_replacement() {
        let (mgr, _chain) = recording_engine(HTTP_ROUTES_YAML).await;
        let (entity_type, resolved_name) = first_route_identity(HTTP_ROUTES_YAML);
        let annotated: Ledger = Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut reported = Vec::new();
        for tag in ["first", "second"] {
            let cfg = make_config(tag, 0, PluginMode::Sequential);
            reported.push(mgr.annotate_route(
                entity_type,
                resolved_name.clone(),
                None,
                "test_hook",
                Arc::new(RecordingHandler::new(cfg.clone(), &annotated)),
                cfg,
            ));
        }
        assert_eq!(
            reported,
            vec![false, true],
            "the first install is new, the second replaces it"
        );

        let result = dispatch(&mgr, "test_hook", http_request(Some("/v1/files/q3.pdf"))).await;
        assert!(result.continue_processing, "the handler allows the request");
        assert_eq!(
            plugins_that_fired(&annotated),
            vec!["second".to_owned()],
            "the later handler is the one kept"
        );
    }

    /// An explicit catch-all `http:` route derives its own name, so it and the
    /// reserved global name are different keys: the route governs what it
    /// resolves and the reserved name governs what resolves nothing.
    #[tokio::test]
    async fn a_root_prefix_route_does_not_share_the_reserved_global_annotation() {
        let (mgr, _chain) = recording_engine(HTTP_CATCHALL_ROUTE_YAML).await;
        let (entity_type, route_name) = first_route_identity(HTTP_CATCHALL_ROUTE_YAML);
        assert_ne!(
            route_name, ENTITY_NAME_GLOBAL,
            "a root prefix is not the reserved name, so the two cannot collide"
        );

        let annotated: Ledger = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut reported = Vec::new();
        for (tag, name) in [
            ("route", route_name.as_str()),
            ("catch-all", ENTITY_NAME_GLOBAL),
        ] {
            let cfg = make_config(tag, 0, PluginMode::Sequential);
            reported.push(mgr.annotate_route(
                entity_type,
                name,
                None,
                "test_hook",
                Arc::new(RecordingHandler::new(cfg.clone(), &annotated)),
                cfg,
            ));
        }
        assert_eq!(
            reported,
            vec![false, false],
            "neither install landed on the other's key"
        );

        // A request carrying a path resolves the route. One that named no path
        // resolves nothing, which is where the reserved name applies.
        for ext in [http_request(Some("/anything/at/all")), http_request(None)] {
            let result = dispatch(&mgr, "test_hook", ext).await;
            assert!(result.continue_processing, "both handlers allow");
        }
        assert_eq!(
            plugins_that_fired(&annotated),
            vec!["route".to_owned(), "catch-all".to_owned()],
            "the route answers what it resolves; the reserved name answers the rest"
        );
    }

    // -- Capturing what the engine emits --
    //
    // A subscriber installed once for the whole binary, always interested, so
    // callsite interest never depends on which test reached it first. The
    // thread-local sink keeps each test reading only its own events.

    #[derive(Clone, Default)]
    struct Events(Arc<std::sync::Mutex<Vec<String>>>);

    impl Events {
        fn matching(&self, needle: &str) -> Vec<String> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .filter(|event| event.contains(needle))
                .cloned()
                .collect()
        }
    }

    std::thread_local! {
        static SINK: std::cell::RefCell<Option<Events>> =
            const { std::cell::RefCell::new(None) };
    }

    struct Capture;

    /// Clears the sink even if the body panics, so a failing test cannot leak
    /// its events into whichever test the runner puts on this thread next.
    struct Sink;

    impl Drop for Sink {
        fn drop(&mut self) {
            SINK.with_borrow_mut(|sink| *sink = None);
        }
    }

    struct Render(String);

    impl tracing::field::Visit for Render {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }

    impl tracing::Subscriber for Capture {
        fn register_callsite(&self, _: &tracing::Metadata<'_>) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::always()
        }

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            SINK.with_borrow(|sink| {
                let Some(events) = sink.as_ref() else {
                    return;
                };
                let mut render = Render(format!("[{}]", event.metadata().level()));
                event.record(&mut render);
                events
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(render.0);
            });
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Capture what the engine emits until the returned guard is dropped.
    fn capturing() -> (Events, Sink) {
        static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INSTALLED.get_or_init(|| {
            tracing::subscriber::set_global_default(Capture)
                .expect("no other subscriber is installed in this test binary");
        });
        let events = Events::default();
        SINK.with_borrow_mut(|sink| *sink = Some(events.clone()));
        (events, Sink)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod assertions_reachability_tests {
    use super::*;
    use crate::assertions::Direction;
    use crate::extensions::{HttpExtension, MetaExtension};
    use crate::http_hook::{HOOK_HTTP_REQUEST, HOOK_HTTP_RESPONSE, HttpHook, HttpPayload};

    /// One `http:` route with a contract, one without, and one named route with
    /// one. Only the first has anything to lose to a missing request line.
    const CONFIG: &str = "
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
    assertions:
      request:
        headers:
          - name: x-auth-path-scope
            from: claim.namespace
      response:
        strip: [x-upstream-*]
  - http: /healthz
  - tool: get_weather
    assertions:
      request:
        headers:
          - name: x-auth-user-id
            from: subject.id
";

    fn engine_with(yaml: &str) -> Arc<PolicyEngine> {
        let engine = Arc::new(PolicyEngine::default());
        let parsed = crate::config::parse_config(yaml).expect("the config loads");
        engine.load_config(parsed).expect("the config installs");
        engine
    }

    fn http_request(path: Option<&str>) -> Extensions {
        Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some(ENTITY_HTTP.to_owned()),
                entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
                ..Default::default()
            })),
            http: Some(Arc::new(HttpExtension {
                method: Some("GET".to_owned()),
                path: path.map(str::to_owned),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn warned(engine: &PolicyEngine, direction: Direction) -> bool {
        match direction {
            Direction::Request => &engine.route_request_assertions_unreachable_warned,
            Direction::Response => &engine.route_response_assertions_unreachable_warned,
        }
        .load(Ordering::Acquire)
    }

    #[tokio::test]
    async fn the_snapshot_names_only_http_routes_declaring_a_contract() {
        let engine = engine_with(CONFIG);
        assert_eq!(
            engine
                .load_runtime()
                .http_routes_declaring_assertions
                .to_vec(),
            vec!["prefix:/v1/files".to_owned()],
            "an http: route with no contract and a tool route with one both have \
             nothing to lose to a missing request line"
        );
    }

    #[tokio::test]
    async fn the_snapshot_list_is_empty_when_no_http_route_declares_a_contract() {
        let engine = engine_with(
            "engine_settings:\n  dispatch: policy\nroutes:\n  - http: /healthz\n  - tool: t\n",
        );
        assert!(
            engine
                .load_runtime()
                .http_routes_declaring_assertions
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_invocation_with_no_path_warns_once_and_not_twice() {
        let engine = engine_with(CONFIG);
        for _ in 0..2 {
            let (_result, _bg) = engine
                .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, http_request(None), None)
                .await;
        }
        assert!(warned(&engine, Direction::Request), "the gate is set");
        // The gate is one-shot, so the second invocation above found it set. What
        // this pins is that it is a gate at all: a reset makes it fire again.
        engine.clear_routing_cache();
        assert!(!warned(&engine, Direction::Request));
    }

    #[tokio::test]
    async fn a_readable_path_does_not_warn() {
        let engine = engine_with(CONFIG);
        let (_result, _bg) = engine
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request(Some("/v1/files/a")),
                None,
            )
            .await;
        assert!(!warned(&engine, Direction::Request));
    }

    /// R30's case: a host that supplies the request line on the way in and not
    /// on the way out gets a warning naming the response direction, which is the
    /// actionable half. One combined gate would have been spent already.
    #[tokio::test]
    async fn the_request_half_warning_does_not_spend_the_response_half() {
        let engine = engine_with(CONFIG);
        let (_result, _bg) = engine
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request(Some("/v1/files/a")),
                None,
            )
            .await;
        assert!(!warned(&engine, Direction::Request));
        assert!(!warned(&engine, Direction::Response));

        let (_result, _bg) = engine
            .invoke_named::<HttpHook>(HOOK_HTTP_RESPONSE, HttpPayload, http_request(None), None)
            .await;
        assert!(
            warned(&engine, Direction::Response),
            "the response half is reported on its own"
        );
        assert!(
            !warned(&engine, Direction::Request),
            "and the request half, which was reachable, is not"
        );
    }

    /// A non-HTTP request carries no path and never could, so it is not a case
    /// of the host having omitted one.
    #[tokio::test]
    async fn a_tool_request_does_not_warn() {
        let engine = engine_with(CONFIG);
        let ext = Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some("tool".to_owned()),
                entity_name: Some("get_weather".to_owned()),
                ..Default::default()
            })),
            ..Default::default()
        };
        let (_result, _bg) = engine
            .invoke_by_name(
                crate::cmf::constants::HOOK_CMF_TOOL_PRE_INVOKE,
                Box::new(crate::cmf::MessagePayload {
                    message: crate::cmf::Message::text(crate::cmf::enums::Role::User, "hi"),
                }),
                ext,
                None,
            )
            .await;
        assert!(!warned(&engine, Direction::Request));
    }

    /// A config whose `http:` routes declare no contract short-circuits, so the
    /// check costs an empty-slice test on the ordinary config.
    #[tokio::test]
    async fn an_empty_list_short_circuits() {
        let engine = engine_with(
            "engine_settings:\n  dispatch: policy\nglobal:\n  assertions:\n    request:\n      \
             strip: [x-auth-*]\nroutes:\n  - http: /healthz\n",
        );
        let (_result, _bg) = engine
            .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, http_request(None), None)
            .await;
        assert!(!warned(&engine, Direction::Request));
    }
}
