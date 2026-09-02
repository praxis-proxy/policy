// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Unified YAML configuration parsing.
//
// Parses the config format that combines global settings, plugin
// declarations, and per-entity routes into a single YAML document.
//
// Supports two dispatch modes, selected by `engine_settings.dispatch`:
//   - `policy` (default): a policy step names the plugin it invokes,
//     with `routes:`, `groups:`, and `global:` scoping the policy.
//   - `hooks`: each plugin declares the hooks it fires at and its own
//     `conditions:` for when it fires.
//
// The two modes are mutually exclusive and each rejects the other's
// keys by name. Hook mode rejects `routes:`, `groups:`, `global:`, and
// `global.defaults:`; policy mode rejects a per-plugin `conditions:`
// and a `plugins:` activation list at any scope.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing::warn;

use crate::cmf::constants::{
    ENTITY_HTTP, ENTITY_LLM, ENTITY_NAME_GLOBAL, ENTITY_PROMPT, ENTITY_RESOURCE, ENTITY_TOOL,
};
use crate::error::PluginError;
use crate::plugin::PluginConfig;

/// Top-level PPE configuration.
///
/// Parsed from a single YAML file. Plugin scoping is controlled by
/// `engine_settings.dispatch` — under `policy` (the default) the `routes:`
/// and `global:` sections decide. Under `hooks` plugins use their own
/// `conditions:` field. Each mode rejects the other's keys at load, so a
/// document is legal in one mode only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Global configuration: always-on policy and per-entity defaults.
    /// Requires `engine_settings.dispatch: policy`; a load error under
    /// `hooks`, which resolves none of it.
    #[serde(default)]
    pub global: GlobalConfig,

    /// Plugin declarations.
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,

    /// Named policy bundles a route can join, keyed by group name. The only
    /// spelling: it lines up with `global:` (always-on defaults) and `routes:`
    /// (per-entity policy) as the third concern.
    ///
    /// Parsing folds these into [`GlobalConfig::bundles`], the internal store
    /// every resolver reads, so a resolver sees one map rather than a document
    /// field and a nested one.
    #[serde(default)]
    pub groups: HashMap<String, PolicyGroup>,

    /// Per-entity routing rules.
    /// Requires `engine_settings.dispatch: policy`; a load error under
    /// `hooks`, which resolves none of them.
    #[serde(default)]
    pub routes: Vec<RouteEntry>,

    /// Engine-wide settings (timeout, error behavior, dispatch mode).
    #[serde(default)]
    pub engine_settings: EngineSettings,
}

impl PolicyConfig {
    /// Which dispatch mode this configuration selects.
    #[must_use]
    pub fn dispatch_mode(&self) -> DispatchMode {
        self.engine_settings.dispatch
    }
}

/// What decides which plugins fire on a request.
///
/// The YAML spellings are `policy` and `hooks`. `policy` is the default: a
/// config that says nothing is read as asking for the mode where a policy
/// decides, rather than the one where every declared plugin fires on every
/// request the hooks it declares cover.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchMode {
    /// A policy step names the plugin it invokes. `routes:`, `groups:`, and
    /// `global:` scope the policy, and a per-plugin `conditions:` is rejected.
    #[default]
    Policy,

    /// Each plugin's own `conditions:` field decides when it fires, and
    /// `routes:`, `groups:`, and `global:` are rejected.
    Hooks,
}

impl DispatchMode {
    /// Whether route and global policy drive dispatch.
    #[must_use]
    pub fn is_policy(self) -> bool {
        matches!(self, Self::Policy)
    }
}

/// Accept only `policy` and `hooks`, naming both when the value is anything
/// else. A lenient parse would read a stale `dispatch: true` as a mode.
impl<'de> Deserialize<'de> for DispatchMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ModeVisitor;

        impl serde::de::Visitor<'_> for ModeVisitor {
            type Value = DispatchMode;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("`policy` or `hooks`")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<DispatchMode, E> {
                match value {
                    "policy" => Ok(DispatchMode::Policy),
                    "hooks" => Ok(DispatchMode::Hooks),
                    other => Err(E::custom(format!(
                        "unknown `dispatch` mode `{other}`, expected `policy` or `hooks`"
                    ))),
                }
            }
        }

        deserializer.deserialize_str(ModeVisitor)
    }
}

/// Engine-wide settings.
///
/// Controls executor behavior and the dispatch mode. All fields have
/// sensible defaults — a missing `engine_settings:` section is valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineSettings {
    /// What decides which plugins fire: `policy` or `hooks`. The mode
    /// decides which half of the document is legal.
    /// Under `policy` (the default) the `routes:` and `global:` sections
    /// determine which plugins fire per entity. Under `hooks` plugins use
    /// their own `conditions:` field.
    #[serde(default)]
    pub dispatch: DispatchMode,

    /// Default timeout per plugin in seconds.
    #[serde(default = "default_timeout")]
    pub plugin_timeout: u64,

    /// Whether to halt on first deny in concurrent mode.
    #[serde(default = "default_true")]
    pub short_circuit_on_deny: bool,

    /// Maximum number of entries in the routing cache.
    ///
    /// Policy mode only: hook mode resolves no routes, so nothing is cached.
    ///
    /// When the cache reaches this size, new resolutions are computed
    /// normally but not memoized — the cache rejects further inserts
    /// and emits a warning. This bounds memory growth from
    /// attacker-controlled entity names without the reasoning hazards
    /// of eviction (silently dropped entries, stale-vs-current
    /// confusion). Operators see the warning and tune the cap or
    /// investigate the entity-name growth.
    #[serde(default = "default_route_cache_max_entries")]
    pub route_cache_max_entries: usize,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            dispatch: DispatchMode::Policy,
            plugin_timeout: 30,
            short_circuit_on_deny: true,
            route_cache_max_entries: default_route_cache_max_entries(),
        }
    }
}

fn default_route_cache_max_entries() -> usize {
    10_000
}

fn default_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

/// Global configuration — applies across all routes.
///
/// Policy mode only. Carries the policy bundles top-level `groups:` declares
/// (including the reserved `all` bundle) and the per-entity-type defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// The policy bundles top-level `groups:` declares, keyed by group name.
    /// The reserved name `all` is applied to every request unconditionally.
    /// Other bundles are inherited by routes via `meta.tags`.
    ///
    /// Not a YAML key. Parsing fills it from [`PolicyConfig::groups`], so a
    /// document declares bundles in one place and every resolver reads them
    /// from one place.
    #[serde(skip)]
    pub bundles: HashMap<String, PolicyGroup>,

    /// Per-entity-type default policy groups. Keys are `tool`, `resource`,
    /// `prompt`, `llm`, and `http`; anything else is rejected at load, since a
    /// misspelled entity type would be inert rather than wrong.
    #[serde(default)]
    pub defaults: HashMap<String, PolicyGroup>,

    /// Global authentication dispatch list (YAML key `authentication:`).
    /// Inherited by every route as the first layer of identity
    /// resolution. A route appends to it (additive, the default) or
    /// replaces it with `authentication.replace_inherited: true`, and the
    /// entity default or a tag bundle the route joins can replace it the same
    /// way.
    ///
    /// Same YAML shape as the route-level `authentication:` block — see
    /// `RouteEntry.authentication` for the accepted forms.
    #[serde(default, deserialize_with = "deserialize_route_identity")]
    pub authentication: Option<crate::identity::RouteIdentityConfig>,

    /// What the engine asserts on the wire (YAML key `assertions:`), the
    /// first of the four levels a contract accumulates over. Every level
    /// stacks the way `authentication:` does, per direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertions: Option<crate::assertions::AssertionsConfig>,
}

/// A named policy group — plugins to activate and optional metadata.
///
/// The `all` group is reserved and always applied.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyGroup {
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Arbitrary metadata for tooling and audit.
    #[serde(default)]
    pub metadata: HashMap<String, String>,

    /// The bundle's activation list, which no mode accepts any more: policy
    /// mode rejects the list shape, and hook mode rejects `groups:` itself. The
    /// field is what the `plugins:` override *mapping* deserializes through, so
    /// it stays and stays empty. A bundle-wide plugin is a `run(name)` step
    /// under the bundle's `authorization:`.
    #[serde(default, deserialize_with = "deserialize_plugin_refs")]
    pub plugins: Vec<PluginRouteRef>,

    /// Authentication dispatch list contributed by this section (YAML key
    /// `authentication:`). Under `groups.<name>:` it is inherited by routes
    /// carrying that tag; under `global.defaults.<entity>:` by every route of
    /// that entity type. Either way it stacks between the global
    /// authentication (first) and the route's own authentication (last). Same
    /// YAML shape as the route-level `authentication:` block.
    #[serde(default, deserialize_with = "deserialize_route_identity")]
    pub authentication: Option<crate::identity::RouteIdentityConfig>,

    /// What the engine asserts on the wire (YAML key `assertions:`), for
    /// every route this section covers. One field serves two of the four
    /// levels, since `groups.<name>:` and `global.defaults.<entity>:` both
    /// deserialize here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertions: Option<crate::assertions::AssertionsConfig>,
}

/// A reference in a `plugins:` activation list, the shape no scope accepts any
/// more.
///
/// Policy mode rejects the list at every scope that could write one, and hook
/// mode rejects those scopes outright, so nothing fills a `Vec` of these from
/// YAML. Kept as the deserialization target the `plugins:` override mapping
/// folds to an empty `Vec` through, and as the type a host building a
/// [`PolicyConfig`] in Rust still names.
///
/// ```yaml
/// plugins:
///   - rate_limiter                     # bare name
///   - pii_scanner:                     # name with config overrides
///       config:
///         sensitivity: high
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PluginRouteRef {
    /// Just the name — activate the plugin with no config overrides.
    Name(String),
    /// Name with config overrides — single-key map.
    WithOverrides(HashMap<String, serde_json::Value>),
}

impl PluginRouteRef {
    /// Extract the plugin name from this reference.
    pub fn name(&self) -> &str {
        match self {
            Self::Name(name) => name,
            Self::WithOverrides(map) => map
                .keys()
                .next()
                .map(std::string::String::as_str)
                .unwrap_or(""),
        }
    }

    /// Extract config overrides, if any.
    pub fn overrides(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Name(_) => None,
            Self::WithOverrides(map) => map.values().next(),
        }
    }
}

/// Deserialize a `plugins:` field that may take either of two YAML shapes.
///
/// - A **sequence** is the structural activation list — each item is a
///   [`PluginRouteRef`] (bare name or single-key override map). It
///   deserializes into the `Vec` as usual, and `reject_mode_conflicts` has
///   already refused it at every scope a document can write one.
/// - A **mapping** is the APL per-plugin *override* form (e.g.
///   `plugins: { audit: { on_error: ignore } }`). It is **not** a
///   structural activation list: the override map is consumed
///   separately by the APL visitor straight from the raw YAML, so here
///   it deserializes to an empty `Vec`. The map supplies overrides;
///   policy steps still do the activating.
///
/// Null / absent → empty `Vec` (same as `#[serde(default)]`).
fn deserialize_plugin_refs<'de, D>(deserializer: D) -> Result<Vec<PluginRouteRef>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    match serde_yaml::Value::deserialize(deserializer)? {
        // Structural activation list.
        serde_yaml::Value::Sequence(items) => items
            .into_iter()
            .map(|item| serde_yaml::from_value(item).map_err(D::Error::custom))
            .collect(),
        // APL override map — owned by the APL visitor, not the
        // structural parse. See doc comment above.
        serde_yaml::Value::Mapping(_) => Ok(Vec::new()),
        // Null / absent → no structural plugins.
        serde_yaml::Value::Null => Ok(Vec::new()),
        other => Err(D::Error::custom(format!(
            "`plugins:` must be a sequence (activation list) or a mapping \
             (APL per-plugin overrides), got {other:?}"
        ))),
    }
}

/// A per-entity routing rule.
///
/// Matches one entity type (tool, resource, prompt, LLM, or generic HTTP
/// request) and determines which plugins fire.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteEntry {
    /// Match a tool by exact name, list, or glob.
    #[serde(default)]
    pub tool: Option<StringOrList>,

    /// Match a resource by exact URI, list, or glob.
    #[serde(default)]
    pub resource: Option<StringOrList>,

    /// Match a prompt by exact name, list, or glob.
    #[serde(default)]
    pub prompt: Option<StringOrList>,

    /// Match an LLM by exact model name, list, or glob.
    #[serde(default)]
    pub llm: Option<StringOrList>,

    /// Match generic HTTP requests by path, and optionally by method.
    /// Requires `engine_settings.dispatch: policy`, which is the default, so
    /// the route is live as written, like every other route selector. See
    /// [`HttpSelector`] for the three shapes.
    #[serde(default)]
    pub http: Option<HttpSelector>,

    /// Operational metadata — tags, scope, properties.
    #[serde(default)]
    pub meta: Option<RouteMeta>,

    /// Group bundles this route joins — a first-class, discoverable spelling
    /// for bundle membership. Accepts a bare string or a list:
    ///
    /// ```yaml
    /// groups: hr-tools          # single
    /// groups: [hr-tools, pii]   # multiple
    /// ```
    ///
    /// **Pure sugar over tags.** Each named group is folded into the route's
    /// tag set at resolution, so `groups: [hr-tools]` and
    /// `meta: { tags: [hr-tools] }` resolve identically, for the bundle's
    /// `authentication:` and for its `authorization:` alike. Tags remain the
    /// substrate — they can also be injected by the host at runtime and carry
    /// metadata beyond membership; `groups:` just names the common "join this
    /// bundle" case up front. See `route_static_tags` and `route_bundle_names`.
    #[serde(default)]
    pub groups: Option<StringOrList>,

    /// The route's activation list, which no mode accepts any more: policy mode
    /// rejects the list shape, and hook mode rejects `routes:` itself. The field
    /// is what the `plugins:` override *mapping* deserializes through, so it
    /// stays and stays empty. A route's plugin is a `run(name)` step under the
    /// route's `authorization:`.
    #[serde(default, deserialize_with = "deserialize_plugin_refs")]
    pub plugins: Vec<PluginRouteRef>,

    /// Authentication dispatch list for this route (YAML key
    /// `authentication:`). **Hook-specific**: applies ONLY to the
    /// `identity.resolve` hook. The one structural dispatch list policy mode
    /// keeps, now that the `plugins:` activation list above is gone: it always
    /// means "these plugins fire on identity.resolve in this order".
    ///
    /// Accepts two YAML shapes; both deserialize to the same IR.
    /// See `crate::identity::route_config::RouteIdentityConfig`.
    ///
    /// ```yaml
    /// # List form — common case, additive default
    /// authentication:
    ///   - corp-jwt
    ///   - spiffe-attestor
    ///
    /// # Object form — when the override flag is needed
    /// authentication:
    ///   replace_inherited: true
    ///   steps:
    ///     - legacy-basic-auth
    /// ```
    #[serde(default, deserialize_with = "deserialize_route_identity")]
    pub authentication: Option<crate::identity::RouteIdentityConfig>,

    /// What the engine asserts on the wire for this route (YAML key
    /// `assertions:`), the most specific of the four levels. It stacks on
    /// what the route inherits unless the direction sets
    /// `replace_inherited: true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertions: Option<crate::assertions::AssertionsConfig>,
}

/// Deserialize the `authentication:` block in a `RouteEntry`. Accepts either a YAML
/// list (treated as additive — `replace_inherited: false`) or a
/// YAML map with `replace_inherited: bool?` + `steps: [...]`. Each
/// step is either a bare plugin name (string) or a map with
/// `name:` + optional `config:`. Produces friendlier error messages
/// than `#[serde(untagged)]` would.
fn deserialize_route_identity<'de, D>(
    deserializer: D,
) -> Result<Option<crate::identity::RouteIdentityConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use crate::identity::RouteIdentityConfig;
    use serde::de::Error as _;

    // Two-stage: deserialize as opaque YAML so we can discriminate
    // list vs object shape with operator-friendly errors.
    let raw = match Option::<serde_yaml::Value>::deserialize(deserializer)? {
        None => return Ok(None),
        Some(serde_yaml::Value::Null) => return Ok(None),
        Some(v) => v,
    };

    let (replace_inherited, raw_steps): (bool, Vec<serde_yaml::Value>) = match raw {
        serde_yaml::Value::Sequence(items) => (false, items),
        serde_yaml::Value::Mapping(map) => {
            // Before either value is read, so a document with both a typo and a
            // bad `steps:` shape is told about the typo. Enforced here rather
            // than from `parse_config`, the way the step map's own set is: this
            // shape is only reachable through the deserializer.
            let unknown = unknown_keys_in(ConfigScope::Authentication, &map, &[]);
            if !unknown.is_empty() {
                return Err(D::Error::custom(format!(
                    "`authentication:` has {}",
                    unknown_keys_message(ConfigScope::Authentication, &unknown)
                )));
            }
            let replace_inherited =
                match map.get(serde_yaml::Value::String("replace_inherited".to_owned())) {
                    Some(v) => v.as_bool().ok_or_else(|| {
                        D::Error::custom("`authentication.replace_inherited` must be a boolean")
                    })?,
                    None => false,
                };
            let steps_val = map
                .get(serde_yaml::Value::String("steps".to_owned()))
                .ok_or_else(|| {
                    D::Error::custom(
                        "`authentication:` object form requires `steps:` (a list of \
                         authentication steps); did you mean to write the list form?",
                    )
                })?;
            let items = steps_val
                .as_sequence()
                .ok_or_else(|| D::Error::custom("`authentication.steps` must be a list"))?
                .clone();
            (replace_inherited, items)
        },
        _ => {
            return Err(D::Error::custom(
                "`authentication:` must be a list of steps or an object with \
                 `steps:` (and optional `replace_inherited:`)",
            ));
        },
    };

    let mut steps = Vec::with_capacity(raw_steps.len());
    for (i, raw) in raw_steps.into_iter().enumerate() {
        steps.push(parse_identity_step(raw, i).map_err(D::Error::custom)?);
    }

    Ok(Some(RouteIdentityConfig {
        steps,
        replace_inherited,
    }))
}

/// Parse one authentication step from raw YAML. Accepts either a bare
/// plugin name (string) or a map with `name:` + optional `config:`.
///
/// The map form carries a closed key set. It used to flatten anything else
/// into a forward-compat bag, which swallowed a typo and a removed key alike.
fn parse_identity_step(
    raw: serde_yaml::Value,
    index: usize,
) -> Result<crate::identity::RouteIdentityStep, String> {
    use crate::identity::RouteIdentityStep;

    match raw {
        serde_yaml::Value::String(name) => {
            if name.is_empty() {
                return Err(format!(
                    "authentication step [{index}] plugin name cannot be empty"
                ));
            }
            Ok(RouteIdentityStep {
                name,
                ..Default::default()
            })
        },
        serde_yaml::Value::Mapping(map) => {
            let unknown = unknown_keys_in(ConfigScope::AuthenticationStep, &map, &[]);
            if !unknown.is_empty() {
                return Err(format!(
                    "authentication step [{index}] has {}",
                    unknown_keys_message(ConfigScope::AuthenticationStep, &unknown)
                ));
            }
            // Lean on serde's derived Deserialize for the map shape, and
            // translate the operator-facing key `config` to the IR field
            // `config_override` (the IR uses a more explicit name to
            // distinguish from the plugin's runtime config).
            // `deny_unknown_fields` keeps this shape from drifting away from
            // the table above, which is what reports a bad key.
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct StepYaml {
                name: String,
                #[serde(default)]
                config: Option<serde_json::Value>,
            }
            let parsed: StepYaml = serde_yaml::from_value(serde_yaml::Value::Mapping(map))
                .map_err(|e| format!("authentication step [{index}]: {e}"))?;
            if parsed.name.is_empty() {
                return Err(format!(
                    "authentication step [{index}] `name:` cannot be empty"
                ));
            }
            Ok(RouteIdentityStep {
                name: parsed.name,
                config_override: parsed.config,
            })
        },
        _ => Err(format!(
            "authentication step [{index}] must be a plugin name (string) or a \
             map with `name:` (and optional `config:`)"
        )),
    }
}

/// Operational metadata on a route entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteMeta {
    /// Entity tags — drive policy group inheritance.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Host-defined grouping (virtual server ID, namespace, etc.).
    /// Used for scope matching: route scope must match request scope.
    #[serde(default)]
    pub scope: Option<String>,

    /// Arbitrary key-value metadata.
    #[serde(default)]
    pub properties: HashMap<String, String>,
}

/// An entity-name pattern. Holds the original pattern string (for
/// serialization round-tripping and operator-facing diagnostics) plus a
/// `WildMatch` matcher pre-compiled at deserialize time so route resolution
/// doesn't re-parse the pattern on every request. Custom `Serialize` /
/// `Deserialize` make this transparent to YAML — it serializes as a plain
/// string, just like the previous `String` field did.
///
/// Glob syntax (via `wildmatch`):
/// - `*` matches any sequence of characters (including empty).
/// - `?` matches any single character.
///
/// The previous hand-rolled matcher only handled trailing-`*` correctly:
/// `*suffix` patterns silently matched almost nothing, and multi-star
/// patterns like `**` accidentally matched everything. Both shapes are
/// real security footguns for scope/tool restriction rules — switching to
/// `wildmatch` gives us full single-segment glob semantics.
#[derive(Debug, Clone)]
pub struct Pattern {
    pattern: String,
    matcher: wildmatch::WildMatch,
}

impl Pattern {
    /// Compile a pattern. Done once at config load; subsequent `matches()`
    /// calls reuse the compiled `WildMatch`.
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let matcher = wildmatch::WildMatch::new(&pattern);
        Self { pattern, matcher }
    }

    /// Match the given name against the compiled pattern.
    pub fn matches(&self, name: &str) -> bool {
        self.matcher.matches(name)
    }

    /// The original pattern string (e.g., `"hr-*"`).
    pub fn as_str(&self) -> &str {
        &self.pattern
    }
}

impl Default for Pattern {
    fn default() -> Self {
        Self::new("")
    }
}

impl Serialize for Pattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.pattern)
    }
}

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Pattern::new(s))
    }
}

/// A tool matcher — single name, list of names, or glob pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    /// Single string (exact name or glob pattern). Pre-compiled at
    /// deserialize time so the route-resolution slow path doesn't re-parse
    /// on each request.
    Single(Pattern),
    /// List of exact names.
    List(Vec<String>),
}

impl Default for StringOrList {
    fn default() -> Self {
        Self::Single(Pattern::default())
    }
}

impl StringOrList {
    /// Check if this matcher matches the given name.
    pub fn matches(&self, name: &str) -> bool {
        match self {
            Self::Single(pattern) => pattern.matches(name),
            Self::List(names) => names.iter().any(|n| n == name),
        }
    }

    /// The literal values as written — the pattern string for `Single`, each
    /// element for `List`. Use where the values are exact names rather than
    /// globs to match against (e.g. group membership, which joins a bundle by
    /// its exact name).
    pub fn as_names(&self) -> Vec<&str> {
        match self {
            Self::Single(pattern) => vec![pattern.as_str()],
            Self::List(names) => names.iter().map(String::as_str).collect(),
        }
    }
}

/// A generic HTTP request matcher on a route.
///
/// Three YAML shapes. A bare string and a list hold **exact** paths, matched by
/// equality, which keeps `http:` consistent with the name selectors and makes
/// breadth explicit. The map form asks for a segment-boundary prefix with
/// `path_prefix:`, or an exact path with `path:`, and may narrow either by
/// `method:`.
///
/// ```yaml
/// http: /healthz                                   # one exact path
/// http: [/healthz, /readyz]                        # several exact paths
/// http: { path_prefix: /v1/files, method: GET }    # a prefix, GET only
/// ```
///
/// A path is matched by equality or by prefix, never by glob, so this does not
/// reuse [`Pattern`]: the segment-boundary reading is the host router's, and a
/// glob dialect here would disagree with it.
///
/// Nothing here resolves unless `engine_settings.dispatch: policy` is in effect.
/// It is the default, so this resolves as written; an `http:` route declared
/// under an explicit `dispatch: hooks` is reported at load rather than left to
/// be discovered.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum HttpSelector {
    /// One exact path.
    Path(String),
    /// Several exact paths.
    Paths(Vec<String>),
    /// A prefix or exact path, optionally narrowed by method.
    Match(HttpMatch),
}

/// The map form of [`HttpSelector`]. Exactly one of `path:` / `path_prefix:`
/// is required, which is reported per route at load rather than here, so the
/// message can name the route.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HttpMatch {
    /// Exact path, matched by byte equality, the way the host router's exact
    /// arm matches. `/api` and `/api/` are two paths, not one.
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,

    /// Segment-boundary prefix. One trailing slash is dropped at parse time,
    /// so `/api/` and `/api` are the same selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    path_prefix: Option<String>,

    /// Methods this selector accepts. Absent accepts any method.
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<StringOrList>,
}

/// The keys the map form of `http:` accepts.
const HTTP_MATCH_KEYS: &[&str] = &["path", "path_prefix", "method"];

impl HttpSelector {
    /// A selector matching one exact path, for a host building a route in Rust
    /// rather than in YAML.
    pub fn exact(path: impl Into<String>) -> Self {
        Self::Path(path.into())
    }

    /// A selector matching a segment-boundary prefix, normalized the way a
    /// parsed one is.
    pub fn prefix(prefix: &str) -> Self {
        Self::Match(HttpMatch {
            path_prefix: Some(trim_declared_slash(prefix)),
            ..HttpMatch::default()
        })
    }

    /// The paths this selector matches by byte equality. Empty for a prefix
    /// selector.
    pub fn exact_paths(&self) -> &[String] {
        match self {
            Self::Path(path) => std::slice::from_ref(path),
            Self::Paths(paths) => paths,
            Self::Match(m) => m.path.as_slice(),
        }
    }

    /// The segment-boundary prefix this selector matches, with one trailing
    /// slash already dropped unless the prefix is the root.
    pub fn path_prefix(&self) -> Option<&str> {
        match self {
            Self::Path(_) | Self::Paths(_) => None,
            Self::Match(m) => m.path_prefix.as_deref(),
        }
    }

    /// The method matcher, when the map form narrows by method. `None`
    /// accepts any method.
    pub fn method(&self) -> Option<&StringOrList> {
        match self {
            Self::Path(_) | Self::Paths(_) => None,
            Self::Match(m) => m.method.as_ref(),
        }
    }

    /// What is wrong with this selector, phrased for the operator, or `None`
    /// when it is well formed. The caller prefixes the route it came from.
    fn defect(&self) -> Option<String> {
        match self {
            Self::Path(path) => {
                if path.is_empty() {
                    return Some("declares an empty `http:` path".to_owned());
                }
                non_absolute_path_defect("http", path)
            },
            Self::Paths(paths) => {
                if paths.is_empty() {
                    Some("declares an empty `http:` list, which matches nothing".to_owned())
                } else if paths.iter().any(String::is_empty) {
                    Some("declares an empty path in its `http:` list".to_owned())
                } else {
                    paths
                        .iter()
                        .find_map(|path| non_absolute_path_defect("http", path))
                }
            },
            Self::Match(m) => {
                // An empty method, or an empty method list, narrows the route to
                // nothing. Reject it rather than loading a route that can never
                // match.
                if let Some(StringOrList::List(methods)) = &m.method
                    && methods.is_empty()
                {
                    return Some(
                        "declares an empty `http.method:` list, which matches nothing".to_owned(),
                    );
                }
                if let Some(method) = &m.method
                    && method.as_names().iter().any(|name| name.is_empty())
                {
                    return Some("declares an empty method under `http.method:`".to_owned());
                }
                // A method is compared literally, so anything but a bare token
                // matches nothing: `GET*` reads as a glob that no dialect here
                // expands, and a typo carrying a space or a slash is the same
                // dead route.
                if let Some(method) = &m.method
                    && let Some(bad) = method
                        .as_names()
                        .iter()
                        .find(|name| !is_http_method_token(name))
                {
                    return Some(format!(
                        "declares `http.method:` as '{bad}', which is not an HTTP method token; a \
                         method is compared literally, so `*` and other non-token characters \
                         match nothing"
                    ));
                }
                match (&m.path, &m.path_prefix) {
                (Some(_), Some(_)) => Some(
                    "declares both `path:` and `path_prefix:` under `http:`, which ask for \
                     different matches; keep one"
                        .to_owned(),
                ),
                (None, None) => Some(
                    "declares neither `path:` nor `path_prefix:` under `http:`; one is required"
                        .to_owned(),
                ),
                (Some(path), None) if path.is_empty() => {
                    Some("declares an empty `http.path:`".to_owned())
                },
                (None, Some(prefix)) if prefix.is_empty() => Some(
                    "declares an empty `http.path_prefix:`; write `/` for the catch-all".to_owned(),
                ),
                (Some(path), None) => non_absolute_path_defect("http.path", path),
                (None, Some(prefix)) => non_absolute_path_defect("http.path_prefix", prefix),
                }
            },
        }
    }
}

/// What is wrong with a declared path that is not absolute, or `None` when it
/// is. Matching reads the request line as given and a request path starts with
/// `/`, so a declared path that does not can never match: the route would load
/// as a dead one with no signal. `key` names the field it came from.
fn non_absolute_path_defect(key: &str, path: &str) -> Option<String> {
    (!path.starts_with('/')).then(|| {
        format!(
            "declares `{key}:` as '{path}', which is not an absolute path; a request path starts \
             with `/`, so this selector matches nothing"
        )
    })
}

/// Whether a declared method is a bare HTTP method token.
///
/// RFC 9110 `tchar`, minus `*`: the star is a token character there, but here it
/// reads as a glob, and methods are compared literally, so `GET*` would match
/// nothing.
fn is_http_method_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'+-.^_`|~".contains(&b))
}

impl<'de> Deserialize<'de> for HttpSelector {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        // Two-stage through opaque YAML so each shape gets an error naming the
        // key or entry at fault, which an untagged enum cannot do.
        match serde_yaml::Value::deserialize(deserializer)? {
            serde_yaml::Value::String(path) => Ok(Self::Path(path)),
            serde_yaml::Value::Sequence(items) => {
                let mut paths = Vec::with_capacity(items.len());
                for (i, item) in items.into_iter().enumerate() {
                    match item {
                        serde_yaml::Value::String(path) => paths.push(path),
                        _ => {
                            return Err(D::Error::custom(format!(
                                "`http:` list entry [{i}] must be a path string"
                            )));
                        },
                    }
                }
                Ok(Self::Paths(paths))
            },
            serde_yaml::Value::Mapping(map) => {
                let mut parsed = HttpMatch::default();
                for (key, value) in map {
                    let Some(key) = key.as_str() else {
                        return Err(D::Error::custom("`http:` map keys must be strings"));
                    };
                    match key {
                        "path" => parsed.path = Some(http_selector_path(key, &value)?),
                        "path_prefix" => {
                            parsed.path_prefix =
                                Some(trim_declared_slash(&http_selector_path(key, &value)?));
                        },
                        "method" => {
                            parsed.method = Some(serde_yaml::from_value(value).map_err(|e| {
                                D::Error::custom(format!(
                                    "`http.method:` must be a method name or a list of them: {e}"
                                ))
                            })?);
                        },
                        other => {
                            return Err(D::Error::custom(format!(
                                "unknown key `{other}` under `http:` (accepts {})",
                                HTTP_MATCH_KEYS.join(", ")
                            )));
                        },
                    }
                }
                Ok(Self::Match(parsed))
            },
            _ => Err(D::Error::custom(
                "`http:` must be a path, a list of paths, or a map with `path:` or \
                 `path_prefix:` (and optional `method:`)",
            )),
        }
    }
}

/// Read one path-valued key of the `http:` map form.
fn http_selector_path<E: serde::de::Error>(
    key: &str,
    value: &serde_yaml::Value,
) -> Result<String, E> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| E::custom(format!("`http.{key}:` must be a path string")))
}

/// Drop one trailing slash from a declared prefix so `/api/` and `/api` are the
/// same selector, which is how the segment-boundary prefix match reads them.
/// The root keeps its slash, since dropping it would leave nothing for
/// diagnostics to name. Prefixes only: a declared exact path keeps whatever
/// slash it was written with, because the exact match compares bytes.
fn trim_declared_slash(path: &str) -> String {
    match path.strip_suffix('/') {
        Some(trimmed) if !trimmed.is_empty() => trimmed.to_owned(),
        _ => path.to_owned(),
    }
}

/// Load and parse a PPE config from a YAML file.
/// # Errors
///
/// Returns `PluginError::Config` when the file cannot be read, and whatever
/// [`parse_config`] reports for its contents.
pub fn load_config(path: &Path) -> Result<PolicyConfig, Box<PluginError>> {
    let content = std::fs::read_to_string(path).map_err(|e| PluginError::Config {
        message: format!("failed to read config file '{}': {}", path.display(), e),
    })?;
    parse_config(&content)
}

/// Parse a PPE config from a YAML string.
/// # Errors
///
/// Returns `PluginError::Config` when the YAML does not deserialize, and when
/// the document, a route, or a section above it carries a key nothing reads.
/// An unrecognized key is rejected rather than ignored: the typed parse drops
/// one silently, so a stale `identity:` block would leave its authentication
/// steps unrun and a misspelled selector would leave a route matching nothing,
/// both of which fail open.
pub fn parse_config(yaml: &str) -> Result<PolicyConfig, Box<PluginError>> {
    // Every key check runs on the raw YAML, before the typed parse: the config
    // structs drop an unknown field, so a removed `policy:` block would
    // otherwise vanish and leave no authorization enforced, a fail-open.
    let raw: serde_yaml::Value = serde_yaml::from_str(yaml).map_err(|e| PluginError::Config {
        message: format!("failed to parse config YAML: {e}"),
    })?;
    reject_unknown_document_keys(&raw)?;
    reject_unknown_engine_settings_keys(&raw)?;
    // No visitor is registered on this path, so only praxis-policy-core's own
    // route keys are accepted. A host whose visitor reads route keys of its
    // own loads through `PolicyEngine::load_config_yaml`, which unions them in.
    reject_unknown_route_keys(&raw, &[])?;
    reject_unknown_section_keys(&raw, &[])?;
    reject_mode_conflicts(&raw)?;
    let mut config: PolicyConfig =
        serde_yaml::from_value(raw).map_err(|e| PluginError::Config {
            message: format!("failed to parse config YAML: {e}"),
        })?;
    fold_groups_into_bundles(&mut config);
    validate_config(&config)?;
    Ok(config)
}

/// Move the top-level `groups:` bundles into [`GlobalConfig::bundles`], the
/// internal store every resolver reads.
///
/// `groups:` is the only YAML input, so the two-sided merge this used to
/// perform is gone. It extends rather than assigns because the store is a public
/// field: a host that built its `PolicyConfig` in Rust and filled the store
/// directly keeps what it put there, and a name declared on both sides resolves
/// to `groups:`.
pub(crate) fn fold_groups_into_bundles(config: &mut PolicyConfig) {
    if config.groups.is_empty() {
        return;
    }
    config
        .global
        .bundles
        .extend(std::mem::take(&mut config.groups));
}

/// The removed config keys, mapped to what to write instead.
///
/// The key sets are closed, so every one of these is already rejected as an
/// unknown key. This table is what turns that rejection into guidance: the
/// unknown-key error names the replacement spelling for a key that has one,
/// and says nothing extra for a key that never worked. Each replacement is
/// written as a phrase, backticks included, because several of them are more
/// than one spelling.
const REPLACED_KEYS: [(&str, &str); 10] = [
    ("policy", "`authorization.pre_invocation`"),
    ("post_policy", "`authorization.post_invocation`"),
    ("identity", "`authentication`"),
    ("policies", "the top-level `groups:` block"),
    (
        "plugin_settings",
        "`engine_settings`, whose `routing_enabled: true` is now `dispatch: policy`",
    ),
    ("when", "a `when:` / `do:` step under `authorization:`"),
    (
        "plugin_dirs",
        "`register_factory()` plus a declaration in the `plugins:` block",
    ),
    (
        "parallel_execution_within_band",
        "`mode: concurrent` on the individual plugin",
    ),
    (
        "fail_on_plugin_error",
        "`on_error: fail` on the individual plugin",
    ),
    (
        "on_error",
        "the `on_error:` of the plugin's own `plugins:` declaration",
    ),
];

/// What replaced `key`, or `None` when nothing did.
fn replacement_for(key: &str) -> Option<&'static str> {
    REPLACED_KEYS
        .iter()
        .find_map(|(old, new)| (*old == key).then_some(*new))
}

/// What a config key is for.
///
/// The role decides how an entry is used, not just whether the key is
/// accepted. The APL runtime assembles a section's synthetic policy block from
/// the policy-language keys alone, so a table that recorded only scope and
/// owner would have it copying structural keys into the block it hands the
/// compiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// A typed field of the scope's own struct, or a block praxis-policy-core
    /// carries for another crate to model.
    Structural,

    /// A policy-language term, compiled by praxis-policy-apl-core.
    AplTerm,

    /// PPE wiring: PDPs, the session store, attribute files. Only the
    /// top-level `global:` block acts on these; elsewhere they are inert.
    EngineWiring,

    /// Accepted in two shapes with a different role in each, so the value
    /// decides. `plugins:` is the only one: a mapping carries per-plugin APL
    /// overrides, and a sequence is the activation list `reject_mode_conflicts`
    /// refuses.
    ShapeConditional,
}

/// Which crate reads a config key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOwner {
    /// praxis-policy-core's typed config model.
    Core,

    /// The APL runtime: its visitor, its compiler, or both.
    Apl,

    /// Both crates, one shape each.
    Shared,
}

/// One accepted config key: its spelling, what it is for, and who reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigKey {
    /// The YAML spelling.
    pub name: &'static str,

    /// What the key is for.
    pub role: KeyRole,

    /// Which crate reads it.
    pub owner: KeyOwner,
}

const fn structural_key(name: &'static str, owner: KeyOwner) -> ConfigKey {
    ConfigKey {
        name,
        role: KeyRole::Structural,
        owner,
    }
}

const fn apl_term_key(name: &'static str) -> ConfigKey {
    ConfigKey {
        name,
        role: KeyRole::AplTerm,
        owner: KeyOwner::Apl,
    }
}

const fn wiring_key(name: &'static str) -> ConfigKey {
    ConfigKey {
        name,
        role: KeyRole::EngineWiring,
        owner: KeyOwner::Apl,
    }
}

const fn shape_conditional_key(name: &'static str) -> ConfigKey {
    ConfigKey {
        name,
        role: KeyRole::ShapeConditional,
        owner: KeyOwner::Shared,
    }
}

/// The authorization term a section accepts, in the order a synthetic policy
/// block copies it.
///
/// A section is `global:`, `global.defaults.<entity>:`, `groups.<name>:`, or a
/// `routes[]` entry, and every one of them accepts it, so this is one table the
/// scope tables share rather than four copies that can drift. `authorization`
/// is the `{ pre_invocation, post_invocation }` form and the only place the two
/// phase lists appear; praxis-policy-apl-core un-nests it, so the nesting lives
/// in exactly one place.
const SECTION_APL_KEYS: &[ConfigKey] = &[apl_term_key("authorization")];

/// The field pipeline terms, accepted on every section but `global:`.
///
/// A field pipeline names one field of the payload a route carries, so the
/// scope has to reach a payload for the name to mean anything. `global:` covers
/// every entity route at once and has no payload of its own, which is why it
/// takes neither.
const FIELD_STAGE_KEYS: &[ConfigKey] = &[apl_term_key("args"), apl_term_key("result")];

/// The engine wiring keys, accepted under `global:` and nowhere else. A PDP,
/// the session store, and the static attribute tree are process-global, so a
/// declaration at another scope is a load error rather than a warning.
///
/// They travel with [`SECTION_APL_KEYS`] into a section's policy block because
/// that block is where the APL visitor reads them from; it strips them again
/// before the policy compiler sees them.
const GLOBAL_WIRING_KEYS: &[ConfigKey] = &[
    wiring_key("pdp"),
    wiring_key("session_store"),
    wiring_key("attribute_files"),
];

/// The keys a config document carries at top level, the [`PolicyConfig`]
/// fields.
const DOCUMENT_KEYS: &[ConfigKey] = &[
    structural_key("global", KeyOwner::Core),
    structural_key("plugins", KeyOwner::Core),
    structural_key("groups", KeyOwner::Core),
    structural_key("routes", KeyOwner::Core),
    structural_key("engine_settings", KeyOwner::Core),
];

/// The structural keys the `global:` block carries, the [`GlobalConfig`] fields
/// plus the `response:` block the APL runtime reads out of band.
const GLOBAL_STRUCTURAL_KEYS: &[ConfigKey] = &[
    structural_key("defaults", KeyOwner::Core),
    structural_key("authentication", KeyOwner::Core),
    structural_key("assertions", KeyOwner::Core),
    structural_key("response", KeyOwner::Apl),
];

/// The structural keys a policy bundle carries, the [`PolicyGroup`] fields plus
/// the `response:` block the APL runtime reads out of band.
///
/// Shared by two scopes because both deserialize to `PolicyGroup`:
/// `groups.<name>:` and `global.defaults.<entity>:`. A unit that needs the two
/// to differ splits the table.
const BUNDLE_STRUCTURAL_KEYS: &[ConfigKey] = &[
    structural_key("description", KeyOwner::Core),
    structural_key("metadata", KeyOwner::Core),
    shape_conditional_key("plugins"),
    structural_key("authentication", KeyOwner::Core),
    structural_key("assertions", KeyOwner::Core),
    structural_key("response", KeyOwner::Apl),
];

/// The structural keys a `routes[]` entry carries, the [`RouteEntry`] fields
/// plus the `response:` block the APL runtime reads out of band.
///
/// Larger than the typed fields on purpose: a route shares its mapping with
/// the orchestrator blocks the typed struct deliberately ignores, so
/// `deny_unknown_fields` would reject every APL-annotated route in the tree.
/// The policy terms and `response:` are those blocks.
const ROUTE_STRUCTURAL_KEYS: &[ConfigKey] = &[
    structural_key("tool", KeyOwner::Core),
    structural_key("resource", KeyOwner::Core),
    structural_key("prompt", KeyOwner::Core),
    structural_key("llm", KeyOwner::Core),
    structural_key("http", KeyOwner::Core),
    structural_key("meta", KeyOwner::Core),
    structural_key("groups", KeyOwner::Core),
    shape_conditional_key("plugins"),
    structural_key("authentication", KeyOwner::Core),
    structural_key("assertions", KeyOwner::Core),
    structural_key("response", KeyOwner::Apl),
];

/// The keys the `engine_settings:` block carries, the [`EngineSettings`] fields.
///
/// [`EngineSettings`] drops an unknown field, so a setting the runtime never
/// honored used to load clean and warn. The table is what makes it a load error
/// naming its per-plugin replacement.
const ENGINE_SETTINGS_KEYS: &[ConfigKey] = &[
    structural_key("dispatch", KeyOwner::Core),
    structural_key("plugin_timeout", KeyOwner::Core),
    structural_key("short_circuit_on_deny", KeyOwner::Core),
    structural_key("route_cache_max_entries", KeyOwner::Core),
];

/// The keys one map-form step of an `authentication:` block carries.
///
/// A step used to flatten every other key into a forward-compat bag, so a typo
/// and a removed `on_error:` both vanished into it. The step's failure handling
/// is the plugin declaration's, not the step's.
const AUTHENTICATION_STEP_KEYS: &[ConfigKey] = &[
    structural_key("name", KeyOwner::Core),
    structural_key("config", KeyOwner::Core),
];

/// The keys the object form of an `authentication:` block carries.
///
/// The object read `replace_inherited` and `steps` and validated nothing else,
/// so `replace_inherted: true` loaded with the flag `false` and quietly changed
/// which identity steps ran. The step map inside it already had a closed set;
/// this closes the object that holds it.
const AUTHENTICATION_KEYS: &[ConfigKey] = &[
    structural_key("steps", KeyOwner::Core),
    structural_key("replace_inherited", KeyOwner::Core),
];

/// The keys an `assertions:` block carries: one per direction.
///
/// Direction is the first level so nothing below it moves when either half
/// grows, and so a level can declare one direction and leave the other to the
/// levels above it.
const ASSERTIONS_KEYS: &[ConfigKey] = &[
    structural_key("request", KeyOwner::Core),
    structural_key("response", KeyOwner::Core),
];

/// The keys one direction of an `assertions:` block carries.
///
/// `replace_inherited` is spelled and defaulted the way `authentication:`'s is,
/// and is read per direction, so a route can replace what it inherits one way
/// while still stacking the other.
const ASSERTIONS_DIRECTION_KEYS: &[ConfigKey] = &[
    structural_key("headers", KeyOwner::Core),
    structural_key("strip", KeyOwner::Core),
    structural_key("replace_inherited", KeyOwner::Core),
];

/// The keys one asserted-header entry carries.
///
/// `from` and `members` are alternatives rather than both; the entry parser
/// refuses an entry carrying the two, since the table can only say which keys
/// exist.
const ASSERTION_HEADER_KEYS: &[ConfigKey] = &[
    structural_key("name", KeyOwner::Core),
    structural_key("from", KeyOwner::Core),
    structural_key("members", KeyOwner::Core),
    structural_key("on_missing", KeyOwner::Core),
    structural_key("encode", KeyOwner::Core),
];

/// A config scope: one mapping shape the loader reads, with one key table each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigScope {
    /// The document itself, a [`PolicyConfig`].
    Document,

    /// The top-level `global:` block.
    Global,

    /// One `global.defaults.<entity>:` block.
    EntityDefault,

    /// One `groups.<name>:` bundle.
    Group,

    /// One `routes[]` entry.
    Route,

    /// The top-level `engine_settings:` block.
    EngineSettings,

    /// The object form of an `authentication:` block, at any scope.
    Authentication,

    /// One map-form step of an `authentication:` block, at any scope.
    AuthenticationStep,

    /// An `assertions:` block, at any scope.
    Assertions,

    /// One direction of an `assertions:` block, at any scope.
    AssertionsDirection,

    /// One `headers:` entry of an `assertions:` direction, at any scope.
    AssertionHeader,
}

impl ConfigScope {
    /// Every scope, for a walk over the whole key model.
    pub const ALL: [Self; 11] = [
        Self::Document,
        Self::Global,
        Self::EntityDefault,
        Self::Group,
        Self::Route,
        Self::EngineSettings,
        Self::Authentication,
        Self::AuthenticationStep,
        Self::Assertions,
        Self::AssertionsDirection,
        Self::AssertionHeader,
    ];

    /// The scope's YAML path, for a diagnostic.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Document => "(document)",
            Self::Global => "global",
            Self::EntityDefault => "global.defaults.<entity>",
            Self::Group => "groups.<name>",
            Self::Route => "routes[]",
            Self::EngineSettings => "engine_settings",
            Self::Authentication => "an authentication block",
            Self::AuthenticationStep => "an authentication step",
            Self::Assertions => "an assertions block",
            Self::AssertionsDirection => "an assertions request or response block",
            Self::AssertionHeader => "an assertions header entry",
        }
    }

    /// The keys this scope accepts: its structural keys, then the shared
    /// authorization term, then the field pipeline terms every scope but
    /// `global:` takes, then the wiring keys `global:` alone carries.
    ///
    /// Every scope is enforced, by the checks [`parse_config`] runs.
    pub fn keys(self) -> impl Iterator<Item = &'static ConfigKey> {
        type Table = &'static [ConfigKey];
        let (structural, terms, fields, wiring): (Table, Table, Table, Table) = match self {
            Self::Document => (DOCUMENT_KEYS, &[], &[], &[]),
            Self::Global => (
                GLOBAL_STRUCTURAL_KEYS,
                SECTION_APL_KEYS,
                &[],
                GLOBAL_WIRING_KEYS,
            ),
            Self::EntityDefault | Self::Group => (
                BUNDLE_STRUCTURAL_KEYS,
                SECTION_APL_KEYS,
                FIELD_STAGE_KEYS,
                &[],
            ),
            Self::Route => (
                ROUTE_STRUCTURAL_KEYS,
                SECTION_APL_KEYS,
                FIELD_STAGE_KEYS,
                &[],
            ),
            Self::EngineSettings => (ENGINE_SETTINGS_KEYS, &[], &[], &[]),
            Self::Authentication => (AUTHENTICATION_KEYS, &[], &[], &[]),
            Self::AuthenticationStep => (AUTHENTICATION_STEP_KEYS, &[], &[], &[]),
            Self::Assertions => (ASSERTIONS_KEYS, &[], &[], &[]),
            Self::AssertionsDirection => (ASSERTIONS_DIRECTION_KEYS, &[], &[], &[]),
            Self::AssertionHeader => (ASSERTION_HEADER_KEYS, &[], &[], &[]),
        };
        structural.iter().chain(terms).chain(fields).chain(wiring)
    }
}

/// The keys a section's synthetic policy block copies verbatim, in the order it
/// copies them: the policy terms plus the wiring keys, which the APL visitor
/// reads out of that block at `global:` scope.
///
/// This is the constructive set, not an accept set. It is the union over the
/// section scopes, so it lists the field pipeline terms `global:` itself
/// rejects. `response:` is absent because it is a sibling of the policy terms
/// rather than one of them, and `plugins:` is absent because only its mapping
/// shape belongs in the block, which the caller decides from the value.
pub fn section_apl_block_keys() -> impl Iterator<Item = &'static ConfigKey> {
    SECTION_APL_KEYS
        .iter()
        .chain(FIELD_STAGE_KEYS)
        .chain(GLOBAL_WIRING_KEYS)
}

/// The engine wiring keys the top-level `global:` block carries. Read from a
/// section's policy block, and stripped from it before the policy compiler runs.
pub fn global_wiring_keys() -> impl Iterator<Item = &'static ConfigKey> {
    GLOBAL_WIRING_KEYS.iter()
}

/// The keys in `map` that `scope` does not accept, in declaration order.
///
/// A non-string key is left to the typed parse to report; every scope here
/// deserializes to a struct, so a non-string key fails there with a better
/// message than this check could give.
pub(crate) fn unknown_keys_in<'a>(
    scope: ConfigScope,
    map: &'a serde_yaml::Mapping,
    extra: &[&str],
) -> Vec<&'a str> {
    map.keys()
        .filter_map(serde_yaml::Value::as_str)
        .filter(|key| !scope.keys().any(|known| known.name == *key) && !extra.contains(key))
        .collect()
}

/// The tail of an unknown-key error: the keys, then what the scope accepts,
/// then the replacement for each key that has one.
///
/// Shared so a route and a section report a typo in the same words. The
/// replacement clauses are what a removed key gets over a misspelled one: the
/// closed key set makes both loud, and [`REPLACED_KEYS`] is what still says
/// where the removed one's contents belong.
pub(crate) fn unknown_keys_message(scope: ConfigScope, unknown: &[&str]) -> String {
    let label = if unknown.len() == 1 { "key" } else { "keys" };
    let mut message = format!(
        "unknown {label} `{}`; {} accepts {}",
        unknown.join("`, `"),
        scope.label(),
        scope
            .keys()
            .map(|known| known.name)
            .collect::<Vec<_>>()
            .join(", ")
    );
    for key in unknown {
        if let Some(replacement) = replacement_for(key) {
            message.push_str(&format!(". `{key}` was replaced by {replacement}"));
        }
    }
    message
}

/// Reject the top-level keys nothing reads, naming every one of them.
///
/// The accept set is [`ConfigScope::Document`]'s table. [`PolicyConfig`] drops
/// an unknown field, so a stale `plugin_settings:` used to load clean with every
/// engine setting discarded, `dispatch:` included, leaving the config in the
/// default mode rather than the one it declared.
///
/// # Errors
///
/// Returns `PluginError::Config` naming every unrecognized top-level key.
pub(crate) fn reject_unknown_document_keys(
    raw: &serde_yaml::Value,
) -> Result<(), Box<PluginError>> {
    let Some(map) = raw.as_mapping() else {
        return Ok(()); // Shape is the typed parse's to report.
    };
    let unknown = unknown_keys_in(ConfigScope::Document, map, &[]);
    if unknown.is_empty() {
        return Ok(());
    }
    Err(Box::new(PluginError::Config {
        message: format!(
            "config document has {}",
            unknown_keys_message(ConfigScope::Document, &unknown)
        ),
    }))
}

/// Reject the `engine_settings:` keys nothing reads, naming every one of them.
///
/// The accept set is [`ConfigScope::EngineSettings`]'s table. [`EngineSettings`]
/// drops an unknown field, so a setting the runtime never honored loaded clean
/// and left an operator to read a warning for the behavior they asked for and
/// did not get.
///
/// # Errors
///
/// Returns `PluginError::Config` naming every unrecognized key in the block.
pub(crate) fn reject_unknown_engine_settings_keys(
    raw: &serde_yaml::Value,
) -> Result<(), Box<PluginError>> {
    let Some(map) = raw
        .get("engine_settings")
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return Ok(()); // Absent, or a shape the typed parse reports.
    };
    let unknown = unknown_keys_in(ConfigScope::EngineSettings, map, &[]);
    if unknown.is_empty() {
        return Ok(());
    }
    Err(Box::new(PluginError::Config {
        message: format!(
            "`engine_settings` has {}",
            unknown_keys_message(ConfigScope::EngineSettings, &unknown)
        ),
    }))
}

/// Reject the route keys nothing reads, naming every one of them and the route.
///
/// The accept set is [`ConfigScope::Route`]'s table. An unknown field is
/// dropped by the typed parse, so a misspelled selector used to load clean and
/// leave the route matching nothing. `extra_route_keys` carries the keys
/// registered visitors consume, so a host orchestrator reading a key
/// praxis-policy-core has never heard of stays loadable.
///
/// # Errors
///
/// Returns `PluginError::Config` naming every unrecognized key on the first
/// route carrying one, with that route's index.
pub(crate) fn reject_unknown_route_keys(
    raw: &serde_yaml::Value,
    extra_route_keys: &[&str],
) -> Result<(), Box<PluginError>> {
    let Some(routes) = raw.get("routes").and_then(|r| r.as_sequence()) else {
        return Ok(());
    };
    for (i, route) in routes.iter().enumerate() {
        let Some(map) = route.as_mapping() else {
            continue; // Shape is the typed parse's to report.
        };
        if map.keys().any(|key| key.as_str().is_none()) {
            return Err(Box::new(PluginError::Config {
                message: format!("route {i} has a key that is not a string"),
            }));
        }
        let unknown = unknown_keys_in(ConfigScope::Route, map, extra_route_keys);
        if !unknown.is_empty() {
            // Every bad key at once: one load reports the whole list rather
            // than one key per attempt.
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "route {i} has {}",
                    unknown_keys_message(ConfigScope::Route, &unknown)
                ),
            }));
        }
    }
    Ok(())
}

/// Reject the keys nothing reads in the sections above a route: `global:`, each
/// `global.defaults.<entity>:`, and each bundle under `groups:`.
///
/// The same fail-open as a route's: [`GlobalConfig`] and [`PolicyGroup`] drop an
/// unknown field, so a misspelled `authorizaton:` at global scope left every
/// route unguarded and reported nothing. `extra_keys` carries the keys
/// registered visitors consume, the same list a route accepts, so an
/// orchestrator's own block stays loadable wherever it writes it.
///
/// # Errors
///
/// Returns `PluginError::Config` naming every unrecognized key in the first
/// section carrying one, with that section's path.
pub(crate) fn reject_unknown_section_keys(
    raw: &serde_yaml::Value,
    extra_keys: &[&str],
) -> Result<(), Box<PluginError>> {
    fn check(
        path: &str,
        scope: ConfigScope,
        yaml: &serde_yaml::Value,
        extra: &[&str],
    ) -> Result<(), Box<PluginError>> {
        let Some(map) = yaml.as_mapping() else {
            return Ok(()); // Shape is the typed parse's to report.
        };
        let unknown = unknown_keys_in(scope, map, extra);
        if unknown.is_empty() {
            return Ok(());
        }
        Err(Box::new(PluginError::Config {
            message: format!("`{path}` has {}", unknown_keys_message(scope, &unknown)),
        }))
    }

    fn check_bundles(
        prefix: &str,
        scope: ConfigScope,
        bundles: Option<&serde_yaml::Value>,
        extra: &[&str],
    ) -> Result<(), Box<PluginError>> {
        let Some(map) = bundles.and_then(serde_yaml::Value::as_mapping) else {
            return Ok(());
        };
        for (name, bundle) in map {
            let name = name.as_str().unwrap_or("?");
            check(&format!("{prefix}.{name}"), scope, bundle, extra)?;
        }
        Ok(())
    }

    if let Some(global) = raw.get("global") {
        check("global", ConfigScope::Global, global, extra_keys)?;
        check_bundles(
            "global.defaults",
            ConfigScope::EntityDefault,
            global.get("defaults"),
            extra_keys,
        )?;
    }
    check_bundles("groups", ConfigScope::Group, raw.get("groups"), extra_keys)?;
    Ok(())
}

/// Reject the keys only an APL visitor reads, when no visitor is registered to
/// read them.
///
/// These keys are in the accept tables because a route shares its mapping with
/// the orchestrator's blocks, and their *bodies* live only in the raw YAML: the
/// typed [`PolicyConfig`] has no field for `authorization:`, `args:`, `result:`,
/// `response:`, or the `global:` wiring. With a visitor registered that is the
/// division of labour working. With none, the load committed the typed config and
/// returned success having dropped every one of them, so a document declaring
/// `authorization: [run(audit)]`, or an unconditional `deny`, loaded clean,
/// installed no handler, and enforced nothing.
///
/// [`reject_policy_mode_with_nothing_to_dispatch`] does not cover this. It passes
/// as soon as the document declares any route, group, default, or global
/// authentication block, which the document in question does.
///
/// The predicate is [`KeyOwner::Apl`] rather than a hand-written list, so a key
/// added to the tables later cannot slip past: owning the key and reading it are
/// the same claim.
///
/// # Errors
///
/// Returns `PluginError::Config` naming the first section carrying such a key,
/// the keys, and the two ways out.
pub(crate) fn reject_apl_keys_without_a_visitor(
    raw: &serde_yaml::Value,
) -> Result<(), Box<PluginError>> {
    fn apl_keys_in(scope: ConfigScope, map: &serde_yaml::Mapping) -> Vec<&str> {
        map.keys()
            .filter_map(serde_yaml::Value::as_str)
            .filter(|name| {
                scope
                    .keys()
                    .any(|key| key.name == *name && key.owner == KeyOwner::Apl)
            })
            .collect()
    }

    fn check(
        path: &str,
        scope: ConfigScope,
        yaml: &serde_yaml::Value,
    ) -> Result<(), Box<PluginError>> {
        let Some(map) = yaml.as_mapping() else {
            return Ok(()); // Shape is the typed parse's to report.
        };
        let found = apl_keys_in(scope, map);
        if found.is_empty() {
            return Ok(());
        }
        let label = if found.len() == 1 { "key" } else { "keys" };
        Err(Box::new(PluginError::Config {
            message: format!(
                "`{path}` declares the {label} `{}`, which only an APL config visitor reads, and \
                 no visitor is registered. praxis-policy-core has no field for the body, so this \
                 load would drop it and enforce nothing. Register the APL runtime's visitor \
                 (`praxis_policy_apl_runtime::register_apl`) before loading, or write \
                 `engine_settings.dispatch: hooks` and fire each plugin at the hooks its own \
                 `hooks:` declares",
                found.join("`, `")
            ),
        }))
    }

    fn check_bundles(
        prefix: &str,
        scope: ConfigScope,
        bundles: Option<&serde_yaml::Value>,
    ) -> Result<(), Box<PluginError>> {
        let Some(map) = bundles.and_then(serde_yaml::Value::as_mapping) else {
            return Ok(());
        };
        for (name, bundle) in map {
            check(
                &format!("{prefix}.{}", name.as_str().unwrap_or("?")),
                scope,
                bundle,
            )?;
        }
        Ok(())
    }

    if let Some(global) = raw.get("global") {
        check("global", ConfigScope::Global, global)?;
        check_bundles(
            "global.defaults",
            ConfigScope::EntityDefault,
            global.get("defaults"),
        )?;
    }
    check_bundles("groups", ConfigScope::Group, raw.get("groups"))?;
    if let Some(routes) = raw.get("routes").and_then(serde_yaml::Value::as_sequence) {
        for (i, route) in routes.iter().enumerate() {
            check(&format!("routes[{i}]"), ConfigScope::Route, route)?;
        }
    }
    Ok(())
}

/// Levenshtein distance, for suggesting the name an operator meant.
/// Two rows rather than the full matrix; the strings are hook names, so
/// both stay short.
fn edit_distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = Vec::with_capacity(b_chars.len() + 1);
        // The cell to the left of the one being filled, carried forward
        // rather than read back out of the row.
        let mut left = i + 1;
        cur.push(left);
        for ((cb, up_left), up) in b_chars.iter().zip(prev.iter()).zip(prev.iter().skip(1)) {
            left = (up_left + usize::from(ca != *cb)).min(up + 1).min(left + 1);
            cur.push(left);
        }
        prev = cur;
    }
    prev.last().copied().unwrap_or(0)
}

/// The dispatch mode the raw document declares, or `None` when `dispatch:`
/// carries a value that is neither spelling.
///
/// A `None` is the typed parse's to report, so the mode checks skip rather
/// than guess which half of the document is legal. An explicit null is one of
/// those: `serde(default)` fills in only for an absent key, so a present null
/// reaches `DispatchMode`'s own `Deserialize` and is refused there by name.
fn declared_dispatch_mode(raw: &serde_yaml::Value) -> Option<DispatchMode> {
    match raw.get("engine_settings").and_then(|s| s.get("dispatch")) {
        None => Some(DispatchMode::default()),
        Some(value) => match value.as_str() {
            Some("policy") => Some(DispatchMode::Policy),
            Some("hooks") => Some(DispatchMode::Hooks),
            _ => None,
        },
    }
}

/// The document keys that only mean something under `dispatch: policy`.
const POLICY_MODE_DOCUMENT_KEYS: [&str; 3] = ["global", "groups", "routes"];

/// Reject the keys the declared dispatch mode does not accept, naming the key
/// and the mode.
///
/// The two modes are mutually exclusive, and each used to ignore the other's
/// keys silently: a `routes:` block under hook dispatch resolved nothing, and a
/// per-plugin `conditions:` under policy dispatch was never consulted. Both are
/// load errors now, so a config that asks for one mode's behavior in the other's
/// spelling says so at load rather than running inert.
///
/// # Errors
///
/// Returns `PluginError::Config` naming the offending key and the mode that
/// rejects it.
pub(crate) fn reject_mode_conflicts(raw: &serde_yaml::Value) -> Result<(), Box<PluginError>> {
    let Some(mode) = declared_dispatch_mode(raw) else {
        return Ok(()); // The value is the typed parse's to report.
    };
    match mode {
        DispatchMode::Hooks => reject_policy_keys_in_hook_mode(raw),
        DispatchMode::Policy => {
            reject_activation_lists_in_policy_mode(raw)?;
            reject_plugin_dispatch_keys_in_policy_mode(raw)
        },
    }
}

/// Reject `routes:`, `groups:`, `global:`, and `global.defaults:` under
/// `dispatch: hooks`, which resolves none of them.
///
/// `global.defaults:` is named on its own so the message points at the block an
/// operator wrote and not only at its parent.
fn reject_policy_keys_in_hook_mode(raw: &serde_yaml::Value) -> Result<(), Box<PluginError>> {
    let mut found: Vec<&str> = POLICY_MODE_DOCUMENT_KEYS
        .into_iter()
        .filter(|key| raw.get(*key).is_some())
        .collect();
    if raw.get("global").and_then(|g| g.get("defaults")).is_some() {
        found.push("global.defaults");
    }
    if found.is_empty() {
        return Ok(());
    }
    let label = if found.len() == 1 { "key" } else { "keys" };
    Err(Box::new(PluginError::Config {
        message: format!(
            "`engine_settings.dispatch: hooks` does not accept the {label} `{}`, which only \
             `dispatch: policy` resolves; under `hooks` a plugin fires at the hooks its own \
             `hooks:` declares, narrowed by its own `conditions:`",
            found.join("`, `")
        ),
    }))
}

/// Reject a `plugins:` activation list at every scope that can write one under
/// `dispatch: policy`: a route, a bundle under `groups:` including the reserved
/// `all`, and a `global.defaults.<entity>:` entry.
///
/// The mapping shape stays valid: it overrides `config`, `capabilities`, and
/// `on_error` for a plugin a policy step already invokes, which is a different
/// construct that happens to share the key.
fn reject_activation_lists_in_policy_mode(raw: &serde_yaml::Value) -> Result<(), Box<PluginError>> {
    fn reject(path: &str, section: &serde_yaml::Value) -> Result<(), Box<PluginError>> {
        if !matches!(section.get("plugins"), Some(serde_yaml::Value::Sequence(_))) {
            return Ok(());
        }
        Err(Box::new(PluginError::Config {
            message: format!(
                "`{path}` declares a `plugins:` activation list, which \
                 `engine_settings.dispatch: policy` does not accept; a policy invokes a plugin \
                 with a `run(name)` step under `authorization:`, and a step under \
                 `global.authorization:` reaches every route. A `plugins:` mapping stays valid \
                 here, overriding `config`, `capabilities`, and `on_error` for a plugin a step \
                 names"
            ),
        }))
    }

    fn reject_bundles(
        prefix: &str,
        bundles: Option<&serde_yaml::Value>,
    ) -> Result<(), Box<PluginError>> {
        let Some(map) = bundles.and_then(serde_yaml::Value::as_mapping) else {
            return Ok(());
        };
        for (name, bundle) in map {
            let name = name.as_str().unwrap_or("?");
            reject(&format!("{prefix}.{name}"), bundle)?;
        }
        Ok(())
    }

    if let Some(routes) = raw.get("routes").and_then(serde_yaml::Value::as_sequence) {
        for (i, route) in routes.iter().enumerate() {
            reject(&format!("routes[{i}]"), route)?;
        }
    }
    reject_bundles("groups", raw.get("groups"))?;
    reject_bundles(
        "global.defaults",
        raw.get("global").and_then(|g| g.get("defaults")),
    )
}

/// Reject the two per-plugin dispatch keys under `dispatch: policy`, where a
/// policy decides dispatch and neither is consulted.
///
/// `conditions:` narrows which requests a plugin fires for, and a policy already
/// decided that by naming the plugin in a step.
///
/// `priority:` orders the entries the registry holds for one hook, and policy
/// dispatch never hands it more than one. Effects run in document order
/// (`praxis-policy-apl-core`'s `evaluate_effects`), a `run(name)` step invokes the
/// single entry that name resolves to, and the runtime passes the executor a
/// one-entry slice, so there is no pair of policy-selected plugins left to order.
/// Identity resolution is declaration order too and reads no priority. This used
/// to be accepted on the claim that the registry still ordered by it, which is
/// true of the registry and not of anything policy dispatch asks the registry
/// for: the key was inert, which is the ambiguity this work exists to remove.
///
/// Only a *declared* key is rejected, which is why this reads the raw YAML. The
/// typed model defaults `priority`, so a host that set the default cannot be
/// told apart from one that set nothing; see [`reject_mode_conflicts_typed`].
fn reject_plugin_dispatch_keys_in_policy_mode(
    raw: &serde_yaml::Value,
) -> Result<(), Box<PluginError>> {
    let Some(plugins) = raw.get("plugins").and_then(serde_yaml::Value::as_sequence) else {
        return Ok(());
    };
    for plugin in plugins {
        let name = plugin
            .get("name")
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("?");
        if plugin.get("conditions").is_some() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{name}' declares `conditions:`, which \
                     `engine_settings.dispatch: policy` does not accept; a policy decides \
                     dispatch there, so the condition is never consulted. Narrow the policy that \
                     names the plugin, or write `engine_settings.dispatch: hooks` to keep the \
                     condition"
                ),
            }));
        }
        if plugin.get("priority").is_some() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{name}' declares `priority:`, which \
                     `engine_settings.dispatch: policy` does not accept; it orders the entries \
                     one hook holds, and policy dispatch never runs more than one at a time. \
                     Effects run in the order the document writes them, and a `run(name)` step \
                     invokes the one plugin it names, so the priority is never consulted. Order \
                     the steps under `authorization:` instead, or write \
                     `engine_settings.dispatch: hooks` to order by priority"
                ),
            }));
        }
    }
    Ok(())
}

/// Reject a policy-mode config that declares plugins and nothing that could
/// reach them, for a host with no orchestrator to decide it better.
///
/// A policy invokes a plugin from a step, and every scope a step can be written
/// in is one of `routes:`, `groups:`, or `global:`. A config with none of the
/// three and a non-empty `plugins:` list has no spelling left that reaches a
/// plugin, so every declared plugin is inert and no request is governed by
/// anything.
///
/// `has_visitor` turns this off, and it has to. praxis-policy-core does not
/// model `global.authorization:`, so a config whose only scope is that block
/// looks scope-less from here while an orchestrator compiles a step out of it
/// and reaches the plugin — the chain-wide replacement for an activation list.
/// A visitor also reports the same fault better: per plugin, and for configs
/// this cannot see, such as one declaring routes that still name nothing.
///
/// It is no longer the only visitor-less check, and it never covered the worst
/// case: it passes as soon as the document declares any route, group, default, or
/// global authentication block, so a route carrying `authorization:` satisfied it
/// while its policy went nowhere.
/// [`reject_apl_keys_without_a_visitor`] is what closes that. This one still
/// earns its place for the document that declares plugins and no scope at all,
/// where there is no APL key to find.
///
/// # Errors
///
/// Returns `PluginError::Config` naming the unreachable plugins.
pub(crate) fn reject_policy_mode_with_nothing_to_dispatch(
    config: &PolicyConfig,
    has_visitor: bool,
) -> Result<(), Box<PluginError>> {
    if has_visitor || !config.dispatch_mode().is_policy() || config.plugins.is_empty() {
        return Ok(());
    }
    let declares_a_policy_scope = !config.routes.is_empty()
        || !config.groups.is_empty()
        || !config.global.bundles.is_empty()
        || !config.global.defaults.is_empty()
        || config.global.authentication.is_some();
    if declares_a_policy_scope {
        return Ok(());
    }
    let names: Vec<&str> = config.plugins.iter().map(|p| p.name.as_str()).collect();
    Err(Box::new(PluginError::Config {
        message: format!(
            "`engine_settings.dispatch: policy` is the default, and this config declares \
             plugins (`{}`) with no `routes:`, `groups:`, or `global:` block to invoke them \
             from, so none of them can ever run. Write a `run(name)` step under an \
             `authorization:` block, or `engine_settings.dispatch: hooks` to fire each plugin \
             at the hooks its own `hooks:` declares",
            names.join("`, `")
        ),
    }))
}

/// Reject what the declared dispatch mode does not accept, on the typed model.
///
/// The mode-conflict checks ran on raw YAML alone, so the public
/// [`crate::engine::PolicyEngine::load_config`] and
/// [`crate::engine::PolicyEngine::from_config`] accepted all three of the shapes
/// the YAML boundary refuses. A policy-mode activation list was the worst of
/// them: [`resolve_plugins_for_entity`] returns nothing in that mode, so the
/// list loaded and sat inert.
///
/// The raw checks stay. They name YAML paths (`routes[0]`,
/// `global.defaults.tool`) that a typed model cannot reconstruct, and a document
/// deserves the better message; this is the backstop for the host that never had
/// YAML. Both run from one place per boundary, so neither can drift ahead.
///
/// `priority:` has no check here, and cannot: the field is
/// `#[serde(default = "default_priority")]`, so a host that set the default is
/// indistinguishable from one that set nothing, and refusing the default value
/// would refuse every `PluginConfig` a caller builds. The raw check catches a
/// *declared* `priority:`, which is the unambiguous half.
///
/// # Errors
///
/// Returns `PluginError::Config` naming the offending shape and the mode that
/// rejects it.
pub(crate) fn reject_mode_conflicts_typed(config: &PolicyConfig) -> Result<(), Box<PluginError>> {
    if config.dispatch_mode().is_policy() {
        reject_typed_activation_lists(config)?;
        return reject_typed_plugin_conditions(config);
    }
    reject_typed_policy_scopes(config)
}

/// A non-empty activation list under `dispatch: policy`, at either scope that
/// carries one.
///
/// A non-empty `Vec` is unambiguously a host-built list: the override *mapping*
/// deserializes to an empty one (see [`deserialize_plugin_refs`]), so YAML cannot
/// produce a non-empty `Vec` that the raw check did not already refuse.
fn reject_typed_activation_lists(config: &PolicyConfig) -> Result<(), Box<PluginError>> {
    let route_lists = config
        .routes
        .iter()
        .enumerate()
        .filter(|(_, route)| !route.plugins.is_empty())
        .map(|(i, _)| format!("routes[{i}]"));
    let bundle_lists = config
        .global
        .bundles
        .iter()
        .filter(|(_, bundle)| !bundle.plugins.is_empty())
        .map(|(name, _)| format!("groups.{name}"));
    let default_lists = config
        .global
        .defaults
        .iter()
        .filter(|(_, entry)| !entry.plugins.is_empty())
        .map(|(entity, _)| format!("global.defaults.{entity}"));
    let Some(path) = route_lists.chain(bundle_lists).chain(default_lists).next() else {
        return Ok(());
    };
    Err(Box::new(PluginError::Config {
        message: format!(
            "`{path}` carries a `plugins:` activation list, which \
             `engine_settings.dispatch: policy` does not accept; a policy invokes a plugin with a \
             `run(name)` step under `authorization:`, and a step under `global.authorization:` \
             reaches every route. The list is inert in that mode, so accepting it would enforce \
             nothing. A `plugins:` mapping stays valid, overriding `config`, `capabilities`, and \
             `on_error` for a plugin a step names"
        ),
    }))
}

/// A per-plugin `conditions:` under `dispatch: policy`, where a policy decides
/// dispatch and nothing consults the condition.
fn reject_typed_plugin_conditions(config: &PolicyConfig) -> Result<(), Box<PluginError>> {
    let Some(plugin) = config.plugins.iter().find(|p| !p.conditions.is_empty()) else {
        return Ok(());
    };
    Err(Box::new(PluginError::Config {
        message: format!(
            "plugin '{}' carries `conditions:`, which `engine_settings.dispatch: policy` does not \
             accept; a policy decides dispatch there, so the condition is never consulted. Narrow \
             the policy that names the plugin, or write `engine_settings.dispatch: hooks` to keep \
             the condition",
            plugin.name
        ),
    }))
}

/// The policy-mode scopes under `dispatch: hooks`, which resolves none of them.
fn reject_typed_policy_scopes(config: &PolicyConfig) -> Result<(), Box<PluginError>> {
    let found: Vec<&str> = [
        (!config.routes.is_empty(), "routes"),
        (!config.global.bundles.is_empty(), "groups"),
        (!config.global.defaults.is_empty(), "global.defaults"),
        (
            config.global.authentication.is_some(),
            "global.authentication",
        ),
    ]
    .into_iter()
    .filter_map(|(present, name)| present.then_some(name))
    .collect();
    if found.is_empty() {
        return Ok(());
    }
    let label = if found.len() == 1 { "scope" } else { "scopes" };
    Err(Box::new(PluginError::Config {
        message: format!(
            "`engine_settings.dispatch: hooks` does not accept the {label} `{}`, which only \
             `dispatch: policy` resolves; under `hooks` a plugin fires at the hooks its own \
             `hooks:` declares, narrowed by its own `conditions:`",
            found.join("`, `")
        ),
    }))
}

/// The dispatched hook name closest to `name`, or `None` when nothing is
/// close enough to be worth printing. The bound is relative to length:
/// `tool_pre_invoke` is four edits from `cmf.tool_pre_invoke` and
/// `cmf.prompt_pre_fetch` is six from `cmf.prompt_pre_invoke`, both
/// worth suggesting, while a genuinely unrelated name should get no
/// suggestion rather than the least-bad match in the table.
///
/// Candidates are the built-in hooks. A host's own hook name is checked
/// against the registry but not suggested, since guessing at names PPE
/// does not define would point an operator at the wrong thing.
fn nearest_known_hook(name: &str) -> Option<String> {
    crate::hooks::builtin_hook_types()
        .into_iter()
        .map(|candidate| {
            let distance = edit_distance(name, candidate.as_str());
            (distance, candidate)
        })
        .filter(|(distance, candidate)| {
            // Char counts on both sides: `distance` counts chars, so comparing it
            // against a byte length would give a multi-byte name a looser bound.
            let longest = name.chars().count().max(candidate.as_str().chars().count());
            distance * 2 <= longest
        })
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate.as_str().to_owned())
}

/// Reject a `hooks:` entry naming a hook nothing dispatches. The field
/// carried free strings that nothing checked, so a typo loaded clean and
/// the plugin never fired.
///
/// Checked against the runtime registry, not the built-in table, so a
/// host that registered its own hook metadata passes. That fixes the
/// ordering: registration has to happen before the config naming those
/// hooks loads.
fn validate_declared_hooks(config: &PolicyConfig) -> Result<(), Box<PluginError>> {
    for plugin in &config.plugins {
        for hook in &plugin.hooks {
            if crate::hooks::lookup_hook_metadata(hook).is_some() {
                continue;
            }
            let suggestion = nearest_known_hook(hook)
                .map_or_else(String::new, |near| format!("; did you mean '{near}'?"));
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' declares unknown hook '{}'{}",
                    plugin.name, hook, suggestion,
                ),
            }));
        }
    }
    Ok(())
}

/// Refuse a route whose rendered names claim [`ENTITY_NAME_GLOBAL`], the name
/// the entity-less HTTP catch-all policy is annotated under.
///
/// A route claiming it takes over the catch-all: its policy body would govern
/// every request that resolves no route while the route itself matched nothing.
/// The check reads the names the route contributes, so it holds for every
/// selector shape rather than for the one spelling that reached it, and it runs
/// whether or not routing is enabled, because the engine consults the
/// annotation table either way.
fn reject_reserved_route_names(config: &PolicyConfig) -> Result<(), Box<PluginError>> {
    for (i, route) in config.routes.iter().enumerate() {
        let Some((entity_type, names)) = route_entity_identity(route) else {
            continue;
        };
        if entity_type == ENTITY_HTTP && names.iter().any(|name| name == ENTITY_NAME_GLOBAL) {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "route {i} resolves to the name '{ENTITY_NAME_GLOBAL}', which is reserved for \
                     the catch-all policy that governs a request matching no route; a route \
                     cannot claim it"
                ),
            }));
        }
    }
    Ok(())
}

/// Validate a parsed config for structural correctness.
///
/// This checks declared hook names plus the *references* in the structural plugin
/// activation lists (`route.plugins` / `policy_group.plugins` sequences): a name
/// no declaration matches is a load error here in either mode. Whether a
/// non-empty list is *allowed* is [`reject_mode_conflicts_typed`]'s question, not
/// this one; this walk used to claim it guarded a host-built list and only ever
/// checked that the names existed. It deliberately
/// does NOT validate APL plugin references, neither `run(...)` policy steps
/// nor the APL per-plugin override *map* (which
/// [`deserialize_plugin_refs`] folds into an empty structural `Vec`, leaving
/// it for the APL visitor to consume). Those are resolved and validated at
/// dispatch-plan build time, where an unknown or unreferenced plugin is logged
/// and skipped (see `praxis-policy-apl-runtime::dispatch_plan`). Keeping praxis-policy-core's validation
/// free of APL semantics is intentional.
pub(crate) fn validate_config(config: &PolicyConfig) -> Result<(), Box<PluginError>> {
    validate_declared_hooks(config)?;
    reject_reserved_route_names(config)?;
    validate_assertions(config)?;

    let mut seen_names = HashSet::new();
    for plugin in &config.plugins {
        if !seen_names.insert(&plugin.name) {
            return Err(Box::new(PluginError::Config {
                message: format!("duplicate plugin name: '{}'", plugin.name),
            }));
        }
    }

    if config.dispatch_mode().is_policy() {
        let plugin_names: HashSet<&str> = config.plugins.iter().map(|p| p.name.as_str()).collect();

        // Authentication steps must name a declared plugin.
        let validate_authentication =
            |authentication: &Option<crate::identity::RouteIdentityConfig>,
             context: &str|
             -> Result<(), Box<PluginError>> {
                let Some(authentication) = authentication else {
                    return Ok(());
                };
                for step in &authentication.steps {
                    if !plugin_names.contains(step.name.as_str()) {
                        return Err(Box::new(PluginError::Config {
                            message: format!(
                                "{context} authentication references unknown plugin '{}'",
                                step.name
                            ),
                        }));
                    }
                }
                Ok(())
            };

        validate_authentication(&config.global.authentication, "global")?;

        // A `global.defaults` key that names no entity type never applies to
        // anything, so a typo there would be silently inert rather than wrong.
        for entity_type in config.global.defaults.keys() {
            if !SELECTOR_KEYS.contains(&entity_type.as_str()) {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "global.defaults key '{entity_type}' is not an entity type (expected one \
                         of {})",
                        SELECTOR_KEYS.join(", ")
                    ),
                }));
            }
        }

        // The name a route contributes, per entity type and scope, and the
        // first route that contributed it. Bucketing keeps the duplicate check
        // linear in the number of routes.
        let mut claimed_names: HashMap<(&str, Option<&str>), HashMap<String, usize>> =
            HashMap::new();

        for (i, route) in config.routes.iter().enumerate() {
            let declared: Vec<&str> = [
                ("tool", route.tool.is_some()),
                ("resource", route.resource.is_some()),
                ("prompt", route.prompt.is_some()),
                ("llm", route.llm.is_some()),
                ("http", route.http.is_some()),
            ]
            .into_iter()
            .filter_map(|(name, present)| present.then_some(name))
            .collect();

            if declared.is_empty() {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "route {i} has no entity matcher (need one of {})",
                        SELECTOR_KEYS.join(", ")
                    ),
                }));
            }
            if declared.len() > 1 {
                return Err(Box::new(PluginError::Config {
                    message: format!(
                        "route {i} has multiple entity matchers ({}); need exactly one of {}",
                        declared.join(", "),
                        SELECTOR_KEYS.join(", ")
                    ),
                }));
            }

            if let Some(http) = &route.http
                && let Some(defect) = http.defect()
            {
                return Err(Box::new(PluginError::Config {
                    message: format!("route {i} {defect}"),
                }));
            }

            // Two routes contributing one name under the same entity type and
            // scope would put one route's annotations under the other's key,
            // because the annotation table is keyed on exactly that triple.
            // Compare the resolved names rather than the written selectors:
            // `["/a", "/b"]` and `["/b", "/c"]` are different selectors that
            // both contribute `/b`.
            if let Some((entity_type, names)) = route_entity_identity(route) {
                let scope = route.meta.as_ref().and_then(|m| m.scope.as_deref());
                let claimed = claimed_names.entry((entity_type, scope)).or_default();
                for name in names {
                    match claimed.entry(name) {
                        // A route repeating a name inside its own list still
                        // resolves to itself, so only another route collides.
                        Entry::Occupied(first) if *first.get() != i => {
                            return Err(Box::new(PluginError::Config {
                                message: format!(
                                    "routes {} and {i} both resolve to the \
                                     {entity_type} name '{}'; two routes cannot \
                                     share a name within one entity type and scope",
                                    first.get(),
                                    first.key()
                                ),
                            }));
                        },
                        Entry::Occupied(_) => {},
                        Entry::Vacant(slot) => {
                            slot.insert(i);
                        },
                    }
                }
            }

            for plugin_ref in &route.plugins {
                if !plugin_names.contains(plugin_ref.name()) {
                    return Err(Box::new(PluginError::Config {
                        message: format!(
                            "route {} references unknown plugin '{}'",
                            i,
                            plugin_ref.name()
                        ),
                    }));
                }
            }

            // Validate the first-class `groups:` membership field: a value
            // naming no defined group is a typo, and silently ignoring it
            // can leave the route without the `authentication:` the group
            // would have supplied. `meta.tags` stays permissive: tags are
            // an open-ended, host-injectable substrate, not all of which
            // name groups. Runs after `fold_groups_into_bundles`, so
            // top-level `groups:` are already folded into the bundle store.
            if let Some(groups) = &route.groups {
                for name in groups.as_names() {
                    if !config.global.bundles.contains_key(name) {
                        return Err(Box::new(PluginError::Config {
                            message: format!("route {i} joins unknown group '{name}'"),
                        }));
                    }
                }
            }

            validate_authentication(&route.authentication, &format!("route {i}"))?;
        }

        for (group_name, group) in &config.global.bundles {
            for plugin_ref in &group.plugins {
                if !plugin_names.contains(plugin_ref.name()) {
                    return Err(Box::new(PluginError::Config {
                        message: format!(
                            "policy group '{}' references unknown plugin '{}'",
                            group_name,
                            plugin_ref.name()
                        ),
                    }));
                }
            }

            validate_authentication(
                &group.authentication,
                &format!("policy group '{group_name}'"),
            )?;
        }
    }

    Ok(())
}

/// What a declared set of `http:` routes leaves ungoverned, one message per
/// gap, empty when there is nothing to report. Only `http:` routes are
/// examined, so a configuration that declares none is never reported on.
///
/// One gap is left to report. The routing-off report that sat beside it is
/// gone: `routes:` is a load error under `dispatch: hooks`, so a config
/// carrying an `http:` route is in policy mode by construction and the branch
/// had no reachable input.
///
/// Kept separate from emission so a test reads the findings rather than a log
/// line. [`crate::engine`] emits these once per config load.
pub(crate) fn http_routing_gaps(config: &PolicyConfig) -> Vec<String> {
    let selectors: Vec<&HttpSelector> = config
        .routes
        .iter()
        .filter_map(|r| r.http.as_ref())
        .collect();
    if selectors.is_empty() {
        return Vec::new();
    }
    if selectors.iter().copied().any(is_http_catch_all) {
        return Vec::new();
    }
    vec![format!(
        "config declares `http:` routes (count={}) but none of them matches every request, so a \
         request matching none of them resolves no route and is governed by the global policy \
         instead; a route selecting `http: {{path_prefix: /}}` is what governs the rest",
        selectors.len(),
    )]
}

/// What a contract on an `http:` route depends on the host for, one message per
/// such route, empty when there is nothing to report.
///
/// A route selecting on `http:` is matched from the request line the host puts
/// on the HTTP extension, so a contract written there is in force only at an
/// invocation that carries one. Absent it the route matches nothing and the
/// levels above govern instead, and nothing errors, which makes it a security
/// control an operator cannot tell is working. Reported rather than refused:
/// whether the host populates the request line is not visible at load, and
/// failing a load over what a host might do is not this layer's call.
///
/// Kept separate from emission so a test reads the findings rather than a log
/// line, the way [`http_routing_gaps`] is.
pub(crate) fn assertions_reachability_gaps(config: &PolicyConfig) -> Vec<String> {
    config
        .routes
        .iter()
        .filter(|route| route.http.is_some() && route.assertions.is_some())
        .enumerate()
        .map(|(i, route)| {
            format!(
                "route {} declares `assertions:` on an `http:` selector, which is in force only \
                 when the host puts the request line (method and path) on the HTTP extension at \
                 that invocation. Without it no `http:` route matches and the levels above govern \
                 instead: `global.defaults.http`, then `global`. The request and the response are \
                 separate invocations, so a host supplying the request line on one and not the \
                 other applies this route's `request:` on the way in and the global `response:` on \
                 the way out, which is a contract nobody wrote",
                route_display_name(route, i),
            )
        })
        .collect()
}

/// Whether a selector matches every request, which is what makes a route the
/// explicit catch-all. A `method:` narrowing leaves the other methods
/// uncovered, so a narrowed root prefix is not one.
fn is_http_catch_all(selector: &HttpSelector) -> bool {
    selector.method().is_none()
        && selector
            .path_prefix()
            .is_some_and(|prefix| prefix.trim_matches('/').is_empty())
}

/// The selector keys a route may declare, one per entity type, and the keys
/// `global.defaults` accepts, since a default applies per entity type. Named
/// from the entity-type constants so the two spellings cannot drift.
const SELECTOR_KEYS: &[&str] = &[
    ENTITY_TOOL,
    ENTITY_RESOURCE,
    ENTITY_PROMPT,
    ENTITY_LLM,
    ENTITY_HTTP,
];

/// Specificity scores for route matching.
const SPECIFICITY_EXACT_NAME: usize = 1000;
const SPECIFICITY_NAME_LIST: usize = 500;
const SPECIFICITY_GLOB: usize = 300;
const SPECIFICITY_WILDCARD: usize = 0;

/// Specificity for an `http:` selector. An `http:` route only ever competes
/// with other `http:` routes, so paths order on their own scale and the name
/// buckets above are left alone.
///
/// An exact path outranks every prefix, however long, and among prefixes the
/// longer one wins. The per-character weight sits above the scope and `method:`
/// bonuses so prefix length decides before any tiebreaker does.
const SPECIFICITY_EXACT_PATH: usize = usize::MAX / 2;
const SPECIFICITY_PATH_PREFIX_STEP: usize = 1000;

/// The bonus a one-method `method:` narrowing adds to whatever the path scored,
/// and the ceiling of the whole method bonus. Each further method the selector
/// names gives one back, so the narrower of two selectors on one path wins.
///
/// It sits below the per-character prefix weight, so it breaks a tie within one
/// path without reordering two different paths, and below
/// [`SPECIFICITY_SCOPE_MATCH`], so a scoped route keeps winning its own scope.
const SPECIFICITY_METHOD_NARROWED: usize = 50;

/// The bonus a route scores for declaring the request's scope. Above the whole
/// method bonus, so a scoped broad route wins its own scope against a
/// method-narrowed global one on the same path.
const SPECIFICITY_SCOPE_MATCH: usize = 100;

/// Score a single entity matcher (tool / resource / prompt / llm) against
/// a request entity name, returning the specificity bucket if it matches
/// or `None` if it doesn't (or the matcher is absent). Replaces four
/// copy-pasted match arms in the entity resolver.
fn score_entity_match(matcher: Option<&StringOrList>, entity_name: &str) -> Option<usize> {
    let matcher = matcher?;
    if !matcher.matches(entity_name) {
        return None;
    }
    let score = match matcher {
        StringOrList::Single(p) if p.as_str() == "*" => SPECIFICITY_WILDCARD,
        StringOrList::Single(p) if p.as_str().contains('*') => SPECIFICITY_GLOB,
        StringOrList::List(_) => SPECIFICITY_NAME_LIST,
        StringOrList::Single(_) => SPECIFICITY_EXACT_NAME,
    };
    Some(score)
}

/// Whether a request path matches a declared prefix at a segment boundary.
///
/// Mirrors the host router's reading in `filter/src/path_match.rs`: one
/// trailing slash on the prefix is insignificant, and an empty or root prefix
/// matches every path. A path that
/// is not absolute matches nothing, which is the one deliberate difference from
/// the host: PPE matches only a path it can read as a request line, so an
/// `OPTIONS *` request resolves no route rather than the catch-all.
fn path_prefix_matches(path: &str, prefix: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    let trimmed = without_trailing_slash(prefix);
    if trimmed.is_empty() || path == trimmed {
        return true;
    }
    path.starts_with(trimmed) && path.as_bytes().get(trimmed.len()) == Some(&b'/')
}

/// A path with one trailing slash dropped, which is what makes `/api` and
/// `/api/` the same prefix. The root becomes empty, so it stays distinct from
/// every other path. The exact comparison does not use this: a declared exact
/// path is matched verbatim.
fn without_trailing_slash(path: &str) -> &str {
    path.strip_suffix('/').unwrap_or(path)
}

/// Whether a request path is the declared exact path.
///
/// A byte compare, which is exactly what the host router's `PathMatch::Exact`
/// arm does. The router matches on the request path as it arrived, so `/admin`
/// and `/admin/` reach different routes there and must reach different routes
/// here. Treating them as one would apply a route's policy to a request the
/// gateway sends somewhere else.
fn exact_path_matches(path: &str, declared: &str) -> bool {
    path == declared
}

/// The effective length of a declared prefix, which is what orders two prefixes
/// that both match one path, as the host's own prefix specificity does. A trailing slash is insignificant here too, and the
/// root counts as one character.
fn path_prefix_specificity(prefix: &str) -> usize {
    let trimmed = without_trailing_slash(prefix);
    if trimmed.is_empty() { 1 } else { trimmed.len() }
}

/// Whether a request method satisfies a selector's `method:` narrowing. An
/// absent narrowing accepts any method, and comparison ignores ASCII case the
/// way the host's own method conditions do.
fn http_method_matches(accepted: Option<&StringOrList>, method: Option<&str>) -> bool {
    let Some(accepted) = accepted else {
        return true;
    };
    let Some(method) = method else {
        return false;
    };
    accepted
        .as_names()
        .iter()
        .any(|name| name.eq_ignore_ascii_case(method))
}

/// The bonus a `method:` narrowing adds to whatever the path scored, scaled by
/// how many methods it names so the narrower of two selectors on one path wins.
/// One method takes the whole [`SPECIFICITY_METHOD_NARROWED`] and each further
/// method gives one back, with a floor of 1 so any narrowing still outranks
/// none. The gateway's own router orders routes by
/// `(is_exact, path_len, constraint_count)`, so counting the constraint rather
/// than noting its presence is how the router itself breaks this tie.
///
/// The floor makes a pathologically long method list score 1 rather than wrap
/// past an unnarrowed route, and the ceiling keeps the whole range under
/// [`SPECIFICITY_SCOPE_MATCH`] and far under
/// [`SPECIFICITY_PATH_PREFIX_STEP`].
fn method_narrowing_bonus(method: Option<&StringOrList>) -> usize {
    match normalized_methods(method) {
        None => 0,
        Some(methods) => SPECIFICITY_METHOD_NARROWED
            .saturating_sub(methods.len().saturating_sub(1))
            .max(1),
    }
}

/// Score an `http:` selector against a request path and method, or `None` when
/// it does not match. The method narrowing both gates the match and adds to the
/// score, so the narrower of two routes on one path wins whichever order they
/// are declared in. The total saturates, since an exact path already scores
/// half the range.
fn score_http_match(selector: &HttpSelector, path: &str, method: Option<&str>) -> Option<usize> {
    if !path.starts_with('/') || !http_method_matches(selector.method(), method) {
        return None;
    }
    let path_score = if let Some(prefix) = selector.path_prefix() {
        path_prefix_matches(path, prefix)
            .then(|| path_prefix_specificity(prefix).saturating_mul(SPECIFICITY_PATH_PREFIX_STEP))
    } else {
        matched_exact_path(selector, path)
            .is_some()
            .then_some(SPECIFICITY_EXACT_PATH)
    }?;
    Some(path_score.saturating_add(method_narrowing_bonus(selector.method())))
}

/// The static bundle-membership tags a route declares: its `meta.tags`
/// plus any `groups:` sugar, unified into one stream. `groups:` is only a
/// discoverable spelling for the common "join this bundle" case — it
/// desugars here into the same tag set the resolvers already match against
/// bundle names, so tags stay the single substrate (runtime-injectable and
/// metadata-bearing).
///
/// Both chains read this, which is the point. [`authentication_layers`] always
/// did; the orchestrator that layers a bundle's `authorization:` read
/// `meta.tags` directly, so a route joining a bundle through `groups:` inherited
/// its authentication steps and not its policy. With the activation lists gone,
/// authorization layering is most of what a bundle is for, so that was a
/// fail-open and not a metadata asymmetry: the route installed no handler at all.
/// [`route_bundle_names`] is how the orchestrator reads it.
///
/// Order is load-bearing beyond deduplication. `meta.tags` in declaration order
/// followed by `groups:` in declaration order is what makes `replace_inherited:`
/// well defined at bundle scope, and the policy layers have to stack in the same
/// order the authentication layers do.
fn route_static_tags(route: &RouteEntry) -> impl Iterator<Item = &str> {
    let meta_tags = route
        .meta
        .iter()
        .flat_map(|m| m.tags.iter().map(String::as_str));
    let group_tags = route.groups.iter().flat_map(StringOrList::as_names);
    meta_tags.chain(group_tags)
}

/// The bundle names a route joins, in the order their layers stack: `meta.tags`
/// first, in declaration order, then `groups:`.
///
/// The orchestrator's read of `route_static_tags`, so the policy chain and the
/// authentication chain cannot disagree about which bundles a route is in. It
/// used to read `meta.tags` alone, which left `groups:` inheriting authentication
/// and not authorization. Both readers are private, so neither is linked here.
///
/// Deduplicated, first-seen wins. A name written in both spellings is one
/// membership: stacking its layer twice would run the bundle's steps twice.
///
/// Static tags only. A tag the host injected at runtime contributes no bundle
/// here, the same way it contributes none of a bundle's `authentication:` steps.
pub fn route_bundle_names(route: &RouteEntry) -> Vec<String> {
    let mut seen = HashSet::new();
    route_static_tags(route)
        .filter(|name| seen.insert(*name))
        .map(str::to_owned)
        .collect()
}

/// The entity type a route selects on and the names it contributes, or `None`
/// when it declares no selector.
///
/// This is the one mapping from a route to the names it is known by: the key an
/// orchestrator annotates under and the name a request resolves to both come
/// from here, so neither can drift from the other. Precedence is `tool`,
/// `resource`, `prompt`, `llm`, then `http`, and a list selector contributes
/// one name per element so each element routes on its own.
pub fn route_entity_identity(route: &RouteEntry) -> Option<(&'static str, Vec<String>)> {
    if let Some(tool) = &route.tool {
        return Some((ENTITY_TOOL, selector_names(tool)));
    }
    if let Some(resource) = &route.resource {
        return Some((ENTITY_RESOURCE, selector_names(resource)));
    }
    if let Some(prompt) = &route.prompt {
        return Some((ENTITY_PROMPT, selector_names(prompt)));
    }
    if let Some(llm) = &route.llm {
        return Some((ENTITY_LLM, selector_names(llm)));
    }
    if let Some(http) = &route.http {
        return Some((ENTITY_HTTP, http_selector_names(http)));
    }
    None
}

/// The names a name selector contributes: the pattern as written, or one name
/// per list element.
fn selector_names(selector: &StringOrList) -> Vec<String> {
    selector.as_names().into_iter().map(str::to_owned).collect()
}

/// The names an `http:` selector contributes. An exact path narrowed by nothing
/// contributes the path itself, since that is the path a request arrives on.
/// Every other shape renders the fields the match consumed ahead of the path,
/// which no request path can equal because a path starts with `/`.
///
/// An exact path is rendered verbatim. Matching compares it byte for byte, so
/// `/admin` and `/admin/` are two routes matching two different requests, and
/// each renders its own name.
fn http_selector_names(selector: &HttpSelector) -> Vec<String> {
    let methods = rendered_methods(selector.method());
    if let Some(prefix) = selector.path_prefix() {
        return vec![rendered_prefix_name(prefix, methods.as_deref())];
    }
    selector
        .exact_paths()
        .iter()
        .map(|declared| rendered_exact_name(declared, methods.as_deref()))
        .collect()
}

/// The one name a prefix selector renders, for the methods it narrows by or for
/// none.
fn rendered_prefix_name(prefix: &str, methods: Option<&str>) -> String {
    match methods {
        Some(methods) => format!("{methods} prefix:{prefix}"),
        None => format!("prefix:{prefix}"),
    }
}

/// The one name a declared exact path renders. Both the names a selector
/// contributes and the name a request resolves to render here, so the resolved
/// name is the annotation key by construction rather than because two walks of
/// the path list happen to agree.
fn rendered_exact_name(declared: &str, methods: Option<&str>) -> String {
    match methods {
        Some(methods) => format!("{methods} path:{declared}"),
        None => declared.to_owned(),
    }
}

/// The method set a selector narrows by, or `None` when it accepts any method.
/// Uppercased, sorted, and deduplicated so the set follows what matching reads
/// rather than the order or case it was written in, and holds across reloads.
/// Matching ignores case, so `GET` and `get` are one method, which is what makes
/// this both the name a route renders and the count that scores its narrowing.
fn normalized_methods(method: Option<&StringOrList>) -> Option<Vec<String>> {
    let mut methods: Vec<String> = method?
        .as_names()
        .iter()
        .map(|name| name.to_ascii_uppercase())
        .collect();
    methods.sort_unstable();
    methods.dedup();
    Some(methods)
}

/// The method set as it appears in a rendered route name.
fn rendered_methods(method: Option<&StringOrList>) -> Option<String> {
    Some(normalized_methods(method)?.join(","))
}

/// The name a matching name selector resolves to: the matched element for a
/// list, the pattern as written for a single. Drawn from the names the route
/// contributes, so a resolved name cannot differ from an annotated one.
fn matched_selector_name(selector: &StringOrList, entity_name: &str) -> Option<String> {
    let names = selector_names(selector);
    match selector {
        // List elements match by equality, so the matched element is the name.
        StringOrList::List(_) => names.into_iter().find(|name| name == entity_name),
        // A single pattern contributes itself, glob or not.
        StringOrList::Single(_) => names.into_iter().next(),
    }
}

/// The name a matching `http:` selector resolves to: the rendered prefix name
/// for a prefix, and the rendered name of the declared path the request equals
/// for the exact shapes.
///
/// The name is the path as declared, so it comes from the configuration rather
/// than from the request. The cache and the annotation table then key on the
/// config rather than on the traffic.
fn matched_http_name(selector: &HttpSelector, path: &str) -> Option<String> {
    let methods = rendered_methods(selector.method());
    if let Some(prefix) = selector.path_prefix() {
        return Some(rendered_prefix_name(prefix, methods.as_deref()));
    }
    Some(rendered_exact_name(
        matched_exact_path(selector, path)?,
        methods.as_deref(),
    ))
}

/// The declared exact path a request path equals, borrowed from the selector,
/// or `None` when it equals none of them. Borrowing is what keeps route
/// resolution from rendering a name per declared path and discarding all but
/// one: only the borrowed path is rendered. It is also the single place that
/// decides which declared path a request matched, so scoring and naming cannot
/// pick different ones.
fn matched_exact_path<'a>(selector: &'a HttpSelector, path: &str) -> Option<&'a str> {
    selector
        .exact_paths()
        .iter()
        .map(String::as_str)
        .find(|declared| exact_path_matches(path, declared))
}

/// The request description route resolution matches against.
///
/// The four name selectors match against `name`. A generic HTTP request matches
/// on its path and method instead, because a path is never the name a request
/// arrives under.
#[derive(Debug, Clone, Copy)]
pub struct RouteQuery<'a> {
    entity_type: &'a str,
    name: &'a str,
    path: &'a str,
    method: Option<&'a str>,
    scope: Option<&'a str>,
}

impl<'a> RouteQuery<'a> {
    /// A request matched by entity name, which is every entity type but generic
    /// HTTP. The path is left empty, so an HTTP query built this way matches no
    /// `http:` route.
    pub fn named(entity_type: &'a str, name: &'a str) -> Self {
        Self {
            entity_type,
            name,
            path: "",
            method: None,
            scope: None,
        }
    }

    /// A generic HTTP request. The path must already be normalized: matching
    /// reads it as given, and a path that is not absolute matches nothing.
    pub fn http(path: &'a str, method: Option<&'a str>) -> Self {
        Self {
            entity_type: ENTITY_HTTP,
            name: "",
            path,
            method,
            scope: None,
        }
    }

    /// Narrow the query to the request's scope.
    #[must_use]
    pub fn with_scope(mut self, scope: Option<&'a str>) -> Self {
        self.scope = scope;
        self
    }
}

/// A route that matched a request, with the name the request resolved to.
///
/// The name is the selector value that matched rather than anything the request
/// carried, so it is config rather than traffic: a request path never becomes a
/// cache key or an annotation key.
#[derive(Debug, Clone)]
pub struct MatchedRoute<'a> {
    /// The route that won.
    pub route: &'a RouteEntry,

    /// The resolved name, which is one of the names
    /// [`route_entity_identity`] contributes for this route.
    pub name: String,
}

/// The plugins a request activates structurally, with no policy consulted.
///
/// Under `dispatch: hooks` that is every declared plugin, which the executor
/// then narrows by each plugin's own `conditions:`.
///
/// **Under `dispatch: policy` it is nothing, and can be nothing.** The four
/// activation lists it used to fold — the `all` bundle, the entity type's
/// defaults, the bundles a route joins by tag, and the route's own `plugins:` —
/// are load errors in that mode, because a policy invokes a plugin with a
/// `run(name)` step. A step under `global.authorization:` is what reaches every
/// route, and that path runs through the APL route handler rather than here.
///
/// The entity type and the matched route are gone from the signature with those
/// lists: nothing left in either branch reads them.
pub fn resolve_plugins_for_entity(config: &PolicyConfig) -> Vec<ResolvedPlugin> {
    if config.dispatch_mode().is_policy() {
        return Vec::new();
    }
    config
        .plugins
        .iter()
        .map(|p| ResolvedPlugin {
            name: p.name.clone(),
            config_overrides: None,
        })
        .collect()
}

/// One layer of `authentication:` steps and where it came from.
///
/// The resolver and the load-time drop report both fold this sequence, so
/// what an operator is told matches what dispatch does by construction.
struct SectionLayer<'a, T> {
    /// The layer's source, for a report that has to name it.
    source: SectionSource<'a>,
    /// The block the layer contributes, flag included.
    config: &'a T,
}

/// Which of the four config levels a layer is declared at.
///
/// Shared by every chain that accumulates over the levels, so two chains cannot
/// name the same level differently or stack it in a different place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionSource<'a> {
    /// The top-level `global:` block, inherited by every route.
    Global,
    /// A `global.defaults.<entity>:` block, named by the entity type it
    /// covers.
    EntityDefault(&'a str),
    /// A tag bundle's block, named by the bundle.
    Bundle(&'a str),
    /// The route's own block.
    Route,
}

impl SectionSource<'_> {
    /// How a report names the layer.
    fn label(self) -> String {
        match self {
            Self::Global => "global".to_owned(),
            Self::EntityDefault(entity_type) => format!("global.defaults.{entity_type}"),
            Self::Bundle(tag) => format!("groups.{tag}"),
            Self::Route => "the route".to_owned(),
        }
    }

    /// The level, without the name that identifies which section it is.
    fn level(self) -> crate::assertions::AssertionLevel {
        use crate::assertions::AssertionLevel;
        match self {
            Self::Global => AssertionLevel::Global,
            Self::EntityDefault(_) => AssertionLevel::EntityDefault,
            Self::Bundle(_) => AssertionLevel::Bundle,
            Self::Route => AssertionLevel::Route,
        }
    }
}

/// The layers of one inherited block that apply to a route, in the order they
/// stack: global, the entity type's default, each bundle the route joins, then
/// the route.
///
/// One walk for every chain that layers this way, so `authentication:` and
/// `assertions:` cannot drift apart about which sections contribute or in what
/// order. Each caller supplies only how to read its own block out of a section.
///
/// Bundle order is `meta.tags` in declaration order followed by `groups:`, which
/// is [`route_bundle_names`] order, deduplicated first-seen-wins. A name written
/// in both spellings is one membership: stacking its layer twice would apply the
/// bundle's contribution twice.
///
/// `request_entity_type` is what lets an entity default apply to a request that
/// matched no route: the level covers an entity type rather than a route, and a
/// generic-HTTP request that selected none of the `http:` routes is still a
/// generic-HTTP request. A matched route's own entity type wins when there is
/// one, since that is the type the level is keyed on. A caller with nothing to
/// say passes `None` and the entity default applies only through a route.
fn section_layers<'a, T>(
    config: &'a PolicyConfig,
    route: Option<&'a RouteEntry>,
    request_entity_type: Option<&'a str>,
    from_global: impl Fn(&'a GlobalConfig) -> Option<&'a T>,
    from_section: impl Fn(&'a PolicyGroup) -> Option<&'a T>,
    from_route: impl Fn(&'a RouteEntry) -> Option<&'a T>,
) -> Vec<SectionLayer<'a, T>> {
    let mut layers: Vec<SectionLayer<'a, T>> = Vec::new();
    if let Some(block) = from_global(&config.global) {
        layers.push(SectionLayer {
            source: SectionSource::Global,
            config: block,
        });
    }
    let entity_type = route
        .and_then(route_entity_identity)
        .map(|(entity_type, _)| entity_type)
        .or(request_entity_type);
    if let Some(entity_type) = entity_type
        && let Some(default) = config.global.defaults.get(entity_type)
        && let Some(block) = from_section(default)
    {
        layers.push(SectionLayer {
            source: SectionSource::EntityDefault(entity_type),
            config: block,
        });
    }
    let Some(route) = route else { return layers };
    let mut joined: Vec<&str> = Vec::new();
    for tag in route_static_tags(route) {
        if joined.contains(&tag) {
            continue;
        }
        joined.push(tag);
        if let Some(bundle) = config.global.bundles.get(tag)
            && let Some(block) = from_section(bundle)
        {
            layers.push(SectionLayer {
                source: SectionSource::Bundle(tag),
                config: block,
            });
        }
    }
    if let Some(block) = from_route(route) {
        layers.push(SectionLayer {
            source: SectionSource::Route,
            config: block,
        });
    }
    layers
}

/// The `authentication:` layers that apply to a route, in the order they
/// stack: global, the entity type's default, each tag bundle the route joins,
/// then the route.
///
/// That is the order the policy layers stack in, and the two chains have to
/// agree: a `global.defaults.<entity>:` block contributing its policy but not
/// its authentication would be a key accepted and honored by half.
///
/// Bundle order is `meta.tags` in declaration order followed by `groups:` in
/// declaration order, which is what [`route_static_tags`] yields. That order is
/// what makes `replace_inherited:` well defined at bundle scope: which bundle
/// replaces, and which bundles survive after it, are both readable from the
/// document rather than from a map's iteration order.
///
/// **Static tags only, deliberately.** A bundle a request joins by a tag the
/// host injected at runtime contributes no authentication steps, because
/// threading the request's tags in would be a signature change past this work's
/// edge. Nothing else reads runtime tags any more either, so the asymmetry the
/// note used to record is gone with the activation lists.
fn authentication_layers<'a>(
    config: &'a PolicyConfig,
    route: Option<&'a RouteEntry>,
) -> Vec<SectionLayer<'a, crate::identity::RouteIdentityConfig>> {
    // `None`: identity layers reach a request through its route, and threading a
    // request's entity type into that chain is a change to which plugins fire.
    section_layers(
        config,
        route,
        None,
        |global| global.authentication.as_ref(),
        |section| section.authentication.as_ref(),
        |route| route.authentication.as_ref(),
    )
}

/// The `assertions:` layers that apply to a route, in the order they stack.
///
/// The same four levels `authentication:` stacks over, walked by the same
/// function, which is what keeps a route's two chains from disagreeing about
/// which sections reach it.
fn assertions_layers<'a>(
    config: &'a PolicyConfig,
    route: Option<&'a RouteEntry>,
    request_entity_type: Option<&'a str>,
) -> Vec<SectionLayer<'a, crate::assertions::AssertionsConfig>> {
    section_layers(
        config,
        route,
        request_entity_type,
        |global| global.assertions.as_ref(),
        |section| section.assertions.as_ref(),
        |route| route.assertions.as_ref(),
    )
}

/// Resolve the identity-resolve dispatch list for a specific
/// entity. The one structural dispatch list policy mode keeps
/// — consults the global `authentication:` block, the entity type's
/// `global.defaults.<entity>.authentication:` block, tag-bundle
/// `authentication:` blocks, and the route's own `authentication:` block
/// to determine which plugins fire on the `identity.resolve` hook for
/// this route.
///
/// # Inheritance / merge order
///
/// Layers stack **global → entity default → tag bundles → route**, the order
/// `authentication_layers` yields, which is the order the policy layers stack
/// in. Each layer appends to the running list, and a layer whose block sets
/// `replace_inherited: true` drops everything accumulated before it first. The
/// flag is honored at every scope it can be written at: a route's drops every
/// inherited layer, and an entity default's or a bundle's drops what came
/// before it while the layers after it still append.
///
/// A flag set above the route removes authentication from a route whose own
/// author never wrote it, so `dropped_inherited_authentication` names every
/// route that loses steps that way, once per config load.
///
/// Order matters: returned plugins fire in the order they were
/// merged. The first plugin's resolved `IdentityPayload` flows into
/// the second plugin's input via the executor's Sequential-phase
/// semantics, so global identity contributions land first, then the
/// entity default's, then tag-bundle, then route-specific overrides /
/// additions.
///
/// Per-step `config_override` is surfaced as
/// `ResolvedPlugin.config_overrides` so the standard
/// `filter_entries_by_route` override pathway
/// (`create_override_instance`) applies. It is the only input to that pathway
/// now that no scope carries a `plugins:` activation list.
///
/// Returns an empty `Vec` when no layer contributed any steps
/// (e.g. anonymous routes that explicitly opt out via
/// `replace_inherited: true` + empty `steps: []`).
pub fn resolve_identity_plugins_for_route(
    config: &PolicyConfig,
    matched: Option<&MatchedRoute<'_>>,
) -> Vec<ResolvedPlugin> {
    // No matched route means there is no route to inherit identity FOR (the
    // global layer still applies, since the host might be doing per-route hook
    // routing on the entity type alone with no specific route).
    let mut steps: Vec<crate::identity::RouteIdentityStep> = Vec::new();
    for layer in authentication_layers(config, matched.map(|m| m.route)) {
        if layer.config.replace_inherited {
            steps.clear();
        }
        steps.extend(layer.config.steps.iter().cloned());
    }

    steps
        .into_iter()
        .map(|step| ResolvedPlugin {
            name: step.name.clone(),
            // Surface config_override under the `config:` key shape
            // that `create_override_instance` already understands —
            // it reads `overrides.get("config")` to find the merge
            // target. Wrapping like this avoids a special-case path.
            config_overrides: step.config_override.as_ref().map(|cfg| {
                let mut wrapper = serde_json::Map::new();
                wrapper.insert("config".to_owned(), cfg.clone());
                serde_json::Value::Object(wrapper)
            }),
        })
        .collect()
}

/// A route whose inherited `authentication:` steps a tag bundle dropped.
///
/// Kept separate from emission so a test reads the finding rather than a log
/// line, the way [`http_routing_gaps`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DroppedAuthentication {
    /// The affected route, named by the entity it selects.
    pub route: String,
    /// The section whose `replace_inherited: true` did the dropping, as
    /// [`SectionSource::label`] names it.
    pub declared_in: String,
    /// The step names the route no longer runs, in the order they stacked.
    pub dropped: Vec<String>,
}

/// Every route whose inherited `authentication:` steps a section above it
/// drops with `replace_inherited: true`, one finding per route.
///
/// A route's own flag is not reported: that drop is written in the route being
/// affected, so its author can see it. A bundle's or an entity default's is
/// written somewhere else entirely, and it is the route's author who ends up
/// with a route that authenticates less than the document in front of them
/// says. A route setting its own flag is silent for the same reason: the
/// route's block replaces whatever the sections above left, so nothing is lost
/// that the route did not discard itself.
///
/// Reports the first such section, since that is the one whose removal reaches
/// back past the route's own tags to the global layer.
pub(crate) fn dropped_inherited_authentication(
    config: &PolicyConfig,
) -> Vec<DroppedAuthentication> {
    let mut findings: Vec<DroppedAuthentication> = Vec::new();
    for (i, route) in config.routes.iter().enumerate() {
        if route
            .authentication
            .as_ref()
            .is_some_and(|id| id.replace_inherited)
        {
            continue;
        }
        let mut steps: Vec<&str> = Vec::new();
        for layer in authentication_layers(config, Some(route)) {
            // Global cannot drop anything: it stacks first, so nothing has
            // accumulated by the time its flag is read. Route is the author's
            // own choice, handled above. What is left is the sections between.
            let declared_away_from_the_route = matches!(
                layer.source,
                SectionSource::EntityDefault(_) | SectionSource::Bundle(_)
            );
            if declared_away_from_the_route && layer.config.replace_inherited && !steps.is_empty() {
                findings.push(DroppedAuthentication {
                    route: route_display_name(route, i),
                    declared_in: layer.source.label(),
                    dropped: steps.iter().map(|s| (*s).to_owned()).collect(),
                });
                break;
            }
            if layer.config.replace_inherited {
                steps.clear();
            }
            steps.extend(layer.config.steps.iter().map(|s| s.name.as_str()));
        }
    }
    findings
}

/// The `assertions:` contract in force for a request, in one direction.
///
/// Accumulates over the four levels in the order they stack: global, the
/// entity type's default, each bundle the route joins, then the route. A level
/// setting `replace_inherited: true` for this direction drops what accumulated
/// before it and then contributes, and the flag reaches operator-authored
/// content only: the unconditional removal of an entry's target, the fixed
/// source exclusions, and the two protocol floors are all outside it.
///
/// `headers:` unions by target header name, compared case-insensitively, and a
/// repeated name takes the more specific level's entry **whole**, members and
/// `on_missing` included. Never merged inside an entry: a members object
/// composed from two levels would have no author and no single level could be
/// pointed at for what it renders. `strip:` unions and deduplicates, so a
/// subordinate level cannot narrow an inherited removal by omitting it.
///
/// `matched: None` with a `request_entity_type` accumulates global plus that
/// entity type's default: the default covers an entity type rather than a route,
/// so a generic-HTTP request that selected none of the `http:` routes is still
/// governed by `global.defaults.http`. With neither, only global applies.
///
/// Returns `None` when no level declared this direction at all, which is
/// distinct from a contract that accumulated to empty because a
/// `replace_inherited` cleared it and added nothing.
#[must_use]
pub fn resolve_assertions_for_route(
    config: &PolicyConfig,
    matched: Option<&MatchedRoute<'_>>,
    request_entity_type: Option<&str>,
    direction: crate::assertions::Direction,
) -> Option<crate::assertions::ResolvedContract> {
    use crate::assertions::{AssertionLevel, ResolvedContract, ResolvedHeader};

    let mut contract = ResolvedContract::default();
    let mut declared = false;
    for layer in assertions_layers(config, matched.map(|m| m.route), request_entity_type) {
        let Some(block) = direction.block_of(layer.config) else {
            continue;
        };
        declared = true;
        if block.replace_inherited {
            contract.headers.clear();
            contract.strip.clear();
        }
        let level = layer.source.level();
        let declared_in = layer.source.label();
        for entry in &block.headers {
            let lowercase = entry.name.to_lowercase();
            let resolved = ResolvedHeader {
                name: entry.name.clone(),
                lowercase: lowercase.clone(),
                source: resolve_entry_source(entry),
                on_missing: entry.on_missing,
                encode: entry.encode,
                declared_in: declared_in.clone(),
                level,
                overrode: None,
            };
            match contract
                .headers
                .iter()
                .position(|held| held.lowercase == lowercase)
            {
                // The later level wins, in the position the earlier one held,
                // so iteration order stays the order the levels contributed in.
                Some(at) => {
                    let previous = contract
                        .headers
                        .get(at)
                        .map(|held| held.declared_in.clone());
                    // Bundles have no order among themselves, so two of them
                    // naming one header would make this a coin toss. Config
                    // load refuses that, and this is where the refusal is
                    // relied on rather than assumed.
                    debug_assert!(
                        !(level == AssertionLevel::Bundle
                            && contract
                                .headers
                                .get(at)
                                .is_some_and(|held| held.level == AssertionLevel::Bundle)),
                        "two bundles both assert `{}`, which config load rejects",
                        entry.name
                    );
                    if let Some(slot) = contract.headers.get_mut(at) {
                        *slot = ResolvedHeader {
                            overrode: previous,
                            ..resolved
                        };
                    }
                },
                None => contract.headers.push(resolved),
            }
        }
        for pattern in &block.strip {
            // Folded the way the matcher folds, so `X-Auth-*` at one level and
            // `x-auth-*` at another are one entry rather than two that remove
            // the same headers. The first level to declare it sets the spelling
            // the artifact shows.
            let folded = pattern.as_str().to_lowercase();
            if !contract
                .strip
                .iter()
                .any(|held| held.as_str().to_lowercase() == folded)
            {
                contract.strip.push(pattern.clone());
            }
        }
    }
    declared.then_some(contract)
}

/// Parse an entry's authored source paths.
///
/// Every path parsed at config load, so a failure here cannot happen. It is
/// reported and the entry kept rather than dropped, because dropping it would
/// take its target out of the removal set and leave a client-supplied value
/// standing under an asserted name.
fn resolve_entry_source(
    entry: &crate::assertions::HeaderEntry,
) -> crate::assertions::ResolvedSource {
    use crate::assertions::{AuthoredSource, ResolvedSource, SourcePath};

    match &entry.source {
        AuthoredSource::From(path) => match SourcePath::parse(path) {
            Ok(parsed) => ResolvedSource::From(parsed),
            Err(cause) => {
                warn!(
                    header = %entry.name,
                    error = %cause,
                    "an assertions source did not parse after config load accepted it",
                );
                ResolvedSource::Unresolvable
            },
        },
        AuthoredSource::Members(members) => {
            let mut parsed = Vec::with_capacity(members.len());
            for (member, path) in members {
                match SourcePath::parse(path) {
                    Ok(source) => parsed.push((member.clone(), source)),
                    Err(cause) => {
                        warn!(
                            header = %entry.name,
                            member = %member,
                            error = %cause,
                            "an assertions member source did not parse after config load accepted \
                             it",
                        );
                        return ResolvedSource::Unresolvable;
                    },
                }
            }
            ResolvedSource::Members(parsed)
        },
    }
}

/// A route whose inherited `assertions:` content a section above it dropped.
///
/// Kept separate from emission so a test reads the finding rather than a log
/// line, the way [`http_routing_gaps`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DroppedAssertions {
    /// The affected route, named by the entity it selects.
    pub route: String,
    /// Which direction lost content, as [`crate::assertions::Direction::label`]
    /// spells it.
    pub direction: &'static str,
    /// The section whose `replace_inherited: true` did the dropping.
    pub declared_in: String,
    /// The header names the route no longer asserts.
    pub dropped_headers: Vec<String>,
    /// The `strip:` patterns the route no longer applies.
    pub dropped_strip: Vec<String>,
}

/// Every route whose inherited `assertions:` content a section above it drops
/// with `replace_inherited: true`, one finding per route and direction.
///
/// A route's own flag is not reported: that drop is written in the route being
/// affected, so its author can see it. A section's is written somewhere else
/// entirely, and it is the route's author who ends up asserting less, or
/// removing less, than the document in front of them says. Global cannot drop
/// anything, since nothing has accumulated by the time its flag is read.
pub(crate) fn dropped_inherited_assertions(config: &PolicyConfig) -> Vec<DroppedAssertions> {
    config
        .routes
        .iter()
        .enumerate()
        .flat_map(|(i, route)| {
            dropped_inherited_assertions_for(config, route, &route_display_name(route, i))
        })
        .collect()
}

/// What one route loses to a `replace_inherited: true` above it, per direction.
///
/// Split out so the effective-policy artifact and the load-time report tell one
/// story about one route rather than two that can drift.
pub(crate) fn dropped_inherited_assertions_for(
    config: &PolicyConfig,
    route: &RouteEntry,
    route_label: &str,
) -> Vec<DroppedAssertions> {
    let mut findings: Vec<DroppedAssertions> = Vec::new();
    for direction in [
        crate::assertions::Direction::Request,
        crate::assertions::Direction::Response,
    ] {
        let route_replaces = route
            .assertions
            .as_ref()
            .and_then(|a| direction.block_of(a))
            .is_some_and(|block| block.replace_inherited);
        if route_replaces {
            continue;
        }
        let mut headers: Vec<String> = Vec::new();
        let mut strip: Vec<String> = Vec::new();
        for layer in assertions_layers(config, Some(route), None) {
            let Some(block) = direction.block_of(layer.config) else {
                continue;
            };
            let above_the_route = matches!(
                layer.source,
                SectionSource::EntityDefault(_) | SectionSource::Bundle(_)
            );
            if above_the_route
                && block.replace_inherited
                && !(headers.is_empty() && strip.is_empty())
            {
                findings.push(DroppedAssertions {
                    route: route_label.to_owned(),
                    direction: direction.label(),
                    declared_in: layer.source.label(),
                    dropped_headers: headers.clone(),
                    dropped_strip: strip.clone(),
                });
                break;
            }
            if block.replace_inherited {
                headers.clear();
                strip.clear();
            }
            headers.extend(block.headers.iter().map(|entry| entry.name.clone()));
            strip.extend(block.strip.iter().map(|p| p.as_str().to_owned()));
        }
    }
    findings
}

/// Check every declared `assertions:` block, naming the level it sits at.
///
/// Runs from [`validate_config`], so every load path reaches it: an unaddressable
/// source, a credential source, a collection with no declared encoding, or a
/// glob that would remove a floor header all refuse the load rather than
/// surfacing as a header that did not appear.
fn validate_assertions(config: &PolicyConfig) -> Result<(), Box<PluginError>> {
    let fail = |message: String| Box::new(PluginError::Config { message });

    if let Some(assertions) = config.global.assertions.as_ref() {
        assertions.validate("global").map_err(fail)?;
    }
    for (entity_type, default) in &config.global.defaults {
        if let Some(assertions) = default.assertions.as_ref() {
            assertions
                .validate(&format!("global.defaults.{entity_type}"))
                .map_err(fail)?;
        }
    }
    for (name, bundle) in &config.global.bundles {
        if let Some(assertions) = bundle.assertions.as_ref() {
            assertions
                .validate(&format!("groups.{name}"))
                .map_err(fail)?;
        }
    }
    for (i, route) in config.routes.iter().enumerate() {
        if let Some(assertions) = route.assertions.as_ref() {
            assertions
                .validate(&route_display_name(route, i))
                .map_err(fail)?;
        }
    }
    reject_bundle_assertion_conflicts(config)
}

/// Refuse a route joining two bundles that assert the same header in the same
/// direction.
///
/// Bundles are the one layer with no order among themselves, so which of the two
/// wins would depend on nothing an operator wrote. Every other pair of levels is
/// ordered, which makes a repeated header there a per-name override rather than
/// an ambiguity. Two bundles naming *different* headers union and are legal, so
/// the check is per header rather than per direction.
///
/// Detectable at load because bundle membership is static: a tag the host injects
/// at runtime contributes no bundle, so there is no request-time ambiguity this
/// check could miss.
fn reject_bundle_assertion_conflicts(config: &PolicyConfig) -> Result<(), Box<PluginError>> {
    for (i, route) in config.routes.iter().enumerate() {
        for direction in [
            crate::assertions::Direction::Request,
            crate::assertions::Direction::Response,
        ] {
            // Deduplicated membership, so a bundle named in both `meta.tags`
            // and `groups:` is one membership rather than a conflict with
            // itself.
            let mut claimed: HashMap<String, String> = HashMap::new();
            for bundle_name in route_bundle_names(route) {
                let Some(block) = config
                    .global
                    .bundles
                    .get(&bundle_name)
                    .and_then(|bundle| bundle.assertions.as_ref())
                    .and_then(|assertions| direction.block_of(assertions))
                else {
                    continue;
                };
                for entry in &block.headers {
                    match claimed.entry(entry.name.to_lowercase()) {
                        Entry::Occupied(first) => {
                            return Err(Box::new(PluginError::Config {
                                message: format!(
                                    "route {} joins `groups.{}` and `groups.{bundle_name}`, which \
                                     both assert `{}` under `{}`; bundles have no order among \
                                     themselves, so which value reaches the wire would depend on \
                                     nothing the config says. Move the header to one bundle, or \
                                     onto the route",
                                    route_display_name(route, i),
                                    first.get(),
                                    entry.name,
                                    direction.label(),
                                ),
                            }));
                        },
                        Entry::Vacant(slot) => {
                            slot.insert(bundle_name.clone());
                        },
                    }
                }
            }
        }
    }
    Ok(())
}

/// How a report names a route: the entity type and the names it selects on, or
/// its position when it selects nothing.
pub(crate) fn route_display_name(route: &RouteEntry, index: usize) -> String {
    match route_entity_identity(route) {
        Some((entity_type, names)) => format!("{entity_type}:{}", names.join(",")),
        None => format!("routes[{index}]"),
    }
}

/// A resolved plugin with optional config overrides.
#[derive(Debug, Clone)]
pub struct ResolvedPlugin {
    /// Plugin name.
    pub name: String,

    /// Config overrides from the route.
    pub config_overrides: Option<serde_json::Value>,
}

/// Find the best matching route for a request, with the name it resolved to.
///
/// Scope matching: if a route declares a scope, the request must have the same
/// scope. No scope on the route matches any request. Among matches the highest
/// specificity wins, and the first declared breaks a tie.
pub fn resolve_route<'a>(
    config: &'a PolicyConfig,
    query: RouteQuery<'_>,
) -> Option<MatchedRoute<'a>> {
    let mut best: Option<(usize, MatchedRoute<'a>)> = None;

    for route in &config.routes {
        let route_scope = route.meta.as_ref().and_then(|m| m.scope.as_deref());
        let scope_bonus = match (route_scope, query.scope) {
            (None, _) => 0,                                              // route is global
            (Some(rs), Some(rq)) if rs == rq => SPECIFICITY_SCOPE_MATCH, // scopes match
            (Some(_), _) => continue,                                    // scope mismatch — skip
        };

        let Some((base_specificity, name)) = score_route_match(route, query) else {
            continue;
        };

        let total = base_specificity.saturating_add(scope_bonus);

        if best.as_ref().is_none_or(|(s, _)| total > *s) {
            best = Some((total, MatchedRoute { route, name }));
        }
    }

    best.map(|(_, matched)| matched)
}

/// Score one route against a query, with the name it would resolve to, or
/// `None` when it does not match.
///
/// HTTP scores on its own scale in its own arm, so the four name selectors keep
/// the buckets and the arithmetic they have.
fn score_route_match(route: &RouteEntry, query: RouteQuery<'_>) -> Option<(usize, String)> {
    if query.entity_type == ENTITY_HTTP {
        let selector = route.http.as_ref()?;
        let score = score_http_match(selector, query.path, query.method)?;
        return Some((score, matched_http_name(selector, query.path)?));
    }

    let matcher = match query.entity_type {
        ENTITY_TOOL => route.tool.as_ref(),
        ENTITY_RESOURCE => route.resource.as_ref(),
        ENTITY_PROMPT => route.prompt.as_ref(),
        ENTITY_LLM => route.llm.as_ref(),
        _ => None,
    }?;
    let score = score_entity_match(Some(matcher), query.name)?;
    Some((score, matched_selector_name(matcher, query.name)?))
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
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

    /// The name the route table resolves for a request, or `None` when nothing
    /// matched. Route matching outlived the activation lists it used to feed.
    fn matched_name(
        config: &PolicyConfig,
        entity_type: &str,
        entity_name: &str,
        request_scope: Option<&str>,
    ) -> Option<String> {
        resolve_route(
            config,
            RouteQuery::named(entity_type, entity_name).with_scope(request_scope),
        )
        .map(|matched| matched.name)
    }

    /// The identity-hook counterpart of `plugins_for`.
    fn identity_for(
        config: &PolicyConfig,
        entity_type: &str,
        entity_name: &str,
        request_scope: Option<&str>,
    ) -> Vec<ResolvedPlugin> {
        let matched = resolve_route(
            config,
            RouteQuery::named(entity_type, entity_name).with_scope(request_scope),
        );
        resolve_identity_plugins_for_route(config, matched.as_ref())
    }

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
    config:
      max_requests: 100
"#;
        let config = parse_config(yaml).unwrap();
        assert_eq!(config.dispatch_mode(), DispatchMode::Policy);
        assert_eq!(config.plugins.len(), 1);
        assert_eq!(config.plugins[0].name, "rate_limiter");
    }

    #[test]
    fn test_no_engine_settings_defaults_to_policy_dispatch() {
        let yaml = r#"
plugins:
  - name: test
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
"#;
        let config = parse_config(yaml).unwrap();
        assert_eq!(config.dispatch_mode(), DispatchMode::Policy);
        assert_eq!(config.engine_settings.plugin_timeout, 30);
    }

    #[test]
    fn test_policy_dispatch() {
        let yaml = r#"
engine_settings:
  dispatch: policy
groups:
  all:
    authentication: [identity]
plugins:
  - name: identity
    kind: builtin
    hooks: [identity.resolve]
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
"#;
        let config = parse_config(yaml).unwrap();
        assert_eq!(config.dispatch_mode(), DispatchMode::Policy);
        // Serialize is derived while Deserialize is hand-written, so the two
        // spellings have to be checked against each other.
        assert_eq!(
            serde_yaml::to_string(&DispatchMode::Policy).unwrap().trim(),
            "policy"
        );
        assert_eq!(
            serde_yaml::to_string(&DispatchMode::Hooks).unwrap().trim(),
            "hooks"
        );
    }

    /// `dispatch: hooks` written out loads the same way as leaving the block
    /// off: every declared plugin resolves.
    #[test]
    fn explicit_hook_dispatch_resolves_every_declared_plugin() {
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: first
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: second
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
"#;
        let config = parse_config(yaml).expect("hook dispatch loads");
        assert_eq!(config.dispatch_mode(), DispatchMode::Hooks);
        let resolved = resolve_plugins_for_entity(&config);
        assert_eq!(
            resolved.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["first", "second"],
            "hook mode resolves every declared plugin, and the executor narrows \
             them by each plugin's own conditions",
        );
    }

    /// A misspelled mode names both accepted spellings rather than being read
    /// leniently as one of them.
    #[test]
    fn an_unknown_dispatch_mode_is_rejected_naming_both() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: plicy
plugins: []
"#,
        )
        .expect_err("a misspelled mode must not load");
        let message = err.to_string();
        assert!(message.contains("plicy"), "{message}");
        assert!(message.contains("policy"), "{message}");
        assert!(message.contains("hooks"), "{message}");
    }

    /// The mode used to be a boolean, so a stale `true` must fail rather than
    /// coerce to a mode.
    #[test]
    fn a_boolean_dispatch_value_is_rejected() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: true
plugins: []
"#,
        )
        .expect_err("a boolean must not coerce to a mode");
        let message = err.to_string();
        assert!(
            message.contains("policy") && message.contains("hooks"),
            "{message}"
        );
    }

    /// `PolicyConfig` drops an unknown field, so the pre-rename key has to be
    /// rejected by name. Otherwise a config asking for route dispatch loads in
    /// hook mode with its whole settings block discarded.
    #[test]
    fn the_pre_rename_plugin_settings_key_is_rejected() {
        let err = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
plugins: []
"#,
        )
        .expect_err("the pre-rename key must not load silently");
        let message = err.to_string();
        assert!(message.contains("engine_settings"), "{message}");
        assert!(message.contains("dispatch: policy"), "{message}");
    }

    #[test]
    fn a_declared_hook_that_nothing_dispatches_is_rejected() {
        let yaml = r#"
plugins:
  - name: apl-policy
    kind: builtin
    hooks: [tool_pre_invoke]
"#;
        let err = parse_config(yaml).unwrap_err().to_string();
        assert!(err.contains("apl-policy"), "{err}");
        assert!(err.contains("tool_pre_invoke"), "{err}");
        // The exact mistake the removed constants and the old example
        // taught, so the suggestion has to land on the dispatched name.
        assert!(err.contains("'cmf.tool_pre_invoke'"), "{err}");
    }

    #[test]
    fn the_wrong_prompt_spelling_suggests_the_dispatched_one() {
        let yaml = r#"
plugins:
  - name: watcher
    kind: builtin
    hooks: [cmf.prompt_pre_fetch]
"#;
        let err = parse_config(yaml).unwrap_err().to_string();
        assert!(err.contains("'cmf.prompt_pre_invoke'"), "{err}");
    }

    #[test]
    fn the_old_cmf_prefixed_http_names_suggest_the_http_family_ones() {
        // The HTTP hooks moved out of the CMF family, so a config carrying
        // either old name has to be refused and pointed at the new one
        // rather than at some unrelated CMF hook.
        for (old, new) in [
            ("cmf.http_request", "'http.request'"),
            ("cmf.http_response", "'http.response'"),
        ] {
            let yaml = format!(
                r#"
plugins:
  - name: filter
    kind: builtin
    hooks: [{old}]
"#
            );
            let err = parse_config(&yaml).unwrap_err().to_string();
            assert!(err.contains(old), "{err}");
            assert!(err.contains(new), "{err}");
        }
    }

    #[test]
    fn a_name_close_to_nothing_gets_no_suggestion() {
        let yaml = r#"
plugins:
  - name: odd
    kind: builtin
    hooks: [wildly_unrelated_hook_name]
"#;
        let err = parse_config(yaml).unwrap_err().to_string();
        assert!(err.contains("wildly_unrelated_hook_name"), "{err}");
        assert!(!err.contains("did you mean"), "{err}");
    }

    #[test]
    fn a_host_registered_hook_passes_validation() {
        let name = "test_config.host_registered_hook";
        crate::hooks::register_hook_metadata(name, crate::hooks::HookMetadata::permissive());
        let yaml = format!(
            r#"
plugins:
  - name: host-plugin
    kind: builtin
    hooks: [{name}]
"#
        );
        parse_config(&yaml).expect("a registered hook is known");
    }

    #[test]
    fn the_shipped_family_hook_names_pass_validation() {
        // The names shipped plugin code and operator YAML already declare.
        for hook in [
            crate::identity::HOOK_IDENTITY_RESOLVE,
            crate::delegation::HOOK_TOKEN_DELEGATE,
            crate::elicitation::HOOK_ELICIT,
        ] {
            let yaml = format!(
                r#"
plugins:
  - name: shipped
    kind: builtin
    hooks: [{hook}]
"#
            );
            parse_config(&yaml).unwrap_or_else(|e| panic!("{hook} rejected: {e}"));
        }
    }

    #[test]
    fn every_hook_the_authority_holds_passes_validation() {
        for hook in crate::hooks::builtin_hook_types() {
            let yaml = format!(
                r#"
plugins:
  - name: declaring
    kind: builtin
    hooks: [{}]
"#,
                hook.as_str()
            );
            parse_config(&yaml).unwrap_or_else(|e| panic!("{hook} rejected: {e}"));
        }
    }

    #[test]
    fn a_plugin_declaring_no_hooks_loads() {
        let yaml = r#"
plugins:
  - name: quiet
    kind: builtin
    hooks: []
  - name: silent
    kind: builtin
"#;
        parse_config(yaml).expect("an empty hooks list is not a typo");
    }

    #[test]
    fn test_duplicate_plugin_names_rejected() {
        let yaml = r#"
plugins:
  - name: dup
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: dup
    kind: builtin
    hooks: [cmf.tool_post_invoke]
"#;
        assert!(
            parse_config(yaml)
                .unwrap_err()
                .to_string()
                .contains("duplicate plugin name")
        );
    }

    #[test]
    fn test_route_requires_one_entity_matcher() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - meta:
      tags: [pii]
"#;
        assert!(
            parse_config(yaml)
                .unwrap_err()
                .to_string()
                .contains("no entity matcher")
        );
    }

    #[test]
    fn test_route_rejects_multiple_entity_matchers() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_compensation
    resource: "hr://employees/*"
"#;
        assert!(
            parse_config(yaml)
                .unwrap_err()
                .to_string()
                .contains("multiple entity matchers")
        );
    }

    /// A config built in Rust rather than parsed can still fill an activation
    /// list, so the reference walk stays. YAML no longer reaches it: the list
    /// shape is refused before validation runs.
    #[test]
    fn test_route_unknown_plugin_rejected() {
        let mut config = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: known
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
"#,
        )
        .expect("the parsed half of the fixture is legal");
        config.routes[0]
            .plugins
            .push(PluginRouteRef::Name("unknown".to_owned()));
        assert!(
            validate_config(&config)
                .unwrap_err()
                .to_string()
                .contains("unknown plugin 'unknown'")
        );
    }

    /// The bundle-scoped half of the same walk, reached the same way.
    #[test]
    fn test_policy_group_unknown_plugin_rejected() {
        let mut config = parse_config(
            r#"
engine_settings:
  dispatch: policy
groups:
  all:
    description: the reserved bundle
plugins: []
routes: []
"#,
        )
        .expect("the parsed half of the fixture is legal");
        config
            .global
            .bundles
            .get_mut("all")
            .expect("the bundle folded into the store")
            .plugins
            .push(PluginRouteRef::Name("nonexistent".to_owned()));
        assert!(
            validate_config(&config)
                .unwrap_err()
                .to_string()
                .contains("unknown plugin 'nonexistent'")
        );
    }

    #[test]
    fn test_route_unknown_authentication_step_rejected() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: builtin
    hooks: [identity.resolve]
routes:
  - tool: get_compensation
    authentication:
      - corp-jtw
"#,
        )
        .expect_err("a typo'd step name is not a loadable config");
        assert!(
            err.to_string()
                .contains("authentication references unknown plugin 'corp-jtw'"),
            "got: {err}"
        );
    }

    #[test]
    fn test_global_unknown_authentication_step_rejected() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
global:
  authentication:
    - missing-resolver
plugins: []
routes: []
"#,
        )
        .expect_err("a typo'd global step name is not a loadable config");
        assert!(
            err.to_string()
                .contains("authentication references unknown plugin 'missing-resolver'"),
            "got: {err}"
        );
    }

    #[test]
    fn test_known_authentication_step_is_accepted() {
        parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: builtin
    hooks: [identity.resolve]
routes:
  - tool: get_compensation
    authentication:
      - corp-jwt
"#,
        )
        .expect("a step naming a declared plugin is legal");
    }

    /// The backstop that catches a policy-mode config nothing could dispatch
    /// from, for a host with no orchestrator to catch it better.
    #[test]
    fn plugins_with_no_policy_scope_are_rejected_without_a_visitor() {
        let config = parse_config(
            r#"
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
"#,
        )
        .expect("nothing here is a key error; the fault is that nothing reaches it");
        let message = reject_policy_mode_with_nothing_to_dispatch(&config, false)
            .expect_err("no scope can name the plugin")
            .to_string();
        assert!(message.contains("audit-log"), "{message}");
        assert!(
            message.contains("dispatch: hooks"),
            "the message names the mode that keeps today's behavior: {message}"
        );
    }

    /// And it stands down for a host that has one. praxis-policy-core cannot see
    /// `global.authorization:`, so a config whose only scope is that block looks
    /// scope-less from here while an orchestrator reaches the plugin from it.
    #[test]
    fn a_visitor_takes_the_scope_check_over_from_the_backstop() {
        let config = parse_config(
            r#"
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
global:
  authorization:
    pre_invocation:
      - "run(audit-log)"
"#,
        )
        .expect("an orchestrator's key on a section is not a typo");
        assert!(
            config.routes.is_empty() && config.groups.is_empty(),
            "the shape under test is one with no scope praxis-policy-core models"
        );
        reject_policy_mode_with_nothing_to_dispatch(&config, true)
            .expect("the visitor sees the step this cannot, so it decides");
    }

    /// Hook dispatch fires each plugin at the hooks it declares, so a config
    /// with no policy scope is what that mode expects rather than a fault.
    #[test]
    fn hook_dispatch_needs_no_policy_scope() {
        let config = parse_config(
            r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
"#,
        )
        .expect("the config is legal in hook mode");
        reject_policy_mode_with_nothing_to_dispatch(&config, false)
            .expect("nothing needs a scope to name it here");
    }

    #[test]
    fn test_resolve_conditions_mode_returns_all() {
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: a
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: b
    kind: builtin
    hooks: [cmf.tool_post_invoke]
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = resolve_plugins_for_entity(&config);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    /// A tag bundle's activation list is rejected like every other one, so a
    /// route joining the bundle cannot inherit plugins from it.
    #[test]
    fn a_bundles_plugins_list_is_rejected_in_policy_mode() {
        let yaml = r#"
engine_settings:
  dispatch: policy
groups:
  pii:
    plugins:
      - apl_policy
plugins:
  - name: apl_policy
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
"#;
        let message = parse_config(yaml)
            .expect_err("a bundle cannot activate a plugin in policy mode")
            .to_string();
        assert!(message.contains("groups.pii"), "{message}");
        assert!(message.contains("run(name)"), "{message}");
    }

    /// The reserved `all` bundle is the chain-wide activation this work
    /// removes, so its list is rejected by the same check under its own name.
    #[test]
    fn the_reserved_all_bundles_plugins_list_is_rejected_in_policy_mode() {
        let yaml = r#"
engine_settings:
  dispatch: policy
groups:
  all:
    plugins:
      - identity
plugins:
  - name: identity
    kind: builtin
    hooks: [identity.resolve]
routes:
  - tool: get_compensation
"#;
        let message = parse_config(yaml)
            .expect_err("the `all` bundle cannot activate a plugin in policy mode")
            .to_string();
        assert!(message.contains("groups.all"), "{message}");
        assert!(
            message.contains("global.authorization"),
            "the message names what replaces chain-wide activation: {message}"
        );
    }

    #[test]
    fn test_exact_match_beats_glob() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: "hr-*"
    authorization:
      pre_invocation: ["allow"]
  - tool: hr-compensation
    authorization:
      pre_invocation: ["allow"]
"#;
        let config = parse_config(yaml).unwrap();
        assert_eq!(
            matched_name(&config, "tool", "hr-compensation", None).as_deref(),
            Some("hr-compensation"),
            "the exact selector outranks the glob that also matches",
        );
    }

    /// A route's `plugins:` list is the construct policy mode drops, and the
    /// error names the step form that replaces it.
    #[test]
    fn a_routes_plugins_list_is_rejected_in_policy_mode() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    plugins:
      - rate_limiter
"#;
        let message = parse_config(yaml)
            .expect_err("a route cannot activate a plugin in policy mode")
            .to_string();
        assert!(message.contains("routes[0]"), "{message}");
        assert!(message.contains("run(name)"), "{message}");
    }

    /// An `authorization:` block on the same route does not make the list
    /// legal: the two are not two spellings of one thing.
    #[test]
    fn a_routes_plugins_list_is_rejected_beside_an_authorization_block() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    plugins:
      - rate_limiter
    authorization:
      pre_invocation: ["run(rate_limiter)"]
"#;
        let message = parse_config(yaml)
            .expect_err("an authorization block does not license the list")
            .to_string();
        assert!(message.contains("run(name)"), "{message}");
    }

    /// The mapping shape is a different construct that happens to share the
    /// key: it overrides a plugin a step already invokes, so it stays valid.
    #[test]
    fn a_routes_plugins_override_map_loads_in_policy_mode() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
    config:
      max_requests: 100
routes:
  - tool: get_compensation
    plugins:
      rate_limiter:
        config:
          max_requests: 10
    authorization:
      pre_invocation: ["run(rate_limiter)"]
"#;
        let config = parse_config(yaml).expect("the override map is not an activation list");
        assert!(
            config.routes[0].plugins.is_empty(),
            "the map is the APL visitor's to read, so the structural Vec stays empty",
        );
    }

    /// An empty sequence is still a sequence. It reads as "activate nothing",
    /// which is a shape policy mode has no meaning for.
    #[test]
    fn an_empty_plugins_list_is_rejected_in_policy_mode() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_compensation
    plugins: []
"#;
        let message = parse_config(yaml)
            .expect_err("an empty activation list is an activation list")
            .to_string();
        assert!(message.contains("run(name)"), "{message}");
    }

    #[test]
    fn test_glob_trailing_wildcard() {
        let matcher = StringOrList::Single(Pattern::new("hr-*"));
        assert!(matcher.matches("hr-compensation"));
        assert!(matcher.matches("hr-benefits"));
        assert!(matcher.matches("hr-")); // empty match for *
        assert!(!matcher.matches("finance-report"));
        assert!(!matcher.matches("hr"));
    }

    #[test]
    fn test_wildcard_matches_everything() {
        let matcher = StringOrList::Single(Pattern::new("*"));
        assert!(matcher.matches("anything"));
        assert!(matcher.matches(""));
    }

    /// Regression for the security footgun: `*suffix` patterns were
    /// silently matching almost nothing because the previous matcher
    /// looked for `"*suffix"` as a literal prefix.
    #[test]
    fn test_glob_leading_wildcard() {
        let matcher = StringOrList::Single(Pattern::new("*-prod"));
        assert!(matcher.matches("foo-prod"));
        assert!(matcher.matches("-prod")); // empty match for *
        assert!(!matcher.matches("foo-staging"));
        assert!(!matcher.matches("prod"));
    }

    /// Regression for `prefix*suffix` patterns also broken before.
    #[test]
    fn test_glob_mid_wildcard() {
        let matcher = StringOrList::Single(Pattern::new("hr-*-v1"));
        assert!(matcher.matches("hr-comp-v1"));
        assert!(matcher.matches("hr--v1")); // empty match for *
        assert!(!matcher.matches("hr-comp-v2"));
        assert!(!matcher.matches("finance-comp-v1"));
    }

    /// Multiple-wildcard patterns must work everywhere `*` appears.
    #[test]
    fn test_glob_multiple_wildcards() {
        let matcher = StringOrList::Single(Pattern::new("*hr*comp*"));
        assert!(matcher.matches("hr-comp"));
        assert!(matcher.matches("xyz-hr-comp-foo"));
        assert!(!matcher.matches("hr-only"));
        assert!(!matcher.matches("comp-only"));
    }

    /// Regression for the OTHER security footgun: multi-star patterns
    /// like `**` were `trim_end_matches('*')`'d to `""` and then matched
    /// every name via `starts_with("")`. With wildmatch this is a
    /// degenerate-but-correct "match anything" pattern, equivalent to `*`.
    #[test]
    fn test_glob_multi_star_is_equivalent_to_single_star() {
        for pattern in &["**", "***", "*****"] {
            let matcher = StringOrList::Single(Pattern::new(*pattern));
            assert!(
                matcher.matches("anything"),
                "pattern {pattern} should match"
            );
            assert!(matcher.matches(""), "pattern {pattern} should match empty");
        }
    }

    /// `WildMatch` is built once at deserialize / `Pattern::new` time and
    /// reused; this test just sanity-checks the round-trip through serde.
    #[test]
    fn test_pattern_round_trips_through_yaml() {
        let yaml = "tool: '*-prod'";
        #[derive(Deserialize, Serialize)]
        struct Wrap {
            tool: StringOrList,
        }
        let parsed: Wrap = serde_yaml::from_str(yaml).unwrap();
        assert!(parsed.tool.matches("foo-prod"));
        assert!(!parsed.tool.matches("foo-staging"));
        let back = serde_yaml::to_string(&parsed).unwrap();
        assert!(
            back.contains("*-prod"),
            "serialized YAML should preserve pattern: {back}"
        );
    }

    #[test]
    fn test_list_matches_any_member() {
        let matcher = StringOrList::List(vec![
            "get_compensation".to_owned(),
            "get_benefits".to_owned(),
        ]);
        assert!(matcher.matches("get_compensation"));
        assert!(matcher.matches("get_benefits"));
        assert!(!matcher.matches("send_email"));
    }

    /// A route that hook mode would never resolve fails on the mode rather
    /// than on the route's own defects, which is the line to fix first.
    #[test]
    fn a_routes_block_is_rejected_in_hook_mode() {
        let yaml = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: test
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - meta:
      tags: [pii]
"#;
        let message = parse_config(yaml)
            .expect_err("hook dispatch resolves no route")
            .to_string();
        assert!(message.contains("`routes`"), "{message}");
        assert!(message.contains("dispatch: hooks"), "{message}");
    }

    /// The same for the other two blocks, named one at a time and together.
    #[test]
    fn every_policy_mode_block_is_rejected_in_hook_mode() {
        for (yaml, expected) in [
            (
                "engine_settings:\n  dispatch: hooks\nplugins: []\ngroups:\n  hr: {}\n",
                "`groups`",
            ),
            (
                "engine_settings:\n  dispatch: hooks\nplugins: []\nglobal:\n  \
                 authentication: []\n",
                "`global`",
            ),
            (
                "engine_settings:\n  dispatch: hooks\nplugins: []\nglobal:\n  defaults:\n    \
                 tool: {}\n",
                "`global`, `global.defaults`",
            ),
        ] {
            let message = parse_config(yaml)
                .expect_err("hook dispatch resolves none of these")
                .to_string();
            assert!(message.contains(expected), "{expected}: {message}");
            assert!(message.contains("dispatch: hooks"), "{message}");
        }
    }

    /// The same document with no `engine_settings:` at all loads, which is the
    /// default flip: a route is what the unwritten mode expects to see.
    #[test]
    fn a_routes_block_loads_under_the_defaulted_mode() {
        let config = parse_config("plugins: []\nroutes:\n  - tool: t\n")
            .expect("policy is the default, and a route is policy-mode");
        assert_eq!(config.dispatch_mode(), DispatchMode::Policy);
        assert_eq!(config.routes.len(), 1);
    }

    /// The policy-mode half of the boundary: nothing consults a per-plugin
    /// condition once a policy decides dispatch.
    #[test]
    fn a_plugin_condition_is_rejected_in_policy_mode() {
        let message = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: pii-scan
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
    conditions:
      - tools: [get_compensation]
"#,
        )
        .expect_err("a condition is never consulted in policy mode")
        .to_string();
        assert!(message.contains("`conditions:`"), "{message}");
        assert!(message.contains("dispatch: policy"), "{message}");
        assert!(message.contains("pii-scan"), "{message}");
    }

    /// A `PolicyConfig` a host built in Rust, with nothing normalized. The typed
    /// boundary is what these cases exercise: `parse_config` would refuse the
    /// same documents earlier, on the raw YAML, which is exactly why the typed
    /// checks were missing for so long.
    fn typed_config(yaml: &str) -> PolicyConfig {
        let mut config: PolicyConfig = serde_yaml::from_str(yaml).expect("deserialize");
        fold_groups_into_bundles(&mut config);
        config
    }

    /// The worst of the three: `resolve_plugins_for_entity` returns nothing in
    /// policy mode, so an activation list that reached the typed boundary loaded
    /// and then sat inert. Every scope that can carry one.
    #[test]
    fn a_typed_activation_list_is_rejected_in_policy_mode() {
        for (path, yaml) in [
            ("routes[0]", "routes:\n  - tool: t\n    plugins: [audit]\n"),
            ("groups.hr", "groups:\n  hr:\n    plugins: [audit]\n"),
            (
                "global.defaults.tool",
                "global:\n  defaults:\n    tool:\n      plugins: [audit]\n",
            ),
        ] {
            let mut config = typed_config(yaml);
            // The override mapping deserializes to an empty Vec, so a non-empty
            // one only ever comes from a host. Set it by hand to be that host.
            let refs = vec![PluginRouteRef::Name("audit".to_owned())];
            match path {
                "routes[0]" => config.routes[0].plugins = refs,
                "groups.hr" => {
                    config.global.bundles.get_mut("hr").expect("bundle").plugins = refs;
                },
                _ => {
                    config
                        .global
                        .defaults
                        .get_mut("tool")
                        .expect("default")
                        .plugins = refs;
                },
            }
            let message = reject_mode_conflicts_typed(&config)
                .expect_err("an activation list is inert in policy mode")
                .to_string();
            assert!(message.contains(path), "must name the scope: {message}");
            assert!(message.contains("run(name)"), "{message}");
            assert!(message.contains("dispatch: policy"), "{message}");
        }
    }

    /// Hook mode has no activation-list scope left to carry one, since `routes:`
    /// and `groups:` are its own load errors. What it does instead is resolve
    /// every declared plugin, so the check must not stand in the way of that.
    #[test]
    fn hook_mode_still_resolves_every_declared_plugin() {
        let config = typed_config(
            "engine_settings:\n  dispatch: hooks\nplugins:\n  - name: audit\n    kind:              builtin\n    hooks: [cmf.tool_pre_invoke]\n",
        );
        reject_mode_conflicts_typed(&config).expect("a bare hook-mode config is what hooks is for");
        assert_eq!(resolve_plugins_for_entity(&config).len(), 1);
    }

    /// The typed twin of `a_plugin_condition_is_rejected_in_policy_mode`.
    #[test]
    fn a_typed_plugin_condition_is_rejected_in_policy_mode() {
        let config = typed_config(
            "plugins:\n  - name: pii-scan\n    kind: builtin\n    hooks:              [cmf.tool_pre_invoke]\n    conditions:\n      - tools: [get_compensation]\n",
        );
        let message = reject_mode_conflicts_typed(&config)
            .expect_err("a condition is never consulted in policy mode")
            .to_string();
        assert!(message.contains("`conditions:`"), "{message}");
        assert!(message.contains("pii-scan"), "{message}");
    }

    /// And the hook-mode half: the policy-mode scopes resolve nothing there.
    #[test]
    fn a_typed_policy_scope_is_rejected_in_hook_mode() {
        let hooks = "engine_settings:\n  dispatch: hooks\n";
        for (scope, yaml) in [
            ("routes", "routes:\n  - tool: t\n"),
            ("groups", "groups:\n  hr:\n    description: x\n"),
            (
                "global.defaults",
                "global:\n  defaults:\n    tool:\n      description: x\n",
            ),
            (
                "global.authentication",
                "global:\n  authentication: [jwt]\n",
            ),
        ] {
            let config = typed_config(&format!("{hooks}{yaml}"));
            let message = reject_mode_conflicts_typed(&config)
                .expect_err("hook mode resolves no policy scope")
                .to_string();
            assert!(message.contains(scope), "must name the scope: {message}");
            assert!(message.contains("dispatch: hooks"), "{message}");
        }
    }

    /// The shape that shares the key and must not be caught: a `plugins:` mapping
    /// is an override for a plugin a step names, and it deserializes to an empty
    /// structural `Vec`.
    #[test]
    fn a_typed_plugin_override_mapping_still_loads_in_policy_mode() {
        let config = typed_config(
            r#"
plugins:
  - name: audit
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: t
    plugins:
      audit:
        on_error: ignore
"#,
        );
        assert!(
            config.routes[0].plugins.is_empty(),
            "the mapping folds into an empty structural Vec"
        );
        reject_mode_conflicts_typed(&config)
            .expect("an override mapping is not an activation list");
    }

    /// Every section that can carry an APL key, refused when no visitor can read
    /// it. The check is on the raw document, so it is exercised here rather than
    /// through an engine.
    ///
    /// The document that motivated it is the first case: a route declaring an
    /// unconditional `deny`, which used to load clean, install no handler, and
    /// enforce nothing.
    #[test]
    fn an_apl_key_is_rejected_when_no_visitor_can_read_it() {
        for (path, key, yaml) in [
            (
                "routes[0]",
                "authorization",
                "routes:\n  - tool: t\n    authorization:\n      pre_invocation:\n        - \
                 \"deny('always')\"\n",
            ),
            (
                "routes[0]",
                "result",
                "routes:\n  - tool: t\n    result:\n      ssn: redact\n",
            ),
            (
                "routes[0]",
                "args",
                "routes:\n  - tool: t\n    args:\n      id: str\n",
            ),
            (
                "routes[0]",
                "response",
                "routes:\n  - tool: t\n    response:\n      status: 403\n",
            ),
            (
                "global",
                "authorization",
                "global:\n  authorization:\n    pre_invocation: [\"deny\"]\n",
            ),
            ("global", "pdp", "global:\n  pdp:\n    - kind: cel\n"),
            (
                "groups.hr",
                "authorization",
                "groups:\n  hr:\n    authorization:\n      pre_invocation: [\"deny\"]\n",
            ),
            (
                "global.defaults.tool",
                "authorization",
                "global:\n  defaults:\n    tool:\n      authorization:\n        pre_invocation: \
                 [\"deny\"]\n",
            ),
        ] {
            let raw: serde_yaml::Value = serde_yaml::from_str(yaml).expect("probe YAML parses");
            let message = reject_apl_keys_without_a_visitor(&raw)
                .expect_err("an APL key with no visitor enforces nothing")
                .to_string();
            assert!(message.contains(path), "must name the section: {message}");
            assert!(message.contains(key), "must name the key: {message}");
            assert!(message.contains("dispatch: hooks"), "{message}");
            assert!(message.contains("register_apl"), "{message}");
        }
    }

    /// A document with no APL key is unaffected, whatever else it declares. The
    /// check is about a body praxis-policy-core cannot read, not about policy
    /// mode.
    #[test]
    fn a_document_with_no_apl_key_needs_no_visitor() {
        for yaml in [
            "routes:\n  - tool: t\n    meta:\n      tags: [hr]\n",
            "routes:\n  - tool: t\n    authentication: [jwt]\n",
            "groups:\n  hr:\n    description: x\n",
            "global:\n  authentication: [jwt]\n",
            "engine_settings:\n  dispatch: hooks\nplugins: []\n",
        ] {
            let raw: serde_yaml::Value = serde_yaml::from_str(yaml).expect("probe YAML parses");
            reject_apl_keys_without_a_visitor(&raw)
                .unwrap_or_else(|e| panic!("`{yaml}` carries no APL key: {e}"));
        }
    }

    /// `priority:` is rejected beside `conditions:`, for the same reason: policy
    /// dispatch never hands the registry more than one entry to order.
    ///
    /// This asserted the opposite, on the claim that the registry sorts by
    /// priority in both modes. It does, and policy dispatch never asks it to:
    /// effects run in document order, a `run(name)` step invokes one named entry,
    /// and the runtime passes the executor a one-entry slice.
    #[test]
    fn a_plugin_priority_is_rejected_in_policy_mode() {
        let message = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: pii-scan
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
    priority: 20
"#,
        )
        .expect_err("nothing consults a priority in policy mode")
        .to_string();
        assert!(message.contains("`priority:`"), "{message}");
        assert!(message.contains("dispatch: policy"), "{message}");
        assert!(message.contains("dispatch: hooks"), "{message}");
        assert!(message.contains("pii-scan"), "{message}");
    }

    /// The default is policy, so a document that never mentions dispatch is
    /// checked as policy mode. That is most of what the rejection reaches.
    #[test]
    fn a_plugin_priority_is_rejected_with_no_dispatch_declared() {
        let message = parse_config(
            r#"
plugins:
  - name: pii-scan
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
    priority: 20
"#,
        )
        .expect_err("the absent key means policy")
        .to_string();
        assert!(message.contains("`priority:`"), "{message}");
    }

    /// And hook mode keeps it, which is the escape the message names.
    #[test]
    fn a_plugin_priority_loads_in_hook_mode() {
        let config = parse_config(
            r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: pii-scan
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
    priority: 20
"#,
        )
        .expect("hook mode orders a hook's entries by priority");
        assert_eq!(config.plugins[0].priority, 20);
    }

    // -- Scope matching tests --

    #[test]
    fn test_scope_match_selects_scoped_route() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_compensation
    meta:
      scope: hr-services
    authorization:
      pre_invocation: ["allow"]
  - tool: get_compensation
    authorization:
      pre_invocation: ["allow"]
"#;
        let config = parse_config(yaml).unwrap();

        // Two routes share a name under different scopes, so the resolved
        // route is identified by the scope it declared.
        let scoped = resolve_route(
            &config,
            RouteQuery::named("tool", "get_compensation").with_scope(Some("hr-services")),
        )
        .expect("the scoped route matches its own scope");
        assert_eq!(
            scoped.route.meta.as_ref().and_then(|m| m.scope.as_deref()),
            Some("hr-services"),
        );

        for request_scope in [None, Some("billing")] {
            let unscoped = resolve_route(
                &config,
                RouteQuery::named("tool", "get_compensation").with_scope(request_scope),
            )
            .expect("the unscoped route matches every other scope");
            assert!(
                unscoped
                    .route
                    .meta
                    .as_ref()
                    .and_then(|m| m.scope.as_deref())
                    .is_none(),
                "a scoped route must not answer for scope {request_scope:?}",
            );
        }
    }

    #[test]
    fn parse_route_identity_list_form() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: spiffe-attestor, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    authentication:
      - corp-jwt
      - spiffe-attestor
"#;
        let cfg = parse_config(yaml).unwrap();
        let route = &cfg.routes[0];
        let id = route.authentication.as_ref().expect("identity present");
        assert!(!id.replace_inherited);
        assert_eq!(id.steps.len(), 2);
        assert_eq!(id.steps[0].name, "corp-jwt");
        assert!(id.steps[0].config_override.is_none());
        assert_eq!(id.steps[1].name, "spiffe-attestor");
    }

    #[test]
    fn parse_route_identity_object_form_carries_replace_inherited() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: legacy-basic-auth, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: legacy
    authentication:
      replace_inherited: true
      steps:
        - legacy-basic-auth
"#;
        let cfg = parse_config(yaml).unwrap();
        let id = cfg.routes[0].authentication.as_ref().unwrap();
        assert!(id.replace_inherited);
        assert_eq!(id.steps.len(), 1);
        assert_eq!(id.steps[0].name, "legacy-basic-auth");
    }

    #[test]
    fn parse_route_identity_map_step_with_config() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    authentication:
      - name: corp-jwt
        config:
          audience: my-tool
"#;
        let cfg = parse_config(yaml).unwrap();
        let id = cfg.routes[0].authentication.as_ref().unwrap();
        let s0 = &id.steps[0];
        assert_eq!(s0.name, "corp-jwt");
        let cfg_override = s0.config_override.as_ref().expect("config_override set");
        assert_eq!(
            cfg_override.get("audience").and_then(|v| v.as_str()),
            Some("my-tool"),
        );
    }

    /// A step's `on_error:` was parsed and read by nothing. It is gone, and the
    /// error names the plugin declaration that carries the real one.
    #[test]
    fn parse_route_identity_step_rejects_on_error() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    authentication:
      - name: corp-jwt
        on_error: deny
"#;
        let err = parse_config(yaml)
            .expect_err("`on_error:` is no longer a step key")
            .to_string();
        assert!(
            err.contains("on_error") && err.contains("plugins:"),
            "the error must name the key and the declaration that carries it: {err}"
        );
    }

    /// The catch-all a step used to flatten swallowed a typo whole, leaving the
    /// step running with the default the misspelled key meant to change.
    #[test]
    fn parse_route_identity_step_rejects_a_misspelled_key() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    authentication:
      - name: corp-jwt
        confg:
          audience: my-tool
"#;
        let err = parse_config(yaml)
            .expect_err("a misspelled step key must fail the load")
            .to_string();
        assert!(err.contains("confg"), "the error must name the key: {err}");
    }

    #[test]
    fn parse_route_identity_mixed_bare_and_map_steps() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: spiffe-attestor, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    authentication:
      - name: corp-jwt
        config: { audience: my-tool }
      - spiffe-attestor
"#;
        let cfg = parse_config(yaml).unwrap();
        let steps = &cfg.routes[0].authentication.as_ref().unwrap().steps;
        assert_eq!(steps.len(), 2);
        assert!(steps[0].config_override.is_some());
        assert!(steps[1].config_override.is_none());
    }

    #[test]
    fn parse_route_identity_object_form_without_steps_errors() {
        let yaml = r#"
engine_settings:
  dispatch: policy
routes:
  - tool: bad
    authentication:
      replace_inherited: true
"#;
        let err = parse_config(yaml).expect_err("object form requires steps");
        let msg = format!("{err}");
        assert!(msg.contains("requires `steps:`"), "got: {msg}");
    }

    #[test]
    fn parse_route_identity_replace_inherited_must_be_boolean() {
        let yaml = r#"
engine_settings:
  dispatch: policy
routes:
  - tool: bad
    authentication:
      replace_inherited: "yes"
      steps:
        - corp-jwt
"#;
        let err = parse_config(yaml).expect_err("replace_inherited must be bool");
        let msg = format!("{err}");
        assert!(msg.contains("boolean"), "got: {msg}");
    }

    #[test]
    fn parse_route_identity_empty_step_name_errors() {
        let yaml = r#"
engine_settings:
  dispatch: policy
routes:
  - tool: bad
    authentication:
      - ""
"#;
        let err = parse_config(yaml).expect_err("empty step name should fail");
        let msg = format!("{err}");
        assert!(msg.contains("empty"), "got: {msg}");
    }

    #[test]
    fn the_removed_identity_key_is_rejected_at_route_and_above() {
        // The removed `identity:` key must fail loudly, never be silently
        // dropped (which would skip authentication — a fail-open).
        for yaml in [
            "routes:\n  - tool: t\n    identity:\n      - corp-jwt\n",
            "global:\n  identity:\n    - corp-jwt\n",
            "groups:\n  all:\n    identity:\n      - corp-jwt\n",
            "global:\n  defaults:\n    tool:\n      identity:\n        - corp-jwt\n",
        ] {
            let err = parse_config(yaml).expect_err("`identity:` must be rejected");
            let msg = format!("{err}");
            assert!(
                msg.contains("identity") && msg.contains("authentication"),
                "the rejection should name the replacement: {msg}"
            );
        }
    }

    #[test]
    fn parse_route_identity_scalar_shape_errors() {
        let yaml = r#"
engine_settings:
  dispatch: policy
routes:
  - tool: bad
    authentication: 42
"#;
        let err = parse_config(yaml).expect_err("scalar identity should fail");
        let msg = format!("{err}");
        assert!(msg.contains("list of steps"), "got: {msg}");
    }

    #[test]
    fn resolve_identity_returns_empty_when_no_route_matches() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    authentication:
      - corp-jwt
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "unmatched_tool", None);
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolve_identity_returns_empty_when_route_has_no_identity_block() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: rate_limiter, kind: builtin, hooks: [cmf.tool_pre_invoke] }
routes:
  - tool: get_weather
    authorization:
      pre_invocation: ["run(rate_limiter)"]
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_weather", None);
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolve_identity_preserves_declared_order() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: spiffe-attestor, kind: builtin, hooks: [identity.resolve] }
  - { name: agent-context, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    authentication:
      - spiffe-attestor
      - corp-jwt
      - agent-context
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_weather", None);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["spiffe-attestor", "corp-jwt", "agent-context"]);
    }

    #[test]
    fn resolve_identity_per_step_config_override_surfaces_for_create_override_instance() {
        // `create_override_instance` reads `overrides.get("config")`
        // — `resolve_identity_plugins_for_route` wraps the step's
        // `config_override` under that key so the existing override
        // pathway picks it up without a special case.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    authentication:
      - name: corp-jwt
        config:
          audience: my-tool
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_weather", None);
        assert_eq!(resolved.len(), 1);
        let overrides = resolved[0]
            .config_overrides
            .as_ref()
            .expect("overrides wrapped");
        let config = overrides.get("config").expect("config key present");
        assert_eq!(
            config.get("audience").and_then(|v| v.as_str()),
            Some("my-tool")
        );
    }

    #[test]
    fn resolve_identity_includes_global_layer_when_route_has_no_block() {
        // global.authentication defined; route declares none of its own. The
        // route should inherit the global steps unchanged.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
routes:
  - tool: get_weather
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_weather", None);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["corp-jwt"]);
    }

    #[test]
    fn resolve_identity_appends_route_steps_after_global_by_default() {
        // global → route is the standard stacking. Route's `identity:`
        // is the list form (implicit replace_inherited=false), so
        // its steps APPEND after the global's.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: agent-context, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
routes:
  - tool: get_weather
    authentication:
      - agent-context
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_weather", None);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["corp-jwt", "agent-context"]);
    }

    #[test]
    fn resolve_identity_stacks_global_then_tag_bundle_then_route() {
        // Full stack: global + tag bundle + route, all contributing.
        // Order is global first, then the matching tag's bundle,
        // then the route's own steps.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: workday-saml, kind: builtin, hooks: [identity.resolve] }
  - { name: agent-context, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
groups:
  finance:
    authentication:
      - workday-saml
routes:
  - tool: get_compensation
    meta:
      tags: [finance]
    authentication:
      - agent-context
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_compensation", None);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["corp-jwt", "workday-saml", "agent-context"]);
    }

    #[test]
    fn resolve_identity_replace_inherited_drops_global_and_tag_layers() {
        // Route says `replace_inherited: true` → only route's steps
        // survive. Global and tag-bundle contributions get dropped.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: workday-saml, kind: builtin, hooks: [identity.resolve] }
  - { name: legacy-basic-auth, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
groups:
  finance:
    authentication:
      - workday-saml
routes:
  - tool: legacy_endpoint
    meta:
      tags: [finance]
    authentication:
      replace_inherited: true
      steps:
        - legacy-basic-auth
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "legacy_endpoint", None);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["legacy-basic-auth"]);
    }

    #[test]
    fn resolve_identity_replace_inherited_with_empty_steps_yields_nothing() {
        // `replace_inherited: true` + `steps: []` is the explicit
        // opt-out — anonymous routes use this to suppress inherited
        // identity entirely.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
routes:
  - tool: anonymous_endpoint
    authentication:
      replace_inherited: true
      steps: []
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "anonymous_endpoint", None);
        assert!(resolved.is_empty());
    }

    /// Two bundles, the second replacing: the global layer and the first
    /// bundle go, the second bundle and the route stay.
    const TWO_BUNDLES_SECOND_REPLACES: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: workday-saml, kind: builtin, hooks: [identity.resolve] }
  - { name: legacy-basic-auth, kind: builtin, hooks: [identity.resolve] }
  - { name: agent-context, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
groups:
  finance:
    authentication:
      - workday-saml
  legacy:
    authentication:
      replace_inherited: true
      steps:
        - legacy-basic-auth
routes:
  - tool: get_compensation
    meta:
      tags: [finance, legacy]
    authentication:
      - agent-context
"#;

    #[test]
    fn resolve_identity_bundle_replace_inherited_drops_the_layers_before_it() {
        let cfg = parse_config(TWO_BUNDLES_SECOND_REPLACES).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_compensation", None);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["legacy-basic-auth", "agent-context"],
            "the replacing bundle drops the global layer and the bundle before it, \
             and the route still appends",
        );
    }

    /// `global.defaults.<entity>:` carries `authentication:` the way a bundle
    /// does, and it used to be accepted and read by nothing: the steps
    /// deserialized, and the resolver walked global to bundles to route
    /// straight past them. A key accepted and honored nowhere is what the rest
    /// of this key model exists to prevent.
    #[test]
    fn resolve_identity_reads_the_entity_default_layer() {
        let yaml = r#"
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: tool-attestor, kind: builtin, hooks: [identity.resolve] }
  - { name: agent-context, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
  defaults:
    tool:
      authentication:
        - tool-attestor
routes:
  - tool: get_compensation
    authentication:
      - agent-context
  - resource: report
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_compensation", None);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["corp-jwt", "tool-attestor", "agent-context"],
            "the entity default stacks between the global layer and the route, \
             the order the policy layers stack in",
        );
        let elsewhere = identity_for(&cfg, "resource", "report", None);
        let other: Vec<&str> = elsewhere.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            other,
            vec!["corp-jwt"],
            "and it reaches only its own entity type",
        );
    }

    /// The flag on an entity default drops what stacked before it, the way a
    /// bundle's does, and the load names the route that lost the steps.
    #[test]
    fn an_entity_default_can_replace_the_inherited_authentication() {
        let yaml = r#"
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: tool-attestor, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
  defaults:
    tool:
      authentication:
        replace_inherited: true
        steps:
          - tool-attestor
routes:
  - tool: get_compensation
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_compensation", None);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["tool-attestor"], "the global layer is dropped");
        assert_eq!(
            dropped_inherited_authentication(&cfg),
            vec![DroppedAuthentication {
                route: "tool:get_compensation".to_owned(),
                declared_in: "global.defaults.tool".to_owned(),
                dropped: vec!["corp-jwt".to_owned()],
            }],
            "and the drop is reported, since the route's own block does not show it",
        );
    }

    #[test]
    fn resolve_identity_bundle_order_decides_what_the_flag_drops() {
        // The same two bundles named the other way round: `legacy` replaces
        // the global layer only, so `finance` survives behind it. Which
        // bundle replaces is readable from tag declaration order.
        let yaml = TWO_BUNDLES_SECOND_REPLACES
            .replace("tags: [finance, legacy]", "tags: [legacy, finance]");
        let cfg = parse_config(&yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_compensation", None);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["legacy-basic-auth", "workday-saml", "agent-context"],
        );
    }

    #[test]
    fn resolve_identity_bundle_replace_inherited_with_empty_steps_contributes_nothing() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
groups:
  public:
    authentication:
      replace_inherited: true
      steps: []
global:
  authentication:
    - corp-jwt
routes:
  - tool: healthcheck
    groups: public
"#;
        let cfg = parse_config(yaml).unwrap();
        assert!(
            identity_for(&cfg, "tool", "healthcheck", None).is_empty(),
            "an empty replacing bundle is the anonymous-route knob at bundle scope",
        );
    }

    #[test]
    fn dropped_inherited_authentication_names_the_route_and_the_bundle() {
        let cfg = parse_config(TWO_BUNDLES_SECOND_REPLACES).unwrap();
        assert_eq!(
            dropped_inherited_authentication(&cfg),
            vec![DroppedAuthentication {
                route: "tool:get_compensation".to_owned(),
                declared_in: "groups.legacy".to_owned(),
                dropped: vec!["corp-jwt".to_owned(), "workday-saml".to_owned()],
            }],
        );
    }

    #[test]
    fn dropped_inherited_authentication_is_silent_when_the_route_replaces() {
        // The route's own flag drops the same layers, and its author can
        // read that off the route. Nothing to report.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: legacy-basic-auth, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
groups:
  legacy:
    authentication:
      replace_inherited: true
      steps:
        - legacy-basic-auth
routes:
  - tool: legacy_endpoint
    groups: legacy
    authentication:
      replace_inherited: true
      steps:
        - legacy-basic-auth
"#;
        let cfg = parse_config(yaml).unwrap();
        assert!(dropped_inherited_authentication(&cfg).is_empty());
    }

    #[test]
    fn dropped_inherited_authentication_is_silent_when_nothing_was_inherited() {
        // A replacing bundle with no layer before it drops nothing, so
        // reporting it would send an operator after a non-event.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: legacy-basic-auth, kind: builtin, hooks: [identity.resolve] }
groups:
  legacy:
    authentication:
      replace_inherited: true
      steps:
        - legacy-basic-auth
routes:
  - tool: legacy_endpoint
    groups: legacy
"#;
        let cfg = parse_config(yaml).unwrap();
        assert!(dropped_inherited_authentication(&cfg).is_empty());
        let resolved = identity_for(&cfg, "tool", "legacy_endpoint", None);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["legacy-basic-auth"]);
    }

    #[test]
    fn resolve_identity_tag_bundle_only_when_route_carries_the_tag() {
        // The tag bundle's identity only contributes when the route
        // declares the matching tag — not for unrelated routes.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: workday-saml, kind: builtin, hooks: [identity.resolve] }
groups:
  finance:
    authentication:
      - workday-saml
routes:
  - tool: with_tag
    meta:
      tags: [finance]
  - tool: without_tag
"#;
        let cfg = parse_config(yaml).unwrap();

        let tagged = identity_for(&cfg, "tool", "with_tag", None);
        assert_eq!(
            tagged.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["workday-saml"],
        );

        let untagged = identity_for(&cfg, "tool", "without_tag", None);
        assert!(
            untagged.is_empty(),
            "tag bundle should NOT apply to untagged routes"
        );
    }

    #[test]
    fn groups_field_is_sugar_for_meta_tags_in_plugin_resolution() {
        // A route's `groups:` joins the same bundle as `meta.tags` — both
        // desugar to the same tag set, so resolution is identical. String and
        // list forms both work. Read through `authentication:`, the dispatch
        // list a bundle still contributes.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: pii-scan, kind: builtin, hooks: [identity.resolve] }
groups:
  hr-tools:
    authentication:
      - pii-scan
routes:
  - tool: via_tags
    meta:
      tags: [hr-tools]
  - tool: via_groups_list
    groups: [hr-tools]
  - tool: via_groups_string
    groups: hr-tools
"#;
        let cfg = parse_config(yaml).unwrap();
        let names = |entity: &str| {
            identity_for(&cfg, "tool", entity, None)
                .iter()
                .map(|r| r.name.clone())
                .collect::<Vec<_>>()
        };

        assert_eq!(names("via_tags"), vec!["pii-scan"]);
        assert_eq!(
            names("via_groups_list"),
            names("via_tags"),
            "groups: [x] must resolve identically to meta.tags: [x]"
        );
        assert_eq!(
            names("via_groups_string"),
            names("via_tags"),
            "bare-string groups: x must resolve identically too"
        );
    }

    #[test]
    fn groups_field_is_sugar_for_meta_tags_in_identity_resolution() {
        // The same sugar applies to the identity (authentication) resolver.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: workday-saml, kind: builtin, hooks: [identity.resolve] }
groups:
  finance:
    authentication:
      - workday-saml
routes:
  - tool: via_groups
    groups: finance
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "via_groups", None);
        assert_eq!(
            resolved.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["workday-saml"],
            "groups: sugar pulls the bundle's authentication just like meta.tags"
        );
    }

    #[test]
    fn groups_and_meta_tags_compose_as_a_union() {
        // A route may carry both spellings; effective membership is the union.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: a, kind: builtin, hooks: [identity.resolve] }
  - { name: b, kind: builtin, hooks: [identity.resolve] }
groups:
  grp-a:
    authentication: [a]
  grp-b:
    authentication: [b]
routes:
  - tool: both
    meta:
      tags: [grp-a]
    groups: [grp-b]
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "both", None);
        let names: Vec<_> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"a"),
            "meta.tags bundle must apply: {names:?}"
        );
        assert!(names.contains(&"b"), "groups bundle must apply: {names:?}");
    }

    #[test]
    fn top_level_groups_is_the_only_bundle_location() {
        // Bundles live at top-level `groups:` and nowhere else. This is the
        // shape a config that used to write `global.policies:` becomes, and it
        // resolves the same way that one did.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: workday-saml, kind: builtin, hooks: [identity.resolve] }
groups:
  finance:
    authentication:
      - workday-saml
routes:
  - tool: pay
    groups: finance
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "pay", None);
        assert_eq!(
            resolved.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["workday-saml"],
            "a bundle at top-level groups: must resolve"
        );
    }

    #[test]
    fn a_bundle_under_global_policies_is_rejected() {
        // The removed location fails the load naming what replaced it, rather
        // than dropping the bundle and leaving every route that joins it
        // unguarded.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: b, kind: builtin, hooks: [identity.resolve] }
global:
  policies:
    old-loc:
      authentication: [b]
routes:
  - tool: mixed
    groups: [old-loc]
"#;
        let err = parse_config(yaml).expect_err("`global.policies:` must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("policies") && msg.contains("groups"),
            "the rejection must name the key and its replacement: {msg}"
        );
    }

    #[test]
    fn stale_identity_key_under_top_level_groups_is_rejected() {
        // The fail-loud guard extends to the new location.
        let yaml = r#"
engine_settings:
  dispatch: policy
groups:
  finance:
    identity:
      - old-key
"#;
        let err = parse_config(yaml).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("groups.finance"), "names the scope: {msg}");
        assert!(msg.contains("authentication"), "mentions the rename: {msg}");
    }

    #[test]
    fn route_joining_unknown_group_is_rejected() {
        // A typo'd `groups:` value must fail at load, not silently
        // leave the route without the group's authentication.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: jwt-hr, kind: identity/jwt, hooks: [identity.resolve] }
groups:
  hr-tools:
    authentication: [jwt-hr]
routes:
  - tool: get_compensation
    groups: hr-toolz
"#;
        let err = parse_config(yaml).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown group"), "names the error: {msg}");
        assert!(msg.contains("hr-toolz"), "names the typo: {msg}");
    }

    #[test]
    fn route_joining_defined_group_passes_validation() {
        // Sanity: a correct `groups:` reference (and via meta.tags, which
        // stays permissive) validates fine.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: jwt-hr, kind: identity/jwt, hooks: [identity.resolve] }
groups:
  hr-tools:
    authentication: [jwt-hr]
routes:
  - tool: get_compensation
    groups: hr-tools
  - tool: search_repos
    meta: { tags: [some-runtime-tag] }
"#;
        parse_config(yaml).unwrap();
    }

    #[test]
    fn resolve_identity_scope_filtering_matches_other_route_resolution() {
        // Identity routing uses the same scope-aware matcher as the
        // generic `plugins:` resolution,
        // so requests for a different scope shouldn't pick up
        // identity from this route.
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    meta:
      scope: tenant-a
    authentication:
      - corp-jwt
"#;
        let cfg = parse_config(yaml).unwrap();
        let matching = identity_for(&cfg, "tool", "get_weather", Some("tenant-a"));
        assert_eq!(matching.len(), 1);

        let non_matching = identity_for(&cfg, "tool", "get_weather", Some("tenant-b"));
        assert!(non_matching.is_empty());
    }

    fn deserialize_cfg(yaml: &str) -> Result<PolicyConfig, String> {
        serde_yaml::from_str(yaml).map_err(|e| e.to_string())
    }

    #[test]
    fn route_plugins_list_parses_as_activation_list() {
        let cfg = deserialize_cfg(
            r#"
routes:
  - tool: get_weather
    plugins:
      - rate_limiter
      - pii_scanner:
          config:
            sensitivity: high
"#,
        )
        .unwrap();
        let plugins = &cfg.routes[0].plugins;
        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[0].name(), "rate_limiter");
        assert_eq!(plugins[1].name(), "pii_scanner");
    }

    #[test]
    fn route_plugins_map_loads_as_empty_structural_list() {
        let cfg = deserialize_cfg(
            r#"
routes:
  - tool: get_weather
    plugins:
      audit:
        on_error: ignore
"#,
        )
        .expect("flat plugins map must deserialize");
        assert!(
            cfg.routes[0].plugins.is_empty(),
            "a plugins map is APL-override data, not a structural activation list",
        );
    }

    #[test]
    fn defaults_and_bundle_plugins_map_loads() {
        let cfg = deserialize_cfg(
            r#"
global:
  defaults:
    tool:
      plugins:
        audit:
          on_error: ignore
groups:
  sensitive:
    plugins:
      pii_scanner:
        config:
          sensitivity: high
"#,
        )
        .expect("defaults/bundle plugins map must deserialize");
        assert!(cfg.global.defaults["tool"].plugins.is_empty());
        // A bare deserialize does not fold `groups:` into the bundle store, so
        // the bundle is read where the document wrote it.
        assert!(cfg.groups["sensitive"].plugins.is_empty());
    }

    #[test]
    fn scalar_plugins_value_is_rejected_with_clear_error() {
        let err = deserialize_cfg(
            r#"
routes:
  - tool: get_weather
    plugins: nonsense
"#,
        )
        .expect_err("scalar plugins must error");
        assert!(
            err.contains("sequence") && err.contains("mapping"),
            "expected a shape-aware error, got: {err}",
        );
    }

    // ---- load and parse failures ------------------------------------------

    /// A missing config file has to name the path. Operators hit this on a typo
    /// or a bad mount, and the OS error alone does not say which file.
    #[test]
    fn a_missing_config_file_reports_the_path() {
        let err = load_config(std::path::Path::new(
            "/nonexistent/praxis-policy-test/policy.yaml",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("failed to read config file"), "{err}");
        assert!(
            err.contains("policy.yaml"),
            "the message must name the file: {err}"
        );
    }

    #[test]
    fn malformed_yaml_is_reported_as_a_parse_failure() {
        let err = parse_config("plugins: [unclosed\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to parse config YAML"), "{err}");
    }

    /// The default when nothing is declared. A config that parsed to something
    /// other than an empty policy would change behavior for every deployment
    /// that omits a section.
    #[test]
    fn an_empty_document_parses_to_an_empty_policy() {
        let cfg = parse_config("{}\n").expect("an empty mapping is a valid config");
        assert!(cfg.plugins.is_empty());
        assert!(cfg.routes.is_empty());
    }

    /// `Pattern` and `StringOrList` both have a `Default` with no caller. The
    /// default is the empty pattern, and what matters is that it matches nothing
    /// rather than everything: a default that behaved like `*` would silently
    /// widen any route that fell back to it.
    #[test]
    fn the_matcher_defaults_match_nothing_rather_than_everything() {
        let p = Pattern::default();
        assert_eq!(p.as_str(), "", "the default pattern is empty");
        assert!(
            !p.matches("get_compensation"),
            "an empty pattern must not behave like a wildcard"
        );
        assert!(!p.matches("*"), "nor match a literal asterisk");
        assert!(p.matches(""), "it does match the empty name, as written");

        let s = StringOrList::default();
        assert!(
            !s.matches("get_compensation"),
            "the default matcher must not admit an arbitrary name"
        );
    }

    // ---- the `http:` selector ---------------------------------------------

    /// Collect the exact paths a selector matches, for comparison against what
    /// the config declared.
    fn exact_paths_of(selector: &HttpSelector) -> Vec<&str> {
        selector
            .exact_paths()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    }

    /// The three shapes and what each asks for: a bare string and a list are
    /// exact paths, the map form is a prefix or an exact path, optionally
    /// narrowed by method. Each also serializes back to what was written, so a
    /// config round-trips through a tool that reads and rewrites it.
    #[test]
    fn every_http_selector_shape_parses_and_serializes_back() {
        let yaml = r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http: /healthz
  - http: [/livez, /readyz]
  - http:
      path_prefix: /v1/files
      method: GET
  - http:
      path: /v1/files/manifest
      method: [GET, HEAD]
"#;
        let cfg = parse_config(yaml).expect("every `http:` shape must parse");

        let scalar = cfg.routes[0].http.as_ref().expect("scalar form");
        assert_eq!(exact_paths_of(scalar), ["/healthz"]);
        assert_eq!(scalar.path_prefix(), None);
        assert!(scalar.method().is_none(), "no method narrows a bare path");

        let list = cfg.routes[1].http.as_ref().expect("list form");
        assert_eq!(exact_paths_of(list), ["/livez", "/readyz"]);
        assert_eq!(list.path_prefix(), None);

        let prefix = cfg.routes[2].http.as_ref().expect("prefix form");
        assert!(
            prefix.exact_paths().is_empty(),
            "a prefix selector matches no path by equality"
        );
        assert_eq!(prefix.path_prefix(), Some("/v1/files"));
        assert!(prefix.method().expect("method matcher").matches("GET"));

        let exact_map = cfg.routes[3].http.as_ref().expect("map form with `path:`");
        assert_eq!(exact_paths_of(exact_map), ["/v1/files/manifest"]);
        assert_eq!(exact_map.path_prefix(), None);
        assert_eq!(
            exact_map.method().expect("method matcher").as_names(),
            ["GET", "HEAD"]
        );

        assert_eq!(
            serde_yaml::to_string(scalar).expect("serialize").trim(),
            "/healthz"
        );
        assert_eq!(
            serde_yaml::to_string(list).expect("serialize"),
            "- /livez\n- /readyz\n"
        );
        assert_eq!(
            serde_yaml::to_string(prefix).expect("serialize"),
            "path_prefix: /v1/files\nmethod: GET\n"
        );
    }

    /// A trailing slash on a prefix is insignificant, matching how the host's
    /// router reads one, so both spellings land on the same selector.
    #[test]
    fn a_trailing_slash_on_a_prefix_parses_to_the_same_selector() {
        let cfg = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  # Distinct scopes, since two routes resolving to one name in one scope is
  # rejected and both spellings resolve to the same name.
  - http: { path_prefix: /api }
    meta:
      scope: tenant-a
  - http: { path_prefix: "/api/" }
    meta:
      scope: tenant-b
"#,
        )
        .expect("both spellings must parse");

        let written = cfg.routes[0].http.as_ref().expect("without slash");
        let with_slash = cfg.routes[1].http.as_ref().expect("with slash");
        assert_eq!(written.path_prefix(), Some("/api"));
        assert_eq!(with_slash.path_prefix(), written.path_prefix());
        assert_eq!(
            serde_yaml::to_string(with_slash).expect("serialize"),
            serde_yaml::to_string(written).expect("serialize"),
        );
    }

    /// The root prefix keeps its slash. Trimming it would leave an empty string
    /// for a diagnostic to name, and the catch-all is the one prefix an operator
    /// is most likely to read back out of an error message.
    #[test]
    fn the_root_prefix_keeps_its_slash() {
        let cfg = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http: { path_prefix: "/" }
"#,
        )
        .expect("the catch-all prefix must parse");
        assert_eq!(
            cfg.routes[0]
                .http
                .as_ref()
                .expect("prefix form")
                .path_prefix(),
            Some("/")
        );
    }

    // ---- what an `http:` route set leaves ungoverned -----------------------

    /// Routes covering three paths and everything else. Nothing falls through,
    /// so a load has nothing to say.
    #[test]
    fn http_routes_with_a_catch_all_leave_no_gap_to_report() {
        let cfg = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http: /healthz
  - http: { path_prefix: /v1/files }
  - http: { path_prefix: "/" }
"#,
        )
        .expect("the fixture must load");
        assert!(
            http_routing_gaps(&cfg).is_empty(),
            "an explicit catch-all governs what the other routes do not"
        );
    }

    /// The overlap the selector exists inside: three scoped paths and no route
    /// for the rest, which the global policy governs instead. An operator who
    /// scoped those three and stopped has to be told.
    #[test]
    fn http_routes_without_a_catch_all_report_the_fallback_to_global() {
        let cfg = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http: /healthz
  - http: { path_prefix: /v1/files }
  - http: { path: /v1/admin, method: POST }
"#,
        )
        .expect("the fixture must load");
        let gaps = http_routing_gaps(&cfg);
        assert_eq!(gaps.len(), 1, "one gap, reported once: {gaps:?}");
        assert!(gaps[0].contains("count=3"), "{}", gaps[0]);
        assert!(
            gaps[0].contains("global policy"),
            "the message names where the rest of the traffic goes: {}",
            gaps[0]
        );
    }

    /// A root prefix narrowed by `method:` covers one method and leaves the
    /// others falling through, so it is not the catch-all.
    #[test]
    fn a_root_prefix_narrowed_by_method_is_not_the_catch_all() {
        let cfg = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http: { path_prefix: "/", method: GET }
"#,
        )
        .expect("the fixture must load");
        assert_eq!(
            http_routing_gaps(&cfg).len(),
            1,
            "a GET-only root prefix governs no other method"
        );
    }

    /// The routing-off report is gone rather than reworded: hook dispatch
    /// rejects `routes:` outright, so an `http:` route only ever reaches the gap
    /// scan in policy mode and the branch had no input left.
    #[test]
    fn an_http_route_under_hook_dispatch_never_reaches_the_gap_scan() {
        let message = parse_config(
            r#"
engine_settings:
  dispatch: hooks
plugins: []
routes:
  - http: { path_prefix: /v1/files }
"#,
        )
        .expect_err("hook dispatch rejects the route before any gap is scanned")
        .to_string();
        assert!(message.contains("`routes`"), "{message}");
    }

    /// A configuration that declares no `http:` route is what every deployment
    /// running today has, so the report has to stay silent for it, glob route
    /// included.
    #[test]
    fn a_config_with_no_http_route_reports_no_gap() {
        let cfg = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_compensation
  - tool: "hr-*"
  - resource: "file:///etc/*"
  - llm: gpt-4
  - prompt: summarize
"#,
        )
        .expect("the fixture must load");
        assert!(
            http_routing_gaps(&cfg).is_empty(),
            "nothing about the four name selectors is reported here"
        );
    }

    /// `http` is an entity type like the other four, so a default declared for
    /// it is found by the same lookup the resolvers already do.
    #[test]
    fn a_global_default_for_http_is_reachable_by_entity_type() {
        let cfg = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: builtin
    hooks: [http.request]
global:
  defaults:
    http:
      description: the http entity default
"#,
        )
        .expect("`global.defaults.http` must parse");

        assert!(
            cfg.global.defaults.contains_key("http"),
            "an http default has to survive the load"
        );
    }

    /// A `global.defaults.<entity>` entry is a scope like any other, so its
    /// activation list is rejected under its own path.
    #[test]
    fn an_entity_defaults_plugins_list_is_rejected_in_policy_mode() {
        let message = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: builtin
    hooks: [http.request]
global:
  defaults:
    http:
      plugins: [corp-jwt]
"#,
        )
        .expect_err("a defaults entry cannot activate a plugin in policy mode")
        .to_string();
        assert!(message.contains("global.defaults.http"), "{message}");
        assert!(message.contains("run(name)"), "{message}");
    }

    /// A misspelled entity type under `global.defaults` applies to nothing, so
    /// it fails at load rather than sitting there inert.
    #[test]
    fn a_global_default_for_an_unknown_entity_type_is_rejected() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
global:
  defaults:
    htp:
      description: a misspelled entity type
"#,
        )
        .expect_err("an unknown entity type must fail the load")
        .to_string();
        assert!(err.contains("htp"), "{err}");
        assert!(err.contains("not an entity type"), "{err}");
        assert!(
            err.contains("http"),
            "the message names the real types: {err}"
        );
    }

    #[test]
    fn a_route_declaring_http_beside_tool_names_both() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_compensation
    http: /v1/compensation
"#,
        )
        .expect_err("two selectors on one route must fail")
        .to_string();
        assert!(err.contains("multiple entity matchers"), "{err}");
        assert!(err.contains("tool"), "{err}");
        assert!(err.contains("http"), "{err}");
    }

    #[test]
    fn a_route_with_no_selector_names_http_among_the_alternatives() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - meta:
      tags: [pii]
"#,
        )
        .expect_err("a route with no selector must fail")
        .to_string();
        assert!(err.contains("no entity matcher"), "{err}");
        assert!(err.contains("http"), "{err}");
    }

    /// A misspelled selector used to load clean: serde drops the unknown key
    /// and the route then matched nothing at all.
    #[test]
    fn a_misspelled_route_key_names_the_key_and_the_route() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
  - htp: /v1/files
"#,
        )
        .expect_err("an unknown route key must fail the load")
        .to_string();
        assert!(err.contains("route 1"), "the route index: {err}");
        assert!(err.contains("htp"), "the key as written: {err}");
    }

    /// The unknown-key error carries the replacement, so a stale `identity:`
    /// block still tells the operator what to write instead.
    #[test]
    fn a_stale_identity_key_names_its_replacement() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    identity:
      - corp-jwt
"#,
        )
        .expect_err("a removed key must fail the load")
        .to_string();
        assert!(err.contains("replaced by `authentication`"), "{err}");
    }

    /// A stale `policy:` block gets more than the key set: the unknown-key error
    /// names the spelling that replaced it, so the operator is told where the
    /// block's contents belong rather than sent looking for a misspelling.
    #[test]
    fn a_stale_policy_key_on_a_route_names_its_replacement() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    policy:
      - "require(authenticated)"
"#,
        )
        .expect_err("a removed key must fail the load")
        .to_string();
        assert!(
            err.contains("replaced by `authorization.pre_invocation"),
            "the replacement, not the key set alone: {err}"
        );
    }

    /// The post-phase half of the same removal. Dropping either block leaves
    /// no authorization enforced, so both fail the load.
    #[test]
    fn a_stale_post_policy_key_on_a_route_names_its_replacement() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    post_policy:
      - "require(authenticated)"
"#,
        )
        .expect_err("a removed key must fail the load")
        .to_string();
        assert!(
            err.contains("replaced by `authorization.post_invocation"),
            "{err}"
        );
    }

    /// One load names every bad key, and the replacement clause is attached to
    /// the key that has one rather than to the list.
    #[test]
    fn a_replacement_is_named_beside_the_unknown_keys_it_shares_the_route_with() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    policy:
      - "require(authenticated)"
    htp: /v1/files
"#,
        )
        .expect_err("a removed key must fail the load")
        .to_string();
        assert!(err.contains("htp"), "the typo is named too: {err}");
        assert!(
            err.contains("replaced by `authorization.pre_invocation"),
            "{err}"
        );
    }

    /// Three bad keys used to take three loads to find. One load now names
    /// all of them.
    #[test]
    fn every_unknown_key_on_a_route_is_named_in_one_error() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    htp: /v1/files
    mehta:
      tags: [pii]
    plugns: []
"#,
        )
        .expect_err("an unknown route key must fail the load")
        .to_string();
        for key in ["htp", "mehta", "plugns"] {
            assert!(err.contains(key), "the error must name `{key}`: {err}");
        }
        assert!(err.contains("unknown keys"), "plural: {err}");
    }

    /// A host orchestrator's own route key stays loadable, which is what the
    /// visitor-declared extras are for. The same key with no visitor declaring
    /// it is still a typo.
    #[test]
    fn a_visitor_declared_route_key_is_accepted() {
        let raw: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes:
  - tool: get_weather
    orchestrator_only: yes
"#,
        )
        .expect("fixture parses");
        reject_unknown_route_keys(&raw, &["orchestrator_only"])
            .expect("a visitor-declared key is not a typo");
        reject_unknown_route_keys(&raw, &[])
            .expect_err("with no visitor declaring it, the key is unknown");
    }

    /// A route shares its mapping with the orchestrator blocks praxis-policy-core
    /// carries but does not model, so the key check has to accept them.
    #[test]
    fn a_route_carrying_orchestrator_blocks_loads() {
        parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "require(authenticated)"
    response:
      status: 403
"#,
        )
        .expect("the policy terms and `response:` are route siblings, not typos");
    }

    /// Every orchestrator term a route accepts, plus the per-plugin override map
    /// form of `plugins:`.
    #[test]
    fn a_route_declaring_every_orchestrator_term_loads() {
        parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "run(deny-gate)"
        - "require(authenticated)"
      post_invocation: []
    args: {}
    result: {}
    plugins:
      deny-gate:
        on_error: ignore
"#,
        )
        .expect("every term a route accepts must load together");
    }

    /// The two phase lists appear under `authorization:` and nowhere else, so a
    /// route still writing one flat names it as the unknown key it now is rather
    /// than loading with its authorization silently dropped.
    #[test]
    fn a_route_writing_a_phase_list_flat_is_rejected() {
        for phase in ["pre_invocation", "post_invocation"] {
            let err = parse_config(&format!(
                r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    {phase}:
      - "require(authenticated)"
"#
            ))
            .expect_err("a phase list written flat is no longer a route key")
            .to_string();
            assert!(err.contains(phase), "the error must name `{phase}`: {err}");
        }
    }

    /// The `apl:` wrapper is gone: a route that still writes one names it as an
    /// unknown key rather than dropping the policy inside it.
    #[test]
    fn a_route_carrying_an_apl_wrapper_is_rejected() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    apl:
      authorization:
        pre_invocation:
          - "require(authenticated)"
"#,
        )
        .expect_err("the wrapper is no longer a route key")
        .to_string();
        assert!(err.contains("apl"), "the error must name the key: {err}");
    }

    /// A PDP and the session store are process-global wiring. Declared on a
    /// route they used to load and warn; the declaration now fails the load.
    #[test]
    fn a_route_carrying_engine_wiring_is_rejected() {
        for (key, block) in [
            ("pdp", "pdp: []"),
            ("session_store", "session_store:\n      kind: memory"),
        ] {
            let err = parse_config(&format!(
                "engine_settings:\n  dispatch: policy\nplugins: []\nroutes:\n  - tool: get_weather\n    {block}\n"
            ))
            .expect_err("engine wiring belongs under `global:`")
            .to_string();
            assert!(err.contains(key), "the error must name `{key}`: {err}");
        }
    }

    #[test]
    fn an_empty_http_list_is_rejected() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http: []
"#,
        )
        .expect_err("a selector that matches nothing must fail")
        .to_string();
        assert!(err.contains("route 0"), "{err}");
        assert!(err.contains("empty `http:` list"), "{err}");
    }

    #[test]
    fn an_http_map_declaring_neither_path_nor_prefix_is_rejected() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http:
      method: GET
"#,
        )
        .expect_err("a method alone selects nothing")
        .to_string();
        assert!(err.contains("route 0"), "{err}");
        assert!(err.contains("neither `path:` nor `path_prefix:`"), "{err}");
    }

    #[test]
    fn an_http_map_declaring_both_path_and_prefix_is_rejected() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http:
      path: /v1/files
      path_prefix: /v1
"#,
        )
        .expect_err("equality and prefix ask for different matches")
        .to_string();
        assert!(err.contains("route 0"), "{err}");
        assert!(err.contains("both `path:` and `path_prefix:`"), "{err}");
    }

    /// An empty method list narrows a route to nothing, so it is a defect
    /// rather than a route that quietly never matches.
    #[test]
    fn an_http_map_declaring_an_empty_method_list_is_rejected() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http:
      path_prefix: /v1
      method: []
"#,
        )
        .expect_err("no method can match an empty list")
        .to_string();
        assert!(err.contains("route 0"), "{err}");
        assert!(err.contains("empty `http.method:` list"), "{err}");
    }

    #[test]
    fn an_http_map_declaring_an_empty_method_is_rejected() {
        for method in ["\"\"", "[GET, \"\"]"] {
            let err = parse_config(&format!(
                r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http:
      path_prefix: /v1
      method: {method}
"#
            ))
            .expect_err("an empty method name matches nothing")
            .to_string();
            assert!(err.contains("route 0"), "{method}: {err}");
            assert!(
                err.contains("empty method under `http.method:`"),
                "{method}: {err}"
            );
        }
    }

    /// The load error for a config declaring one `http:` route, written as just
    /// the selector, so a case reads as the selector it declares.
    fn selector_error(selector: &str) -> String {
        let yaml = format!(
            "engine_settings:\n  dispatch: policy\nplugins: []\nroutes:\n  - http: \
             {selector}\n"
        );
        parse_config(&yaml)
            .expect_err("a malformed selector must fail the load")
            .to_string()
    }

    /// A declared path that is not absolute matches nothing, because matching
    /// reads the request line as given and a request path starts with `/`. Every
    /// shape that can carry one refuses it and names it, rather than loading a
    /// route that can never match.
    #[test]
    fn a_declared_path_that_is_not_absolute_is_rejected() {
        for (selector, named) in [
            ("healthz", "healthz"),
            ("[healthz]", "healthz"),
            ("[/livez, readyz]", "readyz"),
            ("{ path: healthz }", "healthz"),
            ("{ path: healthz, method: GET }", "healthz"),
            ("{ path_prefix: v1 }", "v1"),
            ("{ path_prefix: v1, method: GET }", "v1"),
        ] {
            let err = selector_error(selector);
            assert!(err.contains("route 0"), "{selector}: {err}");
            assert!(err.contains("not an absolute path"), "{selector}: {err}");
            assert!(err.contains(named), "{selector}: {err}");
        }
    }

    /// A method is compared literally against the value as written, so anything
    /// but a bare token is a route that matches nothing: `GET*` reads as a glob
    /// no dialect here expands, and a typo carrying a space or a slash is the
    /// same dead route.
    #[test]
    fn a_method_that_is_not_a_token_is_rejected() {
        for (selector, named) in [
            ("{ path_prefix: /v1, method: 'GET*' }", "GET*"),
            ("{ path_prefix: /v1, method: '*' }", "*"),
            ("{ path_prefix: /v1, method: 'GET POST' }", "GET POST"),
            ("{ path_prefix: /v1, method: 'GET/POST' }", "GET/POST"),
            ("{ path_prefix: /v1, method: [GET, 'PO ST'] }", "PO ST"),
            ("{ path: /v1, method: 'GÉT' }", "GÉT"),
        ] {
            let err = selector_error(selector);
            assert!(err.contains("route 0"), "{selector}: {err}");
            assert!(
                err.contains("not an HTTP method token"),
                "{selector}: {err}"
            );
            assert!(err.contains(named), "{selector}: {err}");
        }
    }

    /// The token check refuses what cannot match, not what is unfamiliar: a
    /// method is any RFC 9110 token, so an extension verb loads.
    #[test]
    fn a_method_written_as_a_bare_token_loads() {
        let cfg = routed_config("  - http: { path_prefix: /dav, method: [PROPFIND, M-SEARCH] }\n");
        assert_eq!(cfg.routes.len(), 1);
        assert!(
            http_name(&cfg, "/dav/x", Some("PROPFIND")).is_some(),
            "an extension verb matches the way a standard one does"
        );
    }

    /// The catch-all policy that governs a request matching no route is
    /// annotated under the reserved name, so no route may render it: a route
    /// that did would govern every unmatched request while matching none itself.
    /// Written over every `http:` shape, since one refused spelling is not the
    /// invariant. The shapes that cannot render the reserved name are refused
    /// for the path instead, and both refusals close the hijack.
    #[test]
    fn no_http_selector_shape_can_claim_the_reserved_global_name() {
        for (selector, reason) in [
            (format!("\"{ENTITY_NAME_GLOBAL}\""), "reserved"),
            (format!("[\"{ENTITY_NAME_GLOBAL}\"]"), "reserved"),
            (format!("[/healthz, \"{ENTITY_NAME_GLOBAL}\"]"), "reserved"),
            (format!("{{ path: \"{ENTITY_NAME_GLOBAL}\" }}"), "reserved"),
            (
                format!("{{ path: \"{ENTITY_NAME_GLOBAL}\", method: GET }}"),
                "not an absolute path",
            ),
            (
                format!("{{ path_prefix: \"{ENTITY_NAME_GLOBAL}\" }}"),
                "not an absolute path",
            ),
            (
                format!("{{ path_prefix: \"{ENTITY_NAME_GLOBAL}\", method: GET }}"),
                "not an absolute path",
            ),
        ] {
            let err = selector_error(&selector);
            assert!(err.contains("route 0"), "{selector}: {err}");
            assert!(err.contains(reason), "{selector}: {err}");
        }
    }

    /// A route claiming the reserved name is refused on the name rather than
    /// waved through, and the mode is the only thing that changes which of the
    /// two refusals an operator reads.
    #[test]
    fn a_route_claiming_the_reserved_name_is_refused_in_policy_mode() {
        let err = parse_config(&format!(
            "engine_settings:\n  dispatch: policy\nplugins: []\nroutes:\n  - http: \
             \"{ENTITY_NAME_GLOBAL}\"\n"
        ))
        .expect_err("the reserved name is refused")
        .to_string();
        assert!(err.contains("route 0"), "{err}");
        assert!(err.contains("reserved"), "{err}");
    }

    /// The invariant read positively: whatever shape a route that loads
    /// declares, none of the names it contributes is the reserved one.
    #[test]
    fn no_loadable_http_route_renders_the_reserved_global_name() {
        let cfg = routed_config(
            "  - http: /healthz\n  - http: [/livez, /readyz]\n  - http: { path: /v1/manifest }\n  \
             - http: { path: /v1/manifest, method: GET }\n  - http: { path_prefix: /v1 }\n  - \
             http: { path_prefix: /v1, method: [GET, POST] }\n  - http: { path_prefix: / }\n",
        );
        assert_eq!(cfg.routes.len(), 7, "one route per selector shape");
        for (i, route) in cfg.routes.iter().enumerate() {
            let (entity_type, names) =
                route_entity_identity(route).expect("every route declares `http:`");
            assert_eq!(entity_type, ENTITY_HTTP);
            for name in names {
                assert_ne!(
                    name, ENTITY_NAME_GLOBAL,
                    "route {i} renders the reserved catch-all name"
                );
            }
        }
    }

    /// A typo inside the map form is a key nothing reads, and the map's own
    /// parse names it rather than reporting the whole selector as malformed.
    #[test]
    fn an_unknown_key_inside_the_http_map_names_the_key() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http:
      path_prefx: /v1/files
"#,
        )
        .expect_err("an unknown key under `http:` must fail")
        .to_string();
        assert!(err.contains("path_prefx"), "{err}");
        assert!(err.contains("path_prefix"), "the accepted keys: {err}");
    }

    #[test]
    fn an_http_selector_of_the_wrong_shape_is_reported() {
        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http: 8080
"#,
        )
        .expect_err("a number is not a path")
        .to_string();
        assert!(err.contains("`http:`"), "{err}");

        let err = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http: [/healthz, 8080]
"#,
        )
        .expect_err("a number is not a path")
        .to_string();
        assert!(err.contains("list entry [1]"), "{err}");
    }

    /// A host may build a route in Rust instead of YAML, so the constructors
    /// have to normalize a prefix the same way the parse does.
    #[test]
    fn a_selector_built_in_rust_matches_a_parsed_one() {
        let built = HttpSelector::prefix("/api/");
        assert_eq!(built.path_prefix(), Some("/api"));
        assert!(built.exact_paths().is_empty());
        assert!(built.method().is_none());

        let built = HttpSelector::exact("/healthz");
        assert_eq!(exact_paths_of(&built), ["/healthz"]);
        assert_eq!(built.path_prefix(), None);
    }

    /// An empty selector list parses into a selector rather than into nothing,
    /// which is what leaves the defect for the load-time check to name.
    #[test]
    fn an_empty_http_selector_list_still_parses_into_a_selector() {
        let route: RouteEntry = serde_yaml::from_str("http: []\n").expect("the shape parses");
        assert!(route.http.is_some());
    }

    // ---- no two routes resolve to one name --------------------------------

    /// Load a config written as just its `routes:` block and return the error
    /// text, so a duplicate case reads as the selectors it declares.
    fn duplicate_error(routes: &str) -> String {
        let yaml = format!("engine_settings:\n  dispatch: policy\nplugins: []\nroutes:\n{routes}");
        parse_config(&yaml)
            .expect_err("two routes resolving to one name must fail")
            .to_string()
    }

    /// Load a config written as just its `routes:` block, expecting success.
    fn routes_load(routes: &str) -> PolicyConfig {
        let yaml = format!("engine_settings:\n  dispatch: policy\nplugins: []\nroutes:\n{routes}");
        parse_config(&yaml).expect("these routes are distinct and must load")
    }

    #[test]
    fn two_routes_declaring_one_http_selector_name_both_indices_and_the_name() {
        let err = duplicate_error(
            r#"  - http: { path_prefix: /v1/files }
    meta:
      scope: tenant-a
  - http: { path_prefix: /v1/files }
    meta:
      scope: tenant-a
"#,
        );
        assert!(err.contains("routes 0 and 1"), "{err}");
        assert!(err.contains("/v1/files"), "{err}");
        assert!(err.contains("http"), "{err}");
    }

    /// The case a comparison of written selectors would pass: two different
    /// lists that both contribute `/b`.
    #[test]
    fn two_http_lists_overlapping_in_one_element_name_that_element() {
        let err = duplicate_error(
            r#"  - http: [/a, /b]
  - http: [/b, /c]
"#,
        );
        assert!(err.contains("routes 0 and 1"), "{err}");
        assert!(err.contains("'/b'"), "{err}");
    }

    #[test]
    fn two_http_map_forms_rendering_one_name_collide() {
        let err = duplicate_error(
            r#"  - http: { path_prefix: /api, method: [POST, GET] }
  - http: { path_prefix: /api/, method: [GET, POST] }
"#,
        );
        assert!(err.contains("routes 0 and 1"), "{err}");
        assert!(err.contains("/api"), "{err}");
    }

    /// Matching compares a method without regard to case, so two spellings of
    /// one method are one route and must be refused rather than both matching.
    #[test]
    fn two_http_routes_differing_only_in_method_case_collide() {
        let err = duplicate_error(
            r#"  - http: { path_prefix: /api, method: GET }
  - http: { path_prefix: /api, method: get }
"#,
        );
        assert!(err.contains("routes 0 and 1"), "{err}");
        assert!(err.contains("GET"), "{err}");
        assert!(err.contains("/api"), "{err}");
    }

    /// A method list is a case-insensitive set, so neither its order nor its
    /// case distinguishes two routes.
    #[test]
    fn two_http_method_lists_differing_in_case_and_order_collide() {
        let err = duplicate_error(
            r#"  - http: { path_prefix: /api, method: [GET, POST] }
  - http: { path_prefix: /api, method: [post, get] }
"#,
        );
        assert!(err.contains("routes 0 and 1"), "{err}");
        assert!(err.contains("GET,POST"), "{err}");
    }

    /// An exact path is matched byte for byte, so `/admin` and `/admin/` are two
    /// paths matching two different requests. Two routes declaring them are two
    /// routes, and both load and reach their own traffic.
    #[test]
    fn two_http_routes_differing_only_in_a_trailing_slash_load() {
        let cfg = routes_load(
            r#"  - http: /admin
  - http: "/admin/"
"#,
        );
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(
            http_name(&cfg, "/admin", Some("GET")).as_deref(),
            Some("/admin"),
            "the slashless request takes the slashless route"
        );
        assert_eq!(
            http_name(&cfg, "/admin/", Some("GET")).as_deref(),
            Some("/admin/"),
            "and the slash request takes the route declared with one"
        );
    }

    /// One list declaring both spellings declares two paths, each with its own
    /// name, so the list loads and each element answers for its own requests.
    #[test]
    fn one_http_list_declaring_both_slash_spellings_loads() {
        let cfg = routes_load(
            r#"  - http: [/admin, "/admin/"]
"#,
        );
        assert_eq!(cfg.routes.len(), 1);
        let (_, annotated) =
            route_entity_identity(&cfg.routes[0]).expect("the route declares an `http:` selector");
        assert_eq!(
            annotated,
            vec!["/admin".to_owned(), "/admin/".to_owned()],
            "each element is annotated under the path it was written as"
        );
    }

    /// A path repeated verbatim is left alone. `tool: [a, a]` loads for every
    /// other selector, and a list that repeats an element says what it looks
    /// like it says.
    #[test]
    fn one_http_list_repeating_a_path_verbatim_loads() {
        let cfg = routes_load(
            r#"  - http: [/admin, /admin]
"#,
        );
        assert_eq!(cfg.routes.len(), 1);
    }

    /// The method is part of the rendered name, so narrowing by a different
    /// method leaves two routes distinct.
    #[test]
    fn two_http_map_forms_differing_only_in_method_load() {
        let cfg = routes_load(
            r#"  - http: { path_prefix: /api, method: GET }
  - http: { path_prefix: /api, method: POST }
"#,
        );
        assert_eq!(cfg.routes.len(), 2);
    }

    #[test]
    fn one_selector_under_two_scopes_loads() {
        let cfg = routes_load(
            r#"  - http: { path_prefix: /v1/files }
    meta:
      scope: tenant-a
  - http: { path_prefix: /v1/files }
    meta:
      scope: tenant-b
  - http: { path_prefix: /v1/files }
"#,
        );
        assert_eq!(cfg.routes.len(), 3);
    }

    #[test]
    fn one_name_under_two_entity_types_loads() {
        let cfg = routes_load(
            r#"  - tool: /healthz
  - prompt: /healthz
  - http: /healthz
"#,
        );
        assert_eq!(cfg.routes.len(), 3);
    }

    /// The check reads the names every selector contributes, so it is not
    /// specific to `http:`.
    #[test]
    fn two_tool_routes_declaring_one_name_collide() {
        let err = duplicate_error(
            r#"  - tool: get_compensation
  - tool: get_compensation
"#,
        );
        assert!(err.contains("routes 0 and 1"), "{err}");
        assert!(err.contains("get_compensation"), "{err}");
        assert!(err.contains("tool"), "{err}");
    }

    #[test]
    fn two_tool_lists_overlapping_in_one_element_name_that_element() {
        let err = duplicate_error(
            r#"  - tool: [a, b]
  - tool: [b, c]
"#,
        );
        assert!(err.contains("routes 0 and 1"), "{err}");
        assert!(err.contains("'b'"), "{err}");
    }

    /// A list repeating an element still resolves to the route that declared
    /// it, so it is not a collision with another route.
    #[test]
    fn a_list_repeating_one_element_loads() {
        let cfg = routes_load(
            r#"  - tool: [a, a]
"#,
        );
        assert_eq!(cfg.routes.len(), 1);
    }

    /// A glob and a wildcard contribute the pattern as written, so two routes
    /// spelling the same pattern collide the way two exact names do.
    #[test]
    fn two_routes_declaring_one_glob_collide() {
        let err = duplicate_error(
            r#"  - tool: "hr-*"
  - tool: "hr-*"
"#,
        );
        assert!(err.contains("routes 0 and 1"), "{err}");
        assert!(err.contains("hr-*"), "{err}");
    }

    // ---- the names a route is known by ------------------------------------

    /// The identity of each route in a config written as just its `routes:`
    /// block, so a case reads as the selectors it declares.
    fn identities(routes: &str) -> Vec<Option<(&'static str, Vec<String>)>> {
        let yaml = format!("engine_settings:\n  dispatch: policy\nplugins: []\nroutes:\n{routes}");
        parse_config(&yaml)
            .expect("every route in the case must parse")
            .routes
            .iter()
            .map(route_entity_identity)
            .collect()
    }

    /// The entity type each selector reports and the names it contributes. A
    /// list contributes one name per element so each element routes on its own,
    /// and a glob or wildcard contributes the pattern as written. These are the
    /// shapes the integration fixtures declare, so an annotation key does not
    /// move.
    #[test]
    fn every_selector_reports_its_entity_type_and_the_names_it_contributes() {
        let found = identities(
            r#"  - tool: get_weather
  - resource: hr://employees/*
  - prompt: summarize_email
  - llm: gpt-4
  - http: /healthz
  - tool: [tool_a, tool_b]
  - tool: "hr-*"
  - tool: "*"
"#,
        );

        assert_eq!(
            found,
            vec![
                Some((ENTITY_TOOL, vec!["get_weather".to_owned()])),
                Some((ENTITY_RESOURCE, vec!["hr://employees/*".to_owned()])),
                Some((ENTITY_PROMPT, vec!["summarize_email".to_owned()])),
                Some((ENTITY_LLM, vec!["gpt-4".to_owned()])),
                Some((ENTITY_HTTP, vec!["/healthz".to_owned()])),
                Some((ENTITY_TOOL, vec!["tool_a".to_owned(), "tool_b".to_owned()])),
                Some((ENTITY_TOOL, vec!["hr-*".to_owned()])),
                Some((ENTITY_TOOL, vec!["*".to_owned()])),
            ]
        );
    }

    /// A configuration cannot declare two selectors on one route, but a host
    /// can build such a route in Rust, so the order the arms are tried in is
    /// pinned rather than incidental. Dropping the winner hands the identity to
    /// the next selector down, and dropping the last leaves nothing to route.
    #[test]
    fn the_selectors_are_tried_in_a_fixed_order() {
        fn entity_of(route: &RouteEntry) -> &'static str {
            route_entity_identity(route)
                .expect("a selector is still declared")
                .0
        }

        let mut route = RouteEntry {
            tool: Some(StringOrList::Single(Pattern::new("t".to_owned()))),
            resource: Some(StringOrList::Single(Pattern::new("r".to_owned()))),
            prompt: Some(StringOrList::Single(Pattern::new("p".to_owned()))),
            llm: Some(StringOrList::Single(Pattern::new("l".to_owned()))),
            http: Some(HttpSelector::exact("/h")),
            ..RouteEntry::default()
        };

        assert_eq!(entity_of(&route), ENTITY_TOOL);
        route.tool = None;
        assert_eq!(entity_of(&route), ENTITY_RESOURCE);
        route.resource = None;
        assert_eq!(entity_of(&route), ENTITY_PROMPT);
        route.prompt = None;
        assert_eq!(entity_of(&route), ENTITY_LLM);
        route.llm = None;
        assert_eq!(entity_of(&route), ENTITY_HTTP);
        route.http = None;
        assert!(
            route_entity_identity(&route).is_none(),
            "a route selecting nothing contributes no name"
        );
    }

    /// An exact path with nothing narrowing it is the path a request arrives
    /// on, so it is contributed verbatim. Every other shape renders the fields
    /// the match consumed, distinctly per shape and never starting with `/`, so
    /// a rendering cannot collide with a request path. The spellings below are
    /// internal and free to change with this test.
    #[test]
    fn an_http_selector_renders_a_name_no_request_path_can_equal() {
        let names: Vec<Vec<String>> = identities(
            r#"  - http: /healthz
  - http: [/livez, /readyz]
  - http: { path: /healthz, method: GET }
  - http: { path_prefix: /v1/files }
  - http: { path_prefix: /v1/files, method: GET }
  - http: { path_prefix: / }
"#,
        )
        .into_iter()
        .map(|identity| identity.expect("an `http:` selector is declared").1)
        .collect();

        assert_eq!(names[0], ["/healthz"], "an exact path is contributed as is");
        assert_eq!(
            names[1],
            ["/livez", "/readyz"],
            "an exact list contributes one path per element"
        );
        assert_eq!(names[2], ["GET path:/healthz"]);
        assert_eq!(names[3], ["prefix:/v1/files"]);
        assert_eq!(names[4], ["GET prefix:/v1/files"]);
        assert_eq!(names[5], ["prefix:/"]);

        let rendered: Vec<&str> = names[2..]
            .iter()
            .map(|names| names[0].as_str())
            .collect::<Vec<_>>();
        for name in &rendered {
            assert!(
                !name.starts_with('/'),
                "a rendered name a request path could equal would collide with it: {name}"
            );
        }
        let distinct: HashSet<&str> = rendered.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            rendered.len(),
            "each shape must render distinctly: {rendered:?}"
        );
    }

    /// The declared methods are part of what the match reads, so two routes
    /// differing only there are known by different names and cannot land on one
    /// annotation.
    #[test]
    fn narrowing_by_a_different_method_yields_a_different_name() {
        let names = identities(
            r#"  - http: { path_prefix: /v1/files, method: GET }
  - http: { path_prefix: /v1/files, method: POST }
  - http: { path_prefix: /v1/files }
"#,
        );
        let distinct: HashSet<Vec<String>> = names
            .into_iter()
            .map(|identity| identity.expect("an `http:` selector is declared").1)
            .collect();
        assert_eq!(
            distinct.len(),
            3,
            "each method narrowing names its own route"
        );
    }

    /// A method list is a set to the matcher, so the order it is written in must
    /// not change the name. Otherwise reordering a list in the config would
    /// orphan the annotation installed under the old spelling.
    #[test]
    fn the_order_a_method_list_is_written_in_does_not_change_the_name() {
        // Each spelling takes its own scope, since they all resolve to one
        // name and two routes cannot share a name within a scope.
        let names = identities(
            r#"  - http: { path_prefix: /v1/files, method: [GET, POST] }
    meta:
      scope: tenant-a
  - http: { path_prefix: /v1/files, method: [POST, GET] }
    meta:
      scope: tenant-b
  - http: { path_prefix: /v1/files, method: [POST, GET, POST] }
    meta:
      scope: tenant-c
"#,
        );
        let written: Vec<Vec<String>> = names
            .into_iter()
            .map(|identity| identity.expect("an `http:` selector is declared").1)
            .collect();
        assert_eq!(written[0], written[1]);
        assert_eq!(
            written[0], written[2],
            "a repeated method is the same set, so it is the same name"
        );
    }
    // ---- matching a request to a route ------------------------------------

    /// A routing-enabled config written as just its `routes:` block, so a case
    /// reads as the selectors it declares.
    fn routed_config(routes: &str) -> PolicyConfig {
        let yaml = format!("engine_settings:\n  dispatch: policy\nplugins: []\nroutes:\n{routes}");
        parse_config(&yaml).expect("every route in the case must parse")
    }

    /// The name a generic HTTP request resolves to, or `None` when no `http:`
    /// route matched it.
    fn http_name(config: &PolicyConfig, path: &str, method: Option<&str>) -> Option<String> {
        resolve_route(config, RouteQuery::http(path, method)).map(|matched| matched.name)
    }

    /// The prefix a request matched, which is how a case tells two prefix
    /// routes apart.
    fn matched_prefix(config: &PolicyConfig, path: &str) -> Option<String> {
        resolve_route(config, RouteQuery::http(path, Some("GET")))?
            .route
            .http
            .as_ref()
            .and_then(HttpSelector::path_prefix)
            .map(str::to_owned)
    }

    /// A request under a prefix resolves the route, and the name it resolves to
    /// is the selector's, not the path it arrived on. Keying on the path would
    /// make the cache and the annotation table grow with traffic.
    #[test]
    fn a_request_under_a_prefix_resolves_to_the_prefix_not_to_its_own_path() {
        let cfg = routed_config("  - http: { path_prefix: /v1/files }\n");

        let matched = resolve_route(&cfg, RouteQuery::http("/v1/files/q3.pdf", Some("GET")))
            .expect("a file under the prefix must match");
        let (entity_type, names) =
            route_entity_identity(matched.route).expect("the route declares `http:`");

        assert_eq!(
            entity_type, ENTITY_HTTP,
            "an `http:` route is an http entity"
        );
        assert!(
            names.contains(&matched.name),
            "the resolved name must be one the route contributes: {names:?}"
        );
        assert!(
            !matched.name.contains("q3.pdf"),
            "no part of the request path belongs in the resolved name: {}",
            matched.name
        );
    }

    /// A list dispatches per element, so the element that matched is the name.
    #[test]
    fn a_list_selector_resolves_to_the_matched_element() {
        let cfg = routed_config("  - http: [/livez, /readyz]\n");

        assert_eq!(
            http_name(&cfg, "/readyz", Some("GET")).as_deref(),
            Some("/readyz"),
            "the matched element is the name"
        );
        assert_eq!(
            http_name(&cfg, "/livez", None).as_deref(),
            Some("/livez"),
            "each element routes on its own"
        );
        assert_eq!(
            http_name(&cfg, "/healthz", Some("GET")),
            None,
            "a list matches by equality, so an undeclared path matches nothing"
        );
    }

    /// The host router's reading: `/api` covers `/api`, `/api/`, and `/api/v1`,
    /// and stops at the segment boundary rather than at the character.
    #[test]
    fn a_prefix_matches_only_at_a_segment_boundary() {
        let mut resolved = Vec::new();
        for declared in ["/api", "/api/"] {
            let cfg = routed_config(&format!("  - http: {{ path_prefix: {declared} }}\n"));
            for path in ["/api", "/api/", "/api/v1"] {
                assert!(
                    http_name(&cfg, path, Some("GET")).is_some(),
                    "`{declared}` must match {path}"
                );
            }
            assert!(
                http_name(&cfg, "/apikeys", Some("GET")).is_none(),
                "`{declared}` must not match /apikeys"
            );
            resolved.push(http_name(&cfg, "/api/v1", Some("GET")));
        }

        assert_eq!(
            resolved[0], resolved[1],
            "a trailing slash on the prefix changes neither the match nor the name"
        );
    }

    /// Among prefixes that both match, the longer one wins whichever order they
    /// are declared in, which is what makes ordering independent of the file.
    #[test]
    fn the_longer_prefix_wins_in_either_declaration_order() {
        for routes in [
            "  - http: { path_prefix: /v1 }\n  - http: { path_prefix: /v1/files }\n",
            "  - http: { path_prefix: /v1/files }\n  - http: { path_prefix: /v1 }\n",
        ] {
            let cfg = routed_config(routes);
            assert_eq!(
                matched_prefix(&cfg, "/v1/files/q3.pdf").as_deref(),
                Some("/v1/files"),
                "the longer prefix must win, declared first or second"
            );
            assert_eq!(
                matched_prefix(&cfg, "/v1/other").as_deref(),
                Some("/v1"),
                "a path outside the longer prefix still falls to the shorter one"
            );
        }
    }

    /// An exact path outranks every prefix that also covers it.
    #[test]
    fn an_exact_path_beats_every_prefix() {
        let cfg = routed_config(
            "  - http: { path_prefix: /v1/files }\n  - http: { path_prefix: /v1 }\n  - http: /v1/files\n",
        );

        let matched = resolve_route(&cfg, RouteQuery::http("/v1/files", Some("GET")))
            .expect("the exact path is declared");
        assert_eq!(
            matched
                .route
                .http
                .as_ref()
                .map(HttpSelector::exact_paths)
                .unwrap_or_default(),
            ["/v1/files"],
            "the exact route must win over both prefixes"
        );

        assert_eq!(
            matched_prefix(&cfg, "/v1/files/q3.pdf").as_deref(),
            Some("/v1/files"),
            "an exact path matches by equality, so a file under it still takes the prefix"
        );
    }

    /// An exact path matches the path as given and nothing else, because the
    /// host router's exact arm is a byte compare on the path it received.
    /// Matching another spelling would apply this route's policy to a request
    /// the router sends elsewhere.
    #[test]
    fn an_exact_path_matches_only_the_path_as_given() {
        let cfg = routed_config("  - http: /healthz\n");

        assert_eq!(
            http_name(&cfg, "/healthz", Some("GET")).as_deref(),
            Some("/healthz"),
            "the path as declared resolves the route"
        );

        for other in [
            "/healthz/",
            "//healthz",
            "/./healthz",
            "/healthz;jsessionid=1",
        ] {
            assert!(
                http_name(&cfg, other, Some("GET")).is_none(),
                "`{other}` is a different path to the router, so it must not \
                 resolve the `/healthz` route"
            );
        }

        assert!(
            http_name(&cfg, "/healthzx", Some("GET")).is_none(),
            "an exact path is not a prefix"
        );
        assert!(
            http_name(&cfg, "/healthz/deep", Some("GET")).is_none(),
            "a path under an exact path is a different path"
        );
    }

    /// The prefix half is untouched by this. A prefix still matches every
    /// spelling the gateway's own `path_prefix_matches` matches, and misses the
    /// ones it misses, because PPE's copy of that function is the same
    /// segment-boundary compare on the path as given.
    #[test]
    fn a_prefix_matches_the_spellings_the_gateway_prefix_matcher_matches() {
        let cfg = routed_config("  - http: { path_prefix: /v1/files }\n");

        for path in [
            "/v1/files",
            "/v1/files/",
            "/v1/files/q3.pdf",
            "/v1/files//q3.pdf",
            "/v1/files/./q3.pdf",
            "/v1/files/../healthz",
        ] {
            assert_eq!(
                http_name(&cfg, path, Some("GET")).as_deref(),
                Some("prefix:/v1/files"),
                "`{path}` is under the prefix at a segment boundary, as it is for \
                 the gateway"
            );
        }

        for path in ["/v1/filesx", "/v1/files;jsessionid=1", "//v1/files", "/v1"] {
            assert!(
                http_name(&cfg, path, Some("GET")).is_none(),
                "`{path}` is not a segment-boundary match, and is not one for the \
                 gateway either"
            );
        }
    }

    /// The case this reading exists for. The gateway's router does not resolve
    /// the dot segment, so `/v1/files/../healthz` is forwarded under
    /// `/v1/files`. Resolving it here first would hand the request the
    /// `/healthz` route's policy and drop whatever `/v1/files` authenticates,
    /// on a path the gateway never sent to `/healthz`.
    #[test]
    fn a_traversal_out_of_a_prefix_resolves_the_prefix_it_was_written_under() {
        let cfg = routed_config("  - http: { path_prefix: /v1/files }\n  - http: /healthz\n");

        assert_eq!(
            http_name(&cfg, "/v1/files/../healthz", Some("GET")).as_deref(),
            Some("prefix:/v1/files"),
            "the traversal must not move the request onto the /healthz route"
        );
        assert_eq!(
            http_name(&cfg, "/healthz", Some("GET")).as_deref(),
            Some("/healthz"),
            "and /healthz still answers for the path it declared"
        );
    }

    /// A declared trailing slash is part of the path. `/admin/` and `/admin`
    /// are two paths to the router, so a route declared with the slash answers
    /// for the slash spelling only.
    #[test]
    fn a_declared_trailing_slash_matches_only_the_trailing_slash_spelling() {
        let cfg = routed_config("  - http: \"/admin/\"\n");

        assert_eq!(
            http_name(&cfg, "/admin/", Some("GET")).as_deref(),
            Some("/admin/"),
            "the declared spelling matches, and keeps its slash in the name"
        );
        assert!(
            http_name(&cfg, "/admin", Some("GET")).is_none(),
            "dropping the slash names a path this route did not declare"
        );
        assert!(
            http_name(&cfg, "/admin/x", Some("GET")).is_none(),
            "the trailing slash does not make the path a prefix"
        );
    }

    /// A lowercase `method:` matches the request the same way an uppercase one
    /// does, and renders uppercase so both spellings are one name.
    #[test]
    fn a_lowercase_method_matches_and_renders_uppercase() {
        let cfg = routed_config("  - http: { path_prefix: /v1/files, method: get }\n");

        assert_eq!(
            http_name(&cfg, "/v1/files/q3.pdf", Some("GET")).as_deref(),
            Some("GET prefix:/v1/files"),
            "a lowercase declaration matches and renders uppercase"
        );
        assert!(
            http_name(&cfg, "/v1/files/q3.pdf", Some("POST")).is_none(),
            "the narrowing still gates the methods it does not name"
        );
    }

    /// The name a request resolves to is the name the route is annotated under,
    /// and both are the path verbatim. A mismatch would leave the route's
    /// policy body keyed under a name no request reaches.
    #[test]
    fn a_declared_trailing_slash_resolves_the_name_the_route_is_annotated_under() {
        let cfg = routed_config("  - http: [\"/admin/\", /healthz]\n");
        let (entity_type, annotated) =
            route_entity_identity(&cfg.routes[0]).expect("the route declares an `http:` selector");
        assert_eq!(entity_type, ENTITY_HTTP);
        assert_eq!(
            annotated,
            vec!["/admin/".to_owned(), "/healthz".to_owned()],
            "the annotation key is the path as declared, trailing slash included"
        );

        assert_eq!(
            http_name(&cfg, "/admin/", Some("GET")).as_deref(),
            Some(annotated[0].as_str()),
            "the declared spelling resolves the name it is annotated under"
        );
        assert_eq!(
            http_name(&cfg, "/healthz", Some("GET")).as_deref(),
            Some(annotated[1].as_str()),
            "and so does the sibling element"
        );
    }

    /// The root as an exact path matches the root and nothing else, which is
    /// what keeps it distinct from the `path_prefix: /` catch-all.
    #[test]
    fn the_root_as_an_exact_path_is_not_the_catch_all() {
        let exact = routed_config("  - http: \"/\"\n");
        let catch_all = routed_config("  - http: { path_prefix: / }\n");

        assert_eq!(
            http_name(&exact, "/", Some("GET")).as_deref(),
            Some("/"),
            "the root resolves the exact route"
        );
        for path in ["/healthz", "/v1/files/q3.pdf"] {
            assert!(
                http_name(&exact, path, Some("GET")).is_none(),
                "an exact `/` must not answer for {path}"
            );
            assert!(
                http_name(&catch_all, path, Some("GET")).is_some(),
                "the catch-all still answers for {path}"
            );
        }
    }

    /// A twenty-path selector, to say what resolving a name against a long
    /// declared list costs.
    fn twenty_path_selector() -> HttpSelector {
        HttpSelector::Paths((0..20).map(|i| format!("/p{i:02}")).collect())
    }

    /// Resolving a matched name reads the declared path by borrow rather than
    /// rendering one name per declared path and keeping one. The signature
    /// binding is the structural half: it only typechecks while the returned
    /// `&str` borrows from the selector, which a rendered list cannot satisfy.
    /// The pointer identity is the runtime half, and it holds for each of the
    /// twenty paths.
    #[test]
    fn a_matched_exact_path_is_borrowed_from_the_selector() {
        let borrows_from_the_selector: for<'a> fn(&'a HttpSelector, &str) -> Option<&'a str> =
            matched_exact_path;
        let selector = twenty_path_selector();

        for declared in selector.exact_paths() {
            let matched = borrows_from_the_selector(&selector, declared)
                .expect("a declared path matches itself");
            assert!(
                std::ptr::eq(matched, declared.as_str()),
                "`{declared}` must be borrowed from the selector, not rendered into a list"
            );
        }

        assert!(
            borrows_from_the_selector(&selector, "/p20").is_none(),
            "a path the selector does not declare matches none of them"
        );
    }

    /// Ten identical requests against a twenty-path selector paired with a
    /// catch-all resolve the same name every time, and each resolution renders
    /// only the name it returns: what the scan reads out of the twenty-path
    /// selector is a borrow of the path that matched.
    #[test]
    fn repeated_requests_against_a_long_path_list_render_only_the_matched_name() {
        let declared = twenty_path_selector();
        let listed = declared.exact_paths().join(", ");
        let cfg = routed_config(&format!(
            "  - http: [{listed}]\n  - http: {{ path_prefix: / }}\n"
        ));

        for _ in 0..10 {
            let matched = resolve_route(&cfg, RouteQuery::http("/p07", Some("GET")))
                .expect("an exact path outranks the catch-all");
            let selector = matched
                .route
                .http
                .as_ref()
                .expect("the winning route declares `http:`");
            assert_eq!(
                matched.name, "/p07",
                "every request resolves the declared path as its name"
            );
            assert!(
                std::ptr::eq(
                    matched_exact_path(selector, "/p07")
                        .expect("the request path is one the selector declares"),
                    selector.exact_paths()[7].as_str()
                ),
                "the scan hands back the declared path itself, so only one name is rendered"
            );
        }
    }

    /// The name each selector shape resolves to, pinned byte for byte, and
    /// pinned as one of the names the same route is annotated under. Those names
    /// key the annotation table and the route cache, so a name that moved on one
    /// side and not the other leaves a route's policy body under a key no
    /// request reaches.
    #[test]
    fn every_selector_shape_resolves_the_name_it_is_annotated_under() {
        let cases: &[(&str, &str, &str)] = &[
            ("/healthz", "/healthz", "/healthz"),
            ("[/healthz, /readyz]", "/readyz", "/readyz"),
            ("\"/admin/\"", "/admin/", "/admin/"),
            ("\"/\"", "/", "/"),
            ("{ path: /admin }", "/admin", "/admin"),
            ("{ path: /admin, method: GET }", "/admin", "GET path:/admin"),
            (
                "{ path: \"/admin/\", method: [get, GET] }",
                "/admin/",
                "GET path:/admin/",
            ),
            (
                "{ path_prefix: /v1/files }",
                "/v1/files/q3.pdf",
                "prefix:/v1/files",
            ),
            (
                "{ path_prefix: /v1/files, method: [post, GET] }",
                "/v1/files/q3.pdf",
                "GET,POST prefix:/v1/files",
            ),
            ("{ path_prefix: / }", "/anything", "prefix:/"),
            (
                "{ path_prefix: /, method: GET }",
                "/anything",
                "GET prefix:/",
            ),
        ];

        for (declaration, path, expected) in cases {
            let cfg = routed_config(&format!("  - http: {declaration}\n"));

            assert_eq!(
                http_name(&cfg, path, Some("GET")).as_deref(),
                Some(*expected),
                "`http: {declaration}` must resolve `{expected}` for `{path}`"
            );

            let (entity_type, annotated) = route_entity_identity(&cfg.routes[0])
                .expect("every case declares an `http:` selector");
            assert_eq!(entity_type, ENTITY_HTTP);
            assert!(
                annotated.iter().any(|name| name == expected),
                "`{expected}` must be one of the names `http: {declaration}` is annotated \
                 under: {annotated:?}"
            );
        }
    }

    /// The name is the path as declared, so the annotation table and the route
    /// cache stay keyed on the config rather than growing with the traffic. The
    /// other spellings resolve nothing at all, so none of them keys anything.
    #[test]
    fn an_exact_path_resolves_the_name_it_was_declared_under() {
        let cfg = routed_config("  - http: { path: /admin, method: GET }\n");

        assert_eq!(
            http_name(&cfg, "/admin", Some("GET")).as_deref(),
            Some("GET path:/admin"),
            "the name renders the path as declared"
        );
        for other in ["/admin/", "/admin//", "/admin/."] {
            assert!(
                http_name(&cfg, other, Some("GET")).is_none(),
                "`{other}` is a path of its own, so it resolves no route and \
                 contributes no cache key"
            );
        }
    }

    /// The root prefix is the catch-all an operator writes when a route should
    /// cover whatever the narrower ones did not.
    #[test]
    fn the_root_prefix_matches_every_absolute_path() {
        let cfg = routed_config("  - http: { path_prefix: / }\n");

        for path in ["/", "/healthz", "/v1/files/q3.pdf", "/a//b"] {
            assert!(
                http_name(&cfg, path, Some("GET")).is_some(),
                "the catch-all must match {path}"
            );
        }
    }

    /// A `method:` narrowing gates the match. Its absence accepts any method,
    /// and a method is compared without regard to case, the way the host's own
    /// method conditions compare it.
    #[test]
    fn a_method_narrows_the_match_and_its_absence_accepts_any_method() {
        let narrowed = routed_config("  - http: { path_prefix: /v1/files, method: GET }\n");

        assert!(
            http_name(&narrowed, "/v1/files/q3.pdf", Some("GET")).is_some(),
            "the declared method must match"
        );
        assert!(
            http_name(&narrowed, "/v1/files/q3.pdf", Some("get")).is_some(),
            "case is not what distinguishes two methods"
        );
        assert!(
            http_name(&narrowed, "/v1/files/q3.pdf", Some("DELETE")).is_none(),
            "a method the route does not accept must not match it"
        );
        assert!(
            http_name(&narrowed, "/v1/files/q3.pdf", None).is_none(),
            "a request with no method cannot satisfy a narrowing"
        );

        let open = routed_config("  - http: { path_prefix: /v1/files }\n");
        for method in [Some("GET"), Some("POST"), Some("PATCH"), None] {
            assert!(
                http_name(&open, "/v1/files/q3.pdf", method).is_some(),
                "an absent `method:` accepts {method:?}"
            );
        }
    }

    /// A method list accepts any of its methods and nothing else.
    #[test]
    fn a_method_list_accepts_any_of_its_methods() {
        let cfg = routed_config("  - http: { path: /ping, method: [GET, HEAD] }\n");

        for method in ["GET", "HEAD"] {
            assert!(
                http_name(&cfg, "/ping", Some(method)).is_some(),
                "{method} is in the list"
            );
        }
        assert!(
            http_name(&cfg, "/ping", Some("POST")).is_none(),
            "POST is not in the list"
        );
    }

    /// A route narrowed by `method:` is the narrower of the two on one path, so
    /// it wins for the methods it names whichever line it was written on.
    #[test]
    fn a_method_narrowed_route_outranks_the_open_path_in_either_order() {
        for routes in [
            "  - http: { path_prefix: /api }\n  - http: { path_prefix: /api, method: DELETE }\n",
            "  - http: { path_prefix: /api, method: DELETE }\n  - http: { path_prefix: /api }\n",
        ] {
            let cfg = routed_config(routes);
            assert_eq!(
                http_name(&cfg, "/api/x", Some("DELETE")).as_deref(),
                Some("DELETE prefix:/api"),
                "the narrowed route must win DELETE, declared first or second"
            );
        }
    }

    /// The bonus applies only where the narrowing matches, so a method the
    /// narrowed route does not name still lands on the open one.
    #[test]
    fn a_method_the_narrowed_route_does_not_name_falls_to_the_open_route() {
        for routes in [
            "  - http: { path_prefix: /api }\n  - http: { path_prefix: /api, method: DELETE }\n",
            "  - http: { path_prefix: /api, method: DELETE }\n  - http: { path_prefix: /api }\n",
        ] {
            let cfg = routed_config(routes);
            for method in [Some("GET"), Some("POST"), None] {
                assert_eq!(
                    http_name(&cfg, "/api/x", method).as_deref(),
                    Some("prefix:/api"),
                    "{method:?} is not narrowed, so the open route governs it"
                );
            }
        }
    }

    /// An exact path already scores half the range, so the bonus has to add to
    /// it rather than wrap it back below the prefixes it is meant to outrank.
    #[test]
    fn an_exact_path_narrowed_by_a_method_adds_the_bonus_without_wrapping() {
        let cfg = routed_config(
            "  - http: { path: /admin, method: GET }\n  - http: { path_prefix: / }\n",
        );
        let selector = cfg.routes[0]
            .http
            .as_ref()
            .expect("the first route declares `http:`");

        let score = score_http_match(selector, "/admin", Some("GET"))
            .expect("the exact path and the method both match");
        assert!(
            score > SPECIFICITY_EXACT_PATH,
            "the bonus must land above the exact-path score, not wrap past it: {score}"
        );

        assert_eq!(
            http_name(&cfg, "/admin", Some("GET")).as_deref(),
            Some("GET path:/admin"),
            "a narrowed exact path still outranks the catch-all prefix"
        );
    }

    /// Three routes on one prefix are equal on length, so the narrowing orders
    /// them: two narrowings that both name the request's method are ordered by
    /// how many methods each names, so the answer is the same in either
    /// declaration order.
    #[test]
    fn equal_length_prefixes_order_by_the_narrowing_not_by_the_file() {
        for routes in [
            "  - http: { path_prefix: /api }\n  - http: { path_prefix: /api, method: [GET, POST] }\n  - http: { path_prefix: /api, method: GET }\n",
            "  - http: { path_prefix: /api, method: GET }\n  - http: { path_prefix: /api, method: [GET, POST] }\n  - http: { path_prefix: /api }\n",
        ] {
            let cfg = routed_config(routes);
            assert_eq!(
                http_name(&cfg, "/api/x", Some("GET")).as_deref(),
                Some("GET prefix:/api"),
                "the GET-only route names one method where the other names two, so it wins GET"
            );
            assert_eq!(
                http_name(&cfg, "/api/x", Some("POST")).as_deref(),
                Some("GET,POST prefix:/api"),
                "only one narrowing names POST"
            );
            assert_eq!(
                http_name(&cfg, "/api/x", Some("DELETE")).as_deref(),
                Some("prefix:/api"),
                "no narrowing names DELETE, so the open route governs it"
            );
        }
    }

    /// A method set built directly, so a case can name one no operator would
    /// write. Distinct tokens, since matching reads the set deduplicated.
    fn methods(count: usize) -> StringOrList {
        StringOrList::List((0..count).map(|i| format!("M{i}")).collect())
    }

    /// An exact-path selector narrowed by a built method set.
    fn narrowed_exact(path: &str, method: StringOrList) -> HttpSelector {
        HttpSelector::Match(HttpMatch {
            path: Some(path.to_owned()),
            method: Some(method),
            ..HttpMatch::default()
        })
    }

    /// Whatever the method set holds, a narrowing scores something: that is what
    /// keeps a narrowed route ahead of the same path left open.
    #[test]
    fn any_method_narrowing_outranks_no_narrowing() {
        assert_eq!(
            method_narrowing_bonus(None),
            0,
            "an open path adds nothing to its path score"
        );
        for count in [1_usize, 2, 9, 50, 51, 1_000, 100_000] {
            assert!(
                method_narrowing_bonus(Some(&methods(count))) > 0,
                "a selector naming {count} methods must still outrank an open path"
            );
        }
    }

    /// Each further method the selector names gives one of the bonus back, so the
    /// selector naming fewer methods outranks the one naming more.
    #[test]
    fn each_further_method_lowers_the_narrowing_bonus() {
        let mut previous = method_narrowing_bonus(Some(&methods(1)));
        for count in 2..=20_usize {
            let bonus = method_narrowing_bonus(Some(&methods(count)));
            assert!(
                bonus < previous,
                "{count} methods scored {bonus}, not below the {} for {}",
                previous,
                count - 1
            );
            previous = bonus;
        }
    }

    /// The narrower of two selectors on one exact path wins a method both name,
    /// in either declaration order. This is the ordering that used to fall to
    /// whichever line came first.
    #[test]
    fn a_narrower_method_set_outranks_a_wider_one_on_an_exact_path() {
        for routes in [
            "  - http: { path: /a, method: [GET, POST] }\n  - http: { path: /a, method: GET }\n",
            "  - http: { path: /a, method: GET }\n  - http: { path: /a, method: [GET, POST] }\n",
        ] {
            let cfg = routed_config(routes);
            assert_eq!(
                http_name(&cfg, "/a", Some("GET")).as_deref(),
                Some("GET path:/a"),
                "the GET-only route must win GET, declared first or second"
            );
            assert_eq!(
                http_name(&cfg, "/a", Some("POST")).as_deref(),
                Some("GET,POST path:/a"),
                "only the wider route names POST"
            );
        }
    }

    /// The same ordering on the prefix shape, where the two selectors also score
    /// the same path length.
    #[test]
    fn a_narrower_method_set_outranks_a_wider_one_on_a_prefix() {
        for routes in [
            "  - http: { path_prefix: /api, method: [GET, POST] }\n  - http: { path_prefix: /api, method: GET }\n",
            "  - http: { path_prefix: /api, method: GET }\n  - http: { path_prefix: /api, method: [GET, POST] }\n",
        ] {
            let cfg = routed_config(routes);
            assert_eq!(
                http_name(&cfg, "/api/x", Some("GET")).as_deref(),
                Some("GET prefix:/api"),
                "the GET-only route must win GET, declared first or second"
            );
            assert_eq!(
                http_name(&cfg, "/api/x", Some("POST")).as_deref(),
                Some("GET,POST prefix:/api"),
                "only the wider route names POST"
            );
        }
    }

    /// The whole method bonus stays under the scope bonus, which is what keeps a
    /// scoped broad route winning its own scope, and far under the per-character
    /// prefix weight, which is what keeps prefix length deciding between two
    /// different paths.
    #[test]
    fn the_method_bonus_stays_under_the_scope_and_prefix_weights() {
        for count in [1_usize, 2, 9, 50, 51, 1_000, 100_000] {
            let bonus = method_narrowing_bonus(Some(&methods(count)));
            assert!(
                bonus < SPECIFICITY_SCOPE_MATCH,
                "{count} methods scored {bonus}, not below the scope bonus"
            );
            assert!(
                bonus * 10 < SPECIFICITY_PATH_PREFIX_STEP,
                "{count} methods scored {bonus}, not far below one prefix character"
            );
        }
    }

    /// A method set no configuration would hold must neither wrap the total nor
    /// invert the ordering: it stays a narrowing, stays behind every smaller set,
    /// and stays above the exact-path score it is added to.
    #[test]
    fn a_pathologically_large_method_set_neither_wraps_nor_inverts() {
        let huge = method_narrowing_bonus(Some(&methods(1_000_000)));
        assert!(huge >= 1, "a huge set is still a narrowing: {huge}");
        assert!(
            huge <= method_narrowing_bonus(Some(&methods(2))),
            "a huge set cannot outrank a two-method one: {huge}"
        );

        let selector = narrowed_exact("/a", methods(1_000_000));
        let score = score_http_match(&selector, "/a", Some("M0"))
            .expect("the exact path and one of its methods match");
        assert!(
            score > SPECIFICITY_EXACT_PATH,
            "the bonus must land above the exact-path score, not wrap past it: {score}"
        );
        let one_method = narrowed_exact("/a", methods(1));
        assert!(
            score_http_match(&one_method, "/a", Some("M0"))
                .expect("the one-method selector matches too")
                > score,
            "the one-method selector must still outrank the huge one"
        );
    }

    /// The bonus sits below the scope bonus, so a scoped route keeps winning its
    /// own scope against a method-narrowed route on the same path.
    #[test]
    fn a_scoped_route_still_outranks_a_method_narrowed_one_on_the_same_path() {
        let cfg = routed_config(
            "  - http: { path_prefix: /v1 }\n    meta: { scope: tenant-a }\n  - http: { path_prefix: /v1, method: GET }\n",
        );

        let matched = resolve_route(
            &cfg,
            RouteQuery::http("/v1/files", Some("GET")).with_scope(Some("tenant-a")),
        )
        .expect("both routes cover the request");
        assert_eq!(
            matched
                .route
                .meta
                .as_ref()
                .and_then(|meta| meta.scope.as_deref()),
            Some("tenant-a"),
            "the scope decides before the narrowing does"
        );
    }

    /// Matching reads a request line, so anything that is not an absolute path
    /// matches nothing, catch-all included. That is what keeps `OPTIONS *` from
    /// picking up a route it was never written for. A route spelled `*` is not
    /// the other half of this case: it is refused at load, both as a path that
    /// is not absolute and as the reserved catch-all name.
    #[test]
    fn a_path_that_is_not_absolute_matches_no_route() {
        let cfg = routed_config("  - http: { path_prefix: / }\n");

        for path in ["*", "", "v1/files", "http://host/v1"] {
            assert!(
                resolve_route(&cfg, RouteQuery::http(path, Some("OPTIONS"))).is_none(),
                "`{path}` is not a path a route can match"
            );
        }
    }

    /// Nothing matching resolves nothing, which is what lets the caller keep
    /// using the reserved global name rather than inventing one.
    #[test]
    fn a_request_matching_no_http_route_resolves_nothing() {
        let cfg = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - http: /healthz
"#,
        )
        .expect("the fixture must parse");

        assert!(
            resolve_route(&cfg, RouteQuery::http("/v1/files", Some("GET"))).is_none(),
            "no declared path covers /v1/files, so nothing resolves"
        );
    }

    /// An `http:` route layers `authentication:` the way every other route
    /// does: the global list, then its tag bundles, then its own steps. That is
    /// the one dispatch list a route still contributes.
    #[test]
    fn an_http_route_layers_authentication_like_any_other() {
        let cfg = parse_config(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: files-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: files-attestor, kind: builtin, hooks: [identity.resolve] }
global:
  authentication: [corp-jwt]
groups:
  files:
    authentication: [files-jwt]
routes:
  - http: { path_prefix: /v1/files }
    groups: files
    authentication: [files-attestor]
"#,
        )
        .expect("the fixture must parse");

        let matched = resolve_route(&cfg, RouteQuery::http("/v1/files/q3.pdf", Some("GET")))
            .expect("the prefix covers the request");

        let identity = resolve_identity_plugins_for_route(&cfg, Some(&matched));
        assert_eq!(
            identity.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["corp-jwt", "files-jwt", "files-attestor"],
            "global, then tag bundle, then the route's own steps"
        );
    }

    /// A scoped route needs the request's scope and outranks an unscoped route
    /// of the same shape; a scope that does not match is skipped outright.
    #[test]
    fn a_scoped_http_route_wins_its_bucket_and_a_mismatched_scope_is_skipped() {
        let cfg = routed_config(
            "  - http: { path_prefix: /v1 }\n    meta: { scope: tenant-a }\n  - http: { path_prefix: /v1 }\n",
        );
        let scope_of = |scope: Option<&str>| {
            let matched = resolve_route(
                &cfg,
                RouteQuery::http("/v1/files", Some("GET")).with_scope(scope),
            )
            .unwrap_or_else(|| panic!("the unscoped route covers {scope:?} at least"));
            matched
                .route
                .meta
                .as_ref()
                .and_then(|meta| meta.scope.clone())
        };

        assert_eq!(
            scope_of(Some("tenant-a")).as_deref(),
            Some("tenant-a"),
            "the scoped route wins for its own scope"
        );
        assert_eq!(
            scope_of(None),
            None,
            "an unscoped request cannot reach a scoped route"
        );
        assert_eq!(
            scope_of(Some("tenant-b")),
            None,
            "another tenant falls to the unscoped route"
        );

        let scoped_only =
            routed_config("  - http: { path_prefix: /v1 }\n    meta: { scope: tenant-a }\n");
        assert!(
            resolve_route(
                &scoped_only,
                RouteQuery::http("/v1/files", Some("GET")).with_scope(Some("tenant-b")),
            )
            .is_none(),
            "a scope mismatch is a hard skip, not a lower score"
        );
    }

    /// Two globs covering one tool rank identically. `when:` used to score a
    /// bonus, so a broad glob declaring one beat a narrower glob without one;
    /// with the key gone, declaration order is all that is left.
    #[test]
    fn two_equally_specific_routes_rank_identically() {
        let name_for = |routes: &str| {
            resolve_route(
                &routed_config(routes),
                RouteQuery::named(ENTITY_TOOL, "hr-get-comp"),
            )
            .expect("both globs cover the tool")
            .name
        };
        assert_eq!(
            name_for("  - tool: \"hr-*\"\n  - tool: \"hr-get-*\"\n"),
            "hr-*",
            "the first declared of two equally specific routes wins"
        );
        assert_eq!(
            name_for("  - tool: \"hr-get-*\"\n  - tool: \"hr-*\"\n"),
            "hr-get-*",
            "declared the other way round, the other one wins"
        );
    }

    /// The name a request resolves to is always one the route contributes, for
    /// every selector shape. This is the property that lets an orchestrator's
    /// annotation key and a resolved name be the same string without either
    /// side knowing how the other spells it.
    #[test]
    fn every_selector_shape_resolves_to_a_name_its_route_contributes() {
        let cases = [
            (
                "tool: get_weather",
                RouteQuery::named(ENTITY_TOOL, "get_weather"),
            ),
            (
                "tool: [tool_a, tool_b]",
                RouteQuery::named(ENTITY_TOOL, "tool_b"),
            ),
            (
                r#"tool: "hr-*""#,
                RouteQuery::named(ENTITY_TOOL, "hr-compensation"),
            ),
            (r#"tool: "*""#, RouteQuery::named(ENTITY_TOOL, "anything")),
            (
                "resource: hr://employees/1",
                RouteQuery::named(ENTITY_RESOURCE, "hr://employees/1"),
            ),
            (
                "prompt: summarize_email",
                RouteQuery::named(ENTITY_PROMPT, "summarize_email"),
            ),
            ("llm: gpt-4", RouteQuery::named(ENTITY_LLM, "gpt-4")),
            ("http: /healthz", RouteQuery::http("/healthz", Some("GET"))),
            ("http: [/livez, /readyz]", RouteQuery::http("/readyz", None)),
            (
                "http: { path: /ping, method: [GET, HEAD] }",
                RouteQuery::http("/ping", Some("HEAD")),
            ),
            (
                "http: { path_prefix: /v1/files }",
                RouteQuery::http("/v1/files/q3.pdf", Some("GET")),
            ),
            (
                "http: { path_prefix: /v1, method: GET }",
                RouteQuery::http("/v1/x", Some("get")),
            ),
            (
                "http: { path_prefix: / }",
                RouteQuery::http("/anything", Some("POST")),
            ),
        ];

        for (selector, query) in cases {
            let cfg = routed_config(&format!("  - {selector}\n"));
            let matched = resolve_route(&cfg, query)
                .unwrap_or_else(|| panic!("`{selector}` must match the request written for it"));
            let (_, contributed) = route_entity_identity(matched.route)
                .unwrap_or_else(|| panic!("`{selector}` declares a selector"));

            assert!(
                contributed.contains(&matched.name),
                "`{selector}` resolved to `{}`, which is not among {contributed:?}",
                matched.name
            );
        }
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
mod assertions_tests {
    use super::*;
    use crate::assertions::{AssertionLevel, Direction, ResolvedSource};

    fn load(yaml: &str) -> PolicyConfig {
        parse_config(yaml).expect("the config loads")
    }

    fn refuse(yaml: &str) -> String {
        parse_config(yaml)
            .expect_err("the config must not load")
            .to_string()
    }

    fn resolve(
        config: &PolicyConfig,
        entity_type: &str,
        name: &str,
        direction: Direction,
    ) -> Option<crate::assertions::ResolvedContract> {
        let matched = resolve_route(config, RouteQuery::named(entity_type, name));
        resolve_assertions_for_route(config, matched.as_ref(), Some(entity_type), direction)
    }

    fn header_names(contract: &crate::assertions::ResolvedContract) -> Vec<&str> {
        contract
            .headers
            .iter()
            .map(|header| header.name.as_str())
            .collect()
    }

    fn strip_patterns(contract: &crate::assertions::ResolvedContract) -> Vec<&str> {
        contract
            .strip
            .iter()
            .map(super::super::assertions::config::StripPattern::as_str)
            .collect()
    }

    /// Four levels, each contributing one header and one `strip:` entry.
    const FOUR_LEVELS: &str = "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-global
          from: subject.id
        - name: x-shared
          from: subject.id
          on_missing: deny
      strip: [x-legacy-global]
    response:
      strip: [server]
  defaults:
    tool:
      assertions:
        request:
          headers:
            - name: x-default
              from: claim.tenant
          strip: [x-legacy-default]
groups:
  hr:
    assertions:
      request:
        headers:
          - name: x-bundle
            from: claim.team
        strip: [x-legacy-bundle]
routes:
  - tool: get_weather
    groups: hr
    assertions:
      request:
        headers:
          - name: x-route
            from: claim.region
          - name: X-Shared
            from: claim.tenant
        strip: [x-legacy-route]
  - tool: sibling
    groups: hr
  - resource: 'file://*'
";

    #[test]
    fn a_route_with_no_block_of_its_own_resolves_the_global_contract() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-global
          from: subject.id
      strip: [x-legacy]
    response:
      strip: [server]
routes:
  - tool: get_weather
",
        );
        let request = resolve(&config, "tool", "get_weather", Direction::Request)
            .expect("the global level declared it");
        assert_eq!(header_names(&request), vec!["x-global"]);
        assert_eq!(strip_patterns(&request), vec!["x-legacy"]);
        let response = resolve(&config, "tool", "get_weather", Direction::Response)
            .expect("the global level declared it");
        assert!(response.headers.is_empty());
        assert_eq!(strip_patterns(&response), vec!["server"]);
    }

    #[test]
    fn all_four_levels_accumulate_in_order() {
        let config = load(FOUR_LEVELS);
        let request = resolve(&config, "tool", "get_weather", Direction::Request)
            .expect("four levels declared it");
        assert_eq!(
            header_names(&request),
            vec!["x-global", "X-Shared", "x-default", "x-bundle", "x-route"],
            "every level contributes, and an overridden name keeps its position"
        );
        assert_eq!(
            strip_patterns(&request),
            vec![
                "x-legacy-global",
                "x-legacy-default",
                "x-legacy-bundle",
                "x-legacy-route",
            ],
            "a subordinate level that omits an inherited glob does not remove it"
        );
    }

    /// A repeated name takes the more specific level's entry whole, its
    /// `on_missing` included.
    #[test]
    fn a_repeated_header_resolves_to_the_more_specific_level() {
        let config = load(FOUR_LEVELS);
        let request =
            resolve(&config, "tool", "get_weather", Direction::Request).expect("a contract");
        let shared = request
            .headers
            .iter()
            .find(|header| header.lowercase == "x-shared")
            .expect("the shared header");
        assert_eq!(shared.name, "X-Shared", "the winning level's spelling");
        assert_eq!(shared.level, AssertionLevel::Route);
        assert_eq!(shared.declared_in, "the route");
        assert_eq!(shared.overrode.as_deref(), Some("global"));
        assert_eq!(
            shared.on_missing,
            crate::assertions::OnMissing::Omit,
            "the route's entry replaced global's `on_missing: deny` whole"
        );
    }

    /// One entry per header name whatever case each level wrote, so a global
    /// `X-Auth-User-Id` and a route `x-auth-user-id` are not two headers.
    #[test]
    fn header_names_key_case_insensitively() {
        let config = load(FOUR_LEVELS);
        let request =
            resolve(&config, "tool", "get_weather", Direction::Request).expect("a contract");
        assert_eq!(
            request
                .headers
                .iter()
                .filter(|header| header.lowercase == "x-shared")
                .count(),
            1
        );
    }

    /// A route declaring one direction still inherits the other, since
    /// resolution runs per direction.
    #[test]
    fn a_route_declaring_one_direction_inherits_the_other() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-global
          from: subject.id
    response:
      strip: [server]
routes:
  - tool: get_weather
    assertions:
      response:
        strip: [x-upstream-*]
",
        );
        let request = resolve(&config, "tool", "get_weather", Direction::Request)
            .expect("global declared it");
        assert_eq!(header_names(&request), vec!["x-global"]);
        let response = resolve(&config, "tool", "get_weather", Direction::Response)
            .expect("both levels declared it");
        assert_eq!(strip_patterns(&response), vec!["server", "x-upstream-*"]);
    }

    /// Granularity is the entry: a members object composed from two levels
    /// would have no author.
    #[test]
    fn a_repeated_members_entry_is_replaced_whole_rather_than_merged() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-auth-attributes
          members:
            roles: subject.roles
            teams: subject.teams
routes:
  - tool: get_weather
    assertions:
      request:
        headers:
          - name: x-auth-attributes
            members:
              region: claim.region
",
        );
        let request =
            resolve(&config, "tool", "get_weather", Direction::Request).expect("a contract");
        let ResolvedSource::Members(members) = &request.headers[0].source else {
            panic!("the entry is a members entry");
        };
        assert_eq!(
            members
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["region"],
            "the route's members alone, not a union of keys"
        );
    }

    #[test]
    fn replace_inherited_on_the_route_drops_the_levels_above_for_that_direction_only() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-global
          from: subject.id
          on_missing: deny
      strip: [x-legacy]
    response:
      strip: [server]
  defaults:
    tool:
      assertions:
        request:
          headers:
            - name: x-default
              from: claim.tenant
groups:
  hr:
    assertions:
      request:
        strip: [x-bundle-legacy]
routes:
  - tool: get_weather
    groups: hr
    assertions:
      request:
        replace_inherited: true
        headers:
          - name: x-route
            from: subject.id
        strip: [x-route-legacy]
",
        );
        let request =
            resolve(&config, "tool", "get_weather", Direction::Request).expect("a contract");
        assert_eq!(header_names(&request), vec!["x-route"]);
        assert_eq!(strip_patterns(&request), vec!["x-route-legacy"]);
        let response = resolve(&config, "tool", "get_weather", Direction::Response)
            .expect("global declared it");
        assert_eq!(
            strip_patterns(&response),
            vec!["server"],
            "the flag reaches the direction it is written in and no other"
        );
    }

    #[test]
    fn replace_inherited_on_a_bundle_drops_what_is_above_it_and_the_route_still_stacks() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-global
          from: subject.id
  defaults:
    tool:
      assertions:
        request:
          headers:
            - name: x-default
              from: claim.tenant
groups:
  hr:
    assertions:
      request:
        replace_inherited: true
        headers:
          - name: x-bundle
            from: claim.team
routes:
  - tool: get_weather
    groups: hr
    assertions:
      request:
        headers:
          - name: x-route
            from: claim.region
",
        );
        let request =
            resolve(&config, "tool", "get_weather", Direction::Request).expect("a contract");
        assert_eq!(header_names(&request), vec!["x-bundle", "x-route"]);
    }

    #[test]
    fn several_routes_joining_one_bundle_all_resolve_its_content() {
        let config = load(FOUR_LEVELS);
        let sibling = resolve(&config, "tool", "sibling", Direction::Request).expect("a contract");
        assert_eq!(
            header_names(&sibling),
            vec!["x-global", "x-shared", "x-default", "x-bundle"],
            "the bundle reaches every route that joins it"
        );
    }

    /// An entity default reaches every route of its type and no other.
    #[test]
    fn an_entity_default_reaches_its_own_entity_type_only() {
        let config = load(FOUR_LEVELS);
        let resource = resolve(&config, "resource", "file://a", Direction::Request)
            .expect("global declared it");
        assert_eq!(header_names(&resource), vec!["x-global", "x-shared"]);
    }

    /// #42 made a per-path contract expressible. The route's content stacks on
    /// the generic-HTTP entity default and on global.
    #[test]
    fn an_http_route_stacks_on_the_levels_above_it() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-global
          from: subject.id
      strip: [x-auth-*]
  defaults:
    http:
      assertions:
        request:
          headers:
            - name: x-served-by
              from: claim.namespace
routes:
  - http:
      path_prefix: /v1/files
      method: [GET, POST]
    assertions:
      request:
        headers:
          - name: x-auth-path-scope
            from: claim.namespace
",
        );
        let matched = resolve_route(&config, RouteQuery::http("/v1/files/a", Some("GET")));
        let request = resolve_assertions_for_route(
            &config,
            matched.as_ref(),
            Some("http"),
            Direction::Request,
        )
        .expect("three levels declared it");
        assert_eq!(
            header_names(&request),
            vec!["x-global", "x-served-by", "x-auth-path-scope"]
        );
        assert_eq!(strip_patterns(&request), vec!["x-auth-*"]);

        // A generic-HTTP request matching no route still gets the entity
        // default, because that level covers an entity type rather than a route.
        let unmatched = resolve_route(&config, RouteQuery::http("/other", Some("GET")));
        assert!(unmatched.is_none(), "no route selects /other");
        let unrouted =
            resolve_assertions_for_route(&config, None, Some("http"), Direction::Request)
                .expect("a contract");
        assert_eq!(
            header_names(&unrouted),
            vec!["x-global", "x-served-by"],
            "global plus global.defaults.http, and not the route's own header"
        );
        // And a request of another entity type gets neither.
        let other_type =
            resolve_assertions_for_route(&config, None, Some("tool"), Direction::Request)
                .expect("global declared it");
        assert_eq!(header_names(&other_type), vec!["x-global"]);
    }

    /// What the pipeline's pre-matching return sites pass, so the answer is
    /// pinned rather than incidental.
    #[test]
    fn no_matched_route_and_no_entity_type_resolves_the_global_layer_alone() {
        let config = load(FOUR_LEVELS);
        let request = resolve_assertions_for_route(&config, None, None, Direction::Request)
            .expect("global declared it");
        assert_eq!(header_names(&request), vec!["x-global", "x-shared"]);
        assert_eq!(strip_patterns(&request), vec!["x-legacy-global"]);
    }

    #[test]
    fn no_block_at_any_level_resolves_to_nothing() {
        let config = load("engine_settings:\n  dispatch: policy\nroutes:\n  - tool: get_weather\n");
        for direction in [Direction::Request, Direction::Response] {
            assert!(resolve(&config, "tool", "get_weather", direction).is_none());
            assert!(resolve_assertions_for_route(&config, None, None, direction).is_none());
        }
    }

    /// A level that clears what it inherited and adds nothing is a declared
    /// contract that asserts nothing, which is not the same as no contract: it
    /// is the spelling for opting out of an inherited floor.
    #[test]
    fn a_contract_cleared_to_empty_is_not_the_same_as_no_contract() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-global
          from: subject.id
          on_missing: deny
routes:
  - tool: analytics
    assertions:
      request:
        replace_inherited: true
",
        );
        let request = resolve(&config, "tool", "analytics", Direction::Request)
            .expect("the route declared the direction");
        assert!(request.is_empty(), "cleared, and nothing added");
    }

    /// A bundle written in both spellings is one membership, so its layer
    /// stacks once.
    #[test]
    fn a_bundle_named_in_both_spellings_contributes_one_layer() {
        let config = load(
            "
engine_settings:
  dispatch: policy
groups:
  hr:
    assertions:
      request:
        strip: [x-hr]
routes:
  - tool: get_weather
    groups: hr
    meta:
      tags: [hr]
",
        );
        let request = resolve(&config, "tool", "get_weather", Direction::Request)
            .expect("the bundle declared it");
        assert_eq!(strip_patterns(&request), vec!["x-hr"]);
    }

    /// Bundles have no order among themselves, so two of them asserting one
    /// header would be decided by nothing the config says.
    #[test]
    fn two_bundles_asserting_one_header_are_refused_naming_both() {
        let err = refuse(
            "
engine_settings:
  dispatch: policy
groups:
  a:
    assertions:
      request:
        headers:
          - name: x-auth-user-id
            from: subject.id
  b:
    assertions:
      request:
        headers:
          - name: X-Auth-User-Id
            from: claim.tenant
routes:
  - tool: get_weather
    groups: [a, b]
",
        );
        assert!(err.contains("groups.a"), "{err}");
        assert!(err.contains("groups.b"), "{err}");
        assert!(err.contains("X-Auth-User-Id"), "{err}");
        assert!(err.contains("assertions.request"), "{err}");
        assert!(err.contains("tool:get_weather"), "{err}");
    }

    #[test]
    fn two_bundles_asserting_different_headers_union() {
        let config = load(
            "
engine_settings:
  dispatch: policy
groups:
  a:
    assertions:
      request:
        headers:
          - name: x-a
            from: subject.id
  b:
    assertions:
      request:
        headers:
          - name: x-b
            from: claim.tenant
routes:
  - tool: get_weather
    groups: [a, b]
",
        );
        let request = resolve(&config, "tool", "get_weather", Direction::Request)
            .expect("both bundles declared it");
        assert_eq!(header_names(&request), vec!["x-a", "x-b"]);
    }

    /// The same header in different directions is not a conflict: they are two
    /// contracts.
    #[test]
    fn two_bundles_naming_one_header_in_different_directions_load() {
        load(
            "
engine_settings:
  dispatch: policy
groups:
  a:
    assertions:
      request:
        headers:
          - name: x-served
            from: subject.id
  b:
    assertions:
      response:
        headers:
          - name: x-served
            from: claim.tenant
routes:
  - tool: get_weather
    groups: [a, b]
",
        );
    }

    /// Every level but bundles is ordered, so a repeated header there is a
    /// per-name override rather than an ambiguity.
    #[test]
    fn an_entity_default_and_a_bundle_naming_one_header_is_an_override() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  defaults:
    tool:
      assertions:
        request:
          headers:
            - name: x-shared
              from: subject.id
groups:
  hr:
    assertions:
      request:
        headers:
          - name: x-shared
            from: claim.tenant
routes:
  - tool: get_weather
    groups: hr
",
        );
        let request =
            resolve(&config, "tool", "get_weather", Direction::Request).expect("a contract");
        assert_eq!(header_names(&request), vec!["x-shared"]);
        assert_eq!(request.headers[0].level, AssertionLevel::Bundle);
        assert_eq!(
            request.headers[0].overrode.as_deref(),
            Some("global.defaults.tool")
        );
    }

    /// A flag above the route removes content the route's own author cannot
    /// see, so every affected route is reported once per direction.
    #[test]
    fn a_flag_above_the_route_is_reported_per_affected_route() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-global
          from: subject.id
      strip: [x-legacy]
groups:
  hr:
    assertions:
      request:
        replace_inherited: true
        headers:
          - name: x-bundle
            from: claim.team
routes:
  - tool: one
    groups: hr
  - tool: two
    groups: hr
  - tool: three
",
        );
        let findings = dropped_inherited_assertions(&config);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert_eq!(findings[0].route, "tool:one");
        assert_eq!(findings[0].declared_in, "groups.hr");
        assert_eq!(findings[0].direction, "assertions.request");
        assert_eq!(findings[0].dropped_headers, vec!["x-global".to_owned()]);
        assert_eq!(findings[0].dropped_strip, vec!["x-legacy".to_owned()]);
        assert_eq!(findings[1].route, "tool:two");
    }

    /// A route's own flag is written where its author can see it, and global's
    /// drops nothing because nothing has accumulated before it.
    #[test]
    fn a_routes_own_flag_and_a_global_one_are_not_reported() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      replace_inherited: true
      headers:
        - name: x-global
          from: subject.id
routes:
  - tool: one
    assertions:
      request:
        replace_inherited: true
        headers:
          - name: x-route
            from: subject.id
",
        );
        assert!(dropped_inherited_assertions(&config).is_empty());
    }

    /// A contract on an `http:` route is in force only when the host supplies
    /// the request line, so every such route is named at load.
    #[test]
    fn an_http_route_declaring_a_contract_is_reported_once() {
        let config = load(
            "
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
    assertions:
      request:
        headers:
          - name: x-a
            from: subject.id
  - http: /healthz
  - tool: get_weather
    assertions:
      request:
        headers:
          - name: x-b
            from: subject.id
",
        );
        let gaps = assertions_reachability_gaps(&config);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert!(gaps[0].contains("prefix:/v1/files"), "{}", gaps[0]);
        assert!(gaps[0].contains("request line"), "{}", gaps[0]);
        assert!(
            gaps[0].contains("global.defaults.http"),
            "the finding names what governs instead: {}",
            gaps[0]
        );
    }

    #[test]
    fn a_config_with_no_http_route_contract_is_not_reported() {
        for yaml in [
            "engine_settings:\n  dispatch: policy\nroutes:\n  - http: /healthz\n",
            "engine_settings:\n  dispatch: policy\nroutes:\n  - tool: t\n",
            "engine_settings:\n  dispatch: policy\n",
        ] {
            assert!(
                assertions_reachability_gaps(&load(yaml)).is_empty(),
                "{yaml}"
            );
        }
    }

    #[test]
    fn a_config_with_no_flag_above_a_route_reports_nothing() {
        let config = load(FOUR_LEVELS);
        assert!(dropped_inherited_assertions(&config).is_empty());
    }
}
