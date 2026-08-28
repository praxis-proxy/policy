// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Unified YAML configuration parsing.
//
// Parses the config format that combines global settings, plugin
// declarations, and per-entity routes into a single YAML document.
//
// Supports two modes controlled by `plugin_settings.routing_enabled`:
//   - false (default, backward compatible): plugins declare their
//     own conditions for when they fire.
//   - true: per-entity routing rules determine which plugins fire,
//     with plugin selection via policy groups and meta.tags.
//
// The two modes are mutually exclusive. When routing is disabled,
// the routes and global sections are ignored. When routing is
// enabled, conditions on individual plugins are ignored.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cmf::constants::{
    ENTITY_HTTP, ENTITY_LLM, ENTITY_NAME_GLOBAL, ENTITY_PROMPT, ENTITY_RESOURCE, ENTITY_TOOL,
};
use crate::error::PluginError;
use crate::plugin::PluginConfig;

/// Top-level PPE configuration.
///
/// Parsed from a single YAML file. Plugin scoping mode is controlled
/// by `plugin_settings.routing_enabled` — if absent or false, plugins
/// use their own `conditions:` field (backward compatible). If true,
/// the `routes:` and `global:` sections take over.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Global configuration — policies, defaults.
    /// Only used when `plugin_settings.routing_enabled` is true.
    #[serde(default)]
    pub global: GlobalConfig,

    /// Directories to scan for plugin modules.
    #[serde(default)]
    pub plugin_dirs: Vec<String>,

    /// Plugin declarations.
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,

    /// Named policy bundles a route can join, keyed by group name. The
    /// canonical, top-level spelling — lines up with `global:` (always-on
    /// defaults) and `routes:` (per-entity policy) as the third concern.
    ///
    /// Superset-compatible with the older `global.policies:` location, which
    /// stays accepted as a deprecated alias: at parse time both are merged
    /// into one bundle map (`global.policies`, the internal store the
    /// resolvers read), with entries here winning on a name collision.
    #[serde(default)]
    pub groups: HashMap<String, PolicyGroup>,

    /// Per-entity routing rules.
    /// Only used when `plugin_settings.routing_enabled` is true.
    #[serde(default)]
    pub routes: Vec<RouteEntry>,

    /// Global plugin settings (timeout, error behavior, routing mode).
    #[serde(default)]
    pub plugin_settings: PluginSettings,
}

impl PolicyConfig {
    /// Whether route-based plugin selection is enabled.
    pub fn routing_enabled(&self) -> bool {
        self.plugin_settings.routing_enabled
    }
}

/// Global plugin settings.
///
/// Controls executor behavior and routing mode. All fields have
/// sensible defaults — a missing `plugin_settings:` section is valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSettings {
    /// Enable route-based plugin selection.
    /// When false (default), plugins use their own `conditions:` field.
    /// When true, the `routes:` and `global:` sections determine which
    /// plugins fire per entity.
    #[serde(default)]
    pub routing_enabled: bool,

    /// Default timeout per plugin in seconds.
    #[serde(default = "default_timeout")]
    pub plugin_timeout: u64,

    /// Whether to halt on first deny in concurrent mode.
    #[serde(default = "default_true")]
    pub short_circuit_on_deny: bool,

    /// Whether plugins can execute in parallel within a mode band.
    #[serde(default)]
    pub parallel_execution_within_band: bool,

    /// Whether to halt the pipeline on any plugin error.
    #[serde(default)]
    pub fail_on_plugin_error: bool,

    /// Maximum number of entries in the routing cache.
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

impl Default for PluginSettings {
    fn default() -> Self {
        Self {
            routing_enabled: false,
            plugin_timeout: 30,
            short_circuit_on_deny: true,
            parallel_execution_within_band: false,
            fail_on_plugin_error: false,
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
/// Only used when routing is enabled. Contains named policy groups
/// (including the reserved `all` group) and per-entity-type defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Named policy groups. The reserved name `all` is applied to
    /// every request unconditionally. Other groups are inherited
    /// by routes via `meta.tags`.
    #[serde(default)]
    pub policies: HashMap<String, PolicyGroup>,

    /// Per-entity-type default policy groups. Keys are `tool`, `resource`,
    /// `prompt`, `llm`, and `http`; anything else is rejected at load, since a
    /// misspelled entity type would be inert rather than wrong.
    #[serde(default)]
    pub defaults: HashMap<String, PolicyGroup>,

    /// Global authentication dispatch list (YAML key `authentication:`).
    /// Inherited by every route as the first layer of identity
    /// resolution. Routes can append to it (additive, the default) or
    /// replace it (with `authentication.replace_inherited: true` on the
    /// route).
    ///
    /// Same YAML shape as the route-level `authentication:` block — see
    /// `RouteEntry.identity` for the accepted forms.
    #[serde(
        default,
        rename = "authentication",
        deserialize_with = "deserialize_route_identity"
    )]
    pub identity: Option<crate::identity::RouteIdentityConfig>,
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

    /// Plugin references to activate when this group matches.
    #[serde(default, deserialize_with = "deserialize_plugin_refs")]
    pub plugins: Vec<PluginRouteRef>,

    /// Authentication dispatch list contributed by this tag bundle
    /// (YAML key `authentication:`). Inherited by routes that carry this
    /// tag in `meta.tags`, stacked between the global authentication
    /// (first) and the route's own authentication (last). Same YAML shape
    /// as the route-level `authentication:` block.
    #[serde(
        default,
        rename = "authentication",
        deserialize_with = "deserialize_route_identity"
    )]
    pub identity: Option<crate::identity::RouteIdentityConfig>,
}

/// A reference to a plugin in a route or policy group.
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

/// Deserialize a `plugins:` field that may take either of two YAML
/// shapes, so the `apl:` wrapper is genuinely optional everywhere.
///
/// - A **sequence** is the structural activation list — each item is a
///   [`PluginRouteRef`] (bare name or single-key override map). It
///   deserializes into the `Vec` as usual.
/// - A **mapping** is the APL per-plugin *override* form, written
///   directly on the section when the `apl:` wrapper is omitted (e.g.
///   `plugins: { audit: { on_error: ignore } }`). It is **not** a
///   structural activation list: the override map is consumed
///   separately by the APL visitor straight from the raw YAML, so here
///   it deserializes to an empty `Vec`. This mirrors the explicit
///   `apl: { plugins: {...} }` wrapper form, where the map never
///   reaches this field at all — keeping the two forms behaviorally
///   identical (the map supplies overrides; policy steps still do the
///   activating).
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
    /// Requires `plugin_settings.routing_enabled: true`, which defaults to
    /// false and leaves the route inert until it is set, like every other
    /// route selector. See [`HttpSelector`] for the three shapes.
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
    /// `meta: { tags: [hr-tools] }` resolve identically. Tags remain the
    /// substrate — they can also be injected by the host at runtime and carry
    /// metadata beyond membership; `groups:` just names the common "join this
    /// bundle" case up front. See `route_static_tags`.
    #[serde(default)]
    pub groups: Option<StringOrList>,

    /// Conditional match expression — carried but not evaluated
    /// during static resolution. Evaluated at runtime when payload
    /// data is available (future: APL evaluator).
    #[serde(default)]
    pub when: Option<String>,

    /// Plugin references to activate for this route.
    #[serde(default, deserialize_with = "deserialize_plugin_refs")]
    pub plugins: Vec<PluginRouteRef>,

    /// Authentication dispatch list for this route (YAML key
    /// `authentication:`). **Hook-specific**: applies ONLY to the
    /// `identity.resolve` hook, independent of the `plugins:` block above
    /// (which is hook-agnostic and means different things depending on
    /// whether APL is annotating the route — `authentication:` always
    /// means "these plugins fire on identity.resolve in this order").
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
    #[serde(
        default,
        rename = "authentication",
        deserialize_with = "deserialize_route_identity"
    )]
    pub identity: Option<crate::identity::RouteIdentityConfig>,
}

/// Deserialize the `authentication:` block in a `RouteEntry`. Accepts either a YAML
/// list (treated as additive — `replace_inherited: false`) or a
/// YAML map with `replace_inherited: bool?` + `steps: [...]`. Each
/// step is either a bare plugin name (string) or a map with
/// `name:` + optional `on_error:` / `config:`. Produces friendlier
/// error messages than `#[serde(untagged)]` would.
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
            let replace_inherited =
                match map.get(serde_yaml::Value::String("replace_inherited".to_owned())) {
                    Some(v) => v.as_bool().ok_or_else(|| {
                        D::Error::custom("`identity.replace_inherited` must be a boolean")
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

/// Parse one identity step from raw YAML. Accepts either a bare
/// plugin name (string) or a map with `name:` + optional
/// `on_error:` / `config:` (and any forward-compat extras).
fn parse_identity_step(
    raw: serde_yaml::Value,
    index: usize,
) -> Result<crate::identity::RouteIdentityStep, String> {
    use crate::identity::RouteIdentityStep;

    match raw {
        serde_yaml::Value::String(name) => {
            if name.is_empty() {
                return Err(format!(
                    "identity step [{index}] plugin name cannot be empty"
                ));
            }
            Ok(RouteIdentityStep {
                name,
                ..Default::default()
            })
        },
        serde_yaml::Value::Mapping(_) => {
            // Lean on serde's derived Deserialize for the map shape —
            // `RouteIdentityStep` already handles `name` / `on_error` /
            // `config_override` and flattens extras into `extra`.
            // Translate the operator-facing key `config` → IR field
            // `config_override` (the IR uses a more explicit name to
            // distinguish from the plugin's runtime config).
            #[derive(serde::Deserialize)]
            struct StepYaml {
                name: String,
                #[serde(default)]
                on_error: Option<String>,
                #[serde(default)]
                config: Option<serde_json::Value>,
                #[serde(default, flatten)]
                extra: std::collections::HashMap<String, serde_json::Value>,
            }
            let parsed: StepYaml =
                serde_yaml::from_value(raw).map_err(|e| format!("identity step [{index}]: {e}"))?;
            if parsed.name.is_empty() {
                return Err(format!("identity step [{index}] `name:` cannot be empty"));
            }
            Ok(RouteIdentityStep {
                name: parsed.name,
                config_override: parsed.config,
                on_error: parsed.on_error,
                extra: parsed.extra,
            })
        },
        _ => Err(format!(
            "identity step [{index}] must be a plugin name (string) or a map \
             with `name:` (and optional `on_error:` / `config:`)"
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
/// Nothing here resolves until `plugin_settings.routing_enabled: true` is set.
/// It defaults to false, and an `http:` route declared without it is reported
/// at load rather than left to be discovered.
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
/// Returns `PluginError::Config` when the YAML does not deserialize, when it
/// carries a renamed legacy key, and when a route carries a key nothing reads.
/// Those two are rejected rather than ignored: an unknown field is dropped
/// silently, so a stale `identity:` block would leave its authentication steps
/// unrun and a misspelled selector would leave a route matching nothing, both
/// of which fail open.
pub fn parse_config(yaml: &str) -> Result<PolicyConfig, Box<PluginError>> {
    // Scan the raw YAML for renamed legacy keys before the typed parse:
    // `RouteEntry` / `GlobalConfig` / `PolicyGroup` silently ignore unknown
    // fields, so a stale `identity:` would otherwise be dropped and its
    // authentication steps never run — a fail-open.
    let raw: serde_yaml::Value = serde_yaml::from_str(yaml).map_err(|e| PluginError::Config {
        message: format!("failed to parse config YAML: {e}"),
    })?;
    reject_renamed_identity_key(&raw)?;
    // No visitor is registered on this path, so only praxis-policy-core's own
    // route keys are accepted. A host whose visitor reads route keys of its
    // own loads through `PolicyEngine::load_config_yaml`, which unions them in.
    reject_unknown_route_keys(&raw, &[])?;
    let mut config: PolicyConfig =
        serde_yaml::from_value(raw).map_err(|e| PluginError::Config {
            message: format!("failed to parse config YAML: {e}"),
        })?;
    merge_groups_into_policies(&mut config);
    validate_config(&config)?;
    Ok(config)
}

/// Fold the canonical top-level `groups:` bundles into the internal
/// `global.policies` map (the deprecated alias location), so every resolver
/// can keep reading a single map. Top-level entries win on a name collision
/// — the canonical spelling takes precedence over the deprecated one.
pub(crate) fn merge_groups_into_policies(config: &mut PolicyConfig) {
    if config.groups.is_empty() {
        return;
    }
    for (name, group) in std::mem::take(&mut config.groups) {
        config.global.policies.insert(name, group);
    }
}

/// Reject the pre-rename `identity:` key (now `authentication:`) at every
/// scope it could appear — `global`, `global.policies.<name>`,
/// `global.defaults.<name>`, and each `routes[]` entry — so a stale config
/// fails loudly rather than silently dropping its authentication steps.
pub(crate) fn reject_renamed_identity_key(raw: &serde_yaml::Value) -> Result<(), Box<PluginError>> {
    fn renamed(scope: &str) -> Box<PluginError> {
        Box::new(PluginError::Config {
            message: format!(
                "in `{scope}`: config field `identity` was renamed to `authentication` — update your config"
            ),
        })
    }
    if let Some(global) = raw.get("global") {
        if global.get("identity").is_some() {
            return Err(renamed("global"));
        }
        for section in ["policies", "defaults"] {
            if let Some(map) = global.get(section).and_then(|m| m.as_mapping()) {
                for (name, group) in map {
                    if group.get("identity").is_some() {
                        let n = name.as_str().unwrap_or("?");
                        return Err(renamed(&format!("global.{section}.{n}")));
                    }
                }
            }
        }
    }
    // Same guard for the canonical top-level `groups:` bundle location.
    if let Some(map) = raw.get("groups").and_then(|m| m.as_mapping()) {
        for (name, group) in map {
            if group.get("identity").is_some() {
                let n = name.as_str().unwrap_or("?");
                return Err(renamed(&format!("groups.{n}")));
            }
        }
    }
    if let Some(routes) = raw.get("routes").and_then(|r| r.as_sequence()) {
        for (i, route) in routes.iter().enumerate() {
            if route.get("identity").is_some() {
                return Err(renamed(&format!("routes[{i}]")));
            }
        }
    }
    Ok(())
}

/// Legacy APL config keys, mapped to their replacements.
///
/// The one table for these names. A parse that meets an unrecognized key drops
/// it, and a dropped `policy:` block leaves no authorization enforced, so every
/// scope that reads route or policy YAML rejects these loudly rather than
/// letting one through unread.
pub const RENAMED_APL_KEYS: [(&str, &str); 2] = [
    (
        "policy",
        "authorization.pre_invocation (or flat pre_invocation)",
    ),
    (
        "post_policy",
        "authorization.post_invocation (or flat post_invocation)",
    ),
];

/// The rename message for a legacy APL key written directly in `yaml`, or
/// `None` when it carries none. Shared so every scope that checks reports the
/// rename in the same words.
#[must_use]
pub fn renamed_apl_key_message(scope: &str, yaml: &serde_yaml::Value) -> Option<String> {
    let map = yaml.as_mapping()?;
    RENAMED_APL_KEYS.iter().find_map(|(old, new)| {
        map.contains_key(serde_yaml::Value::String((*old).to_owned()))
            .then(|| {
                format!(
                    "in `{scope}`: config field `{old}` was renamed to `{new}` — update your config"
                )
            })
    })
}

/// The route keys a configuration may carry.
///
/// Larger than [`RouteEntry`]'s typed fields on purpose: a route shares its
/// mapping with the orchestrator blocks the typed struct deliberately ignores,
/// so `deny_unknown_fields` would reject every APL-annotated route in the tree.
/// `apl:` and `response:` are those blocks; the rest are the APL terms an
/// operator may write flat on the route with no `apl:` wrapper.
const KNOWN_ROUTE_KEYS: &[&str] = &[
    // Typed `RouteEntry` fields.
    "tool",
    "resource",
    "prompt",
    "llm",
    "http",
    "meta",
    "groups",
    "when",
    "plugins",
    "authentication",
    // Orchestrator blocks praxis-policy-core carries but does not model.
    "apl",
    "response",
    // APL terms accepted flat on a route, without the `apl:` wrapper.
    "pre_invocation",
    "post_invocation",
    "authorization",
    "args",
    "result",
    "pdp",
    "session_store",
];

/// Reject the route keys nothing reads, naming every one of them and the route.
///
/// An unknown field is dropped by the typed parse, so a misspelled selector
/// used to load clean and leave the route matching nothing. A key from
/// [`RENAMED_APL_KEYS`] gets the rename message instead, since that is the more
/// specific answer, so that check runs first. `extra_route_keys` carries the
/// keys registered visitors consume, so a host orchestrator reading a key
/// praxis-policy-core has never heard of stays loadable.
///
/// # Errors
///
/// Returns `PluginError::Config` naming the renamed key, or every unrecognized
/// key on the first route carrying one, with that route's index.
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
        // A renamed key is also an unrecognized one, so this runs first or the
        // operator gets sent hunting a typo instead of performing a rename.
        if let Some(message) = renamed_apl_key_message(&format!("routes[{i}]"), route) {
            return Err(Box::new(PluginError::Config { message }));
        }
        let mut unknown: Vec<&str> = Vec::new();
        for key in map.keys() {
            let Some(key) = key.as_str() else {
                return Err(Box::new(PluginError::Config {
                    message: format!("route {i} has a key that is not a string"),
                }));
            };
            if KNOWN_ROUTE_KEYS.contains(&key) || extra_route_keys.contains(&key) {
                continue;
            }
            unknown.push(key);
        }
        if !unknown.is_empty() {
            // Every bad key at once: one load reports the whole list rather
            // than one key per attempt.
            let label = if unknown.len() == 1 { "key" } else { "keys" };
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "route {i} has unknown {label} `{}`; a route accepts {}",
                    unknown.join("`, `"),
                    KNOWN_ROUTE_KEYS.join(", ")
                ),
            }));
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
/// This checks declared hook names plus the *structural* plugin activation
/// lists (`route.plugins` / `policy_group.plugins` sequences). It deliberately
/// does NOT validate APL plugin references — neither `plugin(...)` / `run(...)`
/// policy steps nor the APL per-plugin override *map* (which
/// [`deserialize_plugin_refs`] folds into an empty structural `Vec`, leaving
/// it for the APL visitor to consume). Those are resolved and validated at
/// dispatch-plan build time, where an unknown or unreferenced plugin is logged
/// and skipped (see `praxis-policy-apl-runtime::dispatch_plan`). Keeping praxis-policy-core's validation
/// free of APL semantics is intentional.
pub(crate) fn validate_config(config: &PolicyConfig) -> Result<(), Box<PluginError>> {
    validate_declared_hooks(config)?;
    reject_reserved_route_names(config)?;

    let mut seen_names = HashSet::new();
    for plugin in &config.plugins {
        if !seen_names.insert(&plugin.name) {
            return Err(Box::new(PluginError::Config {
                message: format!("duplicate plugin name: '{}'", plugin.name),
            }));
        }
    }

    if config.routing_enabled() {
        let plugin_names: HashSet<&str> = config.plugins.iter().map(|p| p.name.as_str()).collect();

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
            // would have supplied. `meta.tags` stays permissive — tags are
            // an open-ended, host-injectable substrate, not all of which
            // name groups. Runs after `merge_groups_into_policies`, so
            // top-level `groups:` are already folded into `global.policies`.
            if let Some(groups) = &route.groups {
                for name in groups.as_names() {
                    if !config.global.policies.contains_key(name) {
                        return Err(Box::new(PluginError::Config {
                            message: format!("route {i} joins unknown group '{name}'"),
                        }));
                    }
                }
            }
        }

        for (group_name, group) in &config.global.policies {
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
        }
    }

    Ok(())
}

/// What a declared set of `http:` routes leaves ungoverned, one message per
/// gap, empty when there is nothing to report. Only `http:` routes are
/// examined, so a configuration that declares none is never reported on.
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
    // Inert beats uncovered: with routing off no route resolves at all, so
    // naming the missing catch-all on top of it would send an operator to the
    // wrong line of their config.
    if !config.routing_enabled() {
        return vec![format!(
            "config declares `http:` routes (count={}) but \
             `plugin_settings.routing_enabled` is false, which is the default, so none of them \
             resolves and every request is governed by the global policy",
            selectors.len(),
        )];
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
const SPECIFICITY_WHEN_ONLY: usize = 10;
const SPECIFICITY_WILDCARD: usize = 0;

/// Specificity for an `http:` selector. An `http:` route only ever competes
/// with other `http:` routes, so paths order on their own scale and the name
/// buckets above are left alone.
///
/// An exact path outranks every prefix, however long, and among prefixes the
/// longer one wins. The per-character weight sits above the scope, `method:`,
/// and `when:` bonuses so prefix length decides before any tiebreaker does.
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
/// copy-pasted match arms in `resolve_plugins_for_entity`.
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
/// metadata-bearing). Both membership resolvers iterate this so neither can
/// forget one of the two spellings.
fn route_static_tags(route: &RouteEntry) -> impl Iterator<Item = &str> {
    let meta_tags = route
        .meta
        .iter()
        .flat_map(|m| m.tags.iter().map(String::as_str));
    let group_tags = route.groups.iter().flat_map(StringOrList::as_names);
    meta_tags.chain(group_tags)
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

/// Resolve which plugins should fire for a given entity.
///
/// When routing is disabled, returns all plugin names. When enabled, collects
/// plugins from the `all` group, the entity type's defaults, the matched route's
/// groups (via merged tags), and the route itself.
///
/// The caller matches the route once with [`resolve_route`] and passes the
/// result in. `entity_type` is still needed on its own, because the entity
/// type's defaults apply whether or not a route matched.
///
/// `request_tags` comes from the host's `MetaExtension` on the request.
pub fn resolve_plugins_for_entity(
    config: &PolicyConfig,
    entity_type: &str,
    matched: Option<&MatchedRoute<'_>>,
    request_tags: &HashSet<String>,
) -> Vec<ResolvedPlugin> {
    if !config.routing_enabled() {
        return config
            .plugins
            .iter()
            .map(|p| ResolvedPlugin {
                name: p.name.clone(),
                config_overrides: None,
                when: None,
            })
            .collect();
    }

    let mut resolved = Vec::new();

    // 1. Always include plugins from the "all" policy group
    if let Some(all_group) = config.global.policies.get("all") {
        collect_plugin_refs(&all_group.plugins, &mut resolved, None);
    }

    // 2. Include plugins from matching defaults
    if let Some(default_group) = config.global.defaults.get(entity_type) {
        collect_plugin_refs(&default_group.plugins, &mut resolved, None);
    }

    // 3. Layer the matched route: its groups and tags, then its own plugins.
    if let Some(route) = matched.map(|m| m.route) {
        // Merge tags: route's static membership (meta.tags + groups: sugar)
        // + host's runtime tags.
        let mut merged_tags: HashSet<String> = request_tags.clone();
        for tag in route_static_tags(route) {
            merged_tags.insert(tag.to_owned());
        }

        // Include plugins from all matching policy groups (merged tags)
        for tag in &merged_tags {
            if tag == "all" {
                continue; // already handled above
            }
            if let Some(group) = config.global.policies.get(tag.as_str()) {
                collect_plugin_refs(&group.plugins, &mut resolved, None);
            }
        }

        // Include route-level plugins, carrying the route's when clause
        collect_plugin_refs(&route.plugins, &mut resolved, route.when.as_deref());
    }

    // Deduplicate by name, preserving order. Later overrides win.
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for rp in resolved.into_iter().rev() {
        if seen.insert(rp.name.clone()) {
            deduped.push(rp);
        }
    }
    deduped.reverse();
    deduped
}

/// Resolve the identity-resolve dispatch list for a specific
/// entity. Hook-specific counterpart to [`resolve_plugins_for_entity`]
/// — consults the global `authentication:` block, tag-bundle
/// `authentication:` blocks, and the route's own `authentication:` block
/// to determine which plugins fire on the `identity.resolve` hook for
/// this route.
///
/// # Inheritance / merge order
///
/// Layers are stacked **global → tag bundles → route**, in that
/// order. Within tags, the order is determined by the request's
/// `meta.tags` (which combines static route tags + runtime request
/// tags). Each layer is appended to the running list unless the
/// **route's** block has `replace_inherited: true`, in which case
/// inherited layers (global + tags) are dropped and only the route's
/// steps remain. Tag-bundle `replace_inherited` is parsed but not
/// honored — only the route layer can opt out of inheritance.
///
/// Order matters: returned plugins fire in the order they were
/// merged. The first plugin's resolved `IdentityPayload` flows into
/// the second plugin's input via the executor's Sequential-phase
/// semantics, so global identity contributions land first, then
/// tag-bundle, then route-specific overrides / additions.
///
/// Per-step `config_override` is surfaced as
/// `ResolvedPlugin.config_overrides` so the standard
/// `filter_entries_by_route` override pathway
/// (`create_override_instance`) applies — same mechanism the
/// `plugins:` block uses.
///
/// Returns an empty `Vec` when no layer contributed any steps
/// (e.g. anonymous routes that explicitly opt out via
/// `replace_inherited: true` + empty `steps: []`).
pub fn resolve_identity_plugins_for_route(
    config: &PolicyConfig,
    matched: Option<&MatchedRoute<'_>>,
) -> Vec<ResolvedPlugin> {
    // Route-level block is the override authority. No matched route means
    // there's no route to inherit identity FOR (still consult global identity
    // though, since the host might be doing per-route hook routing on the
    // entity type alone with no specific route).
    let route = matched.map(|m| m.route);
    let route_identity = route.and_then(|r| r.identity.as_ref());

    // Check the override flag before doing any inheritance work —
    // if the route opts out, inherited layers are dropped.
    let replace_inherited = route_identity
        .map(|id| id.replace_inherited)
        .unwrap_or(false);

    let mut steps: Vec<crate::identity::RouteIdentityStep> = Vec::new();

    if !replace_inherited {
        // Global layer first — applies to every route.
        if let Some(global_identity) = config.global.identity.as_ref() {
            steps.extend(global_identity.steps.iter().cloned());
        }

        // Tag-bundle layers next. Walk the route's static membership tags
        // (meta.tags + groups: sugar, via `route_static_tags`). Runtime tags
        // would compose here too, but resolve_* currently doesn't take them as
        // a parameter for identity — symmetry with the existing `plugins:`
        // resolver would extend the signature; deferred until needed.
        if let Some(route) = route {
            for tag in route_static_tags(route) {
                if let Some(bundle) = config.global.policies.get(tag)
                    && let Some(bundle_identity) = bundle.identity.as_ref()
                {
                    steps.extend(bundle_identity.steps.iter().cloned());
                }
            }
        }
    }

    // Route layer last (or only, when replace_inherited).
    if let Some(id) = route_identity {
        steps.extend(id.steps.iter().cloned());
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
            when: None,
        })
        .collect()
}

/// A resolved plugin with optional config overrides and when clause.
#[derive(Debug, Clone)]
pub struct ResolvedPlugin {
    /// Plugin name.
    pub name: String,

    /// Config overrides from the route.
    pub config_overrides: Option<serde_json::Value>,

    /// When clause from the route — carried but not evaluated here.
    pub when: Option<String>,
}

/// Collect plugin refs into the resolved list.
fn collect_plugin_refs(
    refs: &[PluginRouteRef],
    resolved: &mut Vec<ResolvedPlugin>,
    route_when: Option<&str>,
) {
    for plugin_ref in refs {
        resolved.push(ResolvedPlugin {
            name: plugin_ref.name().to_owned(),
            config_overrides: plugin_ref.overrides().cloned(),
            when: route_when.map(String::from),
        });
    }
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

        let when_bonus = if route.when.is_some() {
            SPECIFICITY_WHEN_ONLY
        } else {
            0
        };
        let total = base_specificity.saturating_add(scope_bonus + when_bonus);

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

    // Helper: empty tags for tests that don't need them
    fn no_tags() -> HashSet<String> {
        HashSet::new()
    }

    /// Match once, then layer, which is what the engine does. Keeps the
    /// resolution call sites below reading as one step.
    fn plugins_for(
        config: &PolicyConfig,
        entity_type: &str,
        entity_name: &str,
        request_scope: Option<&str>,
        request_tags: &HashSet<String>,
    ) -> Vec<ResolvedPlugin> {
        let matched = resolve_route(
            config,
            RouteQuery::named(entity_type, entity_name).with_scope(request_scope),
        );
        resolve_plugins_for_entity(config, entity_type, matched.as_ref(), request_tags)
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
    priority: 5
    config:
      max_requests: 100
"#;
        let config = parse_config(yaml).unwrap();
        assert!(!config.routing_enabled());
        assert_eq!(config.plugins.len(), 1);
        assert_eq!(config.plugins[0].name, "rate_limiter");
    }

    #[test]
    fn test_no_plugin_settings_defaults_routing_disabled() {
        let yaml = r#"
plugins:
  - name: test
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
"#;
        let config = parse_config(yaml).unwrap();
        assert!(!config.routing_enabled());
        assert_eq!(config.plugin_settings.plugin_timeout, 30);
    }

    #[test]
    fn test_routing_enabled() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [identity]
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
        assert!(config.routing_enabled());
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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

    #[test]
    fn test_route_unknown_plugin_rejected() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: known
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    plugins:
      - unknown
"#;
        assert!(
            parse_config(yaml)
                .unwrap_err()
                .to_string()
                .contains("unknown plugin 'unknown'")
        );
    }

    #[test]
    fn test_policy_group_unknown_plugin_rejected() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [nonexistent]
plugins: []
routes: []
"#;
        assert!(
            parse_config(yaml)
                .unwrap_err()
                .to_string()
                .contains("unknown plugin 'nonexistent'")
        );
    }

    #[test]
    fn test_resolve_conditions_mode_returns_all() {
        let yaml = r#"
plugins:
  - name: a
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: b
    kind: builtin
    hooks: [cmf.tool_post_invoke]
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = plugins_for(&config, "tool", "anything", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn test_resolve_routes_inherits_policy_groups() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins:
        - identity
    pii:
      plugins:
        - apl_policy
plugins:
  - name: identity
    kind: builtin
    hooks: [identity.resolve]
  - name: apl_policy
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = plugins_for(&config, "tool", "get_compensation", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"identity"));
        assert!(names.contains(&"apl_policy"));
    }

    #[test]
    fn test_resolve_no_matching_route_gets_all_only() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
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
        let config = parse_config(yaml).unwrap();
        let resolved = plugins_for(&config, "tool", "unknown_tool", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["identity"]);
    }

    #[test]
    fn test_exact_match_beats_glob() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: specific
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: general
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: "hr-*"
    plugins:
      - general
  - tool: hr-compensation
    plugins:
      - specific
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = plugins_for(&config, "tool", "hr-compensation", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"specific"));
        assert!(!names.contains(&"general"));
    }

    #[test]
    fn test_plugin_ref_bare_name() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    plugins:
      - rate_limiter
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = plugins_for(&config, "tool", "get_compensation", None, &no_tags());
        assert_eq!(resolved[0].name, "rate_limiter");
        assert!(resolved[0].config_overrides.is_none());
    }

    #[test]
    fn test_plugin_ref_with_overrides() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
    config:
      max_requests: 100
routes:
  - tool: get_compensation
    plugins:
      - rate_limiter:
          config:
            max_requests: 10
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = plugins_for(&config, "tool", "get_compensation", None, &no_tags());
        assert_eq!(resolved[0].name, "rate_limiter");
        assert!(resolved[0].config_overrides.is_some());
        let overrides = resolved[0].config_overrides.as_ref().unwrap();
        assert_eq!(overrides["config"]["max_requests"], 10);
    }

    #[test]
    fn test_plugin_ref_mixed_bare_and_overrides() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: pii_scanner
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    plugins:
      - rate_limiter
      - pii_scanner:
          config:
            sensitivity: high
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = plugins_for(&config, "tool", "get_compensation", None, &no_tags());
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "rate_limiter");
        assert!(resolved[0].config_overrides.is_none());
        assert_eq!(resolved[1].name, "pii_scanner");
        assert!(resolved[1].config_overrides.is_some());
    }

    #[test]
    fn test_deduplication_preserves_order() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [a, b]
    pii:
      plugins: [b, c]
plugins:
  - name: a
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: b
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: c
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = plugins_for(&config, "tool", "get_compensation", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
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

    #[test]
    fn test_validation_skipped_when_routing_disabled() {
        let yaml = r#"
plugins:
  - name: test
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - meta:
      tags: [pii]
"#;
        let config = parse_config(yaml);
        config.unwrap();
    }

    // -- Scope matching tests --

    #[test]
    fn test_scope_match_selects_scoped_route() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: scoped_plugin
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: global_plugin
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    meta:
      scope: hr-services
    plugins:
      - scoped_plugin
  - tool: get_compensation
    plugins:
      - global_plugin
"#;
        let config = parse_config(yaml).unwrap();

        // With matching scope — scoped route wins (more specific)
        let resolved = plugins_for(
            &config,
            "tool",
            "get_compensation",
            Some("hr-services"),
            &no_tags(),
        );
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"scoped_plugin"));
        assert!(!names.contains(&"global_plugin"));

        // Without scope — global route matches
        let resolved = plugins_for(&config, "tool", "get_compensation", None, &no_tags());
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"global_plugin"));
        assert!(!names.contains(&"scoped_plugin"));

        // With different scope — global route matches (scoped doesn't)
        let resolved = plugins_for(
            &config,
            "tool",
            "get_compensation",
            Some("billing"),
            &no_tags(),
        );
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"global_plugin"));
        assert!(!names.contains(&"scoped_plugin"));
    }

    // -- Tag merging tests --

    #[test]
    fn test_host_tags_merged_with_route_tags() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    pii:
      plugins: [pii_plugin]
    runtime_tag:
      plugins: [runtime_plugin]
plugins:
  - name: pii_plugin
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: runtime_plugin
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
"#;
        let config = parse_config(yaml).unwrap();

        // Host provides a runtime tag that matches a policy group
        let mut host_tags = HashSet::new();
        host_tags.insert("runtime_tag".to_owned());

        let resolved = plugins_for(&config, "tool", "get_compensation", None, &host_tags);
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();

        // Both route's static tag (pii) and host's runtime tag activate their groups
        assert!(names.contains(&"pii_plugin"));
        assert!(names.contains(&"runtime_plugin"));
    }

    // -- When clause carried tests --

    #[test]
    fn test_when_clause_carried_on_resolved_plugins() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: conditional_plugin
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    when: "args.include_ssn == true"
    plugins:
      - conditional_plugin
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = plugins_for(&config, "tool", "get_compensation", None, &no_tags());
        assert_eq!(resolved[0].name, "conditional_plugin");
        assert_eq!(
            resolved[0].when.as_deref(),
            Some("args.include_ssn == true")
        );
    }

    #[test]
    fn test_when_clause_not_on_policy_group_plugins() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [global_plugin]
plugins:
  - name: global_plugin
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: route_plugin
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    when: "args.sensitive == true"
    plugins:
      - route_plugin
"#;
        let config = parse_config(yaml).unwrap();
        let resolved = plugins_for(&config, "tool", "get_compensation", None, &no_tags());

        // global_plugin has no when clause (from all group)
        let global = resolved.iter().find(|r| r.name == "global_plugin").unwrap();
        assert!(global.when.is_none());

        // route_plugin carries the route's when clause
        let route = resolved.iter().find(|r| r.name == "route_plugin").unwrap();
        assert_eq!(route.when.as_deref(), Some("args.sensitive == true"));
    }

    #[test]
    fn parse_route_identity_list_form() {
        let yaml = r#"
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
        let id = route.identity.as_ref().expect("identity present");
        assert!(!id.replace_inherited);
        assert_eq!(id.steps.len(), 2);
        assert_eq!(id.steps[0].name, "corp-jwt");
        assert!(id.steps[0].config_override.is_none());
        assert!(id.steps[0].on_error.is_none());
        assert_eq!(id.steps[1].name, "spiffe-attestor");
    }

    #[test]
    fn parse_route_identity_object_form_carries_replace_inherited() {
        let yaml = r#"
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
        let id = cfg.routes[0].identity.as_ref().unwrap();
        assert!(id.replace_inherited);
        assert_eq!(id.steps.len(), 1);
        assert_eq!(id.steps[0].name, "legacy-basic-auth");
    }

    #[test]
    fn parse_route_identity_map_step_with_on_error_and_config() {
        let yaml = r#"
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    authentication:
      - name: corp-jwt
        on_error: deny
        config:
          audience: my-tool
"#;
        let cfg = parse_config(yaml).unwrap();
        let id = cfg.routes[0].identity.as_ref().unwrap();
        let s0 = &id.steps[0];
        assert_eq!(s0.name, "corp-jwt");
        assert_eq!(s0.on_error.as_deref(), Some("deny"));
        let cfg_override = s0.config_override.as_ref().expect("config_override set");
        assert_eq!(
            cfg_override.get("audience").and_then(|v| v.as_str()),
            Some("my-tool"),
        );
    }

    #[test]
    fn parse_route_identity_mixed_bare_and_map_steps() {
        let yaml = r#"
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: spiffe-attestor, kind: builtin, hooks: [identity.resolve] }
routes:
  - tool: get_weather
    authentication:
      - name: corp-jwt
        on_error: deny
      - spiffe-attestor
"#;
        let cfg = parse_config(yaml).unwrap();
        let steps = &cfg.routes[0].identity.as_ref().unwrap().steps;
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].on_error.as_deref(), Some("deny"));
        assert!(steps[1].on_error.is_none());
    }

    #[test]
    fn parse_route_identity_object_form_without_steps_errors() {
        let yaml = r#"
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
    fn legacy_identity_key_is_rejected_at_route_and_global() {
        // The legacy `identity:` key must fail loudly, never be silently
        // dropped (which would skip authentication — a fail-open).
        for yaml in [
            "routes:\n  - tool: t\n    identity:\n      - corp-jwt\n",
            "global:\n  identity:\n    - corp-jwt\n",
            "global:\n  policies:\n    all:\n      identity:\n        - corp-jwt\n",
            "global:\n  defaults:\n    tool:\n      identity:\n        - corp-jwt\n",
        ] {
            let err = parse_config(yaml).expect_err("legacy identity: must be rejected");
            let msg = format!("{err}");
            assert!(
                msg.contains("identity") && msg.contains("authentication"),
                "rejection should name the rename: {msg}"
            );
        }
    }

    #[test]
    fn parse_route_identity_scalar_shape_errors() {
        let yaml = r#"
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
plugins:
  - { name: rate_limiter, kind: builtin, hooks: [cmf.tool_pre_invoke] }
routes:
  - tool: get_weather
    plugins:
      - rate_limiter
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "get_weather", None);
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolve_identity_preserves_declared_order() {
        let yaml = r#"
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
        // global.identity defined; route declares no identity. The
        // route should inherit the global steps unchanged.
        let yaml = r#"
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: workday-saml, kind: builtin, hooks: [identity.resolve] }
  - { name: agent-context, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
  policies:
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
plugin_settings:
  routing_enabled: true
plugins:
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: workday-saml, kind: builtin, hooks: [identity.resolve] }
  - { name: legacy-basic-auth, kind: builtin, hooks: [identity.resolve] }
global:
  authentication:
    - corp-jwt
  policies:
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
plugin_settings:
  routing_enabled: true
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

    #[test]
    fn resolve_identity_tag_bundle_only_when_route_carries_the_tag() {
        // The tag bundle's identity only contributes when the route
        // declares the matching tag — not for unrelated routes.
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - { name: workday-saml, kind: builtin, hooks: [identity.resolve] }
global:
  policies:
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
        // list forms both work.
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - { name: pii-scan, kind: builtin, hooks: [identity.resolve] }
global:
  policies:
    hr-tools:
      plugins:
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
        let no_runtime = HashSet::new();
        let names = |entity: &str| {
            plugins_for(&cfg, "tool", entity, None, &no_runtime)
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
plugin_settings:
  routing_enabled: true
plugins:
  - { name: workday-saml, kind: builtin, hooks: [identity.resolve] }
global:
  policies:
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
plugin_settings:
  routing_enabled: true
plugins:
  - { name: a, kind: builtin, hooks: [identity.resolve] }
  - { name: b, kind: builtin, hooks: [identity.resolve] }
global:
  policies:
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
    fn top_level_groups_section_is_the_canonical_bundle_location() {
        // Bundles can live at top-level `groups:` (canonical) instead of
        // `global.policies:` (deprecated); a route joins one the same way.
        let yaml = r#"
plugin_settings:
  routing_enabled: true
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
            "a bundle at top-level groups: resolves like one at global.policies:"
        );
    }

    #[test]
    fn top_level_groups_and_deprecated_global_policies_both_apply() {
        // Both locations coexist and contribute; neither shadows the other.
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - { name: a, kind: builtin, hooks: [identity.resolve] }
  - { name: b, kind: builtin, hooks: [identity.resolve] }
groups:
  new-loc:
    authentication: [a]
global:
  policies:
    old-loc:
      authentication: [b]
routes:
  - tool: mixed
    groups: [new-loc, old-loc]
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "mixed", None);
        let names: Vec<_> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"a"), "top-level groups applies: {names:?}");
        assert!(
            names.contains(&"b"),
            "deprecated global.policies applies: {names:?}"
        );
    }

    #[test]
    fn top_level_groups_wins_on_name_collision_with_global_policies() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - { name: canonical, kind: builtin, hooks: [identity.resolve] }
  - { name: deprecated, kind: builtin, hooks: [identity.resolve] }
groups:
  dup:
    authentication: [canonical]
global:
  policies:
    dup:
      authentication: [deprecated]
routes:
  - tool: t
    groups: dup
"#;
        let cfg = parse_config(yaml).unwrap();
        let resolved = identity_for(&cfg, "tool", "t", None);
        assert_eq!(
            resolved.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["canonical"],
            "canonical top-level groups: must win over deprecated global.policies:"
        );
    }

    #[test]
    fn stale_identity_key_under_top_level_groups_is_rejected() {
        // The fail-loud guard extends to the new location.
        let yaml = r#"
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
    fn defaults_and_policies_plugins_map_loads() {
        let cfg = deserialize_cfg(
            r#"
global:
  defaults:
    tool:
      plugins:
        audit:
          on_error: ignore
  policies:
    sensitive:
      plugins:
        pii_scanner:
          config:
            sensitivity: high
"#,
        )
        .expect("defaults/policies plugins map must deserialize");
        assert!(cfg.global.defaults["tool"].plugins.is_empty());
        assert!(cfg.global.policies["sensitive"].plugins.is_empty());
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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

    /// Routing off is the default, and it makes every `http:` route inert
    /// rather than merely incomplete. That is the line to fix, so it is the
    /// only one reported.
    #[test]
    fn http_routes_with_routing_disabled_are_reported_as_inert() {
        let cfg = parse_config(
            r#"
plugins: []
routes:
  - http: { path_prefix: /v1/files }
"#,
        )
        .expect("routing off still loads");
        let gaps = http_routing_gaps(&cfg);
        assert_eq!(gaps.len(), 1, "one gap, not two: {gaps:?}");
        assert!(gaps[0].contains("routing_enabled"), "{}", gaps[0]);
        assert!(
            !gaps[0].contains("path_prefix"),
            "the missing catch-all is not the problem to fix first: {}",
            gaps[0]
        );
    }

    /// A configuration that declares no `http:` route is what every deployment
    /// running today has, so the report has to stay silent for it, glob route
    /// included.
    #[test]
    fn a_config_with_no_http_route_reports_no_gap() {
        let cfg = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
        .expect("`global.defaults.http` must parse");

        assert!(cfg.global.defaults.contains_key("http"));
        let resolved = plugins_for(&cfg, "http", "*", None, &no_tags());
        assert_eq!(
            resolved.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["corp-jwt"],
            "an http default has to reach an http request"
        );
    }

    /// A misspelled entity type under `global.defaults` applies to nothing, so
    /// it fails at load rather than sitting there inert.
    #[test]
    fn a_global_default_for_an_unknown_entity_type_is_rejected() {
        let err = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
plugins: []
global:
  defaults:
    htp:
      plugins: []
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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

    /// The renamed-key check runs first, so a stale `identity:` block still
    /// gets the message that tells the operator what to rename it to.
    #[test]
    fn a_stale_identity_key_still_reports_the_rename() {
        let err = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
plugins: []
routes:
  - tool: get_weather
    identity:
      - corp-jwt
"#,
        )
        .expect_err("a renamed key must fail the load")
        .to_string();
        assert!(err.contains("renamed to `authentication`"), "{err}");
    }

    /// A stale `policy:` block is a rename, not a typo. The rename check runs
    /// before the unknown-key scan so the operator is told what to rename it
    /// to rather than sent looking for a misspelling.
    #[test]
    fn a_stale_policy_key_on_a_route_reports_the_rename() {
        let err = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
plugins: []
routes:
  - tool: get_weather
    policy:
      - "require(authenticated)"
"#,
        )
        .expect_err("a renamed key must fail the load")
        .to_string();
        assert!(
            err.contains("renamed to `authorization.pre_invocation"),
            "the rename, not a typo: {err}"
        );
        assert!(!err.contains("unknown key"), "{err}");
    }

    /// The post-phase half of the same rename. Dropping either block leaves
    /// no authorization enforced, so both fail the load.
    #[test]
    fn a_stale_post_policy_key_on_a_route_reports_the_rename() {
        let err = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
plugins: []
routes:
  - tool: get_weather
    post_policy:
      - "require(authenticated)"
"#,
        )
        .expect_err("a renamed key must fail the load")
        .to_string();
        assert!(
            err.contains("renamed to `authorization.post_invocation"),
            "{err}"
        );
    }

    /// The rename is the more specific diagnostic, so it wins even when the
    /// route also carries keys nothing reads.
    #[test]
    fn a_rename_outranks_the_unknown_keys_beside_it() {
        let err = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
plugins: []
routes:
  - tool: get_weather
    policy:
      - "require(authenticated)"
    htp: /v1/files
"#,
        )
        .expect_err("a renamed key must fail the load")
        .to_string();
        assert!(
            err.contains("renamed to `authorization.pre_invocation"),
            "{err}"
        );
    }

    /// Three bad keys used to take three loads to find. One load now names
    /// all of them.
    #[test]
    fn every_unknown_key_on_a_route_is_named_in_one_error() {
        let err = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
plugins: []
routes:
  - tool: get_weather
    apl:
      authorization:
        pre_invocation:
          - "require(authenticated)"
    response:
      status: 403
"#,
        )
        .expect("`apl:` and `response:` are route siblings, not typos");
    }

    /// The same orchestrator terms written flat on the route, with no `apl:`
    /// wrapper, plus the per-plugin override map form of `plugins:`.
    #[test]
    fn a_route_written_in_the_flat_orchestrator_form_loads() {
        parse_config(
            r#"
plugin_settings:
  routing_enabled: true
plugins: []
routes:
  - tool: get_weather
    pre_invocation:
      - "plugin(deny-gate)"
    post_invocation: []
    authorization:
      pre_invocation:
        - "require(authenticated)"
    args: {}
    result: {}
    pdp: []
    session_store:
      kind: memory
    plugins:
      deny-gate:
        on_error: ignore
"#,
        )
        .expect("the flat orchestrator form must keep loading");
    }

    #[test]
    fn an_empty_http_list_is_rejected() {
        let err = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
            "plugin_settings:\n  routing_enabled: true\nplugins: []\nroutes:\n  - http: \
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

    /// The engine reads the annotation table whether or not routing is enabled,
    /// so a route claiming the reserved name is refused either way.
    #[test]
    fn a_route_claiming_the_reserved_name_is_refused_with_routing_disabled() {
        let err = parse_config(&format!(
            "plugins: []\nroutes:\n  - http: \"{ENTITY_NAME_GLOBAL}\"\n"
        ))
        .expect_err("the reserved name is refused with routing off too")
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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
plugin_settings:
  routing_enabled: true
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

    /// Routes are only read when routing is enabled, and the selector follows
    /// that rule rather than inventing one of its own.
    #[test]
    fn an_http_route_with_routing_disabled_is_left_alone() {
        let cfg = parse_config(
            r#"
plugins: []
routes:
  - http: []
"#,
        )
        .expect("routes are inert while routing is disabled");
        assert!(cfg.routes[0].http.is_some());
    }

    // ---- no two routes resolve to one name --------------------------------

    /// Load a config written as just its `routes:` block and return the error
    /// text, so a duplicate case reads as the selectors it declares.
    fn duplicate_error(routes: &str) -> String {
        let yaml =
            format!("plugin_settings:\n  routing_enabled: true\nplugins: []\nroutes:\n{routes}");
        parse_config(&yaml)
            .expect_err("two routes resolving to one name must fail")
            .to_string()
    }

    /// Load a config written as just its `routes:` block, expecting success.
    fn routes_load(routes: &str) -> PolicyConfig {
        let yaml =
            format!("plugin_settings:\n  routing_enabled: true\nplugins: []\nroutes:\n{routes}");
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
        let yaml =
            format!("plugin_settings:\n  routing_enabled: true\nplugins: []\nroutes:\n{routes}");
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
        let yaml =
            format!("plugin_settings:\n  routing_enabled: true\nplugins: []\nroutes:\n{routes}");
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
    fn a_request_matching_no_http_route_resolves_nothing_and_still_gets_its_default() {
        let cfg = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
plugins:
  - { name: http-default, kind: builtin, hooks: [http.request] }
global:
  defaults:
    http:
      plugins: [http-default]
routes:
  - http: /healthz
"#,
        )
        .expect("the fixture must parse");

        let matched = resolve_route(&cfg, RouteQuery::http("/v1/files", Some("GET")));
        assert!(
            matched.is_none(),
            "no declared path covers /v1/files, so nothing resolves"
        );

        let resolved = resolve_plugins_for_entity(&cfg, ENTITY_HTTP, matched.as_ref(), &no_tags());
        assert_eq!(
            resolved.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["http-default"],
            "the entity type's default applies whether or not a route matched"
        );
    }

    /// An `http:` route stacks the same way every other route does: the `all`
    /// group, then the entity-type default, then its tag bundles, then its own
    /// plugins. Its `authentication:` list layers on top of the global one.
    #[test]
    fn an_http_route_layers_groups_defaults_and_authentication_like_any_other() {
        let cfg = parse_config(
            r#"
plugin_settings:
  routing_enabled: true
plugins:
  - { name: audit, kind: builtin, hooks: [http.request] }
  - { name: http-default, kind: builtin, hooks: [http.request] }
  - { name: pii-scan, kind: builtin, hooks: [http.request] }
  - { name: route-plugin, kind: builtin, hooks: [http.request] }
  - { name: corp-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: files-jwt, kind: builtin, hooks: [identity.resolve] }
  - { name: files-attestor, kind: builtin, hooks: [identity.resolve] }
global:
  authentication: [corp-jwt]
  policies:
    all:
      plugins: [audit]
    files:
      plugins: [pii-scan]
      authentication: [files-jwt]
  defaults:
    http:
      plugins: [http-default]
routes:
  - http: { path_prefix: /v1/files }
    groups: files
    plugins: [route-plugin]
    authentication: [files-attestor]
"#,
        )
        .expect("the fixture must parse");

        let matched = resolve_route(&cfg, RouteQuery::http("/v1/files/q3.pdf", Some("GET")))
            .expect("the prefix covers the request");

        let plugins = resolve_plugins_for_entity(&cfg, ENTITY_HTTP, Some(&matched), &no_tags());
        assert_eq!(
            plugins.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["audit", "http-default", "pii-scan", "route-plugin"],
            "the layering an entity route gets applies to an http route too"
        );

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

    /// The summed score still gives a `when:`-carrying route its bonus, so a
    /// broad glob with `when:` outranks a narrower glob without one. Adding the
    /// path scale must not have moved that.
    #[test]
    fn a_when_clause_still_outranks_a_narrower_glob() {
        let cfg = routed_config("  - tool: \"hr-*\"\n    when: \"true\"\n  - tool: \"hr-get-*\"\n");

        let matched = resolve_route(&cfg, RouteQuery::named(ENTITY_TOOL, "hr-get-comp"))
            .expect("both globs cover the tool");
        assert_eq!(
            matched.name, "hr-*",
            "a `when:` route still beats a narrower glob without one"
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
