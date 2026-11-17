// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `RouteDispatchPlan` + `DispatchCache` — pre-resolved per-route plugin
// lineup that lets APL bypass praxis-policy-core's hook-name + condition routing
// while still going through the executor's full 5-phase pipeline.
//
// # Why pre-resolve?
//
// APL routes are already authoritative lineups (the YAML's
// `routes.<r>.pre_invocation: [run(x), run(y)]` IS the plan). Re-resolving
// per call wastes work and lets praxis-policy-core's parallel routing model
// (entity-based conditions) override APL's intent.
//
// Building once per `(route_key, snapshot_generation)` and caching turns
// dispatch into: cache lookup → pick handler by invocation context →
// call `engine.invoke_entries::<CmfHook>(&[entry], ...)`.
//
// # Override materialization
//
// When APL declares a route-level `plugins.<name>:` block that narrows
// `capabilities` or changes `on_error`, the plan creates a derived
// `PluginRef` wrapping the same plugin `Arc<dyn Plugin>` with a merged
// `TrustedConfig`. Each derived
// PluginRef gets a fresh `AtomicBool` circuit breaker — failures in the
// override-context plugin don't disable the base, and vice versa.
//
// # Hook-context classification (v0)
//
// A plugin may register handlers for multiple hooks (e.g. both
// `cmf.tool_pre_invoke` for policy steps and `cmf.field_redact` for
// args/result pipelines). The plan picks one handler per invocation
// context (Step vs Field) by a naming heuristic — hook names containing
// `field`, `redact`, `scan`, or `validate` are treated as field
// handlers. When the heuristic stops being sufficient, the plugin
// declaration will gain an explicit `{step: ..., field: ...}` mapping
// form alongside the flat hook list.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use tokio::sync::OnceCell;

use praxis_policy_core::delegation::HOOK_TOKEN_DELEGATE;
use praxis_policy_core::elicitation::HOOK_ELICIT;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::hooks::{HookMetadata, HookPhase, lookup_hook_metadata};
use praxis_policy_core::metadata::HOOK_METADATA_FETCH;
use praxis_policy_core::plugin::OnError;
use praxis_policy_core::registry::HookEntry;

use praxis_policy_apl_core::constraint::{RestrictSpec, StringSetSpec};
use praxis_policy_apl_core::pipeline::{FieldRule, Stage};
use praxis_policy_apl_core::plugin_decl::{EffectivePlugin, PluginRegistry};
use praxis_policy_apl_core::rules::{CompiledRoute, Condition, Effect, Expression};
use praxis_policy_apl_core::step::PdpResolver;

/// Per-plugin pre-resolved entries for one route. Stores ALL hook
/// entries the plugin registered (keyed by hook name) so the
/// dispatcher can pick the right one for the current context via the
/// praxis-policy-core hook routing table (`hooks::metadata::lookup`).
///
/// Replaces the prior `step_entry` / `field_entry` slot model, which
/// used a brittle naming heuristic to classify hooks and silently
/// collapsed plugins with multiple step-context hooks (e.g. both
/// `cmf.tool_pre_invoke` and `cmf.tool_post_invoke`) to a single entry.
#[derive(Clone)]
pub struct RoutePluginEntry {
    /// The plugin this entry dispatches to.
    pub plugin_name: String,
    /// All hook entries the plugin registered, keyed by hook name.
    /// Per-call overrides (route-level config / caps / `on_error`) are
    /// already applied via `build_override_entries` before being
    /// stored here.
    pub entries_by_hook: HashMap<String, HookEntry>,
}

impl RoutePluginEntry {
    /// Pick the entry whose registered hook matches the current
    /// dispatch context. Walks `entries_by_hook`, consults the
    /// praxis-policy-core hook metadata table for each, returns the first
    /// matching entry.
    ///
    /// `requested_family` is the typed hook family carried by the current
    /// invoker. `requested_entity_type` comes from the request's
    /// `MetaExtension.entity_type` (or `None` if the dispatcher
    /// doesn't have one — in which case any hook's `entity_type`
    /// matches). `requested_phase` comes from the APL invocation
    /// context — `Pre` for `args:` / `pre_invocation:`, `Post` for
    /// `result:` / `post_invocation:`, `Unphased` for unphased
    /// dispatchers (rare in APL).
    ///
    /// Returns `None` when the plugin has no hook matching the
    /// context — caller surfaces this as `PluginError::Dispatch`
    /// with the requested context in the message.
    ///
    /// A hook with no metadata entry falls back to
    /// [`HookMetadata::permissive`], which matches any context, so a
    /// plugin registered under a name nobody described still dispatches.
    pub fn pick_entry(
        &self,
        requested_family: &str,
        requested_entity_type: Option<&str>,
        requested_phase: HookPhase,
    ) -> Option<&HookEntry> {
        self.entries_by_hook
            .iter()
            .find(|(hook_name, _)| {
                let metadata =
                    lookup_hook_metadata(hook_name).unwrap_or_else(HookMetadata::permissive);
                metadata
                    .family
                    .is_none_or(|family| family == requested_family)
                    && metadata.matches(requested_entity_type, requested_phase)
            })
            .map(|(_, entry)| entry)
    }
}

/// A route's resolved plugin lineup. One per `(route_key, generation)`
/// in the cache.
///
/// `plugins` holds entries for CMF-family dispatch (policy steps,
/// pipe-chain stages). `delegation_entries` holds entries for the
/// `token.delegate` hook used by `Step::Delegate` — kept separate
/// because the hook family is different and the dispatch is
/// per-call rather than per-route-chain.
#[derive(Clone, Default)]
pub struct RouteDispatchPlan {
    /// Per-plugin dispatch entries, keyed by plugin name.
    pub plugins: HashMap<String, RoutePluginEntry>,
    /// Plugin name → resolved `token.delegate` hook entry for routes
    /// that declared `delegate(...)` steps. Empty when the route has
    /// no delegation. Built at plan time to avoid per-request
    /// `find_plugin_entries` lookups in the hot path.
    pub delegation_entries: HashMap<String, HookEntry>,
    /// Plugin name → resolved `elicit` hook entry for routes that
    /// declared `require_approval(...)` / `confirm(...)` / … steps. Same
    /// `name → entry` shape as `delegation_entries` — elicitation routes
    /// by plugin name, not by `(kind, channel)`. Empty when the route has
    /// no elicitation.
    pub elicitation_entries: HashMap<String, HookEntry>,
    /// Metadata source name → resolved `metadata.fetch` entry.
    pub metadata_entries: HashMap<String, HookEntry>,
}

impl RouteDispatchPlan {
    /// Build a plan for the given route. Walks all steps + pipeline
    /// stages, collects the unique set of plugin names, resolves each
    /// against praxis-policy-core, and applies any APL route-level overrides.
    ///
    /// Plugins referenced by APL but absent from praxis-policy-core's registry
    /// (or absent from the APL `plugins:` block) are logged at `warn`
    /// and excluded — dispatch then fails with `PluginError::NotFound`
    /// when those plugins are invoked, which is the right behavior for
    /// surfacing config drift.
    pub async fn build(
        route: &CompiledRoute,
        registry: &PluginRegistry,
        engine: &PolicyEngine,
    ) -> Self {
        let mut plan = Self::default();
        let mut resolved_entries: HashMap<String, Vec<(String, HookEntry)>> = HashMap::new();
        for name in collect_plugin_names(route) {
            let Some(entries) =
                build_effective_plugin_entries(&name, route, registry, engine).await
            else {
                continue;
            };
            resolved_entries.insert(name.clone(), entries.clone());

            // Store every (hook_name, HookEntry) pair the plugin
            // registered. Dispatch-time entry selection (pick_entry)
            // consults praxis-policy-core's hook routing table per hook name.
            // Replaces the prior naming heuristic.
            let mut entries_by_hook: HashMap<String, HookEntry> = HashMap::new();
            for (hook_name, entry) in entries {
                entries_by_hook.insert(hook_name, entry);
            }

            plan.plugins.insert(
                name.clone(),
                RoutePluginEntry {
                    plugin_name: name,
                    entries_by_hook,
                },
            );
        }

        // Resolve token.delegate entries for any plugins the route
        // calls via `Step::Delegate`. These don't go through the
        // step/field classification — they're a separate hook family.
        // We still apply per-call config overrides via the existing
        // `build_override_entries` pathway, threading the step's
        // `config_override` as the only override surface (per-step
        // caps and on_error overrides aren't exposed on delegation
        // entries — the on_error lives in the IR step itself and is
        // honored by the evaluator).
        for name in collect_delegate_plugin_names(route) {
            let entries = engine.build_override_entries(&name, None, None, None).await;
            // Pick the first token.delegate entry. Per delegation-hooks
            // spec, plugins typically register one handler under the
            // single `token.delegate` hook name; multiple handlers
            // would be unusual.
            let delegate_entry = entries
                .into_iter()
                .find(|(hook_name, _)| hook_name == HOOK_TOKEN_DELEGATE);
            if let Some((_, entry)) = delegate_entry {
                plan.delegation_entries.insert(name, entry);
            } else {
                tracing::warn!(
                    plugin = %name,
                    route = %route.route_key,
                    "APL route references delegate plugin not registered under \
                     token.delegate hook — `delegate(...)` step will fail at dispatch",
                );
            }
        }

        // Resolve `elicit` entries for any plugins the route calls via an
        // elicitation verb (`require_approval(...)`, `confirm(...)`, …).
        // Same `name → entry` resolution as delegation — elicitation
        // routes by plugin name, not `(kind, channel)`.
        for name in collect_elicit_plugin_names(route) {
            let entries = engine.build_override_entries(&name, None, None, None).await;
            let elicit_entry = entries
                .into_iter()
                .find(|(hook_name, _)| hook_name == HOOK_ELICIT);
            if let Some((_, entry)) = elicit_entry {
                plan.elicitation_entries.insert(name, entry);
            } else {
                tracing::warn!(
                    plugin = %name,
                    route = %route.route_key,
                    "APL route references elicitation plugin not registered under \
                     elicit hook — `require_approval(...)`/`confirm(...)` step will \
                     fail at dispatch",
                );
            }
        }

        for name in collect_fetch_plugin_names(route) {
            let entries = if let Some(entries) = resolved_entries.remove(&name) {
                entries
            } else {
                let Some(entries) =
                    build_effective_plugin_entries(&name, route, registry, engine).await
                else {
                    continue;
                };
                entries
            };
            if let Some((_, entry)) = entries
                .into_iter()
                .find(|(hook_name, _)| hook_name == HOOK_METADATA_FETCH)
            {
                plan.metadata_entries.insert(name, entry);
            } else {
                tracing::warn!(
                    plugin = %name,
                    route = %route.route_key,
                    "APL route references metadata source not registered under metadata.fetch",
                );
            }
        }

        plan
    }

    /// Look up the resolved entries for a plugin by name. None when the
    /// plugin wasn't referenced by the route (or was skipped during
    /// build due to config drift).
    pub fn get(&self, plugin_name: &str) -> Option<&RoutePluginEntry> {
        self.plugins.get(plugin_name)
    }

    /// Resolve a single plugin's entries straight off praxis-policy-core, with
    /// no APL route-level overrides. Convenience for tests and for hosts
    /// that wire the invoker without a `CompiledRoute` in scope (e.g.
    /// adapters that invoke a single plugin imperatively). Returns
    /// `None` if praxis-policy-core has no entries for the plugin.
    pub fn resolve_plugin(engine: &PolicyEngine, plugin_name: &str) -> Option<RoutePluginEntry> {
        let base_entries = engine.find_plugin_entries(plugin_name);
        if base_entries.is_empty() {
            return None;
        }
        let mut entries_by_hook: HashMap<String, HookEntry> = HashMap::new();
        for (hook_name, entry) in base_entries {
            entries_by_hook.insert(hook_name, entry);
        }
        Some(RoutePluginEntry {
            plugin_name: plugin_name.to_owned(),
            entries_by_hook,
        })
    }
}

/// Resolve a route plugin and materialize its route-level overrides.
async fn build_effective_plugin_entries(
    name: &str,
    route: &CompiledRoute,
    registry: &PluginRegistry,
    engine: &PolicyEngine,
) -> Option<Vec<(String, HookEntry)>> {
    let Some(effective) = EffectivePlugin::resolve(name, registry, &route.plugin_overrides) else {
        tracing::warn!(
            plugin = %name,
            route = %route.route_key,
            "APL route references plugin not in `plugins:` block — skipping",
        );
        return None;
    };

    let override_block = route.plugin_overrides.get(name);
    let config_override = override_block.and_then(|override_| override_.config.as_ref());
    let capabilities_override: Option<HashSet<String>> = matches!(
        effective.capabilities,
        praxis_policy_apl_core::plugin_decl::CapsView::Override(_)
    )
    .then(|| effective.capabilities.as_slice().iter().cloned().collect());
    let on_error_override = override_block
        .and_then(|override_| override_.on_error.as_deref())
        .and_then(parse_on_error);

    let entries = engine
        .build_override_entries(
            name,
            config_override,
            capabilities_override.as_ref(),
            on_error_override,
        )
        .await;
    if entries.is_empty() {
        tracing::warn!(
            plugin = %name,
            route = %route.route_key,
            "APL plugin not resolvable (not registered, factory missing, \
             or override construction failed) — skipping",
        );
        return None;
    }

    Some(entries)
}

fn parse_on_error(s: &str) -> Option<OnError> {
    match s.to_ascii_lowercase().as_str() {
        "fail" => Some(OnError::Fail),
        "ignore" => Some(OnError::Ignore),
        "disable" => Some(OnError::Disable),
        _ => None,
    }
}

/// Recursively walk every effect node in an `Effect` tree, invoking
/// `visit` on each. Used by `collect_*_names` below to find Plugin /
/// Delegate references that may be nested inside `Effect::When`,
/// `Effect::Sequential`, `Effect::Parallel`, or `Effect::Pdp` reaction
/// lists. Previously these were flat — `Step::Plugin` lived directly under
/// policy: — so a simple `iter()` was enough; now the IR is tree-
/// shaped and the same scan needs recursion.
pub(crate) fn walk_effects<F: FnMut(&Effect)>(effects: &[Effect], visit: &mut F) {
    for e in effects {
        visit(e);
        match e {
            Effect::When { body, .. } => walk_effects(body, visit),
            Effect::Sequential(inner) | Effect::Parallel(inner) => walk_effects(inner, visit),
            Effect::Pdp {
                on_allow, on_deny, ..
            } => {
                walk_effects(on_allow, visit);
                walk_effects(on_deny, visit);
            },
            _ => {},
        }
    }
}

/// Walk a `CompiledRoute` and return the unique delegate-plugin names
/// referenced by any `Effect::Delegate` anywhere in `pre_invocation` /
/// `post_invocation` (including effects nested inside When / Sequential /
/// Parallel / Pdp reactions). Insertion-ordered for build determinism.
/// Separate from [`collect_plugin_names`] because delegate plugins
/// resolve under a different hook family (`token.delegate`) and the
/// dispatch plan keeps them in a separate map.
#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests assert on known-good values"
)]
mod identity_check_tests {
    use super::*;

    fn delegate_step(plugin: &str, subject: Option<&str>) -> Effect {
        let config_override = subject.map(|s| {
            let mut m = serde_yaml::Mapping::new();
            m.insert(
                serde_yaml::Value::String("subject".into()),
                serde_yaml::Value::String(s.into()),
            );
            serde_yaml::Value::Mapping(m)
        });
        Effect::Delegate(praxis_policy_apl_core::step::DelegateStep {
            plugin_name: plugin.to_owned(),
            config_override,
            on_error: None,
            source: "test".to_owned(),
        })
    }

    fn route_with(steps: Vec<Effect>) -> CompiledRoute {
        let mut route = CompiledRoute::new("tool:get_compensation");
        route.pre_invocation = steps;
        route
    }

    #[test]
    fn a_step_with_no_subject_defaults_to_user() {
        // The invoker defaults an unspecified subject to `user`, so an
        // unannotated step does exchange the caller's credential.
        let route = route_with(vec![delegate_step("oauth", None)]);
        assert_eq!(
            delegate_steps_exchanging_caller_credentials(&route),
            vec!["oauth".to_owned()]
        );
    }

    #[test]
    fn caller_credential_subjects_are_reported() {
        for subject in ["user", "client", "caller_workload"] {
            let route = route_with(vec![delegate_step("oauth", Some(subject))]);
            assert_eq!(
                delegate_steps_exchanging_caller_credentials(&route),
                vec!["oauth".to_owned()],
                "subject {subject} exchanges a credential the caller presented"
            );
        }
    }

    #[test]
    fn this_workload_is_not_reported() {
        // No inbound credential exists for this subject, so identity
        // resolution has nothing to say about it and warning would be
        // noise on a correct config.
        for subject in ["this_workload", "gateway"] {
            let route = route_with(vec![delegate_step("oauth", Some(subject))]);
            assert!(
                delegate_steps_exchanging_caller_credentials(&route).is_empty(),
                "subject {subject} carries no caller credential"
            );
        }
    }

    #[test]
    fn a_mixed_route_reports_only_the_steps_that_need_identity() {
        let route = route_with(vec![
            delegate_step("gateway-oauth", Some("this_workload")),
            delegate_step("user-oauth", Some("user")),
        ]);
        assert_eq!(
            delegate_steps_exchanging_caller_credentials(&route),
            vec!["user-oauth".to_owned()]
        );
    }

    #[test]
    fn a_route_with_no_delegation_reports_nothing() {
        assert!(delegate_steps_exchanging_caller_credentials(&route_with(Vec::new())).is_empty());
    }
}

/// Warn when a route exchanges a credential the caller presented but
/// resolves no identity for it.
///
/// A route that delegates the caller's own credential depends on
/// something having validated it first. Identity resolution is a
/// separate hook the host invokes at request entry, and it is per-route
/// configuration: `route.authentication` is optional, and a route with no
/// identity block resolves no identity plugins at all. Nothing then
/// rejects a token the `IdP` never signed before the delegator exchanges
/// it.
///
/// A warning rather than a hard error: the host, not this crate, decides
/// how identity is established, and a deployment may legitimately
/// validate upstream of PPE. But it is silent otherwise, and the failure
/// it precedes (a delegation minted against an unvalidated credential)
/// does not look like a configuration problem when it surfaces.
///
/// Called from the visitor's config walk rather than from
/// [`RouteDispatchPlan::build`], which runs on a route's first request:
/// a misconfigured route nobody has called yet is exactly the one an
/// operator wants told about, and at plan-build time the warning would
/// wait for the traffic it is meant to precede.
pub(crate) fn warn_if_delegating_without_identity(
    route: &CompiledRoute,
    entity_type: &str,
    entity_name: &str,
    scope: Option<&str>,
    engine: &PolicyEngine,
) {
    let unvalidated = delegate_steps_exchanging_caller_credentials(route);
    if unvalidated.is_empty()
        || engine.route_has_identity_resolution(entity_type, entity_name, scope)
    {
        return;
    }
    tracing::warn!(
        alarm = "delegation_without_identity_resolution",
        route = %route.route_key,
        plugins = ?unvalidated,
        "route delegates the caller's own credential but resolves no identity for it; \
         the token handed to the delegator has not been validated by this process, so \
         the IdP's rejection of a forged one is the only thing standing between an \
         unauthenticated caller and a token exchange. Add an `identity:` block to the \
         route (or globally), or use `subject: this_workload` if the delegation should \
         not carry the caller's credential at all.",
    );
}

/// Delegate steps on this route that exchange a credential the *caller*
/// presented, and therefore depend on something having validated it.
///
/// `subject: this_workload` is excluded: that delegation has no inbound
/// credential by design — the instance authenticates as itself with its
/// own client credentials — so identity resolution is irrelevant to it.
/// `user` is the default when a step names no subject, matching the
/// invoker.
fn delegate_steps_exchanging_caller_credentials(route: &CompiledRoute) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut visit = |e: &Effect| {
        let Effect::Delegate(ds) = e else {
            return;
        };
        let subject = ds
            .config_override
            .as_ref()
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|m| m.get(serde_yaml::Value::String("subject".into())))
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("user");
        // `gateway` is the deprecated spelling of `this_workload`.
        if matches!(subject, "this_workload" | "gateway") {
            return;
        }
        if seen.insert(ds.plugin_name.clone()) {
            out.push(ds.plugin_name.clone());
        }
    };
    walk_effects(&route.pre_invocation, &mut visit);
    walk_effects(&route.post_invocation, &mut visit);
    out
}

pub(crate) fn collect_delegate_plugin_names(route: &CompiledRoute) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut visit = |e: &Effect| {
        if let Effect::Delegate(ds) = e
            && seen.insert(ds.plugin_name.clone())
        {
            out.push(ds.plugin_name.clone());
        }
    };
    walk_effects(&route.pre_invocation, &mut visit);
    walk_effects(&route.post_invocation, &mut visit);
    out
}

/// Walk a `CompiledRoute` and return the unique elicitation-plugin names
/// referenced by any `Effect::Elicit` anywhere in `pre_invocation` /
/// `post_invocation` (including nested). Insertion-ordered for build
/// determinism. Separate from [`collect_plugin_names`] because
/// elicitation plugins resolve under the `elicit` hook family and the
/// plan keeps them in their own map.
pub(crate) fn collect_elicit_plugin_names(route: &CompiledRoute) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut visit = |e: &Effect| {
        if let Effect::Elicit(es) = e
            && seen.insert(es.plugin_name.clone())
        {
            out.push(es.plugin_name.clone());
        }
    };
    walk_effects(&route.pre_invocation, &mut visit);
    walk_effects(&route.post_invocation, &mut visit);
    out
}

/// Return unique metadata source names reached by `fetch(name)`.
pub(crate) fn collect_fetch_plugin_names(route: &CompiledRoute) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for name in route.fetch_names() {
        if seen.insert(name.clone()) {
            out.push(name);
        }
    }
    out
}

/// Return whether a compiled route reads acquired metadata.
///
/// Metadata can be consumed by a `fetch(...)` effect, a predicate at any
/// nesting depth, a PDP argument, or a conditional field-pipeline stage.
/// Keeping this analysis on the compiled route ensures inherited and nested
/// policy surfaces receive the same capability treatment.
pub(crate) fn route_uses_metadata(
    route: &CompiledRoute,
    request_half: bool,
    pdp: Option<&dyn PdpResolver>,
) -> bool {
    let mut uses_metadata = false;
    let mut visit = |effect: &Effect| {
        uses_metadata |= effect_uses_metadata(effect, request_half, pdp);
    };
    let (effects, field_rules) = if request_half {
        (&route.pre_invocation, &route.args)
    } else {
        (&route.post_invocation, &route.result)
    };
    walk_effects(effects, &mut visit);

    for field_rule in field_rules {
        uses_metadata |= stages_use_metadata(&field_rule.pipeline.stages);
    }

    uses_metadata
}

fn effect_uses_metadata(
    effect: &Effect,
    request_half: bool,
    pdp: Option<&dyn PdpResolver>,
) -> bool {
    match effect {
        Effect::Fetch(_) => true,
        Effect::When { condition, .. } => expression_uses_metadata(condition),
        Effect::Pdp { call, .. } => pdp.map_or_else(
            || call.references_metadata(),
            |resolver| resolver.requires_metadata(call),
        ),
        Effect::FieldOp { path, stages } => {
            field_op_runs_in_half(path, request_half) && stages_use_metadata(stages)
        },
        Effect::Restrict { spec } => restrict_uses_metadata(spec),
        _ => false,
    }
}

fn field_op_runs_in_half(path: &str, request_half: bool) -> bool {
    if request_half {
        path.starts_with("args.")
    } else {
        path.starts_with("result.")
    }
}

fn restrict_uses_metadata(spec: &RestrictSpec) -> bool {
    [
        spec.allow_models.as_ref(),
        spec.deny_models.as_ref(),
        spec.allow_regions.as_ref(),
        spec.allow_sites.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| match value {
        StringSetSpec::Ref(path) => attribute_path_uses_metadata(path),
        StringSetSpec::Literal(_) => false,
    })
}

fn stages_use_metadata(stages: &[Stage]) -> bool {
    stages.iter().any(|stage| match stage {
        Stage::Redact {
            condition: Some(condition),
        } => expression_uses_metadata(condition),
        _ => false,
    })
}

fn expression_uses_metadata(expression: &Expression) -> bool {
    match expression {
        Expression::Condition(condition) => match condition {
            Condition::Comparison { key, .. }
            | Condition::IsTrue { key }
            | Condition::IsFalse { key }
            | Condition::Exists { key } => attribute_path_uses_metadata(key),
            Condition::InSet {
                value_key, set_key, ..
            } => attribute_path_uses_metadata(value_key) || attribute_path_uses_metadata(set_key),
        },
        Expression::And(expressions) | Expression::Or(expressions) => {
            expressions.iter().any(expression_uses_metadata)
        },
        Expression::Not(expression) => expression_uses_metadata(expression),
        Expression::Always => false,
    }
}

fn attribute_path_uses_metadata(path: &str) -> bool {
    if path.starts_with("metadata.") {
        return true;
    }

    let mut rest = path;
    while let Some(open) = rest.find('[') {
        let Some(after_open) = rest.get(open + 1..) else {
            return false;
        };
        let Some(close) = after_open.find(']') else {
            return false;
        };
        let Some(inner) = after_open.get(..close) else {
            return false;
        };
        if attribute_path_uses_metadata(inner.trim()) {
            return true;
        }
        let Some(tail) = after_open.get(close + 1..) else {
            return false;
        };
        rest = tail;
    }
    false
}

/// Walk a `CompiledRoute` and return the unique plugin names referenced
/// by any `Effect::Plugin` anywhere in `pre_invocation` / `post_invocation` (including
/// nested) or `Stage::Plugin` (in `args` / `result` pipelines).
/// Insertion-ordered for build determinism.
pub(crate) fn collect_plugin_names(route: &CompiledRoute) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut visit = |e: &Effect| {
        if let Effect::Plugin { name } = e
            && seen.insert(name.clone())
        {
            out.push(name.clone());
        }
    };
    walk_effects(&route.pre_invocation, &mut visit);
    walk_effects(&route.post_invocation, &mut visit);
    for fr in route.args.iter().chain(route.result.iter()) {
        for stage in &fr.pipeline.stages {
            if let Stage::Plugin { name } = stage
                && seen.insert(name.clone())
            {
                out.push(name.clone());
            }
        }
    }
    out
}

/// The plugin names a `CompiledRoute` reaches, split by which half reaches
/// them: `(pre, post)`.
///
/// [`collect_plugin_names`] unions the two halves, which is what a dispatch
/// plan wants. The reachability report wants them apart, because a route's two
/// halves install under different hooks and a plugin reached on one is not
/// covered on the other. `args` pipelines run on the pre half and `result`
/// pipelines on the post half, so each stage joins the side it runs on.
///
/// Delegation and elicitation names join both sides: their effects carry a
/// plugin the route dispatches to the same way a step does.
pub(crate) fn collect_plugin_names_by_half(route: &CompiledRoute) -> (Vec<String>, Vec<String>) {
    fn names_in(effects: &[Effect]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut visit = |e: &Effect| {
            let name = match e {
                Effect::Plugin { name } => name,
                Effect::Delegate(ds) => &ds.plugin_name,
                Effect::Elicit(es) => &es.plugin_name,
                Effect::Fetch(step) => &step.plugin_name,
                _ => return,
            };
            if seen.insert(name.clone()) {
                out.push(name.clone());
            }
        };
        walk_effects(effects, &mut visit);
        out
    }

    fn stage_names(fields: &[FieldRule]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for fr in fields {
            for stage in &fr.pipeline.stages {
                if let Stage::Plugin { name } = stage
                    && !out.contains(name)
                {
                    out.push(name.clone());
                }
            }
        }
        out
    }

    fn extend_unique(into: &mut Vec<String>, names: Vec<String>) {
        for name in names {
            if !into.contains(&name) {
                into.push(name);
            }
        }
    }

    let mut pre = names_in(&route.pre_invocation);
    extend_unique(&mut pre, stage_names(&route.args));
    let mut post = names_in(&route.post_invocation);
    extend_unique(&mut post, stage_names(&route.result));
    (pre, post)
}

/// Return `(plugin, hook)` pairs for effects whose family fixes the hook.
///
/// Delegation uses `token.delegate`; elicitation uses `elicit`, independent of
/// the route's entity.
pub(crate) fn collect_family_fixed_plugin_hooks(
    route: &CompiledRoute,
) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let mut visit = |e: &Effect| {
        let pair = match e {
            Effect::Delegate(ds) => (ds.plugin_name.clone(), HOOK_TOKEN_DELEGATE),
            Effect::Elicit(es) => (es.plugin_name.clone(), HOOK_ELICIT),
            Effect::Fetch(step) => (step.plugin_name.clone(), HOOK_METADATA_FETCH),
            _ => return,
        };
        if !out.contains(&pair) {
            out.push(pair);
        }
    };
    walk_effects(&route.pre_invocation, &mut visit);
    walk_effects(&route.post_invocation, &mut visit);
    out
}

/// Compute the union of capabilities declared by every plugin a
/// `CompiledRoute` can dispatch to (with per-route overrides applied).
///
/// This is what the synthetic `AplRouteHandler`'s `PluginConfig.capabilities`
/// must be set to: praxis-policy-core's executor filters the `Extensions` view
/// before invoking every plugin (including the synthetic one), so if
/// the handler has fewer capabilities than its inner plugins need,
/// downstream views get doubly-filtered and label/delegation mutations
/// fail monotonicity checks on the way back out.
///
/// Plugins missing from the registry are silently skipped — the
/// dispatch plan will log a `warn!` and surface a `NotFound` at
/// invocation time, so config drift surfaces in the right place
/// rather than as a confusing capability gap.
pub(crate) fn route_capability_union(
    route: &CompiledRoute,
    registry: &PluginRegistry,
) -> std::collections::HashSet<String> {
    let mut caps: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Plugin steps (`run(name)` in policy / `plugin: name` in
    // args / result pipelines).
    for name in collect_plugin_names(route) {
        if let Some(eff) = EffectivePlugin::resolve(&name, registry, &route.plugin_overrides) {
            for cap in eff.capabilities.as_slice() {
                caps.insert(cap.clone());
            }
        }
    }
    // Delegate steps (`delegate(name, ...)`). Without this, a
    // delegator plugin that declares `capabilities:
    // [read_inbound_credentials, write_delegated_tokens]` in YAML
    // gets those stripped at the AplRouteHandler boundary — the
    // synthetic handler doesn't union its caps in, so the executor
    // filters out the inbound bearer before DelegationPluginInvoker
    // dispatches, and the delegator handler sees an empty token.
    // Hosts WANT to express per-plugin caps in YAML rather than
    // widening the AplRouteHandler's baseline (which would leak
    // those creds to every other step in the route).
    for name in collect_delegate_plugin_names(route) {
        if let Some(eff) = EffectivePlugin::resolve(&name, registry, &route.plugin_overrides) {
            for cap in eff.capabilities.as_slice() {
                caps.insert(cap.clone());
            }
        }
    }
    // Elicitation steps (`require_approval(name, ...)`, …) — same reason
    // as delegation: an elicitation handler that declares e.g.
    // `read_subject` (to read the approver identity) must not have it
    // stripped at the AplRouteHandler boundary.
    let elicit_plugins = collect_elicit_plugin_names(route);
    for name in &elicit_plugins {
        if let Some(eff) = EffectivePlugin::resolve(name, registry, &route.plugin_overrides) {
            for cap in eff.capabilities.as_slice() {
                caps.insert(cap.clone());
            }
        }
    }
    for name in collect_fetch_plugin_names(route) {
        if let Some(eff) = EffectivePlugin::resolve(&name, registry, &route.plugin_overrides) {
            for cap in eff.capabilities.as_slice() {
                caps.insert(cap.clone());
            }
        }
    }
    // A route with an elicitation step needs `read_headers` on the synthetic
    // handler so the `X-Policy-Elicitation-Id` retry header survives the
    // capability filter and reaches the bag for retry seeding. Without
    // it, the `http` extension is stripped before the handler reads it and
    // every retry re-dispatches a fresh elicitation instead of checking.
    if !elicit_plugins.is_empty() {
        caps.insert("read_headers".to_owned());
    }
    caps
}

/// Host-owned dispatch cache. Construct once, share via `Arc<DispatchCache>`
/// across all `CmfPluginInvoker::for_request` calls so plans built for
/// one request can be reused by the next.
///
/// Cache key is the APL `route_key`. Entries pair with the praxis-policy-core
/// snapshot generation observed at build time; a mismatch on lookup
/// triggers eviction and rebuild. v0 keys on `route_key` only —
/// entity-aware caching (`entity_type/entity_name` from `MetaExtension`)
/// is a follow-up when per-tenant lineup variation lands.
#[derive(Default)]
pub struct DispatchCache {
    inner: RwLock<HashMap<String, CachedDispatchPlan>>,
}

impl DispatchCache {
    /// An empty plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the shared plan for this route and configuration generation.
    /// Concurrent first requests share initialization, including any stateful
    /// plugin instances created for route configuration overrides.
    pub async fn get_or_build(
        &self,
        route: &CompiledRoute,
        registry: &PluginRegistry,
        engine: &PolicyEngine,
    ) -> Arc<RouteDispatchPlan> {
        let cell = self.plan_cell(&route.route_key, engine, engine.config_generation());
        Arc::clone(
            cell.get_or_init(|| async {
                Arc::new(RouteDispatchPlan::build(route, registry, engine).await)
            })
            .await,
        )
    }

    fn plan_cell(
        &self,
        route_key: &str,
        engine: &PolicyEngine,
        current_gen: u64,
    ) -> Arc<OnceCell<Arc<RouteDispatchPlan>>> {
        let cached = {
            let r = self
                .inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            r.get(route_key)
                .filter(|entry| entry.generation == current_gen)
                .map(|entry| Arc::clone(&entry.plan))
        };
        cached.unwrap_or_else(|| {
            let mut w = self
                .inner
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A request may have observed an older generation before another
            // request installed a newer cell. Never evict that newer state.
            let current_gen = engine.config_generation();
            let entry = w
                .entry(route_key.to_owned())
                .or_insert_with(|| CachedDispatchPlan {
                    generation: current_gen,
                    plan: Arc::new(OnceCell::new()),
                });
            if entry.generation != current_gen {
                *entry = CachedDispatchPlan {
                    generation: current_gen,
                    plan: Arc::new(OnceCell::new()),
                };
            }
            Arc::clone(&entry.plan)
        })
    }
}

struct CachedDispatchPlan {
    generation: u64,
    plan: Arc<OnceCell<Arc<RouteDispatchPlan>>>,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod cache_tests {
    use super::{CompiledRoute, DispatchCache, PluginRegistry, PolicyEngine, route_uses_metadata};
    use std::sync::Arc;

    use praxis_policy_apl_core::constraint::{OnEmpty, RestrictSpec, StringSetSpec};
    use praxis_policy_apl_core::pipeline::{FieldRule, Pipeline, Stage};
    use praxis_policy_apl_core::rules::{Condition, Effect, Expression};
    use praxis_policy_apl_core::step::{FetchStep, PdpCall, PdpDialect};

    #[tokio::test]
    async fn stale_generation_reuses_the_newer_initialized_plan() {
        let engine = PolicyEngine::default();
        let cache = DispatchCache::new();
        let route = CompiledRoute {
            route_key: "http:/toys".to_owned(),
            ..Default::default()
        };
        let registry = PluginRegistry::new();
        let stale_generation = engine.config_generation();

        engine.remove_route_annotation("http", "/toys", None, "http.request");
        assert!(engine.config_generation() > stale_generation);
        let installed = cache.get_or_build(&route, &registry, &engine).await;

        let resumed = cache.plan_cell(&route.route_key, &engine, stale_generation);
        assert!(
            resumed
                .get()
                .is_some_and(|plan| Arc::ptr_eq(plan, &installed)),
            "a stale request must reuse the installed plan and its plugin state"
        );
        let subsequent = cache.get_or_build(&route, &registry, &engine).await;
        assert!(
            Arc::ptr_eq(&installed, &subsequent),
            "the stale request must not evict the current generation's plan"
        );
    }

    #[test]
    fn route_metadata_usage_covers_fetch_nested_predicates_and_pdp_arguments() {
        let mut route = CompiledRoute::new("tool:test");
        assert!(
            !route_uses_metadata(&route, true, None),
            "a route without metadata use needs no grant"
        );

        route.pre_invocation.push(Effect::When {
            condition: Expression::And(vec![Expression::Condition(Condition::IsTrue {
                key: "subject.active".to_owned(),
            })]),
            body: vec![Effect::Sequential(vec![Effect::When {
                condition: Expression::Condition(Condition::Exists {
                    key: "metadata.account.active".to_owned(),
                }),
                body: vec![Effect::Allow],
                source: "nested".to_owned(),
            }])],
            source: "outer".to_owned(),
        });
        assert!(
            route_uses_metadata(&route, true, None),
            "nested metadata predicates need the grant"
        );

        let mut fetch_route = CompiledRoute::new("tool:fetch");
        fetch_route.pre_invocation.push(Effect::Fetch(FetchStep {
            plugin_name: "account".to_owned(),
            source: "fetch".to_owned(),
        }));
        assert!(
            route_uses_metadata(&fetch_route, true, None),
            "fetch effects need the grant"
        );

        let mut pdp_route = CompiledRoute::new("tool:pdp");
        pdp_route.pre_invocation.push(Effect::Pdp {
            call: PdpCall {
                dialect: PdpDialect::Opa,
                args: serde_yaml::Value::String("metadata.account.active".to_owned()),
            },
            on_allow: Vec::new(),
            on_deny: Vec::new(),
        });
        assert!(
            route_uses_metadata(&pdp_route, true, None),
            "PDP metadata arguments need the grant"
        );

        let mut pipeline_route = CompiledRoute::new("tool:pipeline");
        pipeline_route.args.push(FieldRule {
            field: "amount".to_owned(),
            pipeline: Pipeline {
                stages: vec![Stage::Redact {
                    condition: Some(Expression::Condition(Condition::IsFalse {
                        key: "metadata.account.redact".to_owned(),
                    })),
                }],
            },
            source: "pipeline".to_owned(),
        });
        assert!(
            route_uses_metadata(&pipeline_route, true, None),
            "conditional pipeline metadata references need the grant"
        );

        let mut field_op_route = CompiledRoute::new("tool:field-op");
        field_op_route.pre_invocation.push(Effect::When {
            condition: Expression::Always,
            body: vec![Effect::FieldOp {
                path: "args.account_status".to_owned(),
                stages: vec![Stage::Redact {
                    condition: Some(Expression::Condition(Condition::IsTrue {
                        key: "metadata.account.sensitive".to_owned(),
                    })),
                }],
            }],
            source: "field-op".to_owned(),
        });
        assert!(
            route_uses_metadata(&field_op_route, true, None),
            "conditional field operations need the grant"
        );

        let mut interpolated_route = CompiledRoute::new("tool:interpolated");
        interpolated_route.pre_invocation.push(Effect::When {
            condition: Expression::Condition(Condition::IsTrue {
                key: "data.tenants[metadata.account.id].blocked".to_owned(),
            }),
            body: vec![Effect::Deny {
                reason: None,
                code: None,
            }],
            source: "interpolated".to_owned(),
        });
        assert!(
            route_uses_metadata(&interpolated_route, true, None),
            "metadata used to interpolate an attribute path needs the grant"
        );

        let mut restrict_route = CompiledRoute::new("tool:restrict");
        restrict_route.pre_invocation.push(Effect::Restrict {
            spec: RestrictSpec {
                allow_regions: Some(StringSetSpec::Ref(
                    "metadata.account.allowed_regions".to_owned(),
                )),
                on_empty: OnEmpty::Fallback,
                ..RestrictSpec::default()
            },
        });
        assert!(
            route_uses_metadata(&restrict_route, true, None),
            "metadata-backed routing restrictions need the grant"
        );

        for (dialect, expression) in [
            (PdpDialect::Cel, "metadata.account.active == true"),
            (PdpDialect::Opa, "input.metadata.account.active == true"),
            (PdpDialect::Cedar, "context.metadata.account.active == true"),
        ] {
            let mut evaluator_route = CompiledRoute::new("tool:evaluator");
            evaluator_route.pre_invocation.push(Effect::Pdp {
                call: PdpCall {
                    dialect,
                    args: serde_yaml::Value::String(expression.to_owned()),
                },
                on_allow: Vec::new(),
                on_deny: Vec::new(),
            });
            assert!(
                route_uses_metadata(&evaluator_route, true, None),
                "documented evaluator metadata paths need the grant: {expression}"
            );
        }

        let mut literal_route = CompiledRoute::new("tool:literal");
        literal_route.pre_invocation.push(Effect::Pdp {
            call: PdpCall {
                dialect: PdpDialect::Opa,
                args: serde_yaml::Value::String("https://metadata.example".to_owned()),
            },
            on_allow: Vec::new(),
            on_deny: Vec::new(),
        });
        assert!(
            !route_uses_metadata(&literal_route, true, None),
            "literal strings must not grant metadata access"
        );
    }

    #[test]
    fn route_metadata_usage_is_scoped_to_the_active_phase() {
        let mut route = CompiledRoute::new("tool:response-metadata");
        route.post_invocation.push(Effect::When {
            condition: Expression::Condition(Condition::Exists {
                key: "metadata.account.active".to_owned(),
            }),
            body: vec![Effect::Allow],
            source: "response".to_owned(),
        });
        route.result.push(FieldRule {
            field: "status".to_owned(),
            pipeline: Pipeline {
                stages: vec![Stage::Redact {
                    condition: Some(Expression::Condition(Condition::IsTrue {
                        key: "metadata.account.sensitive".to_owned(),
                    })),
                }],
            },
            source: "response-pipeline".to_owned(),
        });

        assert!(
            !route_uses_metadata(&route, true, None),
            "response-only metadata use must not widen the request handler"
        );
        assert!(
            route_uses_metadata(&route, false, None),
            "the response handler must receive metadata used by its effects and pipeline"
        );

        let mut out_of_phase = CompiledRoute::new("tool:out-of-phase-field-op");
        out_of_phase.pre_invocation.push(Effect::FieldOp {
            path: "result.status".to_owned(),
            stages: vec![Stage::Redact {
                condition: Some(Expression::Condition(Condition::IsTrue {
                    key: "metadata.account.sensitive".to_owned(),
                })),
            }],
        });
        assert!(
            !route_uses_metadata(&out_of_phase, true, None),
            "a field operation skipped in this phase must not widen the handler"
        );
    }
}
