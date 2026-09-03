// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// What a config gets when it says nothing about dispatch.
//
// `policy` is the default now. That is a fail-open on its own: a config that
// used to fire every declared plugin at every hook it declared now fires
// nothing until a step names it, and nothing about the config changed to say
// so. Two checks close it, and this file is where they are read.
//
// The first is per plugin, at load: a declared plugin no step reaches can
// never run, so the load fails naming it. The second is per request, at
// dispatch: a request the engine cannot identify resolves no route, and where
// it used to fall through to every registered entry it now denies, so a host
// cannot skip a policy by omitting metadata.
//
// Both are only worth anything if the exceptions hold, so the cases that must
// NOT trip either check are here beside them.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::sync::Arc;

use praxis_policy_apl_runtime::{AplOptions, register_apl};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

/// A plugin that registers no handler. Every case here is decided at load, so
/// what the plugin would do on a request is beside the point; what matters is
/// that the declaration resolves to a factory, since an unknown `kind:` fails
/// the load first and would mask the checks under test.
struct Inert(PluginConfig);

impl Plugin for Inert {
    fn config(&self) -> &PluginConfig {
        &self.0
    }
}

struct InertFactory;

impl PluginFactory for InertFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        Ok(PluginInstance {
            plugin: Arc::new(Inert(config.clone())),
            handlers: Vec::new(),
        })
    }
}

/// An engine with the `builtin` kind wired up, and nothing else.
fn engine() -> Arc<PolicyEngine> {
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory("builtin", Box::new(InertFactory));
    mgr
}

/// Load with the APL visitor registered, and return the error text.
fn load_err(yaml: &str) -> String {
    let mgr = engine();
    register_apl(&mgr, AplOptions::in_process());
    match mgr.load_config_yaml(yaml) {
        Ok(()) => panic!("this config must not load"),
        Err(e) => format!("{e}"),
    }
}

/// The same, for a config that has to survive the walk.
fn loads(yaml: &str) {
    let mgr = engine();
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(yaml).expect("this config must load");
}

// ---- the default -------------------------------------------------------

/// The flip itself. A route is a policy-mode key, so a document carrying one
/// and no `engine_settings:` is only loadable if the default is `policy`.
#[test]
fn a_config_that_says_nothing_gets_policy_dispatch() {
    loads(
        "
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
",
    );
}

// ---- reachability ------------------------------------------------------

/// The fail-open the default flip would otherwise open: plugins declared,
/// nothing naming them, and under the old default all of them fired.
#[test]
fn a_declared_plugin_no_step_reaches_fails_the_load() {
    let e = load_err(
        "
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
",
    );
    assert!(e.contains("audit-log"), "the message must name it: {e}");
    assert!(e.contains("run(name)"), "and say what fixes it: {e}");
}

/// Per plugin, not per config. A config naming one of three reaches
/// *something*, so a config-wide check would pass it while two sit inert.
#[test]
fn the_report_names_every_plugin_nothing_reaches() {
    let e = load_err(
        "
plugins:
  - name: reached
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: stranded-a
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
  - name: stranded-b
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - \"run(reached)\"
",
    );
    assert!(e.contains("stranded-a"), "{e}");
    assert!(e.contains("stranded-b"), "{e}");
    assert!(
        !e.contains("`reached`"),
        "the plugin a step names must not be reported: {e}"
    );
}

/// The reference set is wider than a policy step. An `authentication:` list
/// reaches its plugins on the identity hook, which no `run(name)` installs.
#[test]
fn a_plugin_reached_only_by_an_authentication_step_passes() {
    loads(
        "
plugins:
  - name: corp-jwt
    kind: builtin
    hooks: [identity.resolve]
routes:
  - tool: get_weather
    authentication:
      - corp-jwt
",
    );
}

/// The same at global scope, which every route inherits.
#[test]
fn a_plugin_reached_by_the_global_authentication_block_passes() {
    loads(
        "
plugins:
  - name: corp-jwt
    kind: builtin
    hooks: [identity.resolve]
global:
  authentication:
    - corp-jwt
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
",
    );
}

/// A step under `global.authorization:` stacks onto every entity route, which
/// is the chain-wide replacement for the activation list that used to exist.
#[test]
fn a_step_under_global_authorization_reaches_a_plugin() {
    loads(
        "
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
global:
  authorization:
    pre_invocation:
      - \"run(audit-log)\"
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
",
    );
}

/// The same step with no `routes:` under it at all. A `global:` policy governs
/// every request that resolves no route, so it reaches its plugins with nothing
/// to stack onto, and a tally that waited for a route would call this unreachable.
#[test]
fn a_global_step_reaches_a_plugin_with_no_routes_declared() {
    loads(
        "
plugins:
  - name: response-gate
    kind: builtin
    hooks: [http.response]
global:
  authorization:
    post_invocation:
      - \"run(response-gate)\"
",
    );
}

/// A bundle is not the exception `global:` is, and asserting that it was blessed
/// a fail-open. This declared a plugin, put `run(...)` in a group nothing joined,
/// and passed: the tally ran when the layer compiled, so any compiled layer
/// counted as executable. A group installs no handler and matches no request on
/// its own, so with no route carrying its name the step cannot run.
#[test]
fn an_orphan_bundle_reaches_nothing() {
    let e = load_err(
        "
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
groups:
  hr:
    authorization:
      pre_invocation:
        - \"run(audit-log)\"
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
",
    );
    assert!(e.contains("audit-log"), "the message must name it: {e}");
}

/// And the same group with one route joining it loads, in either membership
/// spelling. This is the other half: the tally now comes from the effective
/// route, so it has to see a layer the route actually inherits.
#[test]
fn a_bundle_a_route_joins_reaches_its_plugin() {
    for membership in ["    meta:\n      tags: [hr]\n", "    groups: hr\n"] {
        loads(&format!(
            "
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
groups:
  hr:
    authorization:
      pre_invocation:
        - \"run(audit-log)\"
routes:
  - tool: get_weather
{membership}"
        ));
    }
}

/// An entity default is the same shape as a bundle: it stacks, so a default for
/// an entity type no route declares reaches nothing.
#[test]
fn an_entity_default_with_no_route_of_that_type_reaches_nothing() {
    let e = load_err(
        "
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
global:
  defaults:
    prompt:
      authorization:
        pre_invocation:
          - \"run(audit-log)\"
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
",
    );
    assert!(e.contains("audit-log"), "the message must name it: {e}");
}

/// With a route of that entity type, the default is reachable.
#[test]
fn an_entity_default_reaches_its_plugin_through_a_route_of_that_type() {
    loads(
        "
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
global:
  defaults:
    tool:
      authorization:
        pre_invocation:
          - \"run(audit-log)\"
routes:
  - tool: get_weather
",
    );
}

/// Hook dispatch fires each plugin at the hooks its own `hooks:` names, so a
/// plugin no step reaches is that mode's normal shape rather than a fault. Without
/// this the reachability check would make `dispatch: hooks` unusable for any host
/// that registers an orchestrator.
#[test]
fn hook_dispatch_does_not_ask_what_reaches_a_plugin() {
    loads(
        "
engine_settings:
  dispatch: hooks
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
",
    );
}

/// A config declaring no plugins has nothing to strand, so the check has
/// nothing to say about it. Without this the cases above could be passing
/// because the check fires on any policy-mode config at all.
#[test]
fn a_config_declaring_no_plugins_loads() {
    loads(
        "
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
",
    );
}

/// Delegation and elicitation name a plugin the way a step does, so a plugin
/// reached only that way is reached. Without this the reference set could be
/// narrowed to `run(name)` and the check would strand a working config.
#[test]
fn a_plugin_reached_only_by_delegation_or_elicitation_passes() {
    for step in [
        "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])",
        "require_approval(workday-oauth, from: claim.manager, channel: 'ciba', \\
         purpose: 'Approve access')",
    ] {
        loads(&format!(
            "
plugins:
  - name: workday-oauth
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - \"{step}\"
"
        ));
    }
}

/// The same step above route scope, where the route's own block is not what
/// carries it to a plugin. A layer's tally used a reference set that omitted
/// delegation and elicitation, so each of these failed the load naming a plugin
/// the layer reaches.
///
/// The bundle case carries a route joining `hr`, because a bundle is not
/// executable on its own: a group nothing joins reaches nothing, which
/// `an_orphan_bundle_reaches_nothing` is about. `global:` needs no route, since
/// its catch-all handler governs every request that resolves none.
#[test]
fn a_plugin_reached_only_by_delegation_above_route_scope_passes() {
    for (section, indent, routes) in [
        (
            "global:\n  authorization:\n    pre_invocation:",
            "      ",
            "",
        ),
        (
            "groups:\n  hr:\n    authorization:\n      pre_invocation:",
            "        ",
            "routes:\n  - tool: get_compensation\n    groups: hr\n",
        ),
    ] {
        for step in [
            "delegate(workday-oauth, target: workday-api)",
            "require_approval(workday-oauth, from: claim.manager, channel: 'ciba')",
        ] {
            loads(&format!(
                "
plugins:
  - name: workday-oauth
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
{section}
{indent}- \"{step}\"
{routes}"
            ));
        }
    }
}

// ---- narrowing ---------------------------------------------------------

const NARROWED: &str = "plugin_narrowed_by_policy";

/// Collects the `alarm` field of every event raised while installed.
///
/// Hand-rolled on `tracing` rather than pulled from `tracing-subscriber`: one
/// field off one event is not worth a dependency tree, which is the same reason
/// the delegation-warning test states for its copy.
struct AlarmCollector {
    alarms: Arc<std::sync::Mutex<Vec<String>>>,
}

impl tracing::Subscriber for AlarmCollector {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = AlarmField(None);
        event.record(&mut visitor);
        if let Some(alarm) = visitor.0 {
            self.alarms.lock().unwrap().push(alarm);
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

struct AlarmField(Option<String>);

impl tracing::field::Visit for AlarmField {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "alarm" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "alarm" && self.0.is_none() {
            self.0 = Some(format!("{value:?}").trim_matches('"').to_owned());
        }
    }
}

/// Every alarm the load itself raises. Nothing is invoked, so an alarm here
/// came from the config walk.
fn alarms_raised_by_loading(yaml: &str) -> Vec<String> {
    let alarms = Arc::new(std::sync::Mutex::new(Vec::new()));
    let collector = AlarmCollector {
        alarms: Arc::clone(&alarms),
    };
    let mgr = engine();
    register_apl(&mgr, AplOptions::in_process());
    tracing::subscriber::with_default(collector, || {
        mgr.load_config_yaml(yaml).expect("this config must load");
    });
    alarms.lock().unwrap().clone()
}

/// A plugin declaring two hooks and reached on one loses coverage on the other.
/// Under hook dispatch it fired at both, so the load says what it gave up.
///
/// A warning rather than an error: narrowing can be exactly what an operator
/// meant, and `dispatch: hooks` is there for wanting the old behavior whole.
#[test]
fn a_plugin_reached_on_fewer_hooks_than_it_declares_is_reported() {
    let alarms = alarms_raised_by_loading(
        "
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke, cmf.tool_post_invoke]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - \"run(audit-log)\"
",
    );
    assert!(
        alarms.contains(&NARROWED.to_owned()),
        "a pre-invocation step covers one of the two hooks it declares, so the \
         post hook is uncovered and the load must say so: {alarms:?}"
    );
}

/// And it stays quiet when the policy covers everything declared, so the
/// warning above is not simply raised for every plugin.
#[test]
fn a_plugin_reached_on_every_hook_it_declares_is_silent() {
    let alarms = alarms_raised_by_loading(
        "
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke, cmf.tool_post_invoke]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - \"run(audit-log)\"
      post_invocation:
        - \"run(audit-log)\"
",
    );
    assert!(
        !alarms.contains(&NARROWED.to_owned()),
        "both declared hooks are covered, so there is nothing to report: \
         {alarms:?}"
    );
}

/// A `delegate(...)` step reaches its plugin on `token.delegate`.
#[test]
fn a_delegator_reached_by_a_delegate_step_is_not_reported_as_narrowed() {
    let alarms = alarms_raised_by_loading(
        "
plugins:
  - name: workday-oauth
    kind: builtin
    hooks: [token.delegate]
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - \"delegate(workday-oauth, target: workday-api, audience: workday-api)\"
",
    );
    assert!(
        !alarms.contains(&NARROWED.to_owned()),
        "`token.delegate` is covered: {alarms:?}"
    );
}

/// An elicitation verb reaches its handler on `elicit`.
#[test]
fn an_elicitation_handler_reached_by_a_verb_is_not_reported_as_narrowed() {
    let alarms = alarms_raised_by_loading(
        "
plugins:
  - name: manager-approver
    kind: builtin
    hooks: [elicit]
routes:
  - tool: adjust_compensation
    authorization:
      pre_invocation:
        - \"require_approval(manager-approver, from: claim.manager, channel: \\\"ciba\\\")\"
",
    );
    assert!(
        !alarms.contains(&NARROWED.to_owned()),
        "`elicit` is covered: {alarms:?}"
    );
}

/// Family-specific reachability does not hide other uncovered hooks.
#[test]
fn a_delegator_declaring_an_unreached_cmf_hook_is_still_reported() {
    let alarms = alarms_raised_by_loading(
        "
plugins:
  - name: workday-oauth
    kind: builtin
    hooks: [token.delegate, cmf.tool_post_invoke]
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - \"delegate(workday-oauth, target: workday-api, audience: workday-api)\"
",
    );
    assert!(
        alarms.contains(&NARROWED.to_owned()),
        "`cmf.tool_post_invoke` is declared and no step reaches it there: \
         {alarms:?}"
    );
}

// ---- the core-side backstop -------------------------------------------

/// A host that registers no orchestrator gets the flipped default with no
/// visitor to check it, so praxis-policy-core decides the one case it can see
/// without reading a policy step: plugins declared and no scope to name them
/// from. That is the shape both bundled examples had before they moved to
/// hook dispatch, so it is known to exist downstream.
#[test]
fn plugins_with_no_policy_scope_fail_without_any_visitor() {
    let e = engine()
        .load_config_yaml(
            "
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
",
        )
        .expect_err("no scope can name the plugin, so nothing can run it")
        .to_string();
    assert!(e.contains("audit-log"), "{e}");
    assert!(
        e.contains("dispatch: hooks"),
        "the message must name the mode that keeps today's behavior: {e}"
    );
}

/// `dispatch: hooks` is the escape, and it is what a config wanting the old
/// behavior wholesale writes.
#[test]
fn the_same_config_loads_under_hook_dispatch() {
    engine()
        .load_config_yaml(
            "
engine_settings:
  dispatch: hooks
plugins:
  - name: audit-log
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
",
        )
        .expect("hook dispatch fires it at the hooks it declares");
}

// ---- an APL term needs a visitor that can consume it --------------------

/// The other half of praxis-policy-core's refusal. Every APL term it rejects
/// with no visitor has to keep loading with one, or the check has cost more than
/// it closed.
///
/// The fault it closes: praxis-policy-core has no field for these bodies, so a
/// visitor-less load committed the typed config and returned success having
/// dropped them. A route declaring an unconditional `deny` loaded clean,
/// installed no handler, and enforced nothing.
#[test]
fn every_apl_term_still_loads_with_the_visitor_registered() {
    for yaml in [
        "
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - \"deny('always')\"
",
        "
routes:
  - tool: get_compensation
    result:
      ssn: redact
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
",
        "
global:
  authorization:
    pre_invocation:
      - \"require(authenticated)\"
",
        "
groups:
  hr:
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
routes:
  - tool: get_compensation
    groups: hr
",
    ] {
        let mgr = engine();
        register_apl(&mgr, AplOptions::in_process());
        mgr.load_config_yaml(yaml)
            .unwrap_or_else(|e| panic!("this config must load with a visitor: {e}\n{yaml}"));
    }
}

/// And the refusal itself, through the engine rather than the config function:
/// no visitor registered, so the term is dropped and nothing enforces it.
#[test]
fn an_apl_term_fails_the_load_with_no_visitor_registered() {
    let e = engine()
        .load_config_yaml(
            "
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - \"deny('always')\"
",
        )
        .expect_err("a policy nothing can compile must not load")
        .to_string();
    for needle in [
        "authorization",
        "routes[0]",
        "dispatch: hooks",
        "register_apl",
    ] {
        assert!(e.contains(needle), "the message must name `{needle}`: {e}");
    }
}
