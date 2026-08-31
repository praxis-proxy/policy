// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The shape of the config key model, pinned.
//!
//! One table per scope replaced three overlapping ones, and the tables are
//! indexed by role as well as by scope: the APL runtime builds a section's
//! synthetic policy block from the policy terms alone, so a wrong role marker
//! would send `response:` or `tool:` to the policy compiler. These assertions
//! pin the accept set and that constructive subset, so a later unit's change to
//! either one shows up as a failure here rather than as a config that loads
//! differently.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use praxis_policy_core::config::{
    ConfigScope, KeyOwner, KeyRole, global_wiring_keys, section_apl_block_keys,
};

fn names(scope: ConfigScope) -> Vec<&'static str> {
    scope.keys().map(|key| key.name).collect()
}

/// A key is described once per scope. A second entry would make the accept set
/// depend on which one a reader found first.
#[test]
fn each_scope_table_names_a_key_once() {
    for scope in ConfigScope::ALL {
        let mut seen: Vec<&str> = Vec::new();
        for name in names(scope) {
            assert!(
                !seen.contains(&name),
                "`{name}` is listed twice in the `{}` table",
                scope.label()
            );
            seen.push(name);
        }
    }
}

/// The scope list covers every table exactly once, so a walk over `ALL` is a
/// walk over the whole key model.
#[test]
fn the_scope_list_has_no_duplicates() {
    for (i, scope) in ConfigScope::ALL.iter().enumerate() {
        assert!(
            !ConfigScope::ALL.iter().take(i).any(|seen| seen == scope),
            "{scope:?} appears twice in ConfigScope::ALL"
        );
    }
}

/// The route accept set, in full. `apl:` is gone, and so are the engine wiring
/// keys: a PDP and the session store belong to `global:`.
#[test]
fn the_route_table_is_the_accept_set() {
    assert_eq!(
        names(ConfigScope::Route),
        vec![
            "tool",
            "resource",
            "prompt",
            "llm",
            "http",
            "meta",
            "groups",
            "plugins",
            "authentication",
            "assertions",
            "response",
            "authorization",
            "args",
            "result",
        ],
        "a route's accept set changed"
    );
}

/// The constructive set, in order: the policy terms plus the wiring keys the
/// APL visitor reads out of the block at `global:` scope. It is the union over
/// the section scopes, so it lists the field pipeline terms that `global:`
/// itself rejects.
#[test]
fn the_apl_block_set_is_the_constructive_set() {
    assert_eq!(
        section_apl_block_keys()
            .map(|key| key.name)
            .collect::<Vec<_>>(),
        vec![
            "authorization",
            "args",
            "result",
            "pdp",
            "session_store",
            "attribute_files",
        ],
        "the keys a section's policy block copies changed"
    );
}

/// `response:` sits beside the policy terms rather than among them: copying it
/// into the synthetic block would hand the policy compiler a key it does not
/// model. `plugins:` is excluded for its own reason, that only its mapping
/// shape belongs there.
#[test]
fn the_apl_block_set_excludes_the_keys_that_are_not_policy_terms() {
    let copied: Vec<&str> = section_apl_block_keys().map(|key| key.name).collect();
    for excluded in [
        "response",
        "plugins",
        "tool",
        "meta",
        "groups",
        "apl",
        "pre_invocation",
        "post_invocation",
    ] {
        assert!(
            !copied.contains(&excluded),
            "`{excluded}` must not reach the policy compiler in a section's block"
        );
    }
}

/// The engine wiring keys, in full. `global:` is the only scope that accepts
/// them, and this is the set stripped from a section's block before the policy
/// compiler runs.
#[test]
fn the_wiring_set_belongs_to_global_alone() {
    assert_eq!(
        global_wiring_keys().map(|key| key.name).collect::<Vec<_>>(),
        vec!["pdp", "session_store", "attribute_files"],
        "the engine wiring set changed"
    );
    for key in global_wiring_keys() {
        assert_eq!(
            key.role,
            KeyRole::EngineWiring,
            "`{}` is wiring, whatever scope spells it",
            key.name
        );
        assert!(
            names(ConfigScope::Global).contains(&key.name),
            "`{}` is a `global:` key",
            key.name
        );
        for scope in [
            ConfigScope::Document,
            ConfigScope::EntityDefault,
            ConfigScope::Group,
            ConfigScope::Route,
        ] {
            assert!(
                !names(scope).contains(&key.name),
                "`{}` must not be accepted at `{}`",
                key.name,
                scope.label()
            );
        }
    }
}

/// The wrapper is gone from every scope: a config writing one gets the
/// unknown-key error, not a silently dropped policy.
#[test]
fn no_scope_accepts_the_apl_wrapper() {
    for scope in ConfigScope::ALL {
        assert!(
            !names(scope).contains(&"apl"),
            "the `{}` table still accepts `apl:`",
            scope.label()
        );
    }
}

/// The removed keys are in no table at any scope, so the accept set is the whole
/// answer to whether one loads.
#[test]
fn no_scope_accepts_a_removed_key() {
    for removed in [
        "policy",
        "post_policy",
        "identity",
        "policies",
        "plugin_settings",
        "when",
        "plugin_dirs",
        "parallel_execution_within_band",
        "fail_on_plugin_error",
        "on_error",
    ] {
        for scope in ConfigScope::ALL {
            assert!(
                !names(scope).contains(&removed),
                "the `{}` table still accepts `{removed}:`",
                scope.label()
            );
        }
    }
}

/// Every section scope accepts `authorization:`, which is what lets the APL
/// runtime build a block without knowing which scope it is at. The document
/// scope accepts no policy term at all.
#[test]
fn every_section_scope_accepts_the_authorization_term() {
    for scope in [
        ConfigScope::Global,
        ConfigScope::EntityDefault,
        ConfigScope::Group,
        ConfigScope::Route,
    ] {
        assert!(
            names(scope).contains(&"authorization"),
            "`authorization` is missing from the `{}` table",
            scope.label()
        );
    }
    let document = names(ConfigScope::Document);
    for term in section_apl_block_keys().filter(|key| key.role != KeyRole::EngineWiring) {
        assert!(
            !document.contains(&term.name),
            "`{}` is a section key, not a document key",
            term.name
        );
    }
}

/// A field pipeline names one field of a payload, and `global:` covers every
/// entity route at once rather than reaching a payload of its own, so it is the
/// one section scope that takes neither block.
#[test]
fn global_accepts_no_field_pipeline() {
    let global = names(ConfigScope::Global);
    for field_stage in ["args", "result"] {
        assert!(
            !global.contains(&field_stage),
            "`{field_stage}` must not be accepted at `global:`"
        );
        for scope in [
            ConfigScope::EntityDefault,
            ConfigScope::Group,
            ConfigScope::Route,
        ] {
            assert!(
                names(scope).contains(&field_stage),
                "`{field_stage}` is missing from the `{}` table",
                scope.label()
            );
        }
    }
}

/// `global: { args: ... }` and `global: { result: ... }` each fail the load.
/// This was the only spelling for a field pipeline covering every entity route,
/// and it is removed rather than tightened.
#[test]
fn a_field_pipeline_at_global_scope_is_rejected() {
    for field_stage in ["args", "result"] {
        let err = praxis_policy_core::config::parse_config(&format!(
            "global:\n  {field_stage}:\n    ssn: \"str | redact(!perm.view_ssn)\"\n"
        ))
        .expect_err("a field pipeline at `global:` must fail the load")
        .to_string();
        assert!(
            err.contains(field_stage),
            "the error must name `{field_stage}`: {err}"
        );
    }
}

/// `authorization:` is the only place the two phase lists appear, at every
/// scope. A section still writing one flat gets the unknown-key error rather
/// than a policy block the parse drops on the floor.
#[test]
fn no_scope_accepts_a_phase_list_written_flat() {
    for phase in ["pre_invocation", "post_invocation"] {
        for scope in ConfigScope::ALL {
            assert!(
                !names(scope).contains(&phase),
                "the `{}` table still accepts a flat `{phase}:`",
                scope.label()
            );
        }
    }
    for (path, yaml) in [
        ("global", "global:\n  pre_invocation: []\n"),
        (
            "global.defaults.tool",
            "global:\n  defaults:\n    tool:\n      pre_invocation: []\n",
        ),
        ("groups.hr", "groups:\n  hr:\n    post_invocation: []\n"),
        (
            "routes[]",
            "routes:\n  - tool: get_weather\n    pre_invocation: []\n",
        ),
    ] {
        let err = praxis_policy_core::config::parse_config(yaml)
            .expect_err("a phase list written flat is no longer a key at any scope")
            .to_string();
        assert!(
            err.contains("invocation"),
            "the `{path}` error must name the key: {err}"
        );
    }
}

/// The ownership split on a route: praxis-policy-core reads its typed selector
/// and metadata fields, the APL runtime reads `response:` and every policy
/// term, and `plugins:` is read by both, one shape each.
#[test]
fn the_route_table_records_who_reads_each_key() {
    let owned_by = |owner: KeyOwner| -> Vec<&'static str> {
        ConfigScope::Route
            .keys()
            .filter(|key| key.owner == owner)
            .map(|key| key.name)
            .collect()
    };
    assert_eq!(
        owned_by(KeyOwner::Core),
        vec![
            "tool",
            "resource",
            "prompt",
            "llm",
            "http",
            "meta",
            "groups",
            "authentication",
            "assertions",
        ],
        "the route keys praxis-policy-core reads are its typed fields"
    );
    assert_eq!(
        owned_by(KeyOwner::Shared),
        vec!["plugins"],
        "`plugins:` is the only two-shape route key"
    );
    assert_eq!(
        owned_by(KeyOwner::Apl),
        vec!["response", "authorization", "args", "result"],
        "the rest of a route is the APL runtime's to read"
    );
}

/// `plugins:` is the one shape-conditional key, and it is the only one, at
/// every scope that accepts both of its shapes.
#[test]
fn plugins_is_the_only_shape_conditional_key() {
    for scope in ConfigScope::ALL {
        let conditional: Vec<&str> = scope
            .keys()
            .filter(|key| key.role == KeyRole::ShapeConditional)
            .map(|key| key.name)
            .collect();
        assert!(
            conditional.is_empty() || conditional == vec!["plugins"],
            "the `{}` table marks {conditional:?} shape-conditional",
            scope.label()
        );
    }
}

/// Every scope rejects a key nothing reads, the document included. Before this
/// each of them dropped one silently, so a misspelled policy term at global
/// scope left every route unguarded and said nothing.
#[test]
fn every_scope_rejects_a_misspelled_key() {
    for (scope, yaml, misspelled) in [
        ("(document)", "gobal:\n  authorization: {}\n", "gobal"),
        ("global", "global:\n  authorizaton: {}\n", "authorizaton"),
        (
            "global.defaults.tool",
            "global:\n  defaults:\n    tool:\n      authorizaton: {}\n",
            "authorizaton",
        ),
        (
            "groups.hr",
            "groups:\n  hr:\n    authorizaton: {}\n",
            "authorizaton",
        ),
        (
            "routes[]",
            "routes:\n  - tool: get_weather\n    authorizaton: {}\n",
            "authorizaton",
        ),
    ] {
        let err = praxis_policy_core::config::parse_config(yaml)
            .expect_err("a misspelled key must fail the load")
            .to_string();
        assert!(
            err.contains(misspelled),
            "the `{scope}` error must name `{misspelled}`: {err}"
        );
    }
}

/// A misspelled key gets the key set and nothing more. This is the contrast the
/// replacement hints depend on: a key that never worked has no replacement to
/// name, so naming one would be an invention.
#[test]
fn a_misspelled_key_is_offered_no_replacement() {
    let err = praxis_policy_core::config::parse_config("groups:\n  hr:\n    authorizaton: {}\n")
        .expect_err("a misspelled key must fail the load")
        .to_string();
    assert!(
        !err.contains("was replaced by"),
        "a typo has no replacement to name: {err}"
    );
}

/// The document's own key set, in full. A stale `plugin_settings:` used to load
/// clean with every engine setting dropped, `dispatch:` included, which left the
/// config in the default mode rather than the one it declared.
#[test]
fn the_document_table_is_the_accept_set() {
    assert_eq!(
        names(ConfigScope::Document),
        vec!["global", "plugins", "groups", "routes", "engine_settings"],
        "the document's accept set changed"
    );
}

/// A stale top-level `plugin_settings:` fails the load naming `engine_settings`
/// and the `dispatch:` spelling its boolean became.
#[test]
fn a_stale_plugin_settings_block_is_rejected_naming_its_replacement() {
    let err =
        praxis_policy_core::config::parse_config("plugin_settings:\n  routing_enabled: true\n")
            .expect_err("`plugin_settings:` is no longer a top-level key")
            .to_string();
    for expected in ["plugin_settings", "engine_settings", "dispatch: policy"] {
        assert!(
            err.contains(expected),
            "the error must name {expected}: {err}"
        );
    }
}

/// The removed keys, at every scope each was recognized, each naming both itself
/// and the spelling that replaced it. The closed key set is what makes them loud
/// again; the hint is what keeps them answerable.
#[test]
fn every_removed_key_is_rejected_naming_its_replacement() {
    for (yaml, removed, replacement) in [
        (
            "routes:\n  - tool: get_weather\n    policy:\n      - \"require(authenticated)\"\n",
            "policy",
            "authorization.pre_invocation",
        ),
        (
            "global:\n  policy:\n    - \"require(authenticated)\"\n",
            "policy",
            "authorization.pre_invocation",
        ),
        (
            "global:\n  defaults:\n    tool:\n      policy:\n        - \"require(authenticated)\"\n",
            "policy",
            "authorization.pre_invocation",
        ),
        (
            "groups:\n  hr:\n    policy:\n      - \"require(authenticated)\"\n",
            "policy",
            "authorization.pre_invocation",
        ),
        (
            "routes:\n  - tool: get_weather\n    post_policy:\n      - \"taint(forward)\"\n",
            "post_policy",
            "authorization.post_invocation",
        ),
        (
            "global:\n  post_policy:\n    - \"taint(forward)\"\n",
            "post_policy",
            "authorization.post_invocation",
        ),
        (
            "global:\n  defaults:\n    tool:\n      post_policy:\n        - \"taint(forward)\"\n",
            "post_policy",
            "authorization.post_invocation",
        ),
        (
            "groups:\n  hr:\n    post_policy:\n      - \"taint(forward)\"\n",
            "post_policy",
            "authorization.post_invocation",
        ),
        (
            "routes:\n  - tool: get_weather\n    identity:\n      - corp-jwt\n",
            "identity",
            "authentication",
        ),
        (
            "global:\n  identity:\n    - corp-jwt\n",
            "identity",
            "authentication",
        ),
        (
            "global:\n  defaults:\n    tool:\n      identity:\n        - corp-jwt\n",
            "identity",
            "authentication",
        ),
        (
            "groups:\n  hr:\n    identity:\n      - corp-jwt\n",
            "identity",
            "authentication",
        ),
        (
            "global:\n  policies:\n    hr:\n      plugins: [corp-jwt]\n",
            "policies",
            "groups:",
        ),
    ] {
        let err = praxis_policy_core::config::parse_config(yaml)
            .expect_err("a removed key must fail the load")
            .to_string();
        assert!(
            err.contains(removed) && err.contains(replacement),
            "the error must name `{removed}` and `{replacement}`: {err}"
        );
    }
}

/// A bundle written under top-level `groups:` resolves exactly as one written
/// under the removed nested location did: the same `authentication:` steps reach
/// the route that joins it.
#[test]
fn a_bundle_under_top_level_groups_resolves() {
    let config = praxis_policy_core::config::parse_config(
        "engine_settings:\n  dispatch: policy\nplugins:\n  - name: group-audit\n    kind: \
         builtin\n    hooks: [identity.resolve]\ngroups:\n  hr:\n    authentication: \
         [group-audit]\nroutes:\n  - tool: get_compensation\n    groups: hr\n",
    )
    .expect("a bundle at top-level `groups:` must load");
    let matched = praxis_policy_core::config::resolve_route(
        &config,
        praxis_policy_core::config::RouteQuery::named("tool", "get_compensation"),
    );
    let resolved =
        praxis_policy_core::config::resolve_identity_plugins_for_route(&config, matched.as_ref());
    assert!(
        resolved.iter().any(|p| p.name == "group-audit"),
        "the route must resolve the bundle's step: {:?}",
        resolved.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

/// The wrapper at each scope that used to accept it, now named as the unknown
/// key it is. Without this the removal would have converted a loud error into a
/// silently dropped policy block.
#[test]
fn the_apl_wrapper_is_rejected_at_every_scope_that_accepted_it() {
    for yaml in [
        "global:\n  apl:\n    authorization:\n      pre_invocation: []\n",
        "global:\n  defaults:\n    tool:\n      apl:\n        authorization:\n          pre_invocation: []\n",
        "groups:\n  hr:\n    apl:\n      authorization:\n        pre_invocation: []\n",
        "routes:\n  - tool: get_weather\n    apl:\n      authorization:\n        pre_invocation: []\n",
    ] {
        let err = praxis_policy_core::config::parse_config(yaml)
            .expect_err("`apl:` is no longer a key at any scope")
            .to_string();
        assert!(err.contains("apl"), "the error must name the key: {err}");
    }
}

/// The `engine_settings:` accept set, in full. The block dropped an unknown
/// field, so a setting the runtime never honored loaded clean and warned.
#[test]
fn the_engine_settings_table_is_the_accept_set() {
    assert_eq!(
        names(ConfigScope::EngineSettings),
        vec![
            "dispatch",
            "plugin_timeout",
            "short_circuit_on_deny",
            "route_cache_max_entries",
        ],
        "the engine settings accept set changed"
    );
}

/// One map-form `authentication:` step accepts two keys. It used to flatten
/// every other one into a forward-compat bag that nothing ever read.
#[test]
fn the_authentication_step_table_is_the_accept_set() {
    assert_eq!(
        names(ConfigScope::AuthenticationStep),
        vec!["name", "config"],
        "an authentication step's accept set changed"
    );
}

/// The object form of an `authentication:` block accepts two keys. It read both
/// and validated neither, so `replace_inherted: true` loaded with the flag
/// `false` and quietly changed which identity steps ran.
#[test]
fn the_authentication_table_is_the_accept_set() {
    assert_eq!(
        names(ConfigScope::Authentication),
        vec!["steps", "replace_inherited"],
        "an authentication block's accept set changed"
    );
}

/// The typo that motivated closing the set, at route scope and above it. Each
/// one changes the identity-layer result, and each used to load clean.
#[test]
fn a_misspelled_authentication_object_key_is_rejected() {
    for (path, yaml) in [
        (
            "routes[]",
            "routes:\n  - tool: get_weather\n    authentication:\n      replace_inherted:              true\n      steps: [jwt]\n",
        ),
        (
            "global",
            "global:\n  authentication:\n    replace_inherted: true\n    steps: [jwt]\n",
        ),
        (
            "groups.hr",
            "groups:\n  hr:\n    authentication:\n      replace_inherted: true\n      steps:              [jwt]\n",
        ),
    ] {
        let err = praxis_policy_core::config::parse_config(yaml)
            .expect_err("a misspelled authentication key must be rejected")
            .to_string();
        assert!(
            err.contains("replace_inherted"),
            "the error at {path} must name the key: {err}"
        );
        assert!(
            err.contains("replace_inherited"),
            "and the key it was meant to be, at {path}: {err}"
        );
    }
}

/// Both accepted shapes still load, and the flag still reads through.
#[test]
fn the_authentication_object_shapes_still_load() {
    let additive = praxis_policy_core::config::parse_config(
        "routes:\n  - tool: get_weather\n    authentication: [jwt]\n",
    )
    .expect("the list form is additive");
    let replacing = praxis_policy_core::config::parse_config(
        "routes:\n  - tool: get_weather\n    authentication:\n      replace_inherited:          true\n      steps: [jwt]\n",
    )
    .expect("the object form loads");
    for (label, cfg, expected) in [("list", additive, false), ("object", replacing, true)] {
        let identity = cfg.routes[0]
            .authentication
            .as_ref()
            .expect("both forms declare authentication");
        assert_eq!(
            identity.replace_inherited, expected,
            "{label} form's replace_inherited"
        );
    }
}

/// The five keys the runtime parsed and honored nowhere, each at the scope that
/// recognized it, each naming what to write instead. Four were no-ops the engine
/// warned about; `when:` was scored, so it changed which route won.
#[test]
fn every_inert_key_is_rejected_naming_its_replacement() {
    for (yaml, removed, replacement) in [
        (
            "engine_settings:\n  dispatch: policy\nroutes:\n  - tool: get_weather\n    when: \
             \"args.ssn == true\"\n",
            "when",
            "`do:` step",
        ),
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
        (
            "engine_settings:\n  dispatch: policy\nroutes:\n  - tool: get_weather\n    \
             authentication:\n      - name: corp-jwt\n        on_error: deny\n",
            "on_error",
            "plugins:",
        ),
    ] {
        let err = praxis_policy_core::config::parse_config(yaml)
            .expect_err("a key the runtime never honored must fail the load")
            .to_string();
        assert!(
            err.contains(removed) && err.contains(replacement),
            "the error must name `{removed}` and `{replacement}`: {err}"
        );
    }
}

/// A misspelled `engine_settings:` key and a misspelled step key both fail. The
/// step's is what the deleted catch-all swallowed: the step ran with the default
/// the key meant to change.
#[test]
fn the_two_new_scopes_reject_a_misspelled_key() {
    for (yaml, misspelled) in [
        ("engine_settings:\n  dispath: policy\n", "dispath"),
        (
            "engine_settings:\n  dispatch: policy\nroutes:\n  - tool: get_weather\n    \
             authentication:\n      - name: corp-jwt\n        confg: {}\n",
            "confg",
        ),
    ] {
        let err = praxis_policy_core::config::parse_config(yaml)
            .expect_err("a misspelled key must fail the load")
            .to_string();
        assert!(
            err.contains(misspelled),
            "the error must name `{misspelled}`: {err}"
        );
    }
}

/// The map form of a step still loads with the two keys it accepts.
#[test]
fn an_authentication_step_with_a_name_and_a_config_loads() {
    let config = praxis_policy_core::config::parse_config(
        "engine_settings:\n  dispatch: policy\nplugins:\n  - { name: corp-jwt, kind: builtin, \
         hooks: [identity.resolve] }\nroutes:\n  - tool: get_weather\n    authentication:\n      \
         - name: corp-jwt\n        config: { audience: my-tool }\n",
    )
    .expect("a step naming a plugin with a config override must load");
    let steps = &config.routes[0]
        .authentication
        .as_ref()
        .expect("the route declares authentication")
        .steps;
    assert_eq!(steps[0].name, "corp-jwt");
    assert!(
        steps[0].config_override.is_some(),
        "the step must carry its config override"
    );
}

/// `assertions:` sits beside `authentication:` at all four levels, so a
/// contract can be written at whichever scope owns it. Absent from one table
/// and the key would be rejected at that scope alone, which is the failure the
/// closed tables make loud.
#[test]
fn every_section_scope_accepts_the_assertions_block() {
    for scope in [
        ConfigScope::Global,
        ConfigScope::EntityDefault,
        ConfigScope::Group,
        ConfigScope::Route,
    ] {
        assert!(
            names(scope).contains(&"assertions"),
            "`assertions` is missing from the `{}` table",
            scope.label()
        );
    }
    for scope in [ConfigScope::Document, ConfigScope::EngineSettings] {
        assert!(
            !names(scope).contains(&"assertions"),
            "`assertions` must not be accepted at `{}`",
            scope.label()
        );
    }
}

/// The three nested `assertions:` scopes, in full. Each is only reachable
/// through the block's own deserializer, which is where its table is enforced.
#[test]
fn the_assertions_tables_are_the_accept_sets() {
    assert_eq!(
        names(ConfigScope::Assertions),
        vec!["request", "response"],
        "an assertions block's accept set changed"
    );
    assert_eq!(
        names(ConfigScope::AssertionsDirection),
        vec!["headers", "strip", "replace_inherited"],
        "an assertions direction's accept set changed"
    );
    assert_eq!(
        names(ConfigScope::AssertionHeader),
        vec!["name", "from", "members", "on_missing", "encode"],
        "an assertions header entry's accept set changed"
    );
}

/// praxis-policy-core reads every key of the block, so none of it travels into
/// a section's synthetic policy block.
#[test]
fn the_assertions_keys_belong_to_core() {
    for scope in [
        ConfigScope::Assertions,
        ConfigScope::AssertionsDirection,
        ConfigScope::AssertionHeader,
    ] {
        for key in scope.keys() {
            assert_eq!(
                key.owner,
                KeyOwner::Core,
                "`{}` at `{}` is praxis-policy-core's to read",
                key.name,
                scope.label()
            );
            assert_eq!(
                key.role,
                KeyRole::Structural,
                "`{}` is a typed field",
                key.name
            );
        }
    }
    assert!(
        !section_apl_block_keys().any(|key| key.name == "assertions"),
        "`assertions:` must not reach the policy compiler"
    );
}

/// A misspelled key at each of the three nested scopes. `replace_inherted` is
/// the one that motivated closing these sets: it would otherwise load with the
/// flag false and quietly stack the contract its author meant to drop.
#[test]
fn a_misspelled_assertions_key_is_rejected_at_every_nested_scope() {
    for (scope, yaml, misspelled) in [
        (
            "assertions",
            "global:\n  assertions:\n    requst:\n      headers: []\n",
            "requst",
        ),
        (
            "a direction",
            "global:\n  assertions:\n    request:\n      replace_inherted: true\n",
            "replace_inherted",
        ),
        (
            "a direction",
            "global:\n  assertions:\n    request:\n      strp: [x-a]\n",
            "strp",
        ),
        (
            "a header entry",
            "global:\n  assertions:\n    request:\n      headers:\n        - name: x-a\n          \
             form: subject.id\n",
            "form",
        ),
        (
            "a header entry",
            "global:\n  assertions:\n    request:\n      headers:\n        - name: x-a\n          \
             from: subject.id\n          on_mising: deny\n",
            "on_mising",
        ),
    ] {
        let err = praxis_policy_core::config::parse_config(yaml)
            .expect_err("a misspelled key must fail the load")
            .to_string();
        assert!(
            err.contains(misspelled),
            "the error at {scope} must name `{misspelled}`: {err}"
        );
    }
}

/// The block's own spelling, misspelled at each of the four levels. The typed
/// structs drop an unknown field, so without the tables a document declaring
/// `assertion:` would load having asserted nothing.
#[test]
fn a_misspelled_assertions_block_is_rejected_at_every_level() {
    for (path, yaml) in [
        ("global", "global:\n  assertion:\n    request: {}\n"),
        (
            "global.defaults.tool",
            "global:\n  defaults:\n    tool:\n      assertion:\n        request: {}\n",
        ),
        (
            "groups.hr",
            "groups:\n  hr:\n    assertion:\n      request: {}\n",
        ),
        (
            "routes[]",
            "routes:\n  - tool: get_weather\n    assertion:\n      request: {}\n",
        ),
    ] {
        let err = praxis_policy_core::config::parse_config(yaml)
            .expect_err("a misspelled block name must fail the load")
            .to_string();
        assert!(
            err.contains("assertion"),
            "the `{path}` error must name the key: {err}"
        );
    }
}
