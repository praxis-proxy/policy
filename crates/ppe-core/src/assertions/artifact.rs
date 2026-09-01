// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// What crosses the boundary, as one document.
//
// A contract spans four levels, so a per-level dump does not answer "what does
// this route assert". This renders the accumulated result per scope and names
// the level each header came from, which is the cost additive layering imposes
// on auditability and where it is paid.
//
// The excluded source set and the response floor print from the same constants
// the code matches on, so the artifact cannot say one thing while the engine
// enforces another.

use std::fmt::Write as _;

use super::config::AssertionsConfig;
use super::resolved::{ResolvedContract, ResolvedSource};
use super::{Direction, floor, source};
use crate::config::{
    MatchedRoute, PolicyConfig, RouteEntry, resolve_assertions_for_route, route_bundle_names,
    route_display_name, route_entity_identity,
};
use crate::extensions::Capability;

/// Render what the configuration asserts and removes, in both directions.
///
/// Written for an operator and a security reviewer rather than for a parser: it
/// covers every header that can be emitted with its source and the capability
/// that gates that slot, the removal set including the entry targets no `strip:`
/// entry names, the source exclusions and the response floor with the reason
/// each entry is there, the phase each direction fires on, which dispatch paths
/// are boundaries, and which traffic each level reaches.
#[must_use]
pub fn effective_policy(config: &PolicyConfig) -> String {
    let mut out = String::new();
    out.push_str("Assertions: what this configuration puts on the wire\n\n");

    if !declares_anything(config) {
        out.push_str(
            "Nothing is asserted and nothing is removed, in either direction: no level declares \
             an `assertions:` block.\n",
        );
        return out;
    }

    out.push_str(
        "Every value below is an unsigned statement. Whoever receives it believes it because they
believe the network path, not because they can verify anything.

",
    );
    render_directions(&mut out);
    render_boundaries(&mut out);
    render_exclusions(&mut out);
    render_floor(&mut out);
    render_levels(config, &mut out);
    render_contracts(config, &mut out);
    out
}

/// Whether any level declares a block.
fn declares_anything(config: &PolicyConfig) -> bool {
    declared_blocks(config).next().is_some()
}

/// Every declared block, with the level it sits at.
fn declared_blocks(config: &PolicyConfig) -> impl Iterator<Item = (String, &AssertionsConfig)> {
    let global = config
        .global
        .assertions
        .as_ref()
        .map(|block| ("global".to_owned(), block));
    let defaults = config
        .global
        .defaults
        .iter()
        .filter_map(|(entity, section)| {
            section
                .assertions
                .as_ref()
                .map(|block| (format!("global.defaults.{entity}"), block))
        });
    let bundles = config.global.bundles.iter().filter_map(|(name, section)| {
        section
            .assertions
            .as_ref()
            .map(|block| (format!("groups.{name}"), block))
    });
    let routes = config.routes.iter().enumerate().filter_map(|(i, route)| {
        route
            .assertions
            .as_ref()
            .map(|block| (route_display_name(route, i), block))
    });
    global
        .into_iter()
        .chain(defaults)
        .chain(bundles)
        .chain(routes)
}

/// Which phase each direction fires on, and why the two are not symmetric.
fn render_directions(out: &mut String) {
    out.push_str(
        "Directions, and the hook phase each fires on
  assertions.request   a pre-phase hook, toward the upstream. An allowlist: the engine
                       originates every value it asserts, so only what an entry names is
                       asserted at all.
  assertions.response  a post-phase hook, toward the client. A denylist over a floor fixed in
                       code: a response is the upstream's own output, which the engine cannot
                       enumerate, so a header nothing names reaches the client unchanged.
  A hook registered as neither pre nor post is not a wire boundary and applies neither.

",
    );
}

/// Which dispatch paths apply a contract.
fn render_boundaries(out: &mut String) {
    out.push_str(
        "Dispatch paths
  invoke_by_name, invoke, invoke_named  boundaries. Each applies the contract in force at
                                        every path that returns a result, the paths that
                                        return before the executor included.
  invoke_entries                        applies nothing. A nested dispatch primitive is not a
                                        wire boundary, and the contract belongs after policy
                                        evaluation rather than around each step of it. A host
                                        driving it as its outermost dispatch has no boundary,
                                        and so no contract.

",
    );
}

/// The sources fixed in code as never usable, with the reason each is refused.
fn render_exclusions(out: &mut String) {
    out.push_str(
        "Never usable as a source, in either direction, with no config surface to change it\n",
    );
    for (prefix, reason) in source::EXCLUDED_SOURCES {
        let _ = writeln!(out, "  {prefix:<24} {reason}");
    }
    out.push_str(
        "  The request line and the response status (http.method, http.path, http.host,
  http.scheme, http.status) are refused too, as paths outside the grammar rather than as
  credentials: they are host-populated, so admitting them later is a grammar addition.

",
    );
}

/// The headers no `strip:` entry can remove, one floor per direction.
fn render_floor(out: &mut String) {
    out.push_str("Protocol floors, fixed in code; no strip: entry can remove one\n");
    for (side, entries) in [
        ("request", floor::REQUEST_FLOOR),
        ("response", floor::RESPONSE_FLOOR),
    ] {
        let _ = writeln!(out, "  {side}");
        for entry in entries {
            let _ = writeln!(out, "    {:<32} {}", entry.name, entry.reason);
        }
    }
    out.push_str(
        "  authorization is deliberately NOT in the request floor: an upstream reached on a
  delegated credential should not also get the client's own bearer, so stripping it stays
  legal. set-cookie, server and x-powered-by are NOT in the response floor: removing
  those is a stated use case.

",
    );
}

/// Which traffic each declared level reaches.
fn render_levels(config: &PolicyConfig, out: &mut String) {
    out.push_str("Levels that declare a contract, and the traffic each reaches\n");
    if config.global.assertions.is_some() {
        out.push_str(
            "  global                     every request, and the only level that reaches one
                             resolving no route
",
        );
    }
    for (entity, section) in &config.global.defaults {
        if section.assertions.is_some() {
            let _ = writeln!(
                out,
                "  {:<26} every {entity} request, whether or not it also matches a route",
                format!("global.defaults.{entity}")
            );
        }
    }
    for (name, section) in &config.global.bundles {
        if section.assertions.is_none() {
            continue;
        }
        let joined: Vec<String> = config
            .routes
            .iter()
            .enumerate()
            .filter(|(_, route)| route_bundle_names(route).iter().any(|tag| tag == name))
            .map(|(i, route)| route_display_name(route, i))
            .collect();
        let reach = if joined.is_empty() {
            "no route joins it, so it reaches nothing".to_owned()
        } else {
            format!("the routes joining it: {}", joined.join(", "))
        };
        let _ = writeln!(out, "  {:<26} {reach}", format!("groups.{name}"));
    }
    for (i, route) in config.routes.iter().enumerate() {
        if route.assertions.is_some() {
            let _ = writeln!(
                out,
                "  {:<26} that route alone",
                route_display_name(route, i)
            );
        }
    }
    out.push('\n');
}

/// The accumulated contract per scope, with the level each header came from.
fn render_contracts(config: &PolicyConfig, out: &mut String) {
    out.push_str("Effective contract per scope, accumulated over every level that reaches it\n");
    render_scope(config, None, None, "a request matching no route", out);
    // An entity default covers an entity type rather than a route, so a request
    // of that type matching no route is a scope of its own.
    let mut entity_types: Vec<&str> = config.global.defaults.keys().map(String::as_str).collect();
    entity_types.sort_unstable();
    for entity_type in entity_types {
        if config
            .global
            .defaults
            .get(entity_type)
            .is_some_and(|section| section.assertions.is_some())
        {
            render_scope(
                config,
                None,
                Some(entity_type),
                &format!("{entity_type} requests matching no route"),
                out,
            );
        }
    }
    for (i, route) in config.routes.iter().enumerate() {
        let name = route_entity_identity(route)
            .and_then(|(_, names)| names.into_iter().next())
            .unwrap_or_default();
        let matched = MatchedRoute { route, name };
        let label = route_display_name(route, i);
        render_scope(config, Some(&matched), None, &label, out);
    }
}

/// One scope's two contracts.
fn render_scope(
    config: &PolicyConfig,
    matched: Option<&MatchedRoute<'_>>,
    request_entity_type: Option<&str>,
    label: &str,
    out: &mut String,
) {
    let _ = writeln!(out, "\n  {label}");
    let mut any = false;
    for direction in [Direction::Request, Direction::Response] {
        if let Some(contract) =
            resolve_assertions_for_route(config, matched, request_entity_type, direction)
        {
            any = true;
            render_contract(&contract, direction, out);
        }
    }
    if !any {
        out.push_str("    nothing is asserted and nothing is removed, in either direction\n");
    }
    render_replacements(config, matched.map(|m| m.route), out);
}

/// One direction's accumulated contract.
fn render_contract(contract: &ResolvedContract, direction: Direction, out: &mut String) {
    let _ = writeln!(out, "    {}", direction.label());
    if contract.headers.is_empty() {
        out.push_str("      asserts nothing\n");
    }
    for header in &contract.headers {
        let provenance = match &header.overrode {
            Some(previous) => format!("[{}, overriding {previous}]", header.declared_in),
            None => format!("[{}]", header.declared_in),
        };
        match &header.source {
            ResolvedSource::From(path) => {
                let _ = writeln!(
                    out,
                    "      {:<22}from {} ({}){} {provenance}",
                    header.name,
                    path.authored(),
                    capability_label(path.capability()),
                    encoding_note(header),
                );
            },
            ResolvedSource::Members(members) => {
                let _ = writeln!(out, "      {:<22}one JSON object {provenance}", header.name);
                for (member, path) in members {
                    let _ = writeln!(
                        out,
                        "        {member:<20}from {} ({})",
                        path.authored(),
                        capability_label(path.capability())
                    );
                }
            },
            ResolvedSource::Unresolvable => {
                let _ = writeln!(
                    out,
                    "      {:<22}source unreadable; the header is removed and never asserted \
                     {provenance}",
                    header.name
                );
            },
        }
    }
    out.push_str("      removed before injection\n");
    if contract.headers.is_empty() {
        out.push_str("        (no entry target)\n");
    } else {
        let targets: Vec<&str> = contract
            .headers
            .iter()
            .map(|header| header.name.as_str())
            .collect();
        let _ = writeln!(
            out,
            "        {} (targeted by an entry, so removed whether or not a value renders)",
            targets.join(", ")
        );
    }
    if contract.strip.is_empty() {
        out.push_str("        (no strip: entry)\n");
    } else {
        let patterns: Vec<&str> = contract
            .strip
            .iter()
            .map(super::config::StripPattern::as_str)
            .collect();
        let _ = writeln!(out, "        {} (strip:)", patterns.join(", "));
    }
}

/// What a `replace_inherited: true` above this route dropped, so the artifact
/// and the load-time finding tell one story.
fn render_replacements(config: &PolicyConfig, route: Option<&RouteEntry>, out: &mut String) {
    let Some(route) = route else { return };
    for direction in [Direction::Request, Direction::Response] {
        let own = route
            .assertions
            .as_ref()
            .and_then(|block| direction.block_of(block))
            .is_some_and(|block| block.replace_inherited);
        if own {
            let _ = writeln!(
                out,
                "    {} sets replace_inherited: true, so the levels above contribute nothing to \
                 it",
                direction.label()
            );
        }
    }
    for finding in crate::config::dropped_inherited_assertions_for(config, route, "") {
        let _ = writeln!(
            out,
            "    {} loses what it inherited to replace_inherited: true in {}: headers [{}], strip \
             [{}]",
            finding.direction,
            finding.declared_in,
            finding.dropped_headers.join(", "),
            finding.dropped_strip.join(", "),
        );
    }
}

/// A capability as its config spelling.
fn capability_label(capability: Capability) -> String {
    serde_json::to_string(&capability)
        .unwrap_or_default()
        .trim_matches('"')
        .to_owned()
}

/// How a value that is not a scalar renders, when the entry says.
fn encoding_note(header: &super::resolved::ResolvedHeader) -> String {
    let mut note = String::new();
    if let Some(encoding) = header.encode {
        let _ = write!(
            note,
            " encode: {}",
            serde_json::to_string(&encoding)
                .unwrap_or_default()
                .trim_matches('"')
        );
    }
    if header.on_missing == super::config::OnMissing::Deny {
        note.push_str(" on_missing: deny");
    }
    note
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::config::parse_config;

    const WORKED_EXAMPLE: &str =
        include_str!("../../tests/fixtures/assertions_worked_example.yaml");

    fn render(yaml: &str) -> String {
        effective_policy(&parse_config(yaml).expect("the config loads"))
    }

    #[test]
    fn the_artifact_names_every_configured_header_and_its_source() {
        let rendered = render(WORKED_EXAMPLE);
        for expected in [
            "x-auth-user-id",
            "subject.id",
            "x-auth-tenant-id",
            "claim.tenant",
            "x-auth-attributes",
            "namespaces",
            "claim.namespace",
            "x-auth-scope",
            "encode: csv",
            "on_missing: deny",
            "x-served-tenant",
            "x-served-by",
            "x-auth-path-scope",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected}:\n{rendered}"
            );
        }
    }

    /// The capability model stays the authority on what a slot is, so the
    /// artifact prints the capability beside the path.
    #[test]
    fn the_artifact_names_the_capability_gating_each_source() {
        let rendered = render(WORKED_EXAMPLE);
        for expected in ["read_subject", "read_claims", "read_roles"] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
    }

    /// An entry's target is removed whether or not `strip:` names it, which is
    /// the half of the removal an operator cannot read off the config.
    #[test]
    fn the_artifact_lists_entry_targets_as_removed() {
        let rendered = render(WORKED_EXAMPLE);
        assert!(rendered.contains("targeted by an entry"), "{rendered}");
        assert!(
            rendered.contains(
                "x-auth-user-id, x-auth-tenant-id, x-auth-attributes (targeted by an entry"
            ),
            "{rendered}"
        );
    }

    /// The same spellings a validation error uses, so the artifact and the error
    /// name one level one way.
    #[test]
    fn the_artifact_names_all_four_levels() {
        let rendered = render(WORKED_EXAMPLE);
        for level in [
            "global",
            "global.defaults.http",
            "groups.files-backend",
            "the route",
        ] {
            assert!(rendered.contains(level), "missing {level}:\n{rendered}");
        }
    }

    /// A route's contract spans four levels, so the artifact renders the merged
    /// result and says which level each header came from.
    #[test]
    fn the_artifact_renders_provenance_per_header_and_marks_an_override() {
        let rendered = render(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-shared
          from: subject.id
routes:
  - tool: get_weather
    assertions:
      request:
        headers:
          - name: x-shared
            from: claim.tenant
",
        );
        assert!(
            rendered.contains("[the route, overriding global]"),
            "{rendered}"
        );
    }

    #[test]
    fn the_artifact_names_which_dispatch_paths_are_boundaries() {
        let rendered = render(WORKED_EXAMPLE);
        assert!(
            rendered.contains("invoke_by_name, invoke, invoke_named"),
            "{rendered}"
        );
        assert!(rendered.contains("invoke_entries"), "{rendered}");
        assert!(
            rendered.contains("applies nothing"),
            "the artifact must say a nested dispatch primitive applies no contract:\n{rendered}"
        );
    }

    /// The artifact and the load-time finding tell one story about one route.
    #[test]
    fn the_artifact_renders_what_a_flag_above_a_route_dropped() {
        let yaml = "
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
  - tool: get_weather
    groups: hr
";
        let config = parse_config(yaml).expect("the config loads");
        let rendered = effective_policy(&config);
        assert!(
            rendered.contains("loses what it inherited to replace_inherited: true in groups.hr"),
            "{rendered}"
        );
        assert!(rendered.contains("headers [x-global]"), "{rendered}");
        assert!(rendered.contains("strip [x-legacy]"), "{rendered}");
        let findings = crate::config::dropped_inherited_assertions(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].declared_in, "groups.hr");
    }

    #[test]
    fn the_artifact_renders_a_routes_own_flag() {
        let rendered = render(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-global
          from: subject.id
routes:
  - tool: analytics
    assertions:
      request:
        replace_inherited: true
        headers:
          - name: x-route
            from: subject.id
",
        );
        assert!(
            rendered.contains("sets replace_inherited: true"),
            "{rendered}"
        );
    }

    /// The exclusions and the floor print from the constants the code matches
    /// on, so adding to either without touching the renderer cannot make the
    /// artifact disagree with what is enforced.
    #[test]
    fn the_artifact_prints_every_excluded_source_and_every_floor_header() {
        let rendered = render(WORKED_EXAMPLE);
        for (prefix, reason) in source::EXCLUDED_SOURCES {
            assert!(rendered.contains(prefix), "missing {prefix}");
            assert!(rendered.contains(reason), "missing the reason for {prefix}");
        }
        for entry in floor::REQUEST_FLOOR.iter().chain(floor::RESPONSE_FLOOR) {
            assert!(rendered.contains(entry.name), "missing {}", entry.name);
            assert!(
                rendered.contains(entry.reason),
                "missing the reason for {}",
                entry.name
            );
        }
        for outside in ["http.method", "http.path", "http.status"] {
            assert!(rendered.contains(outside), "missing {outside}");
        }
    }

    /// Not an empty string: an operator asking what crosses the boundary gets an
    /// answer rather than nothing.
    #[test]
    fn a_config_with_no_block_says_that_nothing_is_asserted() {
        let rendered = render("engine_settings:\n  dispatch: policy\n");
        assert!(rendered.contains("Nothing is asserted"), "{rendered}");
        assert!(!rendered.contains("assertions.request"), "{rendered}");
    }

    #[test]
    fn the_artifact_states_which_traffic_each_level_reaches() {
        let rendered = render(WORKED_EXAMPLE);
        assert!(
            rendered.contains("every http request, whether or not it also matches a route"),
            "{rendered}"
        );
        assert!(
            rendered.contains("the routes joining it: tool:files.*, resource:file://*"),
            "{rendered}"
        );
        assert!(
            rendered.contains("a request matching no route"),
            "{rendered}"
        );
        assert!(
            rendered.contains("http requests matching no route"),
            "an entity default covers a type rather than a route, so that is a scope \
             of its own: {rendered}"
        );
    }

    /// The entity default's scope renders its own contract, so an operator can
    /// read what a generic-HTTP request matching no route gets.
    #[test]
    fn the_artifact_renders_the_entity_default_scope() {
        let rendered = render(WORKED_EXAMPLE);
        let scope = rendered
            .split("http requests matching no route")
            .nth(1)
            .expect("the scope is rendered");
        let next = scope.split("\n  tool:").next().unwrap_or(scope);
        assert!(next.contains("x-served-by"), "{next}");
        assert!(next.contains("x-auth-user-id"), "{next}");
        assert!(
            !next.contains("x-auth-path-scope"),
            "and not the http: route's own header: {next}"
        );
    }
}
