---
title: "feat: an HTTP request can match a route"
type: feat
status: completed
date: 2026-08-25
origin: docs/brainstorms/2026-08-25-http-route-selector-requirements.md
---

# feat: an HTTP request can match a route

## Summary

Give `RouteEntry` an `http:` selector that matches paths the way the host's own
router already does, resolve a generic HTTP request against it from the request
line, and key the route cache and the annotation table on the selector value that
matched rather than on the request path. Normalize the path before matching using
the host's rules, so PPE's view of a request agrees with the router that chose its
upstream.

The work is additive. The four MCP selectors are not touched: their scoring,
their dispatch, and the pre-existing gap where a glob route's policy body never
evaluates all stay exactly as they are. No existing configuration changes
behavior.

Two things underneath the selector carry the risk.

The annotation short-circuit is an exact-equality lookup on the entity name, and
APL installs annotations under the literal selector string. A path is never the
name a request arrives under, so an `http:` route would miss its own annotation
by construction. Making the resolved name and the annotation key come from one
function is what makes the selector work at all, and it is what keeps a request
path out of the cache key.

And an empty route resolution currently returns an allow. So the fail-closed rule
for a path that cannot be normalized cannot be expressed by resolving nothing; it
needs a denial the resolution path can actually produce.

---

## Implementation Guidelines

**1. No requirement or plan identifiers in durable text.** Nothing that ships may
cite `R6`, `U3`, `AE7`, or any identifier from this plan or its origin. That covers
rustdoc, comments, commit messages, the CHANGELOG entry, test names, and the PR
description. Describe the behavior:

```
no    // Per R6, key on the matched selector.
yes   // Keying on the matched pattern rather than the request path keeps
      // cache cardinality a function of the config, not of the traffic.
```

**2. Keep comments and rustdoc short.** One or two sentences per item. No em
dashes. No restating the signature in prose. Rationale earns its place where the
code looks wrong without it: in this work that is why the resolved name is not the
request name (U3), why normalization runs before matching but does not touch the
attribute bag (U4), and why an unresolvable path denies rather than falling through
(U6).

**3. Commits.** `git commit -s` on every commit. No AI attribution trailers.
Conventional style. The resolver signature change is breaking for the crate, so
that subject takes `!`; nothing here is breaking for an existing configuration.

**4. One derivation means one.** No unit may add a second place that maps a route
to the name it is known by, including in a test or in the APL visitor. A test that
needs the mapping calls the function.

**4b. Match the host, do not reinvent it.** Path matching and path normalization
here mirror `filter/src/path_match.rs` and
`filter/src/builtins/http/transformation/path_sanitize.rs` in the praxis tree.
PPE cannot depend on that crate, so the code is a deliberate reimplementation.
Any divergence from those semantics is a defect unless a unit states why.

**5. Normalization is not observable as an attribute.** No unit may write a
normalized path back into `HttpExtension` or into the attribute bag. A rule written
against `http.path` keeps its current meaning.

---

## Problem Frame

`RouteEntry` carries four selectors and `find_matching_route` dispatches on four
entity types, ending in `_ => continue`. `ENTITY_HTTP` lands on that arm, so an
HTTP request resolves no route: no route-level plugins, no group membership, no
static tags, no route-level `authentication:`. `validate_config` compounds it by
requiring exactly one of those same four, so a route declaring only `http:` fails
as "no entity matcher" after serde has already dropped the unknown key.

Path predicates do not close the gap. `http.method` and `http.path` are already
attributes, so a global policy can vary its decision by path. It cannot vary which
authentication plugins run, which authorization chain applies, or which assertion
contract is in force, because those attach to a route.

See origin for the full framing, including the two effects the issue names and why
groups cannot apply.

---

## Requirements

Restated from origin. Cited by unit below.

- R1. A route may select on generic HTTP requests with an `http:` key. A bare string or list selects exact paths; a map form selects a segment-boundary prefix with `path_prefix:`, an exact path with `path:`, and may narrow either by `method:`.
- R2. A route declares exactly one selector, and `http:` counts as one.
- R3. A route carrying an unrecognized selector key fails at load, naming the key.
- R4. The map form's `method:` participates in matching; an absent `method:` matches any method.
- R4b. A prefix matches only at a segment boundary: `/api` matches `/api`, `/api/`, `/api/v1`, not `/apikeys`. A trailing slash is insignificant. `path_prefix: "/"` is the catch-all.
- R5. HTTP route resolution matches against the request line, not against `meta.entity_name`.
- R6. The name a request resolves to, and which keys the route cache and the annotation lookup, is the selector value that matched: the matched element for a bare string or list, the declared prefix for a prefix selector, and for the map form a value including every matched field.
- R7. Two distinct routes never resolve to the same name within a scope; where they would, load fails naming both.
- R8. The name a route contributes and the name a request resolves to come from one function.
- R9. `meta.entity_name` and `http.path` reach the attribute bag unchanged.
- R10. An `http:` route reaches its compiled policy body, exact or prefix. The four MCP selectors keep today's dispatch behavior, gap included.
- R11. A list selector continues to dispatch per element.
- R12. An explicit catch-all `http:` route and the implicit global catch-all are distinct; the route wins by resolving, the implicit one applies only when nothing resolves.
- R12b. An `http:` route carrying a policy body dispatches it in place of the structural plugin chain, and that is documented rather than discovered.
- R13. An exact path beats a prefix; among prefixes the longer wins, regardless of declaration order. This is the host router's ordering.
- R14. Ordering is total without consulting declaration order. Equal-length prefixes that both match one path are the same prefix, so a tie can only come from duplicate selectors, which R7 rejects.
- R15. Scoping and `when:` order as they do today, and the four MCP selectors' scoring is untouched. An HTTP route's ordering is self-contained.
- R16. Matching runs on a path normalized the host's way: query and fragment removed, duplicate slashes collapsed, `.` and `..` resolved including percent-encoded spellings, a percent-encoded separator never decoded into a separator, semicolon path parameters stripped.
- R17. A path that cannot be normalized matches no `http:` route, and is denied when any `http:` route is declared.
- R18. Normalization does not rewrite what policy reads.
- R19. The selector matches only host-populated request identity a plugin cannot forge.
- R20. An `http:` route stacks global, entity-type default, group and tag bundles, then the route.
- R21. `global.defaults` accepts `http` as a key, documented rather than incidental.
- R22. When no `http:` route matches, resolution falls back to the reserved global name.
- R23. An `http:` route's `authentication:` applies when the host supplies the request line at the identity hook; otherwise the global list does, as today.
- R24. Both halves of one HTTP exchange resolve to the same route.
- R25. No attacker-controlled string becomes a route cache key.
- R26. Reject-on-full cache behavior and its default are unchanged.
- R27. A configuration with no `http:` route resolves exactly as today.
- R28. Declaring `http:` routes without a catch-all is reported at load.
- R28b. Which route a request resolved to is discoverable from what the engine emits; a path resolving to a prefix does not explain itself the way an entity name does.
- R28c. The selector requires routing to be enabled, stated wherever the selector is documented. The setting defaults off.
- R29. No existing configuration changes how it resolves or dispatches, and the four MCP selectors are untouched. A route carrying a key nothing consumes now fails at load, which is R3's point rather than a regression.
- R30. The engine's account of the global-plus-routes overlap and the host's startup warning agree.

---

## Context & Research

### Verified against the tree

| Concern | Location | Note |
|---|---|---|
| Selector fields | `config.rs:293-369` `RouteEntry` | four `Option<StringOrList>`, no rename or alias; `http` is a fifth field |
| No unknown-field rejection | `config.rs:293` | `RouteEntry` has no `deny_unknown_fields`, and **must not gain it**: `apl:` and `response:` sub-blocks ride alongside in the same mapping |
| Precedent for key rejection | `config.rs:665-705` `reject_renamed_identity_key` | raw-YAML scan before the typed parse, the pattern R3 follows |
| Exactly-one check | `config.rs:808-830` | count array over the four, two error strings naming them |
| Entity dispatch | `config.rs:1144-1150` | bare literals, `_ => continue`; `config.rs` imports nothing from `cmf::constants` |
| Specificity | `config.rs:880-903` | buckets 1000 / 500 / 300 / 0, summed with a `+100` scope bonus and `+10` for `when`. **Not modified by this work** |
| Host path matching | praxis `filter/src/path_match.rs` | `path_prefix_matches` is Gateway API segment-boundary; `path_prefix_specificity` is prefix length. Used by the router (`router/matching.rs:33`) and filter conditions (`condition/request.rs:79`) |
| Host normalizer | praxis `filter/src/builtins/http/transformation/path_sanitize.rs` | resolves `.`, `..`, and `%2e%2e` / `.%2e` / `%2e.`; collapses `//`; ensures a leading `/`; returns `Cow::Borrowed` when unchanged; splits on raw `/` only |
| Host never decodes a separator | praxis, whole tree | `percent-encoding` appears only in `url_rewrite` query keys and a health-admin helper. The request path is matched and forwarded as received |
| Host inbound path is unsanitized | praxis `upstream_request.rs:100` | `has_dot_dot_traversal` guards only a *rewritten* path; an inbound path is neither normalized nor rejected |
| Tie-break | `config.rs:1163` | `is_none_or(...)` on a summed score, strictly greater, so first declared wins |
| Glob matcher | `config.rs:527-570` `Pattern` | `wildmatch::WildMatch`, compiled at deserialize; `*` spans `/` |
| Lists are exact | `config.rs:595` | exact equality per element, no globbing inside a list |
| Tag desugaring | `config.rs:905-919` `route_static_tags` | takes `&RouteEntry`, so groups follow from a route matching at all |
| Defaults lookup | `config.rs:957` | plain map get by entity type, so `global.defaults.http` works once `http` is real |
| Resolver callers | `engine.rs:1570`, `:1577` | the only callers of either `pub` resolver, in-tree and in praxis |
| Annotation lookup | `engine.rs:1465-1501` | exact-equality map get on `AnnotationKey`, scoped then unscoped |
| Annotation install | `engine.rs:1400-1425` `annotate_route` | plain `insert`, so a collision replaces silently and returns nothing |
| Cache key | `engine.rs:112-138` `RouteCacheKey` | four fields, hand-written `Hash` / `PartialEq` over `&str` for allocation-free `raw_entry` lookups |
| Reject-on-full | `engine.rs:1607-1641` | skips memoization at capacity, warns once per fill cycle |
| Route-to-name mapping | `ppe-apl-runtime/src/visitor.rs:943-964` | `entity_identity` plus `names_of`, hardcoded literals, list expanded one annotation per element |
| Hook pair | `ppe-apl-runtime/src/visitor.rs:92-101` | already maps `ENTITY_HTTP` to both HTTP hooks |
| Global HTTP install | `ppe-apl-runtime/src/visitor.rs:528-601` | under `(ENTITY_HTTP, ENTITY_NAME_GLOBAL, None)`, per-half install gates |
| Visitor order | `engine.rs:693-757` | `visit_global` runs before `visit_route`, for every visitor, regardless of `routing_enabled` |
| Request line | `extensions/http.rs:29-48` | `method`, `path`, `host`, `scheme`; `path` doc leaves the query string to the host |
| Forge resistance | `extensions/container.rs:340-362` `merge_http` | request line preserved from canonical state, never taken from a plugin result |
| Attribute bag | `ppe-apl-cmf/src/http.rs:24-48`, `ppe-apl-cmf/src/meta.rs:17-32` | `http.path` and `meta.entity_name` copied verbatim |
| Denial shape | `executor.rs:160` `PipelineResult::denied`, `error.rs:215` `PluginViolation` | `code`, `reason`, `proto_error_code` for the host to map to a status |
| Selector table test | `engine.rs:4068-4140` | rows of `(entity_type, route field, route value, request name, should_match)`; needs HTTP rows |

### An empty resolution is an allow

All three invoke paths return `PipelineResult::allowed_with(...)` when
`filter_entries_by_route` yields no entries (`engine.rs:1132`, `:1207`, `:1286`,
each guarding the call above it). So "matched no route" fails open by
construction. R17 cannot be satisfied by resolving nothing; the resolution path has
to be able to produce a denial. This is the single most important structural fact
in this plan and drives D4.

### The host has already answered the path questions

The selector's semantics are not a free choice. The host matches paths with
segment-boundary prefixes and orders them by prefix length, and it normalizes with
a function that resolves encoded dot segments while leaving an encoded separator
inside its segment. Reusing PPE's `wildmatch` matcher and decoding before reading
segment structure would put PPE at odds with the router that picks the upstream
for the same request: PPE would resolve `/admin/x/..%2f..%2fv1%2fok` to `/v1/ok`
and apply a public policy while the host still routes to the `/admin` cluster.
Mirroring the host removes that whole class, and where a backend is more lenient
than both, PPE lands stricter rather than looser.

One consequence worth stating: the host's router does not resolve dot segments on
an inbound path, so it can route `/v1/files/../../admin` to the `/v1/files`
cluster while a backend resolves the path to `/admin`. That is a host-side gap
this work does not fix and should not paper over.

### Route resolution runs twice per miss today

The engine looks a route up twice on a cache miss: once by name for the annotation
short-circuit (`engine.rs:1473-1501`), then again inside the resolver, which calls
`find_matching_route` itself (`config.rs:962`, `:1040`). Resolving once and passing
the matched route down is a precondition for R6, since the resolved name is only
known after matching, and it removes the duplicate scan rather than adding one.

### Both resolvers are public and uncalled outside the engine

`resolve_plugins_for_entity` and `resolve_identity_plugins_for_route` are `pub` on
`ppe-core`. Grepped across `crates/`, `builtins/`, `reference/`, and the praxis
tree: the only *production* callers are the two engine lines above, so the
signature change in U3 is breaking for the crate and breaks no consumer.

It is not free, though. `config.rs`'s own test module calls the two roughly 33
times between them, and `test_exact_match_beats_glob` asserts specificity through
the resolver rather than against the scorer. U3 rewrites those call sites. That
matters for a second reason: those same tests are the regression that proves the
four MCP selectors are untouched, so the rewrite must be mechanical and must not
change a single expectation.

### No percent-decoding anywhere

Verified across `crates/` and `builtins/`: the only percent-decoding in the
tree is a test helper for OAuth form bodies. The workspace has no
`percent-encoding` or `url` dependency; `http` is present but `Uri::path()`
neither decodes nor resolves dot segments. U4 decides how to close that.

---

## Key Technical Decisions

**D1. `http:` gets its own selector type and its own matcher.** A path is not a
name: it matches by segment-boundary prefix, not by glob, so `http:` cannot reuse
`Pattern` the way the four name selectors do. Introduce `HttpSelector` as an
untagged enum whose scalar and sequence variants hold exact paths and whose map
variant carries `path:` or `path_prefix:` plus optional `method:`. This is the
one place PPE gains a second path dialect, and it exists to *remove* a dialect
mismatch with the host rather than to add one.

**D2. Unknown selector keys are caught by a raw-YAML scan, not by
`deny_unknown_fields`.** `RouteEntry` shares its mapping with `apl:` and
`response:` blocks that the typed struct deliberately ignores, so
`deny_unknown_fields` would reject every APL-annotated route in the tree.
`reject_renamed_identity_key` already scans raw YAML per route for exactly this
class of problem; extend that pass with an allow-list of route keys. The
alternative, enumerating the ignored blocks in the typed struct, couples
`ppe-core` to each orchestrator's YAML.

The allow-list is larger than `apl:` and `response:`. The APL visitor also accepts
its terms written flat on the route mapping: `FLAT_APL_KEYS` in
`ppe-apl-runtime/src/visitor.rs` names `pre_invocation`, `post_invocation`,
`authorization`, `args`, `result`, `pdp`, and `session_store`, and `apl_subblock`
additionally accepts `plugins` when it is a mapping. Two existing tests in
`visitor_e2e.rs` load routes in exactly that shape, so an allow-list built from
D2's description alone would break them. U1 enumerates the full set.

That leaves a real design question this plan must answer rather than discover:
`register_visitor` is a public extension point and the walk hands each visitor the
raw route YAML, so a host shipping its own Rego or Cedar visitor can read a route
key `ppe-core` has never heard of. A closed list turns that into a load failure,
which is the coupling D2 rejects its alternative for. **Decision:** `ConfigVisitor`
gains a method reporting the extra route keys its visitor consumes, defaulting to
empty, and the scan unions those with `ppe-core`'s own list before rejecting a key.
That keeps the extension point open and keeps the typo check useful.

**D3. The existing scorer is not touched; HTTP scores in its own arm.** An earlier
draft replaced the summed `usize` with an ordered key so a literal-character count
could break glob ties. That was only needed because paths were going to be globs,
and it carried a real hazard: the summed score gives a `when:`-carrying route
`+10`, so `hr-*` with `when:` beats `hr-get-*` today, and any reordering that put
length above `when` would silently flip resolution for configurations nobody
edited. With paths matching as prefixes the whole problem disappears. `http:`
contributes an exact-or-prefix score with prefix length as the discriminator,
computed in its own arm of `score_entity_match`, and the four MCP selectors keep
the arithmetic and the outcomes they have today. Nothing needs an equivalence
proof because nothing shared changes.

**D4. Route resolution becomes fallible, and the invoke paths map the failure
to a denial.** R17 needs a deny where the code currently has an allow. Change
`filter_entries_by_route` to return
`Result<Arc<Vec<HookEntry>>, RouteResolutionError>` and have the three invoke
paths turn the error into `PipelineResult::denied` with a violation code the host
can map, `proto_error_code: Some(400)`. The rejected alternative was a synthetic
deny plugin injected into the entry list, which would run inside the executor and
so be subject to `on_error` handling and capability filtering, neither of which
should apply to a request whose path could not be read.

**D5. Normalization is a deliberate reimplementation of the host's, with no new
dependency.** The rules come from `path_sanitize.rs`, not from a general URL
crate: resolve `.`, `..`, and their percent-encoded spellings; collapse duplicate
slashes; never treat a percent-encoded separator as a separator. Because nothing
is decoded, no percent-decoding library is needed and the charset question never
arises. PPE cannot depend on the praxis crate (the dependency runs the other
way), so the code is duplicated on purpose, with the source named at the module
head so the two can be compared when either moves.

**D6. The resolved name for the map form is rendered, and the renderer is the same
function the visitor uses.** The name must include every matched field, so the map
form renders as its method set and its path pattern. Because one function produces
both the route's contributed name and the request's resolved name (R8), the
rendering cannot drift; a test asserts a round trip rather than a literal format,
so the exact spelling stays an implementation detail.

**D7. The catch-all no longer collides, and `annotate_route` still reports a
replacement.** The collision only existed because an explicit `http: "*"` route
derived the reserved name `"*"`, the same key the implicit global catch-all is
installed under. A root prefix does not derive `"*"`, so the two now occupy
different keys: the route wins by being resolved, and the implicit catch-all
applies only when resolution finds nothing. The reporting half is still worth
having on its own merit, because `annotate_route` currently overwrites silently
from any source, so it returns whether it replaced an entry and the visitor says
so. That is a small diagnostic improvement rather than the load-bearing fix it
was.

**D8. A specificity tie cannot arise, so nothing reports one.** An earlier draft
deviated from the origin here, resolving a residual tie deterministically at
runtime with a warning because proving glob intersection at load is expensive.
Prefixes make the question vacuous: two prefixes of equal length that both match
one path are the same prefix. So the only way two routes tie is by declaring the
same selector, which the load-time duplicate check already rejects. The origin's
requirement is met literally, and the deviation that needed sign-off is gone.

**D9. The duplicate check compares resolved names, not selector values.** R7 is a
property of the name two routes resolve to, and checking the written selector
instead misses the collisions that matter: `http: ["/a", "/b"]` and
`http: ["/b", "/c"]` are different selector values that both contribute `/b`, so
one route's annotation would silently replace the other's. The check runs over
what `route_entity_identity` returns, which is the same function the annotation
key comes from, so the two cannot disagree.

---

## Scope Boundaries

- Plugin `conditions:` gating on HTTP. `plugin.rs:296-308` builds `MatchContext`
  from a hardcoded tool, prompt, and resource match. Untouched.
- The `assertions:` feature itself. This work is its prerequisite.
- Glob dispatch for the four MCP selectors. Pre-existing, unchanged here.
- Wildcard syntax inside an `http:` selector, host, scheme, or header matching,
  regular expressions, and path parameter capture. All out of scope in origin. Note
  that segment-boundary matching is *in* scope and is what D1 adopts; what is out
  is a wildcard dialect for paths.
- Any praxis-side change. The host contract is documented here and needs its own
  praxis issue.
- Any change to `require_protocol_metadata` or to how a host classifies traffic.

---

## Implementation Units

- U1. **The `http:` selector loads and validates**

**Goal:** A route can declare `http:` in all three shapes, it round-trips, and a
misspelled selector key fails at load naming the key.

**Requirements:** R1, R2, R3, R21

**Dependencies:** None

**Files:**
- Modify: `crates/ppe-core/src/config.rs`, `crates/ppe-core/src/visitor.rs`

**Approach:**
- Add `HttpSelector`: an untagged enum whose scalar and sequence forms hold exact
  paths and whose map form carries `method: Option<StringOrList>` plus exactly one
  of `path:` (exact) or `path_prefix:` (segment-boundary), rejecting both-or-
  neither at load (D1). Give it accessors so U3 does not destructure it. It does
  **not** wrap `Pattern`: a path is matched by equality or by prefix, never by
  glob.
- Add `pub http: Option<HttpSelector>` to `RouteEntry` after `llm`.
- Extend the count array in `validate_config` and both error strings so zero and
  more-than-one name `http` among the alternatives.
- Extend the existing raw-YAML per-route scan with a route-key allow-list, failing
  on an unrecognized key and naming it and the route index (D2). The list is the
  typed route fields plus `apl`, `response`, and the flat APL terms the visitor
  accepts: `pre_invocation`, `post_invocation`, `authorization`, `args`, `result`,
  `pdp`, `session_store`, and `plugins` as a mapping.
- Add a `ConfigVisitor` method reporting the extra route keys a visitor consumes,
  defaulting to empty, and union it into the scan so an out-of-tree visitor's keys
  are not rejected (D2).
- Document `http` as a `global.defaults` key alongside the other four, and validate
  the defaults keys against the known entity types so a typo there is not silently
  inert either.

**Patterns to follow:** `StringOrList` for the scalar-or-list shape;
`reject_renamed_identity_key` for the raw-YAML pass and its error phrasing. For
the map form's field names, praxis `filter/src/condition/request.rs` already
spells this split as `path:` and `path_prefix:` (Guideline 4b).

**Test scenarios:**
- Happy: all three shapes parse, and each serializes back to what was written.
- Happy: `global.defaults.http` parses and is reachable by entity type.
- Edge: `http:` alongside `tool:` fails naming both; a route with no selector fails
  naming `http` among the alternatives.
- Edge: a misspelled selector key fails naming that key.
- Edge: a route carrying `apl:` and `response:` loads, and so does one written in
  the flat form with `pre_invocation:` and a `plugins:` map, which is the shape
  `visitor_e2e.rs` already exercises.
- Edge: a visitor declaring an extra route key has that key accepted.
- Edge: an empty `http:` list; a map form declaring neither `path:` nor
  `path_prefix:`; a map form declaring both.
- Edge: a trailing slash on `path_prefix:` parses to the same selector as without
  one.

---

- U2. **One function owns the name a route is known by**

**Goal:** The mapping from a route to the names it contributes lives in `ppe-core`
and the APL visitor consumes it instead of keeping its own copy.

**Requirements:** R8, R11

**Dependencies:** U1

**Files:**
- Modify: `crates/ppe-core/src/config.rs`,
  `crates/ppe-apl-runtime/src/visitor.rs`

**Approach:**
- Add `pub fn route_entity_identity(route: &RouteEntry) -> Option<(&'static str,
  Vec<String>)>` to `config.rs`, returning the entity type and the names the route
  contributes. Use the `ENTITY_*` constants rather than the bare literals the
  current sites use, so the values stop being a coincidence.
- Preserve today's precedence and add `http` at the end of the chain, so an
  existing route's coordinates are byte-identical. This unit changes no behavior
  for the four MCP selectors; it moves the mapping and adds a fifth arm.
- Preserve list expansion: a list contributes one name per element (R11). The map
  form contributes one rendered name (D6).
- Delete `entity_identity` and `names_of` from the visitor and call the core
  function. Update the "no match" warning text to name the five selectors.
- Update the visitor module header's entity-to-hook table and the `ConfigVisitor`
  trait doc, both of which enumerate four selectors.

**Patterns to follow:** `route_static_tags`, which is the existing example of one
function in `config.rs` owning a derivation both resolvers read.

**Test scenarios:**
- Happy: each of the five selectors yields its entity type and names; a list yields
  one name per element.
- Happy: for every route shape in the existing APL fixtures, the core function
  returns exactly what the deleted visitor function returned.
- Edge: a route with no selector yields `None`, and the visitor warns and skips.
- Edge: no test enumerates selector names by hand (Guideline 4).

---

- U3. **Matching, resolved names, and one resolution per request**

**Goal:** Resolution takes a request description, returns the matched route *and*
the name it resolved to, and the two resolvers stop re-matching.

**Requirements:** R4, R4b, R5, R6, R13, R15, R20, R22

**Dependencies:** U2

**Files:**
- Modify: `crates/ppe-core/src/config.rs`, `crates/ppe-core/src/engine.rs`

**Approach:**
- Introduce a query type carrying the entity type, the name to match for the four
  MCP types, and for HTTP the normalized path plus the method. Introduce
  `MatchedRoute<'a> { route: &'a RouteEntry, name: String }`.
- Add `pub fn resolve_route<'a>(config, query) -> Option<MatchedRoute<'a>>`. It is
  `find_matching_route` with an `http` arm and with the winning selector value
  carried out alongside the route.
- Add a segment-boundary prefix matcher mirroring the host's `path_prefix_matches`:
  trim one trailing slash from the declared prefix, then match when the path equals
  it or continues with `/`. An empty or root prefix matches everything (R4b).
- Score HTTP in its own arm, leaving the four MCP selectors' arithmetic untouched
  (D3): an exact path takes the exact bucket, a prefix takes a prefix bucket
  discriminated by prefix length, mirroring the host's `path_prefix_specificity`.
  The method matcher gates the match without affecting the score; an absent
  `method:` matches any method (R4).
- Change both resolvers to take an `Option<&MatchedRoute>` instead of calling
  `find_matching_route` themselves, so the layering they already implement (global,
  then entity-type default, then tag bundles, then route) is unchanged and runs
  against a route the caller matched once (R20).
- Returning `None` is what R22's fallback rests on: the caller keeps using the
  reserved global name, which is today's behavior.
- Update the two resolver call sites in `engine.rs` mechanically so the tree
  compiles at the end of this unit, preserving today's behavior. Moving the match
  above the annotation lookup is U6's job, not this one.

**Patterns to follow:** praxis `filter/src/path_match.rs` for the matcher and the
length-based specificity (Guideline 4b); `score_entity_match`, extended with a new
arm rather than restructured; `resolve_identity_plugins_for_route`'s existing
layering, which must not change.

**Test scenarios:**
- Happy: a `GET` for `/v1/files/q3.pdf` resolves the `{path_prefix: "/v1/files"}`
  route and the name is that prefix; a list selector resolves to the matched
  element.
- Happy: `{path_prefix: "/api"}` matches `/api`, `/api/`, and `/api/v1`, and does
  not match `/apikeys`; a trailing slash on the prefix changes nothing.
- Happy: `{path_prefix: "/v1/files"}` beats `{path_prefix: "/v1"}` in both
  declaration orders, and an exact `/v1/files` beats both.
- Happy: the four MCP selectors' resolution outcomes are bit-identical to today,
  asserted by the pre-existing config and engine suites passing untouched.
- Happy: the four MCP entity types resolve exactly as before, asserted over the
  existing selector table plus new HTTP rows.
- Happy: an `http:` route's groups, tags, and `authentication:` layer resolve
  through the unchanged layering.
- Edge: a map form whose method does not match the request does not match the
  route; an absent `method:` matches every method.
- Edge: no `http:` route matches, so resolution yields nothing and the caller
  falls back.
- Edge: scope mismatch still hard-skips, and a scoped route still beats an
  unscoped one of the same bucket.
- Edge: a `when:`-carrying MCP route still outranks a narrower one without `when:`,
  exactly as the summed score does today (D3).

---

- U4. **Path normalization**

**Goal:** One function turns a host-supplied path into the string matching runs
against, or fails.

**Requirements:** R16, R17, R18, R19

**Dependencies:** None

**Files:**
- Create: `crates/ppe-core/src/http_path.rs`
- Modify: `crates/ppe-core/src/lib.rs`

**Approach:**
- `normalize_match_path(raw: &str) -> Result<Cow<'_, str>, PathError>`, mirroring
  the host's `normalize_rewritten_path` (Guideline 4b): strip the fragment, strip
  the query, strip semicolon path parameters per segment, split on **raw** `/`,
  drop empty and `.` segments, and pop on a `..` segment including its
  percent-encoded spellings (`%2e%2e`, `.%2e`, `%2e.`, any case).
- **Nothing is percent-decoded.** A percent-encoded separator stays inside its
  segment and is matched as written, which is what keeps PPE's reading aligned with
  the host's router (D5). Because nothing is decoded there is no charset rule, no
  UTF-8 validation, and no question about a non-UTF-8 octet.
- Borrow when nothing changed. The host's function returns `Cow::Borrowed` on a
  clean path for exactly this reason, and a clean path is the common case.
- Fail, do not sanitize, on a structurally invalid escape (`%zz`, a trailing `%`,
  `%2`), a raw control character, and a path that is not absolute. Each failure
  names what it saw without echoing the whole path into a log line.
- A `..` that would pop past the root clamps at the root rather than failing, which
  is what the host does, so escaping the root is not reachable.
- State at the module head that the output feeds matching only and is never written
  back to `HttpExtension` or the attribute bag (R18, Guideline 5), and that the
  matched form can therefore differ from the `http.path` a policy reads.
- Record in the module doc why the input is trustworthy as *request identity*: the
  container's merge preserves the request line from canonical state and never takes
  it from a plugin result (R19). This is an assumption the module depends on,
  so it belongs where a reader would question it.
- Name the host module these rules came from, so the two can be compared when
  either moves.

**Patterns to follow:** praxis
`filter/src/builtins/http/transformation/path_sanitize.rs` for the rules and the
`Cow` shape; `http_addr.rs` for the local convention of a small self-contained
safety module with its rules stated up front.

**Test scenarios:**
- Happy: an already-normal path comes back borrowed and allocates nothing.
- Happy: query, fragment, and `;params` are removed; `//a//b` collapses; `/a/./b`
  and `/a/c/../b` both resolve to `/a/b`.
- Edge: `/v1/files/%2e%2e/%2e%2e/admin` and `/v1/files/../../admin` both resolve
  to `/admin`, so neither matches a `/v1/files` prefix.
- Edge: `/admin/x/..%2f..%2fv1%2fok` stays under `/admin`, because that segment is
  not a traversal segment. It must not resolve to `/v1/ok`.
- Edge: `/files/caf%E9.pdf` and a raw UTF-8 path pass through untouched, with no
  charset rule applied.
- Edge: `%zz`, a trailing `%`, `%2`, a raw control character, and a non-absolute
  path each fail, and each error names the cause.
- Edge: `/../../..` clamps to `/` rather than failing.
- Edge: an oracle test comparing this function's output against the host's rules
  over a shared corpus, so a divergence fails a test rather than waiting for a
  code review.

---

- U5. **No two routes resolve to one name**

**Goal:** A configuration cannot declare two routes that resolve to the same name,
so the annotation table can never hold one route's handler under another's key.

**Requirements:** R7, R14

**Dependencies:** U3

**Files:**
- Modify: `crates/ppe-core/src/config.rs`

**Approach:**
- Add a load-time check over the names `route_entity_identity` returns, failing
  when two routes contribute the same name within one entity type and scope, and
  naming both route indices and the colliding name (D9). Run it from the same
  validation pass as the exactly-one-selector check.
- Check the **resolved names**, not the written selectors. `http: ["/a", "/b"]` and
  `http: ["/b", "/c"]` are different selector values that both contribute `/b`, and
  a selector-value comparison would pass them.
- Nothing else is needed for R14. Two prefixes of equal length that both match one
  path are the same prefix, so this check is the only way a tie can arise and
  rejecting it is the whole answer (D8). No runtime tiebreak, no warning latch, and
  no change to the existing scorer.

**Patterns to follow:** the existing route validation loop in `validate_config`,
which already reports per-route problems by index with the same phrasing.

**Test scenarios:**
- Edge: two routes declaring the same `http:` selector and scope fail at load,
  naming both indices and the name.
- Edge: `http: ["/a", "/b"]` and `http: ["/b", "/c"]` fail at load, naming `/b` —
  the case a selector-value comparison would miss.
- Edge: the same selector under different scopes loads, since scope is part of the
  key.
- Edge: two routes contributing the same name under *different* entity types load,
  since entity type is part of the key.
- Happy: every existing multi-route fixture in the tree still loads, so the check
  does not reject configurations that are fine today.

---

- U6. **The engine resolves once, keys on the resolved name, and fails closed**

**Goal:** An HTTP request is matched from its request line, the resolved name keys
both the annotation lookup and the cache, an unreadable path denies, and an
operator can see which route was chosen.

**Requirements:** R5, R6, R9, R17, R22, R23, R25, R26, R28b, R28c

**Dependencies:** U3, U4

**Files:**
- Modify: `crates/ppe-core/src/engine.rs`

**Approach:**
- In `filter_entries_by_route`, build the query before any lookup. For
  `ENTITY_HTTP`, take the path and method from `extensions.http` and normalize the
  path; for the four MCP types, take `meta.entity_name` as today.
- Resolve the route once via `resolve_route` when a routing-enabled config is
  present, and use the resolved name for the annotation `AnnotationKey`, for the
  cache hash, and for the owned `RouteCacheKey`.
- When HTTP resolution yields nothing, use the `ENTITY_NAME_GLOBAL` constant as the
  resolved name rather than reading `meta.entity_name`. The constant's doc only
  *asks* a host to set that value, so reading the field leaves a host free to put
  a path-derived name in the cache key and defeat R25 on the fallback path. Naming
  the constant makes R22 literally true and costs nothing.
- **`routing_enabled: true` is a precondition for the whole feature.** It defaults
  false, and the annotation short-circuit currently runs *before* the config is
  consulted, which is why several APL integration fixtures declare routes without
  setting it and still dispatch. Resolving the name first moves that boundary.
  Audit every `annotate_route` caller and fixture for its `routing_enabled` value
  before writing this unit, keep the pre-config path intact for the four MCP entity
  types (which need no name derivation), and state the precondition wherever the
  selector is documented rather than leaving an operator to discover it.
- Pass the matched route into the resolvers instead of letting them re-match, which
  removes the duplicate scan the current code does per miss.
- Change the return type to `Result<_, RouteResolutionError>` and map the error to
  `PipelineResult::denied` in all three invoke paths, with a stable violation code
  and `proto_error_code: Some(400)` (D4). Only a normalization failure with at
  least one `http:` route declared produces it; every other path is unchanged. Note
  that the pre-call `all_entries.is_empty() && route_annotations.is_empty()` early
  return still allows, so the denial applies only when the hook has a registered
  entry or an annotation. Nothing would have enforced on that path anyway, but R17
  reads as unconditional and this is where the exception belongs.
- **Emit a trace on the cache-miss resolution path** carrying the entity type, the
  resolved name, the scope, and the hook name. Today nothing tells an operator which
  route a request matched: `meta.entity_name` is the reserved name for every HTTP
  request, `http.path` is the raw path, and the resolved pattern lives only inside
  this function. For the four MCP types the resolved name equalled the entity, so
  any log line explained itself; HTTP breaks that correspondence. The resolved name
  is a config pattern rather than request input, so it is safe to emit, and doing
  so satisfies Guideline 5 without putting anything in the attribute bag.
- **Warn once when a route's `authentication:` list cannot apply.** When an `http:`
  route declares `authentication:` but `ext.http` or its `path` is absent at the
  identity hook, resolution falls back to the global list. That is today's behavior
  and must stay it (R23), but silently is the wrong way to do it for an
  authentication control. Latch a one-shot warning naming the route, so a host that
  has not adopted the request-line contract is diagnosable from what the engine
  emits rather than from reading the host's source.
- Do not touch `extensions` on the way through. `meta.entity_name` and `http.path`
  reach the bag as the host set them (R9).
- Leave the reject-on-full logic and its default alone (R26).

**Patterns to follow:** the existing `raw_entry` fast path and its manual hash,
which must keep matching the `Hash` impl field for field; the three invoke paths'
existing early-return shape; `route_cache_full_warned` for the one-shot warning
latch, which is the established idiom for a per-request condition that must not
spam.

**Test scenarios:**
- Happy: many requests across distinct paths matching one route produce one cache
  entry per hook, and `routing_cache_size()` proves it.
- Happy: a request resolves the route its path matches, and the policy still reads
  the real path from `http.path` and the host's `meta.entity_name`.
- Happy: an entity request resolves and caches exactly as it does today, asserted
  by the pre-existing engine tests passing unchanged.
- Happy: the resolved name appears in the trace output for a cache-miss resolution.
- Edge: a host setting a path-shaped `meta.entity_name` on an HTTP request still
  produces one cache entry across many distinct paths, because the fallback uses
  the constant rather than the field.
- Edge: no `http:` route declared, so an HTTP request resolves the reserved global
  name and behavior is byte-identical to today.
- Edge: an unnormalizable path with `http:` routes declared denies with the
  violation code and status; the same path with no `http:` route declared behaves
  as today; the same path on a hook with no entries and no annotations still allows.
- Edge: `ext.http` absent, or `path` absent, so no `http:` route matches and the
  fallback applies rather than a denial.
- Edge: an `http:` route declaring `authentication:` with no request line at the
  identity hook runs the global list, warns once, and does not warn again.
- Edge: a scoped and an unscoped annotation for the same resolved name, so the
  scoped-then-unscoped lookup order still holds.

---

- U7. **HTTP routes dispatch, and a replaced annotation is visible**

**Goal:** An `http:` route's compiled policy body runs, and the four MCP selectors
are demonstrably unchanged.

**Requirements:** R10, R11, R12, R12b, R24

**Dependencies:** U6

**Files:**
- Modify: `crates/ppe-core/src/engine.rs`,
  `crates/ppe-apl-runtime/src/visitor.rs`

**Approach:**
- R10 falls out of U2 and U6: the resolved name is the selector value, which is
  exactly the key the visitor annotated under. This unit proves and guards it
  rather than building it.
- Have `annotate_route` report whether it replaced an existing entry, and have the
  visitor say so when it happens (D7). This is a diagnostic improvement on its own
  merit, since the map currently overwrites silently from any source. It is no
  longer load-bearing for the catch-all, which no longer collides.
- Record that an `http:` route carrying a policy body dispatches that body in place
  of the structural plugin chain, the same way an entity route does (R12b). That
  is a property of being annotated at all rather than new behavior, but it is the
  one thing an operator writing a first `http:` route will not expect.
- Confirm the response half resolves the same route as the request half given a host
  that supplies the request line on both invocations, and document that contract
  at the hook constants rather than in a test comment (R24).

**Patterns to follow:** `hook_pair_for_entity`, which already decides per entity
type which hook is which half, so the response half needs no new mapping.

**Test scenarios:**
- Happy: `{path_prefix: "/v1/files"}` with a policy body denies a request the body
  denies, and an exact `http: "/healthz"` route with an empty body inherits nothing.
- Happy: an `http:` route carrying both a policy body and a `plugins:` list runs
  the body and not the structural chain, asserted explicitly so R12b is pinned.
- Happy: `tool: "hr-*"` with a policy body behaves exactly as it does today,
  including still not evaluating the body. This is the regression that proves the
  scope boundary held.
- Every fixture in this unit sets `plugin_settings.routing_enabled: true`
  explicitly, since it is a precondition and the default is false.
- Happy: `tool: [a, b]` continues to dispatch per element (R11 regression).
- Happy: both HTTP halves resolve one route, and a host firing only the request half
  behaves exactly as today.
- Edge: a global HTTP policy plus an explicit `{path_prefix: "/"}` route leaves the
  route governing what it resolves and the implicit catch-all governing the rest,
  with neither overwriting the other.
- Edge: `annotate_route` called twice by a host reports the replacement and keeps
  the later entry.

---

- U8. **Coverage, the host contract, and the record**

**Goal:** An operator learns at load what their `http:` routes do not cover, a host
integrator learns what to supply, and the breaking changes are written down.

**Requirements:** R12b, R23, R27, R28, R28b, R28c, R29, R30

**Dependencies:** U7

**Files:**
- Modify: `crates/ppe-apl-runtime/src/visitor.rs`,
  `crates/ppe-core/src/cmf/constants.rs`,
  `crates/ppe-core/src/config.rs`, `CHANGELOG.md`

**Approach:**
- Report at load when `http:` routes are declared with no catch-all, naming that
  unmatched traffic falls back to the global policy. Reuse the existing load-time
  warning style in the visitor.
- Document the host contract at the HTTP hook constants: the request line must be
  on the extensions at the identity invocation for a route's `authentication:` to
  apply, and on the response invocation for the response half to resolve the same
  route. State plainly that a host supplying neither behaves as it does today
  (R23), so the contract reads as an unlock rather than a new obligation, and point
  at the warning U6 emits as the way to tell which case a deployment is in.
- Reconcile the engine's account of the global-policy-plus-routes overlap with the
  host's startup warning about the same condition, so the two describe one thing
  from two directions (R30). The host's own text is out of this repository; what
  belongs here is that the engine's version does not contradict it.
- The `Added` CHANGELOG entry is written for operators and says five things: the
  selector exists, it requires `plugin_settings.routing_enabled: true`, a prefix
  matches at segment boundaries exactly as the host's router does, an `http:`
  route's policy body replaces its structural plugin chain (R12b), and a route's
  `authentication:` list needs the host to supply the request line at the identity
  hook or it falls back to the global list, which the engine now warns about.
- The resolver signature change is a `Changed` entry, breaking for the crate and
  not for any configuration. Nothing here carries "Breaking for existing config"
  (R29). Link the issue.

**Patterns to follow:** the existing CHANGELOG entries for config-surface
additions, which are multi-sentence and operator-facing rather than one-liners.

**Test scenarios:**
- Happy: a config with `http:` routes and a catch-all reports nothing; one without
  a catch-all reports once.
- Happy: a config with no `http:` route produces no new diagnostics at all, and a
  config with a glob route under one of the four MCP selectors produces none either
  (R27, R29).
- Edge: the CHANGELOG entry cites no requirement or unit identifier (Guideline 1),
  asserted by review rather than by a test.

---

- U9. **End-to-end verification**

**Goal:** The acceptance examples run against a real engine, and the known consumer
of today's global HTTP policy still resolves.

**Requirements:** R27, and evidence for every requirement above

**Dependencies:** U8

**Files:**
- Create: `crates/ppe-apl-runtime/tests/http_route_e2e.rs`
- Modify: `crates/ppe-apl-runtime/tests/global_http_authz.rs`,
  `crates/ppe-core/src/engine.rs` (selector table rows)

**Approach:**
- Build the origin's worked example as a fixture, with
  `plugin_settings.routing_enabled: true` set explicitly:
  `{path_prefix: "/v1/files"}` with an `authentication:` list and a policy body,
  an exact `/healthz`, and a `{path_prefix: "/"}` catch-all. Drive it through
  `invoke_named` the way the existing HTTP test does.
- Add HTTP rows to the engine's selector table test. The existing table keys each
  row on a request name and builds `Extensions` with `meta` only, so the row tuple
  and the extension construction both need extending, not just extra rows.
- Add the segment-boundary cases the host's own suite covers: `/api` against
  `/api`, `/api/`, `/api/v1`, and `/apikeys`, plus trailing-slash equivalence. If
  PPE and the host disagree on any of them, one of the two is wrong.
- Extend the existing global HTTP test rather than replacing it: its current
  assertions are the R27 regression, and they must pass untouched.
- Load the authpolicy demo's policy from praxis-demos and assert it resolves to the
  same plugins and the same handler coordinates as before. If the demo's config
  cannot be loaded in this repository's test environment, assert the equivalent
  shape from a fixture copied into the tree and say in the test header that it
  mirrors the demo.

**Patterns to follow:** `crates/ppe-apl-runtime/tests/global_http_authz.rs` for the
host-side extension construction and the invoke shape;
`crates/ppe-core/tests/identity_route_e2e.rs` for asserting a route's
authentication layering end to end.

**Test scenarios:**
- Every acceptance example in origin has a case here, named for the behavior rather
  than the example.
- `/healthz` inherits nothing while `/metrics` gets the catch-all's plugins.
- `/apikeys` does not match a `/api` prefix, end to end through the engine.
- The authpolicy shape resolves identically before and after.
- A configuration exercising all four MCP selectors, including a glob route,
  resolves and dispatches identically before and after.

---

## Unit Dependency Graph

```text
U1 (selector loads)
 └── U2 (one name derivation)
      └── U3 (matching + resolved name + HTTP scoring arm)
           ├── U5 (no two routes resolve to one name)
           └── U6 (engine: resolve once, key, fail closed)
                └── U7 (HTTP dispatch + replaced-annotation report)
                     └── U8 (coverage, contract, record)
                          └── U9 (end to end)

U4 (path normalization)  ──────► U6
```

U4 is independent of U1 through U3 and can be built in parallel. U5 and U6 both
depend on U3 and are independent of each other. The tree compiles at the end of
every unit: U3 carries the mechanical call-site update in `engine.rs` so the
signature change does not leave a broken tree behind it.

The prerequisite for [#28](https://github.com/praxis-proxy/policy/issues/28) is
satisfied once U6 lands. U7 is proof, U8 is reporting and record, U9 is
verification, so identity-propagation work does not need to wait for them.

---

## System-Wide Impact

- **Public API of `ppe-core`.** `RouteEntry` gains a field; `HttpSelector`,
  `MatchedRoute`, the query type, `resolve_route`, `route_entity_identity`,
  `RouteResolutionError`, and the normalization module are new; both resolvers
  change signature; `annotate_route` changes its return type;
  `filter_entries_by_route` is private and free to change. Breaking for the crate.
  The two resolvers have no caller in this tree or in praxis; `annotate_route` has
  one, in the APL visitor, which U7 updates.
- **Behavior of existing configurations: none at resolution or dispatch.** The
  four MCP selectors keep their scoring, their dispatch, and their pre-existing
  glob-dispatch gap. A configuration that declares no `http:` route resolves and
  dispatches exactly as it does today. It can newly fail at *load*, in one case:
  a route carrying a key nothing consumes, which R3 sets out to catch. This is the main change from the earlier draft, which widened the
  glob fix to every entity type and accepted a behavior change for it.
- **Cost per request.** The removed duplicate resolution is a per-cache-miss
  saving. Normalization is a per-request cost paid on hits too, though a clean
  path borrows and does not allocate. The two are not the same term, so the net is
  worth measuring rather than asserting; U9 owns an HTTP cache-hit benchmark.
- **The APL visitor** loses its own route-to-name mapping and gains a coverage
  report. No change to how policy compiles or stacks.
- **The host** is unchanged unless it wants per-route authentication or the
  response half, which is why R23 and R24 are contracts rather than requirements
  on praxis.
- **Two host-side issues fall out of this work** and belong in the praxis tracker:
  supplying the request line at the identity hook and on the response invocation,
  and the router not resolving dot segments on an inbound path.

---

## Risks & Dependencies

- **The annotation lookup moves behind the config check.** The short-circuit
  currently runs before the policy config is consulted, and `routing_enabled`
  defaults false while several APL integration fixtures declare routes without
  setting it. If resolving the name first changes behavior for any of them, the
  feature would silently require a flag those fixtures do not set. Mitigation:
  audit every `annotate_route` caller and fixture for its `routing_enabled` value
  before writing U6, and keep the pre-config path intact for the four MCP entity
  types, which need no name derivation at all.
- **Normalization is where a bypass would live.** Diverging from the host's rules
  reintroduces the class U4 exists to close, in either direction: decoding too
  much put PPE at odds with the router, and normalizing too little would let a raw
  traversal through. Mitigation: the rules are the host's, the module names its
  source, and U4 carries an oracle test against them.
- **The duplicate-name check could reject configurations that load today.** It is
  new validation on a shared path. Mitigation: U5's happy path is every existing
  multi-route fixture still loading.
- **`http:` is a second path dialect in PPE**, even though it is the *first*
  agreement with the host. An operator reading `routes:` sees four selectors that
  glob and one that does not. Mitigation is documentation, and the alternative was
  a dialect mismatch with the router that picks the upstream.
- **The authpolicy demo lives in another repository.** R27's strongest evidence is
  outside this tree, and the fixture-copy fallback can drift from the demo with no
  signal. Named in U9.
- **Depends on** the hook registry work, already merged on this branch, for correct
  HTTP hook metadata. The assertions work depends on this plan, not the reverse.

---

## Open Questions

### Resolved during planning

- **Who derives the HTTP name.** The engine, from `ext.http`, not the host. A
  host-derived name cannot be verified by PPE and would put a request path in the
  cache key.
- **How paths match.** Segment-boundary prefixes with length ordering, mirroring
  the host's router, rather than reusing `wildmatch`. Verified that the host does
  exactly this in `filter/src/path_match.rs`.
- **What normalization does.** Mirrors the host's `path_sanitize.rs`: resolve `.`,
  `..`, and their encoded spellings; collapse slashes; never decode a separator.
  This dissolved the decode-first bypass rather than mitigating it.
- **Whether the glob fix widens to the four MCP selectors.** No. It stays HTTP-only,
  which makes the work additive and leaves their scoring untouched.
- **Whether a specificity tie needs a tiebreak.** No. Prefixes make it unreachable,
  so the earlier deviation from the origin is withdrawn.
- **Whether `deny_unknown_fields` can satisfy R3.** No. Routes share their mapping
  with orchestrator blocks the typed struct must keep ignoring (D2).
- **Whether to add a dependency for percent-decoding.** No, and now doubly so:
  nothing is decoded (D5).

### Deferred to implementation

- Whether a bare `http:` string means an exact path or a prefix. Written as exact
  for consistency with the four name selectors; the host's more common spelling is
  a prefix. A defaults question, not a capability one.
- Whether a non-absolute path is rejected or gets a leading `/` prepended as the
  host does, and whether stripping `;params` belongs here or is left to the host.
- The rendered form of a map-form resolved name (D6), which stays an
  implementation detail as long as the round trip is tested.
- Whether the duplicate-name check runs pairwise across all routes or bucketed by
  entity type, and what it costs on a large configuration.
- Whether the coverage report should also name each `http:` route whose policy body
  will replace its structural plugin chain.
- Whether the one-shot authentication warning should also fire for the response
  half, where the same missing request line makes both halves resolve different
  routes. U6 covers the identity hook; the response case is the same shape and may
  want the same treatment.

---

## Sources & References

- Origin: `docs/brainstorms/2026-08-25-http-route-selector-requirements.md`
- Issue: [praxis-proxy/policy#40](https://github.com/praxis-proxy/policy/issues/40)
- Unblocks: [#28](https://github.com/praxis-proxy/policy/issues/28), whose route-
  level contracts cannot reach L7 traffic until a route can match it
- Prior plan for the hook metadata this work relies on:
  `docs/plans/2026-08-24-002-fix-cmf-hook-registry-plan.md`
- Conventions: `CONTRIBUTING.md`, `AGENTS.md`, `.markdownlint.yaml`
