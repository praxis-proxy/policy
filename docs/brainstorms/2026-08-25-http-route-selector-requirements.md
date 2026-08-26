---
date: 2026-08-25
topic: http-route-selector
---

# An HTTP request can match a route

## Summary

Routes gain an `http:` selector, so an operator can scope plugin chains,
authentication lists, groups, and tags to a path such as `/v1/files` instead of
governing every non-MCP request with one global policy. HTTP routes reuse the
existing group and tag resolution and the route cache, and they match paths the
way the host already does: segment-boundary prefixes per Gateway API semantics,
ordered by prefix length.

The name a request resolves to is the selector value that matched, not the
request path. That keeps the route cache bounded by declared configuration rather
than by attacker-controlled input, and it lets `ENTITY_NAME_GLOBAL` remain the
fallback rather than the only name an HTTP request can carry.

Deriving that name in one place also closes a defect the selector would
otherwise inherit. The annotation table is looked up by exact equality against
the literal selector string, so a route written `http: "/v1/files"` would
otherwise load, install a handler, and never evaluate. The same defect exists
for a glob route under the four MCP selectors; that is pre-existing and stays
out of scope here.

Addresses [praxis-proxy/policy#40](https://github.com/praxis-proxy/policy/issues/40).
Prerequisite for [#28](https://github.com/praxis-proxy/policy/issues/28).

---

## Problem Frame

Generic HTTP requests cannot match a route. `RouteEntry` carries four selectors
and `find_matching_route` dispatches on four entity types, ending in
`_ => continue`. `ENTITY_HTTP` lands on that arm, so an HTTP request resolves no
route, gets no route-level plugins, no group membership, no static tags, and no
route-level `authentication:` list.

| Where | What it does | State |
|---|---|---|
| `config.rs:293-369` `RouteEntry` | declares the selectors a route may carry | four: `tool`, `resource`, `prompt`, `llm`. No `http:` |
| `config.rs:1144-1150` `find_matching_route` | maps a request's entity type to a selector field | `_ => continue`, so `http` matches nothing |
| `config.rs:808-830` `validate_config` | requires exactly one selector | a route declaring only `http:` fails as "no entity matcher" |
| `crates/ppe-apl-runtime/src/visitor.rs:943-957` `entity_identity` | maps a route to the coordinates its annotation installs under | no `http` branch; the route is warned about and skipped |
| `visitor.rs:92-101` `hook_pair_for_entity` | maps an entity type to its pre and post hooks | already maps `ENTITY_HTTP` to the two HTTP hooks |
| `visitor.rs:528-601` `visit_global` | installs the entity-less HTTP handler | keyed `(http, "*")`; the only HTTP annotation that can exist |
| `engine.rs:1465-1501` annotation lookup | finds a route's compiled handler | exact-equality map lookup on the entity name |
| `config.rs:891-903` `score_entity_match` | assigns a specificity bucket | every glob scores 300, whatever it matches |

Two effects follow, and the issue names both. Operators cannot assign different
plugin chains or assertion contracts to `/v1/files` and `/healthz`. And a
global policy written for MCP traffic also governs health checks, static assets,
and everything else crossing the filter, which with
[#28](https://github.com/praxis-proxy/policy/issues/28) could inject identity
headers into requests that were never explicitly scoped. The host's fail-closed
`require_protocol_metadata` default limits that reach without removing it.

Path predicates do not answer this. `http.method` and `http.path` are already
attributes, so a global policy can vary its authorization decision by path. What
it cannot vary is which authentication plugins run, which authorization chain
applies, or which assertion contract is in force, because those attach to a route
and no route can match. Groups cannot apply for the same reason: `route_static_tags`
needs a `&RouteEntry` to read.

**The blocker the issue does not name.** Route resolution has two independent
paths that disagree about pattern matching. `resolve_plugins_for_entity` matches
the selector against the request name. The annotation short-circuit that runs
before it is an exact-equality lookup on `AnnotationKey { entity_type,
entity_name, scope, hook_name }`, and APL installs annotations keyed on the
*literal* selector string that `entity_identity` and `names_of` return. So a
route written `tool: "hr-*"` annotates under `hr-*`, a request for
`hr_get_salary` looks up `hr_get_salary`, and the compiled policy body never
runs.

That is pre-existing and stays out of scope. It matters here because a path is
never the name a request arrives under, so an `http:` route would hit the same
wall by construction rather than by accident. Whatever the request resolves to
has to be the string the annotation was installed under.

**Nothing in PPE normalizes a request path.** Verified across `crates/` and
`builtins/`: no query stripping, dot-segment resolution, slash collapsing, or
percent-decoding is applied to `http.path` anywhere. `HttpExtension::path`
documents the query string as the host's choice to include or omit. So
`/admin/x`, `/admin/./x`, `//admin/x`, and `/admin/x?y=1` are four unrelated
strings to a matcher. For a selector that scopes an authorization control, that
is a bypass surface, not an inconsistency.

The host, however, does normalize, and its rules are the ones to adopt rather
than reinvent. It resolves `.`, `..`, and their percent-encoded spellings,
collapses duplicate slashes, and never treats a percent-encoded separator as a
separator. Matching a path any other way puts PPE's view of a request at odds
with the router that chose its upstream.

**Cache cardinality is a design constraint, not an afterthought.** The route cache
rejects inserts when full rather than evicting, precisely so attacker-controlled
entity names cannot grow memory without bound. The cost is paid elsewhere: once
full, every further request pays a full linear scan over `routes` plus override
instantiation. If a request path became the cache key, any crawler would fill the
default 10 000 entries and leave every HTTP request on the slow path permanently.

---

## Actors

- A1. Deployment operator: writes `routes:` in unified-config YAML and needs to
  scope policy to a path. Cannot write or build Rust.
- A2. Policy author: writes rules that read `http.*` and `meta.*`. Affected by
  what the selector consumes and by what the attribute bag still shows.
- A3. Host integrator: builds a filter that fires the HTTP hooks and populates
  `meta` and `ext.http`. Needs to know what the engine requires and what it
  supplies today.
- A4. Assertions author (#28): attaches a request or response header contract
  to a route. Blocked entirely on L7 traffic until a route can match it.
- A5. PPE maintainer: adds an entity type or a selector and should change one
  place, not five.

---

## Requirements

**The selector**

- R1. A route may select on generic HTTP requests with an `http:` key. A bare
  string or a list selects exact paths. A map form selects a segment-boundary
  prefix with `path_prefix:`, an exact path with `path:`, and may narrow either
  by `method:`.
- R2. A route declares exactly one selector, and `http:` counts as one. The two
  errors validation already reports for zero and for more than one name `http`
  among the alternatives.
- R3. A route carrying a selector key the engine does not recognize fails at
  load, naming the key. Today an unknown key is dropped silently and the route
  then fails as "no entity matcher", which points the operator at the wrong
  problem.
- R4. The map form's `method:` participates in matching. A request whose method
  is not among those the route declares does not match that route. An absent
  `method:` matches any method.
- R4b. A prefix matches only at a segment boundary. `/api` matches `/api`,
  `/api/`, and `/api/v1`, and does not match `/apikeys`. A trailing slash on the
  declared prefix is insignificant. `path_prefix: "/"` is the catch-all.

**What a request resolves to**

- R5. Route resolution for an HTTP request matches against the request line: the
  path from `http.path` and, for the map form, the method from `http.method`. It
  does not match against `meta.entity_name`, which for an HTTP request is the
  reserved global name.
- R6. The name a request resolves to, and which keys the route cache and the
  annotation lookup, is the selector value that matched: the matched element for
  a bare string or list, the declared prefix for a prefix selector, and for the
  map form a value that includes every field the match consumed.
- R7. Two distinct routes never resolve to the same name within a scope. Where
  they would, config load fails and names both routes.
- R8. That derivation is one function. The name a route contributes to the
  annotation table and the name a request resolves to come from the same code, so
  the two sides cannot drift apart.
- R9. What policy reads does not change. `meta.entity_name` reaches the attribute
  bag as the host set it, and `http.path` continues to carry the real request
  path. Resolution names are internal to routing and are not observable as
  attributes.

**HTTP routes dispatch**

- R10. An `http:` route reaches its compiled policy body whether it selects an
  exact path or a prefix. The four MCP selectors keep exactly today's dispatch
  behavior, including the pre-existing gap where a glob route's body never
  evaluates.
- R11. A list selector continues to dispatch per element, as it does today.
- R12. An explicit catch-all `http:` route and the implicit global HTTP catch-all
  are distinct: the route resolves to its own name and wins by being resolved,
  while the implicit catch-all applies only when no route resolves. Neither
  silently replaces the other.
- R12b. An `http:` route carrying a compiled policy body dispatches that body in
  place of the structural plugin chain, as an entity route does. This is a
  property of the route being annotated at all, and it is documented rather than
  discovered.

**Specificity**

- R13. An exact path beats a prefix, and among prefixes the longer one wins. A
  route scoped to `/v1/files` takes precedence over one scoped to `/v1`
  regardless of the order they are declared in. This is the ordering the host's
  own router already applies.
- R14. Ordering is total for a given request, without consulting declaration
  order. Two prefixes of equal length that both match one path are necessarily
  the same prefix, so a tie can only arise from duplicate selectors, which R7
  rejects at load.
- R15. Scoping and `when:` continue to order as they do today, and the four MCP
  selectors' existing scoring is not touched. An HTTP route's ordering is
  self-contained.

**Path handling**

- R16. Matching runs on a normalized path, normalized the way the host already
  normalizes one. The query string and fragment are removed, duplicate slashes
  collapse, and `.` and `..` segments resolve, including their percent-encoded
  spellings, so neither `/v1/files/../../admin` nor
  `/v1/files/%2e%2e/%2e%2e/admin` reaches a route scoped to `/v1/files`. A
  percent-encoded separator is never decoded into a separator, so it stays
  within its segment and is matched as written. Path parameters introduced by a
  semicolon are stripped.
- R17. A path that cannot be normalized matches no `http:` route, and when any
  `http:` route is declared the request is denied. A request whose path cannot be
  interpreted cannot be authorized against path-scoped policy, and falling
  through to the catch-all would hand it the most permissive route in the
  configuration.
- R18. Normalization does not rewrite what policy reads. `http.path` in the
  attribute bag stays the value the host populated, so a rule written against it
  keeps its current meaning. That the matched form can differ from it is
  recorded where a policy author will meet it.
- R19. The selector matches only values that are host-populated request identity
  and that a plugin cannot forge.

**Layering and fallback**

- R20. An `http:` route stacks the same layers an entity route does: global, then
  the entity-type default, then group and tag bundles, then the route itself.
  `groups:` and `meta.tags` work on an `http:` route with no new mechanism.
- R21. `global.defaults` accepts `http` as a key, and that is documented rather
  than incidental.
- R22. When no `http:` route matches, resolution falls back to the reserved global
  name, which is what an HTTP request resolves to today. The engine names that
  reserved value itself rather than reading it back from the request, so no
  request-derived string can reach the route cache key on the fallback path.
- R23. An `http:` route's `authentication:` list applies when the host makes the
  request line available at the identity hook. When it does not, the route's list
  does not apply and the global list does, which is exactly today's behavior. The
  host contract is documented, and a host that does not change sees no difference
  in what runs. It does see one new signal: the engine reports that a route's
  authentication list could not apply, once, rather than falling back silently. An
  authentication control that quietly stops applying is worth a line in a log even
  when the fallback is the documented behavior.
- R24. The request half and the response half of one HTTP exchange resolve to the
  same route, so a contract attached to a route governs both directions of that
  route. The host contract that makes this possible is documented.

**Bounded cost**

- R25. No attacker-controlled string becomes a route cache key. Cache cardinality
  is bounded by the declared routes, the hooks they install, and the scopes they
  declare.
- R26. Adding `http:` routes does not change the reject-on-full cache behavior or
  its default.

**Compatibility and coverage**

- R27. A configuration declaring no `http:` route resolves exactly as it does
  today. The reserved global name stays the fallback, and the known consumer of
  the current global HTTP policy still resolves as expected.
- R28. Declaring `http:` routes without a catch-all is reported at load. Traffic
  matching none of them falls back to the global policy, which is the overlap
  this work set out to close.
- R28b. Which route a request resolved to is discoverable from what the engine
  emits. For the four MCP selectors the resolved name is the entity, so any
  diagnostic explains itself; a path resolving to a prefix does not, and an
  operator cannot reproduce the match by reading the file.
- R28c. The selector requires routing to be enabled, and that is stated wherever
  the selector is documented rather than left to be discovered. The setting
  defaults off.
- R29. No existing configuration changes how it *resolves or dispatches*. A
  configuration that declares no `http:` route resolves and dispatches exactly as
  it does today, and the four MCP selectors are untouched. One load-time
  exception, and it is the point of R3 rather than a regression: a route carrying
  a key nothing consumes used to load with that key inert and now fails, naming
  it.
- R30. The engine's account of the global-policy-plus-routes overlap and the
  host's startup warning about the same overlap agree with each other. The two
  are mitigations of one condition approached from opposite directions.

---

## Acceptance Examples

- AE1. **Covers R1, R5, R20.** Given a route `http: {path_prefix: "/v1/files"}`
  carrying an `authentication:` list and a group, when a request arrives for
  `/v1/files/q3.pdf`, that route's authentication plugins run, the group's
  plugins are included, and the route's own plugins fire.
- AE2. **Covers R1, R22.** Given the routes `http: "/healthz"` with no body and
  `http: {path_prefix: "/"}` carrying a JWT plugin, when a request arrives for
  `/healthz` no authentication plugin runs, and when one arrives for `/metrics`
  the JWT plugin does.
- AE3. **Covers R4.** Given a route
  `http: {method: GET, path_prefix: "/v1/files"}`, when a `GET` for
  `/v1/files/q3.pdf` arrives it matches, and when a `POST` for the same path
  arrives it does not.
- AE4. **Covers R6, R9, R25.** Given many requests across distinct paths that all
  match a `/v1/files` prefix, the route cache gains one entry per hook rather
  than one per path, and a policy reading `http.path` still sees the individual
  request path.
- AE5. **Covers R10, R11, R12b.** Given a route `http: {path_prefix: "/v1/files"}`
  with a policy body, when a request for `/v1/files/q3.pdf` arrives the compiled
  body evaluates in place of the structural plugin chain. Given a route
  `tool: "hr-*"` with a policy body, dispatch is exactly what it is today. Given
  `tool: [a, b]`, both names continue to dispatch as they do today.
- AE6. **Covers R4b, R13, R14.** Given `{path_prefix: "/v1"}` declared before
  `{path_prefix: "/v1/files"}`, when a request for `/v1/files/q3.pdf` arrives the
  longer prefix wins, and reversing the declaration order gives the same answer.
  Given `{path_prefix: "/api"}`, a request for `/apikeys` does not match it.
  Given two routes declaring the same selector and scope, config load fails and
  names both.
- AE7. **Covers R16, R17.** Given a route scoped to `/v1/files`, when a request
  arrives for `/v1/files/%2e%2e/%2e%2e/admin` it does not resolve to that route,
  and neither does `/v1/files/../../admin`. Given a request whose encoded
  separator keeps it inside its segment, it resolves to the route the written
  path selects rather than to one the decoded path would. Given a path that
  cannot be normalized, the request is denied rather than resolving to the
  catch-all.
- AE8. **Covers R2, R3.** Given a route declaring both `http:` and `tool:`,
  config load fails naming both. Given a route declaring a misspelled selector
  key, config load fails naming that key rather than reporting a missing entity
  matcher.
- AE9. **Covers R12.** Given a global HTTP policy and an explicit
  `http: {path_prefix: "/"}` route, the route governs traffic it resolves and the
  implicit catch-all governs only what resolves to no route; neither overwrites
  the other's handler.
- AE10. **Covers R23.** Given a host that makes the request line available at the
  identity hook, an `http:` route's `authentication:` list runs for a matching
  request. Given a host that does not, the global list runs and behavior is
  identical to today.
- AE11. **Covers R24.** Given an `http:` route carrying both a request-side and a
  response-side contract, and a host that fires both HTTP hooks, both halves
  resolve to that same route.
- AE12. **Covers R27, R28, R29.** Given a configuration with no `http:` route,
  every resolution and every dispatch is unchanged from today, including a glob
  route under one of the four MCP selectors. Given one with `http:` routes and no
  catch-all, load reports the uncovered traffic.

---

## Success Criteria

- An operator scopes a plugin chain, an authentication list, and a group to a
  path from configuration alone, and gives `/healthz` a route that inherits
  nothing.
- An `http:` route evaluates the policy it declares. No `http:` route loads
  clean, installs a handler, and silently never fires it.
- Nested path scopes resolve by prefix length, so moving a route within the file
  cannot change which one applies.
- An operator who has written a path prefix for the host's router can write the
  same prefix here and get the same matching.
- Route cache cardinality is a function of the configuration, not of the traffic,
  and no request path ever becomes a cache key.
- A path that encodes its way around a scope does not reach the route that scope
  protects.
- A host that does not change sees exactly today's behavior, and what a host must
  do to unlock per-route authentication and the response half is written down.
- Planning does not need to invent the config surface: the selector shapes, the
  resolved-name rule, the specificity rule, the normalization rule, and the
  fallback are all decided here.

---

## Scope Boundaries

- Plugin `conditions:` gating on HTTP. `MatchContext` is built from a hardcoded
  tool, prompt, and resource match and gives an HTTP request nothing. That is a
  separate surface, see below.
- The `assertions:` feature itself (#28). This work removes the obstacle in its
  path and is otherwise independent of it.
- Glob dispatch for the four MCP selectors. Pre-existing, unchanged here, and
  tracked below.
- Wildcard syntax inside an `http:` selector. A prefix is a prefix; there is no
  `*` to place.
- Matching on host, scheme, or headers. Only method and path are in this
  selector. `http.host` and `http.scheme` remain policy attributes.
- Regular expressions, path parameter capture, or binding a matched segment to a
  policy variable.
- Any change to how a host classifies traffic as MCP or generic HTTP, or to
  `require_protocol_metadata`.
- Any praxis-side change. PPE defines and routes; the host decides what to fire
  and what to populate.

### Tracked elsewhere

- **A glob route under one of the four MCP selectors never evaluates its policy
  body**, because the annotation lookup is exact and APL keys the annotation on
  the literal pattern. Pre-existing, out of scope here, and worth its own issue.
- **The host's router does not resolve dot segments on an inbound path**, so it
  can route `/v1/files/../../admin` to the `/v1/files` cluster while the backend
  resolves the path to `/admin`. That is a host-side gap independent of this
  work and needs an issue there.
- **The host must supply the request line at the identity hook** for an `http:`
  route's `authentication:` list to apply, and must supply it on the response
  invocation for the response half to resolve the same route. Today the identity
  invocation carries `meta` only, and the HTTP attributes are attached after
  identity resolution rather than before. Needs a praxis-side issue.
- **Plugin `conditions:` cannot gate on HTTP.** Worth its own issue once there is
  a caller that wants it.
- **Firing `cmf.http_response`.** PPE defines and routes both halves; a host that
  never fires the response half behaves exactly as it does now.

---

## Key Decisions

- **The resolved name is the selector that matched, not the request path.** The
  issue lists the full path, a bounded path component, and the method plus path
  as the candidates, and every one of them makes an attacker-controlled string a
  cache key. Deriving the pattern instead bounds cardinality by configuration,
  keeps the reject-on-full cache from ever filling on traffic alone, and leaves
  the annotation table's exact-equality lookup working unchanged. The cost is
  that `meta.entity_name` does not become more informative for HTTP, which
  matters less than it looks: `http.path` already carries the path a policy would
  read.

- **The HTTP selector matches paths the way the host already does, not the way
  the other selectors match names.** The host routes on segment-boundary
  prefixes per Gateway API semantics and orders them by prefix length. Reusing
  the existing `wildmatch` matcher for paths would put two incompatible path
  dialects in one proxy: a host prefix `/api` does not match `/apikeys`, while a
  pattern `/api*` does, and an operator who has written one will reasonably
  expect the other to agree. The cost is that `http:` reads differently from the
  four name selectors, which is honest, because a path is not a name. It also
  means the four MCP selectors need no change at all, so their scoring and
  dispatch stay exactly as they are.

- **Ordering falls out of prefix length, so a tie cannot arise.** Two prefixes of
  equal length that both match one path are necessarily the same prefix, which
  makes duplicate selectors the only way to tie and a load-time reject the whole
  answer. This is why no runtime tiebreak and no declaration-order rule is
  needed, and it is a direct consequence of dropping wildcard syntax rather than
  a separate mechanism.

- **Normalization mirrors the host's rules rather than inventing PPE's own.**
  The host resolves `.`, `..`, and their percent-encoded spellings, collapses
  duplicate slashes, and never decodes a percent-encoded separator into a
  separator. An earlier draft had PPE decode before reading segment structure,
  which is worse than useless here: it makes PPE resolve
  `/admin/x/..%2f..%2fv1%2fok` to `/v1/ok` and apply a public policy, while the
  host's router still sends the request to the `/admin` cluster. Matching the
  host's reading keeps PPE's view of a request aligned with the router that
  chose its upstream, and where a backend is more lenient than both, PPE ends up
  stricter rather than looser. It also removes the question of what to do with a
  percent-encoded octet that is not valid UTF-8: nothing is decoded, so there is
  no charset rule to get wrong.

- **An uninterpretable path is denied, not passed to the catch-all.** Falling
  through is the tempting default and it is backwards: the catch-all is the most
  permissive route in the configuration, so a path crafted to defeat
  normalization would be rewarded with the loosest policy. Denying costs a
  configuration nothing that declares no `http:` routes, because the rule only
  engages once path-scoped policy exists. With nothing decoded the failure set is
  small: a structurally invalid escape, a control character, and a path that is
  not absolute.

- **The map form ships in v1, and it carries more than method.** Once paths match
  as prefixes rather than patterns, the map form is how a route says which of the
  two it wants, so it is structural rather than a convenience. It also carries
  `method:`, which earns its place on its own: `http.method` is already a policy
  attribute, so method-varying authorization is expressible today, but a
  predicate cannot vary the authentication list or the assertion contract, and a
  `GET /healthz` health check and a `POST /healthz` probe attempt want different
  contracts.

---

## Dependencies / Assumptions

- `ENTITY_HTTP` and `ENTITY_NAME_GLOBAL` exist and are already routed.
  `hook_pair_for_entity` maps `ENTITY_HTTP` to the request and response hooks,
  and both hooks carry `ENTITY_HTTP` with their phases in the metadata table. The
  missing piece is the config selector, not the entity type.
- The HTTP hook metadata is correct as of the hook registry work, so a consumer
  reading a hook's phase to derive direction resolves both halves. The assertions
  direction gate depends on this.
- `method`, `path`, `host`, and `scheme` are preserved from canonical state on
  merge and are never taken from a plugin's return value, so a plugin cannot
  forge the value the selector matches on. Verified against the container's merge
  path.
- Route resolution reads the unfiltered extensions, before per-plugin capability
  filtering, so reading `ext.http` for matching needs no capability grant.
- The host hands PPE the path exactly as received, percent-encoding intact and
  dot segments unresolved, and forwards the same URI upstream unless a rewrite
  filter is configured. Verified in the host's policy filter and its upstream
  request handler.
- The host decodes a percent-encoded separator nowhere in the request path, and
  its own path matching, normalizer, and router all read the raw form. So the
  rules this work adopts are the rules already in force one layer out, not a new
  convention. Verified against the host's path-matching and path-sanitizing
  modules.
- The host's normalizer returns a borrowed value when nothing changed, which is
  the shape this work's normalizer should take for the same reason.
- `global.defaults` is a map lookup by entity type, so `global.defaults.http`
  works mechanically the moment `http` is a real entity type. It needs
  documenting and validating, not building.
- `groups:` desugars into the tag set at resolution through a single function
  that takes a `&RouteEntry`, so group and tag support for HTTP routes follows
  from a route matching at all.
- The known consumer of the current global HTTP policy is the authpolicy demo in
  praxis-demos. Confirming it still resolves is part of this work's acceptance,
  not a follow-up.
- Repo convention: requirement identifiers from this document must not appear in
  commit messages, code comments, rustdoc, changelog entries, test names, or
  pull-request descriptions. Describe the behavior instead.

---

## Outstanding Questions

### Deferred to Planning

- [Affects R1][Technical] Whether a bare `http:` string means an exact path, as
  written here for consistency with the four name selectors, or a prefix, which
  is the host's more common spelling. The map form covers whichever the bare form
  does not, so this is a defaults question rather than a capability one.
- [Affects R6][Technical] How the map form's resolved name is rendered, given it
  must include every matched field, stay stable across reloads, and not collide
  with a path that could be written literally.
- [Affects R16][Technical] Whether a path that is not absolute is rejected or has
  a leading slash prepended. The host prepends; rejecting is louder. Also whether
  stripping semicolon path parameters belongs here or is left to the host.
- [Affects R7][Technical] Whether duplicate detection runs over all routes
  pairwise at load or only within an entity type, and what it costs on a large
  configuration.
- [Affects R23, R24][Needs research] The precise shape of the host contract, and
  whether PPE can detect a host that has not adopted it well enough to warn
  rather than silently falling back.
- [Affects R12b][Technical] Whether the load-time coverage report should also
  name each `http:` route whose policy body will replace its structural plugin
  chain, so an operator sees that substitution before traffic does.
