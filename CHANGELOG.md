# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

> **Types of changes:**
>
> - **Added**: for new features.
> - **Changed**: for changes in existing functionality.
> - **Deprecated**: for soon-to-be removed features.
> - **Removed**: for now removed features.
> - **Fixed**: for any bug fixes.
> - **Security**: in case of vulnerabilities.

## [Unreleased]

### Added

- **Delegated tokens can be reused until they expire.** The OAuth delegator runs one RFC 8693 exchange per `delegate` step; a `cache:` block lets it serve a token it already minted instead. Off unless enabled, and then only for `subject: this_workload` and `client`, whose number of cache entries is bounded by configuration rather than by the caller population. `user` and `caller_workload` are opt-in through `cache.subjects`. Concurrent requests for one uncached key produce one exchange rather than one each, and a failed exchange is not stored. A cached token stays usable after an `IdP`-side revocation until its entry retires, which `cache.ttl_ceiling_seconds` bounds. ([#30](https://github.com/praxis-proxy/policy/issues/30))

- **A route that delegates an unvalidated credential is reported at config load.** A `delegate` step whose subject exchanges the caller's own token relies on identity resolution having checked it, but `identity:` is per-route and optional, so a route can reach the delegator with a token this process has not validated. Loading the config now warns under `alarm = "delegation_without_identity_resolution"`, naming the route and the delegate plugins on it. `subject: this_workload` is excluded, since it carries no inbound credential. ([#30](https://github.com/praxis-proxy/policy/issues/30))

- **`http.response`, the return half of the L7 path.** `http.request` had no counterpart because authorization is an admission check that belongs entirely before the request is forwarded. Response filtering is not: stripping a header the upstream set, enforcing a content type, and attaching labels all belong after. Header and extension filtering only, since no response body exists in the model yet and the payload is unused on this path. A `global.apl` carrying `result:` or `post_invocation:` steps now installs a `Post`-phase handler under the same `http` / `*` coordinates the request hook uses; a policy that only authorizes gains nothing and installs nothing. PPE defining and routing a hook does not oblige a host to fire it, so a host that never does sees no change. For the host that does adopt it: a `global.apl` whose post steps were previously inert on the entity-less HTTP path becomes live the moment the hook is fired, and `result.*` keys do not exist for a request carrying no entity, so a step reading one denies. Check what the global post block does before firing.

- **`http.status`, the response status a post-phase policy can read.** The HTTP
  model carried the request line and both header maps but no status, so a rule
  like `http.status >= 500: deny` had nothing to read and a response-phase policy
  could not act on what the upstream returned. `HttpExtension` now carries
  `status: Option<u16>`, and it reaches the attribute bag as an integer under
  `http.status`, so ordering and equality predicates both compare numerically. The
  host populates it on the response invocation only, the way `response_headers` is
  already populated, so the key is absent on the request half. A missing bag key
  makes a comparison false, which means a status rule placed under
  `pre_invocation:` is inert rather than denying; keep it under
  `post_invocation:`. It rides the `read_headers` capability with the rest of the
  `http` slot, and it is omitted from serialized output when unset, so a host that
  never sets it is unaffected. ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **`http:`, a route selector for generic HTTP requests.** L7 traffic carries
  no entity, so it resolved no route at all: no route-level plugins, no group
  membership, no static tags, no route-level `authentication:`. A route can now
  select on the request line, in three shapes. A bare path (`http: /healthz`)
  and a list (`http: [/livez, /readyz]`) match exact paths; the map form asks
  for a segment-boundary prefix (`http: {path_prefix: /v1/files}`) or an exact
  path (`http: {path: /v1/files/manifest}`), either optionally narrowed by
  `method:`. It requires `plugin_settings.routing_enabled: true`, which
  defaults to false and leaves an `http:` route inert until it is set; a load
  now reports that state, and reports a set of `http:` routes that declares no
  catch-all, naming that a request matching none of them is governed by the
  global policy instead. A prefix matches at segment boundaries exactly as the
  gateway's own router reads one, so `/api` covers `/api`, `/api/`, and
  `/api/v1` but not `/apikeys`, and a trailing slash is insignificant. An exact
  path outranks every prefix, the longer prefix wins among prefixes, and a
  route narrowed by `method:` outranks the same path left open for the methods
  it names, with the narrower of two narrowings winning a method both name.
  Declaration order decides nothing among them, and among two selectors naming
  the same number of methods it is what is left. An exact path is
  compared byte for byte against the path the request arrived on, the way the
  gateway router's own exact arm compares it, so `/admin` and `/admin/` are two
  routes answering for two different requests.

  Two things worth knowing before writing the first one. An `http:` route
  carrying a policy body dispatches that body in place of its structural plugin
  chain, the same way an entity route does, so the `plugins:` the route also
  lists run only where a policy step names them; a load names each `http:`
  route that applies to. And a route's `authentication:` list applies only
  where the host supplies the request line at the identity hook. Where it does
  not, the global list governs exactly as it does today, and the engine now
  warns once naming the route, so which of the two a deployment is in is
  readable from what the engine emits rather than from the host's source.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **One declaration per hook, holding both its name and its routing metadata.** `define_hooks!` emits a hook's `pub const` and its `hooks::metadata` row together, so a name without a row is unrepresentable rather than something to test for. A host declaring its own hooks can use it too, then register the resulting slice at startup. `crates/ppe-core/examples/plugin_demo.rs` shows the pattern.

- **PPE performs no outbound HTTP of its own.** A host installs an `HttpTransport` and plugins borrow it, so a process embedding PPE keeps one connection pool, one TLS trust store, and one egress path instead of two. `identity-jwt`, `delegator-oauth`, and `elicitation-ciba` all go through it; `reqwest` is gone from the workspace entirely. A proxy injects its own client via `PolicyEngine::set_http_transport`; anyone embedding PPE standalone can call `install_default_http_transport` for a bundled hyper implementation behind the non-default `http-hyper` feature. ([#20](https://github.com/praxis-proxy/policy/issues/20))

- **`perform_http` capability.** Gates outbound HTTP, and gates the *action* rather than a slot — the first capability that authorizes reaching outside the process. Withholding it stops the call rather than degrading it, because a plugin that quietly skipped its `IdP` call would fail open. **Breaking for existing config**: a plugin using `jwks_url`, an OAuth delegator, or a CIBA approver must now declare it or the engine refuses to start, naming the plugin and the capability to add.

- **Response bodies are bounded.** Every outbound call now carries a size ceiling — 256 KiB for a JWKS document, 64 KiB for a token response — so a compromised or broken endpoint cannot stream until the process dies. `reqwest` applied no limit on any of these paths, so this closes a gap rather than tightening a bound.

- **HTTP/2, where the peer supports it.** The bundled transport advertises ALPN `h2, http/1.1` and falls back to HTTP/1.1, which the previous `reqwest` configuration never enabled. A deployment minting a token per request carries those concurrently over one connection instead of one connection each.

- **Retries are keyed to whether a repeat is safe.** `RetryPolicy` distinguishes an operation that can be repeated from one that cannot, and `HttpTransportError::may_have_reached_peer` answers the question a caller actually needs. A JWKS `GET` retries freely; a token exchange and a CIBA dispatch retry only failures that provably never reached the peer, because a timeout cannot tell "never arrived" from "the reply was lost" and repeating either would mint a second credential or ask a human twice.

- **`delegation.egress_denied` / `elicitation.egress_denied`.** New deny codes for the case where the host refuses a call before it leaves the process — an egress policy, an SSRF guard, an open circuit. Kept distinct from `idp_unreachable` on purpose: "we declined to try" and "we tried and failed" send an operator to different places, and collapsing them turns a blocked destination into a phantom network problem. No behaviour changes until a host transport produces the refusal; the bundled hyper transport never does.

- **A shared table of addresses an outbound call must not reach.** `praxis_policy_core::http_addr` covers loopback, RFC 1918, link-local (the cloud-metadata range), CGNAT `100.64/10`, the IPv6 equivalents, and the embedded-IPv4 forms including NAT64. The table only; `praxis-policy-core` opens no sockets, so a transport enforces it where it dials. Sharing it stops three transports each writing a range list that drifts, and these are exactly the ranges that look finished while missing an entry.

- **`FakeTransport` for tests.** A scripted transport in `praxis-policy-core::http_testing`, which makes the paths a mock server cannot reach — a timeout, a connect failure, a rotation between two fetches — assertable without sleeping.

- **Claim mapping is configuration.** The JWT identity plugin's `claim_mapper` names any of four shipped presets (`standard`, `keycloak`, `auth0`, `cognito`), and a new `claim_map` field takes a map written inline, so an `IdP` that nests roles under `realm_access.roles` or namespaces them behind a URL no longer needs a patched crate. A field lists candidate paths tried in order, with options for shape, splitting, and whether a miss refuses the token, and `merge: union` takes every candidate that resolves, each value once, in first-seen order. Paths use dots for nesting, with `\.` for a literal dot. An existing config is unaffected: naming no mapper resolves to `standard`, which the tests hold to the previous Rust mapper. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **A policy can gate on which `IdP` minted a token.** `claims: {include: [iss]}` returns a claim to the policy-visible bag, registered claims included, so `claim.iss` becomes readable. Registered claims were always dropped, so a deployment trusting several issuers could not gate on which one signed the token. `claims.exclude` drops a claim the other way, and both work with a preset or an inline map. Both lists take top-level claim names, since the bag is keyed by name: a dotted entry is refused at load rather than matching nothing, and a claim whose own name holds a dot is written with `\.`. A `role: caller_workload` resolver carries no claims bag, and says so at load rather than ignoring the setting quietly. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **Each shipped preset records what it omits.** Auth0 and Keycloak put their roles claim where no preset can name it, so those need a hand-written `claim_map`. Presets leave a field empty rather than filling it with the wrong concept, because Keycloak's `groups` holds realm roles and Cognito's `cognito:roles` holds IAM role ARNs. Each preset's description says what it covers and what is opt-in at the provider. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **Roles and permissions are readable as whole sets.** `subject.roles`, `subject.permissions`, `client.roles`, and `client.permissions` join `subject.teams` as `StringSet` bag keys, so a policy can write `"hr" in subject.roles` rather than enumerating `role.<name>` booleans. The flattened boolean keys are unchanged. ([#7](https://github.com/praxis-proxy/policy/pull/7))

### Changed

- **`HookFamily::for_entity` reports an unmapped entity type instead of
  defaulting to CMF.** It returned `HookFamily` and treated every entity type
  other than `http` as the CMF family, so a route on an entity type nobody had
  mapped yet would install a handler that reports the CMF family and hands its
  plugins a chat message no host filled. The `else` also hid the omission from
  the compiler: the closed matches elsewhere in the crate flagged a new family,
  this function did not. It now returns `Option<HookFamily>` over the same
  entity types `hook_pair_for_entity` maps, and the visitor's install path logs
  and skips an unmapped one, which is what it already does for an entity type
  with no hook pair. **Breaking** for a caller that used the returned family
  directly; the fix is to handle `None` rather than assume CMF.

- **`HookFamily` is `#[non_exhaustive]` and `hook_type_name` is public.** The
  enum was public and exhaustive, so a third payload family would have been a
  breaking change for every downstream `match` on it, and its only interesting
  method was private, so a host could hold one and not ask it anything.
  `#[non_exhaustive]` is itself **breaking** for a downstream exhaustive
  `match`, which is the argument for doing it while the enum has two variants
  rather than at the moment a third one lands.

- **The generic-HTTP hooks are their own family: `http.request` and
  `http.response`.** Both used to be spelled `cmf.http_request` and
  `cmf.http_response` and both were typed on `CmfHook`, whose payload is an LLM
  chat message. Nothing on the HTTP path fills it, so a content-inspecting
  plugin written against `CmfHook` could register on the HTTP response hook,
  scan a fabricated message, find nothing, and report clean. An always-passing
  scanner is worse than no scanner. The family now has its own `HttpHook` type
  and an `HttpPayload` that carries no fields, so what a handler reads about an
  HTTP exchange is the `HttpExtension` it is passed and nothing pretends to hold
  content. The metadata rows moved out of the CMF table into the HTTP family's
  own, with the entity type and phases they already had: `http.request` is `Pre`
  under `entity_type: http`, `http.response` is `Post`. **Breaking for existing
  config**: a `hooks:` entry naming `cmf.http_request` or `cmf.http_response`
  now fails to load, and the refusal names the replacement. Rust callers rename
  `HOOK_CMF_HTTP_REQUEST` / `HOOK_CMF_HTTP_RESPONSE` to `HOOK_HTTP_REQUEST` /
  `HOOK_HTTP_RESPONSE`, which now live in `praxis_policy_core::http_hook`.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **A plugin on an HTTP route receives the HTTP payload.** Dispatch follows the
  route's hook family now, so the plugins an `http:` route's policy steps name
  are invoked through `HttpHook` and handed an `HttpPayload`. Before this, every
  APL-dispatched plugin went through `CmfHook`, which meant a scanner named by
  an HTTP route's policy scanned a chat message the HTTP path never filled and
  reported clean. **Breaking for a host firing the HTTP hooks**: fire them as
  `invoke_named::<HttpHook>("http.request", HttpPayload, ...)` rather than
  through `CmfHook`, and a plugin registered on `http.request` or
  `http.response` implements `HookHandler<HttpHook>` rather than
  `HookHandler<CmfHook>`. Nothing about MCP or A2A dispatch changes: an entity
  route still builds a CMF invoker and its plugins still receive
  `MessagePayload`, field stages included. A handler that needs to know which
  half of an exchange fired reads `http.status`, which the host sets on the
  response invocation only; `PluginContext` carries no hook name, and the hook
  metadata documentation no longer claims it does.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **Registration refuses a handler the hook's payload does not fit.** A
  dedicated `HttpHook` type does not by itself keep a CMF plugin off an HTTP
  hook: `register_for_names::<H>` never consults `H`, and a plugin declared in
  YAML reaches the registry through a factory that names no hook type at all,
  which is the path the hazard travels. Each hook's metadata row now records
  the family whose payload the name carries, read off the hook type rather than
  written as a string, and registration compares it against the family the
  handler reports. A CMF handler taking `http.request` or `http.response` is
  refused at load, naming the plugin, the hook, and both families, instead of
  registering and scanning a message nothing filled. Registration stays
  all-or-nothing: a refused name leaves no part of that plugin registered. The
  check is load-time, not compile-time, and it covers what reaches the hook
  index, which is every path a plugin registers through. A host that installs a
  handler with `annotate_route` writes into the route-annotation map instead
  and is not checked there. A row with no family accepts a handler of any
  family, `HookMetadata::permissive()` included, so the open hook registry
  stays open and a host's own hooks need no type of their own. **Breaking for
  Rust callers**: `HookMetadata` carries a third field, and a `define_hooks!`
  row takes an optional `family:` naming the hook type.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **An `args:` or `result:` block on an `http:` route is refused at load.** A
  field stage addresses a path inside a message, and a generic HTTP request
  carries none, so such a stage would read nothing and rewrite nothing. The load
  now fails naming the declaration and the block, and points at
  `pre_invocation:` / `post_invocation:` with the `http.*` attributes instead.
  It covers both scopes that reach HTTP routes and nothing else: a route's own
  `apl:` block and `global.defaults.http.apl`. A `global.apl` carrying `args:`
  still loads, because those stages are meaningful for the entity routes the
  global layer also stacks onto.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **A declared hook name is validated at config load.** `hooks:` carried free strings that nothing checked, so a typo loaded clean and nothing said so. What a typo cost depended on the plugin: a factory that derives its handler names from `config.hooks` (the `audit-logger` and `pii-scanner` reference plugins) registered under the misspelling and never fired, while one that hardcodes its hook name (`identity-jwt`, `delegator-oauth`, `elicitation-ciba`) fired correctly and left the `hooks:` list as decoration that disagreed with reality. Both are now refused, because a `hooks:` entry naming a hook nothing dispatches is a config error either way. An unknown name now refuses the config, naming the plugin, the name, and the nearest name that does dispatch: `tool_pre_invoke` suggests `cmf.tool_pre_invoke`, which is the exact mistake the removed constants and the old `PluginConfig` example taught. A name close to nothing in the table gets no suggestion rather than the least-bad match. **Breaking for existing config** carrying a misspelled or inert hook name. Validation reads the runtime registry, so a host with its own hooks passes once it has registered their metadata — which it must do *before* loading config that names them; registering afterwards is too late and the load refuses. The registry is process-wide while `PolicyEngine` is per-instance, so two engines in one process share one hook table and whichever loads first decides what the second accepts. A config can load under one process layout and refuse under another, such as a host embedding PPE twice or a test binary sharing a process across cases. Register every hook a process uses before loading any config, not only before the config that names them.

- **Both route resolvers take the route already matched.**
  `resolve_plugins_for_entity` and `resolve_identity_plugins_for_route` receive
  the matched route instead of matching a second time, and the identity
  resolver no longer takes an entity type, because a matched route carries the
  one it matched under. The engine used to match once for the annotation lookup
  and again inside each resolver on every cache miss; matching once is also
  what lets the name a request resolved to be the only key the annotation table
  and the route cache ever see, so a request path never becomes a cache key.
  The layering each resolver does (global, entity-type default, group and tag
  bundles, then the route) is unchanged. **Breaking** for Rust callers, of
  which there were none outside this repository's engine; no configuration
  resolves differently.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **`annotate_route` reports whether it replaced a handler.** The annotation
  table was a plain insert, so a second handler at the same `(entity_type,
  entity_name, scope, hook_name)` dropped the first with nothing recording that
  either existed. It now returns whether it replaced one, and the APL visitor
  warns naming the coordinates. The later handler still wins, since a host may
  replace deliberately. **Breaking** for a Rust caller that binds the return
  type; ignoring the value compiles unchanged.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **A path normalizer and a route-resolution error are public surface.**
  `praxis_policy_core::http_path::normalize_match_path` reads a request path and
  refuses one it cannot read: query and fragment removed, semicolon path
  parameters stripped, duplicate slashes collapsed, and `.` / `..` resolved
  including their percent-encoded spellings, with nothing ever percent-decoded
  so an encoded separator stays inside its own segment. Those rewriting rules
  mirror the gateway's `normalize_rewritten_path`, which the gateway applies to
  paths it produced itself and never to an inbound one, and the module names its
  source so the two can be compared. Route matching does not read the value it
  returns, and neither does a policy: `http.path` and `meta.entity_name` reach
  the attribute bag as the host set them, and the normalized form is written
  nowhere. What the function does for the engine is the refusal. A path that
  breaks its rules is denied with the stable code `unreadable_request_path` and
  a `400` wherever at least one `http:` route is declared, because a path PPE
  cannot read is one it cannot claim to have matched the router on. With no
  `http:` route declared, nothing about such a request changes.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **A route key nothing reads fails at load, naming the key and the route.**
  `RouteEntry` ignores unknown fields, so a misspelled selector left a route
  matching nothing and a stale key sat there looking effective. A raw-YAML scan
  now refuses a route key nothing consumes, and `ConfigVisitor` gained a method
  reporting the extra route keys its visitor reads, so an orchestrator's own
  block stays loadable. `deny_unknown_fields` cannot do this job: a route
  mapping legitimately carries `apl:`, `response:`, and the flat APL terms the
  visitor accepts alongside the keys the typed struct models. **Breaking**
  where a route carries a key nothing consumes, which was inert before and is a
  typo either way. A host whose visitor reads route keys of its own must load
  through `load_config_yaml`: `parse_config` and `load_config(path)` register no
  visitor, so they scan with the built-in list alone.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **Config validation runs on every load path.** `PolicyEngine::load_config` and `from_config` take a pre-built `PolicyConfig` and ran neither `validate_config` nor the top-level `groups:` merge, so a host building its config in Rust got no duplicate-plugin-name check, no route-shape check, and no group resolution — routes silently lost the plugins and `authentication:` their group was meant to supply. Both now normalize and validate the way the YAML paths do. **Breaking**: a programmatic config with a duplicate plugin name, a malformed route, an unknown hook name, or a route naming a plugin absent from `plugins:` now fails where it previously loaded with the offending piece inert. That last case reaches a host that registers handlers with `register_handler` instead of declaring them under `plugins:` and then names them in a route.

- **`hooks::metadata::lookup` returns `Option<HookMetadata>`.** It used to substitute a wildcard for a name the registry did not hold, so an absent hook and a deliberately unphased one both read as `Unphased` and a caller reading phase could not tell a missing entry from a real one. `HookMetadata::unknown()` is renamed `permissive()` to match: the wildcard is now a default a caller opts into, not the shape of a failed lookup. **Breaking** for Rust callers; `lookup(name).unwrap_or_else(HookMetadata::permissive)` restores the old behavior exactly.

- **`Plugin::initialize_with` is what the engine calls.** It receives the host services the plugin's capabilities allow, and its default forwards to `initialize`, so a plugin needing nothing from the host is untouched. Override exactly one: the default body of `initialize_with` is what calls `initialize`, so overriding it replaces that call.

- **`identity-jwt` refreshes JWKS on demand instead of on a timer**, and `min_refresh_interval_secs` (default 30) is a new knob bounding how often one issuer may re-fetch. `refresh_secs` keeps its meaning as the staleness bound. See the fix below for why the timer went.

- **Unknown keys in the JWT plugin's config are rejected.** The resolver config and each `trusted_issuers` entry default every field, so a misspelling took effect silently, and a misspelled `audiences` turned audience checking off. **Breaking** for a config carrying a key the plugin does not read. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **A SPIFFE ID with no trust domain is refused.** `spiffe:///ns/default/sa/agent` carries the scheme but no authority, so it named no trust boundary and the mapper still filed it as a workload identity whose trust domain was the empty string. It now declines, the same as any other non-SPIFFE subject, and a valid candidate behind it still resolves. **Breaking** for a deployment minting such a token, which was never a valid SPIFFE ID. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **A workload's trust domain is no longer mappable.** It is the authority of the SPIFFE ID, so it is derived from the identity rather than read from a claim. ([#31](https://github.com/praxis-proxy/policy/pull/31))

### Removed

- **The `hooks::types::hook_names` and `hooks::types::cmf_hook_names` modules.** Sixteen `pub const`s that no dispatch site read. Six of `hook_names` shadowed CMF hooks under names nothing fires; two spelled identity and delegation `identity_resolve` / `token_delegate`, which no handler answers to. `cmf_hook_names` duplicated `cmf::constants` and got the prompt pair wrong, teaching `cmf.prompt_pre_fetch` where the dispatched name is `cmf.prompt_pre_invoke`. Because nothing consumed them they drifted unnoticed for months. **Breaking**, with no replacement needed: `praxis_policy_core::cmf::constants` holds the CMF names and is the supported import path, alongside `identity::HOOK_IDENTITY_RESOLVE`, `delegation::HOOK_TOKEN_DELEGATE`, and `elicitation::HOOK_ELICIT`. Those constants keep their paths and their values. The values are operator-facing, since a `hooks:` list in YAML names them as strings, so they are fixed as public API rather than free to rename.

### Fixed

- **Normalizing a request path that carries a query allocates nothing.** The query and the fragment are dropped by taking a shorter borrow of the request line, but the check for whether the path needed rewriting ran on the raw path, so the `?` and the `#` it found there forced the owned branch and every request carrying a query string paid for a rewrite with nothing to do. The check now runs on the path the borrow covers, so `/v1/files/q3.pdf?page=2` borrows the way `/v1/files/q3.pdf` already did. A path that still needs its dot segments resolved, its duplicate slashes collapsed, or its path parameters stripped is owned as before. Normalized paths are unchanged, except that a trailing slash sitting in front of a query is now kept the way `/a/` already kept its own.

- **Resolving an HTTP route's name stops cloning the selector's path list.** The name a request resolves to is what keys the annotation table and the route cache, so it has to be computed before either lookup, and computing it rendered a name for every path the selector declares and kept one. A twenty-path selector cost twenty discarded names per matching route per request, cached requests included, and a prefix selector built a one-element list for an answer that is a single rendered string. The scan now hands back the declared path it matched by borrow and renders only that name. The names themselves are unchanged: the names a route is annotated under and the name a request resolves to render through the same two functions, so neither can drift from the other. No configuration or behavior changes.

- **The unreachable-authentication check stops walking the route table on every request.** The warn-once latch was only set when the scan found something to report, so the ordinary configuration, where no `http:` route declares `authentication:`, rescanned the route table on every identity-hook invocation that carried no readable path. Which routes can lose their list depends only on the configuration, so the answer is now computed once when a config lands and the request path reads it. A reload recomputes it, so the warning keeps naming the routes the current configuration declares. No configuration or behavior changes.

- **A stale `policy:` on a route reports the rename, and a route's bad keys are reported together.** The route-key scan runs before any visitor and did not know the pre-rename names, so a route carrying `policy:` failed with an unknown-key error listing every key a route accepts rather than the message naming `authorization.pre_invocation`. The rename check now runs first, off the same table the APL visitor reads. The scan also collects every unrecognized key on a route and names them in one error, so three typos take one load to find rather than three. A stale key still fails the load, which is what keeps a dropped authorization block from failing open.

- **HTTP route matching runs on the request path as given.** It normalized the path first, and compared an exact path with one trailing slash treated as insignificant, so PPE could resolve a different route than the one the request is forwarded to. The gateway's router normalizes nothing: it matches on `ctx.rewritten_path` or `ctx.request.uri.path()`, and its exact arm is a byte compare. So `/v1/files/../healthz` resolved the `/healthz` route here while the gateway sent the request to the `/v1/files` cluster, and whatever `/v1/files` authenticates was dropped for it. Matching now uses the path the host supplied and compares an exact path byte for byte, which is how PPE applies the policy of the route the traffic actually goes to. **An exact route no longer matches a trailing-slash spelling of its path**: `http: /admin` answers for `/admin` and not for `/admin/`, a route declared `"/admin/"` answers for `/admin/` and not for `/admin`, and a deployment needing both declares both. Two routes declaring the two spellings now load rather than being refused as one name, and each is annotated under the path it was written as. Prefix matching is untouched and still agrees with the gateway's own `path_prefix_matches`, so a prefix route keeps matching `/api`, `/api/`, and `/api/v1`. The path normalizer still runs as a fail-closed guard, so an unreadable path is denied exactly as before.

- **Two routes narrowed by the same method in different case are refused at load.** Method matching ignores ASCII case, but the rendered route identity did not, so `method: GET` and `method: get` on one path passed the duplicate check and both matched every request, with the first declared silently winning. The identity now uppercases the method set before sorting it, so the two spellings are one name and the load fails naming both routes. A config carrying both stops loading, and a lowercase `method:` renders its name uppercase.

- **A route narrowed by `method:` now outranks the same path left open.** The narrowing gated the match without scoring, so two routes on one path resolved by declaration order: a broad `path_prefix: /api` written above `{path_prefix: /api, method: DELETE}` took the `DELETE` request, and swapping the two lines changed which policy ran. A present `method:` now adds to the score, below the per-character prefix weight so it breaks a tie within one path rather than reordering two paths, and below the scope bonus so a scoped route keeps winning its own scope. A configuration that pairs a broad route with a method-narrowed one moves those methods to the narrower policy.

- **A declared `http:` path that is not absolute is refused at load.** Matching reads the request path as given, so a selector whose path does not start with `/` can never match, and seven shapes of it loaded as dead routes with no signal at all. A bare path, a list element, `path:`, and `path_prefix:` are all checked now, and the error names the route and the path it read. A config declaring one stops loading; write the path with its leading slash.

- **A route can no longer claim the reserved catch-all name.** A route declaring `http: "*"` rendered `*` as its name, which is the name the entity-less catch-all policy is annotated under, so the route matched no request while its policy body governed every request that resolved no route, and it displaced the global `response:` block on the way. A route whose rendered names include the reserved name is now refused at load. The check reads the names the route contributes, so it covers every selector shape rather than the one spelling, and it runs whether or not routing is enabled, because the engine consults the annotation table either way.

- **An `http.method:` value that is not a method token is refused at load.** Methods are compared literally and there is no glob dialect, so `method: 'GET*'` matched nothing, and neither did a typo carrying a space or a slash. A value must now be an RFC 9110 token, with `*` excluded because it reads as a glob, and the error names the route and the value. An extension verb such as `PROPFIND` or `M-SEARCH` is unaffected.

- **Two routes narrowed by `method:` on one path no longer tie.** The narrowing scored a flat bonus whatever its method set held, so `{path: /a, method: [GET, POST]}` written above `{path: /a, method: GET}` took the `GET` request and the narrower policy never ran, with the declaration order deciding which one did. It failed in the fail-open direction, since the route that lost was the narrower one. The bonus now scales with how many methods the selector names, so one method outranks two on the same path, which is how the gateway's own router breaks a tie between equal paths: by counting constraints. The whole bonus still sits under the scope bonus, so a scoped broad route keeps winning its own scope, and far under the per-character prefix weight, so prefix length still decides between two different paths. A config pairing a wide narrowing with a narrow one moves the methods they share to the narrower policy.

- **A body-less `http:` route no longer silences the response half.** A route whose effective layers declare only pre-phase steps installed a post handler that ran nothing, and that empty handler short-circuited the response-side plugin chain, so a configuration gained a catch-all `http:` route and lost whatever governed the way out. Each half now installs on the route path only when the route declares steps for it, which is the rule the global catch-all already applies.

- **An entity route's post-half plugins begin running.** The same missing guard covered `tool:`, `llm:`, `prompt:`, and `resource:` routes: a route listing `plugins:` alongside a policy body that declares only pre-phase steps installed an empty post handler that suppressed those plugins, so a plugin the operator wrote onto the route never ran on the post half. It runs now, so a plugin that denies there begins denying a call that previously passed. Check what the post-half plugins on such a route do before upgrading.

- **Concurrent registration no longer loses plugins.** Every mutation of the engine's runtime snapshot was a load, clone, store with nothing serializing writers, so two threads that loaded the same snapshot each published their own copy and the last write discarded the other silently. A test putting sixteen threads through `register_handler` at once kept one plugin, and all sixteen calls returned `Ok`. Writers now serialize on a mutex held across the copy-on-write, covering `load_config`'s inline swap as well; the read path is untouched and still lock-free, and the generation counter still bumps exactly once per published mutation. Nothing in the workspace registers concurrently today, so no shipped configuration was affected, but registration takes `&self` on an `Arc`-shared engine and a host is free to call it from any thread. Neither that mutex nor the factory-registry `RwLock` is reentrant, so `load_config` now runs every `PluginFactory::create` holding neither: it resolves the factories, releases the registry lock, instantiates, and only then takes the writer lock for the registry clone and the swap. A factory that calls back into `register_handler`, `annotate_route`, `unregister_plugin`, or `register_factory` while being built would otherwise block on a lock its own caller was holding. Whatever such a factory registers on its way through is picked up by the clone rather than discarded by it. The two route-override paths already released the registry lock before `create` and are unchanged. `mutate_runtime` and `try_mutate_runtime` likewise release the writer lock before the snapshot they replaced goes out of scope: that snapshot usually holds the last reference to whatever the mutation discarded, and a plugin or annotation handler's `Drop` is host code too, so `remove_route_annotation` on a handler that called back would have blocked on the lock its own release was holding. A rejected `load_config` is the same story from the other end: the plugins its factories just built have nowhere else to live, and the registry drops the one whose name collided while the entries behind it are never registered at all. Registration now borrows the instances and hands the registry `Arc` clones, so the load keeps the last reference to every one of them and releases the lock before letting go. ([#23](https://github.com/praxis-proxy/policy/issues/23))

- **Three dispatched hooks had no routing metadata.** `http.request` and `elicit` were absent from the table entirely, so `lookup` reported them unphased and a consumer deriving request-versus-response direction from a hook's phase got neither for the L7 path. It never surfaced because the matcher treats an unphased hook as matching every context, so dispatch kept working while the phase it reported was wrong. All three, `http.response` included, now carry the phase and entity type they are installed under, and a test holds the table to what the dispatcher does. **This narrows dispatch as well as correcting it**: a hook with no row matched every entity type and every phase, so a plugin registered under `http.request` used to dispatch for `tool`, `llm`, `prompt`, and `resource` requests too. It now dispatches only for `entity_type: http` in the request phase. A deployment relying on that accidental reach registers the plugin under the hooks it actually serves, or restores the old behavior for that one name with `register_hook_metadata(HOOK_HTTP_REQUEST, HookMetadata::permissive())` at startup. `permissive()` is `phase: Unphased`, which is what makes it match every phase, so a hook registered that way reports `false` from both `is_pre` and `is_post`. A host that wants the phase reported rather than the reach restored writes the row out: `HookMetadata { family: Some(HttpHook::NAME), entity_type: Some(ENTITY_HTTP), phase: HookPhase::Pre }`.

- **`MessageView::is_pre` and `is_post` were a second phase authority that disagreed with the first.** Both matched the hook's name against a substring, so four of the ten phased hooks answered `false` to both: `cmf.llm_input` and `http.request` are `Pre` and contain no "pre", `cmf.llm_output` and `http.response` are `Post` and contain no "post". The policy-visible `is_pre` / `is_post` fields of `to_dict` carried that. Both now read the metadata registry that dispatch reads, so a hook is pre-phase because it is registered that way. A host hook named `express_lane` no longer reads as pre-phase, and an unregistered name reports neither. Nothing outside `MessageView` read these, so this reaches plugin authors rather than a shipped path.

- **Subject claims keep their JSON shape.** `SubjectExtension.claims` holds `serde_json::Value` and flattens into the attribute bag through `payload::walk`, so Keycloak's nested `realm_access.roles` is a `StringSet` a policy can test instead of one opaque string. Client claims always worked this way. **Breaking** for Rust callers reading `claims`; `SubjectExtension::claim_str` covers the scalar lookups. Scalar policies such as `claim.tenant == 'acme'` are unaffected, but a structured claim now sets only the flattened children beneath `claim.<name>`, not the key itself, and a claim whose value is `{}` or `null` sets no key at all where it previously landed as stringified text. ([#9](https://github.com/praxis-proxy/policy/pull/9))

- **A scalar array reaches the bag as a `StringSet` instead of no key.** `payload::walk` emitted nothing for `[]` or for any array holding a number or bool, so a user with no realm roles had no `claim.realm_access.roles`, and a provider minting `"group_ids": [1, 2]` had none of those either — a missing key is a CEL error that fail-closed handling denies. Numbers and bools now render as strings, so `claim.group_ids contains "1"`, matching how a float claim is carried through Cedar. An array holding a nested array or object still sets no key. Applies to `args.*`, `result.*`, `data.*` and `client.claim.*` too. ([#9](https://github.com/praxis-proxy/policy/pull/9))

- **A float claim no longer denies every request through a Cedar step.** Cedar has no floating-point type, and a claim arrives in whatever shape the `IdP` minted, so a float claim is carried as its string form rather than rejected. Operator-authored `resource.attributes` still rejects one and names the key. ([#9](https://github.com/praxis-proxy/policy/pull/9))

- **JWKS rotation was silently dead under any host that dropped the runtime it initialized on.** `identity-jwt` spawned a background refresh ticker during `initialize()`, and `tokio::spawn` binds a task to whichever runtime is current — so a host driving async initialization on a short-lived runtime (a sync filter factory does exactly this) had that task cancelled before it ticked once. Nothing errored and nothing logged; the task simply stopped existing.

  Two consequences, both permanent until a restart. A key roll denied every token signed with the new key. Worse, the deliberate soft-fail-at-boot became permanent-fail-at-boot: a brief `IdP` outage during startup denied an issuer indefinitely, so a rolling restart during `IdP` maintenance was enough to trigger it.

  Refresh now happens on the verify path, triggered by the two failures whose cause is stale keys, single-flighted per issuer and floored by `min_refresh_interval_secs` — the floor matters because an unknown `kid` is reachable with an unauthenticated request and would otherwise be an amplification attack on your own `IdP`. Rotation now recovers on the first token that needs the new key rather than at the next tick, and a failed boot fetch recovers on the next request. ([#29](https://github.com/praxis-proxy/policy/issues/29))

- **An empty set no longer reads as a missing attribute.** Every `StringSet` the CMF bridge emits is now present-but-empty instead of omitted. Under CEL a missing key is an evaluation error that fail-closed handling turns into a denial, so `"x" in subject.roles` denied every subject that had no roles — a routine state, since a plugin without `read_roles` is handed an empty set. Does not cover an absent extension slot, where the namespace is missing entirely. ([#7](https://github.com/praxis-proxy/policy/pull/7))

## [0.1.0] - 2026-08-14

First release. The engine was extracted from another project rather than written
here, so this entry records what moved, what changed on the way, and what the
public surface now is.

### Added

- **The policy engine, ported from [`contextforge-org/cpex`](https://github.com/contextforge-org/cpex) with history intact.** Extracted with `git-filter-repo` at source commit `aed0f15`, 192 files across 37 filtered commits, so `git log` and `git blame` reach back before this repository existed. The Rego decision point came in a second pass from `fa222c4`. [`docs/port-provenance.md`](docs/port-provenance.md) records both anchors, which is what any later comparison between the two trees needs.

- **`praxis-policy`, a host facade.** One dependency instead of a dozen. It re-exports the runtime (`PolicyEngine`, `AplOptions`, `register_apl`) and owns registration of the bundled extensions, each behind its own feature. `default` is empty, so the bare dependency is the engine alone with nothing extra compiled in; `builtins` turns on the whole set, or name a subset (`jwt`, `oauth`, `elicitation-ciba`, `cedar`, `cel`, `opa`, `valkey`).

- **Three decision points, selectable per route.** Cedar policy sets (`cedar:`), inline CEL expressions (`cel:`), and embedded OPA/Rego via regorus (`opa:`). One binary serves all three; a route picks one with a step.

- **Bundled extensions:** multi-source JWT identity, RFC 8693 OAuth token delegation, out-of-band human approval over OIDC CIBA, and a Valkey-backed session store for taint that survives a restart.

- **Sensitive headers never reach a decision point.** `Authorization`, `Cookie` and `X-API-Key` are stripped from the projection a PDP receives, matched case-insensitively because headers arrive in whatever case the client sent. For a remote PDP that projection crosses the network, so this is the difference between consulting a policy service and handing it a bearer token.

- **A documented path for plugins the engine does not bundle.** Implement `PluginFactory` against `praxis_policy_core::prelude` and register it with `PolicyEngine::register_factory` under the `kind:` your policy names. An unrecognised `kind` fails at load, so a missing registration is a startup error naming the kind rather than a plugin that silently never runs. The prelude's doc example is compiled, not `ignore`d, so it cannot drift from what a plugin actually needs.

### Changed

- **Renamed to the Praxis Policy Engine throughout,** crates, types and docs. Deliberately unchanged: the policy document format, the `kind:` strings an operator writes, and the violation codes a client sees. Those are the surface a deployment depends on, and `crates/ppe-core/tests/wire_compatibility.rs` pins them against a document authored before the rename.

- **Edition 2024 and resolver 3,** with the MSRV pinned to the same toolchain the formatter and coverage run on, so there is one Rust version to reason about.

- **Six core crates instead of eight.** `praxis-policy-sdk` became `praxis_policy_core::prelude`: every name in it was already re-exported from core, so the separate crate offered a curated namespace and no dependency saving, which a module provides without a second crate to version. `praxis-policy-builtins` folded into the facade, because the feature list, the factory re-exports and the registration table all describe one set and can disagree when split across two crates.

- **The PII scanner and audit logger are no longer published or bundled.** They live under `reference/plugins/` as worked examples a host registers itself. The scanner is regex matching with no Luhn check, and the logger writes to stderr; neither is something a policy engine should ship as supported, and both are what a deployment will want to replace. **This is breaking** for anyone who had `features = ["pii"]` or `["audit"]`, or who named `PiiScannerFactory` / `AuditLoggerFactory`: register the factory instead.

### Fixed

- **A float in a Cedar attribute source denied every request through that step.** Cedar's value model has no floating-point type, so `attributes: { score: 1.5 }` failed entity construction with a message that named neither the attribute nor the reason. It now reports which key holds the float and what to supply instead. The same walker covers the operator-authored resource block.

- **A quoted argument containing a lone quote aborted the policy parser** instead of being read as a literal.

- **Branch outcomes are keyed rather than positional,** so a concurrent effect's result can no longer be attributed to the wrong branch.

### Security

- **`nbf` is now enforced on inbound JWTs.** `validate_nbf` is off by default in jsonwebtoken, unlike `validate_exp`, and nothing turned it on. The module documented `auth.token_not_yet_valid` as a stable code and mapped `ImmatureSignature` to it, but that error could never be produced, so a token whose own issuer said it was not valid until later was accepted the moment it was minted. Enforced under the same leeway that already covers `exp`, so ordinary clock skew is still tolerated. A deployment whose IdP deliberately mints a future `nbf` will start seeing that code.

- **An issuer accepting no signature algorithms now rejects every token from it,** rather than treating the empty list as "any algorithm is acceptable" and handing algorithm choice to whoever minted the token.

### Internal

- **Line coverage at 95%,** gated in CI by `COVERAGE_FLOOR` so it cannot silently regress. The `nbf` gap and the Cedar float defect both surfaced while writing those tests, which is the argument for the exercise.

- **191 lint rules configured across rustc, clippy and rustdoc,** every one at an explicit level. Anything that could silently change an enforcement decision is denied; [`docs/lints.md`](docs/lints.md) explains each group that is not.

[Unreleased]: https://github.com/praxis-proxy/policy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/praxis-proxy/policy/releases/tag/v0.1.0
