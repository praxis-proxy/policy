---
issue: https://github.com/praxis-proxy/policy/issues/152
discussion: >-
  Design for embedding the limitador crate as an in-process
  request-rate-limiting plugin. PPE config and API claims are cited to this repo;
  the crate's API to its published docs (exact signatures confirmed in the PoC).
  Related to the Kuadrant compatibility work (00130, 00133).
status: proposed 
authors:
  - maleck13
graduation_criteria:
  - A net-new `ratelimit/limitador` plugin is specified. Its kind, hook point, config schema, and the attribute-bag → Limitador context mapping, each cited to this repo or the crate.
  - The reason request-rate limiting is a standalone plugin (not folded
    into existing metering) is stated.
  - The storage model is specified in-memory for the spike, host-injected shared storage (redis-like) as the production path, with the plugin constructing no network connection of its own.
  - Verification is specified at two tiers. In-process PPE tests cover native
    attributes, global and route-level policy placement, limiter logic, and
    the deny's `proto_error_code` and HTTP status detail; an end-to-end run against `praxis-ai`
    confirms a real request returns a real 429.
  - An HTTP-only limiter inherited by an MCP or LLM route is rejected at
    startup. Request admission for an entity-aware gateway has one defined
    HTTP request boundary.
stakeholders:
  - araujof
  - terylt
---

# Limitador rate-limit plugin (embedded crate)

## What?

A net-new PPE plugin, `kind: ratelimit/limitador`, that embeds the
[`limitador`](https://crates.io/crates/limitador) crate (v0.13.0) to enforce
**authenticated, application-level request-rate limits** inside the policy
filter. It runs on the `http.request` hook after identity resolution, builds a
Limitador evaluation context from PPE data, and calls Limitador's
`check_rate_limited_and_update` to admit or refuse the request. The target is
parity with Kuadrant `RateLimitPolicy` semantics (N requests per window,
selected by conditions over identity and request attributes).

Scope is **application and authenticated** rate limiting — limits keyed on who
the caller is and what they are doing, applied after identity resolution.
Infrastructure / network-layer rate limiting is out of scope (see Non-goals).

The spike uses Limitador's in-memory storage. The production path is a shared
(redis-like) store whose connection is **injected by the host**, not built by
the plugin.

The first PoC is deliberately narrower than the compatibility target: it
builds a PPE attribute bag from the plugin's capability-filtered Extensions,
then binds native `subject.id` and `http.method` to Limitador CEL variables.
A test also binds `claim.plan` to prove the mapping is configurable. This
proves the plugin and counter path before Kuadrant attributes are available.
Another test runs separate limiter instances from `global` and an HTTP route,
showing both policy scopes with PPE-native attributes. See
`crates/builtins/src/plugins/ratelimit/README.md` for its runnable config.
The in-process header-binding test uses a caller-controlled header to exercise
the same scopes without an identity plugin; it is not an authenticated identity
source. A real HTTP gateway check remains future work.

### Why?

- PPE already resolves identity and builds an attribute bag. Keying rate limits
  on authenticated identity is cheap here and avoids a second filter that would
  re-resolve well-known attributes and re-handshake identity across a filter
  boundary.
- Limitador is embeddable (the crate exposes CEL conditions and pluggable
  storage), so this validates reusing an upstream Kuadrant component in-process
  rather than as a network dependency.
- Limitador's distributed mode uses a redis-compatible store, which PPE already
  supports — the `session::valkey` builtin runs against the same kind of
  backend.
- It answers an open architectural question: does a **stateful counter** fit
  PPE's plugin/effect model, which otherwise forbids background tasks and
  plugin-owned network connections?

### Goals

- One plugin that enforces request-rate limits from PPE config.
- Prove alice/bob request limits using PPE-native variables first, then
  reproduce a Kuadrant `RateLimitPolicy` through the compatibility mapping.
- Keep the plugin free of background tasks and self-constructed network
  connections (storage is host-injected), consistent with the quota plugin's
  host-transport rule.

### Non-goals

- Token/cost budgets at this stage (future work). That is the existing `quota/limitador` plugin's job; this plugin counts requests, not tokens.
- A production-grade shared-store deployment. The spike proves the mechanism
  with in-memory storage; the host-injected store is specified but not built.
- Infrastructure / network-layer rate limiting — per-IP throttling, global
  request floods, L3/L4 edge protection, DoS mitigation. Those belong at the
  gateway or a dedicated infrastructure limiter. This plugin keys on the authenticated caller, so it runs after identity resolution and does not see unauthenticated edge traffic.

## Design

### Plugin shape

Mirrors the quota plugin's structure
(`crates/builtins/src/plugins/quota/`):

- `KIND = "ratelimit/limitador"` — namespaced so other rate-limit backends
  could register alongside.
- `PluginFactory::create(&PluginConfig) -> Result<PluginInstance, Box<PluginError>>`
  builds one shared core (holding the `RateLimiter` and parsed limits) and
  registers a single handler on `HOOK_HTTP_REQUEST`
  (`crates/ppe-core/src/http_hook.rs:40`, `"http.request"`, `HttpHook`
  family, `Pre` phase) via `TypedHandlerAdapter::<HttpHook, _>`.
- Gated behind its own cargo feature in `crates/builtins`, `experimental`
  stability, consistent with quota.

### Global and route-level policy placement

The PoC declares one limiter under `global.authorization.pre_invocation` and
a second under an `http: /toys` route. A root-prefix route catches other HTTP
paths. APL runs the global step on all matching requests and adds the route
step only on `/toys`; each configured plugin instance keeps its own counters.
The in-process test proves a global denial on `/other`, a route denial on
`/toys`, and an allowed request outside the route. Route selection uses APL's
HTTP path matcher; it does not add route-only bag attributes to the plugin's
Limitador context. These examples contain HTTP routes only.

### Entity-aware gateway admission

`ratelimit/limitador` registers only on `http.request`. APL inherits a global
`run(name)` step into `tool:` and `llm:` routes, whose policy evaluation uses
CMF hooks. The current gateway runs its HTTP authorization path only for a
pure HTTP policy; with entity routes it gates identity on the request headers
and evaluates the entity policy after classification. Putting a global HTTP
limiter and an entity route in one policy document would dispatch the limiter
under the wrong hook. The APL config visitor now checks the plugin's actual
registered handlers against each effective route at load time and rejects that
combination before serving requests.

The current gateway can run two policy filters in order: an HTTP-only limiter
policy first, then a separate MCP or LLM policy. The first filter evaluates
`http.request` once per incoming request, and its admission marker prevents a
second count if the body callback runs. The entity policy has no inherited
limiter step. For MCP, the classifier runs before the entity policy filter.
Authenticated limits must resolve the subject in the first filter; the PoC's
`X-Demo-User` header is only a local smoke-test selector.

A single-filter implementation would need an explicit ingress HTTP admission
stage after identity resolution and before entity dispatch, plus policy
layering that does not copy that ingress step into the entity route. Merely
registering the limiter on CMF hooks would count entity invocations, not
necessarily HTTP requests, and does not provide once-per-request admission.

### Flow (per request, on `http.request`)

1. Handler receives an empty `HttpPayload` and capability-filtered
   `Extensions`. The latter carries the resolved identity and the HTTP
   request line; `read_headers` is required to see the HTTP extension.
2. Build a plugin-local PPE attribute bag using the shared `BagBuilder` on
   those filtered Extensions. Configured bindings select string-valued bag
   keys such as `subject.id`, `http.method`, and `claim.plan` for Limitador's
   flat CEL context. Missing or non-string bound attributes deny the request.
3. Call `rate_limiter.check_rate_limited_and_update(namespace, &ctx, 1, false)`
   under an async mutex shared by the plugin instance. Limitador applies its
   own CEL `conditions` to pick matching limits. The mutex serializes the
   in-memory check and update across concurrent requests to this instance.
4. If limited, return `PluginResult::deny(PluginViolation::new(code, msg))`
   (`crates/ppe-core/src/hooks/trait_def.rs`) with `proto_error_code: 429` and
   `details["http.status"]: 429`; otherwise `PluginResult::allow()`.

### Attribute mapping

Limitador 0.13 evaluates its **own** CEL over a context the plugin supplies.
The PoC uses the same extension-to-bag mapping as APL for PPE-native
attributes, but builds a local bag because APL's route-level bag is not passed
to plugins. Limitador's public context accepts flat string variables, so
`bindings` map dotted PPE bag keys to simple CEL variable names.

In the compatibility stage, the plugin would populate its context from the
shared compatibility mapping. Translating
raw identity claims and request fields into Kuadrant well-known names
(`auth.identity.*`, `request.*`) is owned by the compatibility layer
(`engine_settings.kuadrant_compat: true`, 00130 Approach A; the mapping itself
fixed by 00133). Reusing it would keep one source of truth and avoid a second
map in this plugin.

That is the compatibility target. The current APL bag is built inside the
route handler and is not passed to the plugin, so its route-only `route.key`
and `data.*` attributes are absent from the plugin-local bag. A later
integration must reuse the shared compatibility mapping when it lands.

Consequence: running a Kuadrant `RateLimitPolicy`'s conditions verbatim depends
on that compat layer being enabled, so the bag already carries the WKA-shaped
attributes the conditions reference. What is unresolved is whether those
compat-mapped names are visible to a plugin at the `http.request` hook, or only
the raw identity and request fields are; the later compatibility integration
must answer this (see Open questions). See
[00133](00133_kuadrant-authpolicy-attribute-mapping.md).

### Storage

- **Spike:** Limitador in-memory storage (`RateLimiter::new(capacity)`).
  Per-replica counters, lost on restart. Acceptable for proving the mechanism;
  not shared limiting. A plugin-local async mutex prevents concurrent requests
  to one instance from over-admitting during the in-memory check/update.
- **Production:** the `limitador` crate supports a redis-like backend
  (`RedisStorage` / `AsyncRedisStorage`). The connection/storage handle is
  **injected by the host** through `Extensions` and passed to the plugin, the
  same ownership model the quota plugin uses for the host HTTP transport. The
  plugin constructs no connection, owns no pool, and runs no background task.
  The in-memory vs shared choice is then a host wiring decision, not a plugin
  rewrite.

### Config schema (illustrative compatibility target)

```yaml
plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [http.request]          # registered in code; declarative only
    capabilities: [read_subject, read_claims]
    config:
      namespace: toystore
      limits:
        - max: 5
          seconds: 10
          conditions: ["auth.identity.userid == 'alice'"]
          variables: []
        - max: 2
          seconds: 10
          conditions: ["auth.identity.userid == 'bob'"]
          variables: []
```

Each `limits[]` entry maps to `Limit::new(namespace, max, seconds, conditions,
variables)`. Typed config with
`#[serde(deny_unknown_fields)]` and a `validate()` at construction, matching
`QuotaConfig`.

### Capabilities

- `read_subject` — to expose `subject.id` to the plugin-local bag.
- `read_claims` — needed when a binding reads a `claim.*` attribute, as in
  the PoC's `claim.plan` test.
- `read_headers` — required to read `HttpExtension`, including method and path.
- No `perform_http`: in-memory storage makes no outbound call. A host-injected
  shared store reaches the network through host-owned machinery, so the
  capability story there is a host concern, resolved when that path is built.

## Worked example (the PoC target)

A Kuadrant `RateLimitPolicy` targeting the `toystore` HTTPRoute: alice gets
5 req / 10 s, bob gets 2 req / 10 s, selected by
`auth.identity.userid == 'alice' | 'bob'`. The first PoC instead uses
PPE-native `subject_id` conditions. A resolved `subject.id` is not guaranteed
to equal an `auth.identity.userid` claim. Its in-process PPE test proves the 6th
alice request and 3rd bob request within the window are refused and that the
denial carries `proto_error_code: 429` and `details["http.status"]: 429`.
The separate in-process header-binding test uses a caller-controlled
`X-Demo-User` header to check the native attribute path. A later gateway test
will check it on real HTTP requests, and the compatibility stage will run the
original Kuadrant conditions.

## Alternatives considered

- **Second backend under the quota plugin.** Rejected: request-rate limiting
  has no debit phase, uses the `http.request` hook not `cmf.llm_*`, and selects
  via Limitador CEL rather than a single descriptor, so it does not fit quota's
  `check`+`report` backend trait. The shared asset is the `limitador` crate,
  not a plugin surface.
- **Remote-only.** Rejected for the spike: #152 asks whether *embedding* the
  crate works. The host-injected shared store keeps a distributed deployment
  open without a network client in this plugin.
- **Design a full storage abstraction up front.** Partially adopted: the
  host-injected handle *is* the abstraction, but the spike builds only the
  in-memory arm. 

## Open questions

1. **Wire-status rendering of 429.** The current `praxis-proxy-filter` 0.7.3
   generic-HTTP adapter reads `details["http.status"]` when choosing the HTTP
   response status; it does not use `proto_error_code` for that path. The PoC
   sets both fields, and its in-process test asserts both. A live gateway run
   is still needed to confirm a real 429 and
   `X-Policy-Violation: ratelimit.exceeded` end to end.
2. **Host storage-injection API.** The exact `Extensions` seam for passing a
   `limitador` storage/`RateLimiter` handle from host to plugin is not yet
   designed; the spike uses an in-process in-memory instance.
3. **Compat-mapped attribute visibility.** Whether the Kuadrant WKA names the
   compat layer produces (`auth.identity.*`, `request.*`) are reachable by a
   plugin at the `http.request` hook, or only the raw identity and request
   fields are. This decides whether a `RateLimitPolicy`'s conditions run
   verbatim or need the bag's native names.

## PoC plan

Verification proceeds in three stages. Steps 1–3 are implemented in-process;
steps 4–5 remain future work.

1. Add the `limitador` crate (in-memory feature) and a minimal
   `ratelimit/limitador` plugin behind an experimental feature.
2. Wire the `http.request` handler: capability-filtered Extensions → PPE
   attribute bag → configured string bindings → Limitador context →
   `check_rate_limited_and_update` → allow/deny, setting
   `proto_error_code = 429` and `details["http.status"] = 429` on a limited
   deny.
3. **In-process PPE test (in-repo):** fire N `http.request` invocations through
   the engine with injected identity; assert the limiter counts, selects the
   right limit by CEL, passes a `claim.plan` bag attribute through a configured
   binding, and that the deny violation carries `proto_error_code == 429` and
   HTTP status detail 429.
   Exercise both `global` and route-level `run(name)` placement, including a
   request outside the route. Reject inherited HTTP-only limiter steps under
   `tool:` and `llm:` routes at startup. No gateway or network.
4. **Real HTTP verification (against `praxis-ai`):** build the gateway with this
   PPE worktree and `experimental-ratelimit`, then check allowed requests,
   global and route limits, and an on-wire 429. A local smoke policy may bind
   `http.request_headers.x-demo-user` solely as a test selector. The live
   gateway run is still needed; local demo scripts are outside this PoC.
5. **Kuadrant compatibility:** after the shared mapping is available, run the
   original `auth.identity.*` conditions with authenticated requests and
   compare the behavior with `RateLimitPolicy`.

## References

### Verified (this repo)

- `crates/builtins/src/plugins/quota/` — factory, config, backend trait,
  README; the structural template this plugin mirrors.
- `crates/ppe-core/src/http_hook.rs:40` — `HOOK_HTTP_REQUEST` / `HttpHook`.
- `crates/ppe-core/src/hooks/trait_def.rs` — `PluginResult::{allow,deny}`.
- `crates/ppe-core/src/error.rs` — `PluginViolation`, including
  `proto_error_code` and structured `details`.
- `crates/builtins/src/plugins/quota/handlers.rs:343` — precedent:
  `.with_proto_error_code(429)` on an over-budget deny.
- `crates/ppe-apl-runtime/src/visitor.rs` — plugin chain-deny from a route step.
- [00130](00130_kuadrant-adapter-compatibility.md),
  [00133](00133_kuadrant-authpolicy-attribute-mapping.md) — Kuadrant
  compatibility and attribute mapping.

### Unverified (external)

- `limitador` v0.13.0 (crates.io / docs.rs) — shared-storage integration
  remains unverified by this PoC.
- Kuadrant `RateLimitPolicy` semantics and the toystore example (Kuadrant docs).
