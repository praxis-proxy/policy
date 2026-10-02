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
  - The storage model is specified: in-memory for the spike, host-injected shared storage (redis-like) as the production path, with the plugin constructing no network connection of its own.
  - Verification is specified at two tiers: an in-process PPE test for the
    limiter logic and the deny's `proto_error_code`, and an end-to-end run
    against `praxis-ai` confirming a real request returns a real 429.
stakeholders:
  - araujof
  - terylt
---

# Limitador rate-limit plugin (embedded crate)

## What?

A net-new PPE plugin, `kind: ratelimit/limitador`, that embeds the
[`limitador`](https://crates.io/crates/limitador) crate (v0.13.0) to enforce
**authenticated, application-level request-rate limits** inside the policy
filter. It runs on the `http.request` hook after identity resolution, maps the
PPE attribute bag into a Limitador evaluation context, and calls Limitador's
`check_rate_limited_and_update` to admit or refuse the request. The target is
parity with Kuadrant `RateLimitPolicy` semantics (N requests per window,
selected by conditions over identity and request attributes).

Scope is **application and authenticated** rate limiting — limits keyed on who
the caller is and what they are doing, applied after identity resolution.
Infrastructure / network-layer rate limiting is out of scope (see Non-goals).

The spike uses Limitador's in-memory storage. The production path is a shared
(redis-like) store whose connection is **injected by the host**, not built by
the plugin.

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
- Reproduce a Kuadrant `RateLimitPolicy` (the alice/bob example below) without
  rewriting its limit conditions by hand.
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

### Flow (per request, on `http.request`)

1. Handler receives the `HttpPayload` (request line, headers) and
   `Extensions` (resolved identity, host-injected storage).
2. Build a Limitador evaluation **context** (a variable map) by copying values
   from the PPE bag — resolved identity (via `read_subject`/`read_claims`) and
   request attributes (path, method, headers from the payload). No remapping;
   the names come from the bag as PPE produced them (see Attribute mapping).
3. Call `rate_limiter.check_rate_limited_and_update(namespace, &ctx, 1, false)`
   (signature per `limitador` v0.13.0 docs; exact arguments to confirm in the
   PoC). Limitador applies its own CEL `conditions` to pick matching limits and
   increments their counters atomically.
4. If limited, return `PluginResult::deny(PluginViolation::new(code, msg))`
   (`crates/ppe-core/src/hooks/trait_def.rs`); otherwise
   `PluginResult::allow()`.

### Attribute mapping

Limitador 0.13 evaluates its **own** CEL over a context the plugin supplies.
The plugin populates that context by **copying values from the PPE attribute
bag** — it does not re-implement the Kuadrant attribute mapping. Translating
raw identity claims and request fields into Kuadrant well-known names
(`auth.identity.*`, `request.*`) is owned by the compatibility layer
(`engine_settings.kuadrant_compat: true`, 00130 Approach A; the mapping itself
fixed by 00133). Reusing it keeps one source of truth; this plugin adds no
second map.

Consequence: running a Kuadrant `RateLimitPolicy`'s conditions verbatim depends
on that compat layer being enabled, so the bag already carries the WKA-shaped
attributes the conditions reference. What is unresolved is whether those
compat-mapped names are visible to a plugin at the `http.request` hook, or only
the raw identity and request fields are; the PoC answers this (see Open
questions). See [00133](00133_kuadrant-authpolicy-attribute-mapping.md).

### Storage

- **Spike:** Limitador in-memory storage (`RateLimiter::new(capacity)`).
  Per-replica counters, lost on restart. Acceptable for proving the mechanism;
  not shared limiting.
- **Production:** the `limitador` crate supports a redis-like backend
  (`RedisStorage` / `AsyncRedisStorage`). The connection/storage handle is
  **injected by the host** through `Extensions` and passed to the plugin, the
  same ownership model the quota plugin uses for the host HTTP transport. The
  plugin constructs no connection, owns no pool, and runs no background task.
  The in-memory vs shared choice is then a host wiring decision, not a plugin
  rewrite.

### Config schema (illustrative)

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
variables)` (per crate docs; confirm in PoC). Typed config with
`#[serde(deny_unknown_fields)]` and a `validate()` at construction, matching
`QuotaConfig`.

### Capabilities

- `read_subject` / `read_claims` — to populate identity variables in the
  Limitador context. Without them, identity-keyed limits cannot be selected.
- No `perform_http`: in-memory storage makes no outbound call. A host-injected
  shared store reaches the network through host-owned machinery, so the
  capability story there is a host concern, resolved when that path is built.

## Worked example (the PoC target)

A Kuadrant `RateLimitPolicy` targeting the `toystore` HTTPRoute: alice gets
5 req / 10 s, bob gets 2 req / 10 s, selected by
`auth.identity.userid == 'alice' | 'bob'`. The PoC proves the 6th alice request
and 3rd bob request within the window are refused — first as an in-process PPE
assertion, then end-to-end against a running `praxis-ai` (the `test-spike/`
harness on branch `spike/ratelimit-limitador`, with its mock JWT issuer), where
a real request returns a real 429.

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

1. **Wire-status rendering of 429.** A deny carries a `proto_error_code` that
   the plugin sets and the **host** maps to the HTTP status
   (`crates/ppe-core/src/error.rs`, `PluginViolation::proto_error_code`); the
   quota plugin already sets `429` for over-budget denials
   (`crates/builtins/src/plugins/quota/handlers.rs:343`). So reaching 429 is not
   in doubt in PPE — the plugin sets it, and an in-process test asserts the
   violation carries it. What the in-repo test cannot show is the host rendering
   that code on the wire; the end-to-end arm (below) confirms a real request
   returns a real 429, since that mapping lives in `praxis-ai`, not this repo.
2. **Host storage-injection API.** The exact `Extensions` seam for passing a
   `limitador` storage/`RateLimiter` handle from host to plugin is not yet
   designed; the spike uses an in-process in-memory instance.
3. **In-memory concurrency.** Whether the sync `RateLimiter` or the
   `AsyncRateLimiter` is the right fit under PPE's async executor, and the
   atomicity of check-and-update across concurrent requests to one replica.
4. **Compat-mapped attribute visibility.** Whether the Kuadrant WKA names the
   compat layer produces (`auth.identity.*`, `request.*`) are reachable by a
   plugin at the `http.request` hook, or only the raw identity and request
   fields are. This decides whether a `RateLimitPolicy`'s conditions run
   verbatim or need the bag's native names.

## PoC plan

On branch `spike/ratelimit-limitador` (throwaway). Verification is two-tier.

1. Add the `limitador` crate (in-memory feature) and a minimal
   `ratelimit/limitador` plugin behind an experimental feature.
2. Wire the `http.request` handler: bag → context → `check_rate_limited_and_update`
   → allow/deny, setting `proto_error_code = 429` on a limited deny.
3. **In-process PPE test (in-repo):** fire N `http.request` invocations through
   the engine with injected identity; assert the limiter counts, selects the
   right limit by CEL, passes attributes through, and that the deny violation
   carries `proto_error_code == 429`. No gateway or network.
4. **End-to-end (against `praxis-ai`):** build `praxis-ai` with the PoC PPE,
   run the alice/bob policy via `test-spike/run.sh`, and curl real requests at
   `127.0.0.1:8095` — observe a real 429 on the over-limit request (confirms the
   host renders the code; resolves Q1).
5. Document reproduction steps if it works; report the blocker if it does not.

## References

### Verified (this repo)

- `crates/builtins/src/plugins/quota/` — factory, config, backend trait,
  README; the structural template this plugin mirrors.
- `crates/ppe-core/src/http_hook.rs:40` — `HOOK_HTTP_REQUEST` / `HttpHook`.
- `crates/ppe-core/src/hooks/trait_def.rs` — `PluginResult::{allow,deny}`.
- `crates/ppe-core/src/error.rs` — `PluginViolation`, including
  `proto_error_code` (plugin sets it; the host maps it to the wire status).
- `crates/builtins/src/plugins/quota/handlers.rs:343` — precedent:
  `.with_proto_error_code(429)` on an over-budget deny.
- `crates/ppe-apl-runtime/src/visitor.rs` — plugin chain-deny from a route step.
- `test-spike/` (branch `spike/ratelimit-limitador`) — `run.sh` runs `praxis-ai`
  with a PPE policy on `127.0.0.1:8095` for end-to-end request/response checks.
- [00130](00130_kuadrant-adapter-compatibility.md),
  [00133](00133_kuadrant-authpolicy-attribute-mapping.md) — Kuadrant
  compatibility and attribute mapping.

### Unverified (external)

- `limitador` v0.13.0 (crates.io / docs.rs) — `RateLimiter`,
  `AsyncRateLimiter`, `check_rate_limited_and_update`, `Limit::new`,
  in-memory and redis storage. Exact signatures to confirm during the PoC.
- Kuadrant `RateLimitPolicy` semantics and the toystore example (Kuadrant docs).
