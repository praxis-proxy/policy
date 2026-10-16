---
issue: https://github.com/praxis-proxy/policy/issues/152
discussion: >-
  Experimental embedded Limitador plugin for HTTP requests, tool calls,
  and LLM tokens, initially using per-instance in-memory storage.
status: proposed
repos:
  - policy
  - praxis
  - ai
authors:
  - maleck13
graduation_criteria:
  - Count and token handlers share typed definitions and enforce all matching
    limits.
  - A typed PPE limit extension passes scoped definitions or references to
    count and token handlers without bypassing capability checks.
  - Verified identity, counting, token settlement, and protocol denials are
    demonstrated through PPE and the gateway.
  - Token settlement works for buffered JSON and normally completed SSE
    responses, with original request context and no whole-stream buffering.
  - Runtime failure policy, private invocation state, selected parallel denials,
    duplicate prevention, and returned commit errors have tested contracts.
  - Restart, eviction, expiry, and skipped-output limitations are documented.
  - Quota retirement requires a migration decision and shared-storage parity;
    the existing plugin remains available during the experiment.
stakeholders:
  - araujof
  - terylt
---

# Experimental Limitador plugin

## Decision and scope

This proposal extends the existing HTTP request-count prototype into one
Limitador plugin for HTTP requests, tool calls, and LLM tokens. The initial
HTTP PR adds `ratelimit/limitador` and `experimental-ratelimit`; the unified
design below is follow-on work.

Add one experimental `kind: limitador` builtin, gated by
`experimental-limitador` in builtins and the facade. Embed the Limitador
crate with in-memory storage, extending the existing module at
`crates/builtins/src/plugins/ratelimit/` within the builtins crate.

The plugin uses resolved identity and request attributes without a separate
Limitador service call. `target` identifies what is limited; PPE's existing
`mode` continues to control execution:

- `http_request`: count one admitted request at `http.request`.
- `tool_call`: count one admitted tool invocation at `cmf.tool_pre_invoke`.
- `llm_tokens`: reserve an estimate at `cmf.llm_input`; record actual total
  tokens or `missing_usage_charge` at `cmf.llm_output`. The initial token
  milestone includes buffered JSON and normally completed SSE responses.

Limits use expiring counters within configured time windows. Durable usage
metering and billing are outside scope. Token "charges" and "settlement"
below mean updating those counters and releasing reservations.

Each instance has one target, immutable rules, and its own counters. APL
`run(name)` controls placement. Authentication resolves identity before the
limiter, whose handlers receive capability-filtered PPE extensions. The host
supplies trusted usage and applies protocol responses.

Matching the existing AI `token_rate_limit` filter's accounting behavior is
outside this initial work. Cancellation, interrupted-stream recovery, and
unconditional settlement remain follow-up work; see
[callback limitations](#callback-limitations). Pre-authentication IP
throttling and request-flood protection are also outside scope.

Keep `quota/limitador` and `experimental-quota` available during the
experiment. That plugin uses remote check/report and the service deployment's
storage. Retiring it is a graduation goal.

The HTTP prototype has in-process tests; real-gateway verification with
authenticated identity remains outstanding. The
[prototype README](../../crates/builtins/src/plugins/ratelimit/README.md)
documents the current implementation.

## Responsibilities

### Existing Limitador behavior

The [Limitador crate][limitador] already provides:

- CEL rule matching and enforcement of all matching limits.
- Request-count checks and updates, counter windows, and expiry.
- Token reservations, recording reported usage, and releasing temporary holds.

PPE uses these existing operations. Reservations are temporary and do not
guarantee a hard token budget for the whole inference. Repeating a commit
can count the same usage twice.

### PPE and Praxis integration

PPE supplies configuration and filtered attributes, connects count and token
handlers to the appropriate hooks, and translates Limitador results into
policy decisions. It preserves the original invocation context, prevents
duplicate commits, and applies the configured failure policy. Failed commits
are not automatically retried.

The builtin has separate count and token handlers sharing a private
Limitador adapter. It remains opt-in, outside default builds and the facade's
`builtins` feature. The shared typed contract belongs in `ppe-core`; compiled
rules and storage remain private to the adapter.

PPE's APL runtime and Praxis's policy filter require changes to preserve
state and support token settlement. These are prerequisites for the plugin
to work in Praxis, and shared runtime changes also affect existing plugins.

### Typed PPE limit extension

Add a typed `Extensions.limit` contract through which the trusted host/APL
runtime supplies configured limit definitions or references to both handler
types. Each view is scoped to its plugin instance, target, namespace, and
configuration generation.

The proposed `read_limit` capability grants access to this immutable view.
Identity, claims, HTTP data, and usage retain their own access rules. Caller
input cannot replace limit definitions, and missing or invalid references
are errors rather than permission to skip enforcement.

Static rules are compiled once. Limitador remains responsible for matching
them and enforcing all applicable limits. Token settlement uses the admitting
configuration, with reservations and invocation state kept private.

### Upstream Limitador prerequisite: CEL errors

Limitador 0.13.0 can panic on data-dependent CEL evaluation errors instead of
returning an error. An upstream fix is required before PPE can apply
`failure_mode` to those errors. This prerequisite must preserve Limitador's
matching semantics and PPE's existing panic containment.

### Private state across APL and host callbacks

PPE already returns private plugin state in `PipelineResult.context_table`,
but APL and the Praxis policy filter do not currently preserve it through
the LLM request/response lifecycle.

The APL runtime must retain each nested plugin's state across input and
output. The [Praxis policy filter][praxis-policy-filter] must store the
returned table in its existing [typed per-filter state][praxis-filter-state]
and pass it to the matching `cmf.llm_output` invocation, alongside its
existing identity and HTTP admission state.

State must stay private and tied to the original filter, plugin, invocation,
and configuration generation. Changed output identity or a configuration
reload must not redirect the token update. Repeated or overlapping callbacks
must permit at most one commit attempt, including after a commit error.

### Selected denials in parallel policies

Parallel plugin checks can currently overwrite each other's denial details.
The selected decision must carry its complete violation, including status
and details, through APL evaluation. Existing branch-selection order and
custom denial responses must be preserved. This runtime correction applies
to all plugins.

## Configuration and attribute contract

Each plugin instance defines a target, namespace, backend, attribute
bindings, and limits. Each limit has a stable ID, CEL conditions, counter-key
expressions, and a positive count and time window.

The initial configuration supports:

- Embedded memory storage with a positive `counter_capacity`.
- Count handlers in `sequential` or `concurrent` mode. Token handlers require
  `sequential` mode and paired input/output steps; they cannot run in
  `parallel:` branches.
- `failure_mode: allow | deny`, defaulting to `allow`.
- Windows expressed in integer `s`, `m`, `h`, or `d` units. Conditions and
  counter-key variables default to empty.

Invalid configuration is rejected at load time, including unsupported
backends, incompatible hook placement, unknown fields, invalid expressions,
nonpositive or overflowing bounds, and duplicate IDs or equivalent rules.
Token-only settings are rejected for count targets.

`conditions` select rules; `variables` partition counters. No variables
means a shared counter for every request matching that rule. No matching
rules means allow without charging. These are Limitador's existing rule
semantics. PPE adopts its fixed-window counters.

Bindings map flat CEL variable names to native PPE attributes from the
handler's capability-filtered extensions:

| PPE attribute | Availability |
| --- | --- |
| `subject.id`, `subject.type` | `read_subject` |
| `claim.*` | `read_claims` |
| `http.*`, including request headers | `read_headers` |
| `mcp.tool.name` | Existing MCP slot is unrestricted |
| `route.key`, `data.*` | Unavailable in this plugin-local bag |

Only referenced bindings are required, and their values must be strings.
Missing or non-string values are errors before counters change, even when
referenced by a rule that might not match. A caller-controlled header cannot
substitute for verified identity. Token usage remains numeric and comes
from the host's trusted completion extension, not these string bindings.

The examples describe the proposed unified contract, including `read_limit`;
they are not configurations for the existing HTTP-only PR.

### HTTP example and placement

This example assumes the host resolves identity before `http.request`.
Alice gets five GETs per ten seconds and Bob two.

```yaml
engine_settings:
  dispatch: policy
plugins:
  - name: app-ratelimit
    kind: limitador
    hooks: [http.request]
    mode: sequential
    capabilities: [read_limit, read_subject, read_headers]
    config:
      target: http_request
      namespace: toystore
      failure_mode: allow
      backend: { type: embedded, storage: memory, counter_capacity: 10000 }
      bindings: { subject_id: subject.id, http_method: http.method }
      limits:
        - id: alice-get
          conditions: ["subject_id == 'alice'", "http_method == 'GET'"]
          limit: { count: 5, window: 10s }
        - id: bob-get
          conditions: ["subject_id == 'bob'", "http_method == 'GET'"]
          limit: { count: 2, window: 10s }
global:
  authorization:
    pre_invocation:
      - "run(app-ratelimit)"
```

HTTP-only steps inherited into `tool:` or `llm:` routes remain invalid,
because those routes dispatch CMF hooks. The initial gateway arrangement uses
two policy filters: authenticated HTTP admission first, then entity policy.
Each filter resolves identity independently, so this arrangement duplicates
authentication work. A future single-filter admission stage would let HTTP
limiting and entity policy reuse one resolved identity. In the current
arrangement, header/body callbacks must count each HTTP request only once.

### Tool example

```yaml
engine_settings:
  dispatch: policy
plugins:
  - name: tool-limits
    kind: limitador
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
    capabilities: [read_limit, read_subject]
    config:
      target: tool_call
      namespace: acme-tools
      backend: { type: embedded, storage: memory, counter_capacity: 10000 }
      bindings:
        caller_id: subject.id
        caller_type: subject.type
        tool_name: mcp.tool.name
      limits:
        - id: all-tools-per-agent
          conditions: ["caller_type == 'agent'"]
          variables: [caller_id]
          limit: { count: 100, window: 1m }
        - id: each-tool-per-agent
          conditions: ["caller_type == 'agent'"]
          variables: [caller_id, tool_name]
          limit: { count: 10, window: 1m }
routes:
  - tool: "*"
    authorization:
      pre_invocation:
        - "run(tool-limits)"
```

### PPE count handlers

Each handler asks Limitador to check and increment by one. PPE serializes
calls per instance so concurrent requests cannot over-admit. Limitador checks
all matching counters and updates them only when admission succeeds.

A later policy denial does not refund an earlier admitted count. Separate
global and route instances intentionally maintain independent counters.
Duplicate placements of the same count instance on one executable request
or tool-invocation path are rejected:

```yaml
global:
  authorization:
    pre_invocation:
      - "run(app-ratelimit)"

routes:
  - http: /toys
    authorization:
      pre_invocation:
        - "run(app-ratelimit)"
```

## Failure policy

| Outcome | Behavior |
| --- | --- |
| Count admission exceeded | Deny `ratelimit.exceeded` |
| Token reservation refused for exhausted budget | Deny `quota.exhausted` |
| Returned input, evaluation, or backend error | Apply `failure_mode` |
| Invalid configuration | Reject startup |

Under `allow`, a returned error is reported and policy evaluation continues.
Under `deny`, it produces a distinct runtime-error violation. Confirmed
excess always denies, with `proto_error_code: 429` and
`details["http.status"]: 429` for protocol/HTTP response handling. Diagnostics
must not expose credentials or sensitive counter keys.

The allow default is an availability choice for this experimental limiter.
Migrating the existing HTTP configuration must explicitly set
`failure_mode: deny` to retain its current posture. Authentication and
authorization still enforce their own decisions.

PPE's outer `PluginConfig.on_error` continues to govern uncaught panics,
timeouts, and dispatch faults, and defaults to `Fail`. The limiter's
`failure_mode` does not override that control.

## PPE token handlers

Connect Limitador's existing `reserve` and `commit_reservation` APIs to PPE's
paired LLM hooks. PPE defines the estimate, `missing_usage_charge`, and
invocation-state handoff below.

```yaml
engine_settings:
  dispatch: policy
plugins:
  - name: llm-budget
    kind: limitador
    hooks: [cmf.llm_input, cmf.llm_output]
    mode: sequential
    capabilities: [read_limit, read_subject]
    config:
      target: llm_tokens
      namespace: acme-tokens
      backend: { type: embedded, storage: memory, counter_capacity: 10000 }
      bindings: { caller_id: subject.id }
      reservation: { amount: 1000, ttl: 30s }
      missing_usage_charge: 1000
      limits:
        - id: subject-token-budget
          variables: [caller_id]
          limit: { count: 10000, window: 1h }
routes:
  - llm: "*"
    authorization:
      pre_invocation:
        - "run(llm-budget)"
      post_invocation:
        - "run(llm-budget)"
```

Require paired input/output steps, a positive `missing_usage_charge`, and
a fixed positive reservation amount at least `missing_usage_charge` and no
greater than any configured token maximum. Initially accept TTLs of 1–60
seconds. These are PPE configuration choices; Limitador manages expiry.

- **Input:** call Limitador with the estimate and filtered attributes. Deny
  if capacity is unavailable; otherwise retain the original context and
  reservation for the matching output.
- **Output:** commit actual total tokens, or `missing_usage_charge` when usage
  is absent, unusable, or zero. The update uses the original context and can
  be attempted only once per invocation.


When failure_mode: allow lets a request proceed after an admission error, 
PPE still attempts to charge usage on completion, provided it retained valid 
caller attributes and limiter configuration. Without that context, PPE reports
an error.

### PPE commit-error handling

Returned commit errors follow `failure_mode`: report and continue under
`allow`, or deny where the host can still act under `deny`. Failed commits
are not retried, including through repeated callbacks. Later admissions
continue through Limitador's checks.

### Required Praxis policy-filter integration

Praxis's policy filter currently supplies usage for buffered JSON responses
but releases SSE without invoking `cmf.llm_output`. Both response paths must
support token settlement in the initial milestone.

For SSE, reuse the AI filters' [token usage extraction][ai-token-count]. At
normal stream completion, the policy filter must pass trusted final usage
and the saved request context to PPE. Chunks continue to the client without
whole-stream buffering or per-chunk token updates. Missing or unusable usage
selects `missing_usage_charge`; provider-specific parsing stays in the AI
layer.

### Callback limitations

Initial token settlement depends on reaching the configured output step;
skipped output can leave usage uncounted. Closing this gap is a
[future requirement](#storage-and-follow-up-work).

## Storage and follow-up work

The initial implementation uses Limitador's in-memory storage. Counters are
independent per configured instance and replica; restart or cache eviction
can lose usage and reservations.

The plugin creates no network connections or pools and runs no background
tasks. Future network-backed storage must use host-owned resources with
access authorized per invocation.

| Backend | Rule ownership | Counter storage |
| --- | --- | --- |
| Embedded memory | PPE config | Per instance and replica |
| Embedded shared (future) | PPE config | Host-provided |
| Service (future) | Service config | Service-owned |

Shared storage and service integration require separate proposals. The
existing `quota/limitador` plugin remains available during this experiment.

Other follow-up work:

- Guaranteed token finalization when policy steps are skipped or requests
  encounter errors, cancellation, or interrupted streams.
- Single-filter HTTP admission for gateways with entity policies.
- Dynamic token estimates and typed non-string attribute bindings.
- Remaining-budget policy actions and usage notifications.

## Review basis

Reviewed against this worktree and the cached published Limitador 0.13.0
source, plus the local Praxis and AI checkouts and Obsidian notes
“Limitador (Rate Limiting)”, “Token Rate Limiting Reconciliation”, and
“PPE Rate Limiting”. Gateway behavior must be reverified against the version
used for the demo.

- [PPE principles](../content/vision.md),
  [safety invariants](../dev/safety-invariants.md), and
  [conventions](../dev/conventions.md).
- [HTTP prototype](../../crates/builtins/src/plugins/ratelimit/README.md) and
  [remote quota](../../crates/builtins/src/plugins/quota/README.md).
- [Context contract](../../crates/ppe-core/src/context.rs),
  [extension filtering](../../crates/ppe-core/src/extensions/filter.rs),
  [APL invoker](../../crates/ppe-apl-runtime/src/cmf_invoker.rs),
  [route handler](../../crates/ppe-apl-runtime/src/route_handler.rs),
  [visitor](../../crates/ppe-apl-runtime/src/visitor.rs), and
  [phase ordering](../../crates/ppe-apl-core/src/route.rs).
- [Limitador API source][limitador], [predicate matching][matching], and
  [reservation settings][reservations], all at `crate-v0.13.0`.

[limitador]: https://github.com/Kuadrant/limitador/blob/crate-v0.13.0/limitador/src/lib.rs
[matching]: https://github.com/Kuadrant/limitador/blob/crate-v0.13.0/limitador/src/limit.rs
[reservations]: https://github.com/Kuadrant/limitador/blob/crate-v0.13.0/limitador/src/reservation.rs
[praxis-filter-state]: https://github.com/praxis-proxy/praxis/blob/main/crates/filter/src/context.rs
[praxis-policy-filter]: https://github.com/praxis-proxy/praxis/blob/main/crates/filter/src/builtins/http/security/policy/filter.rs
[ai-token-count]: https://github.com/praxis-proxy/ai/blob/main/filters/src/token_usage/count.rs
