---
issue: https://github.com/praxis-proxy/policy/issues/215
discussion: >-
  Design for an HTTP policy information point that enriches a request with
  external metadata before authorization.
repos:
  - policy
status: proposed
authors:
  - mkoushni
graduation_criteria:
  - The proposal defines pipeline, context, HTTP, failure, cache, and
    observability contracts for metadata/http.
  - A worked configuration shows external metadata changing a decision and
    states the behavior when the lookup fails.
  - The implementation breakdown separates prerequisites, the initial PIP,
    and follow-ups under issue 184, with validation for capability enforcement,
    cache isolation, and failure handling.
stakeholders:
  - araujof
  - terylt
---

# HTTP external-metadata policy information point

## What?

Add a builtin `metadata/http` plugin that performs a bounded, authenticated
HTTP call before an authorization decision and publishes the response under
`metadata.<instance>.*`. This supplies facts the request does not carry, such
as account status, resource ownership, and tenant entitlements.

The recommendation has four parts:

1. Build an internal callout core for request construction, authentication,
   retry, limits, caching, and observation. `metadata/http` is its first output
   adapter; a Kubernetes TokenReview identity adapter can reuse it later.
2. Add a dedicated `metadata.fetch` hook and `fetch(name)` APL effect. The
   effect runs exactly where written in `authorization.pre_invocation`, after
   any earlier identity work and before the predicates or PDP calls that need
   the result.
3. Add an immutable, capability-gated `metadata.*` extension instead of using
   mutable, host-vouched `custom.*` data.
4. Make cache-key coverage a load-time invariant and fail closed on callout
   errors unless the operator explicitly selects fail-open behavior.

The syntax and configuration in this proposal are designs, not surfaces the
current loader accepts.

### Goals

- GET and POST callouts whose path, query, headers, and structured body can
  reference permitted bag attributes.
- JSON and text responses exposed consistently to APL, CEL, OPA, and Cedar.
- Shared-secret authentication in the first release and OAuth2 client
  credentials as a follow-up.
- Bounded execution: static authority, timeouts, response limits, concurrency
  limits, retry budget, circuit breaking, and fail-closed defaults.
- An isolated, bounded response cache with dynamic keys, single-flight, TTL,
  and a path to HTTP revalidation.
- Tracing and audit events from the first release, with seams for metrics and
  distributed caching.

### Non-goals

- Methods other than GET and POST, streaming responses, or multi-megabyte
  payloads.
- A distributed cache in the first release.
- Dynamic credential minting; that remains a `delegator/*` concern.
- Fetching telemetry, logs, or traces for correlation with individual policy
  requests.
- Implementing the Kubernetes TokenReview adapter in the same change.

## Architecture

```text
authorization.pre_invocation
  identity/authentication steps
  fetch(account_status)
          |
          v
  metadata.fetch hook  ----> metadata/http adapter
                                  |
                                  v
                           internal callout core
                 request | auth | retry | cache | limits | observer
                                  |
                                  v
                     HostServices::http_request
                                  |
                                  v
                       host HttpTransport + egress policy
          |
          v
  metadata.account_status.* in the policy bag
  APL predicate / CEL / OPA / Cedar decision
```

The `fetch(name)` effect publishes the result into framework-owned extensions
and refreshes the evaluator's attribute bag before the next sequential step.
The same refreshed snapshot is passed to PDP calls. The current route handler
builds its bag once before evaluation, so writing an extension alone would not
make fetched attributes visible to a later predicate or PDP in that invocation.

The callout core belongs under
`crates/builtins/src/plugins/metadata_http/callout/`, behind a new
`metadata-http` feature. It remains internal to the builtins crate. When a
second adapter needs it, move the module to a shared sibling inside that crate;
do not create another published crate merely to share implementation.

The core owns behavior that must not diverge between adapters:

- template discovery and context-specific encoding;
- HTTP request bounds and retry selection;
- outbound authentication and secret redaction;
- cache keys, storage, and single-flight;
- concurrency and circuit-breaker state;
- normalized errors, tracing, and audit events.

An adapter owns only its configuration schema, response interpretation,
result type, and hook integration.

### Why a dedicated effect and hook?

`metadata.fetch` is unphased because, like `identity.resolve` and
`token.delegate`, it is a semantic operation invoked from a phase rather than
a wire lifecycle phase itself. `fetch(name)` fixes ordering in policy text and
makes the network side effect visible to review.

The current generic `run(name)` path dispatches a plugin through the current
CMF or HTTP hook family. A new metadata hook has its own request/result
contract and must work for both families. Therefore the runtime should resolve
`fetch(name)` into a dedicated `metadata.fetch` entry just as
`delegate(name, ...)` resolves `token.delegate`; silently special-casing
`run(name)` by plugin kind would make identical syntax use different hook
families.

`fetch(name)` is valid only in `authorization.pre_invocation`. Post-invocation
metadata cannot influence the decision already taken, and field pipelines
cannot safely retain an extension mutation made by a stage.

### Conditional execution

Normal APL rule conditions control whether the effect runs. Cheap gates should
come first:

<!-- validate: fragment -->
```yaml
authorization:
  pre_invocation:
    - "require(authenticated)"
    - when: "role.member"
      do: "fetch(account_status)"
    - "require(metadata.account_status.active)"
```

`require_authenticated: true` is also the plugin default. It prevents an
accidental callout for an anonymous request even when policy omitted the cheap
gate. The adapter returns a missing-subject failure before cache lookup or
network access; normal `on_error` handling then applies.

## Context contract

### Typed metadata extension

Add a metadata container to `Extensions`, keyed by plugin instance name. Each
entry contains a flattened value map plus provenance:

| Field | Meaning |
|---|---|
| `source` | plugin kind and instance name |
| `fetched_at` | wall-clock timestamp of the successful fetch |
| `cache` | `miss`, `hit`, `revalidated`, or `stale` |
| `status` | upstream HTTP status when configured for exposure |
| `stale` | true only when an explicitly permitted stale value was served |
| `values` | bounded scalar/string-set attributes |

The extension is capability-gated with a new `read_metadata` capability. The
framework, acting for the `metadata.fetch` result, owns writes; there is no
general `write_metadata` capability. An instance may create its own entry once
per request. A duplicate write or an attempt to write another instance's name
is a framework error. Once installed, the entry is immutable.

The fetch hook returns its result to the evaluator for publication. It does not
rely on a plugin's `modify_extensions` return: immutable slots are not merged
from ordinary plugin extension writes. Publication and bag refresh complete
before the evaluator advances to the next sequential step.

The APL route handler must receive `read_metadata` when the compiled route
contains `fetch(...)` or a `metadata.*` reference. Downstream plugins see the
slot only when their own declared capabilities include `read_metadata`.

### Bag projection and evaluator parity

Values flatten to `metadata.<instance>.<path>`. Instance names follow the
existing plugin-name grammar. JSON object keys containing `.` or starting with
`$` are rejected rather than made ambiguous with dotted paths and reserved
provenance fields.

CEL and OPA already rebuild nested values from arbitrary dotted bag keys, so a
metadata projection reaches them without a second metadata-specific input.
APL predicates read the same bag keys directly. Cedar currently constructs a
selected context rather than forwarding every bag namespace; the prerequisite
work must add metadata at `context.metadata.<instance>.*`. A Cedar schema must
declare that context shape when schema validation is enabled.

Provenance fields project as reserved leaves:

```text
metadata.account_status.$source
metadata.account_status.$fetched_at
metadata.account_status.$cache
metadata.account_status.$status       # only with expose_status: true
metadata.account_status.$stale        # only when stale
```

Fetched JSON is untrusted and bounded. Proposed defaults and hard ceilings:

| Limit | Default | Hard ceiling |
|---|---:|---:|
| response bytes | 1 MiB | 4 MiB |
| object depth | 8 | 16 |
| flattened leaves | 256 | 1,024 |
| key length | 128 bytes | 256 bytes |
| string length | 4 KiB | 16 KiB |

Booleans, signed 64-bit integers, finite floats, and strings become bag
scalars. Arrays containing only strings become string sets. `null` is absent.
Objects recurse. Mixed arrays, nested arrays, non-finite numbers, invalid keys,
or exceeded limits fail the whole response with `metadata.bad_response`;
partial metadata is never published.

## HTTP contract

### Request construction and interpolation

The plugin config separates a static URL authority from templated request
components. Scheme, host, and port are fixed at load time. Only path segments,
query values, header values, and structured body fields may reference bag
attributes using `{attribute.path}`.

The loader walks the complete template tree and records every referenced bag
attribute. That one reference set drives both capability validation and cache
key coverage, so the checks cannot disagree.

Encoding is determined by context:

| Context | Rule |
|---|---|
| path segment | percent-encode outside the URI unreserved set, including `/`, `?`, `#`, and `%`; reject a resolved `.` or `..` segment |
| query value | form-urlencode; repeat the parameter for a string set |
| header value | reject CR, LF, and NUL; never strip them |
| JSON field | insert a typed JSON value; no string concatenation |
| form field | form-urlencode |

Every reference requires the capability that protects its source slot. A
reference to `subject.id`, for example, requires `read_subject`; a reference
to a request header requires `read_headers`. Missing declarations are load
errors that name the reference and capability.

Inbound credentials are not ordinary template inputs. Referring to
`raw_credentials.*` or the inbound Authorization header additionally requires:

- the corresponding capability (`read_inbound_credentials` or
  `read_headers`);
- `allow_credential_interpolation: true`;
- the exact destination field in `credential_fields`.

Use is included in the audit event. This explicit escape hatch supports a
later TokenReview request without turning token forwarding into a default.

### Transport, TLS, and SSRF

All calls go through `HostServices::http_request`; the plugin never owns an
HTTP client or transport handle. The existing request type already carries
overall timeout, connect-timeout hint, and maximum response bytes, and the host
transport remains responsible for destination policy and connection pooling.

The static authority rule prevents request data from choosing a destination.
The host must still enforce DNS/IP egress policy at resolution and connection
time, including redirects if it follows them. The reference transport should
reject loopback, link-local, RFC1918, and CGNAT destinations by default.
Deployments that intentionally call in-cluster services must install a host
transport policy that permits the exact destinations; plugin YAML gets no
`allow_private_networks` bypass.

Plain HTTP requires `insecure_http: true`. Custom trust and mTLS use a named
host TLS profile referenced as `tls_profile: kube-api`; CA files, client keys,
and certificates do not belong in plugin config. Adding the optional profile
identifier to `HttpRequest` is follow-up transport work and is not required for
the first HTTPS/web-PKI release.

Redirects are off by default. If added later, each hop must preserve the
static-authority and egress checks, and credentials must never cross authority.

### Outbound authentication

The first release supports `shared_secret` with `bearer`, `header`, and
`basic` schemes. Config names a value from the top-level `secrets:` block; it
does not embed a raw provider reference or secret. Secret buffers are zeroized
where practical and every `Debug`/event representation is redacted.

OAuth2 client credentials follows after the first release. It should reuse the
grant behavior from `delegator/oauth`, but its access-token cache is separate
from the metadata response cache. Token expiry is the smaller of upstream
`expires_in` minus skew and the configured token-cache TTL. Refresh is
single-flight. A source 401 invalidates the access token and permits one
reauthenticated retry.

### Response and retry

`response.type` is `json` by default and may be `text`. The declared type and
Content-Type must agree. Accepted statuses default to 200 through 299. An
operator may add statuses such as 404 and expose `$status` so policy can branch
on them; an accepted status is not itself an error.

GET uses `RetryPolicy::idempotent()`. POST uses
`RetryPolicy::undelivered_only()` because a delivered POST may have side
effects even when its response is lost. In both cases `total_budget` is capped
by the callout's overall timeout, so retry backoff cannot extend the policy
request indefinitely.

## Runtime and failure semantics

The plugin defaults to `on_error: fail`, `mode: sequential`, and
`require_authenticated: true`. A failure returns a violation and stops the
authorization phase before any decision can consume absent or partial data.

| Code | Meaning | Class |
|---|---|---|
| `metadata.subject_required` | no authenticated subject | fatal |
| `metadata.timeout` | connect or overall timeout | recoverable |
| `metadata.upstream_error` | 5xx or transport failure | recoverable |
| `metadata.overloaded` | per-instance concurrency cap reached | recoverable |
| `metadata.circuit_open` | degraded source is being fast-failed | recoverable |
| `metadata.auth_failed` | source 401/403 or auth acquisition failure | fatal |
| `metadata.response_too_large` | response exceeds configured bytes | fatal |
| `metadata.bad_response` | status, content type, parse, or flatten failure | fatal |
| `metadata.rejected_destination` | host egress policy rejected the call | fatal |

`on_error: ignore` is an explicit fail-open setting. It publishes no metadata
entry, including no synthetic `$error` value. Policies using it must test
existence and deny when metadata is absent. Caching errors is forbidden.

Each instance has a semaphore. Saturation fails immediately instead of
waiting behind requests already consuming the upstream timeout. A basic
circuit breaker also ships in the initial release:

- closed: open after at least 20 calls in 30 seconds with 50% counted failure;
- open: cache hits and permitted stale values remain usable, but a miss returns
  `metadata.circuit_open` without taking a permit;
- half-open: after 15 seconds, admit a small number of probes; success closes
  and failure reopens the breaker.

Timeouts, 5xx responses, and transport failures count. Authentication and
response-shape failures do not: they require operator or source correction,
not recovery probing. All state transitions are audited and traced.

## Cache contract

The response cache is off unless configured. Its security invariants are:

1. Every bag attribute that can vary the request is covered by the key.
2. A missing key attribute bypasses caching; missing values never collapse
   into one shared key.
3. The instance name and configuration fingerprint scope every key.
4. Entries are immutable, bounded, and contain metadata only, never a
   credential.

The key is
`HMAC-SHA256(process_secret, instance || config_fingerprint || canonical_attributes)`.
Canonical encoding is length-delimited and typed so distinct attribute tuples
cannot concatenate to the same bytes. Raw key material is never logged.

At load, every template reference must occur in `cache.key`. A reference that
provably does not vary the response may appear in `cache.key_exempt`, paired
with a non-empty reason. Each exemption emits a warning audit event at load
and on evaluations that rely on it. This exception cannot account for
server-side implicit variation such as source IP, time, or a rollout flag.
For such a source, disable caching or set `volatile: true`, which caps TTL at
30 seconds and disables stale serving.

The in-process implementation uses the existing `moka` dependency for a
bounded store and coalesced misses. Bound retained response bytes as well as
entry count: at the proposed 1 MiB default response limit, 10,000 entries
could otherwise retain roughly 10 GiB of response data. `max_bytes` defaults
to 64 MiB and counts cached payloads and response metadata; implementation
overhead needs a separate allowance. Errors are not inserted.
`ttl_seconds` is a ceiling. A later release may honor a smaller upstream
`Cache-Control: max-age`, revalidate with ETag, and optionally serve a last
good entry for at most `max_stale_seconds`. Every stale serve sets `$stale`
and emits an event.

An internal `MetadataCacheStore` trait keeps storage replaceable, but only the
in-process implementation ships initially. The existing session store is not
reused: sessions and arbitrary response values have different retention,
isolation, and invalidation contracts.

## Observability

Each attempt creates a tracing span with instance, method, outcome, status,
latency, retry count, cache result, and inbound trace identifiers. URL query,
headers, body, secret identifiers, and response values are excluded.

One audit event records:

- instance and source authority;
- outcome/error code and accepted status;
- cache result and stale use;
- credential-interpolation use;
- response leaf count and rejected-key count;
- circuit-breaker transition, when any.

The core accepts a `CalloutObserver` interface. The initial implementation
emits tracing and audit data. Metrics can later implement the same interface:

```text
ppe_metadata_callout_total{instance,outcome}
ppe_metadata_callout_duration_seconds{instance}
ppe_metadata_cache_total{instance,result}
```

Trace propagation is shared infrastructure. A follow-up may add W3C
`traceparent`/`tracestate` injection at the host transport seam so every
outbound plugin benefits; the initial PIP still correlates local spans.

## Worked example

This proposed configuration fetches an account record after identity
resolution and permits a tool only when the account is active and entitled to
the requested operation.

<!-- validate: fragment -->
```yaml
engine_settings:
  dispatch: policy

secrets:
  providers:
    shell: { kind: env }
  values:
    entitlement-api-token:
      provider: shell
      ref: ENTITLEMENT_API_TOKEN

plugins:
  - name: account_status
    kind: metadata/http
    hooks: [metadata.fetch]
    mode: sequential
    on_error: fail
    capabilities: [perform_http, read_subject]
    config:
      require_authenticated: true
      request:
        method: GET
        url: https://entitlements.example.com
        path_segments: [v1, accounts, "{subject.id}"]
        query:
          resource: "{meta.entity_name}"
        timeout_milliseconds: 1500
        connect_timeout_milliseconds: 500
        max_response_bytes: 65536
      auth:
        kind: shared_secret
        scheme: bearer
        secret: entitlement-api-token
      response:
        type: json
      cache:
        key: [subject.id, meta.entity_name]
        ttl_seconds: 30
        max_entries: 10000
        max_bytes: 67108864
      max_concurrent_callouts: 64

global:
  pdp:
    - kind: cel

routes:
  - tool: export_report
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "fetch(account_status)"
        - cel:
            expr: >-
              has(metadata.account_status) &&
              metadata.account_status.active == true &&
              'report:export' in metadata.account_status.entitlements
```

For this response:

```json
{
  "active": true,
  "entitlements": ["report:read", "report:export"],
  "tenant": {"plan": "enterprise"}
}
```

the plugin publishes `metadata.account_status.active`,
`metadata.account_status.entitlements`, and
`metadata.account_status.tenant.plan`; the CEL step allows.

If DNS, transport, timeout, authentication, status, size, or parsing fails,
`on_error: fail` returns the corresponding `metadata.*` violation and the CEL
step never runs. If the operator changes to `on_error: ignore`, the plugin
publishes nothing; the explicit `has(metadata.account_status)` guard makes the
CEL expression false, so the request still denies. A fail-open policy would
have to make a separate, conspicuous choice to allow on absence.

Equivalent evaluator access is:

| Evaluator | Example |
|---|---|
| APL | `require(metadata.account_status.active)` |
| CEL | `metadata.account_status.active == true` |
| OPA | `input.metadata.account_status.active == true` |
| Cedar | `context.metadata.account_status.active == true` (with a compatible schema) |

## Security analysis

| Threat | Control |
|---|---|
| request-controlled SSRF | static authority, context encoding, host egress policy |
| path/header injection | segment encoding; CR/LF/NUL rejection |
| one principal receives another's metadata | load-time key coverage, HMAC scoping, missing-key bypass |
| cached data becomes a credential | metadata-only slot, no delegator access without `read_metadata` |
| plugin over-reads context | template-derived capability check plus filtered extensions |
| inbound token exfiltration | default deny, explicit flag and field allow-list, audit |
| malicious source floods the bag | response and flatten limits; atomic failure |
| anonymous amplification | authenticated-subject default, cache, semaphore, breaker |
| stale authorization after revocation | short bounded TTL; stale serving off by default |
| secret leakage in logs | redacted request/debug output and value-free events |

The dominant residual risk is implicit server-side variation that is absent
from the request and therefore invisible to cache-key analysis. Operators must
disable caching for such sources unless the bounded `volatile` mode is
acceptable.

## Alternatives considered

### Reuse `custom.*`

Rejected. `custom.*` is host-vouched, mutable data without per-source
ownership. Network-fetched policy inputs need provenance, isolation,
immutability, and an explicit read capability.

### Use generic `run(name)`

Rejected for the dedicated hook. `run` dispatches the current payload family,
while metadata fetch has a family-independent request/result contract. A
first-class effect also makes a pre-decision network call obvious in review.

### Give the plugin its own HTTP client

Rejected. It would create another pool, trust store, redirect policy, and SSRF
boundary, bypassing the host's `perform_http` gate and egress controls.

### Free-form cache keys

Rejected. Documentation cannot reliably enforce principal and tenant
isolation. Template extraction makes coverage checkable at load time.

### Inline CA and client certificate material

Rejected. Named host TLS profiles keep key material out of plugin config and
allow trust stores and connection pools to be shared safely.

### Build TokenReview first

Rejected. Starting with a narrow adapter would duplicate or prematurely hide
the generic request, authentication, limit, and observation machinery.

## Implementation breakdown under [#184](https://github.com/praxis-proxy/policy/issues/184)

### P0: prerequisites

1. Add `MetadataExtension`, per-instance ownership/provenance, immutable
   install semantics, `read_metadata`, extension filtering, and bag flattening.
2. Add the `MetadataFetchHook` request/result types and hook metadata.
3. Add `fetch(name)` to APL parsing, route reachability, dispatch plans, and
   the pre-invocation evaluator. Publish each successful result to the
   framework-owned extension and refresh the bag/PDP input before the next
   sequential step. Reject `fetch(name)` in all other positions.
4. Grant the synthetic route handler `read_metadata` only for compiled routes
   that fetch or reference metadata.
5. Add the Cedar `context.metadata` projection and schema tests. CEL and OPA
   receive coverage tests for arbitrary metadata keys.
6. Define the callout error taxonomy and audit event schema.

These are prerequisites because without them the adapter would either write an
unprotected generic namespace or expose different data to different PDPs.

### P1: initial metadata PIP

1. Add the `metadata-http` feature, factory, adapter, and internal callout core.
2. Implement GET/POST, static authority, context-aware template encoding,
   template-derived capability checks, and credential-interpolation opt-in.
3. Implement shared-secret auth and JSON/text response flattening with hard
   limits.
4. Use host HTTP with bounded retry budgets and normalized errors.
5. Implement the in-process cache, HMAC keys, load-time coverage validation,
   single-flight, TTL, and entry/byte bounds.
6. Add authenticated-subject gating, per-instance concurrency limits, and the
   circuit breaker.
7. Emit tracing and audit events. Document the builtin and feature flag.

P1 is useful with ordinary HTTPS services and does not require a transport
trait change.

### P2: shared infrastructure and richer HTTP

- Named TLS profiles and optional `HttpRequest` profile selection.
- W3C trace-context propagation at the host transport seam.
- OAuth2 client credentials with a separate token cache and one 401 refresh.
- Cache-Control/ETag revalidation and bounded stale serving.
- Metrics through `CalloutObserver`.
- Optional shared cache implementation after its isolation and invalidation
  contract is reviewed.

### P3: adapters

- Kubernetes TokenReview identity adapter using the callout core, named TLS
  profiles, and explicit credential-in-body configuration.
- Other external metadata adapters only when their response semantics cannot
  be represented by `metadata/http` configuration.

## Validation plan

### Capability enforcement

- Load fails for a template reference whose required capability is absent,
  including nested JSON fields and every query/header entry.
- Credential references fail without all three controls: capability, explicit
  opt-in, and named field.
- A plugin without `read_metadata` receives an empty metadata slot.
- One metadata instance cannot write or replace another instance's entry.
- CEL, OPA, Cedar, and APL see the same allowed scalar and string-set values.

### Cache isolation

- Load fails when any request reference is absent from `cache.key`.
- An exemption without a reason fails; accepted exemptions audit at load and
  use time.
- Principal, tenant, instance, and config changes produce distinct keys.
- Missing key attributes bypass cache and never share a null key.
- Concurrent identical misses make one upstream call; errors are not cached.
- Large responses evict entries before the configured byte limit is exceeded.
- Property tests cover canonical encoding and HMAC derivation.

### Failure handling

- Fake-transport tests cover every error code, GET/POST retry policy, total
  budget, size limit, malformed JSON, rejected status, and auth rejection.
- Route tests prove fetch occurs after identity and before APL/CEL/OPA/Cedar,
  that a subsequent APL predicate and each PDP see the published result in the
  same invocation, and that a fetch violation prevents the decision from running.
- Fail-open tests prove no partial or synthetic metadata is published and the
  worked example still denies on absence.
- Deterministic clock tests cover semaphore saturation and every breaker
  transition; cache hits remain available while open.
- Security tests cover encoded traversal, header injection, authority
  interpolation rejection, credential exfiltration, and bag-limit attacks.
- A real-transport test covers host destination rejection. Benchmarks record
  cache-hit and miss overhead before assigning a numeric performance budget.

## Open questions

1. Should `cache.key_exempt` ship in P1, or should the first release require
   strict coverage with no escape hatch?
2. Is `fetch(name)` the preferred verb, or should the syntax spell the domain
   explicitly as `fetch_metadata(name)`?
3. Should an accepted non-2xx status expose `$status` only, or also permit an
   empty/text body without a response mapping?
4. What exact host configuration owns named TLS profiles, and how are profile
   names authorized per plugin?
5. Is `require_authenticated: true` accepted as the secure default even though
   it differs from more permissive external-metadata implementations?
6. Must the initial release include the circuit breaker, or may it be the first
   production-blocking fast-follow after P1?

## Verified repository foundations

The design is based on these current repository seams:

| Concern | Location |
|---|---|
| bounded HTTP request/response and redacted debug | `crates/ppe-core/src/http.rs` |
| host operation and `perform_http` enforcement | `crates/ppe-core/src/host.rs` |
| idempotent/undelivered retry and total budget | `crates/ppe-core/src/http_retry.rs` |
| capability model and immutable slots | `crates/ppe-core/src/extensions/tiers.rs` |
| extension filtering | `crates/ppe-core/src/extensions/filter.rs` |
| unphased identity/delegation hooks | `crates/ppe-core/src/identity/hook.rs`, `crates/ppe-core/src/delegation/hook.rs` |
| dedicated-effect dispatch-plan precedent | `crates/ppe-apl-runtime/src/dispatch_plan.rs` |
| synthetic route-handler capability union | `crates/ppe-apl-runtime/src/visitor.rs` |
| CEL arbitrary bag projection | `crates/builtins/src/pdps/cel/activation.rs` |
| OPA arbitrary bag projection | `crates/builtins/src/pdps/opa/input.rs` |
| Cedar selected context projection | `crates/builtins/src/pdps/cedar_direct/request.rs` |
| OAuth HMAC/single-flight cache patterns | `crates/builtins/src/plugins/delegator_oauth/cache/` |
| shared form encoding | `crates/ppe-core/src/http.rs` |

This proposal implements the external-metadata gap identified by
[proposal 00133](00133_kuadrant-authpolicy-attribute-mapping.md) and is the
design deliverable for [issue 215](https://github.com/praxis-proxy/policy/issues/215)
under [issue 184](https://github.com/praxis-proxy/policy/issues/184).
