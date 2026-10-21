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
- JSON and text responses exposed to APL, CEL, OPA, and Cedar through explicit,
  evaluator-appropriate projections.
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

The common contract is an `AcquiredFacts` record in `ppe-core`, returned by an
ordinary plugin registered on `metadata.fetch`. Framework code owns record
installation and projection; it does not ask each source plugin to mutate the
bag. A source-specific PIP trait or backend registry should wait until a second
source demonstrates what its interface must abstract.

Registration follows the existing typed policy-hook path. `ppe-core` defines a
`MetadataFetchHook` request/result pair with `define_hook!`, declares
`metadata.fetch` with `define_hooks!` as an unphased, entity-independent hook,
and adds its generated `METADATA_HOOK_METADATA` table to `HOOK_TABLES`.
`metadata_http` supplies a `MetadataHttpFactory` for kind `metadata/http`; the
facade registers that factory explicitly behind the `metadata-http` feature
before configuration is loaded. `MetadataHttpFactory::create` validates
`hooks: [metadata.fetch]` and returns a `PluginInstance` pairing that name with
a typed `MetadataFetchHook` handler. Config loading installs the pair in the
policy plugin registry, whose hook-family check rejects a mismatched handler;
a host registering a source directly uses
`register_handler_for_names::<MetadataFetchHook, _>`.

The compiled `fetch(name)` dispatch-plan entry resolves `name` to that plugin
instance, and the evaluator invokes it through
`PolicyEngine::invoke_named::<MetadataFetchHook>("metadata.fetch", ...)`.
For a Praxis embedding, the security `PolicyFilter` installs the enabled PPE
factory and drives this invocation inside PPE; `metadata.fetch` is not a Praxis
`HttpFilter` lifecycle hook and must not be registered or dispatched as one.
The hook is a policy information acquisition operation: the source receives a
capability-filtered extension snapshot, requires `perform_http` for its host
call, and cannot install metadata. Only the framework can validate, stamp, and
install the returned record under the resolved instance name.

HTTP callout support belongs in a private shared module under
`crates/builtins/src/plugins/metadata_common/`, with `metadata_http` as its
first adapter behind the `metadata-http` feature. This is deliberately scoped
more narrowly than a generic `utils` module. Future HTTP-backed adapters reuse
request construction, authentication, cache machinery, and observation code
without creating another published crate or copying it into each plugin.

The private `metadata_common` module owns behavior that must not diverge
between HTTP-backed adapters:

- template discovery and context-specific encoding;
- HTTP request bounds and retry selection;
- outbound authentication and secret redaction;
- cache keys, storage, and single-flight;
- concurrency and circuit-breaker state;
- normalized errors, tracing, and audit events.

An adapter owns only its configuration schema, response interpretation, and
hook integration. The `AcquiredFacts` type defines the record shape;
`metadata_common` builds, caches, and observes those records. Framework code
alone validates source ownership, stamps and installs the record, derives all
evaluator projections, and renders assertions from it.

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

A compiled route may contain at most one `fetch(name)` for a given instance.
Load-time validation conservatively counts every syntactic occurrence,
including occurrences in conditional branches, and rejects duplicates even
when the conditions appear mutually exclusive. It does not defer a second
write to runtime, reuse an earlier record, or replace one; this preserves the
one-install-per-instance invariant without relying on condition analysis.

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
entry is an immutable `AcquiredFacts` record; flattened bag values are a
derived view, not the stored representation:

| Field | Meaning |
|---|---|
| `source` | plugin kind and instance name, set by the framework from trusted registration |
| `outcome` | source-owned `success` or `error`; a conditionally skipped fetch creates no record |
| `fetched_at` | wall-clock timestamp of a successful fetch, otherwise absent |
| `cache` | this evaluation's `disabled`, `miss`, `hit`, `revalidated`, or `stale` disposition, stamped on the returned record |
| `status` | upstream HTTP status when configured for exposure |
| `stale` | true only when an explicitly permitted stale value was served |
| `error_code` | normalized source error code, never raw upstream text |
| `value` | the bounded structured JSON value on success, otherwise absent |

The extension is capability-gated with a new `read_metadata` capability. The
framework, acting for the `metadata.fetch` result, owns writes; there is no
general `write_metadata` capability. It overwrites the plugin-supplied source
identity with the registered kind and instance before installation. An
instance may create its own entry once per request. A duplicate write or an
attempt to write another instance's name is a framework error. Once installed,
the structured value and provenance are immutable.

Metadata is local to one PPE policy invocation. A filtered or other child
subrequest starts with an empty `MetadataExtension`: neither the structured
record nor its derived `metadata.*` bag projection is inherited. In the Praxis
continuation path, `filter_metadata` and `structured_metadata` remain transport
and filter-lifecycle state; they must not serialize, copy, or alias PPE
`AcquiredFacts`, and the child-bound flattened context is scrubbed of the
`metadata` namespace. A child may run its own configured fetches and install
records in its own extension, but child records and extension changes are
never merged or written back to the parent. Parent response assertions retain
only the parent's record; child assertions see only the child's record. A
process-wide cache may be shared, subject to the cache partitions below, but
sharing cache storage does not share an installed record or mutable extension
state.

The fetch hook returns its result to the evaluator for publication. It does not
rely on a plugin's `modify_extensions` return: immutable slots are not merged
from ordinary plugin extension writes. Publication and bag refresh complete
before the evaluator advances to the next sequential step.

The APL route handler must receive `read_metadata` when the compiled route
contains `fetch(...)` or a `metadata.*` reference. Downstream plugins see the
slot only when their own declared capabilities include `read_metadata`.

### Bag projection and evaluator parity

The projector derives `metadata.<instance>.<path>` from the structured record.
An object response places its members directly below the instance. A text
response, or a JSON response whose root is a scalar, array, or `null`, uses the
stable leaf `metadata.<instance>.value`; the instance itself remains an object
so it can also carry provenance. Metadata instance names must match
`^[A-Za-z_][A-Za-z0-9_]*$`; the metadata adapter rejects any other name at
load even though the general plugin registry permits broader names. This
prevents an instance such as `acct.billing` from colliding with a `billing`
object published by an `acct` instance. JSON object keys containing `.` or
starting with `$` are rejected rather than made ambiguous with dotted paths
and reserved provenance fields. The top-level key `value` is also reserved:
an object root containing that key is rejected as `metadata.bad_response`, so
an object member can never collide with the leaf used for a non-object root.
Nested object keys named `value` remain valid because their paths are
unambiguous.

The `AcquiredFacts` record always retains the original bounded JSON value, so
nulls, array order, duplicate array elements, mixed arrays, and arrays of
objects survive in storage. The accepted numeric domain is deliberately the
intersection that CEL and OPA can project without conversion: signed 64-bit
integers and finite IEEE-754 binary64 values whose JSON decimal token denotes
that binary64 value exactly. The bounded parser validates decimal and exponent
tokens against the exact binary64 rational value before constructing the JSON
record. Integers outside `i64`, non-finite values, and decimals such as `0.1`
that require binary rounding fail the whole response as
`metadata.bad_response`; exactly representable values such as `0.5` and
`1.25` are accepted. CEL and OPA therefore receive a lossless projection of
every accepted record, with integers kept as integers and accepted non-integer
numbers kept as doubles. APL's flat bag receives scalar leaves and string
arrays as string sets; every other present JSON node receives `NonScalar`, so
presence is retained even when APL has no operator for its shape.

Cedar receives a direct projection at `context.metadata.<instance>`, but its
value model is not lossless JSON: `null` is omitted, arrays become unordered
sets with duplicate elements collapsed, and numbers outside Cedar `Long`
become strings. The projection uses the existing Cedar sanitizer and rejects
reserved Cedar escape keys rather than changing their meaning. A route using
Cedar must accept those semantics, and its schema must declare the sanitized
context shape when schema validation is enabled. No evaluator reconstructs a
value from flattened bag keys.

The evaluator always registers the top-level `metadata` object, even when no
fetch runs or publishes an instance. Consequently CEL
`has(metadata.account_status)` evaluates to false instead of failing on an
undeclared variable. Metadata is also a sensitive diagnostic namespace: CEL
deny diagnostics must redact it in the same way as payload namespaces rather
than printing every referenced fetched value into audit logs.
For the same absence semantics, Cedar always receives empty `metadata` and
`metadata_provenance` records when nothing was published.

Provenance fields project as reserved leaves:

```text
metadata.account_status.$source
metadata.account_status.$outcome
metadata.account_status.$fetched_at
metadata.account_status.$cache
metadata.account_status.$status       # only with expose_status: true
metadata.account_status.$stale        # only when stale
metadata.account_status.$error_code   # only for error
```

For CEL and OPA these reserved fields are sibling entries in the derived
instance object; CEL accesses a reserved name with map indexing, for example
`metadata.account_status['$outcome']`. APL receives the same fields as dotted
bag leaves. Cedar exposes the same information, with identifier-safe field
names (`source`, `outcome`, `fetched_at`, `cache`, `status`, `stale`, and
`error_code`), at `context.metadata_provenance.<instance>`; its schema must
declare that record when a policy reads provenance. When `on_error: ignore`
applies, an error publishes only the bounded provenance record, not a value.
A conditionally skipped fetch publishes no instance, so the two cases remain
distinguishable.

Fetched JSON is untrusted and bounded. Proposed defaults and hard ceilings:

| Limit | Default | Hard ceiling |
|---|---:|---:|
| response bytes | 1 MiB | 4 MiB |
| object depth | 8 | 16 |
| JSON nodes | 256 | 1,024 |
| key length | 128 bytes | 256 bytes |
| string length | 4 KiB | 16 KiB |

Booleans, signed 64-bit integers, exactly representable finite binary64 values,
and strings become bag scalars. Arrays containing only strings additionally
become APL string sets;
all arrays remain ordered JSON in the record. Objects recurse, and `null`
remains present. Duplicate object member names, non-finite numbers, invalid
keys, or exceeded limits fail the whole response with
`metadata.bad_response`; partial metadata is never published.

### Assertion projection and trust

`assertions:` accepts `metadata.<instance>.<path>` in both request and response
header entries. It reads the immutable structured record directly rather than
the flattened APL bag, so an object or array can use the existing `json`
encoding and a string array can use `csv`. A non-object root is addressed as
`metadata.<instance>.value`. Reserved `$` provenance fields are not assertion
sources; headers may project acquired values only. JSON `null` is treated as
missing for `on_missing`, matching claim-source behavior.

An assertion is an explicit trust promotion: the remote metadata service is
untrusted, but the receiving upstream or client will treat the emitted header
as PPE-authored because it trusts the network path. Configuration therefore
names the exact source path and target header; whole-instance projection is
rejected. The normal assertion rule removes the target header before
injection, so neither a client request nor an upstream response can supply a
fallback value when metadata is absent. The effective-policy artifact names
the producing plugin, labels the source as externally acquired, and records
whether its value may come from cache. There is no claim that asserted
metadata remains non-credential: an upstream may authorize on any configured
header. Cache scope, TTL, and stale policy therefore apply to assertions with
the same security weight as to authorization predicates. Mapping metadata to
`Authorization`, `Proxy-Authorization`, `Cookie`, or `Set-Cookie` additionally
requires `allow_credential_target: true` on that exact assertion entry and
emits a warning audit event at load and use time. Target header names are
parsed with HTTP header-name rules and normalized to lowercase ASCII before
credential-target classification; the four names above therefore match
case-insensitively, and mixed casing cannot bypass the opt-in. The flag applies
only to the assertion entry that names the target, not globally. Pre-injection
removal likewise removes every case-insensitive occurrence of the target.

Metadata never enters a delegator or outbound callout authentication path
automatically; crossing either boundary requires separate explicit config.

Metadata used by a request assertion must be fetched before assertion
rendering at that wire boundary. Load fails if the route cannot schedule the
named fetch first. A conditional fetch is allowed, with absence handled by the
entry's existing `on_missing` rule. Response assertions may reuse a record
acquired earlier in the same invocation; post-invocation fetching remains
forbidden.

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
| header value | reject CR, LF, and NUL; never strip them; reject `Host` as a configured or templated header name, case-insensitively |
| JSON field | insert a typed JSON value; no string concatenation |
| form field | form-urlencode |

Every reference requires the capability that protects its source slot. A
reference to `subject.id`, for example, requires `read_subject`; a reference
to a request header requires `read_headers`. Missing declarations are load
errors that name the reference and capability. Only protected slots create a
requirement: `meta.*` is currently unrestricted, so the worked example's
`meta.entity_name` reference does not require the non-gating `read_meta`
declaration. If `meta` becomes protected, the validator and example must change
together.

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
HTTP client or transport handle. The existing request type carries an attempt
timeout, connect-timeout hint, and maximum response bytes, and the host
transport remains responsible for destination policy and connection pooling.
The request-time service carrier must cap the retry budget and every attempt to
the invocation's remaining deadline. The current carrier does not yet carry
that deadline, so adding the cap is a P0 prerequisite rather than an assumed
property of `HostServices`.

The static authority rule prevents request data from choosing a destination.
Rejecting a configured `Host` header also prevents request data from selecting
a different virtual host at the pinned destination while an outbound secret is
attached.
The host must enforce DNS/IP egress policy at resolution and connection time,
including redirects if it follows them. A Praxis embedding must use
`SubRequestClient::execute_url` or an equivalent hardened executor that:

- validates the complete resolved address set before connection and repeats
  destination validation after every DNS resolution and redirect;
- derives `Host` and TLS SNI from the configured authority and prevents later
  framework headers from replacing them;
- preserves the invocation deadline, per-attempt timeout, and response-byte
  ceiling across DNS, fallback addresses, connection, and response reads; and
- never forwards an attached credential across an authority-changing redirect.

The reference transport must reject loopback, link-local, RFC1918, and CGNAT
destinations by default. The P1 real-transport test exercises rejection through
the same executor the Praxis host adapter installs, not only through a fake
transport.
The bundled `HyperTransport` currently offers only the transport-wide
`with_allow_private_destinations` switch, which admits every private and
link-local destination for every plugin using that transport. Until P2 adds a
per-destination allow-list, an in-cluster metadata service therefore requires
a separately scoped host transport or accepting that broader exposure. Plugin
YAML gets no `allow_private_networks` bypass.

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
Content-Type must agree. A text response is retained as a JSON string and
projects to `metadata.<instance>.value`. A non-object JSON root uses the same
`value` leaf; object members remain directly below the instance. Accepted
statuses default to 200 through 299. An operator may add statuses such as 404
and expose `$status` so policy can branch on them; an accepted status is not
itself an error.

GET uses `RetryPolicy::idempotent()`. POST uses
`RetryPolicy::undelivered_only()` because a delivered POST may have side
effects even when its response is lost. Configuration separates
`attempt_timeout` from the larger `total_timeout`: `HttpRequest.timeout` is the
per-attempt value and `RetryPolicy.total_budget` is the total value covering
all attempts and backoff. Load validation requires `attempt_timeout` to be
less than `total_timeout` when retries are enabled. This leaves room for a
useful retry after a fast failure while bounding the complete callout by the
policy request's remaining deadline.

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
| `metadata.bad_response` | status, content type, parse, bound, or projection failure | fatal |
| `metadata.rejected_destination` | host egress policy rejected the call | fatal |

`MetadataFetchHook` returns an `AcquiredFacts` record for every attempted
source operation, including a source-normalized `error` outcome. The evaluator
validates and stamps the registered source identity, then applies `on_error`:
`fail` converts the error outcome to a violation without installing it, while
`ignore` installs that same source-owned record and continues. Framework
failures such as an ownership mismatch, malformed hook result, plugin panic,
or missing required capability are always fatal and never become a synthetic
source outcome.

`on_error: ignore` is an explicit fail-open setting. It publishes the source's
`error` record containing bounded provenance and a normalized
`$error_code`, but no fetched value or raw error text. Policies using it must
test for a successful outcome or for the required value. A conditionally
skipped fetch publishes no instance; when neither case creates an instance,
the evaluator still exposes an empty top-level `metadata` object so existence
checks are well-defined. Error records are never cached.

Each instance has a semaphore. After cache-key construction and cache lookup,
an identical miss first joins any existing single-flight operation. Only the
leader checks the circuit breaker and acquires a semaphore permit; followers
consume no permits and wait only up to their own invocation's remaining
deadline. A different-key miss, or a leader for a new flight, fails immediately
on semaphore saturation instead of waiting behind requests already consuming
the upstream timeout. A follower cancellation does not cancel the leader, and
all followers receive the leader's normalized result; failures are not cached.
A basic circuit breaker also ships in the initial release:

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
2. Principal, tenant, and outbound-credential scope are explicit partitions,
   independent of which values happen to appear in request templates.
3. A missing or unknown partition bypasses caching; unknown scopes never
   collapse into one shared key.
4. The instance name and configuration fingerprint scope every key.
5. Credential rotation invalidates entries in the old credential partition.
6. Entries are immutable, bounded `AcquiredFacts` success records and never
   contain the outbound credential used to fetch them. Per-evaluation cache
   provenance is stamped on a copy returned from the cache, never by mutating
   the stored entry. A fetched value can cross a trust boundary only through
   an explicit assertion mapping.

The key is
`HMAC-SHA256(process_secret, instance || config_fingerprint || scope_partitions || canonical_attributes)`.
Canonical encoding is length-delimited and typed so distinct attribute tuples
cannot concatenate to the same bytes. Raw key material is never logged.

`cache.scope` declares `principal`, `tenant`, and `credential` independently.
The first two name stable attribute paths. The credential partition names a
declared outbound credential and uses its non-secret generation identifier,
not its bytes. A dimension that cannot vary may be declared `invariant` only
with a non-empty operator reason. If a declared attribute is absent, a plugin
uses dynamic credentials without a stable generation, or the source's scope is
otherwise unknown, that evaluation bypasses the cache.

The secret store exposes a monotonically changing, non-secret generation for
each resolved value and notifies metadata cache users on refresh. Rotation
evicts the old credential partition before the new generation can be used.
OAuth token refresh and a source 401 perform the same invalidation for the
credential partition they replace. If a provider cannot supply reliable
generation or refresh notification, credential-scoped caching stays disabled.

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
to 64 MiB and counts structured values and provenance; implementation overhead
needs a separate allowance. Error records are not inserted.
`ttl_seconds` is a ceiling. A later release may honor a smaller upstream
`Cache-Control: max-age`, revalidate with ETag, and optionally serve a last
good entry for at most `max_stale_seconds`. Every stale serve sets `$stale`
and emits an event.

The stored success record is a canonical cache value, not the record installed
into an invocation. For every evaluation, `metadata_common` clones the stored
facts into a fresh return record and stamps that operation's `cache` value; it
also sets `stale` only on the copy for a current stale serve. A successful
leader and followers joined to its uncached flight report `miss`; a later
lookup of the retained entry reports `hit`. A revalidation reports
`revalidated`, and a cache bypass reports `disabled`. Neither lookup nor stale
serving mutates the stored record. This stamping happens before framework code
validates and stamps source identity, installs the record, and makes it
immutable for the invocation.

The internal shared metadata support module owns canonical scope construction,
cache lookup, single-flight, invalidation, byte accounting, construction of
source-normalized `AcquiredFacts`, and callout observation; adapters do not
reimplement them. For cacheable requests, it performs the single-flight join
before semaphore admission. A `MetadataCacheStore` trait keeps storage
replaceable, but only the in-process implementation ships initially. The
existing session store is not reused: sessions and arbitrary response values
have different retention, isolation, and invalidation contracts. The framework,
not this module, validates, stamps, installs, projects, and renders assertions
from the returned record.

## Observability

Each attempt creates a tracing span with instance, method, outcome, status,
latency, retry count, cache result, and inbound trace identifiers. URL query,
headers, body, secret identifiers, and response values are excluded.

One audit event records:

- instance and source authority;
- outcome/error code and accepted status;
- cache result and stale use;
- credential-interpolation use;
- response node count and rejected-key count;
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
        scope:
          principal: subject.id
          tenant:
            invariant: true
            reason: account records are scoped solely by authenticated subject
          credential: secret.entitlement-api-token
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
              metadata.account_status['$outcome'] == 'success' &&
              metadata.account_status.active == true &&
              'report:export' in metadata.account_status.entitlements
    assertions:
      request:
        headers:
          - name: x-account-plan
            from: metadata.account_status.tenant.plan
            on_missing: deny
```

For this response:

```json
{
  "active": true,
  "entitlements": ["report:read", "report:export"],
  "tenant": {"plan": "enterprise"}
}
```

the framework retains the structured response and derives
`metadata.account_status.active`,
`metadata.account_status.entitlements`, and
`metadata.account_status.tenant.plan`; the CEL step allows and the request
assertion emits `x-account-plan: enterprise`.

If DNS, transport, timeout, authentication, status, size, or parsing fails,
`on_error: fail` returns the corresponding `metadata.*` violation and the CEL
step never runs. If the operator changes to `on_error: ignore`, the plugin
publishes an `error` record without `active` or `entitlements`; the
explicit outcome guard makes the CEL expression false, so the request still
denies. If the fetch is conditionally skipped, `has(metadata.account_status)`
is false. A fail-open policy would have to make a separate, conspicuous choice
to allow either outcome.

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
| path/header injection | segment encoding; CR/LF/NUL rejection; `Host` header rejection |
| one principal or tenant receives another's metadata | explicit scope partitions, load-time key coverage, HMAC scoping, unknown-scope bypass |
| parent metadata crosses into a child execution | empty child metadata extension, namespace scrubbing, no child-to-parent merge |
| rotated credentials reuse old cached authority | credential-generation partition and rotation invalidation |
| cached data crosses a trusted assertion boundary | exact source/target mapping, isolated cache scope, bounded TTL, credential-target opt-in, effective-policy disclosure, audit |
| plugin over-reads context | template-derived capability check plus filtered extensions |
| inbound token exfiltration | default deny, explicit flag and field allow-list, audit |
| untrusted fetched data becomes a trusted header | exact assertion source/target mapping, unconditional target removal, effective-policy disclosure |
| malicious source floods policy input | response and structure limits; atomic failure |
| anonymous amplification | authenticated-subject default, cache, semaphore, breaker |
| stale authorization after revocation | short bounded TTL; stale serving off by default |
| secret or metadata leakage in logs | redacted request/debug output, redacted CEL diagnostics, and value-free events |

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

### Define a generic PIP trait or backend registry now

Deferred. `metadata.fetch` is the stable acquired-facts contract, and ordinary
plugins can register for that hook. An HTTP source does not establish which
operations a database or another future source would share. Introduce a
source-specific trait only when a second implementation proves the common
backend surface; publication, projection, cache isolation, and observation
are already shared without it.

### Give the plugin its own HTTP client

Rejected. It would create another pool, trust store, redirect policy, and SSRF
boundary, bypassing the host's `perform_http` gate and egress controls.

### Free-form cache keys

Rejected. Documentation cannot reliably enforce principal and tenant
isolation. Explicit scope partitions provide that isolation, while template
extraction makes request-input coverage checkable at load time.

### Inline CA and client certificate material

Rejected. Named host TLS profiles keep key material out of plugin config and
allow trust stores and connection pools to be shared safely.

### Build TokenReview first

Rejected. Starting with a narrow adapter would duplicate or prematurely hide
the generic request, authentication, limit, and observation machinery.

## Implementation breakdown under [#184](https://github.com/praxis-proxy/policy/issues/184)

### P0: prerequisites

1. Add the structured `AcquiredFacts`/`MetadataExtension` record,
   per-instance ownership/provenance, immutable install semantics,
   `read_metadata`, extension filtering, child-subrequest scrubbing and
   no-write-back isolation, and derived evaluator projections.
2. Add the `MetadataFetchHook` request/result types; declare the unphased
   `metadata.fetch` hook metadata in the built-in hook table. Wire ordinary
   source factories through `PluginInstance`'s typed handler entry and the
   policy plugin registry (with `register_handler_for_names` for direct host
   registration), then use typed `invoke_named` dispatch. Classify this as
   capability-filtered PPE policy dispatch rather than a Praxis `HttpFilter`
   lifecycle hook. Do not add a generic PIP backend trait yet.
3. Add `fetch(name)` to APL parsing, route reachability, dispatch plans, and
   the pre-invocation evaluator. Publish success and ignored error records to
   the framework-owned extension and refresh the bag/PDP input before the next
   sequential step. Reject `fetch(name)` in all other positions and reject a
   second syntactic fetch of the same instance in a compiled route.
4. Grant the synthetic route handler `read_metadata` only for compiled routes
   that fetch or reference metadata.
5. Add lossless CEL and OPA projections for the accepted numeric domain, plus
   exact number-token validation and Cedar's sanitized
   `context.metadata` and identifier-safe `context.metadata_provenance`
   projections with schema tests. Always register an empty top-level metadata
   object when no instance is published.
6. Treat metadata as a sensitive namespace in CEL deny diagnostics and cover
   its redaction in audit-log tests.
7. Extend assertion sources with exact `metadata.<instance>.<path>` reads,
   load-time fetch ordering, structured rendering, provenance exclusion, and
   effective-policy trust disclosure. Require an exact-target opt-in and audit
   for credential-bearing header targets.
8. Add the invocation's remaining deadline to the request-time host-service
   carrier and cap retries and attempts before transport dispatch.
9. Define the callout error taxonomy and audit event schema.

These are prerequisites because without them the adapter would either write an
unprotected generic namespace or expose different data to different PDPs.

### P1: initial metadata PIP

1. Add the `metadata-http` feature, factory, adapter, and private
   `metadata_common` support module for callouts, structured cache records,
   normalized record construction, and observation. Keep validation, source
   stamping, installation, projection, and assertion rendering in framework
   code.
2. Implement GET/POST, static authority, metadata-instance name validation,
   context-aware template encoding, `Host` header rejection,
   template-derived capability checks, and credential-interpolation opt-in.
3. Implement shared-secret auth, bounded structured JSON retention, duplicate
   object-key rejection, exact numeric-domain validation, reserved top-level
   `value` rejection, stable `.value` projection for text and non-object roots,
   and derived projections with hard limits.
4. Use host HTTP with distinct per-attempt and total timeouts, bounded retry
   budgets, normalized errors, and a hardened URL executor preserving
   authority/SNI, destination checks, deadlines, and response limits.
5. Implement the shared in-process cache, explicit principal/tenant/credential
   partitions, HMAC keys, load-time coverage validation, unknown-scope bypass,
   single-flight joining before semaphore admission, TTL, and entry/byte bounds.
6. Expose non-secret credential generations from the secret store and evict
   the old partition on rotation; disable credential-scoped caching when a
   reliable generation or refresh notification is unavailable.
7. Add authenticated-subject gating, per-instance concurrency limits, and the
   circuit breaker.
8. Emit tracing and audit events. Document the builtin and feature flag.

P1 is useful with ordinary HTTPS services and does not require a transport
trait signature change. It does require the request-time deadline carrier and
the Praxis host adapter's hardened URL-executor wiring described above.

### P2: shared infrastructure and richer HTTP

- Named TLS profiles and optional `HttpRequest` profile selection.
- Per-destination private/link-local allow-lists in `HyperTransport`, scoped so
  enabling an in-cluster service does not admit every private destination for
  every outbound plugin.
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
- A compiled route with two `fetch(name)` occurrences for the same instance
  fails load even when the occurrences are in different conditional branches.
- Filtered and other child subrequests begin without parent `AcquiredFacts` or
  derived `metadata.*`; child fetches do not alter parent records,
  `filter_metadata`, or `structured_metadata`.
- Metadata instance names outside `^[A-Za-z_][A-Za-z0-9_]*$` fail at load.
- Protected template sources require their gating capability; unrestricted
  `meta.*` references do not acquire a fictitious `read_meta` requirement.
- CEL, OPA, Cedar, and APL see the same allowed scalar and string-set values;
  Cedar's documented null, number, and set conversions are covered separately.
- CEL receives an empty `metadata` object when no fetch publishes an instance,
  and deny diagnostics never include fetched metadata values.
- Structured records and the CEL/OPA projections preserve nulls, array order,
  duplicate array elements, mixed arrays, and arrays of objects. Cedar tests
  pin its sanitized projection, and no evaluator reconstructs metadata from
  flattened keys.
- Numeric tests accept `i64` boundaries and exactly representable decimals,
  preserve their CEL/OPA types and values, and reject out-of-range integers
  and rounding decimals such as `0.1` atomically.
- Text and non-object JSON roots project at `.value` without colliding with
  provenance; object roots retain direct member paths and reject a top-level
  `value` member, while nested `value` members remain valid.
- Assertions render exact metadata value paths in both directions, reject
  whole-instance and provenance sources, remove spoofed target headers,
  enforce fetch-before-render ordering, and require explicit credential-target
  opt-in where applicable. Table-driven cases use mixed-case spellings of
  `Authorization`, `Proxy-Authorization`, `Cookie`, and `Set-Cookie` to prove
  classification, opt-in enforcement, and spoofed-header removal are
  case-insensitive.

### Cache isolation

- Load fails when any request reference is absent from `cache.key`.
- An exemption without a reason fails; accepted exemptions audit at load and
  use time.
- Principal, tenant, credential generation, instance, and config changes
  produce distinct keys even when a scope value is absent from the request
  template.
- Missing key attributes and unknown scope partitions bypass cache and never
  share a null key.
- Credential rotation evicts the old partition before the new generation is
  used; providers without reliable generation notification bypass caching.
- A successful uncached fetch projects `$cache: disabled`; cached outcomes use
  only the other declared cache states.
- A retained-value test performs a miss followed by a hit and proves the first
  returned record reports `$cache: miss`, the second reports `$cache: hit`, and
  the immutable stored entry is unchanged. Joined followers report `miss`.
- With `max_concurrent_callouts: 1`, a second concurrent identical miss joins
  the first flight before semaphore admission and makes one upstream call;
  a different-key miss is rejected as overloaded, and errors are not cached.
- Large responses evict entries before the configured byte limit is exceeded.
- Property tests cover canonical encoding and HMAC derivation.

### Failure handling

- Fake-transport tests cover every error code, GET/POST retry policy,
  per-attempt and total budgets, size limit, malformed JSON, rejected status,
  and auth rejection.
- Route tests prove fetch occurs after identity and before APL/CEL/OPA/Cedar,
  that a subsequent APL predicate and each PDP see the published result in the
  same invocation, and that a fetch violation prevents the decision from running.
- Fail-open tests prove no partial value or raw error text is published, an
  ignored `error` record differs from a skipped fetch, and the worked example
  denies for both outcomes.
- The same source-owned error record drives both modes: `fail` converts it to a
  violation without publication, while `ignore` installs it unchanged.
- Deterministic clock tests cover semaphore saturation and every breaker
  transition; cache hits remain available while open.
- Security tests cover encoded traversal, header injection, case-insensitive
  `Host` header and authority interpolation rejection, credential
  exfiltration, and bag-limit attacks.
- A real-transport test covers destination rejection through Praxis's
  `SubRequestClient::execute_url` or the installed equivalent, including
  authority/SNI integrity, complete-address-set rejection, deadline capping,
  and response limits. Benchmarks record cache-hit and miss overhead before
  assigning a numeric performance budget.

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
| hook metadata table and family enforcement | `crates/ppe-core/src/hooks/metadata.rs` |
| plugin factory and typed-handler registration | `crates/ppe-core/src/factory.rs`, `crates/ppe-core/src/engine.rs` |
| explicit builtin factory registration | `crates/ppe/src/lib.rs` |
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
