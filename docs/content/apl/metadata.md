# Fetched Metadata

`fetch(name)` acquires one immutable fact record from the named plugin before
the next policy step runs. It is available only in
`authorization.pre_invocation`; the result appears immediately under
`metadata.<name>.*` in the APL bag, including for a following PDP call.

```yaml
plugins:
  - name: account
    kind: metadata/account-service
    hooks: [metadata.fetch]
    on_error: fail

routes:
  - tool: submit_payment
    authorization:
      pre_invocation:
        - "fetch(account)"
        - "require(metadata.account.active)"
        - "require(metadata.account.credit_limit >= 100)"
```

The source returns one typed `AcquiredFacts` record. PPE validates it, stamps
the configured source name and kind, installs it in the request extensions,
and refreshes the APL bag. A source cannot forge another source's provenance.

CEL receives each projected record at `metadata.<name>`, and OPA receives it at
`input.metadata.<name>`. Object-valued responses expose their members directly
under that record; arrays and other non-object roots are stored under its
`value` member. Nulls, object shape, array order, duplicate elements, and mixed
arrays are preserved. Provenance is available through the reserved `$source`,
`$outcome`, `$fetched_at`, `$cache`, `$status`, `$stale`, and `$error_code`
sibling fields. The top-level `metadata` object is always present, including
when no fetch ran. CEL deny diagnostics report only `metadata=map`, never
fetched values or raw source errors.

Cedar receives values at `context.metadata` and identifier-safe provenance at
`context.metadata_provenance`. Cedar omits nulls, converts arrays to sets
(collapsing duplicates), and renders numbers outside `Long` as strings. A
schema-backed Cedar resolver must declare both records in the action context,
including when they are empty.

The common accepted numeric domain is signed 64-bit integers and exactly
representable finite binary64 decimals. Values such as `0.5` and `1.25` are
accepted; unsigned values beyond `i64::MAX` and rounding decimals such as
`0.1` reject the entire acquired record.

A source parsing a raw JSON response must construct successful facts with
`AcquiredFacts::success_json`. It validates the original number tokens before
accepting the parser's potentially rounded values. `AcquiredFacts::success`
remains available for sources whose SDK already provides a typed
`serde_json::Value`; those sources are responsible for ensuring the SDK did
not round an earlier wire token.

Each source name may occur syntactically only once in a compiled route. This
also applies across mutually exclusive `when` branches: use one fetch followed
by conditional predicates instead. Fetches are sequential effects and are not
allowed inside `parallel`.

## Source errors

An attempted source can return an error record with a normalized error code in
the reserved `metadata.*` namespace. Other code namespaces are rejected so a
source cannot impersonate a policy denial or framework control signal.
HTTP metadata sources use the following stable codes:

| Code | Class | Meaning |
|---|---|---|
| `metadata.subject_required` | fatal | no authenticated subject |
| `metadata.timeout` | recoverable | connect, attempt, or invocation timeout |
| `metadata.upstream_error` | recoverable | transport failure or upstream 5xx |
| `metadata.overloaded` | recoverable | per-source concurrency limit reached |
| `metadata.circuit_open` | recoverable | source circuit breaker is open |
| `metadata.auth_failed` | fatal | source authentication failed |
| `metadata.response_too_large` | fatal | configured byte ceiling exceeded |
| `metadata.bad_response` | fatal | invalid status, media type, shape, or projection |
| `metadata.rejected_destination` | fatal | host egress policy rejected the destination |

The plugin's configured `on_error` determines publication:

- `fail` stops the route and publishes no record.
- `ignore` publishes the source-owned error record and continues. Later policy
  can inspect `metadata.<name>.$outcome == 'error'` and
  `metadata.<name>.$error_code`; no acquired value is present.

A conditional fetch whose predicate is false publishes no instance at all.
That absence is distinct from an ignored source error. Malformed records,
missing records, and framework dispatch failures always fail closed.

`on_error: ignore` applies only when the source completes and returns a valid
error record. An executor timeout, panic, or source error returns no trusted
`AcquiredFacts`; the fetch therefore denies even under `ignore`. The same holds
when the source denies, or returns without a record.

The fetch runs inside the APL route handler, and both share the invocation's
remaining deadline. The Praxis embedding must seed that budget on request-time
`Extensions` with `Extensions::with_invocation_deadline`; Policy cannot infer a
gateway deadline. Request-time host services then preserve the absolute deadline
across nested dispatches and cap every HTTP attempt, connect hint, retry budget,
and backoff before transport dispatch. An adapter may configure a stricter
deadline but cannot extend the invocation budget. If no time remains, the host
service returns the stable transport timeout classification without dispatching
the request. Sources using `on_error: ignore` must set a request deadline within
the route budget remaining after earlier steps, leaving enough time to build
and return a trusted `metadata.timeout` record. If the route deadline expires
before the source can return that record, the framework timeout still fails
closed and `ignore` does not apply.

## Builtin HTTP source

Enable the `metadata-http` Cargo feature and call
`praxis_policy::install_builtins` to register `kind: metadata/http`. The
[loaded example](metadata-http.example.yaml) shows a complete source and route.

The source fixes scheme, host, and port at load. Templates are allowed only in
path segments, query values, header values, and whole JSON or form fields. PPE
encodes each destination in its own context, rejects dot segments and `Host`
headers, and requires HTTPS unless `request.insecure_http: true` is explicit.
Each protected template reference requires its matching read capability;
`meta.*` is unrestricted. Credential interpolation additionally requires the
source capability, `allow_credential_interpolation: true`, and the exact target
in `credential_fields`. Raw inbound tokens use
`raw_credentials.inbound_tokens.<role>.token`; they resolve directly from the
filtered request extensions and never enter the general policy attribute bag.
Missing, empty, ambiguous, or unsupported raw credential paths fail closed.

Responses default to JSON and statuses 200–299. `response.type: text` accepts
`text/plain`; configured `accepted_statuses` add statuses, and
`expose_status: true` publishes `$status`. JSON is rejected atomically on
duplicate or ambiguous keys, malformed or rounding numeric tokens, and byte,
depth, node, key, or string limit violations. Defaults are 1 MiB, depth 8, 256
nodes, 128-byte keys, and 4 KiB strings; hard ceilings are 4 MiB, depth 16,
1,024 nodes, 256-byte keys, and 16 KiB strings.

This initial transport path performs one attempt with redirects disabled by the
host transport. Retry and total-budget behavior belongs to issue #251.

## Callout audit contract

`MetadataCalloutAuditEvent` is a versioned, value-free record consumed through
`CalloutObserver`. It contains only the configured instance, parsed source
authority, outcome and normalized code, accepted status, cache and stale state,
credential-interpolation use, bounded response counts, and an optional breaker
transition. It has no fields for URL paths or queries, headers, bodies, secret
identifiers or material, response values, or raw upstream error text. Schema
version `1` is serialized in every event. The builtin emits one event for each
completed source operation through its observer, including the
credential-interpolation marker when that escape hatch was used.
