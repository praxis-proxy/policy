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

The fetch runs inside the APL route handler, and both share
`engine_settings.plugin_timeout`. A source adapter that maps transport failures
to records must set its own request deadline so that it fits inside what is
left of that budget after the route's earlier steps, with enough time to
construct and return (for example) a `metadata.timeout` record. If the budget
runs out first, the route times out as a whole and `ignore` does not apply. PPE
cannot validate this ordering at load because adapter deadlines live inside
source-specific configuration.
