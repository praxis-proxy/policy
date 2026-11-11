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
`AcquiredFacts`; the fetch therefore denies even under `ignore`. A source
adapter that maps transport failures to records must set its own request
deadline shorter than `engine_settings.plugin_timeout`, leaving enough time to
construct and return (for example) a `metadata.timeout` record. PPE cannot
validate this ordering at load because adapter deadlines live inside
source-specific configuration.
