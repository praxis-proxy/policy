# Embedded request rate limit

`ratelimit/limitador` counts requests against limits held by an embedded
[Limitador] limiter, in process. It is experimental, available only with the
`experimental-ratelimit` Cargo feature, and excluded from `builtins`.

An instance runs at one of two rate-limit hooks, on the routes whose
`rate_limits:` list names it:

- `ratelimit.pre_identity` runs before identity resolution, so a coarse limit
  protects token verification.
- `ratelimit.post_identity` runs after it, so a limit can count per user or
  per plan.

The plugin's `hooks:` picks the stage. `rate_limits:` picks the routes, with
the same list forms and inheritance as `authentication:`. See
[Configuration](../../../../../docs/content/configuration.md#rate-limits).

## Per-user limits after identity

```yaml
plugins:
  - name: jwt
    kind: identity/jwt
    hooks: [identity.resolve]
    # config elided; see the identity/jwt plugin

  - name: per-user-limits
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject, read_claims, read_headers]
    config:
      namespace: per-user
      bindings:
        subject_id: subject.id
        http_method: http.method
        plan: claim.plan
      limits:
        - max: 100
          seconds: 60
          variables: [subject_id]
        - max: 10
          seconds: 60
          conditions: ["plan == 'free'", "http_method == 'POST'"]
          variables: [subject_id]

global:
  authentication: [jwt]
  rate_limits: [per-user-limits]

routes:
  - http: /toys
    rate_limits:
      replace_inherited: true
      steps:
        - name: per-user-limits
          config:
            limits:
              - max: 5
                seconds: 60
                variables: [subject_id]
```

Each subject gets 100 requests a minute. A free-plan POST also counts against
a second limit of 10, so it spends both. Requests to `/toys` run their own
instance, with a limit of 5 per subject in place of the global one. Because
`replace_inherited` drops an inherited limiter, the load reports it with
alarm `rate_limits_replaced_inherited`.

## Edge limits before identity

```yaml
plugins:
  - name: edge-limits
    kind: ratelimit/limitador
    hooks: [ratelimit.pre_identity]
    capabilities: [read_headers]
    config:
      namespace: edge
      bindings:
        client: http.client_address
      limits:
        - max: 50
          seconds: 1
          variables: [client]

global:
  rate_limits: [edge-limits]
```

Each client address gets 50 requests a second, counted before any token is
verified. The host must set `http.client_address`; a request without it is
denied with `ratelimit.missing_attribute`.

Both examples omit keys that already hold the only accepted or the default
value: `mode` (`sequential`), `on_error` (`fail`),
`engine_settings.dispatch` (`policy`) and `counter_capacity` (10000).
`capabilities` stays, because the plugin reads its bound attributes from
capability-filtered extensions. Without the capability that exposes an
attribute, the plugin never sees it and denies.

A route that skips authentication but inherits a post-identity limiter denies
every request whose limit binds identity. Drop the limiter there with
`rate_limits: { replace_inherited: true, steps: [] }`. Until then the load
warns with alarm `rate_limit_without_authentication`.

## How stages work

| Stage | Route list read | Attributes present |
| --- | --- | --- |
| `ratelimit.pre_identity` | `global`, `global.defaults.http`, and the matched `http:` route with its groups | the request line (`http.method`, `http.path`, `http.host`, `http.scheme`), `http.client_address` and `http.request_headers.*` |
| `ratelimit.post_identity` | the same layers for the route the request matched, of any entity type | the above, plus identity: `subject.*`, `claim.*`, `role.*`, `perm.*`, `team.*`, `authenticated`, `client.*`, `caller_workload.*`, `delegation.*`, `delegated` |

The load rejects:

- `hooks:` that is not exactly one of the two rate-limit hooks;
- `on_error` other than `fail`, and `mode` other than `sequential`;
- a pre-identity binding to an identity attribute, since none is set before
  identity runs;
- a pre-identity counter keyed on an attribute the caller picks, or that a
  host commonly fills from caller input (`http.request_headers.*`,
  `http.query`, `http.path`, `http.host`, `agent.*`, `args.*`, `custom.*`,
  `llm.input.*`, `meta.properties.*`, `provenance.*`, `request.*`), since a
  caller would reset it by changing the value. Those attributes are fine in
  `conditions`, and a post-identity counter keyed on one loads with a
  warning;
- a pre-identity plugin listed under a `tool:`, `llm:`, `resource:` or
  `prompt:` route's `rate_limits:`, or under a group only such routes join,
  since that hook runs before the request is classified;
- a step `config:` that is not a mapping;
- a `run(name)` step naming the plugin. List it under `rate_limits:` instead.

A post-identity limit counts before APL policy runs, so a request that policy
later denies still counts.

## Bindings and the CEL dialect

`bindings` maps a flat CEL variable name to a string-valued PPE attribute. The
defaults are `subject_id: subject.id` and `http_method: http.method`; an
explicit `bindings` map replaces them. The method is uppercased before it is
bound, so a lowercase `get` matches `http_method == 'GET'`.

Only bindings that a limit references are resolved per request. A missing or
non-string referenced attribute denies the request before any counter
changes.

`conditions` select which limits apply. `variables` split a limit into one
counter per distinct value. A limit with no `variables` is one counter shared
by every matching request.

Every counter expression in a matching limit must resolve to a key. A
computed expression such as `{'alice': 'known'}[subject_id]` has no key for
Charlie. If the limit's conditions match Charlie, the plugin denies with
`ratelimit.check_failed` (503) before this limiter changes its counters,
even when another matching limit has a valid key. To limit only Alice, put
`subject_id == 'alice'` in `conditions`. To give every subject a counter,
use `variables: [subject_id]`. The operator log names the failing limit
and expression; the client response does not.

Conditions and variables are Limitador CEL, parsed with `cel` 0.12, over the
bound variable names. This is not the `cel:` PDP dialect, which reads the PPE
attribute bag. Macros such as `exists`, `all`, `map` and `filter` may
introduce local names, so `['/api/'].exists(prefix, path.startsWith(prefix))`
needs a binding for `path` but not for `prefix`. An unbound free name fails
the load. Limitador's `limit` metadata (`limit.name`, `limit.id`) is allowed
in conditions only.

## Denial codes

| Code | Status | Meaning | Remedy |
| --- | --- | --- | --- |
| `ratelimit.exceeded` | 429 | the request is over a limit | retry after `retry_after_seconds` |
| `ratelimit.check_failed` | 503 | a matching counter expression has no key, or Limitador could not check the request | read the operator log and fix the expression or evaluation error |
| `ratelimit.no_identity` | 401 | a limit binds `subject.id` and the request has no subject | authenticate the route, or drop the limiter there |
| `ratelimit.no_http_method` | 400 | a limit binds `http.method` and the request has none | have the host set the request line |
| `ratelimit.missing_attribute` | 400 | a bound attribute is absent, or the plugin cannot read it | have the host set it, or grant the capability that exposes it |
| `ratelimit.unsupported_attribute` | 400 | a bound attribute is not a string | bind a string-valued attribute |
| `ratelimit.unavailable` | 503 | the engine has no instance for a `rate_limits:` step with a `config:` override | reload the configuration |

`ratelimit.unavailable` comes from the engine, not the plugin. It covers a
step whose limiter the running snapshot lacks, including a base plugin that
was unregistered after the load. A Limitador condition that fails at runtime,
such as `int(subject_id)` on a non-numeric value, makes Limitador panic. The
plugin contains the panic and denies with `ratelimit.check_failed`, and logs
the cause at most once a minute.

No reason text names a binding, attribute, capability, limit or namespace.
For the attribute codes, the plugin warns at most once a minute with which
binding failed, which capability would expose it, and how many denials it
held back in `suppressed`.

## Alarms

| Alarm | Raised | Trigger | Fix |
| --- | --- | --- | --- |
| `rate_limits_replaced_inherited` | at load | a `replace_inherited: true` drops limiters a route inherited | remove the flag if the block meant to add limits |
| `rate_limit_without_authentication` | at load | a route runs a post-identity limiter but resolves no authentication | add an `authentication:` step, or drop the limiter on that route |
| `rate_limit_listed_twice` | at load | a route inherits one base limiter from more than one section; it runs once | remove the repeat, or give one listing its own `config:` for a separate limit |
| `rate_limit_stage_skipped` | once per cycle | `identity.resolve` ran on a context table that never reached `ratelimit.pre_identity` while a pre-identity limit is in force | call `ratelimit.pre_identity` first and pass its context table on |

Each alarm is a `tracing` warning with an `alarm` field and a `route` field
naming the affected route.

## The 429 details

A `ratelimit.exceeded` violation sets `proto_error_code: 429` and carries
exactly these `details` keys, taken from the most restrictive matched counter:

| Key | Value |
| --- | --- |
| `http.status` | 429 |
| `limit` | the counter's maximum per window |
| `remaining` | what the counter has left in this window |
| `retry_after_seconds` | whole seconds until the counter resets, at least 1 |
| `window_seconds` | the counter's window length |

The limit name and namespace go to the debug log only. A host maps only these
keys into the response, for example as `Retry-After` and RateLimit headers.
The plugin's other denials carry `http.status` alone.

## Host contract

The host calls each rate-limit hook once per inbound request:
`ratelimit.pre_identity` before the first `identity.resolve`, and
`ratelimit.post_identity` after the last. It sets the entity metadata and the
request line at both calls, and passes one context table through every hook
of the request. It sets `http.client_address` from the TCP peer or a trusted
proxy hop, never from a caller header. See
[HTTP Routing](../../../../../docs/content/http-routing.md#rate-limit-hooks).

## Counters and reloads

Counters live in the plugin instance, in process. The plugin serializes each
check and update, so concurrent requests to one instance cannot exceed a
limit.

A `rate_limits:` step with a `config:` override gets its own instance and
counters. The override, which must be a mapping, is merged key by key over
the plugin's `config`, and the engine builds that instance once per loaded
configuration. Every route inheriting the step shares it. A factory that
rejects the merged config fails the load.

A limiter listed at two layers without a `config:`, say at `global` and on a
route, runs once per request. An override step is its own limiter and counts
beside the base one.

`initialize()` initializes override instances with the base plugins. A
configuration loaded into an already initialized engine builds new override
instances without initializing them, so a rate-limit kind that needs
`initialize` must be loaded into a new engine. No in-tree rate-limit kind
needs it.

Counters restart at zero when the process restarts and on every configuration
load, including a load that changes nothing about the limiter.

## Eviction

Limitador's in-memory store holds about `counter_capacity` counters that have
`variables`. When it is full, a new key either evicts a less used counter or
is kept out. Either way the affected counter restarts at zero. Counters with
no `variables` are never evicted.

Limitador gives no eviction signal, so the plugin logs none. Instead, a
counter keyed on `http.client_address` or a caller-picked attribute with a
`counter_capacity` below 10000 warns at load.

## Choosing quota or ratelimit

`quota/limitador` checks and reports a token budget against a remote
Limitador service, at `cmf.llm_input` and `cmf.llm_output`. Its counters live
in that service, so they survive restarts and are shared across replicas.

`ratelimit/limitador` embeds Limitador in process and counts requests at the
rate-limit hooks. It needs no service, but its counters are per instance and
per replica.

## Limitations

- A host built with `panic = "abort"` cannot contain a Limitador panic, so the
  factory refuses to load there. This holds until Limitador returns condition
  errors instead of panicking.
- A contained Limitador panic still runs the process panic hook, once per
  request that triggers it, which writes to stderr and captures a backtrace
  when `RUST_BACKTRACE` is set. The once-a-minute log limit does not cover
  that output. Install a throttling panic hook in the host, and avoid
  conditions that can fail on request data, such as `int(...)` on a caller
  value.
- Each IPv6 /64 is its own `http.client_address` key, so a holder of a larger
  allocation can rotate keys. Pair a per-address limit with a coarser one. See
  [HTTP Routing](../../../../../docs/content/http-routing.md#rate-limit-hooks).
- Counters are per process. Replicas do not share them, and nothing persists
  them.
- There is no shared or Redis-backed counter storage.
- There is no `auth.identity.*` or `request.*` compatibility mapping.
  `subject_id` is PPE's resolved subject ID and may differ from a Kuadrant
  policy's `auth.identity.userid` claim.

## Tests and bench

```console
cargo nextest run -p praxis-policy-builtins --features experimental-ratelimit --test ratelimit
cargo bench -p praxis-policy-builtins --features experimental-ratelimit --bench ratelimit_hot_path
```

[Limitador]: https://github.com/Kuadrant/limitador
