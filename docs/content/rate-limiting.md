# Rate limiting

`ratelimit/limitador` counts requests with an in-process [Limitador] limiter.
Enable the `experimental-ratelimit` Cargo feature and register the enabled
builtin factories with `praxis_policy::install_builtins`. The plugin is
excluded from the `builtins` feature, so enable it by name even if you use
`builtins`. It runs with the default `dispatch: policy` mode.

Each instance runs at one hook. Use `ratelimit.pre_identity` for an edge
limit that runs before token verification. Use `ratelimit.post_identity` for
limits keyed on a resolved subject or claim. A route's `rate_limits:` list
selects the plugins; the plugin's `hooks:` selects its stage.

| Hook | Common inputs |
| --- | --- |
| Pre-identity | request line, client address, request headers |
| Post-identity | those plus resolved identity attributes |

The post-identity attributes include `subject.*`, `claim.*`, `role.*`,
`perm.*`, `team.*`, `client.*`, `caller_workload.*`, `delegation.*`, and
`delegated`. A pre-identity rule may read caller headers in its conditions,
but cannot use them as counter keys.

## Limit requests before identity

This policy allows 50 requests per second from each client address:

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

The host must supply `http.client_address` from the TCP peer or a trusted
proxy hop. An absent address denies the request with
`ratelimit.missing_attribute`; the plugin cannot make a useful per-address
counter without it. `read_headers` lets the plugin read that attribute.
The host must also call the rate-limit hooks as described under
[Host integration](#host-integration).

## Limit requests after identity

Add the following plugin to a policy that already resolves `subject.id` and
`claim.plan`. List it under `global.rate_limits` or on the routes it should
protect:

```yaml
plugins:
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

Each subject gets 100 requests per minute. A free-plan POST also spends one
of that subject's 10 requests under the second limit. Because this plugin
runs before APL policy, a request denied later by policy still counts.
The `/toys` route replaces the inherited limiter with a separate limit of
five requests per minute for each subject.

A route that has no authentication but inherits a limit keyed on identity
will deny requests missing that identity. Remove the inherited limiter on
that route with
`rate_limits: { replace_inherited: true, steps: [] }`. The load raises
`rate_limit_without_authentication` until you resolve identity or remove
the limiter.

## Conditions, bindings, and counter keys

`bindings` maps flat CEL names to string-valued PPE attributes. If omitted,
it contains `subject_id: subject.id` and `http_method: http.method`. An
explicit map replaces both defaults. The plugin uppercases the HTTP method
before binding it, so `get` matches `http_method == 'GET'`. It resolves only
bindings that a rule references. A missing or non-string referenced
attribute denies before counters change.

`conditions` decide whether a rule applies. `variables` choose its counter
key. A rule with no `variables` uses one shared counter for all matching
requests; a rule with `variables: [subject_id]` gives each subject a counter.
Every matching rule must produce a key. For example,
`{'alice': 'known'}[subject_id]` produces no key for Charlie. If the rule
matches Charlie, the plugin denies with `ratelimit.check_failed` (503)
before changing this instance's counters. To apply the rule only to Alice,
put `subject_id == 'alice'` in `conditions`.

Conditions and variables use Limitador CEL (parsed with `cel` 0.12) over
the binding names, rather than the `cel:` decision point's attribute-bag
dialect. CEL macros such as
`exists`, `all`, `map`, and `filter` can introduce local names. For example,
`['/api/'].exists(prefix, path.startsWith(prefix))` needs a binding for
`path`, not for the local `prefix`. An unbound free name fails the load.
Limitador's `limit.name` and `limit.id` metadata are available in
conditions, not counter expressions.
There is no mapping from Kuadrant's `auth.identity.*` or `request.*`
attributes; bind PPE attributes explicitly.

## Placement and configuration

`rate_limits:` is accepted at `global`, `global.defaults.<entity>`, groups,
and routes. The engine combines those layers in that order. One list feeds
both rate-limit hooks, and each plugin runs at the hook it declares.
The list and `replace_inherited` forms match `authentication:`; see
[Configuration](configuration.md#rate-limits) for the full syntax.

A step's `config:` must be a mapping. The engine merges it key by key over
the plugin's config and creates a separate limiter for that step. For
example, the `/toys` route above gets a separate counter for each subject. Its
`replace_inherited` drops the global limiter, so the load raises
`rate_limits_replaced_inherited`. Without `replace_inherited`, both the
base limiter and the override run. Listing the same base limiter twice
without an override still runs it once per request; the load raises
`rate_limit_listed_twice`.

The plugin accepts only one of the two rate-limit hooks, `mode: sequential`,
and `on_error: fail`. Those last two values are defaults and need not be
written. A pre-identity instance cannot bind identity-derived attributes.
It also cannot key a counter on caller-controlled attributes such as
`http.request_headers.*`, `http.query`, `http.path`, `http.host`, `args.*`,
or `custom.*`: changing a value would start a fresh counter. Those
attributes may appear in conditions. A post-identity counter keyed on one
loads with a warning. A pre-identity plugin cannot be listed on a non-HTTP
route, and the plugin cannot run from an APL `run(name)` step.

`max` and `seconds` must be positive. `seconds` cannot exceed
9,223,372,036,854; a larger window fails at load because Limitador stores
expiry as a `u64` microsecond timestamp. Invalid merged overrides also
fail the load.

## Host integration

The host calls `ratelimit.pre_identity` once per inbound request before the
first `identity.resolve`, and `ratelimit.post_identity` once after the last.
It supplies the request line and entity metadata at both hooks and passes
the returned context table to the next hook. A host may skip a hook when
`PolicyEngine::has_hooks_for` reports no plugins on it. If identity runs
without a required pre-identity call, the engine raises
`rate_limit_stage_skipped` once per cycle.

The host sets `http.client_address` from a trusted source. The extension
strips ports, converts IPv4-mapped IPv6 to IPv4, and reduces other IPv6
addresses to their /64 prefix. It drops invalid values. Do not use an
unverified `X-Forwarded-For` header as the client address. If the host
rebuilds extensions between hooks, it must set the address again. See
[HTTP Routing](http-routing.md#rate-limit-hooks) for the hook coordinates,
context table, address trust, and denial handling.

## Denials and alarms

The host stops the request on a rate-limit denial. The violation carries its
HTTP status in `proto_error_code` and `details.http.status`:

| Code | Status | Cause |
| --- | ---: | --- |
| `ratelimit.exceeded` | 429 | a counter is exhausted |
| `ratelimit.check_failed` | 503 | a computed key or check failed |
| `ratelimit.no_identity` | 401 | a bound subject is absent |
| `ratelimit.no_http_method` | 400 | a bound method is absent |
| `ratelimit.missing_attribute` | 400 | attribute missing or unreadable |
| `ratelimit.unsupported_attribute` | 400 | a bound attribute is not a string |
| `ratelimit.unavailable` | 503 | the running engine lacks a listed limiter |

`ratelimit.unavailable` comes from the engine, including when a base plugin
is unregistered after the configuration loads. Reload the configuration or
register the plugin again. For `ratelimit.check_failed`, inspect the
operator log for the failed rule or expression. The client-facing reason
does not contain binding, attribute, capability, limit, or namespace names.

A 429 carries `http.status`, `limit`, `remaining`,
`retry_after_seconds`, and `window_seconds` in `details`. The retry value
is a whole number of seconds, at least 1. The limit name and namespace go
to the operator log, not the response. Other plugin denials carry
`http.status` alone. The host may map the 429 fields to `Retry-After` and
RateLimit headers.

The engine also logs these alarms:

- `rate_limits_replaced_inherited` at load when a layer drops inherited
  limiters;
- `rate_limit_without_authentication` at load when a post-identity limiter
  has no authentication steps on a route;
- `rate_limit_listed_twice` at load when a route lists one base limiter
  more than once;
- `rate_limit_stage_skipped` once per cycle when identity runs without the
  required pre-identity hook.

## Counter lifetime and limits

Counters are local to each plugin instance. Checks and updates are
serialized, so concurrent requests to one instance cannot exceed its
limit. A step with a `config:` override has its own counters, shared by
every route inheriting that step. All counters reset when the process
restarts or the configuration loads again, even if the limiter's config
did not change. Replicas do not share counters.

`counter_capacity` defaults to 10,000. Limitador holds about that many
counters with `variables`. When the store fills, a new key may evict a less
used counter or be left out. Either way, the affected counter starts at
zero. A rule without
`variables` has a shared counter that is never evicted. Limitador provides
no eviction event, so the plugin cannot log one. A small capacity (below
10,000) for a counter keyed on `http.client_address` or a caller-controlled
attribute raises a load-time warning.

Each IPv6 /64 gets its own address key. A client with a larger allocation
can rotate among /64s. Pair a per-address rule with a coarser rule, such
as one with no `variables`.

Limitador can panic on a condition that fails at request time, such as
`int(subject_id)` for a non-numeric subject. The plugin checks conditions
before calling Limitador and denies evaluation errors with
`ratelimit.check_failed`. A `catch_unwind` guard contains unexpected
Limitador panics, which still invoke the host's panic hook. A build with
`panic = "abort"` cannot contain a panic, so the plugin refuses to load.

`quota/limitador` serves a different purpose: it checks and reports token
budgets at `cmf.llm_input` and `cmf.llm_output` against a remote Limitador
service. Its counters can survive restarts and be shared by replicas.

[Limitador]: https://github.com/Kuadrant/limitador
