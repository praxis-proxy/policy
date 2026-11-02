# HTTP Routing

Most routes select an operation by name: a `tool:`, a `resource:`, a
`prompt:`, an `llm:`. An `http:` route selects on the request line
instead, so plain HTTP traffic that names no entity can still be
authorized.

One PPE instance can therefore cover an agent's tool calls and the
surrounding HTTP traffic under one APL document.

## Selector forms

A bare path, or a list of them, matches exactly:

```yaml
routes:
  - http: /admin
    authorization:
      pre_invocation:
        - "require(role.admin)"

  - http: [/metrics, /healthz]
    authorization:
      pre_invocation:
        - "allow"
```

The map form takes exactly one of `path:` or `path_prefix:`, optionally
narrowed by `method:`:

```yaml
routes:
  - http:
      path_prefix: /api/v1
      method: [POST, PUT, PATCH]
    authorization:
      pre_invocation:
        - "require(perm.write)"

  - http:
      path: /api/v1/status
      method: GET
    authorization:
      pre_invocation:
        - "allow"
```

Anything other than `path`, `path_prefix`, and `method` in that map is
a load error.

## Precedence

When more than one route could match, the winner is decided in this
order:

1. An exact path outranks a prefix.
2. A longer prefix outranks a shorter one.
3. A narrower method set breaks a remaining tie.

`/api/v1/status` above wins over the `/api/v1` prefix beside it,
regardless of declaration order.

Exact paths compare byte for byte. `/admin` and `/admin/` are two
different paths, and a route declaring one does not match the other. A
prefix is normalized instead: one trailing slash is dropped at parse
time, so `path_prefix: /api/` and `path_prefix: /api` are the same
selector. A prefix matches on segment boundaries, so `/api` does not
match `/apidocs`.

## The catch-all

A request that matches no `http:` route falls through to global policy.
That is a real decision rather than an accident, so a configuration
declaring `http:` routes without a catch-all is reported at load.

To write one, use the root prefix:

```yaml
routes:
  - http:
      path_prefix: /
    authorization:
      pre_invocation:
        - "require(authenticated)"
```

## Host obligations

Missing either obligation changes which policy runs without failing the request.

The request line at the identity hook. A route's own
`authentication:` list is only reachable if the engine knows the method
and path when identity is resolved. A host that puts them on the HTTP
extension at the identity invocation unlocks per-route authentication;
a host that does not gets global authentication instead, and the engine
warns rather than pretending the route's list ran.

The response hook, invoked explicitly. A global `result:` or
`post_invocation:` block installs a handler on `http.response`, but the
host fires it. Before turning that on, review your global post steps:
HTTP steps that were previously inert become active, and `result.*` is
absent for a request carrying no entity.

Response bodies are not modeled. The response half covers headers and
extensions.

## Rate-limit hooks

A configuration with a `rate_limits:` list needs the host to call the two
rate-limit hooks. See [Configuration](configuration.md#rate-limits) for list
syntax and [Rate Limiting](rate-limiting.md) for plugin behavior.

Order and count. Call `ratelimit.pre_identity` before the first
`identity.resolve` of a request, and `ratelimit.post_identity` after the last.
Call each once per inbound request, even when identity is resolved more than
once, as a tool call resolving at the HTTP route and again at the tool does.
Identity can run twice without side effects; a counter cannot. A host may skip
a hook when `PolicyEngine::has_hooks_for` reports nothing on it.

Request context. At both calls, set the entity metadata (`entity_type` and
`entity_name`) and the request line (method and path) on the extensions, as
for `identity.resolve`. Pre-identity runs before the request is classified,
so it uses the HTTP coordinates: `entity_type: http`, `entity_name: "*"`.
Post-identity uses the route the request resolved to, with the resolved
identity attached.

One context table. Pass the `PipelineResult.context_table` each call returns
into the next hook of the same request, starting with the pre-identity call.
That is how the engine knows the pre-identity stage ran. When
`identity.resolve` runs on a table that never reached
`ratelimit.pre_identity`, while a pre-identity limit is in force for the
request, the engine warns once with alarm `rate_limit_stage_skipped`.

Client address. Set it with `HttpExtension::set_client_address`, from the TCP
peer, or from the rightmost untrusted hop of a proxy header you configured as
trusted. Never take it from a header the caller controls, such as an
unverified `X-Forwarded-For`. The engine normalizes the value: a port is
stripped, an IPv4-mapped IPv6 address becomes IPv4, and other IPv6 addresses
become their /64 prefix. An empty or unparseable value leaves it unset, and a
limit that binds it then denies. A host that rebuilds the extensions for
`ratelimit.post_identity` sets the address again. Plugins read it as
`http.client_address` with `read_headers` and cannot change it. `Debug`
output hides it; serialized output, which audit sinks read, includes it.

One /64 is one key. A client holding a larger IPv6 allocation, such as a /48,
can rotate across its /64s and get a fresh counter for each, and enough keys
fill the counter store. Pair a per-address limit with a coarser one, for
example a limit with no `variables` shared by every caller.

Denials. A rate-limit denial comes back as `PipelineResult.violation`, with
the HTTP status in `proto_error_code`. Stop the request there: before identity
for a pre-identity denial, before policy for a post-identity one. For a 429,
map only the `details` keys `http.status`, `limit`, `remaining`,
`retry_after_seconds` and `window_seconds` into the response.

| Code | Status | Raised by | Meaning |
| --- | --- | --- | --- |
| `ratelimit.exceeded` | 429 | the plugin | the request is over a limit |
| `ratelimit.unavailable` | 503 | the engine | a `rate_limits:` step has no limiter in the running configuration, such as after the plugin is unregistered; reload the configuration or register the plugin again |

Every rate-limit denial carries its status in `details` as `http.status`. See
the plugin's denial codes for the rest.

## Reading the response status

`http.status` carries the response status to post-phase policy. The
host sets the optional value on response invocation; it enters the
attribute bag as an integer and uses the existing `read_headers`
capability.

The key is absent on requests, so a rule reading it belongs under
`post_invocation:`.

```yaml
routes:
  - http:
      path_prefix: /api
    authorization:
      post_invocation:
        - "require(http.status < 500)"
```

## Dispatch mode

`http:` routes require the default `dispatch: policy`. Under
`dispatch: hooks` a `routes:` block is a load error outright, so a
configuration carrying an `http:` route is in policy mode by
construction.

A policy body replaces the route's structural plugin chain, so a listed
plugin runs only where a step names it with `run(name)`.

## Next

- [Identity and Delegation](identity-delegation.md): resolve inbound principals
  and mint outbound credentials.
- [Header Assertions](assertions.md): control the identity and response headers
  crossing the boundary.
- [Deployment](deployment.md): place the HTTP enforcement point.
