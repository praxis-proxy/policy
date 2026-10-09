# Embedded request rate limit PoC

`ratelimit/limitador` runs at `http.request` and keeps counters in the
process. It is available only with the `experimental-ratelimit` Cargo feature.
Each plugin instance owns one Limitador limiter, so counters reset on restart
and are not shared across replicas. The plugin serializes each in-memory
check/update across concurrent requests to that instance.

The plugin builds a PPE attribute bag from the capability-filtered Extensions
it receives. `bindings` select string-valued bag attributes for Limitador's
flat CEL context. These bindings are the defaults:

| CEL variable | PPE bag attribute | Required capability |
| --- | --- | --- |
| `subject_id` | `subject.id` | `read_subject` |
| `http_method` | `http.method` | `read_headers` |

An explicit `bindings` map replaces the defaults. For example, add
`plan: claim.plan` along with the two defaults, grant `read_claims`, and use
`plan == 'free'` in a limit condition. The integration test proves this claim
selects a limit without hardcoding `claim.plan` in the handler. A missing or
non-string bound attribute denies the request.

There is no `auth.identity.*` or `request.*` compatibility mapping yet.
`subject_id` is PPE's resolved subject ID and may differ from a Kuadrant
policy's `auth.identity.userid` claim.
The plugin-local bag contains attributes extracted from its Extensions. APL's
route-only attributes such as `route.key` and `data.*` are not supplied to it.
Missing identity or HTTP method denies the request before updating a counter.
A Limitador evaluation error also denies. An exceeded limit sets both
`proto_error_code: 429` and `details["http.status"]: 429`; the current
gateway policy filter reads the latter for a plain HTTP 429 response.

```yaml
engine_settings:
  dispatch: policy

plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [http.request]
    mode: sequential
    capabilities: [read_subject, read_headers]
    config:
      namespace: toystore
      counter_capacity: 1000
      bindings:
        subject_id: subject.id
        http_method: http.method
      limits:
        - max: 5
          seconds: 60
          conditions: ["subject_id == 'alice'", "http_method == 'GET'"]
        - max: 2
          seconds: 60
          conditions: ["subject_id == 'bob'", "http_method == 'GET'"]

global:
  authorization:
    pre_invocation:
      - "run(app-ratelimit)"
```

The `run` step is required under policy dispatch. The `hooks` list declares
the hook for config validation; the factory registers the handler in code.
Authentication must resolve the subject before the `http.request` invocation.

Demo the in-process decision sequence from this worktree with:

```console
cargo test -p praxis-policy-builtins --features experimental-ratelimit --test ratelimit counts_alice_and_bob_independently_and_returns_429 -- --exact --nocapture
```

The output shows Alice's POST allowed without using a GET counter, five Alice
GETs and two Bob GETs allowed, then Alice's sixth and Bob's third GET denied
with `proto_error_code=429`. Each test starts a fresh engine, so rerunning the
command resets the counters. This exercises PPE's route and plugin in process;
it does not start an HTTP server or show an HTTP response on the wire.

## Global and route policy demo

The same plugin kind can have separate instances and counters. This policy
applies Alice's limit globally, then adds Bob's limit only on `/toys`. The
root-prefix route catches other HTTP paths and keeps the global policy in
effect there.

```yaml
engine_settings:
  dispatch: policy
plugins:
  - name: global-ratelimit
    kind: ratelimit/limitador
    hooks: [http.request]
    mode: sequential
    capabilities: [read_subject, read_headers]
    config:
      namespace: global-demo
      limits:
        - max: 5
          seconds: 60
          conditions: ["subject_id == 'alice'", "http_method == 'GET'"]
  - name: toys-ratelimit
    kind: ratelimit/limitador
    hooks: [http.request]
    mode: sequential
    capabilities: [read_subject, read_headers]
    config:
      namespace: toys-demo
      limits:
        - max: 2
          seconds: 60
          conditions: ["subject_id == 'bob'", "http_method == 'GET'"]
global:
  authorization:
    pre_invocation:
      - "run(global-ratelimit)"
routes:
  - http: /toys
    authorization:
      pre_invocation:
        - "run(toys-ratelimit)"
  - http:
      path_prefix: /
```

```console
cargo test -p praxis-policy-builtins --features experimental-ratelimit --test ratelimit demo_global_and_route_scoped_rate_limits -- --exact --nocapture
```

The output shows Alice's sixth GET on `/other` denied by the global policy,
Bob's third GET on `/toys` denied by the route policy, and Bob's GET on
`/other` allowed. The route selector controls which plugin instance runs;
the plugin still reads PPE attributes from its filtered Extensions.

Run the native attribute binding proof with:

```console
cargo test -p praxis-policy-builtins --features experimental-ratelimit --test ratelimit a_string_claim_from_the_ppe_bag_selects_a_limit -- --exact
```

Run the full in-process proof with:

```console
cargo test -p praxis-policy-builtins --features experimental-ratelimit --test ratelimit
```

## HTTP header binding test

The in-process test `header_binding_sets_http_429` binds
`http.request_headers.x-demo-user` and `http.method` from PPE's attribute bag.
It checks global and `/toys` route limits and both 429 fields without starting
a gateway. `X-Demo-User` is caller-controlled test input; use a resolved
`subject.id` for authenticated limits. A real HTTP gateway check remains to
be done separately.

## Using the limiter with MCP or LLM policy

This plugin has an `http.request` handler only. APL inherits
`global.authorization` steps into every route, including `tool:` and `llm:`
routes. The current gateway switches to CMF dispatch for those routes and does
not run its pure-HTTP authorization path. A single policy document that puts
`run(global-ratelimit)` under `global` and also declares an MCP or LLM route
would invoke the HTTP-only plugin in CMF context. PPE now rejects that policy
at startup with the route, plugin, and registered hooks in the error.

For the current gateway, put request admission in a **first, HTTP-only policy
filter** and the entity routes in a **second policy filter**. The first
filter runs `http.request` once for each incoming request and the gateway's
per-filter admission marker prevents a second count if the body callback runs.
The second filter can then classify and authorize the MCP or LLM entity; its
policy must not inherit the limiter step. Configure the `mcp` classifier
before the entity policy filter when using MCP routes. The gateway supports
multiple policy filter instances in one chain.

Authenticated limits must resolve `subject.id` within that first filter before
the limiter runs. A future single-filter integration would need a distinct
ingress HTTP admission stage after identity resolution and before entity
dispatch, with the ingress step excluded from inherited entity route steps.
