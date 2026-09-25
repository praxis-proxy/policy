# Token quota (Limitador)

A per-principal token budget, enforced as a policy against a standalone
[Limitador](https://github.com/Kuadrant/limitador). The plugin registers two
hooks: a pre-invoke check on `cmf.llm_input` that admits or refuses a request,
and a post-invoke debit on `cmf.llm_output` that charges the tokens the
response used. The counter lives in Limitador, so the budget persists across
restarts and across replicas.

The budget is a soft cap. The check probes with a delta of one and charges
nothing. The debit records the real spend after the response. Concurrent
requests for the same principal each pass their own check before those debits
land, so a burst can exceed the budget by roughly the number of requests in
flight. Size budgets with that headroom in mind. Do not treat the quota as a
hard admission limit.

## Config

Written under `plugins[<name>].config`.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `endpoint` | string | required | Limitador base URL, e.g. `http://limitador.grid-system.svc:8080`. The plugin POSTs to `{endpoint}/check` and `{endpoint}/report`. |
| `namespace` | string | required | Limitador limit namespace the counters live under, e.g. `grid-tokens`. The budget value itself lives in Limitador's `limits.yaml`, not here. |
| `identity_claim` | string | `sub` | Which resolved-identity value keys the budget, and the Limitador descriptor key. `sub` reads the authenticated subject id. Must be a verified, always-present claim (see Identity). |
| `on_error` | `deny` \| `allow` | `deny` | What to do when a Limitador call fails for a transient reason (timeout, refused connection, dropped socket, oversize response, or an unexpected Limitador status). `deny` fails closed, `allow` serves. Governs only those transient failures, never an over-budget verdict and never a permanent fault (see Failure behavior). |
| `usage_json_path` | string | `usage.total_tokens` | Fallback path to the token total in the response body, read only when the gateway's typed usage is absent. Segments split on `.` or `/`. |
| `timeout_seconds` | integer | `5` | Per-call HTTP timeout, so a slow Limitador fails fast into the failure path rather than stalling the request. |
| `allow_unauthenticated` | bool | `false` | Whether to serve a request that carries no resolved identity. Default denies (nothing to meter, so fail closed). Set `true` only when authentication is enforced upstream and an unauthenticated request should pass unmetered by design. Every such request then logs a warning. |

`endpoint` and `namespace` must be non-empty or the plugin fails to construct.
An unknown config key is rejected rather than ignored.

## Capabilities

The plugin needs all three. A missing `perform_http` always fails closed:
every metered request is denied with `quota.backend_unavailable`. A missing
`read_subject` or `read_claims` resolves the identity to `None`, which fails
closed by default (`quota.no_identity`) and serves unmetered only when
`allow_unauthenticated` is `true`.

| Capability | Why |
|---|---|
| `perform_http` | The check and debit are outbound calls, made through the host HTTP transport. Without it every metered request is denied with `quota.backend_unavailable`, regardless of `on_error`. |
| `read_subject` | Reads `security.subject.id`, which `identity_claim: sub` keys on. Without it the identity is `None`, which denies by default (see `allow_unauthenticated`). |
| `read_claims` | Reads a non-`sub` `identity_claim` from the subject claims. Required when `identity_claim` names anything other than `sub`. |

## Example

```yaml
plugins:
  - name: token-quota
    kind: quota
    hooks: [cmf.llm_input, cmf.llm_output]
    capabilities: [read_subject, read_claims, perform_http]
    config:
      endpoint: http://limitador.grid-system.svc:8080
      namespace: grid-tokens
      identity_claim: sub
      on_error: deny
      usage_json_path: usage.total_tokens
      timeout_seconds: 5
      allow_unauthenticated: false
```

The plugin registers both hooks itself; the `hooks` list in config has no
effect.

## Identity

`identity_claim` must name a claim the gateway verifies and that is always
present on an authenticated request. `sub` is the only safe default. It reads
the authenticated subject id. A client-supplied claim can be dropped or forged
to change the descriptor the budget is keyed on, so do not key a budget on one.

## Deployment

The check and debit run through the host HTTP transport, which enforces the
host's egress policy. Limitador is normally an in-cluster Service on a private
(RFC 1918) ClusterIP. A transport that blocks private destinations by default
(an SSRF guard) refuses every call to it. The plugin then denies with
`quota.egress_denied`, regardless of `on_error`, because a refused call never
reached Limitador.

Configure the host transport to permit the Limitador address, either by
allowing private destinations or by an egress allowlist entry for the Limitador
ClusterIP. Without that, no request is metered, and under the default
`on_error: deny` none is served. This is a host-transport setting. The plugin
does not control it.

## Failure behavior

The check path is the gate. Its outcomes:

| Outcome | Result | Deny code |
|---|---|---|
| Within budget | allow | |
| Over budget | deny (HTTP 429) | `quota.exhausted` |
| No resolved identity, `allow_unauthenticated: false` | deny | `quota.no_identity` |
| No resolved identity, `allow_unauthenticated: true` | allow (logged) | |
| No transport, `perform_http` withheld, or a malformed request | deny, regardless of `on_error` | `quota.backend_unavailable` |
| Host refused the call (egress policy, SSRF guard, open circuit) | deny, regardless of `on_error` | `quota.egress_denied` |
| Transient Limitador failure (timeout, connect, io, oversize, or unexpected status) | `on_error`: `deny` denies, `allow` serves | `quota.backend_unavailable` (under `deny`) |

`on_error` governs only the last row. Every permanent fault fails closed on its
own, so a misconfiguration cannot silently stop enforcement.

The debit path (`cmf.llm_output`) never denies. The response is already out, so
a failed debit is logged and the balance lags rather than blocking the request.
Neither call retries: `/report` increments unconditionally, so a repeat would
double-charge, and `/check` skips retry to keep tail latency off the admission
path.
