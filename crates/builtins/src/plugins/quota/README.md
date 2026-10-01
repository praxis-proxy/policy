# Token quota (Limitador)

A per-principal token budget, enforced as a policy against a standalone
[Limitador](https://github.com/Kuadrant/limitador). The plugin registers two
hooks: a pre-invoke check on `cmf.llm_input` that admits or refuses a request,
and a post-invoke debit on `cmf.llm_output` that charges the tokens the
response used. The counter lives in Limitador, so the budget itself persists
across restarts and across replicas. The plugin's pending-debit state (see
Failure behavior) does not: it is per replica and in process, so it is lost on
restart and not shared between replicas.

The budget is a soft cap. The check probes with a delta of one and charges
nothing. The debit records the real spend after the response, and runs
asynchronously: the response is released before the debit lands. So the
overrun window covers both concurrent requests for the same principal, which
each pass their own check before any debit lands, and the principal's next
sequential request, which can be admitted against the pre-debit counter while
the previous `/report` is still in flight (bounded by `timeout_seconds`). A
burst can therefore exceed the budget by roughly the requests admitted within
one `/report` latency. Size budgets with that headroom in mind. Do not treat the
quota as a hard admission limit.

## Config

Written under `plugins[<name>].config`.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `endpoint` | string | required | Limitador base URL, e.g. `https://limitador.grid-system.svc`. The plugin POSTs to `{endpoint}/check` and `{endpoint}/report`. |
| `namespace` | string | required | Limitador limit namespace the counters live under, e.g. `grid-tokens`. The budget value itself lives in Limitador's `limits.yaml`, not here. |
| `identity_claim` | string | `sub` | Which resolved-identity value keys the budget, and the Limitador descriptor key. `sub` reads the authenticated subject id. Must be a verified, always-present claim (see Identity). |
| `on_error` | `deny` \| `allow` | `deny` | What to do when a Limitador call fails for a transient reason (timeout, refused connection, dropped socket, oversize response, or a 5xx). `deny` fails closed, `allow` serves. Never governs an over-budget verdict or a Limitador status other than 5xx. A connect failure counts as transient even when its cause is permanent (an untrusted certificate, a wrong host, a wrong port), so under `allow` such a misconfiguration serves unmetered (see Failure behavior). |
| `timeout_seconds` | integer | `5` | Nonzero per-call HTTP timeout, so a slow Limitador fails fast into the failure path rather than stalling the request. |
| `missing_usage_charge` | integer | `1000` | Tokens debited when usage cannot be determined (a streamed response, or a provider without typed usage). Non-zero so the balance still moves; over-charge is the fail-closed direction. Size it at or above the largest response a principal may draw (see Usage metering). |
| `insecure_http` | bool | `false` | Allow a plaintext `http://` endpoint. Default requires `https://` so the host transport encrypts the connection to Limitador. Set `true` only for a localhost or demo Limitador with no TLS; the principal's subject id then crosses the network in cleartext (see Security requirements). |
| `allow_unauthenticated` | bool | `false` | Whether to serve a request that carries no resolved identity. Default denies (nothing to meter, so fail closed). Set `true` only when authentication is enforced upstream and an unauthenticated request should pass unmetered by design. Every such request then logs a warning. |

`endpoint` and `namespace` must be non-empty; `timeout_seconds` and
`missing_usage_charge` must be greater than zero. Invalid values or unknown
config keys fail plugin construction.

## Usage metering

The debit charges the gateway's typed usage: the `total_tokens` the completion
extension carries after the response. The response body is not parsed for a
token count. The `cmf.llm_output` message carries the model's generated text,
not the provider's usage block, so a body total would meter on model output and
is easy to forge.

When typed usage is absent or reports zero, the debit falls back to
`missing_usage_charge`. Accurate metering therefore requires the gateway to
populate typed usage on the completion extension; without it every response
debits the flat fallback.

### Streaming

A streamed response usually carries no typed usage, so its debit falls to
`missing_usage_charge`. This closes the free-request hole (a stream is never
charged nothing) and its fail-closed direction is over-charge, but it is not
accurate metering: if the fallback is smaller than a stream's real token count,
that stream under-meters. Two conditions keep it from bypassing the budget: size
`missing_usage_charge` at or above the largest response a principal may draw, and
prefer a gateway that aggregates streamed usage into the typed completion usage
(OpenAI's `stream_options: {include_usage: true}`, for example), which routes the
stream back through the exact typed path.

The plugin cannot fail a streamed request closed on its own. The pre-invoke check
sees a normalized CMF message, not the raw request, so it has no `stream` flag to
gate on, and the post-invoke debit cannot deny once the response has begun.
Fail-closed-on-stream would need the gateway to surface a stream signal the check
could read; until then, size the fallback and populate typed usage.

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
    kind: quota/limitador
    hooks: [cmf.llm_input, cmf.llm_output]
    capabilities: [read_subject, read_claims, perform_http]
    config:
      endpoint: https://limitador.grid-system.svc:8443
      namespace: grid-tokens
      identity_claim: sub
      on_error: deny
      timeout_seconds: 5
      allow_unauthenticated: false
      # insecure_http: true   # only for a localhost/demo Limitador with no TLS
```

The plugin registers both hooks itself; the `hooks` list in config has no
effect.

### Host HTTP transport

For a standalone host, enable `experimental-quota` and `http-hyper`, then call
`praxis_policy::install_builtins_with_default_http_transport(&engine)` before
loading the policy. It installs hyper when no transport has been injected. A
host with its own transport calls `engine.set_http_transport(...)` first; the
helper keeps that transport.

The bundled hyper default refuses private destinations. For an in-cluster
Limitador, inject a host transport with a scoped egress allowance for its
address before calling the helper. `HyperTransport::with_allow_private_destinations`
is available for controlled environments, but permits every private address.

## Identity

`identity_claim` must name a claim the gateway verifies and that is always
present on an authenticated request. `sub` is the only safe default. It reads
the authenticated subject id. A client-supplied claim can be dropped or forged
to change the descriptor the budget is keyed on, so do not key a budget on one.

## Security requirements

This plugin meters a principal identified only by its subject id. It sends no
credential of its own to Limitador and trusts the deployment to establish who
the caller is and to protect the counter. Three controls are required for the
budget to mean anything.

Authenticate before this plugin runs. The budget is keyed on the resolved
subject id, which an upstream identity plugin or the gateway must have verified.
With `allow_unauthenticated: false` (the default) an unresolved identity denies,
but the plugin cannot tell a forged subject from a real one; that is the
authenticator's job.

Isolate each issuer in its own Limitador namespace. Counters are keyed by
subject id within a namespace, and a subject id is unique only within its
issuer. Two issuers that mint the same `sub` under one `namespace` share a
budget, so one tenant's spend can exhaust another's. Give each issuer its own
`namespace`.

Secure the connection to Limitador. The plugin identifies a principal by its
plaintext subject id in the request body and sends no credential, so any
workload that can reach Limitador can debit or check any principal: a
`POST /report` with a victim's subject id drains that victim's budget. Restrict
who can reach Limitador and authenticate the connection with mTLS or an
equivalent. The `endpoint` must be `https://` by default, so the host transport
encrypts the connection; `insecure_http: true` opts into plaintext for a
localhost or demo Limitador only. The transport is the host's (see Deployment),
so TLS, the CA trust store and any client certificate for mTLS are configured on
the host transport, not in this plugin.

The bundled `ppe` hyper transport trusts only the webpki public roots and
presents no client certificate. An `https://` endpoint for an in-cluster
Limitador signed by a service CA or any private CA therefore fails to verify
with that transport, and it cannot do mTLS. For https or mTLS to such a
Limitador, the host must install a transport configured with that CA and a
client identity. Do not fall back to `insecure_http` to work around it.

The plugin reads only the subject id it keys on, never a credential.
`read_subject` exposes that id; `read_claims`, required for a non-`sub`
`identity_claim`, also exposes the subject id.

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
| No transport, `perform_http` withheld, a malformed request, or a Limitador status other than 200, 429 or 5xx (a 1xx, a 3xx redirect, a non-429 4xx) | deny, regardless of `on_error` | `quota.backend_unavailable` |
| Host refused the call (egress policy, SSRF guard, open circuit) | deny, regardless of `on_error` | `quota.egress_denied` |
| Transient Limitador failure (timeout, connect, io, oversize, or a 5xx) | `on_error`: `deny` denies, `allow` serves | `quota.backend_unavailable` (under `deny`) |

`on_error` governs only the last row, and every other fault fails closed on its
own. One gap remains: the host transport reports every connect-phase failure as
a connect error, including an untrusted certificate, an unknown host and a
refused port, so under `on_error: allow` those misconfigurations serve
unmetered. Keep `deny` unless an outage should pass traffic, and alert on the
rate of the `on_error` warning.

The debit path (`cmf.llm_output`) never denies, and it runs off the response
path: the `/report` call is dispatched asynchronously so a slow Limitador does
not add its round trip to the response tail. A failed debit is recorded as a
per-principal pending debit and re-reported by the next admission, which is
denied (`quota.unsettled_debit`) until it lands. The pending state is per
replica and in process: a restart loses it. On shutdown the plugin drains
in-flight debits, bounded by `timeout_seconds`, so a clean restart lets them
land or record; a debit still in flight when that bound elapses, or when the
process dies, is lost.

Neither call retries: `/report` increments unconditionally, so a repeat would
double-charge, and `/check` skips retry to keep tail latency off the admission
path.
