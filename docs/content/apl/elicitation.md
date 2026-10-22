# Human-in-the-Loop Elicitation

Some operations should not proceed on the caller's say-so alone. A large payroll
change wants a manager's approval; a destructive action wants the user to
confirm; a sensitive read wants a fresh second factor. Elicitation lets a policy
pause an operation to ask a human and resume once they respond — without
blocking the request path, and with the decision bound to the actual request
rather than to an LLM's paraphrase of it.

## Approval requirement

The scenario's `approve_raise` may run only after the requester's manager
approves, and the approval must cover the specific amount being requested. The
manager is not the caller, may take hours to respond, and their answer must be
genuine — a signed decision from the right person, not a value the agent
asserts. PPE must dispatch the ask, hold the operation open across the agent's
retries, and verify the response before letting the tool run.

## Elicitation as an effect

Elicitation is an effect in the `authorization.pre_invocation` phase. A sugar
verb names an elicitation handler plugin and who to ask:

```yaml
plugins:
  - name: manager-approver
    kind: elicitation/ciba
    hooks: [elicit]

routes:
  - tool: approve_raise
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - when: "args.amount > 10000"
          do:
            - "require_approval(manager-approver, from: claim.manager,
                                 channel: \"ciba\",
                                 scope: \"args.amount <= 25000\",
                                 purpose: \"Approve raise\")"
```

- `from` is who to ask — an attribute reference resolved against the request
  bag (here `claim.manager`, the requester's manager, who differs from the
  subject). An attribute `from` that doesn't resolve fails closed rather than
  dispatching to a bogus identity.
- `scope` is the args binding — an APL boolean expression the runtime checks
  against the live request when the response comes back.
- `purpose` is the audited, human-readable description of what is being
  asked.

The other verbs (`confirm`, `require_step_up`, `require_attestation`,
`request_info`, `require_review`) parse to the same effect with a different
kind; each selects the validation contract the runtime applies to the response.

## The model: suspend and resume

An elicitation has three short, synchronous touch-points. The hours-long human
gap lives in the channel (e.g. Keycloak CIBA), never in a blocking call:

1. Dispatch — first arrival: register the intent, open the channel
   backchannel, return a correlation id.
2. Check — on each agent retry: read status (`pending` / `resolved` /
   `expired`) without blocking.
3. Validate — once resolved: verify the response is *genuine*, then the
   runtime layers the `scope`-over-args *sufficiency* check before honoring the
   approval.

While pending, the phase suspends rather than denies. The decision stays
`Allow`, but a pending marker rides alongside it, and the host maps that to
JSON-RPC `-32120` ("not complete — retry echoing this id"). The forward rule
is one clause: *forward only when the decision is `Allow` and nothing is
pending.* Expiry, channel error, a genuine denial, or a failed validation all
fail closed (default `on_error: deny`).

![The elicitation suspend-and-resume flow: an agent request hits require_approval, which opens a Keycloak CIBA backchannel and returns -32120 with an elicitation id; agent retries hit a non-blocking status check that keeps returning pending until the channel resolves; validate then verifies genuineness and scope over the live args, forwarding to the tool when approved and sufficient, and failing closed on denial, expiry, or invalid responses](../../images/apl_elicitation_flow.svg)

## The CIBA channel plugin

The bundled `elicitation/ciba` plugin drives the ask through OpenID Connect CIBA
(Client-Initiated Backchannel Authentication) against Keycloak or any
CIBA-capable OP:

```yaml
plugins:
  - name: manager-approver
    kind: elicitation/ciba
    hooks: [elicit]
    config:
      backchannel_endpoint: "https://idp.example.com/realms/corp/protocol/openid-connect/ext/ciba/auth"
      token_endpoint:       "https://idp.example.com/realms/corp/protocol/openid-connect/token"
      client_id: "ppe-gateway"
      client_secret_source:
        kind: file
        path: /etc/ppe-secrets/client-secret
      approver_claim: preferred_username
```

`from` becomes the CIBA `login_hint`, `purpose` seeds the `binding_message`, and
`timeout` maps to `requested_expiry`. Dispatch returns an `auth_req_id` that
doubles as the elicitation id the agent echoes on retry.

## Elicitation attributes

Dispatch and resolution write `elicitation.*` attributes that later rules in the
same phase — and the audit log — can read:

| Attribute | Meaning |
|-----------|---------|
| `elicitation.id` | Correlation id the agent echoes on retry. |
| `elicitation.status` | `pending` / `resolved` / `expired`. |
| `elicitation.outcome` | `approved` / `denied`, once resolved. |
| `elicitation.approver` | Resolved approver identity, cross-checked against `from`. |
| `elicitation.channel` | Audit label for how the human was reached (not a routing key). |

## Genuineness and argument binding

Two independent checks stand between an approval and the tool call:

- Genuineness is the channel plugin's job. For CIBA, the approver identity
  is extracted from the token the OP returns and cross-checked against the
  `login_hint`. The plugin trusts the token because it comes straight from the
  OP over a client-authenticated TLS poll — it does not independently verify
  the JWT signature. That trust therefore rests on the token endpoint being
  reached over correctly configured TLS with client authentication; deploy
  accordingly (always `https://`, real client credentials) and do not point a
  CIBA handler at a plaintext or unauthenticated endpoint outside local
  development.
- Sufficiency is the runtime's job. Keycloak has no RFC 9396 rich
  authorization request, so the binding between "what was approved" and "what is
  being executed" lives in APL: the `scope:` expression is evaluated against the
  live request args at validation. A human can approve, but if the args drift
  outside `scope` (e.g. the amount was raised after approval), the operation
  fails closed regardless.

The `purpose` is recorded verbatim as the source of truth for what was approved
— it is never derived from model output.

The CIBA correlation binds the id to the selected policy route (including its
scope), exact tool name, and authenticated requester subject that opened it. A
different route, tool, or requester cannot poll or redeem the id; CIBA denies
dispatch, check, and validation without a non-empty route or `subject.id`.
OP rejection reasons report the status without reflecting the
response body, which may contain client credentials. A successful non-peek
validation consumes it atomically, so a
second application fails; an `X-Policy-Elicitation-Peek` request checks without
consuming and can be followed by one application. If a later step fails after
validation, the id is still spent. Correlations expire on their own.

## Correlation store

A pending approval spans requests, so the CIBA plugin keeps it in a
correlation store chosen by the plugin's `store:` block:

- `kind: memory` holds approvals in this process. A restart loses them, and a
  retry on another replica cannot find them.
- `kind: valkey` shares them across replicas and survives gateway restarts.
  Redeeming is atomic, so two replicas cannot both apply one approval.

Omitting `store:` uses memory and logs a startup warning naming the plugin.
`global.session_store` configures Session Taint only. It does not move CIBA
approvals unless a `store:` block references it.

The store holds who was asked and who approved, never a token. Write access to
it is still sensitive: anyone who can write the CIBA keys can mark an approval
as given. Keys are `<key_prefix>:<plugin name>:<digest>`, so two CIBA plugins
on one server never see each other's approvals, while replicas running the
same plugin share them. The key prefix keeps CIBA and Session Taint keys apart;
a separate Valkey ACL user is what keeps one credential from reaching the
other's keys.

### Shared server, separate ACL user

The recommended setup. The CIBA store reuses the session store's endpoint and
TLS through `connection: session_store`, and overrides the credentials and key
prefix:

```yaml
global:
  session_store:
    kind: valkey
    endpoint: valkey.internal:6380
    tls: true
    username: ppe-taint
    password: { env: PPE_TAINT_VALKEY_PASSWORD }

plugins:
  - name: manager-approver
    kind: elicitation/ciba
    hooks: [elicit]
    capabilities: [perform_http]
    config:
      backchannel_endpoint: https://kc/realms/corp/protocol/openid-connect/ext/ciba/auth
      token_endpoint: https://kc/realms/corp/protocol/openid-connect/token
      client_id: praxis-policy-gateway
      client_secret_source: { kind: env_var, name: CIBA_CLIENT_SECRET }
      store:
        kind: valkey
        connection: session_store
        username: ppe-ciba
        password: { file: /run/secrets/ciba-valkey-password }
        key_prefix: ciba:v1
```

A reference may override `username`, `password`, `key_prefix`,
`connect_timeout_ms`, and `command_timeout_ms`. It cannot change `endpoint` or
`tls`; use the standalone form for a different server. A reference fails to
load when `global.session_store` is absent or is not `kind: valkey`. Hosts must
load the document with `load_config_yaml`, the only loader that reads
`global.session_store`. Overriding `username` without `password`, or the
reverse, is refused, so a reference never mixes two users' credentials.

Confine each user to its own keys and to the commands its store sends. PPE
does not create or check these users:

```console
ACL SETUSER ppe-taint reset on >taint-password ~taint:v1:* resetchannels +sadd +smembers +expire +multi +exec +ping +unwatch +client|setinfo
ACL SETUSER ppe-ciba reset on >ciba-password ~ciba:v1:* resetchannels +hmset +hgetall +hset +pexpire +del +exists +multi +exec +eval +ping +unwatch +client|setinfo
```

`reset` starts each user from nothing, so it holds only the commands listed:

| Commands | Why |
|----------|-----|
| `sadd`, `smembers`, `expire` | Session Taint labels and their TTL |
| `hmset`, `hgetall`, `pexpire`, `del` | CIBA correlations and their expiry |
| `eval`, `exists`, `hset` | CIBA redeem and resolve scripts, and the commands they run |
| `multi`, `exec` | Both stores write inside a transaction |
| `ping`, `unwatch` | The pool checks a connection before reuse. Without them every request opens a new connection |
| `client\|setinfo` | The client names itself on connect. Denying it is harmless but fills the ACL log |

A missing data command fails closed: the session store errors and CIBA denies
with `elicitation.store_unavailable`. With these users, stolen taint
credentials cannot forge an approver, and stolen CIBA credentials cannot clear
Session Taint labels. Neither user can read the other's keys, list the
keyspace, or run commands outside its list.

### Separate server

The strongest isolation. A standalone block names its own endpoint, TLS, and
credentials:

```yaml
plugins:
  - name: manager-approver
    kind: elicitation/ciba
    hooks: [elicit]
    capabilities: [perform_http]
    config:
      backchannel_endpoint: https://kc/realms/corp/protocol/openid-connect/ext/ciba/auth
      token_endpoint: https://kc/realms/corp/protocol/openid-connect/token
      client_id: praxis-policy-gateway
      client_secret_source: { kind: env_var, name: CIBA_CLIENT_SECRET }
      store:
        kind: valkey
        endpoint: valkey-ciba.internal:6380
        tls: true
        username: ppe-ciba
        password: { env: CIBA_VALKEY_PASSWORD }
```

Choose it when approvals need their own failure domain, `noeviction` policy,
retention, or backups, so a full taint store cannot evict pending approvals.
The standalone form takes the same settings as `global.session_store`. TLS is
required off localhost, and the default key prefix is `ciba:v1`.

### Reference without a credential override

Convenient, but not compartmentalized. The CIBA store gets its own key prefix
and connects as the session store's user, so both stores share one trust
boundary:

```yaml
global:
  session_store:
    kind: valkey
    endpoint: localhost:6379

plugins:
  - name: manager-approver
    kind: elicitation/ciba
    hooks: [elicit]
    capabilities: [perform_http]
    config:
      backchannel_endpoint: https://kc/realms/corp/protocol/openid-connect/ext/ciba/auth
      token_endpoint: https://kc/realms/corp/protocol/openid-connect/token
      client_id: praxis-policy-gateway
      client_secret_source: { kind: env_var, name: CIBA_CLIENT_SECRET }
      store: { kind: valkey, connection: session_store }
```

A store that cannot answer, because Valkey is unreachable, slow, or returns
data that cannot be decoded, denies with `elicitation.store_unavailable`. That
is never read as an unknown id or as approved under the default `on_error`;
a step set to `on_error: continue` skips instead, as for any elicitation error.
The caller-visible reason is generic. The backend error is logged with
`alarm = "ciba_store_unavailable"`, the plugin, and the operation. A failed
store after a dispatch reached the OP also logs the `auth_req_id`, because the
approver has already been prompted.

A check or validate that fails this way can be retried with the same
elicitation id once the store recovers. A dispatch cannot: it returns no id, so
a retry prompts the approver again.

### Durability

Single use holds only while Valkey keeps acknowledged writes. A redeemed
approval comes back if the server restarts from an older snapshot, or fails
over to a replica that had not received the delete. For approvals that must
not be replayed, run the CIBA store with `appendonly yes` and
`appendfsync always`, and without failover to an asynchronous replica. Use
`noeviction` so memory pressure drops new writes instead of pending
approvals. A restart that loses data fails closed: pending approvals read as
an unknown id.

## Pipeline integration

`require_approval(...)` and its sibling verbs dispatch to a plugin implementing
the `elicit` hook, resolved by name off the route's dispatch plan exactly like
`delegate(...)`. Because elicitation is an explicit, sequenced effect — gated
behind authentication, checked on every retry, and validated before the forward
— a pending or unapproved operation never reaches the tool.

## Next

- [Session Taint](tainting.md): enforce information-flow controls across
  requests.
- [Backend Restriction](restrict.md): constrain the backends eligible for a
  request.
