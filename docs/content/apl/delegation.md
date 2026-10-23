# Delegation and Token Exchange

When PPE forwards an operation to a backend, the backend needs a credential.
Forwarding the caller's inbound token is usually wrong: it is scoped for the
agent, not the backend, and it carries more privilege than the operation needs.
Delegation mints a fresh, narrowly scoped credential for the specific downstream
call.

## Delegation requirement

The scenario's `get_compensation` reads from a backend HR system that expects
its own audience-scoped token with only the `read_compensation` scope. The
caller never holds that token. PPE must exchange the caller's verified identity
for a downstream credential, scoped down to exactly what the operation needs,
and only after authorization has passed.

## Delegation as an effect

`delegate` is an effect in the `authorization.pre_invocation` phase. It names a
delegator plugin and the target it mints for:

<!-- validate: route-body -->
```yaml
authorization:
  pre_invocation:
    - "require(role.hr)"
    - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
    - "delegation.granted.permissions contains 'read_compensation': allow"
```

The order matters. The `require` gate runs first, so a credential is only minted
for a caller who passed authorization. After the exchange, a post-check verifies
the credential actually carries the scope requested, and denies the operation if
the IdP returned less.

![The delegation flow: the caller's verified token enters delegate(workday-oauth), which performs an RFC 8693 exchange at the IdP token endpoint; the resulting downstream token is audience- and scope-limited, delegation.granted.permissions is verified before forward, and only the minted token reaches the backend](../../images/apl_delegation_flow.svg)

## The delegator plugin

The bundled `delegator/oauth` plugin performs RFC 8693 token exchange against an
IdP token endpoint:

```yaml
plugins:
  - name: workday-oauth
    kind: delegator/oauth
    hooks: [token.delegate]
    config:
      token_endpoint: "https://idp.example.com/realms/agents/protocol/openid-connect/token"
      client_id: "ppe-gateway"
      client_secret_source:
        kind: file
        path: /etc/ppe-secrets/client-secret
      default_outbound_header: "Authorization"
```

It exchanges the caller's inbound token for one scoped to `audience` with the
requested `permissions`, and attaches it to the outbound request. The result
populates delegation attributes that later rules read.

The bundled `delegator/vault` plugin resolves an existing PAT or API key from
Vault KV v2 instead of minting an OAuth token. It requires
`perform_http`, `read_inbound_credentials`, the relevant identity-read
capability, and `write_delegated_tokens`. `scheme_prefix` explicitly controls
the outbound header value: use `"token "` for GitHub-style Authorization values,
`"Bearer "` where required, or omit it for a bare `X-API-Key`. See the
[Vault recipes](../identity-delegation.md#recipe-8-a-users-vault-stored-credential)
for Vault policy, enrollment, and complete configuration.

## Choosing who the exchange is for

By default a `delegate` step exchanges the user's token: the minted
credential speaks for the user, on-behalf-of style. Two step keys change that:

| Key | Meaning | Accepts | Default |
|-----|---------|---------|---------|
| `subject` | Whose identity the minted token speaks for. | `user`, `client`, `caller_workload`, `this_workload` | `user` |
| `actor` | An additional credential recorded as the RFC 8693 `actor_token`, naming who is *acting*. | `user`, `client`, `caller_workload` | none |

`actor` accepts only inbound credentials, because an actor is by definition a
party that presented itself to us. `subject` additionally accepts
`this_workload` — us — which is the one principal with no inbound credential at
all. (`gateway` is accepted as a deprecated alias of `this_workload`, from
before PPE was decoupled from the gateway shape.)

### On-behalf-of a user, with the agent named

The common agentic shape: a user asked for something, and an agent is carrying
it out. The user is the subject; the calling agent's SVID rides along as the
actor, so PPE asks the token service to record `act` alongside `sub`, letting
the backend see both parties.

Whether `act` lands in the minted token is the token service's call: RFC 8693
distinguishes *impersonation* (subject only, no `act`) from *delegation* (`act`
records the actor), and only a service implementing the delegation path emits
it. PPE always sends the delegation request.

Keycloak's Standard Token Exchange (v2) implements impersonation only and
silently ignores `actor_token`. Keycloak 26.8 adds delegation as a preview
feature (`token-exchange-delegation`), which handles any exchange that carries
an `actor_token`, but only when the subject token already names that actor in a
`may_act` claim: its `sub` must be the actor's user (for an agent, its service
account), and a `client_id` in it, if present, must match both the actor token's
client and the client requesting the exchange. The actor token must be an
access token, its own sender binding (such as `DPoP`) is checked, and the
minted token's `act` nests any `act` the actor token already carried. So the
subject's token has to be issued with `may_act` for the actor in advance,
typically by a protocol mapper. Where neither is in place, capture the actor at
the PPE boundary instead (audit, or an asserted downstream header).

<!-- validate: phase-list -->
```yaml
- "delegate(workday-oauth, target: workday-api, subject: user, actor: caller_workload,
            audience: workday-api, permissions: [read_compensation])"
```

### An agent acting on its own

A scheduled or background agent with no user in the loop exchanges its own SVID:

<!-- validate: phase-list -->
```yaml
- "delegate(workday-oauth, target: workday-api, subject: caller_workload,
            audience: workday-api, permissions: [read_compensation])"
```

This requires a `role: caller_workload` identity resolver to have populated the
SVID slot. With no workload credential present the exchange has no subject token
and is denied rather than silently falling back.

### The enforcement point calling as itself

A common deployment (an MCP gateway is one shape): agents authenticate to PPE,
but *this instance* is the one holding access to the backend tools. The agent
never possesses a credential the backend would accept.

<!-- validate: phase-list -->
```yaml
- "require(role.hr)"
- "delegate(workday-oauth, target: workday-api, subject: this_workload,
            audience: workday-api, permissions: [read_compensation])"
```

`subject: this_workload` has no inbound credential to exchange, so the delegator
switches from RFC 8693 token exchange to an RFC 6749 §4.4
`client_credentials` grant: no `subject_token` is sent, and this instance's
identity is the OAuth client identity it already authenticates with. Nothing
extra to configure — the delegator's existing `client_id` / `client_secret` *is*
this instance's identity.

This shape has two consequences:

- This instance is the only enforcement point. The backend sees a token that
  says "this instance" and has no idea which agent triggered the call. Whatever
  the `require` gates allow is what happens; there is no second opinion
  downstream. Gate accordingly.
- The minted token cannot name the calling agent. `actor_token` is a
  token-exchange parameter with no meaning under `client_credentials`, so it is
  not sent even if the step asks for one. Attribution to the calling agent lives
  in your audit log, not in the credential. Carrying the agent inside the token
  requires this instance to have a real subject credential of its own to
  exchange — its own SVID — which is not yet wired up.

### When an inbound token is `DPoP`-bound

A [`DPoP`](../identity-delegation.md#binding-tokens-to-the-callers-key-dpop)-bound
token can be used only by the client it was issued to, with a proof from that
client's key. An IdP may also refuse to let any other client exchange it, and
Keycloak does. PPE verifies such a token on the way in but cannot produce that
proof, so the token cannot be the one a `delegate` step sends:

| Step | Sends | With a `DPoP`-bound inbound token |
|------|-------|-----------------------------------|
| `subject: user` | the user's token | works while the user's token is not itself bound |
| `subject: client` | the client's token | refused by an IdP that holds bound tokens to their client |
| `actor: client` or `actor: user` | that token as `actor_token` | refused the same way: the IdP checks the actor's binding too |
| `subject: caller_workload`, `actor: caller_workload` | the SVID | unaffected: a JWT-SVID is not `DPoP`-bound |
| `subject: this_workload` | no inbound token | works |

When the IdP refuses, the step is denied with `delegation.idp_rejected`, and
the reason says which token sent was bound and what to change; the token is
named in `details.bound_tokens`. [Recipe 11](../identity-delegation.md#recipe-11-an-agent-with-a-dpop-bound-token)
shows both working shapes: exchanging a separate user token, and delegating on
this instance's own credential.

### Who the minted token speaks for

Each exchange is attributed to exactly one principal, and the attribution is
derived from `subject` rather than declared:

| `subject` | Attribution | Speaks for |
|-----------|-------------|-----------|
| `user` (default) | `on_behalf_of_user` | The end user |
| `client` | `on_behalf_of_user` | The brokering application |
| `caller_workload` | `as_caller_workload` | The calling agent |
| `this_workload` | `as_this_workload` | This instance itself |

APL has no `mode` key. If routes could declare the attribution
independently of the credential they hand over, a route could claim to act on
behalf of a user while exchanging a workload SVID. Deriving it means the
operator states one thing — which credential — and the consequence follows.

The attribution is load-bearing beyond the audit trail: minted credentials are
cached per `(subject, workload, delegator, target, audience, scopes,
attribution)`, so tokens minted for one calling agent or one plugin instance
are never silently replaced by another's.

## Delegation attributes

After a `delegate` effect, policy can read the outcome and the delegation
context:

| Attribute | Meaning |
|-----------|---------|
| `delegation.granted.permissions` | Scopes the IdP actually granted on the minted token. |
| `delegation.depth` | How many delegations deep this request is. |
| `delegated` | True when the request is acting under a delegated credential. |
| `delegation.origin_subject_id` | The original subject at the head of the chain. |
| `delegation.actor_subject_id` | The acting subject for this hop. |

These let policy reason about the chain itself, for example
`require(delegation.depth <= 1)` to refuse deeply nested delegation, or the
post-check above to enforce least privilege on what was actually granted.

## Pipeline integration

`delegate` dispatches to a plugin implementing the `token.delegate` hook. The
minted credential is recorded in the request's delegation context and the audit
log. Because delegation is an explicit effect rather than a side effect of
forwarding, it is sequenced like any other effect: gated behind authorization,
followed by verification, and halted on error when configured with `on_error:
deny`.

## Next

- [Elicitation](elicitation.md): suspend an operation for human approval.
- [Session Taint](tainting.md): carry information-flow labels across requests.
