# Identity and IdP Integration

Policy reads attributes: `role.hr`, `perm.view_ssn`, `subject.id`. Those
attributes must come from a trusted source. Identity resolution runs before
policy and turns a verified credential into the attribute bag that predicates
read.

## Identity requirement

The scenario authorizes with `require(role.hr)` and redacts with
`redact(!perm.view_ssn)`. For those to mean anything, PPE must know, for each
request, who the caller is and what roles and permissions they hold, established
from a token the caller cannot forge, not from anything the LLM said.

## Resolving identity

An identity plugin validates an inbound token and populates the subject. The
bundled `identity/jwt` plugin verifies a JWT against a trusted issuer and maps
its claims into the bag:

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      role: user
      credential:
        kind: header
        name: X-User-Token
      trusted_issuers:
        - issuer: "https://idp.example.com/realms/agents"
          audiences: ["ppe-gateway"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/realms/agents/protocol/openid-connect/certs"
```

The token is verified against the issuer's JWKS. Only after verification do its
claims become attributes. An unverified or expired token resolves to no subject,
and `require(authenticated)` denies.

`identity/api-key` looks up an opaque key in a file or HTTP directory and maps
its record into the same attributes. Policies such as `require(role.hr)` work
with either resolver. See [Recipe 7](../identity-delegation.md#recipe-7-an-opaque-api-key-resolved-against-a-directory)
for configuration and revocation timing.

## What lands in the bag

A resolved identity populates a flat attribute namespace that predicates read
directly:

| Source | Attributes |
|--------|-----------|
| Subject | `subject.id`, `authenticated`, `subject.roles`, `subject.permissions`, `subject.teams` |
| Roles | `role.<r>` for undotted names (for example `role.hr`, `role.security`) |
| Permissions | `perm.<p>` for undotted names (for example `perm.view_ssn`) |
| Claims | `claim.<k>` |
| OAuth client | `client.client_id`, `client.authorized_scopes`, `client.roles`, `client.permissions`, and aliases for undotted members under `client.role.<r>` / `client.perm.<p>` |
| Workload (SPIFFE / mTLS) | `caller_workload.spiffe_id`, `caller_workload.trust_domain` |
| Delegation chain (`role: user` with an `act` claim) | `delegation.depth`, `delegated`, `delegation.origin_subject_id`, `delegation.actor_subject_id`, `delegation.age_seconds` |

`require(role.hr)` is true when the verified token carried the `hr` role, and
`redact(!perm.view_ssn)` redacts unless it carried the `view_ssn` permission.
Membership names containing `.` do not receive aliases because policy engines
can interpret dotted keys as nested namespaces. Names containing `:` cannot be
written as attribute paths. Use the canonical sets for either case:
`subject.roles contains "admin.readonly"` or
`subject.roles contains "system:authenticated"`.

## Delegation chain from the `act` claim

A token minted by RFC 8693 token exchange names the party acting for the
subject in an `act` claim, and an actor that was itself acting for someone nests
the earlier `act` inside its own:

```json
{ "sub": "alice", "act": { "sub": "agent-b", "act": { "sub": "agent-a" } } }
```

A `role: user` `identity/jwt` resolver reads that nesting into the delegation
chain, so `delegation.*` predicates see the chain the token carries. Alice
delegated to `agent-a`, which delegated to `agent-b`, so `require(delegation.depth <= 1)`
refuses the token above (depth 2) and `require(!delegated)` refuses any token
that carries `act`.

| Attribute | Value for the token above |
|-----------|---------------------------|
| `delegation.depth` | `2`, one per `act` object |
| `delegated` | `true`; `false` when the token has no `act` |
| `delegation.origin_subject_id` | the resolved subject id (`alice`) |
| `delegation.actor_subject_id` | the outermost `act.sub` (`agent-b`), the current actor |
| `delegation.age_seconds` | seconds since the token's `iat`, `0` without one |

The chain is trusted as presented: it is as trustworthy as the issuer, because
the resolver reads it only from a token whose signature, issuer and audience
verified. Depth is never capped, since a clipped chain would read shallower than
it is. A malformed `act` (not an object, or an object without a non-empty string
`sub`) denies the request with `auth.mapping_failed` instead of being ignored,
so a delegated call cannot pass as direct; a JSON `null` counts as absent.
Because the chain is whatever the issuer wrote, write depth limits against
issuers that record `act` honestly: an issuer that never writes it leaves
`delegation.depth` at `0`.

The `client` and `caller_workload` roles ignore `act`.

## Multiple sources

A request often carries more than one identity: the end user, the calling
application, and the calling workload. Register an identity plugin per source.
The bundled JWT plugin takes a `role` (`user`, `client`, or `caller_workload`)
and a `credential` location (header, cookie, or query parameter), so each
inbound credential resolves into its own namespace:

| `role` | Namespace | Typical credential |
|--------|-----------|--------------------|
| `user` | `subject.*` | End-user OIDC token on `X-User-Token` |
| `client` | `client.*` | OAuth client token on `Authorization` |
| `caller_workload` | `caller_workload.*` | SPIFFE JWT-SVID on `X-Workload-Token` |

Policy can then require several at once: `require(authenticated) &
client.authorized_scopes contains "tools:invoke"`.

### Workload identity

A `role: caller_workload` resolver is the ingress for the calling agent's
SPIFFE JWT-SVID:

```yaml
plugins:
  - name: jwt-workload
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      role: caller_workload
      credential:
        kind: header
        name: X-Workload-Token
      trusted_issuers:
        - issuer: "https://spire.example.com"
          audiences: ["ppe-gateway"]
          decoding_key:
            kind: jwks_url
            url: "https://spire.example.com/keys"
```

The SPIFFE ID is read from the SVID's `sub` claim, and the trust domain is
derived from it, populating `caller_workload.spiffe_id` and
`caller_workload.trust_domain`. A token whose `sub` is not SPIFFE-shaped is
rejected rather than filed into the workload slot, so anything policy finds
there really is an attested workload.

The bag distinguishes two machine identities:

- `caller_workload` — the attested workload on the inbound network peer. The
  agent calling *us*. Many different agents call through one gateway.
- `this_workload` — this PPE instance's *own* attested identity, used for
  outbound calls. A single principal.

They are not interchangeable, and confusing them is how a token minted for one
agent ends up presented by another. Delegation depends on the distinction — see
[Delegation](delegation.md).

### Credential location

Each resolver reads its token from one wire location, named by
`credential:` in the plugin config:

| Kind | Use | Example name |
|---|---|---|
| `header` (default) | Bearer token | `Authorization` |
| `cookie` | Browser session | `__Host-jwt` |
| `query_param` | WebSocket or SSE | `access_token` |

```yaml
# A browser app whose JWT arrives in a cookie
plugins:
  - name: jwt-browser
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      credential:
        kind: cookie
        name: __Host-jwt
      trusted_issuers:
        - issuer: "https://idp.example.com"
          audiences: ["my-app"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

Cookie and query-string values are parsed by PPE, not by the host's HTTP
framework, so the same request resolves identically regardless of which
proxy sits in front of it. See
[Configuration — Credential location](../configuration.md#credential-location)
for the full reference and security notes.

## Pipeline integration

Identity resolution is a hook (`identity.resolve`) that runs ahead of the
route's policy phase. The resolved subject is filtered by each downstream
plugin's declared capabilities (see [Extensions &
Capability-Gating](../extensions.md)): a plugin only sees the identity fields it
is entitled to. APL predicates read the same bag, gated the same way.

Once identity is resolved, policy can authorize ([APL](index.md)), delegate
downstream ([Delegation](delegation.md)), or hand a relationship decision to a
PDP ([PDP Integration](pdp.md)).

## Next

- [Identity Claim Mapping](../identity-claim-mapping.md): add and test a
  provider-specific JWT claim mapper preset.
- [Static Attributes](attributes.md): combine verified identity with
  operator-maintained facts.
- [Delegation](delegation.md): exchange verified credentials for scoped
  downstream tokens.
