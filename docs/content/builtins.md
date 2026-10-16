# Builtins

PPE ships a set of plugins, decision points, and a session store, each
behind a Cargo feature. With a feature enabled,
`praxis_policy::install_builtins` registers its factory and a policy can
name it by `kind`.

## Catalog

| Kind | Type | Feature | Purpose |
|---|---|---|---|
| `identity/jwt` | identity | `jwt` | Resolve a subject from a verified JWT, with configurable claim mapping. See [Identity](apl/identity.md). |
| `identity/api-key` | identity | `api-key` | Resolve an API key against a file or HTTP directory. See [Recipe 7](identity-delegation.md#recipe-7-an-opaque-api-key-resolved-against-a-directory). |
| `delegator/oauth` | delegator | `oauth` | RFC 8693 token exchange, with optional caching. See [Delegation](apl/delegation.md). |
| `delegator/vault` | delegator | `delegator-vault` | Resolve caller-scoped or workload-owned downstream credentials from Vault KV v2. See [Vault delegation recipes](identity-delegation.md#recipe-8-a-users-vault-stored-credential). |
| `elicitation/ciba` | elicitation | `elicitation-ciba` | OIDC CIBA human approval. See [Elicitation](apl/elicitation.md). |
| `cedar-direct` | decision point | `cedar` | Evaluate Cedar policy (dialect `cedar`). |
| `cel` | decision point | `cel` | Evaluate CEL expressions (dialect `cel`). |
| `opa` | decision point | `opa` | Evaluate Rego, embedded (dialect `opa`). |
| `valkey` | session store | `valkey` | Persist Session Taint labels across processes. See [Session Taint](apl/tainting.md). |
| `vault` | secret provider | `secrets-vault` | Resolve `secret:` references from Vault KV v2. Not auto-registered: it needs an `HttpTransport` the host supplies. |
| `quota` | policy plugin | `experimental-quota` | Enforce a per-principal token budget through Limitador. Experimental and excluded from `builtins`. |

The default session store is in-process memory. It needs no feature and
no `kind`, but labels in it do not survive a reload or reach a second
replica.

The CIBA approval correlation store is also in-process memory, independent of
the session store. Its approvals bind to the tool and requester, expire, and
can be applied once. Pending approvals do not survive a restart or move to a
second replica; see [Elicitation](apl/elicitation.md).

The three decision points are held to each other by a differential test
suite. Given the same attributes and equivalent policy intent, they must
agree across their shared boolean, integer, string, and string-set
subset. Documented semantic differences are allowlisted; a new
disagreement fails the build.

## Not builtins

Two worked examples live in `reference/plugins/` and are not bundled: a PII
scanner (`validator/pii-scan`) and an audit
logger (`audit/logger`). They are linted and tested here, and each
manifest says why it is an example rather than a builtin: the scanner is
plain regexes with no checksum validation, and the logger's sink is
stderr. Register them the way you would any host plugin.

## Cargo features

```toml
# engine only, the default
praxis-policy = "0.4"

# every bundled extension
praxis-policy = { version = "0.4", features = ["builtins"] }

# a granular subset
praxis-policy = { version = "0.4", features = ["jwt", "cedar"] }
```

| Feature | Pulls in |
|---|---|
| `builtins` | all ten below: `jwt`, `api-key`, `oauth`, `delegator-vault`, `elicitation-ciba`, `cedar`, `cel`, `opa`, `valkey`, `secrets-vault` |
| `jwt` | `identity/jwt` |
| `api-key` | `identity/api-key` |
| `oauth` | `delegator/oauth` |
| `delegator-vault` | `delegator/vault` |
| `elicitation-ciba` | `elicitation/ciba` |
| `cedar` | the `cedar-direct` decision point |
| `cel` | the `cel` decision point |
| `opa` | the `opa` decision point |
| `valkey` | the Valkey session store, and the redis and TLS stack it carries |
| `secrets-vault` | the Vault KV v2 secret provider. Not auto-registered: it needs an `HttpTransport` the host supplies |
| `experimental-quota` | the opt-in Limitador-backed token quota plugin; excluded from `builtins` |
| `http-hyper` | a default outbound HTTP transport, off by default |

The default build is the engine alone, so a host that needs only the
runtime and its own plugins compiles nothing extra.

### The HTTP transport

`http-hyper` is the odd one. PPE performs no outbound HTTP of its own: a
host installs an `HttpTransport` and the plugins borrow it, so a process
embedding PPE keeps one connection pool, one TLS trust store, and one
egress path instead of two. A host with its own client injects it with
`PolicyEngine::set_http_transport`. A host with none calls
`install_default_http_transport`, which is what this feature provides.
It is never wired automatically.

Install it before `initialize()`, since that is when a plugin first asks
for it. The install is set-once: a second call is ignored and returns
`false`, so a host that wires twice cannot swap the transport out from
under plugins already holding it.

Two distinct mistakes fail that same `initialize()`, and the message
names which one you made:

- No transport installed. The plugin needs the `http` host service
  "but none is installed; the embedding host must install one before
  initializing the engine". That is a wiring problem in the embedding
  program, not something the policy YAML can fix.
- Transport installed, capability withheld. The plugin does not
  declare `perform_http`, and the error names the capability to add to
  its `capabilities:` list.

The engine keeps the two apart on purpose, so the message points at the
file that needs the edit.

## Referencing a builtin

A registered builtin is named by `kind`. Plugins are declared under
`plugins:` with their hooks and capabilities, decision points under
`global.pdp:`, and the session store under `global.session_store:`.

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      credential:
        kind: header
        name: X-User-Token

global:
  pdp:
    - kind: opa
      policy_text: |
        package ppe
        default allow := false
  session_store:
    kind: valkey
    endpoint: localhost:6379
```

A plugin that fetches JWKS, exchanges a token, or dispatches a CIBA
prompt must declare `perform_http`, or the engine refuses to start and
names the plugin and the missing capability.

### Credential location (`identity/jwt`)

Each `identity/jwt` instance reads its token from one wire location,
named by the `credential:` block in the plugin's `config:`. Three
kinds are supported:

| Kind | Use case | Example |
|---|---|---|
| `header` | The common case — a Bearer token on an HTTP header | `Authorization`, `X-User-Token` |
| `cookie` | Browser apps that deliver the JWT in an HttpOnly cookie | `__Host-jwt`, `session` |
| `query_param` | Endpoints where the client cannot set headers (WebSocket, SSE) | `access_token` |

```yaml
# Cookie-based JWT
plugins:
  - name: jwt-user
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
          audiences: ["my-api"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

```yaml
# Query-parameter JWT (WebSocket handshake)
plugins:
  - name: jwt-ws
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      credential:
        kind: query_param
        name: access_token
      trusted_issuers:
        - issuer: "https://idp.example.com"
          audiences: ["my-api"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

Omitting `credential:` defaults to
`{ kind: header, name: Authorization }`.

Cookie and query-string values are parsed by PPE itself, not by the
host's HTTP framework, so the same request resolves the same credential
regardless of which proxy sits in front of it. Duplicate cookie names or
query-parameter names for the configured credential are rejected as
ambiguous (`auth.ambiguous_credential`) rather than resolved by
first-wins or last-wins.

> **Security note.** A query-parameter token routinely appears in
> access logs, CDN logs, and browser history. PPE logs a one-time
> notice at startup when a resolver uses `query_param` so the operator
> can scrub raw query strings from infrastructure logging.

## Next

- [Testing](testing.md): test policy and plugin behavior through the runtime.
- [Configuration](configuration.md): declare builtins in a policy document.
