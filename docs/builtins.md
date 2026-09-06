# Builtins

PPE ships a set of plugins, decision points, and a session store, each
behind a Cargo feature. With a feature enabled,
`praxis_policy::install_builtins` registers its factory and a policy can
name it by `kind`.

## The catalog

| Kind | Type | Feature | Purpose |
|---|---|---|---|
| `identity/jwt` | identity | `jwt` | Resolve a subject from a verified JWT, with configurable claim mapping. See [Identity](apl/identity.md). |
| `delegator/oauth` | delegator | `oauth` | RFC 8693 token exchange, with optional caching. See [Delegation](apl/delegation.md). |
| `elicitation/ciba` | elicitation | `elicitation-ciba` | OIDC CIBA human approval. See [Elicitation](apl/elicitation.md). |
| `cedar-direct` | decision point | `cedar` | Evaluate Cedar policy (dialect `cedar`). |
| `cel` | decision point | `cel` | Evaluate CEL expressions (dialect `cel`). |
| `opa` | decision point | `opa` | Evaluate Rego, embedded (dialect `opa`). |
| `valkey` | session store | `valkey` | Persist Session Taint labels across processes. See [Session Taint](apl/tainting.md). |

The default session store is in-process memory. It needs no feature and
no `kind`, but labels in it do not survive a reload or reach a second
replica.

The three decision points are held to each other by a differential test
suite: given the same attributes and equivalent policy intent, they must
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
praxis-policy = "0.2"

# every bundled extension
praxis-policy = { version = "0.2", features = ["builtins"] }

# a granular subset
praxis-policy = { version = "0.2", features = ["jwt", "cedar"] }
```

| Feature | Pulls in |
|---|---|
| `builtins` | all seven below: `jwt`, `oauth`, `elicitation-ciba`, `cedar`, `cel`, `opa`, `valkey` |
| `jwt` | `identity/jwt` |
| `oauth` | `delegator/oauth` |
| `elicitation-ciba` | `elicitation/ciba` |
| `cedar` | the `cedar-direct` decision point |
| `cel` | the `cel` decision point |
| `opa` | the `opa` decision point |
| `valkey` | the Valkey session store, and the redis and TLS stack it carries |
| `http-hyper` | a default outbound HTTP transport, off by default |

The default build is the engine alone, so a host that needs only the
runtime and its own plugins compiles nothing extra.

`http-hyper` is the odd one. PPE performs no outbound HTTP of its own: a
host installs an `HttpTransport` and the plugins borrow it, so a process
embedding PPE keeps one connection pool, one TLS trust store, and one
egress path instead of two. A host with its own client injects it with
`PolicyEngine::set_http_transport`. A host with none calls
`install_default_http_transport`, which is what this feature provides.
It is never wired automatically.

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
      header: X-User-Token

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

See [Configuration](configuration.md) for the surrounding document.
