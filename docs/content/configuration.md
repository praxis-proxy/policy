# Configuration

A PPE configuration is one YAML document. It declares the plugins the
process can reach, the cross-cutting wiring, and the policy that decides
which of them run for a given operation.

Every key is known. A key the document model does not name fails the
load, and where a key was renamed the error names its replacement. If
your configuration loads, every key in it does something. That is a
deliberate reversal: keys used to be dropped silently, so a stale
`plugin_settings:` block could take every engine setting down with it
and leave the process running in a mode nobody chose.

## The six top-level keys

```yaml
engine_settings:  # dispatch mode and runtime limits
global:           # cross-cutting wiring, defaults, and policy
plugins:          # the plugins available, by kind
groups:           # reusable policy bundles routes opt into
routes:           # policy, one entry per operation
secrets:          # secret material: providers, and the values bound to them
```

Anything else is a load error. All six are optional.

## Dispatch modes

`engine_settings.dispatch` picks between two mutually exclusive models,
and a document is legal in one of them only.

| Mode | What selects a plugin | Rejects |
|---|---|---|
| `policy` (default) | a `run(name)` step, or a policy block that reaches one | a per-plugin `conditions:` and `priority:`, and a list-form `plugins:` |
| `hooks` | each plugin's own `hooks:` and `conditions:` | `routes:`, `groups:`, `global:`, `global.defaults:` |

Under `dispatch: policy` a plugin runs only where a step names it, so
the load reports a declared plugin no policy reaches, by name, and
warns when a plugin is reached on fewer hooks than it declares.

| Setting | Default | Meaning |
|---|---|---|
| `dispatch` | `policy` | which model above |
| `plugin_timeout` | `30` | per-plugin timeout, in seconds |
| `short_circuit_on_deny` | `true` | stop a hook's remaining plugins once one denies |
| `route_cache_max_entries` | `10000` | dispatch-plan cache size |

## What each scope accepts

The accept sets below are the config model's own tables. A key outside
its scope's set is a load error naming the scope and the set.

| Scope | Keys |
|---|---|
| the document | `global`, `plugins`, `groups`, `routes`, `secrets`, `engine_settings` |
| `global:` | `defaults`, `authentication`, `assertions`, `response`, `authorization`, `pdp`, `session_store`, `attribute_files` |
| `global.defaults.<entity>:` | `description`, `metadata`, `plugins`, `authentication`, `assertions`, `response`, `authorization`, `args`, `result` |
| `groups.<name>:` | the same set as `global.defaults.<entity>:` |
| `routes[]` | `tool`, `resource`, `prompt`, `llm`, `http`, `meta`, `groups`, `plugins`, `authentication`, `assertions`, `response`, `authorization`, `args`, `result` |
| `engine_settings:` | `dispatch`, `plugin_timeout`, `short_circuit_on_deny`, `route_cache_max_entries` |
| an `authentication:` block | `steps`, `replace_inherited` |
| an `authentication:` step | `name`, `config` |
| an `assertions:` block | `request`, `response` |
| an `assertions:` direction | `headers`, `strip`, `replace_inherited` |
| an `assertions:` header entry | `name`, `from`, `members`, `on_missing`, `encode` |

Three scopes require additional constraints.

`pdp:`, `session_store:` and `attribute_files:` are `global:` only.
They wire process-global machinery, so there is nowhere else for them
to mean anything.

`args:` and `result:` are not accepted under `global:`. A field
pipeline names one field of a payload, and `global:` covers every entity
route at once rather than carrying a payload of its own. Write the
pipeline on each `global.defaults.<entity>:` block that has a payload,
or on the routes themselves. This is a removed capability rather than a
tightening: there is no longer any spelling for one field pipeline
covering every entity route.

`plugins:` changes shape by mode. Under `dispatch: policy` it is a map
of per-plugin overrides. The list form, which activated a chain, is a
load error; invoke a plugin with `run(name)` instead.

## Plugins

Each entry declares how a plugin is identified, where it runs, and what
it may see.

| Field | Meaning |
|---|---|
| `name` | instance name, referenced from policy as `run(name)` or `delegate(name, ...)` |
| `kind` | which implementation, for example `identity/jwt` |
| `hooks` | the hook points it registers on |
| `mode` | `sequential` (default), `transform`, `audit`, `concurrent`, `fire_and_forget`, or `disabled`; see [Execution modes](pipeline.md#execution-modes) |
| `on_error` | `fail` (default), `ignore`, or `disable` |
| `capabilities` | declared context access, see [Extensions](extensions.md) |
| `config` | plugin-specific settings |

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      header: X-User-Token
      trusted_issuers:
        - issuer: "https://idp.example.com/realms/agents"
          audiences: ["ppe-gateway"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/realms/agents/protocol/openid-connect/certs"
```

A plugin that reaches outside the process must declare `perform_http`.
Withholding it stops the call rather than degrading it, because a
plugin that quietly skipped its IdP call would fail open.

## Global

```yaml
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
        permit(principal, action == Action::"read", resource is Repo)
        when { principal.roles.contains("security") };
  session_store:
    kind: valkey
    endpoint: localhost:6379
  attribute_files:
    - attributes/tenants.yaml
```

`pdp:` is a sequence, one block per decision point. `session_store:`
selects where Session Taint labels live; without it, labels stay in an
in-process memory store and do not survive a reload or reach a second
replica. `attribute_files:` loads the operator-maintained tree policy
reads under `data.*`, covered in
[Static Attributes](apl/attributes.md).

## Routes

Routes carry the policy, one entry per operation, selected by `tool:`,
`resource:`, `prompt:`, `llm:`, or `http:`.

```yaml
plugins:
  - name: workday-oauth
    kind: delegator/oauth
    hooks: [token.delegate]
  - name: audit-log
    kind: audit/logger
    hooks: [cmf.tool_pre_invoke]

routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api)"
        - "taint(secret, session)"
        - "run(audit-log)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

Both phase lists nest under `authorization:`. Writing `pre_invocation:`
or `post_invocation:` directly on a route is a load error, and an empty
`authorization:` block is rejected. `args:` and `result:` stay directly
on the route.

## Groups

A group is a named, reusable bundle a route opts into: `authentication:`
steps, `authorization:` steps, field pipelines, or assertions. It is the
middle layer between global defaults and per-route policy, and
`groups:` is the only place a bundle is declared.

```yaml
plugins:
  - name: jwt-manager
    kind: identity/jwt
    hooks: [identity.resolve]

groups:
  hr-tools:
    authentication: [jwt-manager]
    authorization:
      pre_invocation:
        - "require(role.hr)"

routes:
  - tool: get_compensation
    groups: hr-tools
```

`groups:` on a route takes a bare string or a list. It is sugar over
tags: `meta: { tags: [hr-tools] }` is exactly equivalent, and a
host-injected runtime tag joins a group the same way when its name
matches one.

## Requests with no entity

A request carrying no entity metadata resolves no route. It is denied
with the violation code `unidentified_request` and a 400-class status,
kept distinct from a policy's own deny because no rule was reached.

For authorizing plain HTTP requests rather than named entities, see
[HTTP Routing](http-routing.md).

## Secrets and key material

There is no `${ENV}` substitution in configuration fields. A secret has
exactly one shape and the config names where it comes from rather than
carrying it.

### The `secrets:` block

A **provider** reads one backend. A **value** binds a name to one
provider and one reference. Everything downstream names the value, never
the provider and never a raw reference, so the set of secrets the process
can reach is the `values:` map and nothing else.

```yaml
secrets:
  providers:
    local: { kind: file, base_dir: /etc/ppe }
    shell: { kind: env }
  values:
    upstream_api_key: { provider: local, ref: upstream.key }
    session_password: { provider: shell, ref: VALKEY_PASSWORD }
```

Two provider kinds need no dependencies and ship in the engine:

| kind | `ref` is | notes |
|---|---|---|
| `file` | a path | With `base_dir`, a reference must be relative and may not contain `..`. One trailing newline is stripped. An empty file is an error, not an empty value. |
| `env` | a variable name | A process's environment is fixed at exec, so these never rotate without a restart. |

`file` covers Kubernetes Secret volumes, CSI-projected secrets, container
secret mounts, and a Vault Agent sidecar templating to disk, so a
deployment using any of those needs no network backend.

### Vault KV v2

The `vault` kind is the `secrets-vault` feature, absent from the default
build. Compiling the feature does not register the factory:
`install_builtins` does not wire it. The host calls
`register_vault_secret_provider` (or `registry_with_vault`) with the same
`HttpTransport` it installed on the engine.

Every call goes through that transport. Auth is Kubernetes or AppRole,
with no default. The address must be `https://` unless
`insecure_http: true`. The `ref` is `<mount>/<path>#<field>`, which is
`GET /v1/<mount>/data/<path>` and then that field of `data.data`.

In-cluster Vault (Kubernetes service DNS, RFC 1918) is refused by the
bundled `HyperTransport` unless the host builds it with
`with_allow_private_destinations`. A proxy injecting its own transport
already chose an egress policy.

<!-- validate: fragment -->
```yaml
secrets:
  providers:
    vault-prod:
      kind: vault
      address: https://vault.example.com:8200
      auth:
        method: kubernetes
        role: ppe
  values:
    session_password: { provider: vault-prod, ref: secret/ppe#password }
```

AppRole `secret_id` comes from an environment variable or a file. A
development-only `literal` is refused unless the document also sets
`allow_insecure_literal: true`. Kubernetes login rereads the projected
service-account token on every login.

Token renewal is lazy on the next `get_secret` (startup or
`refresh_secrets()`). Nothing spawns a ticker: a host that initializes
on a short-lived runtime would lose it. A renewable token is renewed
after two thirds of `lease_duration`, minus jitter; a non-renewable one
is obtained again. A `403` on a read triggers one reauthentication and
one retry, which is not a missing secret.

A name may contain letters, digits, `_`, `-`, and `/`. A `/` groups
names on a large document but a name is a key rather than a path, so a
leading, trailing, or repeated separator is refused: every name has one
spelling. A repeated key in `providers:` or `values:` is a load error
rather than a last-one-wins.

### Resolution and refresh

Shape is checked at load: a value naming an undeclared provider fails
against the document, without contacting a backend.

Every declared value is read during `PolicyEngine::initialize()`, before
any plugin initializes. A value that cannot be read stops startup. A
credential that has never resolved once has no last-good to serve, so
there is no degraded state to start in.

After startup the host decides when to re-read, by calling
`refresh_secrets()`. Nothing in the engine spawns a ticker: a task binds
to whichever runtime started it, and a host that initializes on a
short-lived runtime would lose it before it ticked once, leaving a
process that never rotates a credential and never says so.

A value that fails to re-read keeps its last-good bytes, so a backend
outage after startup degrades to a possibly-stale credential rather than
to none. The returned report names every failure, and
`provider_last_success()` is the staleness signal to alarm on. The
interval a host picks is therefore the upper bound on how long a revoked
credential stays in use.

### Per-plugin secret sources

Plugins that predate the `secrets:` block carry their own typed source
enums. OAuth and CIBA client secrets use `client_secret_source`:

<!-- validate: fragment -->
```yaml
client_secret_source:
  kind: env_var
  name: IDP_CLIENT_SECRET
```

## Next

- [HTTP Routing](http-routing.md): select policy by request path and method.
- [Identity and Delegation](identity-delegation.md): configure inbound identity
  and outbound credentials.
- [Header Assertions](assertions.md): project derived identity onto upstream
  requests.
- [Upgrading APL](../upgrade-apl.md): migrate an older configuration.
