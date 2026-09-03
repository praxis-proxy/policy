# Upgrading an APL configuration

Every key and form an existing configuration must rewrite, with a before and an
after. Each entry says what the old form did, what to write instead, and how the
engine reports the old form if you miss one.

The short version: nothing is silently dropped any more. A key that is not part
of the language fails the load and names its replacement, and a key the runtime
never honored is gone rather than warned about. If your configuration loads, it
means every key in it does something.

Work through the sections in order. The first two change the shape of the
document, and the rest are local rewrites.

Section 10 also covers the `perform_http` capability required by plugins that
fetch JWKS, exchange tokens, or dispatch CIBA prompts.

---

## 1. `engine_settings:`, and the dispatch mode

`plugin_settings:` is `engine_settings:`, and the boolean `routing_enabled` is a
named mode.

```yaml
# before
plugin_settings:
  routing_enabled: true
  plugin_timeout: 30
```

```yaml
# after
engine_settings:
  dispatch: policy
  plugin_timeout: 30
```

**The default changed, and this is the widest break in the release.** `dispatch:`
defaults to `policy`. It used to default to `hooks`, where every declared plugin
fires at every hook its own `hooks:` list names.

- A configuration that declares `routes:`, `groups:`, or `global:` was already
  relying on policy dispatch. Write nothing; the default is now what you wanted.
- A configuration that declares only `plugins:`, and relied on all of them
  firing, must write `dispatch: hooks`. That restores the old behavior exactly
  and is the whole of the change for such a document.

The two modes now reject each other's keys by name, so a document is legal in one
mode only. Under `dispatch: hooks`, `routes:`, `groups:`, `global:`, and
`global.defaults:` are load errors. Under `dispatch: policy`, a per-plugin
`conditions:` and a per-plugin `priority:` are both load errors: a policy decides
which plugin runs, and it never runs more than one at a time, so neither key is
consulted. `priority:` stays legal under `dispatch: hooks`, which is where it
orders a hook's entries. In policy mode, order the steps under `authorization:`.

A stale top-level `plugin_settings:` fails the load naming `engine_settings`,
rather than loading with its contents dropped.

### Two new load-time reports

Under `dispatch: policy` a plugin runs only where a step names it, so the load
now tells you when nothing does.

- **A declared plugin no policy reaches fails the load, by name.** The reference
  set is wider than a `run(name)` step: an `authentication:` list at any scope, a
  `delegate` call, and an elicitation verb's handler all reach a plugin, and a
  step under `global.authorization:` reaches one for every route it stacks onto.
  If a plugin is genuinely meant to be inert, drop the declaration.
- **A plugin reached on fewer hooks than it declares is warned about**, under
  `alarm = "plugin_narrowed_by_policy"`, naming every uncovered hook. Narrowing
  is often intended, so it does not fail the load. Add a step on the uncovered
  hooks, or narrow the plugin's own `hooks:` to match what the policy asks for.

### Requests with no entity metadata are denied

A request carrying no `meta.entity_type` / `meta.entity_name` resolves no route.
It used to fall through to every plugin registered on the hook; it is now denied
with the violation code `unidentified_request` and a 400-class code, distinct
from a policy's own deny because no rule was reached.

The guard is the configuration, not the mode: a configuration that declares no
policy at all passes such a request exactly as before. An HTTP request is
unaffected either way, since it names its entity type.

---

## 2. The `apl:` wrapper is gone

APL terms sit on the section that carries them.

```yaml
# before
routes:
  - tool: get_compensation
    apl:
      authorization:
        pre_invocation:
          - "require(authenticated)"
      result:
        ssn: "redact(!perm.view_ssn)"
```

```yaml
# after
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(authenticated)"
    result:
      ssn: "redact(!perm.view_ssn)"
```

`apl:` is now an unknown key at every scope: on a route, at `global:`, under
`global.defaults.<entity>:`, and on a `groups.<name>:` bundle.

The wrapper had created two opposed precedence rules for `response:`, which read
from the section and then from inside `apl:`, with the section winning. There is
one source now: the section. A `response:` nested inside anything is an unknown
key.

### `attribute_files:` moves with it

It was read only as `global.apl.attribute_files`, so it does not simply lose a
wrapper, it relocates:

```yaml
# before
global:
  apl:
    attribute_files:
      - ./data/tenants.yaml
```

```yaml
# after
global:
  attribute_files:
    - ./data/tenants.yaml
```

Diagnostics follow: an error that named `global.apl.attribute_files` now names
`global.attribute_files`.

### `pdp:` and `session_store:` are `global:` keys and nowhere else

They were accepted on a route, under `global.defaults.<entity>:`, and on a
bundle, where the compiler dropped them and the load warned. They now fail the
load naming the key. A PDP, the session store, and the static attribute tree are
process-global, so all three engine blocks agree on their own scope.

---

## 3. `authorization:` is the only place a phase list appears

The flat spellings are gone.

```yaml
# before
routes:
  - tool: get_compensation
    pre_invocation:
      - "require(authenticated)"
    post_invocation:
      - "taint(audit, session)"
```

```yaml
# after
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(authenticated)"
      post_invocation:
        - "taint(audit, session)"
```

One phase is enough: a block naming only `post_invocation:` is complete. A block
that contributes no step fails the load, which covers `authorization:` written
with nothing under it, `authorization: {}`, and every phase it names written as
an empty list. All three used to load clean and enforce nothing. A phase written
empty *beside* one that carries steps still loads: only a block with nothing in
it at all is refused.

**A published compatibility guarantee lapses here.** The 0.1.0 note that the
policy document format was unchanged no longer holds for phase spellings. Plugin
`kind:` strings, hook names, and violation codes are all still guaranteed.

**A capability is removed, not tightened:** `args:` and `result:` under `global:`
are load errors. A global field pipeline had no field set to apply to, so write
field stages on the route, or on `global.defaults.<entity>:` where the entity
fixes the fields.

---

## 4. The five legacy keys

Each fails the load naming its replacement, at every scope.

| Before | After |
|---|---|
| `policy:` | `authorization.pre_invocation:` |
| `post_policy:` | `authorization.post_invocation:` |
| `identity:` | `authentication:` |
| `global.policies:` | top-level `groups:` |
| `apl:` | nothing; see section 2 |

A bundle written under top-level `groups:` resolves exactly as one written under
`global.policies:` did.

`authentication:` now stacks **global to entity default to tag bundles to
route**, the order the policy layers already stacked in. The
`global.defaults.<entity>.authentication:` layer is the new one: the key was
accepted before and read by nothing, so an entity type's default identity steps
were parsed and dropped. A document already carrying that block gains the
identity steps it was silently going without. Its `replace_inherited: true`
drops what stacked before it, and the load names every route that loses steps
that way.

A misspelled key now fails the load at every scope rather than only on a route.
`GlobalConfig` and `PolicyGroup` used to drop an unknown field, so a typo under
`global:`, `global.defaults.<entity>:`, or a bundle loaded clean and enforced
nothing. An out-of-tree orchestrator's own block stays loadable wherever it is
written, through its visitor's declared keys.

---

## 5. The five keys nothing honored

These parsed and did nothing. They are gone rather than warned about.

| Key | Scope | What to write instead |
|---|---|---|
| `when:` | a route | a `when:` / `do:` step inside `authorization:` |
| `plugin_dirs` | top level | nothing; it was never read |
| `parallel_execution_within_band` | `engine_settings:` | nothing; a plugin's `mode:` decides |
| `fail_on_plugin_error` | `engine_settings:` | a plugin's own `on_error:` |
| `on_error:` | an `authentication:` step | the `on_error:` of the plugin's own `plugins:` declaration |

`when:` is the only one that takes a capability rather than a no-op. It also
carried a route-specificity bonus, so a configuration that declared `when:` on
one of two otherwise equally specific routes may find the other route winning
now. Since `when:` is an unknown route key in the same release, no configuration
can reach that state after upgrading; check it while rewriting.

An `authentication:` step's key set is closed too, so a misspelling inside one
fails the load rather than being swallowed.

---

## 6. `plugins:` as an activation list

Under `dispatch: policy`, a `plugins:` **list** is a load error at every scope
that could write one: a route, a bundle under `groups:`, a
`global.defaults.<entity>:` entry, and the reserved `all` bundle. A policy names
the plugin it runs.

```yaml
# before
routes:
  - tool: get_compensation
    plugins: [audit-log]
```

```yaml
# after
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "run(audit-log)"
```

For a plugin that used to run on every request, write one step under
`global.authorization:`; it stacks onto every entity route.

```yaml
global:
  authorization:
    pre_invocation:
      - "run(audit-log)"
```

A `plugins:` **map** is unaffected: that is the per-plugin override block, and it
is still how a route narrows a plugin's `config`, `capabilities`, or `on_error`.

Per-plugin `conditions:` and tag-based group activation are hook-mode features.
If you need them, `dispatch: hooks` is the mode that has them; policy mode
expresses the same intent as a predicate on a step.

---

## 7. `run(name)` is the only invoke form

`plugin(name)` is gone from both step and stage position.

```yaml
# before
authorization:
  pre_invocation:
    - "plugin(audit-log)"
```

```yaml
# after
authorization:
  pre_invocation:
    - "run(audit-log)"
```

The word survives as a noun: `plugin:` as a keyword argument inside
`delegate(...)`, and the `delegate:` map form, both still parse.

---

## 8. Quoting and escapes inside policy text

A quoted literal now has one rule wherever it appears, and it processes exactly
three escapes: `\\`, `\'`, and `\"`. Anything else after a backslash is an error
naming the escape.

**This is the one change that can break policy text which looks fine.** A
backslash used to pass through a literal untouched, so a regex character class
worked by accident. It must be doubled now:

```yaml
# before
result:
  employee_id: 'regex("\d+")'
```

```yaml
# after
result:
  employee_id: 'regex("\\d+")'
```

The single-backslash form fails the load naming the unrecognized escape, so this
is reported rather than silently reinterpreted.

Two related tightenings, both of which used to be quiet:

- A lone quote in a stage argument is an unterminated literal. `regex(")` used to
  compile to a pattern matching one quote character.
- A closing paren inside a literal is content. `deny("blocked (see policy)")` used
  to be rejected as a malformed call, because paren matching ignored quotes.

An empty stage in a pipe chain is a load error. A leading, trailing or doubled
`|` left a position with no stage in it, and those were skipped, so a chain
compiled shorter than it was written:

```yaml
# before: compiled to one stage, silently
result:
  ssn: "redact(!perm.view_ssn) |"
```

```yaml
# after
result:
  ssn: "redact(!perm.view_ssn)"
```

A field value that is entirely empty is still accepted as "no stages", since an
absent value is not a malformed one.

An attribute path is a production now, so these fail the load rather than
resolving to an absent attribute and making a predicate silently false:
`a..b`, `a.`, `.a`, `data.t[]`, `data.t[a:b]`, and `data.t["a]"]`. A quoted map key
inside a subscript was never matching anything; write `data.t[subject.tenant]`,
with the inner path unquoted.

`not` is a reserved word. `not authenticated` fails naming `!`; the `not in`
phrase still parses.

`&&` and `||` fail naming `&` and `|`. Spacing around an operator is not
significant and never was.

`1.`, `.5`, `-.5`, and `1e5` are rejected naming the number. `007` is still the
integer 7, deliberately: changing it would alter a value silently.

---

## 9. `require(P)` is a predicate

`require(...)` means `!P` and composes like any other predicate, so forms that
used to be rejected now parse:

```yaml
authorization:
  pre_invocation:
    - "require(a) & b"          # the same as "!a & b"
    - "require(!delegated)"     # could not be written before
    - "require(delegation.depth < 3)"
```

Every form already in use compiles to what it compiled to before, and that is
structural rather than a promise: negation is normalized to the leaves, so
`require(a)`, `require(a, b)` and `require(a | b)` each produce exactly the tree
they produced previously. Nothing a deployed policy contains changes what it
decides.

A top-level `require(...)` rule accepts only `deny` as its action;
`require(a): allow` fails the load naming the inversion, since the construct is a
refusal.

**One thing to read before upgrading, because it goes the other way.** Mixing `,`
and `|` inside the parens used to be refused outright, since the old parser tracked
one separator and had no precedence to appeal to. It means something now: the comma
binds loosest, so `require(a, b | c)` is `!(a & (b | c))`. A configuration that was
*rejected* for mixing them will now load and decide something. If you have one,
check that what it decides is what you meant.

---

## 10. Rust API changes

For a host embedding the engine rather than only writing configuration.

| Before | After |
|---|---|
| `PluginSettings` | `EngineSettings` |
| `PolicyConfig::plugin_settings` | `::engine_settings` |
| `routing_enabled()` | `dispatch_mode()` |
| `Phase::Policy` | `Phase::PreInvocation` |
| `Phase::PostPolicy` | `Phase::PostInvocation` |
| `CompiledRoute.policy` | `.pre_invocation` |
| `CompiledRoute.post_policy` | `.post_invocation` |
| `GlobalConfig.identity`, `PolicyGroup.identity`, `RouteEntry.identity` | `.authentication` |
| `compile_config`, `ConfigYaml`, `CompiledConfig` | deleted; see below |
| `ParseError::RenamedField`, `::ConflictingAuthorizationForms` | deleted |
| `cmf::constants::HOOK_CMF_HTTP_REQUEST` | `http_hook::HOOK_HTTP_REQUEST` |
| `cmf::constants::HOOK_CMF_HTTP_RESPONSE` | `http_hook::HOOK_HTTP_RESPONSE` |
| `invoke_named::<CmfHook>` on either HTTP hook | `invoke_named::<HttpHook>`, with `HttpPayload` |
| `HookHandler<CmfHook>` for an HTTP hook | `HookHandler<HttpHook>` |
| `HookFamily::for_entity -> HookFamily` | `-> Option<HookFamily>` |
| `Subject::claims: HashMap<String, String>` | `HashMap<String, Value>` |

### The generic-HTTP hooks moved families

The hook names are now `http.request` and `http.response`; their constants,
handler type, and empty payload live in `praxis_policy_core::http_hook`:

```rust
// before
use praxis_policy_core::cmf::constants::HOOK_CMF_HTTP_REQUEST;
let payload = MessagePayload { message: Message::text(Role::User, "") };
mgr.invoke_named::<CmfHook>(HOOK_CMF_HTTP_REQUEST, payload, ext, None).await;
```

```rust
// after
use praxis_policy_core::http_hook::{HOOK_HTTP_REQUEST, HttpHook, HttpPayload};
mgr.invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, ext, None).await;
```

HTTP handlers no longer receive a fabricated placeholder message. YAML using
`cmf.http_request` or `cmf.http_response` now fails with the replacement name.

### Subject claims keep their JSON shape

`Subject::claims` changed from `HashMap<String, String>` to
`HashMap<String, Value>`. To retain flat strings without quoting string values:

```rust
let flat = value.as_str().map_or_else(|| value.to_string(), str::to_owned);
```

### A host must install an HTTP transport

This requirement is checked at initialization, not compile time.

`identity-jwt`, `delegator-oauth`, and `elicitation-ciba` use a transport supplied
by the host. Without one, HTTP-dependent plugins fail at
`PolicyEngine::initialize()`.

To reuse the host's connection pool, trust store, and egress path:

```rust
mgr.set_http_transport(Arc::new(MyTransport::new()));
```

Otherwise, enable `praxis-policy`'s non-default `http-hyper` feature and install
the bundled transport explicitly:

```rust
praxis_policy::install_builtins(&mgr);
praxis_policy::install_default_http_transport(&mgr);
```

The bundled transport builds its pool on first use. Each plugin using `jwks_url`,
OAuth delegation, or CIBA must also declare `perform_http`:

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    capabilities:
      - perform_http
```

`ServiceError::NotInstalled` indicates a missing host transport;
`ServiceError::NotPermitted` indicates a missing capability.

`Phase` and `CompiledRoute` both derive `Serialize`, so **the serialized keys
change too**: a phase serializes as `pre_invocation` / `post_invocation`, and a
serialized `CompiledRoute` names its two step lists the same way. A consumer
reading either shape off the wire moves with it. The `authentication` rename is
Rust-only, since the serde key was already `authentication`.

`compile_config` read a document whose `routes:` was a map keyed by route name,
while a real configuration writes `routes:` as a list of selectors. Nothing in
production called it. A host compiling a policy block should use
`compile_policy_block_value`, which is unchanged. Tests wanting one compiled
route plus a plugin registry can enable the new `test-util` feature on
`praxis-policy-apl-core` and call `test_util::compile_test_policy`.

`ConfigVisitor` gains a defaulted `visit_complete` method, called once per
visitor after its own route walk. An existing implementor needs no change.
`PolicyEngine::dispatch_mode()` is new.

---

## Checking your work

Load the rewritten config through your own host binary, the one that registers
your plugin factories and the APL visitor. The load names every fault it can
find, so read all of it rather than fixing the first line and re-running.

`PolicyEngine::load_config_yaml` is the entry point that checks what this guide
changed. It is the only one that walks the registered visitors, and the visitor
walk is where APL bodies compile, where a policy key with no visitor to claim it
is rejected, and where the reachability report comes from. The typed
`parse_config` / `load_config` pair checks the document's shape but runs no
visitor, so it accepts a policy body this release does not.

No separate tool can stand in for your host: plugin kinds resolve against the
factories it registered, so only the process that has them can check a config
naming your plugins.

`cargo run --example plugin_demo` is not that check. It loads its own bundled
`plugin_demo.yaml`, takes no path argument, and registers only its four demo
factories. Read it as a shape reference, not a validator.

A configuration that loads clean under this release has no inert keys in it. If
the load warns rather than fails, the warning is about coverage you may have
narrowed on purpose, and `dispatch: hooks` is the escape for wanting the previous
behavior wholesale.

For what the language accepts after all of this, rather than what changed,
`docs/apl-grammar.md` is normative.

## A worked example: what the demo configs needed

The three policies in praxis-demos (`demos/policy-engine/policy.yaml`,
`policy-cel.yaml`, `policy-opa.yaml`) were read against the finished language. What
each needs, measured rather than estimated:

| Change | Count |
|---|---|
| `plugin_settings:` / `routing_enabled: true` to `engine_settings:` | 3, one per file |
| Flat `pre_invocation:` on a route, to nest under `authorization:` | 12, four per file |
| Stale comments claiming the engine accepts both a wrapped and a flat form | 2, in `policy-cel.yaml` and `policy-opa.yaml` |

Nothing else. None of the three uses `apl:`, a removed legacy key, a `plugins:`
activation list, `plugin(name)`, a `when:` route key, a backslash in policy text, or
a `regex(...)` / `enum(...)` stage, so the rest of this guide does not apply to
them.

`dispatch:` needs no value written. All three declare `routes:`, so the new default
is already the mode they were asking for; only the block's name changes.

The two stale comments are worth calling out because they are the failure mode this
release exists to remove, in prose rather than in code. They say APL terms may sit
either on the section or inside an `apl:` wrapper and point at `policy.yaml` for
"the wrapped style" — but `policy.yaml` does not use a wrapper either, and no
document can now, so the note describes a choice that no longer exists and points at
an example that never demonstrated it.
