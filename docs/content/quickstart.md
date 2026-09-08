# Quick Start

Stand up PPE and run the [scenario](overview.md): a `get_employee` route
that authorizes by role and redacts a field by permission.

You need Rust 1.96 or newer ([install with rustup](https://rustup.rs)).
The toolchain is pinned in the repository, so `cargo build` picks the
right one.

## 1. Add PPE

```toml
praxis-policy = { version = "0.2", features = ["builtins", "http-hyper"] }
```

`builtins` compiles in every bundled extension: JWT identity, OAuth
delegation, CIBA elicitation, the Cedar, CEL and OPA decision points,
and the Valkey session store. For a smaller build, name a subset
instead: `features = ["jwt", "cedar"]`. See [Builtins](builtins.md).

The default build is the engine alone. `http-hyper` is separate from
`builtins` because it is the one piece a host commonly already owns: it
supplies the bundled outbound HTTP transport, and a host with its own
HTTP client injects that instead (step 2).

## 2. Register the runtime

Create the engine, register the enabled builtin factories, and install
the APL config visitor:

```rust,ignore
use std::sync::Arc;
use praxis_policy::PolicyEngine;

let engine = Arc::new(PolicyEngine::default());

// Registers every enabled builtin factory and installs the APL visitor.
praxis_policy::install_builtins(&engine);
```

Without the `builtins` feature there is nothing to register, so install
the APL visitor yourself:

```rust,ignore
use std::sync::Arc;
use praxis_policy::{
    AplOptions, DispatchCache, MemorySessionStore, PolicyEngine, register_apl,
};

let engine = Arc::new(PolicyEngine::default());
register_apl(
    &engine,
    AplOptions {
        dispatch_cache: Arc::new(DispatchCache::new()),
        session_store: Arc::new(MemorySessionStore::new()),
        pdps: Vec::new(),
        pdp_factories: Vec::new(),
        session_store_factories: Vec::new(),
        base_capabilities: None,
    },
);
```

A host with plugins of its own registers each one alongside this. See
[Plugins and the Execution Pipeline](pipeline.md#when-to-write-a-plugin).

Then install the outbound HTTP transport. PPE performs no HTTP of its
own, so a plugin that fetches JWKS, exchanges a token, or dispatches a
CIBA prompt has nowhere to send its request until a host supplies one:

```rust,ignore
// The bundled transport, from the `http-hyper` feature.
praxis_policy::install_default_http_transport(&engine);
```

A host that already has an HTTP client calls
`engine.set_http_transport(my_transport)` instead, so the process keeps
one connection pool and one TLS trust store. Either call goes before
`initialize()`, and a plugin that reaches outward must also declare the
`perform_http` capability. [Builtins](builtins.md#the-http-transport)
covers both, and the error each mistake produces.

## 3. Write the policy

`routes:` is a list, one entry per operation. This route matches the
`get_employee` tool, authorizes by role, and redacts on the wire by
permission:

```yaml
routes:
  - tool: get_employee
    args:
      employee_id: "str"
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "require(role.hr)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
      salary: "int | redact(!role.hr)"
      employee_id: "str | mask(4)"
```

`require(authenticated)` and `require(role.hr)` read attributes resolved
from the caller's verified token. [Identity](apl/identity.md) covers how
those attributes get there; for now, an identity plugin such as
`identity/jwt` resolves the subject and roles before policy runs.

## 4. Load and run

```rust,ignore
engine.load_config_yaml(policy)?;
engine.initialize().await?;
```

Loading is where mistakes surface. An unknown key fails and names its
replacement, an unrecognized plugin `kind` fails because no factory
registered it, and under the default `dispatch: policy` a declared
plugin that no policy reaches fails by name. A configuration that loads
is one where every key does something.

The repository carries two runnable programs under
[`crates/ppe-core/examples/`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-core/examples):

```console
cargo run -p praxis-policy-core --example plugin_demo
cargo run -p praxis-policy-core --example cmf_capabilities_demo
```

Both run in `dispatch: hooks` mode and show the plugin and hook
machinery rather than APL policy. Their README explains what each one
demonstrates.

## What the policy produces

- An HR caller with `view_ssn` receives the full record.
- An HR caller without `view_ssn` receives the record with `ssn`
  redacted before it leaves PPE.
- A non-HR caller is denied at `require(role.hr)`, and the call never
  reaches the backend.

## Next

- [Overview](overview.md): follow the enforcement pipeline through one scenario.
- [Use Cases](use-cases.md): run the full control set behind a gateway.
- [APL](apl/index.md): the language, and its
  [normative grammar](apl/apl-grammar.md).
- [Configuration](configuration.md): the document, its keys, and both
  dispatch modes.
- [Identity](apl/identity.md): resolving callers into the attributes
  policy reads.
- [Delegation](apl/delegation.md): minting scoped downstream
  credentials.
