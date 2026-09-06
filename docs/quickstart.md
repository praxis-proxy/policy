# Quick Start

Standing up PPE as an enforcement point, then running the
[scenario](overview.md): a `get_employee` route that authorizes by role
and redacts a field by permission.

You need Rust 1.96 or newer ([install with rustup](https://rustup.rs)).
The toolchain is pinned in the repository, so `cargo build` picks the
right one.

## 1. Add PPE

```toml
praxis-policy = { version = "0.2", features = ["builtins"] }
```

`builtins` compiles in every bundled extension: JWT identity, OAuth
delegation, CIBA elicitation, the Cedar, CEL and OPA decision points,
and the Valkey session store. For a smaller build, name a subset
instead: `features = ["jwt", "cedar"]`. See [Builtins](builtins.md).

The default build is the engine alone.

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

Without the `builtins` feature, register your own factories and install
the visitor yourself:

```rust,ignore
use std::sync::Arc;
use praxis_policy::{PolicyEngine, register_apl, AplOptions};

let engine = Arc::new(PolicyEngine::default());
engine.register_factory(MyIdentityFactory);
register_apl(&engine, AplOptions::default());
```

**Give it an HTTP transport if anything reaches outside the process.**
PPE performs no outbound HTTP of its own, so a plugin that fetches
JWKS, exchanges a token, or dispatches a CIBA prompt has nowhere to
send its request until a host supplies one. A host with its own client
injects it; a host without one uses the bundled implementation, behind
the non-default `http-hyper` feature:

```rust,ignore
// A host with its own client, one pool and one trust store for the process.
engine.set_http_transport(my_transport);

// Or the bundled hyper implementation.
praxis_policy::install_default_http_transport(&engine);
```

Plugins that reach outward must also declare the `perform_http`
capability, or the engine refuses to start and names what is missing.

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

- [Use Cases](use-cases.md): the full set of controls running end to end
  behind a real gateway.
- [APL](apl/README.md): the language, and its
  [normative grammar](apl-grammar.md).
- [Configuration](configuration.md): the document, its keys, and both
  dispatch modes.
- [Identity](apl/identity.md): resolving callers into the attributes
  policy reads.
- [Delegation](apl/delegation.md): minting scoped downstream
  credentials.
