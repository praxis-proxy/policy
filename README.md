# Praxis Policy Engine

<i>Policy Engine enforcement for Praxis.</i>

[![CI](https://github.com/praxis-proxy/policy/actions/workflows/ci.yml/badge.svg)](https://github.com/praxis-proxy/policy/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/praxis-policy.svg)](https://crates.io/crates/praxis-policy)
[![docs.rs](https://img.shields.io/docsrs/praxis-policy)](https://docs.rs/praxis-policy)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-blue.svg)](rust-toolchain.toml)

A deterministic Reference Monitor for
[Praxis](https://github.com/praxis-proxy/praxis). It mediates AI inference and
agent traffic through typed, phased APL pipelines. Each decision controls who
may call a tool, what data returns, and where that data may go next.

## What it does

- Identity: Resolves and independently validates user, agent, and workload
  identities.
- Authorization: Evaluates APL predicates and pluggable decision points,
  including relationship-based authorization.
- Delegation: Exchanges credentials through RFC 8693, giving each upstream
  service a token scoped to that service.
- Data control: Redacts fields in transit and propagates Session Taint
  across tool calls and requests.
- Header assertions: Renders the identity it derived onto the upstream
  request as headers, removes the client-supplied headers that would collide
  with it, and filters what an upstream is allowed to tell a client back. See
  [docs/content/assertions.md](docs/content/assertions.md).
- Human approval: Supports out-of-band human approval when a decision cannot
  be automated.
- Audit: Emits an audit event for every decision.

## Using it

Add one dependency to get the engine and all bundled extensions:

```toml
praxis-policy = { version = "0.2", features = ["builtins"] }
```

Without `builtins`, you get the engine alone and no extensions compiled in.
Declare individual features instead: `jwt`, `oauth`, `elicitation-ciba`,
`cedar`, `cel`, `opa`, `valkey`.

The crates are versioned together and released together, so a single `0.2`
requirement covers the set. Requires Rust 1.96 or newer.

## Documentation

[docs/content/index.md](docs/content/index.md) indexes the full set.

## Status

0.2.x. The public API will move between minor versions while the shape settles;
a breaking change gets a minor bump and is documented in the CHANGELOG.

## Layout

    crates/             the engine, APL implementation, and host facade
    builtins/           bundled plugins, decision points, and session stores
    reference/          worked examples, not published and not bundled

A host may replace any bundled plugin. Implement a Plugin Factory through
`PluginFactory` against `praxis_policy_core::prelude`, then register it with
`PolicyEngine::register_factory` under the `kind:` your policy names. An
unrecognized `kind` causes policy loading to fail, so missing registrations are
detected at startup.

`reference/plugins/` holds two worked examples: a PII scanner and an audit
logger. These are not published, but are linted and tested here, and the
reference [demo](https://github.com/praxis-proxy/demos) registers them as host
plugins.

## Building

The toolchain is pinned and is also the MSRV, so `cargo build` picks the right
one. `make help` lists the available targets.

## License

Apache-2.0. See [LICENSE](LICENSE).
