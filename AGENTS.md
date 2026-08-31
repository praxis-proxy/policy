# Agent Guidance

This file provides guidance to coding agents when
working with code in this repository.

AI tools may assist with implementation, but do not
add Claude or another AI tool as a commit
collaborator, co-author, or signatory. Commit
sign-off belongs to the human contributor responsible
for the change.

## Requirements

- Rust stable 1.96+ (pinned in `rust-toolchain.toml`)
- No nightly required (formatting uses stable)

## Quick Reference

```console
make check          # type-check both feature sets (never links)
make build          # workspace build (debug)
make test           # all workspace tests (two passes)
make lint           # fmt --check + clippy -D warnings
make lint-extra     # typos + taplo fmt --check
make audit          # cargo deny check
make coverage       # line coverage gated at 95%
make doc            # rustdoc with -D warnings
make ci             # lint + test (what CI runs)
make setup-hooks    # install pre-commit hook
```

Run a single test:

```console
cargo test -p praxis-policy-core --lib -- test_name
```

## Architecture

16-crate workspace implementing a policy engine for
AI agent traffic. The engine decides who may call
which tool, what data comes back, and where that
data goes next.

**Crate layout:**

```text
crates/
  ppe           facade crate (praxis-policy), re-exports
  ppe-core      config, context, extensions, hooks,
                identity, delegation, elicitation
  ppe-orchestration  async branch concurrency
  ppe-apl-core  policy language parser + evaluator
  ppe-apl-cmf   canonical message format transforms
  ppe-apl-runtime  host runtime, plugin invokers,
                   route handler, session management
  ppe-pdp-diff  differential tests across cedar/cel/opa

builtins/
  plugins/      identity-jwt, delegator-oauth,
                elicitation-ciba
  pdps/         cedar-direct, cel, opa
  session/      valkey

reference/
  plugins/      pii-scanner, audit-logger (examples)
```

**Dependency flow:**

```text
ppe (facade)
 -> ppe-apl-runtime -> ppe-apl-cmf -> ppe-apl-core
 -> ppe-orchestration
 -> ppe-core
```

## Conventions

### Deliberate divergences from conventions template

These are settled decisions, not a backlog:

- **rustfmt**: stable-only, `max_width = 100` (not
  nightly, not 120)
- **30+ clippy lints at `allow`**: documented in
  `Cargo.toml` with per-group rationale. Do not
  change without reviewer approval.
- **No `panic = "abort"`**: this is a library; abort
  would take the host process down on a recoverable
  policy panic
- **`dead_code`, `elided_lifetimes_in_paths`,
  `single_use_lifetimes` at `allow`**: style and
  cleanup items that do not affect runtime behavior
- **`mod.rs` module style**: three module directories
  use `mod.rs`; not switching to file-adjacent style

### File headers

Every source file starts with:

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors
```

No author lines, no path lines.

### Lint rules

- Do not add new violations of a non-enforced lint
- Suppress lints at the narrowest scope, with a
  `reason`
- `[workspace.lints]` in `Cargo.toml` is the
  authority

### Tests

Two test passes: default features then `--all-features`.
The facade's tests are feature-gated because its
`default` is empty. Dropping either pass hides tests.

The Valkey session store tests are `#[ignore]`-gated
and need `VALKEY_TEST_URL` set to run against a real
server. `make coverage` runs them with
`VALKEY_TESTS_OPTIONAL=1` so they skip gracefully.

Prefer one test binary per concern over many small
ones. Cargo builds one binary per `tests/*.rs`, and a
`tests/<dir>/main.rs` harness that gathers related
cases links once instead of a dozen times.

While iterating:

- Use `make check` for fast compile-time feedback.
- Run tests for affected crates:
  `cargo nextest run -p <crate> --lib`.
- Reserve full workspace test runs for commit boundaries.

Newly linked test binaries may be delayed by endpoint
security. The test workflow above helps mitigate this issue.

## Supply Chain

```console
make audit          # cargo deny check
make publish-dry    # package without uploading
```

`deny.toml` has MPL-2.0 in the license allow-list
(for a dev-only HTTP mocking crate) and advisory
ignores for dev-only transitive dependencies.
