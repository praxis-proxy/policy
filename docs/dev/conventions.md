# Development Conventions

Adapted from the Praxis development conventions for the
Praxis Policy Engine. Repository-specific lint levels in
[Cargo.toml] and the settled decisions in [Agent Guidance]
take precedence over the shared style recommendations.
See [Lints] for the rationale behind the lint policy.

[Agent Guidance]: ../../AGENTS.md#conventions
[Lints]: lints.md

## Coding Style

### General Principles

- Brevity is a component of quality. Keep code lean and
  complete; no bloat.
- Small, composable, single-purpose functions are the
  default unit of organization. Split code into small
  files with focused responsibilities.
- Minimize side effects. Prefer pure transformations when
  feasible: data in, data out. Resist mutable state when
  feasible and outside the critical paths.
- Keep functions short enough to reason about in isolation.
- Prefer raw performance when reasonable. Reduce memory
  copies where feasible. Use references, borrowing, and
  in-place mutation when it avoids unnecessary cloning.

### Important Tools

- **Clippy**: Enforce idiomatic Rust and catch common
  mistakes
- **rustfmt**: Ensure consistent code formatting
- **cargo-deny**: Enforce supply chain safety policies
- **cargo-machete**: Detect unused dependencies
- **cargo-semver-checks**: Lint for SemVer violations
- **cargo-llvm-cov**: Enforce the coverage floor
- **rustdoc**: Generate the API documentation
- **Criterion**: Policy engine microbenchmarks in
  `crates/ppe-benches`, driven by `make bench`
- **dhat**: Heap profiling via `make bench-heap`

Use the targets in [Makefile] for the repository's
supported workflows. `make audit` uses `cargo deny check`
for advisories, licenses, bans, and sources; `make machete`
is advisory, and `make semver-facade` checks the facade's
public API with all features enabled.

[Makefile]: ../../Makefile

### Comments vs Tracing

Comments answer **"why?"**, never **"what?"**.

**"What?" belongs in `tracing`**, not comments. If a
comment describes what the code is doing at runtime
("parse the config", "reject the request", "skip this
filter"), replace it with a `tracing::debug!`,
`tracing::trace!`, or `tracing::info!` call. Runtime
narration (what the code did, what it decided, what it
skipped) is structured logging, not commentary.

**"Why?" belongs in comments**, but only when
non-obvious. A hidden constraint, a subtle invariant, a
workaround for a specific bug, or behavior that would
surprise a reader: these justify a comment. If removing
the comment would not confuse a future reader, do not
write it.

**"What?" at the code level needs neither.** Well-named
identifiers already explain what the code does. Do not
write comments that restate what names already convey.

### Testing

**New capabilities require all of the following:**

1. Unit tests covering the implementation
2. Integration tests proving end-to-end behavior through
   the policy engine, including allow and deny outcomes
3. Example policy or configuration documentation in
   `docs/content/`, with regression coverage for examples
   and fixtures in the affected suite
4. Significant changes need to be [benchmarked].

A feature without tests and a usable example is not
complete. See [Testing Policy] for route outcomes,
scripted transports, live dependencies, and suite layout.

`make test` runs two passes: default features, then
`--all-features`. Both are required; the facade's default
feature set is empty, so dropping the all-features pass
hides feature-gated tests. During iteration, use
`make check` and `cargo nextest run -p <crate> --lib` for
the affected crates. Reserve full workspace test runs for
commit boundaries.

The integration, resilience, and security suites under
`tests/` run in the all-features pass. Use
`make test-integration`, `make test-resilience`, or
`make test-security` to run them separately. Prefer one
test binary per concern, gathering related cases under a
`tests/<dir>/main.rs` harness.

[Testing Policy]: ../content/testing.md

Prefer more doctests when in doubt. Duplicative coverage
between doctests and unit/integration tests is fine.

Prefer assertion messages over inline comments. Put the
explanation in the assertion's message argument so it
prints on failure:

```rust
// Bad:
// ACL should block loopback
assert_eq!(status, 403);

// Good:
assert_eq!(status, 403, "ACL should block loopback");
```

[benchmarked]: benchmarks.md

#### Coverage Floor

`make coverage` enforces a hard floor: **96% line
coverage**. `make coverage-lcov` enforces the same floor
and produces `lcov.info`. The floor only ratchets up,
never down. The Makefile is the authority on coverage
flags and exclusions; `ppe-benches` is excluded.

Coverage includes all features and ignored tests, with
`VALKEY_TESTS_OPTIONAL=1` so tests needing a live Valkey
server skip gracefully. Set `VALKEY_TEST_URL` to measure
those paths against a real server. Other live suites and
their environment requirements are documented in
[Testing Policy].

#### Mutation Testing

Coverage proves code executed; mutation testing
(`make mutants`) checks whether assertions would notice
if the code were wrong. cargo-mutants rewrites function
bodies and operators and reports a surviving mutant when
the suite still passes. Strengthen the assertions or
remove unneeded code when a mutant survives.

`make mutants` runs the workspace on demand. It is
advisory and is not part of the blocking CI gate.

#### Property-Based Testing

Consider property-based tests for code with algebraic invariants:
parsers (round-trip), arithmetic (commutativity,
bounds), encodings (encode/decode identity).
Example-based tests pin known cases; property tests
search the input space for the case you did not think
of.

- `proptest!` blocks live inside `#[cfg(test)] mod
  tests`, after the example-based tests.
- Property test names state the invariant
  (`total_is_commutative`).
- Use `prop_assert!`/`prop_assert_eq!` with messages,
  like ordinary assertions.
- Commit `proptest-regressions/` files: they pin found
  counterexamples as permanent regression tests.

### RFC Conformance

When implementing protocol-level behavior (HTTP semantics,
header handling, TLS, etc.), identify the governing RFCs
and verify conformance against them.

- Cite the specific RFC number and section in test names
  or doc comments for protocol conformance tests.
- RFC references in doc comments must use reference-style
  rustdoc links to the IETF datatracker:

  ```rust
  /// Safe methods per [RFC 9110 Section 9.2.1].
  ///
  /// [RFC 9110 Section 9.2.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-9.2.1
  ```

- When in doubt about an edge case, the RFC is the
  authority, not other proxy implementations.
- Add dedicated conformance cases in the affected crate
  or the relevant integration or security suite when
  implementing RFC-specified behavior.

### Rules, Practices & Lints

Security is enforced at the lint level. See lints in
[Cargo.toml] for the full set.

- Unsafe code is forbidden by
  `[workspace.lints.rust].unsafe_code = "forbid"`.
  Member crates inherit the workspace lints.
- Clippy runs with `-D warnings` (zero tolerance)
- Errors via `thiserror`
- Logging via `tracing`
- Use workspace dependencies (`[workspace.dependencies]`)
  to keep versions consistent across crates
- Keep dependencies light. Avoid new dependencies
  when feasible
- Only add dependencies with well-established
  reputation
- Always specify full semver versions with patch
  (e.g. `1.2.3`, not `1.2` or `1`)
- `make audit` runs `cargo deny check` for supply chain
  safety, honoring the reviewed exceptions in
  [deny.toml]. Do not maintain a second advisory ignore
  list for a separate audit tool.

[Cargo.toml]:../../Cargo.toml
[deny.toml]: ../../deny.toml

#### Lint Suppression Policy

By default, do *not* suppress lints. Use your best
judgement if the situation really calls for it.

Prefer `#[expect(...)]` when the lint fires in every
supported feature set; it warns when the expectation
becomes stale. Use `#[allow(...)]` where feature-gated
bodies make that expectation unreliable. Both forms are
permitted here. Keep suppressions at the narrowest scope
and include a `reason`:

```rust
#[expect(
    clippy::indexing_slicing,
    reason = "the caller guarantees a nonempty slice"
)]
fn first_byte(bytes: &[u8]) -> u8 {
    bytes[0]
}
```

Do not add new violations of a non-enforced lint or change
the settled allow groups without reviewer approval.
`dead_code` is denied. Keep an unused public item only
with a reason naming its host or other out-of-tree caller;
delete items reserved only for hypothetical future work.

#### Arithmetic Safety

Arithmetic and `as` conversions remain allowed in the
policy evaluator's numeric paths; this is a settled
repository decision. For new code, state overflow and
conversion behavior explicitly:

- `checked_*` when overflow is an error to propagate
- `saturating_*` when clamping at the bounds is correct
- `wrapping_*` when modular arithmetic is intended
  (document why)

Prefer `From`/`Into` for lossless conversions and
`TryFrom`/`TryInto` where conversion can fail. The
specific `cast_*` lints in [Cargo.toml] remain enforced.
Never compare floats with `==` (`float_cmp`);
compare against an explicit epsilon.

Byte-order conversions must be explicit: `to_be_bytes`
or `to_le_bytes`, never the native-endian `to_ne_bytes`
(`host_endian_bytes`).

#### Exhaustive Matching

Prefer explicit enum variants when every new variant
needs a decision at each match site. Wildcard enum arms
are permitted here; use them only when the same fallback
is correct for the remaining variants.

#### Deterministic Iteration

Use `BTreeMap`/`BTreeSet`, or collect and sort, when
iteration affects reproducible output, serialization, or
tests. `HashMap`/`HashSet` iteration is permitted where
order has no effect on correctness, such as attribute
merging and configuration validation.

#### Async Safety

Do not hold synchronization guards across `.await`
points. Holding a `Mutex`, `RefCell`, or `RwLock`
guard across a suspension point risks deadlocks or
runtime panics. The `await_holding_lock` and
`await_holding_refcell_ref` lints enforce this.

```rust
// Bad - guard held across await:
let guard = mutex.lock().await;
let result = some_async_call().await;
drop(guard);

// Good - drop guard before awaiting:
let data = {
    let guard = mutex.lock().await;
    guard.clone()
};
let result = some_async_call().await;
```

Never silently drop futures or `#[must_use]` values.
`let _ = async_fn()` drops the future without polling
it. The `let_underscore_future` lint catches dropped futures.
`let_underscore_must_use` remains allowed here.

#### String Safety

Raw string indexing (`&s[n..m]`) panics on non-char
boundaries and is denied by the `string_slice` and
`indexing_slicing` lints. Use safe alternatives:

- `.get(range)` for fallible substring access
- `.chars().nth(n)` for character-level access
- `.char_indices()` for iterating with byte offsets

#### Trait Import Convention

When importing a trait only for its methods (not
naming the trait type), use `as _` to keep the name
out of scope. The `unused_trait_names` lint enforces
this.

```rust
// Good - trait name unused, import anonymously:
use std::io::Write as _;

// Bad - trait name pollutes scope unnecessarily:
use std::io::Write;
```

#### Module Organization

The repository uses `mod.rs`, including the builtin
extension groups. Keep the existing module layout;
`mod_module_files` remains allowed.

#### Naming Clarity

Use names that explain the value's role. Short bindings
and single-character lifetimes are permitted in concise
closures, matches, and generic contexts. Existing domain
field prefixes and staged shadow bindings are also
permitted; do not rename them solely to match the shared
conventions template.

#### Visibility Design

- Choose field visibility around the caller's needs.
  Mixed public and private fields are permitted here.
- Public fields must not be underscore-prefixed
  (`pub_underscore_fields`).
- Use `pub(crate)`, not `pub(in crate)`
  (`pub_without_shorthand`).
- Named generic parameters and argument-position
  `impl Trait` are both permitted. Choose the form that
  makes the public API clearest.
- Accept `Option<&T>`, not `&Option<T>` (`ref_option`).

#### Type Design

Make invalid states unrepresentable. The type system
and serde should enforce constraints at parse time,
not at runtime.

- **Enums over strings for fixed value sets.** Never
  use `String` where the valid values are known. Use
  `#[serde(rename_all = "snake_case")]` enums.
- **Structs over maps for known keys.** Never use
  `BTreeMap`/`HashMap` for config deserialization when
  the key set is known. Use a struct with
  `#[serde(deny_unknown_fields)]`.
- **Enums over multiple `Option<T>` fields.** When
  exactly one of N fields must be set, use an N-variant
  enum.
- **`#[serde(default)]` over `Option<T>` with
  `unwrap_or`.** Use the concrete type with
  `#[serde(default = "fn_name")]` instead.
- **`#[serde(try_from)]` for constrained numerics.**
  Define an enum with `TryFrom` for fixed numeric
  values.
- **`#[serde(deny_unknown_fields)]` by default.** Apply
  to all config structs unless the struct intentionally
  accepts arbitrary keys.

### Additional Coding Conventions

- Use separator comments to visually separate distinct
  sections of code.
- Avoid re-export-only files unless they define an
  intentional public facade. `crates/ppe` deliberately
  re-exports the engine and builtin APIs.
- **Constants** must be at the top of the file (after
  imports), never inside functions or impl blocks.
  Give them their own separator comment
  (e.g. `// Constants`).
- **File ordering**:
  1. Constants (with separator comment)
  2. Public types, impls, and functions
  3. Private types and impls (below their public
     consumers)
  4. Private utility/utility functions (with separator)
  5. `#[cfg(test)] mod tests` block (always last)
- **Field and method ordering**: Alphabetical, with
  `name` pinned first on structs and `new()`/`name()`
  pinned first in impl blocks.
- **Inside `#[cfg(test)] mod tests`**:
  1. Imports
  2. All test functions (`#[test]` / `#[tokio::test]`)
  3. Test utilities at the end (with `// Test Utilities`
     separator)
- **Attribute formatting on structs, enums, fields,
  and variants**:
  - Order items within `#[derive(...)]` alphabetically.
  - Order parameters within `#[serde(...)]`
    alphabetically.

  ```rust
  // Good:
  #[derive(Clone, Debug, Default, Deserialize, Serialize)]
  #[serde(default, deny_unknown_fields)]
  pub struct Foo {

  // Bad (non-alphabetical):
  #[derive(Debug, Clone, Default, Serialize, Deserialize)]
  #[serde(deny_unknown_fields, default)]
  pub struct Foo {
  ```

- Keep attributes attached to their item without blank
  lines (`empty_line_after_outer_attr` is denied).
- Separate distinct logical actions with blank lines.
  Function calls, variable bindings that begin a new
  step, and expression blocks that perform a discrete
  operation should have some newline space.
- Prefer pre-computed numeric literals over expressions
  like `1024 * 10`. Always add a trailing comment with
  the human-readable size or meaning (e.g.
  `const MAX_BODY: usize = 10_485_760; // 10 MiB`).

#### Separator Comments

All separator comments must be full-width (77 dashes),
never short-form:

```rust
// -----------------------------------------------------------------------------
// Section Name
// -----------------------------------------------------------------------------
```

Never: `// --- Section Name ---`

#### Test Conventions

- Never use inline comments inside test function bodies.
  All explanatory text must be either an assertion
  message or a `tracing::info!` / `debug!` / `trace!`
  call. Bad: `// ACL should block`.
  Good: `assert_eq!(status, 403, "ACL should block")`.
- Do not add doc comments (`///`) or regular comments
  (`//`) on test functions. The function name is the
  documentation. The exception is RFC conformance tests,
  which should have a doc comment citing the RFC number
  and section.
- Do not add per-test separator comments. Use one
  full-width separator to mark where tests begin. The
  exception is RFC conformance tests, which should have
  a separator comment for each test citing the RFC
  number and section.
- Use "Test Utilities" in separator comments, not
  "Utilities". Test utility modules should use doc
  comments that say "test utilities", not "utilities".
- Test utilities must stay inside the `#[cfg(test)]`
  block so they compile only during testing.
- Name tests after the behavior they prove. Do not use
  a `test_` prefix for new behavior tests. Existing
  prefixed names are permitted;
  `redundant_test_prefix` remains allowed here.
  Bad: `fn test_acl_blocks_loopback()`.
  Good: `fn acl_blocks_loopback()`.
- Do not assert on `Result` states
  (`assertions_on_result_states`): `assert!(r.is_ok())`
  discards the error message. Production code denies
  `unwrap`/`expect`; tests may use scoped suppressions
  with a reason. Prefer fallible tests returning `Result`
  and propagating with `?`, then assert on the value:

  ```rust
  #[test]
  fn config_parses_defaults() -> Result<(), ConfigError> {
      let cfg = Config::from_str("")?;

      assert_eq!(
          cfg.timeout_secs, 30,
          "default timeout should be 30s"
      );
      Ok(())
  }
  ```

  For expected errors, match the variant instead of
  unwrapping:

  ```rust
  assert!(
      matches!(result, Err(ConfigError::UnknownField(_))),
      "unknown keys must be rejected"
  );
  ```

#### Restriction Lints

The following restriction lints are enforced across all
crates:

- **`todo` / `unimplemented`**: no placeholder macros in
  production code. Use proper error handling or feature
  gates instead.
- **`unused_result_ok`**: do not silently discard
  `Result` values via `.ok()`. Handle or propagate the
  error.
- **`exit`**: do not call `std::process::exit()`. Use
  graceful shutdown via the runtime instead.
- **`mem_forget`**: do not call `std::mem::forget()`. It
  leaks resources. Use `ManuallyDrop` if drop must be
  suppressed.

#### Rustdoc Lints

Rustdoc quality is enforced at compile time via
`[workspace.lints.rustdoc]`:

- Broken intra-doc links, bare URLs, unescaped
  backticks, invalid HTML tags, and invalid codeblock
  attributes are all denied.
- Every crate must have a crate-level doc comment
  (`//!` at the top of `lib.rs` or `main.rs`).
- Private doc tests are denied.

#### Idiomatic Rust

- Prefer `to_owned()` over `to_string()` for `&str` to
  `String` conversions. Reserve `to_string()` for
  Display formatting on non-string types (integers,
  errors, enums).
- Prefer `String::new()` over `"".to_owned()` or
  `"".into()` for empty strings.
- Use inline format args: `format!("{var}")` not
  `format!("{}", var)`.
- Use `is_some_and()` instead of
  `.map(...).unwrap_or(false)`.
- Use let-chains for nested `if let`: prefer
  `if let Some(x) = e && cond { }` over
  `if let Some(x) = e { if cond { } }`.

### Documentation

- Public functions, methods, structs, enums, and type
  aliases must have `///` doc comments (`missing_docs`).
  Every crate needs crate-level docs. Document private
  items when it helps explain intent;
  `missing_docs_in_private_items` remains allowed.
- Rustdoc **prose** must cover intent, interface, and
  example usage only. Do not explain internal mechanics
  unless they are critical for a caller to use the item
  correctly. If a sentence describes how the function
  works rather than what it does or when to call it,
  remove it.
- Do not over-explain standard patterns (Arc, Cow, early
  returns, option unwrapping) in prose.
- Do not add redundant "Default: X" lines when the
  default is already implied by the trait default or
  function body.
- Do not document memory efficiency in rustdoc (e.g.
  "avoids allocation", "zero-copy", "cheap clone").
  Correct memory use is expected; it does not need
  narration.
- **Prefer ample doctests.** When in doubt, add one.
  Doctests are valuable; keep them thorough. The
  restriction above is on prose text, not on the
  quantity of doctests.
- Use reference-style rustdoc links, not inline. Put
  link definitions at the bottom of the doc block:

  ```rust
  /// Uses [`Pipeline`] to execute the chain.
  ///
  /// [`Pipeline`]: crate::Pipeline
  ```

### File Headers

Every source file starts with:

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors
```

Do not add author or path lines.

### Formatting

- Wrap lines at 80 characters in `.md` files. Code lines
  follow stable rustfmt with `max_width = 100`. Code
  blocks inside Markdown may use up to 120 characters.
- Always use the correct syntax highlighter on fenced
  code blocks in `.md` files: `console` for shell,
  `rust` for Rust, `yaml` for YAML, `toml` for TOML,
  etc. Never use bare triple backticks.

## Code Responsibility

This project does not distinguish between code written by
hand, generated by a tool (e.g. lint), or produced by any
other means. **Every contributor is responsible for the
code they submit**, and *all* code MUST be human reviewed
before submission, or merging.

Signed-off commits (`Signed-off-by:`) are required and
represent your assertion that you have reviewed and fully
understand the changes you are submitting.

PRs from a bot or tool (with the exception of
GitHub-specific ones like `dependabot`) will not be
accepted.

Before submitting or merging PRs, ensure that you have:

- Read every line of the diff. If you cannot explain why
  something exists, do not submit it.
- Verified that the change does what you intended and
  nothing more.
- Run the test suite *locally* first. The CI pipeline is
  not a substitute for local verification.

> **Note**: `Draft` pull requests are not exempt from
> these guidelines. They are still expected to be
> reviewed before submission.

### Commit Messages

Commits follow the Conventional Commit format:

```text
type(scope): summary
```

- Types: `build`, `chore`, `ci`, `docs`, `feat`, `fix`,
  `perf`, `refactor`, `test`
- Scope is optional, lowercase, kebab-case
- Subject line at most 72 characters
- Body explains what and why when the subject is not
  enough

### Pull Request Conventions

Keep PRs reviewable. The contribution rules are:

- **Size**: at most 500 added lines of production code.
  `Cargo.toml`/`Cargo.lock`, tests, docs, examples, and
  benchmarks do not count toward the limit. Split larger
  changes into a stack of reviewable PRs.
- **Description**: every PR must explain what it does
  and why.
- **Commit format**: subjects follow the conventional
  commit format above.
- **DCO**: every commit carries a `Signed-off-by`
  trailer.
- **Signed commits**: every commit must be
  cryptographically signed (GPG or SSH).
- **Human authorship**: commits claiming they were
  authored, co-authored, or signed-off by AI tools are
  rejected, per the policy above. Humans are
  responsible for the code they submit, and must know
  it and understand it prior to submission, regardless
  of what tooling they used to produce it.
- **Proposals**: proposal files must satisfy the
  frontmatter and lifecycle rules in
  [the enhancements repository](https://github.com/praxis-proxy/enhancements).

Run the applicable checks locally before submission.
The workflows under `.github/workflows/` are the
source of truth for automated enforcement.
