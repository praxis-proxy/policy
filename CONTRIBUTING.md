# Contributing

## Toolchain

The toolchain is pinned in `rust-toolchain.toml` and is also the project MSRV.
`cargo` picks it up automatically. Formatting and coverage both run on that
pinned stable toolchain, so nothing here needs nightly.

## Before opening a pull request

```
make lint
make test
make audit
```

`make ci` runs the same set CI does.

## File headers

Every source file starts with exactly these two lines, and nothing else:

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors
```

The year is the year the file was added. `#` instead of `//` in TOML, YAML and
shell. This covers workflows and project config, not just crate sources.

One exception: `crates/ppe-core/tests/fixtures/legacy-policy-document.yaml` carries
no header. It is a verbatim copy of a policy document authored against the engine's
previous name, and staying byte-identical is what makes it evidence.

No `Authors:` line and no path line. Both go stale: a path breaks the moment a
file moves, and an author list stops being true as soon as somebody else edits
the file. `git log --follow` answers both questions accurately.

## Comments explain the code, not the work that produced it

A comment earns its place by telling a reader something they need in order to
change the code safely. Some things that feel worth writing down are not:

- **Progress and task state.** Remaining-work counts, "started at X, now Y",
  which items are deferred. It is stale within a sprint and it belongs in the
  tracker or a `docs/plans/` document.
- **History.** "This used to be a separate crate", "we tried X first". State the
  requirement in the present tense. If the reason a mistake is easy to repeat is
  itself worth knowing, say what the constraint is, not what happened.
- **Internal milestone names.** "Slice B", "Phase 0". They mean nothing to a
  reader and can collide with real vocabulary: this codebase documents a
  five-phase execution model, so an unrelated "Phase 5" points at the wrong idea.
- **Cross-repository census numbers.** A count of another project's lint set goes
  stale when they commit, not when we do, so it cannot be kept honest.

```rust
// no
// Two passes, because folding the aggregator into the facade silently stopped
// three tests running. A green single-pass run said nothing was wrong.

// yes
// Two passes: the second is the only way to reach `#[cfg(feature = ...)]` test
// modules. Dropping either hides tests without failing.
```

Some documentation is generated from source comments. `make lint` regenerates and
compares it, so run the full gate rather than `cargo clippy` alone.

## Durable text carries no planning identifiers

Commit messages, code comments, rustdoc, changelog entries, and pull-request
descriptions must stand on their own. Do not cite requirement or plan document
identifiers such as `R12` or `U3` in any of them.

Those documents do not ship with the code. An identifier is meaningless to
someone reading the commit a year from now, and it rots the moment the document
changes or moves. Describe the behavior or the reason instead:

```
# no
fix: address R24 fail-closed requirement in parser

# yes
fix: return a deny when the parser hits an unreachable branch

    An invariant that becomes a permit if it turns out to be reachable is a
    policy bypass, so the error path maps to deny at the decision boundary.
```

This applies to commits authored here. It does not apply to the commit history
imported from the engine's previous home, which is preserved as written.

## Imported history

Most of this tree was imported from another repository with its history intact,
so `git log` and `git blame` reach back before this repository existed. Two
consequences are worth knowing:

- Imported commit messages reference pull-request numbers from the original
  repository. GitHub will autolink them to unrelated numbers here. They are not
  rewritten, because rewriting them would cost more traceability than the
  autolink noise costs.
- Imported commits that touched both ported and excluded paths were rewritten to
  their ported portion, so they do not correspond one-to-one with commits in the
  original repository. Cross-tree comparison works by path and content, not by
  commit identity.

`docs/port-provenance.md` records the exact source commit the import was taken
from.

## Lints

`[workspace.lints]` in `Cargo.toml` is the authority. Most rules are denied; the
ones that are not sit at the end of each section, grouped by why, with a comment
per group. That list is a settled decision rather than a backlog: every lint that
could silently change an enforcement decision is already denied.

Three rules for contributors:

- **Do not add new violations of a non-enforced lint.** It is not enforced
  because the existing violations were judged not worth the churn, which is not
  an invitation to add more.
- **Do not suppress a lint at a wider scope than the code that needs it.** A
  module-level allow that covers lints the module does not violate hides the next
  real one, so prefer the narrowest scope, with a `reason`.
- **`dead_code` reasons must name the out-of-tree caller.** The lint is denied.
  A public host-facing item with no in-tree caller may keep
  `#[allow(dead_code, reason = "...")]` only when the reason says who calls it
  from outside this workspace. Reasons that only defer work (`future`, `TODO`,
  `might`) are not enough; delete the item. Test fixtures may use a test-scoped
  reason.

Enforcing one of the allowed groups is welcome as a focused change, one lint at a
time, separate from feature work. `docs/lints.md` is worth reading first: it
records which lints clippy reports as machine-fixable but cannot actually fix, and
where a lint's suggested rewrite is worse than the code it replaces.
