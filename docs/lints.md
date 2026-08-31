# Lints

`[workspace.lints]` in `Cargo.toml` is the authority on what is enforced. Entries
that are not enforced are grouped there by reason, and each group is a settled
decision rather than a backlog. This document explains those decisions: why a lint
is allowed, what enforcing it would take, and the traps in measuring that.

Every lint that could silently change an enforcement decision is denied.

## How the counts are produced

From the compiler, not from reading the source:

```
cargo clippy --workspace --all-targets --all-features -- -W <lint>
```

A hit inside a `#[cfg(test)]` region, or in a `tests/`, `examples/`, or `benches/`
target, is not a production site. Test code is scope-allowed at the module or
crate level, so these numbers describe the library's own surface.

Three measurement traps, all of which produced wrong numbers here before:

- **A text scan cannot tell production from a scope-allowed test module.** The
  first inventory recorded 58 production panic sites by scanning. The real number
  under the same six lints is 28.
- **Some clippy lints suppress each other.** Measured as a group,
  `needless_raw_string_hashes` reports zero because `needless_raw_strings` covers
  the same spans. On its own it fires 12 times. Measure one lint at a time when
  the number will be relied on.
- **Clippy does not check `rustdoc::` lints.** Passing them to clippy reports zero
  for every one. They need `cargo doc` with `RUSTDOCFLAGS`.

Worth re-checking whenever these numbers are refreshed: an allow attribute placed
above a file's `#[cfg(test)]` boundary would suppress production hits and make the
surface look clean. All 462 such attributes in `src` currently sit inside a test
region. A gate that reports green because its suppressions are misplaced is worse
than one that reports a large number.

## Relationship to Praxis's lint set

Every lint Praxis configures has an explicit level here, so nothing is enforced by
accident or left unconsidered. Most match Praxis exactly; the rest are either
weaker, with the reason recorded in the group tables below, or stricter, which is
allowed to stand.

Deliberately not recorded: a count of how many match. That number moves when
Praxis changes its own lints, so a figure written here goes stale without anything
in this repository changing. Compare the two `[workspace.lints]` blocks directly
when the question comes up.

The entries that are not enforced, by group:

| Group | Lints |
|---|---:|
| style | 10 |
| perf | 9 |
| hygiene | 6 |
| api | 5 |
| complexity | 5 |
| attributes | 2 |
| docs | 1 |
| concurrency | 1 |
| test-hygiene | 1 |

Thirty-seven of the 40 are rules Praxis enforces more strictly. The other three
are lints Praxis also does not enforce, or does not configure.

`dead_code` is not in that table. It is denied: unused items fail the build.
Public host-facing API with no in-tree caller is kept with a reason on the item
naming who calls it from outside the workspace. A reason that only defers work
(`future`, `TODO`, `might`) is not enough; delete the item. Test fixtures may
suppress with a test-scoped reason. Do not add a text-scan CI gate for these
attributes: a scan cannot tell production from a scope-allowed test module.

## Documentation lints

Every public item is documented and `missing_docs` is enforced, along with
`missing_errors_doc`, `doc_markdown`, `doc_lazy_continuation`,
`doc_overindented_list_items`, and `rustdoc::missing_crate_level_docs`.

That was 968 items. What it took, and what generalizes:

- **247 sites were mechanical** and closed with `clippy --fix`: identifiers
  needing backticks, and list indentation. Ten needed hand correction, including
  a prose line beginning with `+`, which markdown read as a list item and turned
  the following six lines into lazy continuations.
- **13 crate docs and 127 module lines.** Both had usable prose already, as
  plain `//` header comments rather than `//!` or `///`, so most of this was
  promoting what was there and cutting it to length.
- **103 constants** across two tables. Systematic enough to derive from the name
  and value, which is legitimate for a table of attribute keys and hook names.
- **60 `# Errors` sections**, each read from the function's error paths. Several
  carry the reason the error exists rather than just its variant: an unresolved
  deny-list reference cannot fail open to empty the way an allow-list can, an
  unresolved Cedar `${key}` would change which policy matches, and a failed
  session append becomes a deny because the decision is already computed.
- **The remaining 425 items** are the domain types: rule IR, pipeline stages,
  step dialects, extension slots, payload builders, and the error enums.

Two doc links of my own were caught by `make doc` on the way: one pointed at a
private method from a public section, and one repeated a path the label already
resolved. That is the doc gate paying for itself.

`missing_docs_in_private_items` stays allowed, at 243 items. Private items never
reach docs.rs, so it is documentation for readers of the source rather than for
callers, and it is the one docs lint whose absence costs nothing externally.

## Applying this lint set to newly imported code

The Rego decision point arrived after the gate was already closed, which made it
a useful test of whether the gate is a one-time cleanup or a standing bar. It
came in at 50 violations across 6 files, none of which had ever been compiled
against these rules.

29 closed with `clippy --fix`. Of the 21 that did not, three are worth recording:

- **`string_slice` in the diagnostic truncator.** The slice offset came from
  `floor_char_boundary`, so it was provably on a boundary. Converted to `get`
  anyway, which carries the fact rather than asserting it.
- **`float_to_value` had the same off-by-one bound as the CEL crate**, admitting
  2^63 because `i64::MAX as f64` rounds up. Fixed the same way, so the two
  decision points agree on what an integral float becomes.
- **One `# Errors` section** and 32 documentation items.

The rest was test-scope suppressions. Nothing in the lint table changed to
accommodate the import, which is the outcome that matters: a new crate meets the
existing bar rather than the bar bending to admit it.

## Counting pitfall: numbers taken on a tree that does not compile

Fourteen lints were left allowed on production counts that were really zero:
they fired only in test code, which is scope-allowed. Those are now enforced, at
the cost of scoped allows in the affected test modules and no production change
at all.

The lesson is the measurement order. Each of those fourteen looked like work
because earlier counts were taken while other lints still failed, and a crate that
fails to compile blocks its dependents from being linted, so every count taken
before the tree was clean understated some lints and left others looking larger
than they were. Re-measure after each class closes.

## Where a lint's own suggested fix is wrong

Clippy reported 718 sites across 22 lints as `MachineApplicable`. Fourteen lints
closed cleanly. The other eight did not, and the reasons are worth recording
because the applicability flag is not a promise:

- **`unused_qualifications` (130 sites).** Reported applicable, but rustfix
  cannot apply the suggestions: they overlap within single statements. Applying
  them by hand at that volume is churn with no reader gain.
- **`let_underscore_drop` (12).** The rewrite spans several edits per site, and
  applying them mechanically produced syntactically broken code. `let _ =` on a
  droppable value is also often the deliberate spelling.
- **`wildcard_imports` (4).** The fix expanded a glob into a 48-name import list
  and still missed three names a test module used. All four globs are sibling
  modules of one logical unit split across files, where the glob is the better
  code. They keep their globs with per-site reasons, and the lint is enforced.
- **`allow_attributes` (58).** Converting `#[allow]` to `#[expect]` turns a
  suppression into an assertion that the lint still fires. Two suppressions here
  cannot satisfy that under every feature set: `register_builtins` and
  `builtin_pdps` have bodies that are entirely `#[cfg(feature)]`-gated, so
  `unused_variables` and `unused_mut` fire with no features enabled and not with
  all of them. No single attribute is correct for both, so the lint stays allowed.

That last one paid for itself anyway. Because `#[expect]` fails when a lint stops
firing, the conversion surfaced **63 stale suppression entries** in test-module
blocks: lints listed in an allow list that no longer occur in that module, so a
future real violation would have gone unflagged. Those were removed and stay
removed.

Two smaller lessons from the same sweep. A fix can violate an already-enforced
lint, as one `single_match_else` rewrite left a tail expression that tripped
`semicolon_if_nothing_returned`. And `derivable_impls` appends a second
`#[derive]` rather than merging into the existing one, which compiles but reads
badly.

## Numeric casts and unsafe code

Three of the 35 cast sites were live defects rather than provably-safe
conversions.

- **A valkey `ttl_seconds` past `i64::MAX` wrapped negative**, and `EXPIRE` with
  a non-positive TTL deletes the key at once. Because this store carries session
  taint, an absurd TTL made taint quietly fail to persist between requests: a
  downgrade, not an outage, and invisible in logs. Now rejected at config load,
  and saturating at the call site as a second guard.
- **The evaluator compared integer pairs through `f64`.** Above 2^53 distinct
  i64 values collapse onto one double, so an ordering test answers wrongly.
  Integer pairs now compare exactly; mixed int/float still needs a common type
  and carries a reason.
- **Delegation depth and a delegated-token TTL hint wrapped.** Both now
  saturate, so an overflow reads as maximally deep or unshortened rather than
  shallow or negative. `delegation.depth > N` is a rule operators write, so a
  wrapped depth was a bypass.

The unsafe class closed by deletion. The crate's only unsafe code was two
hand-written `Send`/`Sync` impls on a zero-sized capability token, justified by a
comment claiming a private zero-sized field suppresses auto traits. That is not
how auto traits work: the sole field is `()`, which is already `Send + Sync`, so
the impls bought nothing. A compile-time assertion stands in their place, so a
future non-`Send` field fails there with a clear message.

Two related classes were checked and needed no work. `await_holding_lock` and
`await_holding_refcell_ref` are clean: no synchronous guard is held across an
`await` anywhere, which is the case that actually deadlocks.
`integer_division` and `modulo_arithmetic` measured zero from the start, which
retires divide-by-zero.

`significant_drop_tightening` stays allowed at 9 sites, deliberately. The scopes
where tightening removed a real hazard are closed: the plugin factory lookup no
longer holds the registry read lock across host-supplied `create` code, which
could re-enter the engine and deadlock, and the CEL compile cache now logs
outside its guard while keeping the capacity check and the insert under one lock
so the cap cannot be exceeded by two threads racing. The rest hold a guard across
a synchronous call on purpose and document why.

## Panic sources

Every panic source is enforced. There are no `gate:` entries left.

Now at deny: `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`,
`string_slice`, `unreachable`, `get_unwrap`, `print_stdout`, `print_stderr`,
`exit`, `mem_forget`, and the rustdoc link lints. `integer_division` and
`modulo_arithmetic` measured zero from the start, which retired divide-by-zero
without work.

68 production sites were closed. Two of them were live bugs rather than
provably-safe indexing:

- **`regex(")` and `enum(")` aborted the parser.** A lone quote satisfies both
  `starts_with('"')` and `ends_with('"')`, and the follow-up `s[1..s.len() - 1]`
  slices from index 1 to 0. Two of five hand-rolled quote strippers were missing
  the length guard the other three had. `parse_pipeline` is public and policy text
  is operator input, so this was reachable, not theoretical. All five now share one
  `strip_prefix`/`strip_suffix` helper, which cannot take that shape.
- **An empty issuer algorithm list aborted token validation.** Config validation
  blocks it, so it was only reachable by emptying the public field after a valid
  build. It now denies: an empty list read as "any algorithm acceptable" hands
  algorithm choice to whoever minted the token.

The rest were structurally eliminable, with the bound check sitting next to the
index. Those were restructured so the panic cannot be expressed rather than given
an error path, which is why most carry no new test: there is no new branch to
test, and reaching one would have meant widening a crate's public surface to get
at provably dead code.

Three fixes were checked against their previous implementations rather than
trusted to review, because a silent behavior change in any of them would be a
routing, disclosure, or decision bug: `glob_match` (116,345 pattern/text pairs),
`redact_endpoint` and `parse_duration_secs` (11,111 cases). Zero mismatches,
including multi-byte input on paths that indexed bytes.

Two fail-open hazards were closed by restructuring rather than by bounds checks,
because a bounds-checked positional write has no safe failure branch. In the
orchestrator, dropping an outcome left its slot unset, which becomes `Aborted`,
and an `Aborted` that was really a `Deny` is a bypass; outcomes are now keyed, and
map insertion is total. In the executor, pairing an outcome with the wrong entry
would apply the wrong plugin's `on_error` and turn a configured `Fail` into an
`Ignore`; it now zips and denies on a length mismatch.

## Coverage

Not a lint concern. `COVERAGE_FLOOR` in the `Makefile` is the gate, and the only
place that threshold is written down.

Worth knowing when reading both documents: enforcing a lint from the tables above
barely moves coverage, because those changes remove or restructure code without
adding branches.
