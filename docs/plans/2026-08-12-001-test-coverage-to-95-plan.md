# Line coverage floor: 96%

Created: 2026-08-12
Updated: 2026-09-08
Status: closed at 96.01% line coverage; `COVERAGE_FLOOR` is 96

## Why 96, not 100

The first effort closed the floor at 95. [#14](https://github.com/praxis-proxy/policy/issues/14) asked for a number above that. Measured on 2026-09-08 with `make coverage` (`--workspace --all-features --include-ignored`, `VALKEY_TESTS_OPTIONAL=1`, rustc 1.96.0):

| | lines counted | missed | cover |
|---|---:|---:|---:|
| workspace | 51,181 | 2,043 | **96.01%** |
| `crates/ppe-apl-core/src/parser.rs` | 4,213 | 250 | 94.07% |
| `crates/ppe-core/src/engine.rs` | 6,018 | 322 | 94.65% |
| `builtins/session/valkey/src/store.rs` | 36 | 3 | 91.67% |

`--fail-under-lines 96` is green. The next integer, 97, is not: it would need hundreds more covered lines. The ~25 unreachable defensive guards (cannot exclude on stable) plus test-module panic arms that we refuse to collapse cap the achievable number. 96 is the highest integer the suite currently defends.

There is almost no headroom. If a platform difference of a few lines turns CI red, cover something rather than lowering the floor.

## What this increment covered

- Parser: bad-input cases for stage/taint arguments, `when:`/`do:` shape errors, nested `do:` / PDP-in-`do:`, `on_deny:`, malformed call forms, `restrict:` field validation, predicate lexer errors (`1.`, `1e2`, unclosed `(`, empty subscript, literal-first comparison, reserved `not`).
- Engine: `ConfigVisitor` refusal now includes `visit_route` and `visit_complete`; `load_config_yaml` names YAML lex failures and `PolicyConfig` deserialize failures.
- Valkey: `append_labels` with an empty slice is a no-op without dialing. The coverage job starts a Valkey service with a `valkey-cli ping` healthcheck and sets `VALKEY_TEST_URL`.

Panic arms in the parser tests and named mock plugins in the engine were not collapsed.

## What remains uncovered, with a reason

**Parser (~250 missed lines).** Roughly half are test `panic!` arms that name the unexpected variant; collapsing them would lift the metric and make failures mute. Production leftovers are error-return sites that still lack a dedicated bad-input case (lexer edges, elicit/delegate value parsing, some `require`/`exists` arms). The internal `taint(...)` "did not produce a taint stage" path is unreachable if `parse_taint` only returns `Stage::Taint`.

**Engine (~322 missed).** Named mock plugins and their factories account for a large share. Remaining production paths include request-path denials, assertion unreachable warnings, and other load/runtime arms that need fixtures beyond a refusing visitor.

**Valkey (3 missed lines, `store.rs:95-97`).** `conn()`'s pool-error and acquire-timeout arms. Hitting them needs a stalled or poisoned pool, not a healthy `VALKEY_TEST_URL`. Empty append and the integration suite against a real endpoint are covered.

## Verification

```
make lint
make test
make coverage      # cargo llvm-cov --workspace --fail-under-lines 96
```

Raise `COVERAGE_FLOOR` only after the suite is green at the new value, and never lower it.
