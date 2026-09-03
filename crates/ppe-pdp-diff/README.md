# Differential testing (Cedar, CEL, OPA)

Three PDP resolvers read the same `AttributeBag`. Each crate tests itself.
This crate feeds one bag and an equivalent policy intent to all three and
compares verdicts and cause kinds. An unlisted disagreement fails `make
test`, which CI already runs on every pull request.

This README is the written semantic subset required by
[issue #25](https://github.com/praxis-proxy/policy/issues/25). The catalog
in `src/cases.rs` and the allowlist in `src/allowlist.rs` are the
executable form.

## Semantic subset (must agree)

A bag shape is in the subset when all three engines have a native type for
it **and** Cedar's principal builder actually surfaces it. Cedar only maps
`subject.id` / `subject.type`, `role.*` (true bools), `perm.*` (true bools),
`subject.teams`, and `claim.*`. Subset cases use that vocabulary.

| Bag | Operator | Cedar surface | CEL / OPA |
|---|---|---|---|
| `String` `subject.id` | equality | `principal.id` | `subject.id` |
| `Bool` **present** `role.hr` | truth | `principal.roles.contains("hr")` | `has(role.hr) && role.hr` / `input.role.hr == true` |
| `Int` `claim.depth` | `<=` | `principal.claims.depth` | `claim.depth` / `input.claim.depth` |
| `StringSet` with members `subject.teams` | contains / `in` | `principal.teams.contains` | `"eng" in subject.teams` |

Negative subset cases must all **deny**. Cause kinds may still differ:
Cedar no-match is `DefaultDeny`; CEL/OPA `false` is `PolicyFalse`. That
triple is named on the case (`AgreeDeny`), not hidden.

Present-empty `StringSet` (`empty-set`, `bridge-empty-teams`,
`bridge-empty-roles`) is in the subset: membership is false everywhere,
including APL `require(subject.roles contains "hr")`. Cedar rebuilds
`principal.roles` from flattened `role.*` trues; CEL and OPA read the
original `subject.roles` set. The bridge writes both from the same
`HashSet`, so they agree when empty.

Unguarded probes of **omitted scalars** and of a flattened bool whose
namespace was never written are not in the subset. See
[`docs/cmf-extensions.md`](../../docs/cmf-extensions.md).

## Out of subset (allowlist)

| Id | Shape | Why they cannot be required to agree |
|---|---|---|
| `floats-claim` | `AttributeValue::Float` on `claim.*` | Cedar has no float type; claims are stringified. CEL/OPA compare numerically. |
| `floats-whole` | `Float(2.0)` on a claim | CEL/OPA coerce whole floats to int. Cedar still has a string, so `== 2` does not match. |
| `floats-resource` | float in Cedar `resource.attributes` | Cedar rejects at entity build (`PdpError::Dispatch`). CEL/OPA accept the bag value. |
| `missing-collection` | no `role.*` keys, unguarded CEL `role.hr` | Cedar empty set (clean false). Unguarded CEL is an eval error. OPA without `default` is undefined. |
| `missing-subject-id` | no `subject.id` | Cedar cannot build a principal. CEL eval error. OPA undefined. |
| `missing-claim-string` | omitted `claim.tenant` | Optional strings are omitted. Unguarded equality is a CEL/Cedar eval error and an undefined OPA query. |
| `missing-claim-int` | omitted `claim.depth` | Same as a missing string; emitting `0` would pass a `<= 2` gate. |

Each allowlist row in `src/allowlist.rs` carries a `reason`. An unused id
or an empty reason fails the meta tests.

## Cause kinds

The harness compares `Verdict` (Allow / Deny / DispatchError) **and**
`CauseKind`. It does not require the full English `reason` string to match.
CEL eval errors append variable lists; Cedar forbid text includes policy
ids. Those sentences change without the *kind* of deny changing.

| Kind | Stable marker |
|---|---|
| `Allow` | `Decision::Allow` |
| `PolicyFalse` | `"CEL expression evaluated to false"` / `"OPA query evaluated to false"` |
| `DefaultDeny` | Cedar `rule_source == "cedar.default_deny"`; OPA `"OPA query undefined — request not granted"` |
| `EvalError` | reason starts with `"CEL eval error:"` or Cedar `cedar.evaluation_error` |
| `DispatchError` | `Err(PdpError::Dispatch(_))` |

## CI

`make test` runs `cargo test --workspace` twice (default features, then
`--all-features`). This crate is a default workspace member, so an
unlisted divergence fails GitHub Actions job `test`.

A fourth shipped PDP must be added to `HARNESS_PDP_KINDS` and `Dialect` in
this crate. The facade test
`every_builtin_pdp_kind_is_in_the_differential_harness` fails if
`builtin_pdp_factories` grows a kind that is not in that list.
