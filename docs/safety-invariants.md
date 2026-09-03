<!--
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Praxis Contributors
-->

# Safety invariants

PPE's core promise is that every degraded path resolves to deny, or to
the configured default, and never fails open. This document is that
promise as a list of testable claims. The suite that pins them is the
fault-injection catalog: a plugin and a PDP resolver that can panic,
return an error, or hang, driven across every seam.

A claim that is only a comment is not an invariant. Each item below
names the test that fails if the claim is violated.

## Containment versus halt

A panic, error, or timeout is **contained** when it does not unwind
`Executor::execute` / `evaluate_effects` and is routed through the
configured error policy. Whether the pipeline then **halts** follows
`PluginMode::can_block`, the same rule that already governed error and
timeout before panic was contained in every phase:

| Mode | `can_block` | `on_error: fail` on panic / error / timeout |
| --- | --- | --- |
| Sequential, Concurrent | yes | **Deny**, violation code `plugin_panic` / `plugin_error` / `plugin_timeout` |
| Transform, Audit | no | Continue; the failure is recorded on `PipelineResult.errors` |
| Fire-and-forget | no | The pipeline has already allowed; `wait_for_background_tasks` records a panic. Error and timeout are logged on the task and do not change the verdict |

That difference is deliberate. Transform and audit cannot halt: a
redactor or a logger that panics must not become an enforcement point,
and must not skip the rest of the pipeline by unwinding. Fire-and-forget
cannot block by construction. Sequential and concurrent *are*
enforcement points, so fail-closed means deny.

There is no `PluginMode::Ref`. Audit is the read-only serial phase,
dispatched through `run_ref_phase`. Containing panics there is the
audit cell.

`Disabled` is not a dispatch phase. `group_by_mode` skips it.

## Claims

**I1. A plugin panic is contained in every dispatch phase.** It does not
unwind `execute()`. Sequential and concurrent with `on_error: fail`
deny with code `plugin_panic`. Transform and audit continue and record
code `panic`. Fire-and-forget allows; after `wait_for_background_tasks`
the panic is an error, not a test unwind. A sequential panic under
`on_error: ignore` still runs later audit; a sequential panic under
`on_error: fail` does not.
Tests: `plugin_fault_catalog_asserts_the_safe_verdict`,
`a_contained_serial_panic_under_ignore_still_runs_audit`, and
`a_serial_fail_panic_does_not_run_audit` in
`crates/ppe-core/tests/safety_invariants.rs`.

**I2. A plugin error is fail-closed in blocking phases.** Sequential and
concurrent with `on_error: fail` deny with code `plugin_error`.
Transform and audit continue and record the error. Fire-and-forget
allows.
Same catalog.

**I3. A plugin timeout is fail-closed in blocking phases.** Sequential
and concurrent with `on_error: fail` deny with code `plugin_timeout`.
Transform and audit continue and record code `timeout`. Fire-and-forget
allows.
Same catalog.

**I4. `on_error: ignore` and `on_error: disable` are the configured
default for that plugin.** They continue in concurrent (and, for
panic/error/timeout, in serial, transform, and audit). Disable marks the
plugin so it is not dispatched again.
Tests: the concurrent nine-cell matrix in `crates/ppe-core/src/executor.rs`
(`a_concurrent_*_under_ignore_*`, `a_concurrent_*_under_disable_*`), and
`plugin_ignore_and_disable_do_not_halt_serial_transform_or_audit` in
`crates/ppe-core/tests/safety_invariants.rs`.

**I5. `OnError` defaults to `Fail`.** An unset `on_error` is fail-closed.
Pinned by `#[default]` on `OnError` and by `omitted_on_error_in_yaml_is_fail`
in `crates/ppe-core/tests/safety_invariants.rs`.

**I6. An empty plugin list allows.** No plugin means nothing denied.
Test: `empty_plugin_list_allows` in `crates/ppe-core/tests/safety_invariants.rs`.

**I7. A PDP panic, error, or timeout is a deny.** The evaluator spawns
the resolver call with a 30s budget (`PDP_EVALUATE_TIMEOUT`). Panic and
timeout become `PdpError::Dispatch`; the `Effect::Pdp` arm already maps
that to `Decision::Deny`. The control (`InjectedFailure::None`) allows.
Test: `pdp_fault_catalog_asserts_the_safe_verdict` in
`crates/ppe-apl-core/tests/safety_invariants.rs`, driven once per shipped
dialect so a new dialect without a cell fails to compile.

**I8. CEL eval errors default to deny.** `CelResolver`'s `OnError`
defaults to `Deny`. `on_error: allow` is an operator-chosen default for
runtime eval errors only; compile errors still deny.
Test: `membership_on_absent_key_denies_but_empty_set_evaluates` in
`builtins/pdps/cel/src/resolver.rs`, and the missing-attribute cells
below.

**I9. A missing attribute is not an allow.** Each shipped dialect's
verdict may be deny-by-eval-error, deny-by-default, or a dispatch error;
none of those is `Allow`. The cell pins the allowlist row
`missing-subject-id` (Cedar dispatch error, CEL eval error, OPA default
deny), not merely that the verdict is not allow.
Test: `every_dialect_missing_attribute_is_not_allow` in
`crates/ppe-pdp-diff/src/safety.rs`.

**I10. Malformed config does not start an engine.** An unknown key, a
misspelled block, or unparseable YAML fails the load. No request is
allowed because no engine is running that config.
Test: `malformed_config_fails_the_load` in
`crates/ppe-core/tests/safety_invariants.rs` (unknown key, misspelled
`pluginss:`, unparseable YAML).

**I11. Malformed PDP policy is not an allow.** Garbage Cedar, CEL, or
OPA text yields deny or dispatch error, not permit. Cedar is a dispatch
error; CEL is a compile error; OPA is compile or dispatch.
Test: `every_dialect_malformed_policy_is_not_allow` in
`crates/ppe-pdp-diff/src/safety.rs`.

**I12. Adding a dispatch phase without a catalog cell fails the build.**
`PluginMode` matches in `is_dispatch_phase`, `group_by_mode`,
`all_plugin_modes`, and `expected_plugin_verdict` are exhaustive inside
`ppe-core`. `plugin_fault_catalog_covers_every_dispatch_mode` checks
that the catalog visits a mode iff `is_dispatch_phase` is true.

**I13. Adding a shipped PDP dialect without a catalog cell fails the
build.** `ppe-pdp-diff::drivers::Dialect::all` and the safety catalog
match on `Dialect` are exhaustive. The facade test
`every_builtin_pdp_kind_is_in_the_differential_harness` still requires
the dialect on `HARNESS_PDP_KINDS`. AuthZen and NeMo are
`PdpDialect` variants without an in-tree resolver; they are not shipped
harness dialects.

## Catalog

Plugin axis, `on_error: fail`, one cell per
`{Sequential, Transform, Audit, Concurrent, FireAndForget} × {panic, error, timeout}`
plus a `None` control per mode. Each cell asserts the decision (deny
with a named code, or continue with a named record, or allow plus the
background-task observation), not merely that no allow was returned.

PDP axis, one cell per `{cedar, cel, opa} × {panic, error, timeout}`
plus a `None` control, missing-attribute, and malformed policy.

## What is not an invariant

CEL `on_error: allow` fails *open* for runtime eval errors because the
operator configured that default. The invariant is "deny or the
configured default", not "deny always".

A fire-and-forget plugin cannot change a verdict that has already been
returned. A hang there is bounded by the per-plugin timeout inside the
spawned task; it does not hold the request.

APL predicates treat a missing attribute as `false`. That is not a
permit: a `when` that does not match simply does not fire. A deny rule
that does match still denies. Missing-attribute *PDP* behaviour is I9.
