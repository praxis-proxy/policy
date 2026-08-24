# Benchmark suite (issue [#19](https://github.com/praxis-proxy/policy/issues/19))

This document is the acceptance write-up for the Criterion suite under
`crates/ppe-benches/` (`ppe-benches`). It records **how to run**, **what each target
measures**, **CI policy**, and **baseline / profile** results.

**Framework:** Criterion **0.7** (`html_reports`, `async_tokio`).

## Framework choice

**Criterion only** (with `async_tokio`). One framework keeps the suite
runnable and comparable over time; mixing Divan / iai / ad-hoc `Instant`
instrumentation on the request path was rejected for this ticket.

## What is in scope

The hot path is `PolicyEngine::invoke_named` (and, for PDP microbenches,
`PdpResolver::evaluate`). **Out of scope:** Praxis HTTP, Pingora, JWKS,
upstream I/O, Valkey.

YAML parse, Cedar compile, and APL visitor annotation run in **setup**,
never inside Criterion iters. Compile cost matters at load, not per request.

## Targets

| Target | Ticket axis | What it isolates |
|--------|-------------|------------------|
| `hook_overhead` | Time — plugin dispatch | N no-op plugins, sequential + concurrent modes, no APL/PDP |
| `full_decision` | Time — full decision; eval vs dispatch | APL `plugin_only` / `cedar_only` / `plugin_then_cedar` |
| `throughput` | Throughput | Concurrent Tokio callers; YAML `mode: concurrent` |
| `pdp_cost` | Per-PDP cost | Cedar / CEL / OPA `evaluate` only |
| `memory` | Memory | Session taint; policy-size decision sweep; optional dhat |
| `heap_profile` | Memory (bytes) | Per-decision alloc + policy-size footprint (`dhat-heap`) |

Criterion’s console/HTML report mean / median / slope. It does **not** print
p95/p99 by default. After a bench run, derive percentiles from samples:

```bash
make bench-percentiles
# → python3 tools/bench_percentiles.py  (reads target/criterion/**/new/sample.json)
```

## How to run

```bash
# Full suite (on demand)
make bench
# equivalent:
cargo bench -p ppe-benches

# One target
cargo bench -p ppe-benches --bench full_decision
cargo bench -p ppe-benches --bench pdp_cost

# Percentiles for docs / review
make bench-percentiles

# Heap bytes (requires dhat-heap)
make bench-heap
```

### CPU profile (flamegraph)

```bash
# Linux with perf (not WSL2). Build with symbols, then profile the binary:
#   CARGO_PROFILE_BENCH_DEBUG=1 RUSTFLAGS='-C force-frame-pointers=yes'
#   cargo bench -p ppe-benches --bench full_decision --no-run
# Direct binary run needs --bench or Criterion stays in test mode:
BIN=target/release/deps/full_decision-*
perf record -g -F 99 -o perf.data -- \
  $BIN --bench cedar_only --warm-up-time 1 --measurement-time 8 --sample-size 25
perf script | inferno-collapse-perf | inferno-flamegraph > flamegraph.svg
```

Artifact checked into the repo:
[`docs/flamegraph-full_decision-cedar_only.svg`](flamegraph-full_decision-cedar_only.svg)
(open in a browser).

On hosts without `perf`, the Criterion differential table under **CPU profile
findings** remains a useful cross-check.

### Memory profile (dhat)

```bash
# Criterion memory target (optional allocator; wall-clock not comparable)
cargo bench -p ppe-benches --features dhat-heap --bench memory

# Isolated per-decision + policy-size footprint (preferred for byte numbers)
make bench-heap
# → prints per_decision_bytes and max_bytes vs policy count; dhat-heap.json
```

`session_append_one` reseeds the store to exactly `n_labels` every iteration
(`iter_batched` setup) and reports `Throughput::Elements(1)`.

## CI decision (acceptance criterion)

| Question | Decision |
|----------|----------|
| Do benchmarks gate CI / PRs? | **No.** |
| Why? | Wall-clock p99 on shared runners is noise-dominated; a flaky gate trains people to ignore red CI. |
| What *does* CI do? | `clippy --all-targets` (via `make lint` / `make ci`) **compiles** every `[[bench]]` so the suite cannot bitrot. |
| Is `make bench` part of `make ci`? | **No.** Documented on-demand only. |
| If we ever gate later | Prefer a relative regression threshold ≥ **15–20%** on p50 (not p99) against a stored baseline on dedicated hardware — not default GitHub-hosted runners. |

## Baseline numbers

Captured locally on the hardware below. Do **not** treat GitHub-hosted CI
runners as a source of truth for these numbers.

### Hardware (record when capturing)

| Field | Value |
|-------|-------|
| Date | 2026-08-26 |
| Host | WSL2 (`C-PF4TF3ED`) |
| CPU | AMD Ryzen 7 PRO 7840HS (8c/16t) |
| Cores / threads | 8 / 16 |
| RAM | 30 GiB (WSL2) |
| OS | Linux 6.18 (WSL2 on Windows 10) |
| `rustc` | 1.96.0 (ac68faa20 2026-05-25) |
| Profile | Criterion default (release for benches) |

> Re-run `make bench` on bare metal and replace this table if you need
> numbers for release notes — WSL2 adds scheduler noise.

### Latency (p50 / p95 / p99)

Derived with `tools/bench_percentiles.py` from Criterion `sample.json`
(`time_per_iter = sample_time / iters`). Means included for comparison.

| Bench | p50 | p95 | p99 | mean | notes |
|-------|-----|-----|-----|------|-------|
| `hook_overhead/empty_registry` | 270 ns | 278 ns | 284 ns | 272 ns | floor: invoke with no plugins |
| `hook_overhead/sequential/1` | 1.04 µs | 1.11 µs | 1.16 µs | 1.06 µs | real plugin dispatch (fixed hook name) |
| `hook_overhead/sequential/4` | 2.88 µs | 3.01 µs | 3.23 µs | 2.90 µs | |
| `hook_overhead/sequential/16` | 8.48 µs | 8.95 µs | 9.11 µs | 8.55 µs | |
| `hook_overhead/concurrent/1` | 39.8 µs | 44.9 µs | 49.0 µs | 40.4 µs | concurrent-mode executor cost |
| `hook_overhead/concurrent/4` | 46.9 µs | 50.2 µs | 53.1 µs | 47.2 µs | |
| `hook_overhead/concurrent/16` | 70.7 µs | 73.5 µs | 77.3 µs | 70.5 µs | |
| `full_decision/plugin_only` | 5.75 µs | 6.03 µs | 6.29 µs | 5.78 µs | APL + noop plugin |
| `full_decision/cedar_only` | 57.5 µs | 59.1 µs | 63.3 µs | 57.6 µs | APL + Cedar |
| `full_decision/plugin_then_cedar` | 59.9 µs | 62.1 µs | 65.7 µs | 60.2 µs | operator shape |
| `pdp_cost/cel_evaluate` | 7.27 µs | 7.78 µs | 8.34 µs | 7.32 µs | `evaluate` only |
| `pdp_cost/cedar_evaluate` | 40.3 µs | 43.6 µs | 44.8 µs | 40.4 µs | |
| `pdp_cost/opa_evaluate` | 47.0 µs | 50.0 µs | 50.8 µs | 46.5 µs | |

### Throughput

32 concurrent Tokio callers per sample (Criterion `thrpt`). Percentiles are
**per burst** (not per single decision).

| Bench | tasks | p50 / burst | p95 | p99 | elems/s (approx) | notes |
|-------|-------|-------------|-----|-----|------------------|-------|
| `throughput/plugins_concurrent_mode` | 32 | 148 µs | 153 µs | 156 µs | ~216 Kelem/s | plugins only, concurrent mode |
| `throughput/apl_yaml_mode_concurrent` | 32 | 241 µs | 314 µs | 352 µs | ~131 Kelem/s | YAML `mode: concurrent` |
| `throughput/apl_plugin_then_cedar` | 32 | 609 µs | 640 µs | 803 µs | ~52 Kelem/s | APL plugin → Cedar |

### Memory / session

| Bench | input | p50 (approx) | observation |
|-------|-------|--------------|-------------|
| `memory/session_load_labels` | 8 / 64 / 512 | 115 ns / 1.58 µs / 12.8 µs | scales with label cardinality |
| `memory/session_append_one` | 8 / 64 / 512 | ~0.46 / 2.1 / 16 µs (p50) | reseed to `n_labels` each iter; thrpt = 1 elem |
| `memory/session_snapshot` | 10 / 100 / 1000 | 844 ns / 10.6 µs / 115 µs | scales with session count |
| `memory/full_decision_with_session_id` | — | 88.4 µs (p50) | `YAML_PLUGIN_THEN_CEDAR` + session hydrate/persist |
| `memory/policy_size_decision` | 1 / 10 / 50 policies | 58.2 / 67.0 / 103 µs | decision latency vs Cedar rule count |

### CPU profile findings (captured flamegraph)

**Capture host (RHEL lab VM, 2026-08-26):**

| Field | Value |
|-------|-------|
| Host | `rhel.mmv9t.sandbox694.opentlc.com` (OpenTLC RHEL 10) |
| CPU / RAM | 2 vCPU / 3.5 GiB |
| Kernel | 6.12.0-55.9.1.el10_0.x86_64 |
| Tool | `perf record -g -F 99` → `inferno-collapse-perf` → `inferno-flamegraph` |
| Case | `full_decision/cedar_only` (APL + Cedar allow path) |
| Binary | bench profile with `debug=1`, `strip=none`, frame pointers |
| Samples | 1889 (`perf.data`); SVG: `docs/flamegraph-full_decision-cedar_only.svg` |

**How to read the SVG:** a large share of samples sits in Criterion/rayon
bootstrap worker threads (analysis after measurement). The **PPE hot path**
is the stack under `ppe_benches::invoke_once` / `PolicyEngine::invoke_named`
(~25% of process samples in this capture). Within that path:

| Frame (approx share of process samples) | Role |
|-------------------------------------------|------|
| `PolicyEngine::invoke_named` → `Executor::execute` / `run_serial_phase` | Engine dispatch |
| `AplRouteHandler::invoke` → `evaluate_effects` | APL orchestration |
| `PdpRouter` / `CedarDirectResolver::evaluate` | PDP entry (~22%) |
| `cedar_direct::request::parse` | Request construction (~7%) |
| `cedar_direct::entities::build` / `build_principal` | Entity bag lift (~7%) |
| `cedar_policy` `Entity::from_json_value` / `Context::from_json_value` | Cedar JSON entity/context build |

**Findings:**

- On the APL+Cedar path, **time is dominated by Cedar evaluate and its
  request/entity construction**, not by sequential no-op plugin dispatch.
  Concurrent-mode plugin dispatch is a separate cost center (~40–70 µs).
- YAML parse / Cedar **policy compile** do not appear on the hot stacks
  (they run in Criterion setup, outside timed iters) — matches the ticket.
- WSL Criterion differentials (below) agree once hook registration is fixed:
  sequential PDP ≫ sequential dispatch; concurrent-mode dispatch is not free.

**WSL cross-check (differentials, after hook-registration fix):**

| Slice | Evidence | Finding |
|-------|----------|---------|
| Empty invoke | `hook_overhead/empty_registry` p50 ≈ 270 ns | Floor without plugins |
| Sequential dispatch | `sequential/1` ≈ 1.0 µs → `sequential/16` ≈ 8.5 µs | Real no-op handler cost; scales with N |
| Concurrent-mode dispatch | `concurrent/1` ≈ 40 µs → `concurrent/16` ≈ 71 µs | Concurrent executor path is far costlier than sequential |
| APL + plugin | `full_decision/plugin_only` p50 ≈ 5.8 µs vs `sequential/1` ≈ 1.0 µs | APL orchestration ≈ 4–5 µs over bare sequential dispatch |
| Cedar eval | `pdp_cost/cedar` p50 ≈ 40 µs vs `cedar_only` p50 ≈ 58 µs | PDP dominates; APL tax ≈ 18 µs on Cedar path |
| Session path | `full_decision_with_session_id` p50 ≈ 88 µs vs `plugin_then_cedar` ≈ 60 µs | Session hydrate/persist adds ~28 µs on this fixture |
| PDP ranking | CEL ≪ Cedar ≈ OPA | Dialect choice matters more than sequential dispatch |

### Memory profile findings

**Session-taint curve (Criterion):**

- `load_labels` grows with label set size (~100× from 8 → 512).
- `snapshot` grows with session count (~100× from 10 → 1000).
- `session_append_one` keeps starting size fixed via per-iter reseed.

**Policy size (Criterion latency):** decision p50 rises ~58 µs → ~103 µs as
Cedar policies go 1 → 50 (fillers do not match `reader`, but still participate
in evaluation work).

**Per-decision allocation + policy-size footprint** (`make bench-heap`,
`dhat::HeapStats`, 2026-08-26):

| Measurement | Result |
|-------------|--------|
| Per-decision (`delta_total_bytes / 500` after setup) | ≈ **209 KiB / decision** |
| Peak during that window (`max_bytes`) | ≈ 415 KiB |
| Policy count 1 — `max_bytes` / live `curr_bytes` | ≈ 127 KiB / ≈ 16 KiB |
| Policy count 10 — `max_bytes` / `curr_bytes` | ≈ 212 KiB / ≈ 47 KiB |
| Policy count 50 — `max_bytes` / `curr_bytes` | ≈ 608 KiB / ≈ 184 KiB |

Notes:

- Prefer `make bench-heap` over Criterion+dhat totals: fixed N, setup excluded
  from the per-decision delta.
- `max_bytes` includes load transients; `curr_bytes` after load+one decide is
  the steadier footprint signal as policy size grows.
- dhat slows wall-clock heavily — use it for **bytes**, not latency.

## Mapping to ticket acceptance criteria

| Acceptance criterion | Where it lives |
|----------------------|----------------|
| Suite under `crates/ppe-benches/` covering hook, full-decision, throughput, per-PDP | `hook_overhead`, `full_decision`, `throughput`, `pdp_cost` |
| `make bench` | `Makefile` target `bench` |
| Baseline numbers in `docs/` with hardware | this file (p50/p95/p99 via `bench-percentiles`) |
| CPU + memory profiles + findings | `docs/flamegraph-full_decision-cedar_only.svg` + findings; `make bench-heap` |
| CI gate decision (+ threshold if gating) | **CI decision** section — not gating; threshold guidance if revisited |
