# Benchmarks

PPE ships a Criterion suite that measures the decision hot path: plugin
dispatch, a full route decision, per-PDP evaluation, throughput under
concurrency, and heap use per decision. Benchmarks run on demand and never
gate CI.

Setup work stays outside the timed loop. YAML parsing, Cedar compilation, and
plugin registration all run before measurement starts, so a result reflects
`PolicyEngine::invoke_named`, `PdpResolver::evaluate`, or a `SessionStore`
operation, not load cost.

## Prerequisites

| Requirement | Needed for |
|-------------|------------|
| Rust stable, pinned in `rust-toolchain.toml` | everything |
| Python 3.10+ | `make bench-percentiles` |
| Linux `perf` plus [inferno](https://github.com/jonhoo/inferno) | CPU profiles |

`dhat` is feature-gated and requires no system package.

## Targets

The suite lives in the unpublished `ppe-benches` crate. It is not a workspace
default member, so an everyday `cargo build` skips it.

| Target | Measures |
|--------|----------|
| `hook_overhead` | Plugin dispatch alone: N no-op plugins, sequential and concurrent, no APL or PDP |
| `full_decision` | A route decision: plugin only, Cedar only, plugin then Cedar |
| `throughput` | Decisions per second with 8, 32, and 128 concurrent callers |
| `pdp_cost` | `evaluate` on Cedar, CEL, and OPA, enforcing the same rule |
| `memory` | Session taint growth and decision latency against Cedar policy count |
| `heap_profile` | Bytes per decision and footprint by policy count, under `dhat` |

## Running

```console
make bench                                    # the whole suite
cargo bench -p ppe-benches --bench pdp_cost   # one target
cargo bench -p ppe-benches -- --test          # run once each, no timing
```

The `--test` form runs each case once without measuring it. Use it in a
pre-push loop or to verify fixtures after a policy or engine change. A single
target returns almost at once; the whole suite takes well under a minute.

## Reading the results

Criterion prints a mean and a confidence interval per case, and writes an HTML
report with distribution and regression plots:

```console
open target/criterion/report/index.html
```

Criterion reports mean and median but not request-level tail latency. To
calculate percentiles across its per-sample iteration means:

```console
make bench-percentiles
```

This prints a Markdown table of p50, p95, and p99 per case. These values
describe the sample means, not individual-request latency.

## Comparing against a previous run

Criterion saves each run and compares the next one against it, reporting the
delta and a p-value:

```text
hook_overhead/sequential/16
                        time:   [148.96 µs 149.95 µs 150.88 µs]
                 change: [+7.1491% +8.2192% +9.2949%] (p = 0.00 < 0.05)
                        Performance has regressed.
```

The saved baseline is whatever ran last on that machine. It is not a number
stored in the repository, so the comparison is only meaningful when both runs
happened on the same host under the same conditions.

## Profiling

Use a CPU profile to find where a slow benchmark spends its time:

```console
BIN=target/release/deps/full_decision-*
perf record -g -F 99 -o perf.data -- \
  $BIN --bench cedar_only --warm-up-time 1 --measurement-time 8 --sample-size 25
perf script | inferno-collapse-perf | inferno-flamegraph > flamegraph.svg
```

For allocation behavior:

```console
make bench-heap
```

That reports bytes per decision and the footprint as Cedar policy count grows,
and writes `dhat-heap-*.json` under `crates/ppe-benches/` for
[dh_view](https://docs.rs/dhat/latest/dhat/#viewing-the-output). `dhat`
replaces the global allocator and slows execution considerably, so read it for
bytes and ignore its wall-clock numbers.

## Getting trustworthy numbers

- Treat results as specific to the machine that produced them. The
  plugin-dispatch numbers in particular vary by more than an order of
  magnitude across hosts, and the sequential versus concurrent ordering can
  invert. Re-measure locally rather than trusting a recorded figure.
- Compare shapes, not absolutes. How a number scales with plugin count,
  policy count, or concurrency survives a change of host; the nanoseconds do
  not.
- Leave the machine idle. A compile or a test run on another core moves
  results well past the effect sizes worth chasing.
- Re-run before believing a regression. Criterion reports significance
  against one prior run, which is not the same as a stable baseline.

## CI

Benchmarks do not gate pull requests. Wall-clock timing on shared runners is
noise-dominated, and a flaky performance gate teaches people to ignore red
builds.

CI compiles every benchmark target with `cargo clippy --all-targets` and an
additional pass with the `dhat-heap` feature.

## Related documentation

- [Benchmark results](../dev/benchmarks.md): recorded baselines, profile
  findings, and the reasoning behind the CI decision.
- [Testing](testing.md): testing a policy as code.
- [Crates](crates.md): what each crate in the workspace is for.
- [Documentation index](index.md): return to the documentation map.
