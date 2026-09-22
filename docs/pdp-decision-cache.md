<!--
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Praxis Contributors
-->

# PDP decision cache

An optional, bounded cache around PDP `evaluate`. It stores **Allow and
Deny decisions**, not the CEL compile cache or the OPA prepared-engine
cache that already live inside those backends.

It is **off by default**. A `global.pdp[]` entry with no `cache:` block
is unchanged: every call reaches the resolver.

This feature is meant to land after the hot-path suite in
[#19](https://github.com/praxis-proxy/policy/issues/19) / [PR 35](https://github.com/praxis-proxy/policy/pull/35)
so operators can compare a miss (today's cost) with a hit. Until that
suite is on `main`, `make bench-pdp-cache` in this repository records
the same two numbers for the wrapper itself.

## Configuration

```yaml
global:
  pdp:
    - kind: cel
      cache:
        ttl_seconds: 30
        max_entries: 1024
```

Both fields are required when `cache:` is present, and both must be
positive integers. Omission of the whole block disables the cache.
`ttl_seconds: 0` or `max_entries: 0` fails configuration load.

Keep `max_entries` in the hundreds to low thousands. Evicting an
entry scans the FIFO order (`O(n)` in the cap); a value like 65536
makes every overflow insert expensive. The example above (1024) is
the intended scale. A later change can make removal `O(1)`.

The `cache:` key is stripped before the Cedar / CEL / OPA factory sees
the block, so those backends' unknown-key checks stay exact.

## Key

The map key is a SHA-256 digest of:

1. the PDP dialect
2. the call arguments, with YAML mappings hashed in sorted-key order
3. the complete attribute bag, with keys sorted and `StringSet` members
   sorted

The digest is what is stored. Request attributes are not retained in
the cache.

## What is stored

| Outcome | Cached? |
|---|---|
| `Ok(Allow)` | yes |
| `Ok(Deny)` | yes |
| `Err` (dispatch failure, timeout, missing args) | **no** |

Expired entries are dropped on lookup and never returned. When an
insert would exceed `max_entries`, every expired slot is dropped
first; only then does FIFO evict the oldest *live* entry. An expired
key in the middle of the queue therefore cannot occupy a slot that a
live entry needs. Eviction is deterministic for a given insert
sequence.

A PPE configuration generation change (any successful `load_config` /
`load_config_yaml`) drops the whole map, including wrappers still held
by in-flight handlers. Those handlers keep their previous resolver
(the Cedar/OPA policy they were built with) but must re-evaluate;
they cannot reuse a cached Allow or Deny from before the bump. New
handlers get the rebuilt resolver and start empty.

## Staleness of external PDP policy

**An external PDP policy can change independently of PPE.** A Cedar
file on disk, a Rego module edited outside this process, or an OPA
bundle the operator reloads without calling `load_config_yaml` is
invisible to the cache. Decisions from the previous policy may be
served until `ttl_seconds` elapses.

That is the cost of a decision cache. Choose a short TTL if those
policies move often, or leave `cache:` omitted.

PPE-side configuration changes do **not** have that window: they bump
`config_generation` and the cache is emptied.

## Observability

Counters, no key material and no attributes:

- `hits`
- `misses`
- `expiries`
- `evictions`

Each also emits `tracing` at `debug` with `alarm = "pdp_decision_cache"`
and `event` in `{hit, miss, expiry, eviction, generation_invalidated}`.

Tests read [`CachedPdpResolver::stats`](../crates/ppe-apl-runtime/src/decision_cache/wrapper.rs).

## Benchmarks and CI

`make bench-pdp-cache` times a miss (inner CEL evaluate) against a hit
(digest lookup) for the same call and bag. The harness matches PR 35's
`pdp_cost` bench: `CelResolver::new()`, `has(role.reader) && role.reader`,
the reader bag, `SamplingMode::Flat`, `b.to_async`, and Criterion group
`pdp_cost` so the function names are already `pdp_cost/cache_miss` and
`pdp_cost/cache_hit`. The miss cap is 1_000_000 so the timed loop does
not FIFO-evict.

**CI does not gate on wall-clock numbers.** Runner noise would flake
the gate, which is the same decision [#19](https://github.com/praxis-proxy/policy/issues/19)
records for the broader suite. Clippy `--all-targets` still compiles
the bench so it cannot bitrot.

When PR 35's `ppe-benches` crate is on `main`, add `pdp_cost/cache_hit`
and `pdp_cost/cache_miss` next to the existing per-PDP rows and copy
the numbers below into that document against the same hardware.

### Baseline (this machine)

`make bench-pdp-cache` on 2026-09-22, `SamplingMode::Flat`, 100
samples. CPU: 11th Gen Intel Core i7-1185G7 @ 3.00GHz.

| function | p50 | p95 | p99 | hardware |
|---|---|---|---|---|
| `pdp_cost/cache_miss` | 36 µs | 62 µs | 73 µs | i7-1185G7 @ 3.00GHz |
| `pdp_cost/cache_hit` | 1.1 µs | 1.7 µs | 2.2 µs | i7-1185G7 @ 3.00GHz |

A hit is about 30× cheaper than a miss at p50. Enabling `cache:` is
worthwhile for repeated identical PDP calls. If a workload almost
never repeats a digest, leave `cache:` omitted.
