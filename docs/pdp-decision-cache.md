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

Expired entries are dropped on lookup and never returned. At
`max_entries`, the oldest live entry is evicted (FIFO). Eviction is
deterministic for a given insert sequence.

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
`pdp_cost` bench: `CelResolver::new()`, `subject.id == 'alice'`, the
reader bag, `b.to_async`, and Criterion group `pdp_cost` so the function
names are already `pdp_cost/cache_miss` and `pdp_cost/cache_hit`.

**CI does not gate on wall-clock numbers.** Runner noise would flake
the gate, which is the same decision [#19](https://github.com/praxis-proxy/policy/issues/19)
records for the broader suite. Clippy `--all-targets` still compiles
the bench so it cannot bitrot.

When PR 35's `ppe-benches` crate is on `main`, add `pdp_cost/cache_hit`
and `pdp_cost/cache_miss` next to the existing per-PDP rows and copy
the numbers below into that document against the same hardware.

### Baseline (this machine)

Run `make bench-pdp-cache` and record Criterion's p50 / p95 / p99
here before publishing, with the CPU model. Until then the suite
compiles (`clippy --all-targets`) but does not claim a number.

| function | p50 | p95 | p99 | hardware |
|---|---|---|---|---|
| `pdp_cost/cache_miss` | — | — | — | fill in |
| `pdp_cost/cache_hit` | — | — | — | fill in |

A hit should be cheaper than a miss by enough to matter on the hot
path. If it is not, leave `cache:` omitted.
