#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
"""Compute p50/p95/p99 from Criterion sample.json files (issue #19).

Criterion does not print p95/p99 by default. Per-iteration times are
sample_time_ns / iters for each sample; we take percentiles of that series.

Usage (from repo root, after `make bench` or a targeted cargo bench):

  python3 tools/bench_percentiles.py
  python3 tools/bench_percentiles.py --root target/criterion --filter full_decision
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


def fmt_ns(ns: float) -> str:
    if ns < 1_000:
        return f"{ns:.1f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.2f} µs"
    return f"{ns / 1_000_000:.2f} ms"


def per_iter_times(sample_path: Path) -> list[float]:
    data = json.loads(sample_path.read_text(encoding="utf-8"))
    iters = data["iters"]
    times = data["times"]
    out: list[float] = []
    for n, t in zip(iters, times, strict=True):
        if n <= 0:
            continue
        out.append(float(t) / float(n))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--root",
        type=Path,
        default=Path("target/criterion"),
        help="Criterion output root",
    )
    ap.add_argument(
        "--filter",
        default="",
        help="Only include benchmark ids containing this substring",
    )
    args = ap.parse_args()

    rows: list[tuple[str, float, float, float, float]] = []
    for sample in sorted(args.root.glob("**/new/sample.json")):
        # .../<group>/.../new/sample.json → id relative to root without /new/sample.json
        rel = sample.relative_to(args.root).parent.parent.as_posix()
        if args.filter and args.filter not in rel:
            continue
        vals = per_iter_times(sample)
        if len(vals) < 2:
            continue
        vals.sort()
        rows.append(
            (
                rel,
                percentile(vals, 50),
                percentile(vals, 95),
                percentile(vals, 99),
                sum(vals) / len(vals),
            )
        )

    if not rows:
        print(f"no samples under {args.root} (run make bench first)")
        return

    print("| Bench | p50 | p95 | p99 | mean |")
    print("|-------|-----|-----|-----|------|")
    for name, p50, p95, p99, mean in rows:
        print(
            f"| `{name}` | {fmt_ns(p50)} | {fmt_ns(p95)} | {fmt_ns(p99)} | {fmt_ns(mean)} |"
        )


if __name__ == "__main__":
    main()
