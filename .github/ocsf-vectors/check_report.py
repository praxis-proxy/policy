# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors

"""Require the signed-record checks that the verifier's baseline profile omits."""

import argparse
import json


RECORD_DIMENSIONS = (
    "structural_validity", "decision_consistency", "fingerprint", "signature", "key_binding",
)
CHAIN_DIMENSIONS = (
    "trust_policy", "record_uniqueness", "chain_links", "chain_gaps", "chain_head",
)
STREAM_DIMENSIONS = ("stream_sequence", "stream_head")


def verified(report: dict, dimension: str, context: str) -> None:
    status = report.get(dimension, {}).get("status")
    if status != "verified":
        raise SystemExit(f"{context}: {dimension} must be verified, got {status}")


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("report")
parser.add_argument("--stream", action="store_true", help="require the example's stream stamps")
args = parser.parse_args()
with open(args.report, encoding="utf-8") as source:
    report = json.load(source)["report"]
records = report.get("records")
if not isinstance(records, list) or not records:
    raise SystemExit("no verified records")
for index, record in enumerate(records):
    for dimension in RECORD_DIMENSIONS:
        verified(record, dimension, f"record {index}")
for dimension in RECORD_DIMENSIONS + CHAIN_DIMENSIONS:
    verified(report, dimension, "stream")
for dimension in STREAM_DIMENSIONS:
    if args.stream or report.get(dimension, {}).get("applies") is not False:
        verified(report, dimension, "stream")
# These examples supply no independent head; they cannot prove tail completeness.
if report.get("tail", {}).get("status") not in ("verified", "not_checked"):
    raise SystemExit("tail must be verified or explicitly not checked")
