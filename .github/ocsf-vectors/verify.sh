#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors

# Check the ocsf-audit records with a verifier that shares no code with the
# emitter: the signed decision stream from `demo_stream`, a restart of it,
# the two records `emit_sample` prints, and copies that must fail.
set -euo pipefail

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
here="$(dirname "$0")"
example() { cargo run --quiet --locked -p praxis-policy-plugin-ocsf-audit --example "$@"; }
verify() {
	agent-evidence-verify ocsf-decision "$1" --trust-policy "$2" > "$work/report.json" || return $?
	python3 "$here/check_report.py" "$work/report.json" "${@:3}"
}
# Exit 1 is a refusal of a record that was read; 2 is a record not read.
refuse() {
	local rc=0
	verify "$1" "$2" || rc=$?
	if [ "$rc" -ne "$4" ]; then
		echo "$3: expected exit $4, got exit $rc" >&2
		cat "$work/report.json" >&2
		exit 1
	fi
	echo "refused as expected: $3"
}

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/key.pem" 2>/dev/null
python3 "$here/prepare.py" jwks ci-key org-ci --pem "$work/key.pem" > "$work/ci.jwks"
export DEMO_SIGNING_KEY="$work/key.pem" DEMO_KEY_ID=ci-key DEMO_AUTHORITY=org-ci

DEMO_CHAIN_UID=ci-chain-1 example demo_stream > "$work/stream.ndjson"
verify "$work/stream.ndjson" "$work/ci.jwks" --stream
echo "verified: $(wc -l < "$work/stream.ndjson") signed decision records"

# A restart opens a new epoch and a new chain; both verify together.
cp "$work/stream.ndjson" "$work/restart.ndjson"
DEMO_EPOCH=1755648000000000001 DEMO_CHAIN_UID=ci-chain-2 example demo_stream >> "$work/restart.ndjson"
verify "$work/restart.ndjson" "$work/ci.jwks" --stream
echo "verified: two processes, two chains"

example emit_sample | python3 "$here/prepare.py" ndjson > "$work/sample.ndjson"
python3 "$here/prepare.py" jwks demo-key-2026-07 org-f3576cf6 --scalar 42 > "$work/demo.jwks"
verify "$work/sample.ndjson" "$work/demo.jwks"
echo "verified: emit_sample, as committed in SAMPLE-OUTPUT.md"

sed '1s/"disposition_id":1,/"disposition_id":2,/' "$work/stream.ndjson" > "$work/altered.ndjson"
cmp -s "$work/stream.ndjson" "$work/altered.ndjson" && { echo "the alteration did not apply" >&2; exit 1; }
refuse "$work/altered.ndjson" "$work/ci.jwks" "a changed verdict" 1
sed '3d' "$work/stream.ndjson" > "$work/gap.ndjson"
refuse "$work/gap.ndjson" "$work/ci.jwks" "an interior record removed" 1

python3 "$here/prepare.py" unsigned < "$work/stream.ndjson" > "$work/unsigned-stream.ndjson"
refuse "$work/unsigned-stream.ndjson" "$work/ci.jwks" "an unsigned decision stream" 1
python3 "$here/prepare.py" unsigned < "$work/sample.ndjson" > "$work/unsigned-sample.ndjson"
refuse "$work/unsigned-sample.ndjson" "$work/demo.jwks" "unsigned sample records" 1
: > "$work/empty.ndjson"
refuse "$work/empty.ndjson" "$work/ci.jwks" "an empty stream" 1
