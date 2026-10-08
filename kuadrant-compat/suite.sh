#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
#
# Smoke-test host request metadata across Authorino and PPE; not value parity.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY="${SCRIPT_DIR}/cases/cel-req-id.ppe.yaml"
AUTH_POLICY="${SCRIPT_DIR}/cases/cel-req-id.authpolicy.yaml"
AUTH_DENY_POLICY="${SCRIPT_DIR}/cases/cel-req-id-deny.authpolicy.yaml"
AUTH_ALLOW_MARKER="authorino-allow-request-id"
AUTH_DENY_MARKER="authorino-deny-control"
EXPECTED="${SCRIPT_DIR}/cases/cel-req-id.expected"
ACTIVE="${SCRIPT_DIR}/policy-active.yaml"
PRAXIS_AI_DIR="${PRAXIS_AI_DIR:-${HOME}/projects/src/github.com/praxis-proxy/ai}"
BIN="${PRAXIS_AI_DIR}/target/release/praxis-ai"
PPE_LOG="$(mktemp -t praxis-req-id.XXXXXX)"
PPE_PID=""
AUTH_APPLIED=""

stop_ppe() {
  if [ -n "$PPE_PID" ]; then
    kill "$PPE_PID" 2>/dev/null || true
    wait "$PPE_PID" 2>/dev/null || true
    PPE_PID=""
  fi
}

cleanup() {
  local status=$?
  stop_ppe
  if [ -n "$AUTH_APPLIED" ]; then
    kubectl delete -f "$AUTH_POLICY" --ignore-not-found >/dev/null 2>&1 || true
  fi
  rm -f "$ACTIVE"
  if [ "$status" -ne 0 ] && [ -s "$PPE_LOG" ]; then
    echo "PPE startup log: $PPE_LOG" >&2
  else
    rm -f "$PPE_LOG"
  fi
}
trap cleanup EXIT

die() { echo "ERROR: $*" >&2; exit 1; }

decision() {
  case "$1" in
    200) echo allow ;;
    403) echo deny ;;
    000) echo noconn ;;
    *) echo "http$1" ;;
  esac
}

fire() { # url host request-id -> HTTP status
  local url="$1" host="$2" request_id="$3"
  if [ -n "$host" ]; then
    curl -q -s -o /dev/null -m 5 -w '%{http_code}' -H "Host: $host" \
      -H "x-request-id: $request_id" "$url" || true
  else
    curl -q -s -o /dev/null -m 5 -w '%{http_code}' \
      -H "x-request-id: $request_id" "$url" || true
  fi
}

AUTHORINO_RESPONSE=""
AUTHORINO_STATUS="000"

fire_authorino() { # request-id -> response headers/body and HTTP status
  local request_id="$1" output
  output="$(curl -q -sS -i -m 5 -w $'\n__KUADRANT_STATUS__:%{http_code}\n' \
    -H "Host: api.toystore.com" -H "x-request-id: $request_id" \
    "http://${GW}/toys" || true)"
  AUTHORINO_STATUS="$(printf '%s\n' "$output" \
    | sed -n 's/^__KUADRANT_STATUS__://p' | tail -1)"
  AUTHORINO_RESPONSE="$output"
  [ -n "$AUTHORINO_STATUS" ] || AUTHORINO_STATUS="000"
}

authorino_has_marker() {
  grep -Fq -- "$1" <<< "$AUTHORINO_RESPONSE"
}

wait_authorino() { # expected-status expected-marker phase
  local expected="$1" marker="$2" phase="$3" attempt request_id all_match
  for ((attempt = 0; attempt < 30; attempt++)); do
    all_match=1
    for request_id in "${ids[@]}"; do
      fire_authorino "$request_id"
      if [ "$AUTHORINO_STATUS" != "$expected" ] || ! authorino_has_marker "$marker"; then
        all_match=0
        break
      fi
    done
    if [ "$all_match" -eq 1 ]; then return 0; fi
    sleep 1
  done
  die "$phase did not return HTTP $expected with marker '$marker' for every client header (gateway propagation timed out)"
}

start_ppe() { # kuadrant_compat: false|true
  local compat="$1" started=$SECONDS status
  if [ "$compat" = true ]; then
    sed 's/^  kuadrant_compat: false$/  kuadrant_compat: true/' "$POLICY" > "$ACTIVE"
  else
    cp "$POLICY" "$ACTIVE"
  fi
  ( cd "$SCRIPT_DIR" && exec "$BIN" -c "${SCRIPT_DIR}/praxis.yaml" ) >"$PPE_LOG" 2>&1 &
  PPE_PID=$!
  while [ $((SECONDS - started)) -lt 60 ]; do
    if ! kill -0 "$PPE_PID" 2>/dev/null; then
      tail -30 "$PPE_LOG" >&2
      die "PPE exited before listening (kuadrant_compat=$compat)"
    fi
    status="$(fire http://127.0.0.1:8095/ "" req-abc)"
    if [ "$status" != 000 ]; then return 0; fi
    sleep 0.2
  done
  tail -30 "$PPE_LOG" >&2
  die "PPE did not start listening (kuadrant_compat=$compat)"
}

[ -x "$BIN" ] || die "praxis-ai not found at $BIN (see SETUP.md)"
[ "$(grep -cx '  kuadrant_compat: false' "$POLICY")" -eq 1 ] \
  || die "PPE policy must contain one kuadrant_compat: false line"
curl -q -s -o /dev/null -m 3 http://127.0.0.1:9200/anything \
  || die "httpbin is not reachable on 127.0.0.1:9200"
kubectl cluster-info >/dev/null 2>&1 || die "kubectl cannot reach the testbed cluster"
if lsof -ti tcp:8095 >/dev/null 2>&1; then die "PPE port 8095 is in use"; fi
GW="$(kubectl get gateway external -n api-gateway -o jsonpath='{.status.addresses[0].value}')"
[ -n "$GW" ] || die "gateway api-gateway/external has no address"

ids=()
wants=()
while read -r request_id expected _; do
  [ -z "$request_id" ] && continue
  case "$request_id" in \#*) continue ;; esac
  ids+=("$request_id")
  wants+=("$expected")
done < "$EXPECTED"
[ "${#ids[@]}" -gt 0 ] || die "no expected decisions in $EXPECTED"

echo "gateway: $GW"
echo "Smoke test only: actual Authorino values and value parity remain unverified."
AUTH_APPLIED=1
kubectl apply -f "$AUTH_DENY_POLICY" >/dev/null
kubectl wait --for=condition=Enforced authpolicy/cel-req-id -n toystore --timeout=60s >/dev/null
# A client header equal to req-abc must not satisfy request.id == 'req-abc':
# Envoy supplies independent stream metadata. Require actual denials before
# accepting any allow result, so a gateway bypassing authorization cannot pass.
wait_authorino 403 "$AUTH_DENY_MARKER" "Authorino deny control"
echo "Authorino deny control: PASS (both requests denied with the AuthConfig marker)"

kubectl apply -f "$AUTH_POLICY" >/dev/null
kubectl wait --for=condition=Enforced authpolicy/cel-req-id -n toystore --timeout=60s >/dev/null
# The condition may precede data-plane propagation. Wait for the same resource
# to switch from the observed deny policy to the original allow policy.
wait_authorino 200 "$AUTH_ALLOW_MARKER" "Authorino allow policy"

authorino=()
for i in "${!ids[@]}"; do
  fire_authorino "${ids[$i]}"
  authorino+=("$(decision "$AUTHORINO_STATUS")")
  authorino_has_marker "$AUTH_ALLOW_MARKER" \
    || die "Authorino allow response lost marker '$AUTH_ALLOW_MARKER'"
done
kubectl delete -f "$AUTH_POLICY" --ignore-not-found >/dev/null
AUTH_APPLIED=""

start_ppe false
off=()
for i in "${!ids[@]}"; do
  off+=("$(decision "$(fire http://127.0.0.1:8095/anything "" "${ids[$i]}")")")
done
stop_ppe

start_ppe true
on=()
for i in "${!ids[@]}"; do
  on+=("$(decision "$(fire http://127.0.0.1:8095/anything "" "${ids[$i]}")")")
done
stop_ppe

echo
printf '%-15s %-10s %-11s %-9s %-7s\n' CLIENT-HEADER EXPECTED AUTHORINO FLAG-OFF FLAG-ON
fail=0
for i in "${!ids[@]}"; do
  printf '%-15s %-10s %-11s %-9s %-7s\n' \
    "${ids[$i]}" "${wants[$i]}" "${authorino[$i]}" "${off[$i]}" "${on[$i]}"
  [ "${authorino[$i]}" = "${wants[$i]}" ] || fail=1
  [ "${off[$i]}" = deny ] || fail=1
  [ "${on[$i]}" = "${wants[$i]}" ] || fail=1
done
echo
[ "$fail" -eq 0 ] || die "request.id smoke test failed; PPE requires a host-owned RequestExtension.request_id (see SETUP.md)"
echo "PASS: host request.id presence smoke test; value parity remains unverified"
