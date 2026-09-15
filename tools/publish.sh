#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
#
# Publish every publishable workspace crate to crates.io, in dependency order,
# pacing around the registry's rate limit and skipping anything already up.
#
# Why this exists rather than a bare `cargo publish --workspace`:
#
#   crates.io limits *new* crate publishes to a burst of 5 and one per 10 minutes
#   thereafter. A first release of 13 new crates therefore cannot complete in one
#   pass, and a version, once uploaded, cannot be deleted — only yanked. So the
#   failure mode of the bare command is a permanently half-published release with
#   the tag already consumed.
#
#   This script is idempotent instead. A crate whose version is already on
#   crates.io is skipped, so an interrupted run is resumed by running it again,
#   and a manual publish followed by a tag push does not collide.
#
# Usage:
#   CARGO_REGISTRY_TOKEN=... tools/publish.sh            # publish
#   tools/publish.sh --dry-run                           # print the plan only
#
# Requires: a token, either in CARGO_REGISTRY_TOKEN or via `cargo login`.

set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

# Seconds to wait after a rate-limit rejection. The registry refills one new-crate
# token every 10 minutes; the extra 30s keeps us clear of the boundary.
BACKOFF="${PUBLISH_BACKOFF:-630}"
# How many times to wait out the limit for a single crate before giving up.
MAX_TRIES="${PUBLISH_MAX_TRIES:-8}"

# Dependency order. Every crate here must publish after everything it depends on,
# because crates.io rejects a version whose dependencies it cannot resolve.
#
# Taken from cargo's own resolution: `cargo publish --workspace --dry-run` prints
# these in exactly this sequence. The set is cross-checked against the workspace
# below, so adding or removing a crate fails loudly rather than being skipped.
ORDER=(
  praxis-policy-orchestration
  praxis-policy-apl-core
  praxis-policy-core
  praxis-policy-apl-cmf
  praxis-policy-plugin-delegator-oauth
  praxis-policy-plugin-elicitation-ciba
  praxis-policy-plugin-identity-jwt
  praxis-policy-apl-runtime
  praxis-policy-pdp-cedar-direct
  praxis-policy-pdp-cel
  praxis-policy-pdp-opa
  praxis-policy-session-valkey
  praxis-policy-secrets-vault
  praxis-policy
)

VERSION="$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"

# Guard: the hardcoded order must match what the workspace actually publishes, or
# a new crate would be silently left behind.
PUBLISHABLE="$(cargo metadata --no-deps --format-version 1 \
  | python3 -c '
import json,sys
for p in json.load(sys.stdin)["packages"]:
    # publish == None means unrestricted; [] means publish = false.
    if p.get("publish") != []:
        print(p["name"])
' | sort | tr "\n" " ")"
ORDERED_SORTED="$(printf '%s\n' "${ORDER[@]}" | sort | tr "\n" " ")"
if [ "$PUBLISHABLE" != "$ORDERED_SORTED" ]; then
  echo "error: the publish order in $0 does not match the workspace." >&2
  echo "  workspace publishable: $PUBLISHABLE" >&2
  echo "  listed in ORDER:       $ORDERED_SORTED" >&2
  echo "  Update ORDER (dependency order) and re-run." >&2
  exit 1
fi

# Strip the token from anything this script prints. cargo redacts its own output,
# so this is belt-and-braces against a future tool that does not.
scrub() {
  if [ -n "${CARGO_REGISTRY_TOKEN:-}" ]; then
    sed "s|${CARGO_REGISTRY_TOKEN}|<redacted>|g"
  else
    cat
  fi
}

# Already on crates.io at this version?
published() {
  local name="$1" code
  code="$(curl -s -o /tmp/publish-check.json -w '%{http_code}' \
    -A "praxis-policy-publish/${VERSION}" \
    "https://crates.io/api/v1/crates/${name}/${VERSION}" || echo 000)"
  [ "$code" = "200" ]
}

echo "publishing ${#ORDER[@]} crates at version ${VERSION}"
[ "$DRY_RUN" = "1" ] && echo "(dry run: nothing will be uploaded)"
echo

for name in "${ORDER[@]}"; do
  if published "$name"; then
    echo "== ${name} ${VERSION}: already published, skipping"
    continue
  fi

  if [ "$DRY_RUN" = "1" ]; then
    echo "== ${name} ${VERSION}: would publish"
    continue
  fi

  try=1
  while :; do
    echo "== ${name} ${VERSION}: publishing (attempt ${try}/${MAX_TRIES})"
    if out="$(cargo publish -p "$name" --locked 2>&1)"; then
      echo "   published"
      break
    fi
    echo "$out" | scrub | sed 's/^/   | /'

    # Someone else's run, or a retry after a partial success, got there first.
    if echo "$out" | grep -qiE "already (been )?uploaded|crate version .* is already"; then
      echo "   already on the registry, treating as done"
      break
    fi
    # Rate limited: wait out the refill and try the same crate again.
    if echo "$out" | grep -qiE "too many|rate limit|429"; then
      if [ "$try" -ge "$MAX_TRIES" ]; then
        echo "error: ${name} still rate limited after ${MAX_TRIES} attempts." >&2
        echo "  Re-run this script later; published crates are skipped." >&2
        exit 1
      fi
      echo "   rate limited; waiting ${BACKOFF}s for the registry to refill"
      sleep "$BACKOFF"
      try=$((try + 1))
      continue
    fi
    # Anything else is a real failure. Stop rather than corrupt the order.
    echo "error: ${name} failed to publish for a reason that is not a rate limit." >&2
    echo "  Fix it, then re-run; crates already up are skipped." >&2
    exit 1
  done
done

echo
if [ "$DRY_RUN" = "1" ]; then
  echo "dry run complete: nothing was uploaded"
else
  echo "all ${#ORDER[@]} crates are published at ${VERSION}"
fi
