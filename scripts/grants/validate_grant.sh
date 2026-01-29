#!/usr/bin/env sh
set -eu

PATH_IN="${1:-}"
if [ -z "$PATH_IN" ]; then
  echo "usage: $0 <grant.json>" >&2
  exit 2
fi

if [ ! -f "$PATH_IN" ]; then
  echo "missing: $PATH_IN" >&2
  exit 1
fi

# Minimal validation without external deps.
# Deterministic checks: required keys must exist.
req='"id"' ; grep -q "$req" "$PATH_IN" || { echo "missing id" >&2; exit 1; }
req='"status"' ; grep -q "$req" "$PATH_IN" || { echo "missing status" >&2; exit 1; }
req='"applicant"' ; grep -q "$req" "$PATH_IN" || { echo "missing applicant" >&2; exit 1; }
req='"milestones"' ; grep -q "$req" "$PATH_IN" || { echo "missing milestones" >&2; exit 1; }
req='"requested_total"' ; grep -q "$req" "$PATH_IN" || { echo "missing requested_total" >&2; exit 1; }

echo ok
