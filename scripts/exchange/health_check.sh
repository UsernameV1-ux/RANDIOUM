#!/usr/bin/env sh
set -eu

DATADIR="$1"
Moonrand_EXE="${Moonrand_EXE:-./Moonrand.exe}"

HEALTH="$($Moonrand_EXE health "$DATADIR")"
READY="$($Moonrand_EXE readiness "$DATADIR")"

echo "health: $HEALTH"
echo "readiness: $READY"

case "${HEALTH}${READY}" in
  *fail*|*error*|*bad*)
    echo "health_check: failure" 1>&2
    exit 1
    ;;
esac
