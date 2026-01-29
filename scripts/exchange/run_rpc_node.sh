#!/usr/bin/env sh
set -eu

DATADIR="$1"
MODE="${2:-full}"
ID="${3:-}"
TICKS_PER_LOOP="${4:-10}"
Moonrand_EXE="${Moonrand_EXE:-./Moonrand.exe}"

echo "Starting Moonrand node loop..."
echo "DataDir=$DATADIR Mode=$MODE Id=$ID TicksPerLoop=$TICKS_PER_LOOP"

while true; do
  if [ -n "$ID" ]; then
    "$Moonrand_EXE" run-node "$DATADIR" --mode "$MODE" --id "$ID" --ticks "$TICKS_PER_LOOP"
  else
    "$Moonrand_EXE" run-node "$DATADIR" --mode "$MODE" --ticks "$TICKS_PER_LOOP"
  fi
  sleep 0.25
done
