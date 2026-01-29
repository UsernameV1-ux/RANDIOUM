#!/usr/bin/env sh
set -eu

DATADIR="${1:-./_tmp_perf}"
SEED="${2:-77}"
BLOCKS="${BLOCKS:-0}"
WORKLOAD="${WORKLOAD:-}"
PRESET="${PRESET:-perf}"

cmake -S . --preset "$PRESET"
cmake --build --preset "$PRESET"

EXE="${Moonrand_EXE:-}"
if [ -z "$EXE" ]; then
  if [ -f "./cmake-build-$PRESET/Moonrand.exe" ]; then
    EXE="./cmake-build-$PRESET/Moonrand.exe"
  else
    EXE="./cmake-build-$PRESET/Moonrand"
  fi
fi

mkdir -p "$DATADIR"

ARGS="bench all $DATADIR --seed $SEED"
if [ "$BLOCKS" != "0" ]; then
  ARGS="$ARGS --blocks $BLOCKS"
fi
if [ -n "$WORKLOAD" ]; then
  ARGS="$ARGS --workload $WORKLOAD"
fi

$EXE $ARGS

PERF_PATH="$DATADIR/logs/perf_report.json"
if [ ! -f "$PERF_PATH" ]; then
  echo "missing perf report: $PERF_PATH" 1>&2
  exit 1
fi
if [ ! -s "$PERF_PATH" ]; then
  echo "perf report is empty: $PERF_PATH" 1>&2
  exit 1
fi

echo "ok"
echo "perf_report=$PERF_PATH"
