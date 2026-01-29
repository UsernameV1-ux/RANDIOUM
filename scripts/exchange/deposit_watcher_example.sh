#!/usr/bin/env sh
set -eu

DATADIR="$1"
ACCOUNT_ID="$2"
POLL_MS="${3:-1000}"
Moonrand_EXE="${Moonrand_EXE:-./Moonrand.exe}"

echo "Watching deposits for id=$ACCOUNT_ID in data_dir=$DATADIR"

LAST_BAL=0
HAS_LAST=0

while true; do
  RAW="$($Moonrand_EXE rpc getAccount "$DATADIR" --id "$ACCOUNT_ID" || true)"

  if [ "$RAW" = "null" ] || [ -z "$RAW" ]; then
    BAL=0
    NONCE=0
  else
    BAL="$(printf "%s" "$RAW" | tr -d '\r' | sed -n 's/.*"balance"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')"
    NONCE="$(printf "%s" "$RAW" | tr -d '\r' | sed -n 's/.*"nonce"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')"
    [ -n "$BAL" ] || BAL=0
    [ -n "$NONCE" ] || NONCE=0
  fi

  if [ "$HAS_LAST" = "1" ] && [ "$BAL" -gt "$LAST_BAL" ]; then
    DELTA=$((BAL - LAST_BAL))
    echo "DEPOSIT DETECTED id=$ACCOUNT_ID delta=$DELTA new_balance=$BAL nonce=$NONCE"
  fi

  LAST_BAL="$BAL"
  HAS_LAST=1

  sleep "$(awk "BEGIN { printf \"%.3f\", $POLL_MS / 1000 }")"
done
