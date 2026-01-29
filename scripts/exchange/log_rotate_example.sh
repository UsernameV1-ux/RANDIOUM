#!/usr/bin/env sh
set -eu

LOGDIR="$1"
MAXFILES="${2:-10}"

SRC="$LOGDIR/node.jsonl"

if [ ! -f "$SRC" ]; then
  echo "No node.jsonl found at $SRC"
  exit 0
fi

i="$MAXFILES"
while [ "$i" -ge 1 ]; do
  FROM="$SRC.$i"
  TO="$SRC.$((i+1))"
  if [ -f "$FROM" ]; then
    mv -f "$FROM" "$TO"
  fi
  i=$((i-1))
done

mv -f "$SRC" "$SRC.1"
echo "Rotated $SRC -> $SRC.1"
