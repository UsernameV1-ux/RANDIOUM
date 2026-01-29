#!/usr/bin/env sh
set -eu

DATA_DIR="${1:-}"
OWNER="${2:-}"

if [ -z "$DATA_DIR" ] || [ -z "$OWNER" ]; then
  echo "usage: $0 <data_dir> <owner>" >&2
  exit 2
fi

Moonrand tx send-deploy "$DATA_DIR" --from "$OWNER" --fee 1 --gas 50000 --code-marker AMM119
