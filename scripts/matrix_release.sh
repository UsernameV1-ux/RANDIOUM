#!/usr/bin/env sh
set -eu

PRESET="${1:-release}"

cmake -S . --preset "$PRESET"
cmake --build --preset "$PRESET"
ctest --preset "$PRESET"

echo "ok"
