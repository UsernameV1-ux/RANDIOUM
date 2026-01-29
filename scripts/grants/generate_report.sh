#!/usr/bin/env sh
set -eu

ROOT="${1:-}"
OUT="${2:-}"

if [ -z "$ROOT" ] || [ -z "$OUT" ]; then
  echo "usage: $0 <root> <out.json>" >&2
  exit 2
fi

app_dir="$ROOT/grants/applications"
mkdir -p "$(dirname "$OUT")"

# Deterministic minimal JSON writer with stable ordering.
# Grants are emitted sorted by filename.
{
  echo '{'
  echo '  "schema": 1,'
  echo '  "grants": ['

  if [ -d "$app_dir" ]; then
    first=1
    for f in $(ls -1 "$app_dir"/*.json 2>/dev/null | LC_ALL=C sort || true); do
      id=$(grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" | head -n1 | sed 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
      st=$(grep -o '"status"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" | head -n1 | sed 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
      rt=$(grep -o '"requested_total"[[:space:]]*:[[:space:]]*[0-9][0-9]*' "$f" | head -n1 | sed 's/.*"requested_total"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/')
      [ -z "$rt" ] && rt=0

      if [ "$first" -eq 0 ]; then
        echo '    ,'
      fi
      first=0
      echo '    {'
      echo "      \"id\": \"$id\","
      echo "      \"status\": \"$st\","
      echo "      \"requested_total\": $rt"
      echo '    }'
    done
  fi

  echo '  ]'
  echo '}'
} > "$OUT"

echo "wrote $OUT"
