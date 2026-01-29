#!/usr/bin/env sh
set -eu

ROOT="${1:-}"
ID="${2:-}"

if [ -z "$ROOT" ] || [ -z "$ID" ]; then
  echo "usage: $0 <root> <id>" >&2
  exit 2
fi

grants_dir="$ROOT/grants"
app_dir="$grants_dir/applications"
mkdir -p "$app_dir"

path="$app_dir/$ID.json"
if [ -f "$path" ]; then
  echo "grant already exists: $path" >&2
  exit 1
fi

cat > "$path" <<'JSON'
{
  "id": "",
  "status": "draft",
  "applicant": {
    "name": "",
    "contact": "",
    "repo": ""
  },
  "milestones": [],
  "requested_total": 0,
  "notes": ""
}
JSON

# Inject id deterministically without timestamps.
# Portable: replace first occurrence of "id": "" with "id": "<ID>"
# shellcheck disable=SC2001
sed -i"" -e "0,/\"id\": \"\"/s//\"id\": \"$ID\"/" "$path" 2>/dev/null || true

# If sed -i differs (busybox/gnu), fall back to rewrite.
if ! grep -q "\"id\": \"$ID\"" "$path"; then
  tmp="$path.tmp"
  awk -v id="$ID" 'BEGIN{done=0} { if(!done && $0 ~ /"id": ""/){ sub(/"id": ""/, "\"id\": \"" id "\""); done=1 } print }' "$path" > "$tmp"
  mv "$tmp" "$path"
fi

echo "created $path"
