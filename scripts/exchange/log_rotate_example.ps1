param(
  [Parameter(Mandatory=$true)][string]$LogDir,
  [int]$MaxFiles = 10
)

$ErrorActionPreference = 'Stop'

# Minimal example: rotate node.jsonl by renaming to node.jsonl.<N>
$src = Join-Path $LogDir 'node.jsonl'
if (!(Test-Path $src)) {
  Write-Host "No node.jsonl found at $src"
  exit 0
}

for ($i = $MaxFiles; $i -ge 1; $i--) {
  $from = "$src.$i"
  $to = "$src." + ($i + 1)
  if (Test-Path $from) {
    Move-Item -Force $from $to
  }
}

Move-Item -Force $src "$src.1"
Write-Host "Rotated $src -> $src.1"
