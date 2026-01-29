param(
  [string]$Preset = 'debug'
)

$ErrorActionPreference = 'Stop'

cmake -S . --preset $Preset
cmake --build --preset $Preset
ctest --preset $Preset
if ($LASTEXITCODE -ne 0) {
  throw "ctest failed (exit=$LASTEXITCODE)"
}

Write-Host "ok"
