param(
  [string]$DataDir = (Join-Path (Get-Location) '_tmp_perf'),
  [UInt64]$Seed = 77,
  [UInt64]$Blocks = 0,
  [string]$Workload = '',
  [string]$Preset = 'perf',
  [string]$RandiumExe = ''
)

$ErrorActionPreference = 'Stop'

cmake -S . --preset $Preset
cmake --build --preset $Preset

$buildDir = Join-Path (Get-Location) ("cmake-build-$Preset")

if ($RandiumExe -eq '') {
  $cand1 = Join-Path $buildDir 'Moonrand.exe'
  $cand2 = Join-Path $buildDir 'Moonrand'
  if (Test-Path $cand1) { $RandiumExe = $cand1 }
  elseif (Test-Path $cand2) { $RandiumExe = $cand2 }
  else { throw "Moonrand executable not found in $buildDir" }
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$args = @('bench', 'all', $DataDir, '--seed', [string]$Seed)
if ($Blocks -ne 0) { $args += @('--blocks', [string]$Blocks) }
if ($Workload -ne '') { $args += @('--workload', $Workload) }

& $RandiumExe @args
if ($LASTEXITCODE -ne 0) {
  throw "bench all failed (exit=$LASTEXITCODE)"
}

$perfPath = Join-Path $DataDir 'logs' | Join-Path -ChildPath 'perf_report.json'
if (!(Test-Path $perfPath)) {
  throw "missing perf report: $perfPath"
}

$size = (Get-Item $perfPath).Length
if ($size -le 0) {
  throw "perf report is empty: $perfPath"
}

Write-Host "ok"
Write-Host "perf_report=$perfPath"
