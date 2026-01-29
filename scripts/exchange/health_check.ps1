param(
  [Parameter(Mandatory=$true)][string]$DataDir,
  [string]$RandiumExe = 'Moonrand.exe'
)

$ErrorActionPreference = 'Stop'

$health = & $RandiumExe 'health' $DataDir
if ($LASTEXITCODE -ne 0) {
  throw "health failed"
}

$ready = & $RandiumExe 'readiness' $DataDir
if ($LASTEXITCODE -ne 0) {
  throw "readiness failed"
}

Write-Host "health: $health"
Write-Host "readiness: $ready"

# Optional: fail fast on common unhealthy strings.
if ($health -match 'fail|error|bad') {
  throw "health indicates failure"
}
if ($ready -match 'fail|error|bad') {
  throw "readiness indicates failure"
}
