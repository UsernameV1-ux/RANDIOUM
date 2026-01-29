param(
  [Parameter(Mandatory=$true)][string]$DataDir,
  [ValidateSet('full','archive','validator')][string]$Mode = 'full',
  [string]$Id = '',
  [int]$TicksPerLoop = 10,
  [string]$RandiumExe = 'Moonrand.exe'
)

$ErrorActionPreference = 'Stop'

Write-Host "Starting Moonrand node loop..."
Write-Host "DataDir=$DataDir Mode=$Mode Id=$Id TicksPerLoop=$TicksPerLoop"

while ($true) {
  $args = @('run-node', $DataDir, '--mode', $Mode, '--ticks', [string]$TicksPerLoop)
  if ($Id -ne '') {
    $args = @('run-node', $DataDir, '--mode', $Mode, '--id', $Id, '--ticks', [string]$TicksPerLoop)
  }

  & $RandiumExe @args
  if ($LASTEXITCODE -ne 0) {
    throw "run-node failed (exit=$LASTEXITCODE)"
  }

  Start-Sleep -Milliseconds 250
}
