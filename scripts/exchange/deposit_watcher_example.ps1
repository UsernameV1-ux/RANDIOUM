param(
  [Parameter(Mandatory=$true)][string]$DataDir,
  [Parameter(Mandatory=$true)][string]$AccountId,
  [int]$PollMs = 1000,
  [string]$RandiumExe = 'Moonrand.exe'
)

$ErrorActionPreference = 'Stop'

Write-Host "Watching deposits for id=$AccountId in data_dir=$DataDir"

$lastBalance = $null

while ($true) {
  $raw = & $RandiumExe 'rpc' 'getAccount' $DataDir '--id' $AccountId
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "rpc getAccount failed"
    Start-Sleep -Milliseconds $PollMs
    continue
  }

  if ($raw -eq 'null') {
    $balance = 0
    $nonce = 0
  } else {
    $obj = $raw | ConvertFrom-Json
    $balance = [uint64]$obj.balance
    $nonce = [uint64]$obj.nonce
  }

  if ($lastBalance -ne $null -and $balance -gt $lastBalance) {
    $delta = $balance - $lastBalance
    Write-Host "DEPOSIT DETECTED id=$AccountId delta=$delta new_balance=$balance nonce=$nonce"
  }

  $lastBalance = $balance
  Start-Sleep -Milliseconds $PollMs
}
