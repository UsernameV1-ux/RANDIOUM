param(
  [Parameter(Mandatory=$true)][string]$Root,
  [Parameter(Mandatory=$true)][string]$Out
)

$ErrorActionPreference = 'Stop'

$appDir = Join-Path (Join-Path $Root 'grants') 'applications'
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null

$items = @()
if (Test-Path $appDir) {
  $files = Get-ChildItem -Path $appDir -Filter '*.json' | Sort-Object Name
  foreach ($f in $files) {
    $j = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json
    $items += [ordered]@{
      id = [string]$j.id
      status = [string]$j.status
      requested_total = [int64]$j.requested_total
    }
  }
}

$report = [ordered]@{
  schema = 1
  grants = $items
}

($report | ConvertTo-Json -Depth 10) | Out-File -FilePath $Out -Encoding utf8
Write-Output "wrote $Out"
