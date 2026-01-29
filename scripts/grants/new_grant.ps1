param(
  [Parameter(Mandatory=$true)][string]$Root,
  [Parameter(Mandatory=$true)][string]$Id
)

$ErrorActionPreference = 'Stop'

$grantsDir = Join-Path $Root 'grants'
$appDir = Join-Path $grantsDir 'applications'
New-Item -ItemType Directory -Force -Path $appDir | Out-Null

$path = Join-Path $appDir ($Id + '.json')
if (Test-Path $path) {
  Write-Error "grant already exists: $path"
}

$template = @{
  id = $Id
  status = 'draft'
  applicant = @{
    name = ''
    contact = ''
    repo = ''
  }
  milestones = @()
  requested_total = 0
  notes = ''
}

$template | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding utf8
Write-Output "created $path"
