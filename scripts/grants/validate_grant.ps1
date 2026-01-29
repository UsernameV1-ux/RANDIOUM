param(
  [Parameter(Mandatory=$true)][string]$Path
)

$ErrorActionPreference = 'Stop'

if (!(Test-Path $Path)) {
  Write-Error "missing: $Path"
}

$j = Get-Content -Raw -Path $Path | ConvertFrom-Json

if ([string]::IsNullOrWhiteSpace($j.id)) { Write-Error 'missing id' }
if ([string]::IsNullOrWhiteSpace($j.status)) { Write-Error 'missing status' }
if ($null -eq $j.applicant) { Write-Error 'missing applicant' }
if ($null -eq $j.milestones) { Write-Error 'missing milestones' }
if ($j.requested_total -lt 0) { Write-Error 'requested_total must be >= 0' }

Write-Output 'ok'
