param(
  [Parameter(Mandatory=$true)][string]$DataDir,
  [Parameter(Mandatory=$true)][string]$Owner
)

$ErrorActionPreference = 'Stop'

# Deterministic AMM bootstrap: deploy AMM119 marker.
& Moonrand tx send-deploy $DataDir --from $Owner --fee 1 --gas 50000 --code-marker AMM119
