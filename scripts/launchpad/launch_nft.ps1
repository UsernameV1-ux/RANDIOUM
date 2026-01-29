param(
  [Parameter(Mandatory=$true)][string]$DataDir,
  [Parameter(Mandatory=$true)][string]$Owner
)

$ErrorActionPreference = 'Stop'

# Deterministic NFT launch: deploy RANDNFT marker.
& Moonrand tx send-deploy $DataDir --from $Owner --fee 1 --gas 50000 --code-marker RANDNFT
