# Sample: AMM119

## Goal

Deploy AMM119 marker contract and create a pool + add liquidity.

## Steps (CLI)

```sh
Moonrand init-data-dir ./amm_demo
Moonrand genesis-init ./amm_demo --max-supply 2000 --alloc owner:2000

# Deploy RAND20 tokens used as pool assets (token0/token1)
Moonrand tx send-deploy ./amm_demo --from owner --fee 1 --gas 50000 --code-marker RAND20
Moonrand run-node ./amm_demo --mode full --ticks 1
# Repeat deploy for a second token
Moonrand tx send-deploy ./amm_demo --from owner --fee 1 --gas 50000 --code-marker RAND20
Moonrand run-node ./amm_demo --mode full --ticks 1

# Deploy AMM119
Moonrand tx send-deploy ./amm_demo --from owner --fee 1 --gas 50000 --code-marker AMM119
Moonrand run-node ./amm_demo --mode full --ticks 1

# Create pool + add liquidity require input bytes (see module119 AMM docs/contract definition).
```

## Expected outputs

- AMM deploy prints `contract=<64-hex>`
