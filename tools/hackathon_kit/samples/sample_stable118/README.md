# Sample: STABLE118

## Goal

Deploy STABLE118 marker contract and demonstrate a minimal end-to-end flow.

## Steps (CLI)

```sh
Moonrand init-data-dir ./stable_demo
Moonrand genesis-init ./stable_demo --max-supply 3000 --alloc owner:1000 --alloc alice:1000 --alloc bob:1000

Moonrand tx send-deploy ./stable_demo --from owner --fee 1 --gas 50000 --code-marker STABLE118
Moonrand run-node ./stable_demo --mode full --ticks 1

# Configure / deposit / mint actions depend on contract inputs.
# See docs/module118_stablecoin_rails.md for reference flows.
```

## Expected outputs

- `tx send-deploy` prints `contract=<64-hex>`
