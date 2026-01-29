# Sample: RAND20 Token

## Goal

Deploy a RAND20 marker contract, mint tokens, transfer tokens, and query supply.

## Steps (CLI)

```sh
# 1) Init data dir
Moonrand init-data-dir ./token_demo

# 2) Genesis
Moonrand genesis-init ./token_demo --max-supply 1000 --alloc owner:1000

# 3) Deploy RAND20 marker
Moonrand tx send-deploy ./token_demo --from owner --fee 1 --gas 50000 --code-marker RAND20

# 4) Run 1 tick to include tx
Moonrand run-node ./token_demo --mode full --ticks 1

# 5) Mint 100 to alice (owner-only mint)
Moonrand tx send-call ./token_demo --from owner --fee 1 --gas 50000 --contract <CONTRACT_HEX> --rand20-mint --to alice --amount 100
Moonrand run-node ./token_demo --mode full --ticks 1

# 6) Transfer 1 from alice to bob
Moonrand tx send-call ./token_demo --from alice --fee 1 --gas 50000 --contract <CONTRACT_HEX> --rand20-transfer --to bob --amount 1
Moonrand run-node ./token_demo --mode full --ticks 1

# 7) Query supply
Moonrand query rand20-supply ./token_demo --contract <CONTRACT_HEX>
```

## Expected outputs

- `tx send-deploy` prints `contract=<64-hex>`
- `query rand20-supply` prints a non-null integer
