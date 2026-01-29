# Sample: RANDNFT Mint

## Goal

Deploy RANDNFT marker contract, mint an NFT, and query owner.

## Steps (CLI)

```sh
Moonrand init-data-dir ./nft_demo
Moonrand genesis-init ./nft_demo --max-supply 1000 --alloc owner:1000

Moonrand tx send-deploy ./nft_demo --from owner --fee 1 --gas 50000 --code-marker RANDNFT
Moonrand run-node ./nft_demo --mode full --ticks 1

# Mint NFT to alice
Moonrand tx send-call ./nft_demo --from owner --fee 1 --gas 50000 --contract <CONTRACT_HEX> --randnft-mint --to alice --meta "demo"
Moonrand run-node ./nft_demo --mode full --ticks 1

# Query owner
Moonrand query randnft-owner ./nft_demo --contract <CONTRACT_HEX> --token-id <TOKEN_ID>
```

## Expected outputs

- `query randnft-owner` prints `alice` (or a JSON containing owner id)
