# Quickstart (Deterministic Devnet)

This quickstart uses the deterministic CLI and does not require live servers.

## Create a devnet

```sh
Moonrand devnet init ./devnet --validators 2 --network devnet --max-supply 1000 --balance-per-validator 100
Moonrand devnet spin-up ./devnet --ticks 1
```

Expected outputs:

- `./devnet/genesis.json` exists
- `./devnet/rpc/status.json` exists
- `./devnet/explorer/index.json` exists
