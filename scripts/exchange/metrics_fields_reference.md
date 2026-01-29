# metrics.json field reference (Moonrand)

`run-node` writes `logs/metrics.json`.

## Fields

All fields are unsigned integers.

- `ticks`
  - total ticks executed in the most recent `run-node` invocation

- `uptime_ticks`
  - cumulative ticks since the node started (within the process lifetime)

- `blocks_produced`
  - number of blocks committed

- `proposals`
  - count of proposal events (primarily relevant for validator mode)

- `votes`
  - count of vote events (primarily relevant for validator mode)

- `slashes`
  - count of slashing events

- `rewards_minted`
  - total rewards minted

- `tx_applied`
  - total transactions applied

- `tx_aborted`
  - total transactions aborted

## Example command

```sh
Moonrand.exe run-node <data_dir> --mode full --ticks 10
```

Example output path:
- `<data_dir>/logs/metrics.json`
