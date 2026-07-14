# Recovery benchmarks

Run the deterministic comparison with:

```bash
poetry run python benchmarks/benchmark_recovery.py
```

The instrumented in-memory mint counts:

- restore and state-check network calls;
- total and unique blinded messages sent to NUT-09;
- total and unique proofs sent to NUT-07;
- blind signatures returned, including duplicates from overlapping probes; and
- local algorithm runtime, excluding real network latency.

## Baseline run

The baseline uses a restore batch and binary probe window of 25, two terminal
empty batches for legacy recovery, `d_gap=100`, and one synthetic skipped
derivation every 137 counters.

| Method | T | Calls | Blinded messages | Unique blinded | Proofs checked | Signatures returned |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy | 100 | 12 | 175 | 175 | 101 | 101 |
| Efficient | 100 | 32 | 851 | 750 | 101 | 178 |
| Legacy | 1,000 | 84 | 1,075 | 1,075 | 994 | 994 |
| Efficient | 1,000 | 31 | 826 | 800 | 100 | 127 |
| Legacy | 10,000 | 804 | 10,075 | 10,075 | 9,929 | 9,929 |
| Efficient | 10,000 | 31 | 826 | 775 | 101 | 228 |
| Legacy | 100,000 | 8,004 | 100,075 | 100,075 | 99,272 | 99,272 |
| Efficient | 100,000 | 32 | 851 | 750 | 101 | 303 |

These are algorithm and disclosure measurements, not real-network latency
benchmarks. End-to-end recovery time will be dominated by sequential network
round trips, so the network-call count is the useful latency proxy.

For alternate histories and parameters:

```bash
poetry run python benchmarks/benchmark_recovery.py \
  --histories 500,5000,50000 \
  --d-gap 200 \
  --batch-size 50 \
  --gap-every 211
```
