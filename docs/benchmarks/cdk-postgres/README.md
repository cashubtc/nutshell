# CDK wallets against one multi-worker Nutshell mint

## Results

Each throughput figure counts successful CDK wallet operations per second across the two trials. Latency is the 95th percentile of successful operations. Each revision received the same number of attempts in each row.

| Wallets | Operation | Attempts per revision | Main successes | PR successes | Main ops/s | PR ops/s | Main p95 (ms) | PR p95 (ms) |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | Mint | 64 | 64 | 64 | 15.64 | 15.02 | 71.0 | 78.6 |
| 1 | Swap | 64 | 64 | 64 | 23.35 | 23.09 | 48.9 | 59.7 |
| 1 | Melt | 64 | 64 | 64 | 6.04 | 5.97 | 317.3 | 305.9 |
| 8 | Mint | 128 | 128 | 128 | 46.16 | 56.27 | 256.9 | 220.6 |
| 8 | Swap | 128 | 109 | 128 | 17.33 | 77.51 | 368.1 | 150.6 |
| 8 | Melt | 128 | 121 | 128 | 16.8 | 31.04 | 861.4 | 359.3 |
| 32 | Mint | 512 | 512 | 512 | 102.27 | 105.84 | 606.0 | 467.2 |
| 32 | Swap | 512 | 269 | 512 | 19.19 | 141.81 | 766.5 | 279.9 |
| 32 | Melt | 512 | 315 | 512 | 21.94 | 51.38 | 1055.7 | 828.6 |
| 64 | Mint | 1024 | 1023 | 1024 | 115.57 | 115.42 | 755.7 | 916.3 |
| 64 | Swap | 1024 | 320 | 1024 | 19.16 | 150.46 | 774.5 | 1012.6 |
| 64 | Melt | 1024 | 377 | 1024 | 20.7 | 53.57 | 1201.8 | 1573.7 |

At 64 wallets, the PR completed 7.9 times as many swaps per second as the base. Throughput varied from 149.24 to 151.7 successful swaps/s between PR trials and from 18.54 to 19.78 on main. Main returned lock-acquisition errors for 704 of the 1,024 swap attempts at this concurrency. Including failures, swap p95 was 1159.9 ms on main and 1012.6 ms on the PR.

Across all four concurrency levels, the PR completed all 5,184 measured operations. On main, CDK recorded 966 database-lock errors during swaps, 851 failed payments during melts, and one mint quote state error. The two main databases ended with 851 unpaid melt quotes in total. All four databases ended with zero pending proofs, and every wallet warmed up successfully on the first attempt.

With one wallet, median eight-proof swap latency was 42.8 ms on main and 41.4 ms on the PR. Mint-worker CPU per swap was 31.9 ms and 31.7 ms, respectively. The single-wallet cell has 64 observations per revision on a shared host, so small differences carry substantial uncertainty.

The summary includes run-to-run throughput ranges, failure counts, all-attempt p95, and worker CPU. The compressed JSONL files contain individual samples in trial order. [Summary CSV](summary.csv) · [PR trial 1](head-1.jsonl.gz) · [Main trial 1](main-1.jsonl.gz) · [Main trial 2](main-2.jsonl.gz) · [PR trial 2](head-2.jsonl.gz)

## Method

On November 19, 2026, the benchmark compared the head of PR #1271 (`6e09a3bb`) with its merge base on `main` (`d0389306`). Both revisions include background keyset accounting. Each trial starts one Uvicorn supervisor, one listening socket and 16 worker processes sharing a fresh PostgreSQL instance. The runner verifies that all workers finished startup and that the same worker PIDs survive each measurement.

The host was an Intel Core Ultra 9 185H with 16 physical cores, 22 logical CPUs and 30 GiB RAM. The kernel was Linux 7.0.0-43-generic with the powersave governor. Uvicorn 0.31.1 ran on CPython 3.10.22. The PostgreSQL 16.16 container used its ordinary data volume and durability settings, with `max_connections=256`. CDK 0.18.3 was built with rustc 1.101.0-nightly (3e92e1a2d) and ran in release mode with four Tokio runtime threads and a separate in-memory SQLite wallet and random seed for each client. The mint, PostgreSQL, and wallets shared the host. All traffic used loopback.

Wallets were prepared one at a time and completed one warmup operation before timing. Preparation could start again with a fresh wallet up to twice. The raw records include those setup errors. The driver then released the wallets together. A wallet started its next operation as soon as the preceding one returned. The four concurrency levels were 1, 8, 32, and 64 wallets with 32, 8, 8, and 8 measured operations per wallet, respectively. This is a closed-loop concurrency sweep. It measures completed wallet operations per second under those conditions. Wallet setup, prefunding, invoice generation and warmup are outside the timed interval. The two trials for each revision ran in PR, main, main, PR order.

| Workload | One timed CDK wallet operation |
|---|---|
| Mint | Request an 8-sat BOLT11 quote, check its status, issue eight 1-sat proofs and verify their amounts. |
| Swap | Swap eight distinct, prefunded 1-sat proofs for eight fresh 1-sat proofs. Each operation has its own inputs. After timing, each fully successful wallet verifies its balance and denominations. |
| Melt | Quote a unique external 16-sat test invoice, spend one prefunded 32-sat proof, and finalize the payment. The wallet checks the paid state, payment proof, and that payment plus fee plus change equals 32 sats. |

Both revisions used FakeWallet with immediate incoming and outgoing payments, zero input fees, and the normal accounting interval. CDK's HTTP request pacing and the mint's IP rate limit were disabled for this local load test. CDK requested asynchronous melts and reconciled pending payments through its HTTP recovery API, checking again after 50 ms if necessary. The driver counted only settled, validated melts. Each measured operation had a 30-second deadline.

Preflight runs determined those settings. CDK's default HTTP token bucket refills at 20 requests per minute. The first single-wallet issuance run reached the three-second spacing between successive HTTP requests. In another preflight, the ordinary CDK melt confirmation kept a WebSocket open while PostgreSQL already recorded the payment as paid. Nutshell's event clients are local to each worker. A parallel warmup also encountered a table-lock error on main. All reported trials use serial setup and concurrent measurement. Pilot samples are excluded.

Successful throughput is the number of validated successes divided by the sum of the two measured wall-clock intervals. The interval includes failed attempts and the time until the last wallet finishes. Latency runs from CDK call initiation through validation. Percentiles use nearest rank. Mint CPU sums user and system CPU time for all Uvicorn workers and excludes PostgreSQL and the driver. The raw measurements include every client outcome and the mint's execution-endpoint HTTP status counts.

## Reproduce

Use Linux, Docker, the project's Python environment, and Rust. Run the commands from the benchmark branch with that Python environment active. The script creates and removes its own PostgreSQL container and runs the selected Nutshell source in a private temporary directory. The wallet driver connects to localhost. [Mint runner](../../../scripts/benchmarks/cdk_postgres.py) · [CDK workload](../../../tests/cdk_wallet/examples/stress.rs)

```bash
set -e
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/nutshell-cdk-bench-target}"
cargo build --release --locked --manifest-path tests/cdk_wallet/Cargo.toml --example stress
driver="$CARGO_TARGET_DIR/release/examples/stress"
mkdir -p benchmark-results
mkdir -p /tmp/codex-worktrees/nutshell
base_dir=$(mktemp -d /tmp/codex-worktrees/nutshell/cdk-benchmark-base.XXXXXXXX)
git worktree add --detach "$base_dir" d038930673b9c0dc82953ce9bd26231919acfa15
for trial in head-1 main-1 main-2 head-2; do
    case "$trial" in
        head*) mint_source="$PWD" ;;
        main*) mint_source="$base_dir" ;;
    esac
    python scripts/benchmarks/cdk_postgres.py --source "$mint_source" \
        --driver "$driver" --workers 16 --output "benchmark-results/$trial.jsonl"
done
git worktree remove "$base_dir"
python scripts/benchmarks/cdk_summary.py benchmark-results/*.jsonl
```

The runner defaults to one worker per physical core available to the process. The explicit worker count reproduces this host's setting. Each trial requires a new output filename. Each JSONL starts with the exact mint revision and PostgreSQL image, contains one record per measured workload and concurrency, and ends with a database audit of melt states and pending proofs.
