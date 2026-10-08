# How to contribute

Please contribute to Nutshell! You can open issues if you find bugs and pull requests for improvements.

## Contributing

Pick an issue you would like to work on. Those with the tag `good first issue` are great for getting started. When you open a pull request, make sure that you've run tests and formatting locally before you push code.

## Formatting

We use [Ruff](https://docs.astral.sh/ruff/formatter/) for formatting. To make sure that your tests succeed, please run `make format` before you push code. You can find the Ruff parameters in `pyproject.toml`.

## Setting up your environment

We use [Poetry](https://python-poetry.org/) as a dependency and environment manager. Currently, Nutshell supports Python `3.10` which you can install using `pyenv` (see README.md). To install all dependencies, run `poetry install`. After install, activate the environment with `poetry env activate` (or install the optional poetry-plugin-shell if you prefer `poetry shell`). Now you can execute `cashu --help` to use the wallet or `mint` to run the mint.

### Precommit hook

To run the formatter and mypy (linter) before you push code, you can install the very useful pre-commit hook which will check your code every time you push with git.

```bash
poetry run pre-commit install
```

## Debugging

For more expressive debug logging, you can enable debug logs or trace-level logs (even more expressive).

```
DEBUG=TRUE
LOG_LEVEL=TRACE
```

## Testing

To run the tests, run `make test` or `pytest tests` in the poetry environment.

### Mutation testing

Mutation testing checks whether the test suite detects small behavioral changes
to the production code. Nutshell uses
[Mutmut](https://mutmut.readthedocs.io/en/latest/) for this.

Run the mutation-testing pilot with:

```bash
PYTHONUNBUFFERED=1 DEBUG=true MINT_BACKEND_BOLT11_SAT=FakeWallet \
  MUTATION_TESTING=true TOR=false \
  poetry run python scripts/run_mutation.py --profile tor
```

The profiles cover each complete production subsystem: core, mint, wallet,
lightning, and Tor. Use `--profile mint` (or another subsystem) to generate
mutants only for that subtree and resume previously completed results. Mutmut
uses the non-fuzz pytest suite to discover relevant tests, then limits clean
baseline checks to those tests. Profile caches are
invalidated when source, tests, runner, dependencies, or configuration change,
including resolved shell/`.env` settings and pytest or regtest flags.

Each invocation uses one worker because the integration tests share database
paths and HTTP/RPC ports. Mutmut's fork server starts each baseline and mutant
with fresh imports, without inheriting databases or gRPC threads from a prior
test session. Parallel CI shards run on separate machines.

The runner retries baseline failures up to three times, excluding failed tests
for that invocation and rebuilding mutation coverage and results. Exclusions
and failure details are saved in `mutation-baseline.json`; results with exclusions
are explicitly marked as partial coverage. Every new invocation retries all
tests. Pass `--baseline-retries 0` to stop on the first baseline failure.
Collection errors, fixture errors, unusable baselines, and failures after the
baseline still stop the run. Test failures caused by an actual mutant mark that
mutant as killed and do not stop mutation testing.

For a function-specific forced rerun, pass a Mutmut wildcard. Explicit mutant
targets rerun cached verdicts; use `--profile` for incremental execution:

```bash
PYTHONUNBUFFERED=1 DEBUG=true MINT_BACKEND_BOLT11_SAT=FakeWallet \
  MUTATION_TESTING=true TOR=false \
  poetry run python scripts/run_mutation.py 'cashu.core.split*'
```

Mutmut stores incremental results in the ignored `mutants/` directory. View
surviving mutants with `poetry run mutmut results`, or create the machine-readable
`mutants/mutmut-cicd-stats.json` report with
`poetry run mutmut export-cicd-stats`. Use
`poetry run mutmut show <mutant-name>` to inspect a mutant and
`poetry run mutmut apply <mutant-name>` to apply it temporarily for debugging.
Only apply mutants in a clean worktree.

Scheduled CI runs each profile independently at 01:00 UTC: core on Monday, mint
on Tuesday, wallet on Wednesday, lightning on Thursday, and Tor on Friday.
Mint and wallet each use four shards, core and lightning use two, and Tor uses
one. Source paths are deterministically assigned to exactly one shard, including
new files. To reproduce one shard locally, use
`scripts/run_mutation.py --profile mint --shard 0 --shards 4` with the environment
and Python command shown above.

Every workflow also supports manual dispatch. Surviving mutants are advisory
during the initial rollout: improve the relevant tests or document why a mutant
is equivalent. CI uploads each profile's report and log as artifacts and retains
its incremental mutation state in a separate cache, including after a timeout.
Caches resume only within the same revision and shard; reruns save a new cache
snapshot. Shard artifacts retain their individual logs, while a combined
artifact preserves the profile report format and flags missing or unfinished
shards. On Saturday, CI collects the five profile reports and opens a labeled
weekly GitHub issue when actionable
mutants remain, baseline tests were excluded, or a profile report is unavailable.
Jobs use GitHub's six-hour hosted-runner limit. Mutation execution receives 340
minutes, leaving time to upload partial results if a profile does not finish.
Failed profiles with available artifacts still contribute their partial counts
to the weekly report. Test the runner and report tooling separately with
`poetry run pytest scripts/tests`; these tests are outside mutmut's own suite.
Do not add `# pragma: no mutate` or broaden `do_not_mutate` without review.
Changes involving cryptography, key handling, migrations, protocol behavior, or
public APIs require maintainer review.

The dedicated Hypothesis fuzz suite remains a separate quality check; run it
with `make fuzz`.

### FakeWallet

We use the `FakeWallet` backend for most of the tests. `FakeWallet` acts like a Lightning node where all (fake) invoices are always automatically paid. It's great for testing code that does not affect the Lightning functionality of the mint. To use it, set:

```
MINT_BACKEND_BOLT11_SAT=FakeWallet
```

You can control how fast payments should succeed by setting these flags

```
FAKEWALLET_DELAY_PAYMENT=TRUE
FAKEWALLET_DELAY_OUTGOING_PAYMENT=3
FAKEWALLET_DELAY_INCOMING_PAYMENT=3
```

A test can also choose the outcome of a single melt. If the description of the invoice being paid is JSON of this shape, it overrides the mint-wide `FAKEWALLET_*` payment settings for that invoice only:

```json
{"pay_invoice_state": "PENDING", "check_payment_state": "PAID", "pay_err": false, "check_err": false}
```

All four fields are required. States are `PAID` (or `SETTLED`), `PENDING`, `FAILED` (or `UNPAID`) and `UNKNOWN`. `pay_err` makes the payment raise and `check_err` makes the status check raise. The format matches the CDK fake wallet, and `get_fake_invoice` in `tests/helpers.py` builds such an invoice.

### Lightning regtest

There are many tests that also run in regtest, a simulated Lightning network environment. To run the regtest, clone [this repository](https://github.com/callebtc/cashu-regtest-enviroment) and run `./start.sh`. This will start your regtest environment with several Lightning node implementations.

Quick setup checklist:

- Prereqs: Docker with compose plugin, `jq`, and your user in the `docker` group.
- Keep the regtest repo as a sibling of `nutshell` (e.g. `../cashu-regtest-enviroment`).
- Start regtest: `cd ../cashu-regtest-enviroment && ./start.sh` (runs health checks; give it a minute).
- In `nutshell`: `cp .env.example .env`, then fill the variables below; use absolute paths if you run the mint from elsewhere.
- If `./start.sh` fails on `jq` or Docker permissions, install `jq` or re-login after adding yourself to the `docker` group.

You can choose one of the nodes as a backend for nutshell using the `.env` variable:

```
# Choose one from:
# LndRPCWallet, LndRestWallet, CLNRestWallet

MINT_BACKEND_BOLT11_SAT=LndRestWallet
```

The Nutshell settings to connect to the provided nodes are given below

```
# regtest
MINT_LND_REST_ENDPOINT=https://localhost:8081
MINT_LND_REST_CERT="../cashu-regtest-enviroment/data/lnd-3/tls.cert"
MINT_LND_REST_MACAROON="../cashu-regtest-enviroment/data/lnd-3/data/chain/bitcoin/regtest/admin.macaroon"


MINT_CLNREST_URL=https://localhost:3010
MINT_CLNREST_RUNE="../cashu-regtest-enviroment/data/clightning-2/rune"
MINT_CLNREST_CERT="../cashu-regtest-enviroment/data/clightning-2/regtest/ca.pem"

```

### Spark backend regtest

The Spark tests use the real Breez SDK installed by Poetry with the local Spark
operators, SSP, Esplora, LND, and CLN from
[cashu-regtest](https://github.com/callebtc/cashu-regtest). Set up the environment:

```sh
cd ~/cashu-regtest
git switch main
git pull --ff-only
./start.sh --spark

cd ~/nutshell
make test-spark-regtest
```

The first Spark stack build can take 30–90 minutes and needs disk space for its
Rust and Go builds. `start.sh` resets the regtest's existing containers, volumes,
and Lightning data. The tests themselves use the running stack without restarting
it. If the checkout is elsewhere, run
`CASHU_REGTEST_DIR=/path/to/cashu-regtest make test-spark-regtest`.

`make test-spark-regtest` runs three commands sequentially:

| Command | Coverage |
| --- | --- |
| `make test-spark-backend-regtest` | Four direct backend round trips: LND and CLN, in sat and msat, including events, preimages, fee/balance accounting, and reconnecting. |
| `make test-spark-mint` | The existing `make test-mint` suite with `SparkL2Wallet`, including held payments that settle or fail and pending Cashu proofs. |
| `make test-spark-wallet` | The existing `make test-wallet` suite with `SparkL2Wallet`, including recovery after an interrupted melt succeeds or fails. |

GitHub CI runs the shared Spark mint and wallet suites with both SQLite and
PostgreSQL. The Spark mint jobs also run the four direct backend cases. All
regtest jobs use the revision pinned in `.github/actions/setup-regtest/action.yml`;
Spark jobs start it with `--spark` and allow up to 90 minutes for setup and
45 minutes for the shared suite.

The shared suites start the real HTTP mint. An opt-in pytest fixture configures
the installed Breez SDK to use local endpoints and generated operator
certificates. The HTTP mint and in-process test ledger use separate temporary
seeds and caches; backend instances within each process share one SDK. The test
ledger receives 10,000 regtest sats before the suite starts. Startup-recovery
tests submit a real backend payment without recording its result in the mint,
then reconcile its pending proofs using the persisted quote and payment history.
No Breez API key or configured mint mnemonic is used. The fixture does not mock
backend or SDK payment operations. Funding helpers wait until the receiving
backend or HTTP mint can see the payment before continuing. The fixture records
which process created each invoice so these checks query the correct wallet.
USD retains the existing `FakeWallet` backend for mixed-unit tests.

For direct pytest invocation of the shared suites, set:

```sh
CASHU_SPARK_REGTEST=true MINT_BACKEND_BOLT11_SAT=SparkL2Wallet \
  MINT_BACKEND_BOLT11_USD=FakeWallet TOR=FALSE \
  poetry run pytest tests/mint/test_mint_regtest.py tests/wallet/test_wallet_regtest.py -v
```

The direct backend cases use their own isolated wallets and remain skipped in
normal runs. Spark reports an unpaid receive request as `UNKNOWN` until it
appears in payment history; the shared tests check that distinction explicitly.
MPP cases use the existing capability checks because Spark does not support MPP.
The three tests tied to nonzero LND/CLN routing fees are skipped for Spark.
This version of `open-ssp` requires `SSP_SWAP_FEE_SATS=0` and rejects nonzero
fees because fee-bearing Swap V3 fills are unsupported. Nonzero Spark fee
conversion remains covered by the mocked backend tests; live nonzero-fee parity
requires upstream SSP support.

The tests leave payment history and wallet balances until the next stack reset.
Repeated runs can consume the SSP's initial 500,000-sat liquidity. Replenish it
without resetting the running stack using the regtest repository's helper:

```sh
cd ~/cashu-regtest
source ./docker-scripts.sh
cashu-spark-fund-ssp
```

After many runs, SSP leaf splitting can also exhaust the operators' unused
deposit-address quota, preventing this helper from creating a funding address.
Reset the regtest stack before rerunning in that case.

An explicitly enabled run fails if the local services are unavailable.

### Profiling

If you'd like to profile your code (measure how long steps take to execute), run the mint using `DEBUG_PROFILING=TRUE`. Make sure to turn this off again, as your application will be significantly slower with profiling enabled.
