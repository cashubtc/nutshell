# How to contribute

Please contribute to Nutshell! You can open issues if you find bugs and pull requests for improvements.

## Contributing

Pick an issue you would like to work on. Those with the tag `good first issue` are great for getting started. When you open a pull request, make sure that you've run tests and lint checks locally before you push code.

## Development setup

Nutshell uses [Poetry](https://python-poetry.org/) and Python **3.10** (see README.md for `pyenv` and environment notes).

### Quick start

```bash
poetry install
make install-pre-commit-hook
```

**Windows users:** Run once after cloning:

```bash
git config core.autocrlf input
```

### Before committing

Stage your changes, then:

```bash
make format
```

Pre-commit hooks run automatically on `git commit`. To match CI before you push:

```bash
make pre-commit
```

## Line endings

This project uses **LF (Unix-style)** line endings. The repository handles this via `.gitattributes`, `.editorconfig`, and pre-commit hooks.

If you see unexpected whitespace or line-ending diffs:

```bash
poetry run pre-commit run mixed-line-ending --all-files
```

## Lint and style

We use [Ruff](https://docs.astral.sh/ruff/) **as a linter only** (`ruff check`); there is no enforced Ruff formatter in pre-commit or CI.

- `make format` — staged files: `ruff check --fix` + line-ending / whitespace hooks
- `make pre-commit` — full tree, matches CI (pre-commit hooks + mypy, etc.)
- `make ruff-check` — lint only, no fixes

## Debugging

For more expressive debug logging, you can enable debug logs or trace-level logs (even more expressive).

```
DEBUG=TRUE
LOG_LEVEL=TRACE
```

## Testing

To run the tests, run `make test` or `pytest tests` in the poetry environment.

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
# LndRPCWallet, LndRestWallet, CLNRestWallet, CoreLightningRestWallet, LNbitsWallet

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

MINT_CORELIGHTNING_REST_URL=https://localhost:3001
MINT_CORELIGHTNING_REST_MACAROON=../cashu-regtest-enviroment/data/clightning-2-rest/access.macaroon
MINT_CORELIGHTNING_REST_CERT=../cashu-regtest-enviroment/data/clightning-2-rest/certificate.pem
```

### Profiling

If you'd like to profile your code (measure how long steps take to execute), run the mint using `DEBUG_PROFILING=TRUE`. Make sure to turn this off again, as your application will be significantly slower with profiling enabled.

### V0 API only

To run the mint with only V0 API support (deprecated), use `DEBUG_MINT_ONLY_DEPRECATED=TRUE`
