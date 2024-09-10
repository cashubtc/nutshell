# How to contribute

Please contribute to Nutshell! You can open issues if you find bugs and pull requests for improvements.

## Contributing
Pick an issue you would like to work on. Those with the tag `good first issue` are great for getting started. When you open a pull request, make sure that you've run tests and formatting locally before you push code.

## Formatting
We use [Ruff](https://docs.astral.sh/ruff/formatter/) for formatting. To make sure that your tests succeed, please run `make format` before you push code. You can find the Ruff parameters in `pyproject.toml`.

## Setting up your environment

We use [Poetry](https://python-poetry.org/) as a dependency and environment manager. Currently, Nutshell supports Python `3.10.4` which you can install using `pyenv` (see README.md). To install all dependencies, run `poetry install`. After install, you can activate the shell with `poetry shell`. Now you can execute `cashu --help` to use the wallet or `mint` to run the mint.

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

There are many tests that also run in regtest, a simulated Lightning network environment. To run the regtest, clone [this repository](https://github.com/callebtc/cashu-regtest) and run `./start.sh`. This will start your regtest environment with several Lightning node implementations.

You can choose one of the nodes as a backend for nutshell using the `.env` variable:
```
# Choose one from:
# LndRestWallet, CLNRestWallet, CoreLightningRestWallet, LNbitsWallet

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
