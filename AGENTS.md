# AGENTS.md

> Guidance for AI agents and automated workflows contributing to **Nutshell**.
> For human contributors, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Common Commands

| Task | Command |
|---|---|
| Install dependencies | `poetry install` |
| Activate virtual env | `poetry env activate` |
| Run the wallet CLI | `cashu --help` |
| Run the mint server | `poetry run mint` |
| Run all tests | `make test` (or `pytest tests`) |
| Run wallet tests only | `make test-wallet` |
| Run mint tests only | `make test-mint` |
| Lint + type-check | `make check` (Ruff + mypy) |
| Auto-format code | `make format` |
| Install pre-commit hook | `poetry run pre-commit install` |

### Environment setup

- Python **3.10.4** (install via `pyenv install 3.10.4 && pyenv local 3.10.4`)
- [Poetry](https://python-poetry.org/) for dependency and environment management
- Copy `.env.example` to `.env` and set `MINT_BACKEND_BOLT11_SAT=FakeWallet` for local testing

## Repo Conventions

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: correct a bug
docs: update documentation
chore: maintenance / tooling
```

Optional scope: `feat(wallet):`, `fix(mint):`, `docs(core):`, etc.

### Pull requests

- Keep PRs small and focused on a single concern.
- Reference related issues in the PR description (e.g. `Closes #123`).
- Run `make format` and `make check` before pushing -- CI will catch failures, but checking locally first saves review cycles.
- PRs are reviewed by a maintainer (typically [@callebtc](https://github.com/callebtc)) before merging.

### Testing

- Most tests use the `FakeWallet` backend (no real Lightning node required).
- Set `MINT_BACKEND_BOLT11_SAT=FakeWallet` and `TOR=FALSE` in your `.env`.
- Regtest (simulated Lightning network) tests exist for deeper integration testing -- see [CONTRIBUTING.md](CONTRIBUTING.md#lightning-regtest) for setup.

## Autonomous vs. Human-Required Changes

### Safe for agents to do autonomously

- Bug fixes with clear reproduction steps and test coverage
- Documentation improvements
- Code formatting and lint fixes
- Adding or improving tests
- Small refactors that don't change public APIs

### Requires human review and decision

- **Security-sensitive changes** -- cryptographic operations, key management, blind signature logic (`cashu/core/crypto/`)
- **Database migrations / schema changes** -- any changes to database models or migration scripts
- **Cashu protocol (NUT) specification changes** -- protocol-level behavior defined by [NUTs](https://github.com/cashubtc/nuts)
- **Dependency major version bumps** -- especially cryptographic or networking libraries
- **Deployment and secrets configuration** -- `.env` variables, Docker configs, CI/CD workflows
- **API breaking changes** -- changes to mint or wallet REST API contracts

When in doubt, open an issue or discussion first rather than submitting a large unsolicited change.

## Architecture Overview

```
cashu/                  # Main package
  core/                 # Shared models, crypto primitives, protocol logic
  mint/                 # Mint server (FastAPI)
  wallet/               # CLI wallet (Click)
  lightning/            # Lightning backend integrations (LND, CLN, FakeWallet, etc.)
  tor/                  # Tor proxy support
tests/                  # Test suite (pytest)
  mint/                 # Mint-specific tests
  wallet/               # Wallet-specific tests
scripts/                # Utility scripts
docker/                 # Docker-related configs (Redis, Keycloak, etc.)
```

### Key files

| File | Purpose |
|---|---|
| `pyproject.toml` | Project metadata, dependencies, Ruff config |
| `Makefile` | Common dev tasks (test, format, check, build) |
| `.env.example` | Template for environment variables |
| `.pre-commit-config.yaml` | Pre-commit hook configuration |
| `mypy.ini` | Mypy type-checking settings |

## Key Documentation Links

- [CONTRIBUTING.md](CONTRIBUTING.md) -- contributor guide (setup, testing, formatting)
- [README.md](README.md) -- project overview, install instructions, usage
- [Cashu protocol specs (NUTs)](https://github.com/cashubtc/nuts) -- the protocol specification
- [Cashu documentation](https://docs.cashu.space) -- general Cashu ecosystem docs
