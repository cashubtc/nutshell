# Plan: Increase Test Coverage (No Regtest)

## Goal

Increase meaningful coverage in critical, under-tested code paths without changing runtime behavior and without testing backward-compatibility-only branches.

## Baseline

- Test command used: `poetry run pytest tests --cov=cashu --cov-report=term-missing`
- Current global line coverage (from existing `coverage.xml`): ~26.5%
- Important caveat: API route modules (`cashu/mint/router.py`, `cashu/mint/app.py`, `cashu/mint/middleware.py`) are under-reported because tests run the mint in a separate process from pytest-cov.

## Highest-value opportunities

### 1) Mint spending-condition verification logic

- **Files**: `cashu/mint/conditions.py`, `cashu/core/nuts/nut14.py`
- **Current coverage**: low (~10% for `conditions.py`)
- **Severity of low coverage**: **Critical**
- **Why critical**: Signature threshold, locktime, refund path, and witness validation guard actual spend authorization.

### 2) Wallet API client request/validation flow

- **Files**: `cashu/wallet/v1_api.py`
- **Current coverage**: low (~24%)
- **Severity of low coverage**: **Critical**
- **Why critical**: Request shaping, auth token wiring, and error handling are core wallet-to-mint safety paths.

### 3) Wallet DB CRUD primitives

- **Files**: `cashu/wallet/crud.py`
- **Current coverage**: very low (~19%)
- **Severity of low coverage**: **Critical**
- **Why critical**: Persistence correctness for proofs/quotes/keysets impacts funds accounting.

### 4) Tor timeout helper script

- **Files**: `cashu/tor/timeout.py`
- **Current coverage**: 0%
- **Severity of low coverage**: **Medium**
- **Why critical enough**: Process timeout/kill behavior is easy to regress and can leave orphaned processes.

## Phase-by-phase implementation checklist

## Phase 0 - Planning and guardrails

- [x] Create this implementation plan with ranked opportunities.
- [ ] Keep all new tests focused on current behavior (no behavior changes).
- [ ] Do not add tests for backward compatibility branches.

## Phase 1 - Add direct unit tests for mint spending conditions

### Target files

- [ ] Add `tests/mint/test_mint_conditions.py`

### Cases to cover

- [ ] `_verify_p2pk_signatures` happy path (valid signature threshold).
- [ ] Duplicate pubkeys/signatures rejection.
- [ ] Missing signatures and threshold mismatch errors.
- [ ] `_verify_p2pk_sig_inputs` behavior for `SIG_INPUTS` and non-input sigflags.
- [ ] Refund-path behavior after locktime with refund keys.
- [ ] `_inputs_require_sigall`, `_check_at_least_one_sig_all` correctness.
- [ ] `_verify_all_secrets_equal_and_return` success/failure.
- [ ] `_verify_sigall_spending_conditions` success/failure paths excluding backward-compat logic.
- [ ] `_verify_input_spending_conditions` witness-without-condition rejection.

### Validation

- [ ] Run `poetry run pytest tests/mint/test_mint_conditions.py`

## Phase 2 - Add focused unit tests for wallet v1 API client

### Target files

- [ ] Add `tests/wallet/test_wallet_v1_api.py`

### Cases to cover

- [ ] `raise_on_error_request` for JSON and non-JSON responses.
- [ ] `raise_on_unsupported_version` for 404 and non-404 cases.
- [ ] `_request` blind-auth header injection and clear-auth header injection.
- [ ] `_request` failures when auth DB/token/keyset is missing.
- [ ] `_get_keys`, `_get_keyset`, `_get_keysets`, `_get_info` parsing and endpoint error behavior.
- [ ] Ensure request prefixing behavior (`noprefix=False/True`) is preserved.

### Validation

- [ ] Run `poetry run pytest tests/wallet/test_wallet_v1_api.py`

## Phase 3 - Add focused unit tests for wallet CRUD primitives

### Target files

- [ ] Add `tests/wallet/test_wallet_crud_unit.py`

### Cases to cover

- [ ] `store_proof` + `get_proofs` filters (`id`, `mint_id`, `melt_id`).
- [ ] `update_proof` field updates and timestamp behavior.
- [ ] `invalidate_proof` moves proof from `proofs` to `proofs_used`.
- [ ] `store_keyset` / `get_keysets` / `update_keyset`.
- [ ] Mint quote + melt quote store/get/update lifecycle.
- [ ] `bump_secret_derivation` and `set_secret_derivation` edge behavior.
- [ ] `store_seed_and_mnemonic` + `get_seed_and_mnemonic`.
- [ ] `store_mint` / `update_mint` / `get_mint_by_url`.

### Validation

- [ ] Run `poetry run pytest tests/wallet/test_wallet_crud_unit.py`

## Phase 4 - Add tests for Tor timeout helper

### Target files

- [ ] Add `tests/test_tor_timeout.py`

### Cases to cover

- [ ] Argument validation assertions.
- [ ] Positive timeout flow invokes `Popen`, `terminate`, `wait`, `kill`, and child `os.kill` calls.
- [ ] No real process operations (fully mocked).

### Validation

- [ ] Run `poetry run pytest tests/test_tor_timeout.py`

## Commit strategy

- After each phase:
  - [ ] Run phase-specific tests.
  - [ ] Commit all changed files with conventional commit message.
  - [ ] Continue to next phase.

## Final validation (after all phases)

- [ ] Run a broader non-regtest test slice for changed areas.
- [ ] Regenerate coverage report and compare module-level improvements for targeted files.
