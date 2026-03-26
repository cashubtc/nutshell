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
- [x] Keep all new tests focused on current behavior (no behavior changes).
- [x] Do not add tests for backward compatibility branches.

## Phase 1 - Add direct unit tests for mint spending conditions

### Target files

- [x] Add `tests/mint/test_mint_conditions.py`

### Cases to cover

- [x] `_verify_p2pk_signatures` happy path (valid signature threshold).
- [x] Duplicate pubkeys/signatures rejection.
- [x] Missing signatures and threshold mismatch errors.
- [x] `_verify_p2pk_sig_inputs` behavior for `SIG_INPUTS` and non-input sigflags.
- [x] Refund-path behavior after locktime with refund keys.
- [x] `_inputs_require_sigall`, `_check_at_least_one_sig_all` correctness.
- [x] `_verify_all_secrets_equal_and_return` success/failure.
- [x] `_verify_sigall_spending_conditions` success/failure paths excluding backward-compat logic.
- [x] `_verify_input_spending_conditions` witness-without-condition rejection.

### Validation

- [x] Run `poetry run pytest tests/mint/test_mint_conditions.py`

## Phase 2 - Add focused unit tests for wallet v1 API client

### Target files

- [x] Add `tests/wallet/test_wallet_v1_api.py`

### Cases to cover

- [x] `raise_on_error_request` for JSON and non-JSON responses.
- [x] `raise_on_unsupported_version` for 404 and non-404 cases.
- [x] `_request` blind-auth header injection and clear-auth header injection.
- [x] `_request` failures when auth DB/token/keyset is missing.
- [x] `_get_keys`, `_get_keyset`, `_get_keysets`, `_get_info` parsing and endpoint error behavior.
- [x] Ensure request prefixing behavior (`noprefix=False/True`) is preserved.

### Validation

- [x] Run `poetry run pytest tests/wallet/test_wallet_v1_api.py`

## Phase 3 - Add focused unit tests for wallet CRUD primitives

### Target files

- [x] Add `tests/wallet/test_wallet_crud_unit.py`

### Cases to cover

- [x] `store_proof` + `get_proofs` filters (`id`, `mint_id`, `melt_id`).
- [x] `update_proof` field updates and timestamp behavior.
- [x] `invalidate_proof` moves proof from `proofs` to `proofs_used`.
- [x] `store_keyset` / `get_keysets` / `update_keyset`.
- [x] Mint quote + melt quote store/get/update lifecycle.
- [x] `bump_secret_derivation` and `set_secret_derivation` edge behavior.
- [x] `store_seed_and_mnemonic` + `get_seed_and_mnemonic`.
- [x] `store_mint` / `update_mint` / `get_mint_by_url`.

### Validation

- [x] Run `poetry run pytest tests/wallet/test_wallet_crud_unit.py`

## Phase 4 - Add tests for Tor timeout helper

### Target files

- [x] Add `tests/test_tor_timeout.py`

### Cases to cover

- [x] Argument validation assertions.
- [x] Positive timeout flow invokes `Popen`, `terminate`, `wait`, `kill`, and child `os.kill` calls.
- [x] No real process operations (fully mocked).

### Validation

- [x] Run `poetry run pytest tests/test_tor_timeout.py`

## Phase 5 - Add focused unit tests for mint rate limiting helpers

### Target files

- [x] Add `tests/mint/test_mint_limit.py`

### Cases to cover

- [x] `_rate_limit_exceeded_handler` returns HTTP 429 JSON response.
- [x] `get_remote_address_excluding_local` strips localhost but keeps remote IPs.
- [x] `assert_limit` success and failure behavior using mocked limiter backend.
- [x] `get_ws_remote_address` fallback behavior when client/host missing.
- [x] `limit_websocket` bypass for localhost and enforcement for remote clients.

### Validation

- [x] Run `poetry run pytest tests/mint/test_mint_limit.py`

## Phase 6 - Increase coverage of wallet v1 API client further

### Target files

- [x] Extend `tests/wallet/test_wallet_v1_api.py`

### Cases to cover

- [x] Proxy-selection branches in `async_set_httpx_client` (`tor`, `socks_proxy`, `http_proxy`).
- [x] Verbose request/response logging branch in `_request`.
- [x] `mint_quote` load-mint guard path and request payload assertions.
- [x] `mint` payload shape and response parsing.
- [x] `split` response parsing and empty-result guard.
- [x] `melt_quote`, `get_melt_quote`, and `melt` non-backward-compat happy paths.
- [x] `check_proof_state` normal v1 path (without backward-compat fallback).
- [x] `restore_promises` and `blind_mint_blind_auth` response parsing.

### Validation

- [x] Run `poetry run pytest tests/wallet/test_wallet_v1_api.py`

## Phase 7 - Increase lightning backend coverage with mocked backend-specific responses

### Target files

- [x] Add `tests/lightning/test_lightning_backends_mocked.py`

### Backend-by-backend expected behavior and mocked coverage targets

- [x] `LNbitsWallet` (`cashu/lightning/lnbits.py`)
  - Expected behavior:
    - Wallet endpoint error details map to `StatusResponse.error_message`.
    - Invoice creation converts HTTP failures into `InvoiceResponse(ok=False)`.
    - Missing `payment_hash` on payment-send yields `PaymentResult.UNKNOWN`.
    - Invalid payment-status payload returns `PaymentResult.UNKNOWN`.
  - Tests added for these branches using mocked REST responses.

- [x] `StrikeWallet` (`cashu/lightning/strike.py`)
  - Expected behavior:
    - USD wallet falls back to USDT balance when USD balance absent.
    - Payment quote currency mismatches are rejected.
    - Payment execute HTTP errors map to `PaymentResult.FAILED`.
    - 404 payment-status lookup maps to `PaymentResult.UNKNOWN`.
  - Tests added for these branches using mocked REST responses.

- [x] `CLNRestWallet` (`cashu/lightning/clnrest.py`)
  - Expected behavior:
    - `description_hash` without unhashed description raises `Unsupported`.
    - MPP amount mismatch with `supports_mpp=False` fails early and deterministically.
    - Missing payment in `listpays` maps to `PaymentResult.UNKNOWN`.
    - Quote calculation honors MPP amount override (`options.mpp.amount`).
  - Tests added for these branches using mocked decode/REST responses.

- [x] `CoreLightningRestWallet` (`cashu/lightning/corelightningrest.py`)
  - Expected behavior:
    - `description_hash` without unhashed description raises `Unsupported`.
    - Missing payment in `listPays` maps to `PaymentResult.UNKNOWN`.
  - Tests added for these branches using mocked REST responses.

- [x] `LndRestWallet` (`cashu/lightning/lndrest.py`)
  - Expected behavior:
    - Invoice creation decodes `r_hash` (base64) into hex checking id.
    - Payment endpoint `payment_error` maps to `PaymentResult.FAILED`.
    - Streaming payment tracking maps status/fee/preimage correctly.
    - Quote calculation uses MPP amount override when provided.
  - Tests added for these branches using mocked REST stream/decode responses.

- [x] `BlinkWallet` (`cashu/lightning/blink.py`)
  - Expected behavior:
    - Known API edge-case with two opposite-direction txs (`SEND`+`RECEIVE`) maps to failed payment status.
  - Additional edge-case test added using mocked GraphQL response.

- [ ] `LndRPCWallet` (`cashu/lightning/lnd_grpc/lnd_grpc.py`)
  - Planned expectation coverage:
    - gRPC channel balance/status, invoice creation, and streamed payment status mapping.
    - Keep tests fully mocked at stub/channel layer (no node dependency).
  - Deferred in this pass due larger proto/stub mocking surface.

- [ ] `FakeWallet` (`cashu/lightning/fake.py`)
  - Planned expectation coverage:
    - deterministic balance transitions and queue-driven incoming payment stream behavior.
  - Lower priority because this backend is already heavily exercised indirectly by integration tests.

### Validation

- [x] Run `poetry run pytest tests/lightning/test_lightning_backends_mocked.py`

## Phase 8 - Add focused auth and security tests for mint and wallet

### Target files

- [x] Add `tests/mint/test_mint_auth_server_unit.py`
- [x] Add `tests/mint/test_mint_auth_middleware.py`

### Cases to cover

- [x] `AuthLedger._verify_oicd_issuer` success and issuer mismatch failure.
- [x] `AuthLedger._get_user` returns existing users and creates missing users.
- [x] `verify_clear_auth` maps invalid JWT flows to `ClearAuthFailedError`.
- [x] `verify_clear_auth` maps rate-limit failures to `BlindAuthRateLimitExceededError`.
- [x] `mint_blind_auth` enforces max blind token count and updates user last access.
- [x] `verify_blind_auth` invalidates proofs on success and unsets pending in `finally`.
- [x] `ClearAuthMiddleware` requires `clear-auth` headers only on protected paths.
- [x] `BlindAuthMiddleware` requires `blind-auth` headers only on protected paths.

### Validation

- [x] Run `poetry run pytest tests/mint/test_mint_auth_server_unit.py tests/mint/test_mint_auth_middleware.py`

## Phase 9 - Add in-process mint app, router, and middleware tests

### Target files

- [ ] Add `tests/mint/test_mint_app_router.py`

### Cases to cover

- [ ] `create_app` metadata and router registration expectations.
- [ ] `catch_exceptions` maps `CashuError` and generic exceptions into JSON responses.
- [ ] `request_validation_exception_handler` includes query params in the response detail.
- [ ] `CompressionMiddleware` compression precedence and streaming bypass behavior.
- [ ] `/v1/info`, `/v1/keys`, `/v1/keysets`, and `/v1/keys/{keyset_id}` happy/error paths using in-process ASGI.
- [ ] `/v1/checkstate` and `/v1/restore` non-regtest happy/error paths.

### Validation

- [ ] Run `poetry run pytest tests/mint/test_mint_app_router.py`

## Phase 10 - Add websocket and subscription protocol robustness tests

### Target files

- [ ] Add `tests/mint/test_mint_websocket_protocol.py`
- [ ] Add `tests/wallet/test_wallet_subscription_unit.py`

### Cases to cover

- [ ] `LedgerEventClientManager` parse errors, invalid request errors, method-not-found errors, and unsubscribe failures.
- [ ] Subscription add/remove limits and initialization behavior for quote and proof-state subscriptions.
- [ ] `LedgerEventManager.submit` only dispatches to matching subscribers.
- [ ] `SubscriptionManager` websocket URL formation for http/https and port handling.
- [ ] `SubscriptionManager._on_message` ignores responses, dispatches notifications, and ignores malformed payloads.

### Validation

- [ ] Run `poetry run pytest tests/mint/test_mint_websocket_protocol.py tests/wallet/test_wallet_subscription_unit.py`

## Phase 11 - Add management RPC server unit tests

### Target files

- [ ] Add `tests/mint/test_mint_management_rpc_server.py`

### Cases to cover

- [ ] Metadata update RPCs (`UpdateMotd`, `UpdateName`, `AddUrl`, `RemoveUrl`, contacts) mutate settings correctly.
- [ ] Quote getter/update RPCs serialize quote state correctly.
- [ ] `RotateNextKeyset` forwards expected arguments and response fields.
- [ ] `UpdateLightningFee` and `UpdateAuthLimits` reject missing inputs.
- [ ] `serve` chooses insecure vs mTLS startup path and validates missing file errors.

### Validation

- [ ] Run `poetry run pytest tests/mint/test_mint_management_rpc_server.py`

## Phase 12 - Expand migration and DB concurrency safety tests

### Target files

- [ ] Add `tests/mint/test_mint_migrations_matrix.py`
- [ ] Add `tests/wallet/test_wallet_migrations_matrix.py`
- [ ] Add `tests/mint/test_mint_db_concurrency_edges.py`

### Cases to cover

- [ ] Re-running migrations is idempotent on already-upgraded databases.
- [ ] Critical schema/data migrations preserve rows and expected state transitions.
- [ ] Pending-proof and quote update flows behave deterministically under concurrent access.
- [ ] SQLite-specific lock and retry behavior is exercised where practical.

### Validation

- [ ] Run the new migration and DB edge test slices.

## Commit strategy

- After each phase:
  - [x] Run phase-specific tests.
  - [x] Commit all changed files with conventional commit message.
  - [x] Continue to next phase.

## Final validation (after all phases)

- [x] Run a broader non-regtest test slice for changed areas.
- [x] Regenerate coverage report and compare module-level improvements for targeted files.
