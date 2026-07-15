# Implementation Plan: Retire Deprecated Nutshell Code

Audit date: 2026-07-15

> **Mandatory milestone workflow:** After every milestone, update this implementation plan with the completed checklist, final status, and validation results, then commit the milestone's changed files together with the plan update. A milestone is not complete until its commit succeeds. Use one focused Conventional Commit per milestone; do not combine milestones in one commit.

## Goal

Remove deprecated Nutshell features, old Nutshell API compatibility, and obsolete wallet compatibility in small, reviewable milestones while preserving every non-deprecated feature.

The work is a pure removal project. It must not introduce replacement behavior, refactor unrelated code, or change current business logic.

## Requirements and guardrails

- All fixes must be minimal and limited to the deprecated feature being retired in the active milestone.
- No unrelated code may be touched.
- Do not reformat, rename, reorganize, or refactor unaffected code.
- Other business logic must remain unchanged and unaffected.
- Current API request and response behavior must remain unchanged except for the explicitly removed deprecated shape.
- Current cryptography, proof verification, quote accounting, fees, key derivation, minting, melting, swapping, restoration, and wallet behavior must remain unchanged unless the milestone explicitly removes a deprecated variant.
- Delete deprecated code, its dedicated tests, configuration, documentation, imports, and exports together when they form one feature.
- Add or retain focused regression coverage for the corresponding current behavior. Do not broaden the implementation while adding tests.
- Preserve historical database migrations unless a milestone explicitly establishes and implements a new minimum database schema. Migration squashing is not part of ordinary deprecated-code removal.
- Do not change Cashu protocol behavior merely because a path is described as legacy. Protocol changes require a separate decision.
- Do not touch generated Lightning protobuf code, pytest's `junit_family=legacy`, Keycloak `LEGACY` settings, or unrelated compatibility abstractions.
- Treat `cashu/core/crypto/`, old key derivation, token recovery, database compatibility, NUT behavior, dependency APIs, and public API removal as requiring human review.
- Before editing, inspect the worktree and preserve all unrelated user changes.
- At the end of every milestone:
  - Run the milestone-specific tests.
  - Run Ruff and mypy in proportion to the changed scope.
  - Run `git diff --check`.
  - Confirm repository-wide searches no longer find the retired symbols or settings.
  - Update this plan's checklist, status, validation record, and notes.
  - Commit only the milestone files and this plan using a focused Conventional Commit.

## Status legend

- **Not started**: no implementation work has begun.
- **In progress**: implementation or validation is underway, or the milestone commit is pending.
- **Blocked**: an explicit compatibility, recovery, protocol, or minimum-version decision is required.
- **Deferred**: outside the current Nutshell-removal scope.
- **Complete**: checklist, success criteria, validation, plan update, and milestone commit are all complete.

## Milestone summary

| Milestone | Scope | Status |
|---|---|---|
| 0 | Baseline, scope, and guardrails | Complete |
| 1 | Remove deprecated hash-to-curve support | Complete |
| 2 | Remove deprecated configuration aliases | Not started |
| 3 | Remove pre-0.16 wallet v1 fallbacks | Not started |
| 4 | Remove old quote and mint-info response fallbacks | Not started |
| 5 | Remove the mint v0 API | Not started |
| 6 | Remove dead runtime/database compatibility artifacts | Not started |
| 7 | Remove TokenV3 support | Blocked — token-format cutoff and recovery policy required |
| 8 | Remove pre-0.15 base64 keyset support | Blocked — old-token and old-mint recovery policy required |
| 9 | Remove version-`00` keyset support | Blocked — ecosystem cutoff and recovery policy required |
| 10 | Remove old LNbits API support | Deferred — external backend compatibility decision |
| 11 | Final compatibility sweep and full regression verification | Not started |

## Milestone 0: Baseline, scope, and guardrails

**Status:** Complete

### Checklist

- [x] Inventory tracked deprecated and backward-compatibility code.
- [x] Separate Nutshell compatibility from generated code and third-party deprecations.
- [x] Identify compatibility that can affect funds recovery or old mint databases.
- [x] Define minimal-change and no-unrelated-code requirements.
- [x] Define the mandatory per-milestone plan-update and commit workflow.
- [x] Record the untracked `cashu/core/domain/` compatibility duplicates.
- [x] Commit this implementation plan as the Milestone 0 artifact.

### Success criteria

- The implementation scope is divided into independently testable and committable milestones.
- High-risk compatibility cannot be removed without its stated policy prerequisite.
- Non-deprecated protocol and business behavior is explicitly protected.
- The implementation plan is committed.

### Validation record

- Repository-wide marker and call-site audit completed on 2026-07-15.
- No production code changed as part of the audit itself.
- Milestone commit: completed with this plan update.

## Milestone 1: Remove deprecated hash-to-curve support

**Status:** Complete

### Scope

Remove the pre-0.15 hash-to-curve algorithm, wallet selection flag, verification fallbacks, and tests that exist only for the deprecated mapping.

### Checklist

- [x] Remove `hash_to_curve_deprecated`.
- [x] Remove `step1_alice_deprecated`.
- [x] Remove `verify_deprecated` and the fallback from `verify`.
- [x] Remove `carol_verify_dleq_deprecated` and the fallback from `carol_verify_dleq`.
- [x] Remove `wallet_use_deprecated_h2c`.
- [x] Make wallet output and proof construction always use current `step1_alice`.
- [x] Remove deprecated hash-to-curve tests and imports.
- [x] Retain current hash-to-curve and DLEQ coverage.
- [x] Add positive and negative current `verify` coverage.
- [x] Replace the stale generic DLEQ fixture with current mapping values.
- [x] Add the mint-level legacy hash-to-curve alias rejection regression from the PR #1082 approach.
- [x] Confirm no deprecated H2C symbols or settings remain.
- [x] Run focused crypto tests.
- [x] Run a wallet integration test covering current output/proof behavior.
- [x] Run focused Ruff and mypy checks.
- [x] Run `git diff --check`.
- [x] Update this milestone to **Complete** with final validation results.
- [x] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- Only the current hash-to-curve mapping is callable from production code.
- A proof valid under the current mapping remains valid.
- A different ordinary secret and the crafted legacy alias are both rejected.
- Current DLEQ verification remains unchanged.
- No deprecated H2C setting, branch, import, symbol, test, or fixture remains.
- All milestone tests and static checks pass.
- The implementation and updated plan are committed together.

### Validation record

- `tests/test_crypto.py`: 14 passed.
- Combined crypto and mint verification tests: 98 passed, including current-proof acceptance and legacy-alias rejection.
- Wallet integration test: 1 passed after allowing its local test servers to bind loopback ports.
- Focused Ruff: passed.
- Focused mypy: passed.
- `git -c core.whitespace=cr-at-eol diff --check`: passed for the repository's tracked CRLF files.
- Repository-wide deprecated H2C symbol and setting search: no matches outside this historical plan.
- Milestone commit: completed with this plan update.

## Milestone 2: Remove deprecated configuration aliases

**Status:** Not started

### Scope

Remove old environment setting names and their startup-time translation into current settings.

| Deprecated setting | Current setting |
|---|---|
| `SOCKS_HOST` and `SOCKS_PORT` | `SOCKS_PROXY` |
| `MINT_LIGHTNING_BACKEND` | `MINT_BACKEND_BOLT11_SAT` |
| `MINT_MAX_PEG_IN` | `MINT_MAX_MINT_BOLT11_SAT` |
| `MINT_MAX_PEG_OUT` | `MINT_MAX_MELT_BOLT11_SAT` |
| `MINT_PEG_OUT_ONLY` | `MINT_BOLT11_DISABLE_MINT` |

### Checklist

- [ ] Remove the deprecated fields from `cashu/core/settings.py`.
- [ ] Remove their translation logic from `startup_settings_tasks()`.
- [ ] Remove tests, examples, and documentation that reference the deprecated names.
- [ ] Add or retain focused tests proving the current settings still load and behave identically.
- [ ] Confirm no deprecated setting names remain in tracked source, tests, CI, or documentation.
- [ ] Run focused settings tests, Ruff, mypy, and `git diff --check`.
- [ ] Update this milestone to **Complete** with validation results.
- [ ] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- Only the current setting names are accepted and used.
- Current proxy, Lightning backend, mint limit, melt limit, and mint-disable behavior is unchanged.
- No unrelated settings or startup behavior changes.
- The implementation and updated plan are committed together.

## Milestone 3: Remove pre-0.16 wallet v1 fallbacks

**Status:** Not started

### Scope

Remove wallet interoperability with pre-0.16 v1 response/request shapes while leaving current v1 behavior untouched.

### Checklist

- [ ] Remove the wallet fallback that parses melt results as `{paid, preimage, change}`.
- [ ] Remove the wallet import and usage of `PostMeltResponse_deprecated` where it exists only for the fallback.
- [ ] Remove the `/v1/checkstate` retry that sends `secrets` after a `Ys` request returns HTTP 422.
- [ ] Remove tests dedicated only to these old response/request shapes.
- [ ] Retain or add focused tests for current melt and `checkstate` behavior.
- [ ] Confirm current error propagation remains unchanged for invalid modern responses.
- [ ] Confirm no `< 0.16` wallet compatibility markers remain outside later milestones.
- [ ] Run focused wallet API tests, Ruff, mypy, and `git diff --check`.
- [ ] Update this milestone to **Complete** with validation results.
- [ ] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- Wallet melt parsing accepts only the current quote response model.
- Wallet proof-state checks send only `Ys` and do not retry with secrets.
- Current mint communication, error handling, and proof-state behavior remains unchanged.
- The implementation and updated plan are committed together.

## Milestone 4: Remove old quote and mint-info response fallbacks

**Status:** Not started

### Scope

Remove compatibility with incomplete pre-0.17/pre-0.20.1 quote responses and the old NUT-06 contact representation.

### Checklist

- [ ] Make current mint quote response fields required where they are currently optional only for compatibility.
- [ ] Make current melt quote response fields required where they are currently optional only for compatibility.
- [ ] Remove wallet fallbacks to local `amount`, `unit`, and payment `request` values.
- [ ] Remove compatibility for missing quote `method` once the minimum supported version is confirmed.
- [ ] Remove the old list-of-lists NUT-06 contact preprocessor.
- [ ] Remove tests dedicated only to missing legacy response fields or contact shapes.
- [ ] Retain or add focused tests for complete current quote and mint-info responses.
- [ ] Confirm current quote accounting, states, expiry, payment preimage, and change handling remain unchanged.
- [ ] Run focused model and wallet tests, Ruff, mypy, and `git diff --check`.
- [ ] Update this milestone to **Complete** with validation results.
- [ ] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- Current response models reject old incomplete shapes.
- Complete current responses produce the same wallet quote state and stored values as before.
- Current mint-info contact objects parse unchanged.
- No quote accounting or state-transition logic changes.
- The implementation and updated plan are committed together.

## Milestone 5: Remove the mint v0 API

**Status:** Not started

### Scope

Remove the server-side v0 API as one coherent API-breaking milestone. Wallet-side v0 support has already been removed.

### Deprecated endpoints

- `GET /info`
- `GET /keys`
- `GET /keys/{idBase64Urlsafe}`
- `GET /keysets`
- `GET /mint`
- `POST /mint`
- `POST /melt`
- `POST /checkfees`
- `POST /split`
- `POST /check`
- `POST /restore`

### Checklist

- [ ] Remove `cashu/mint/router_deprecated.py` and its import.
- [ ] Stop mounting deprecated routes in `cashu/mint/app.py`.
- [ ] Remove `debug_mint_only_deprecated`.
- [ ] Remove all test branches conditioned on `debug_mint_only_deprecated`.
- [ ] Remove deprecated-only CI inputs and workflow labels.
- [ ] Remove the deprecated-only instructions from `CONTRIBUTING.md`.
- [ ] Remove skipped deprecated API integration tests and deprecated API fuzz tests.
- [ ] Remove v0-only models, imports, and exports after confirming they have no remaining users.
- [ ] Remove `BlindedMessage_Deprecated` after confirming no remaining users.
- [ ] Remove pre-0.12 `payment_hash` lookup compatibility contained in the v0 router.
- [ ] Remove pre-0.13 `fst`/`snd` split responses.
- [ ] Remove pre-0.14 and pre-0.15 output-without-keyset-ID adaptation contained in the v0 router.
- [ ] Confirm only `/v1` mint routes remain registered.
- [ ] Run current mint API, wallet integration, fuzz, Ruff, mypy, and `git diff --check`.
- [ ] Update this milestone to **Complete** with validation results.
- [ ] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- No v0 endpoint is mounted or importable.
- No deprecated-only server mode, model, test, CI input, or documentation remains.
- Every current `/v1` route and response remains unchanged.
- Current mint, melt, swap, restore, key, info, and proof-state tests pass.
- The implementation and updated plan are committed together.

## Milestone 6: Remove dead runtime/database compatibility artifacts

**Status:** Not started

### Scope

Remove compatibility fields and runtime fallbacks that are provably unreachable with the supported current schema. Do not squash or delete required historical migrations in this milestone.

### Checklist

- [ ] Prove `duplicate_keyset_id` has no runtime or serialized users, then remove it.
- [ ] Determine whether the melt quote `payment_preimage` fallback to the old `proof` column is still reachable after migrations.
- [ ] Determine whether runtime checks for absent `issued_time`, `last_checked`, `updated_at`, NUT-20 keys, and accounting columns are still reachable.
- [ ] Remove only fallbacks proven unreachable under the supported schema.
- [ ] Keep migrations required to construct or upgrade supported databases.
- [ ] Keep `m018`, `m020`, `m028`, `m032`, and `m037` unless a separately approved schema-baseline change replaces them.
- [ ] Keep migration numbering and ordering intact.
- [ ] Leave `m004_p2sh_locks` intact unless removing it is proven safe for both fresh and upgraded databases.
- [ ] Add focused current-schema loading tests for any removed fallback.
- [ ] Run SQLite and PostgreSQL-relevant model/migration tests where available, plus Ruff, mypy, and `git diff --check`.
- [ ] Update this milestone to **Complete** with validation results.
- [ ] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- Only dead runtime compatibility is removed.
- Fresh databases and all supported upgrade paths still migrate successfully.
- Current quote loading and persistence remain unchanged.
- No schema, migration order, or database business logic changes unintentionally.
- The implementation and updated plan are committed together.

## Milestone 7: Remove TokenV3 support

**Status:** Blocked — token-format cutoff and recovery policy required

### Prerequisites

- Define the oldest token format the wallet must receive.
- Decide whether exporting TokenV3 remains necessary for interoperability.
- Define how users recover or convert stored TokenV3 before removal.

### Checklist

- [ ] Record the approved TokenV3 cutoff and recovery policy in this plan.
- [ ] Remove `TokenV3` and `TokenV3Token` models.
- [ ] Remove `cashuA` deserialization and redemption.
- [ ] Remove TokenV3-to-TokenV4 and TokenV4-to-TokenV3 conversion.
- [ ] Remove automatic legacy serialization for base64 keysets, coordinated with Milestone 8.
- [ ] Remove `cashu send --legacy`.
- [ ] Remove `cashu pending --legacy` output.
- [ ] Remove TokenV3-only tests, imports, and documentation.
- [ ] Retain or add focused TokenV4 send, receive, pending, DLEQ, and memo tests.
- [ ] Confirm no `cashuA`, `TokenV3`, or legacy CLI option remains.
- [ ] Run wallet CLI, token, receive/redeem, Ruff, mypy, and `git diff --check`.
- [ ] Update this milestone to **Complete** with validation results.
- [ ] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- The wallet accepts and emits only current token formats.
- TokenV4 behavior remains byte-for-byte compatible for existing test vectors.
- Current send, receive, pending-token, DLEQ, memo, and unit behavior is unchanged.
- The approved recovery/cutoff policy is documented.
- The implementation and updated plan are committed together.

## Milestone 8: Remove pre-0.15 base64 keyset support

**Status:** Blocked — old-token and old-mint recovery policy required

### Prerequisites

- Define whether pre-0.15 tokens must remain spendable or recoverable.
- Define the minimum supported mint database version.
- Define how old base64 keysets are converted, redeemed, or retired.
- Resolve the interaction with TokenV3 removal.

### Checklist

- [ ] Record the approved base64-keyset cutoff and recovery policy in this plan.
- [ ] Remove `derive_keys_backwards_compatible_insecure_pre_0_12`.
- [ ] Remove `derive_keys_deprecated_pre_0_15`.
- [ ] Remove `derive_keyset_id_deprecated` from runtime code.
- [ ] Remove pre-0.12 and pre-0.15 branches from `MintKeyset.generate_keys()`.
- [ ] Remove base64 keyset detection and permissive legacy version acceptance.
- [ ] Remove base64 URL-safe keyset normalization from modern `/v1/keys/{keyset_id}`.
- [ ] Remove wallet base64 keyset fetching and deterministic-secret fallback.
- [ ] Remove `force_old_keysets` and wallet base64 inactivation compatibility.
- [ ] Remove `mint_inactivate_base64_keysets` and `wallet_inactivate_base64_keysets`.
- [ ] Remove mint-side base64 inactivation logic.
- [ ] Preserve required historical migration behavior or replace it only under an approved minimum-schema plan.
- [ ] Remove base64-keyset and pre-0.15 derivation tests; retain current keyset tests.
- [ ] Confirm no base64 keyset compatibility remains in active runtime code.
- [ ] Run mint keyset, wallet keyset, recovery, migration, Ruff, mypy, and `git diff --check`.
- [ ] Update this milestone to **Complete** with validation results.
- [ ] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- Runtime code accepts only supported hex keyset versions.
- Current version-`00` and version-`01` behavior remains unchanged at this milestone.
- Current mint startup, wallet key loading, deterministic secrets, and proof spending remain unchanged.
- Supported database migrations still work.
- The approved recovery/cutoff policy is documented.
- The implementation and updated plan are committed together.

## Milestone 9: Remove version-`00` keyset support

**Status:** Blocked — ecosystem cutoff and recovery policy required

### Prerequisites

- Define whether version-`00` tokens and mint keysets remain supported by the Cashu ecosystem.
- Define the minimum supported Nutshell version and keyset version.
- Provide a redemption or migration window for existing version-`00` ecash.

### Checklist

- [ ] Record the approved version-`00` cutoff and recovery policy in this plan.
- [ ] Remove the `0.15` to `< 0.20` keyset-generation branch.
- [ ] Remove version-`00` keyset ID derivation if it has no remaining current use.
- [ ] Restrict supported keyset versions to version `01` and later approved versions.
- [ ] Remove BIP32 deterministic-secret selection based on version `00`.
- [ ] Remove version-`00` short-ID passthrough behavior where obsolete.
- [ ] Remove version-`00` tests and vectors; retain version-`01` vectors unchanged.
- [ ] Confirm current version-`01` mint and wallet behavior remains unchanged.
- [ ] Run full keyset, deterministic-secret, mint/wallet integration, Ruff, mypy, and `git diff --check`.
- [ ] Update this milestone to **Complete** with validation results.
- [ ] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- Only approved current keyset versions are accepted or generated.
- Version-`01` IDs, short IDs, deterministic secrets, and test vectors remain unchanged.
- No current mint, wallet, proof, or token behavior changes.
- The approved ecosystem cutoff and recovery policy is documented.
- The implementation and updated plan are committed together.

## Milestone 10: Remove old LNbits API support

**Status:** Deferred — external backend compatibility decision

### Scope

This is not old Nutshell compatibility. `cashu/lightning/lnbits.py` starts with the old LNbits SSE endpoint and switches to the newer WebSocket API after detecting a new server.

### Prerequisites

- Define the minimum supported LNbits version.
- Confirm supported deployments no longer require the SSE endpoint.

### Checklist

- [ ] Record the approved minimum LNbits version in this plan.
- [ ] Remove `old_api` state and SSE listener logic.
- [ ] Keep the current WebSocket listener unchanged.
- [ ] Remove old-API tests and retain focused WebSocket tests.
- [ ] Run LNbits backend tests, Ruff, mypy, and `git diff --check`.
- [ ] Update this milestone to **Complete** with validation results.
- [ ] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- LNbits uses only the supported current notification API.
- Invoice creation, payment status, paid-invoice streaming, reconnect, and backoff behavior for the current API remain unchanged.
- The implementation and updated plan are committed together.

## Milestone 11: Final compatibility sweep and full regression verification

**Status:** Not started

### Checklist

- [ ] Search tracked source, tests, CI, and documentation for all retired symbols, settings, routes, versions, and comments.
- [ ] Classify every remaining `deprecated`, `legacy`, and `compatibility` marker as intentionally retained or unrelated.
- [ ] Verify generated protobuf deprecations and third-party compatibility were not modified accidentally.
- [ ] Verify historical migrations required by the supported minimum schema remain intact.
- [ ] Verify no unrelated files changed across the milestone series.
- [ ] Run `make format` only if needed and review every formatting change for scope.
- [ ] Run `make check`.
- [ ] Run the complete supported test suite.
- [ ] Run `git diff --check`.
- [ ] Record final retained compatibility and its rationale in this plan.
- [ ] Update this milestone to **Complete** with validation results.
- [ ] Commit the final plan and any strictly scoped cleanup using a focused Conventional Commit.

### Success criteria

- Every approved deprecated feature is absent from active runtime code.
- Every intentionally retained compatibility path is documented with a reason.
- The complete supported test suite and static checks pass.
- No non-deprecated business logic or public behavior changed.
- The final plan update is committed.

## Cross-cutting workspace note: `cashu/core/domain/`

At the time this plan was written, `cashu/core/domain/` was untracked and duplicated several compatibility paths:

- Pre-0.12 and pre-0.15 key derivation in `keysets.py`.
- `duplicate_keyset_id`.
- Deprecated v0 `BlindedMessage` in `proofs.py`.
- TokenV3 in `tokens.py`.
- `< 0.17` quote field fallbacks.
- An additional `< 0.16` conversion from old `paid` booleans to quote `state`.

Do not edit or delete this untracked work without explicit authorization. Before completing any milestone, determine whether the refactor has landed or become the active implementation. If it has, apply the same minimal removal to the surviving implementation and its tests. If it has not, leave it untouched and record that fact in the milestone notes.

## Explicitly retained or out of scope

The following must remain unchanged unless separately authorized:

- NUT-20 signatures being optional when a quote has no public key.
- Generic NUT-08 change generation, including support for any valid number of blank outputs.
- Historical migrations required for supported database initialization and upgrades.
- Generated LND protobuf deprecations.
- Pytest's `junit_family=legacy` setting.
- Keycloak `LEGACY` synchronization configuration.
- `cashu/core/db.py` compatibility abstractions unrelated to old Nutshell APIs.
- CryptoJS-compatible AES behavior.
- Current version-`01` keysets and approved future keyset versions.
- Current TokenV4 behavior and vectors.
