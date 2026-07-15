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
- Keep deprecated configuration aliases because removing them would break existing deployments using old configuration names.
- Keep TokenV3 and version-`00` keyset support; they are intentionally retained and are not retirement targets.
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
| 1 | Remove pre-0.16 wallet v1 fallbacks | Complete |
| 2 | Remove old quote and mint-info response fallbacks | Complete |
| 3 | Remove the mint v0 API | Complete |
| 4 | Remove dead runtime/database compatibility artifacts | Complete |
| 5 | Remove pre-0.15 base64 keyset support | Blocked — old-token and old-mint recovery policy required |
| 6 | Remove old LNbits API support | Deferred — external backend compatibility decision |
| 7 | Final compatibility sweep and full regression verification | Not started |

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
- Deprecated hash-to-curve support was verified as already removed on `main` by PR #1082 (`61019f2b`) and is excluded from the implementation milestones.
- No production code changed as part of the audit itself.
- Milestone commit: completed with this plan update.

## Milestone 1: Remove pre-0.16 wallet v1 fallbacks

**Status:** Complete

### Scope

Remove wallet interoperability with pre-0.16 v1 response/request shapes while leaving current v1 behavior untouched.

### Checklist

- [x] Remove the wallet fallback that parses melt results as `{paid, preimage, change}`.
- [x] Remove the wallet import and usage of `PostMeltResponse_deprecated` where it exists only for the fallback.
- [x] Remove the `/v1/checkstate` retry that sends `secrets` after a `Ys` request returns HTTP 422.
- [x] Remove tests dedicated only to these old response/request shapes.
- [x] Retain or add focused tests for current melt and `checkstate` behavior.
- [x] Confirm current error propagation remains unchanged for invalid modern responses.
- [x] Confirm no `< 0.16` wallet compatibility markers remain outside later milestones.
- [x] Run focused wallet API tests, Ruff, mypy, and `git diff --check`.
- [x] Update this milestone to **Complete** with validation results.
- [x] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- Wallet melt parsing accepts only the current quote response model.
- Wallet proof-state checks send only `Ys` and do not retry with secrets.
- Current mint communication, error handling, and proof-state behavior remains unchanged.
- The implementation and updated plan are committed together.

### Validation record

- `tests/wallet/test_wallet_v1_api.py`: 25 passed.
- Current `/v1/checkstate` request coverage confirms only `Ys` is sent.
- HTTP 422 regression confirms the wallet raises the current mint error after one request and does not retry with secrets.
- Deprecated melt-response regression confirms the old `{paid, preimage, change}` shape raises `ValidationError`.
- No dedicated legacy-only wallet tests existed; current melt and proof-state coverage was retained and expanded.
- Focused Ruff: passed.
- Focused mypy: passed.
- `git diff --check`: passed.
- Wallet search found no remaining `PostMeltResponse_deprecated` import/use or `< 0.16` compatibility marker.
- The deprecated melt model remains only for the explicitly retained server v0 API milestone.
- Milestone commit: completed with this plan update.

## Milestone 2: Remove old quote and mint-info response fallbacks

**Status:** Complete

### Scope

Remove compatibility with incomplete pre-0.17/pre-0.20.1 quote responses and the old NUT-06 contact representation.

### Checklist

- [x] Make current mint quote response fields required where they are currently optional only for compatibility.
- [x] Make current melt quote response fields required where they are currently optional only for compatibility.
- [x] Remove wallet fallbacks to local `amount`, `unit`, and payment `request` values.
- [x] Remove compatibility for missing quote `method` once the minimum supported version is confirmed.
- [x] Remove the old list-of-lists NUT-06 contact preprocessor.
- [x] Remove tests dedicated only to missing legacy response fields or contact shapes.
- [x] Retain or add focused tests for complete current quote and mint-info responses.
- [x] Confirm current quote accounting, states, expiry, payment preimage, and change handling remain unchanged.
- [x] Run focused model and wallet tests, Ruff, mypy, and `git diff --check`.
- [x] Update this milestone to **Complete** with validation results.
- [x] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- Current response models reject old incomplete shapes.
- Complete current responses produce the same wallet quote state and stored values as before.
- Current mint-info contact objects parse unchanged.
- No quote accounting or state-transition logic changes.
- The implementation and updated plan are committed together.

### Validation record

- Current mint responses now require `amount`, `unit`, `method`, and `state`.
- Current melt responses now require `unit`, `method`, `request`, and `state`.
- Missing-field regressions reject all eight incomplete current quote shapes with `ValidationError`.
- Current mint-info contact objects parse unchanged; the old list-of-lists shape raises `ValidationError`.
- Wallet API, wallet CRUD, and mint router tests: 61 passed.
- Focused wallet mint/melt integration tests: 2 passed.
- Existing mint quote accounting and stale-response tests pass unchanged.
- Current melt state, expiry, payment preimage, and change tests pass unchanged.
- Focused Ruff: passed.
- Focused mypy: passed.
- `git -c core.whitespace=cr-at-eol diff --check`: passed for the repository's tracked CRLF files.
- Tracked-source search found no remaining quote local-value fallback, old quote optionality marker, or current mint-info contact preprocessor.
- V0-only quote/info models remain for the explicitly separate server v0 API milestone.
- Milestone commit: completed with this plan update.

## Milestone 3: Remove the mint v0 API

**Status:** Complete

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

- [x] Remove `cashu/mint/router_deprecated.py` and its import.
- [x] Stop mounting deprecated routes in `cashu/mint/app.py`.
- [x] Remove `debug_mint_only_deprecated`.
- [x] Remove all test branches conditioned on `debug_mint_only_deprecated`.
- [x] Remove deprecated-only CI inputs and workflow labels.
- [x] Remove the deprecated-only instructions from `CONTRIBUTING.md`.
- [x] Remove skipped deprecated API integration tests and deprecated API fuzz tests.
- [x] Remove v0-only models, imports, and exports after confirming they have no remaining users.
- [x] Remove `BlindedMessage_Deprecated` after confirming no remaining users.
- [x] Remove pre-0.12 `payment_hash` lookup compatibility contained in the v0 router.
- [x] Remove pre-0.13 `fst`/`snd` split responses.
- [x] Remove pre-0.14 and pre-0.15 output-without-keyset-ID adaptation contained in the v0 router.
- [x] Confirm only `/v1` mint routes remain registered.
- [x] Run current mint API, wallet integration, fuzz, Ruff, mypy, and `git diff --check`.
- [x] Update this milestone to **Complete** with validation results.
- [x] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- No v0 endpoint is mounted or importable.
- No deprecated-only server mode, model, test, CI input, or documentation remains.
- Every current `/v1` route and response remains unchanged.
- Current mint, melt, swap, restore, key, info, and proof-state tests pass.
- The implementation and updated plan are committed together.

### Validation record

- The v0 router, its dedicated integration/fuzz suites, and all v0-only request and response models were removed together.
- A route registration regression confirms `/v1/info` is mounted and none of the 11 retired v0 paths are mounted.
- Mint application/router tests: 13 passed.
- Current mint API tests: 17 passed, 2 backend-dependent tests skipped.
- Current mint API fuzz tests: 10 passed.
- Focused wallet, mint operation, melt, and database integration tests: 12 passed.
- Management RPC CLI tests whose v0-only skips were removed: 18 passed.
- Total scoped regression result: 70 passed, 2 skipped.
- Focused Ruff lint: passed.
- Focused mypy: passed for 11 production source files.
- Ruff format checking still reports unrelated pre-existing formatting in affected test files; those sections were not reformatted under the no-unrelated-code guardrail.
- GitHub Actions workflow YAML parsing: passed.
- `git -c core.whitespace=cr-at-eol diff --check`: passed for the repository's tracked CRLF files.
- Tracked-source search found no remaining v0 router, deprecated-only setting/CI mode, v0-only model, or v0 test-branch symbol.
- The untracked `cashu/core/domain/` duplicate remains untouched as required by the worktree-preservation guardrail.
- Historical keyset-ID derivation and migration compatibility remains intact because it protects persisted databases and is outside the v0 REST API.
- Milestone commit: completed with this plan update.

## Milestone 4: Remove dead runtime/database compatibility artifacts

**Status:** Complete

### Scope

Remove compatibility fields and runtime fallbacks that are provably unreachable with the supported current schema. Do not squash or delete required historical migrations in this milestone.

### Checklist

- [x] Prove `duplicate_keyset_id` has no runtime or serialized users, then remove it.
- [x] Determine whether the melt quote `payment_preimage` fallback to the old `proof` column is still reachable after migrations.
- [x] Determine whether runtime checks for absent `issued_time`, `last_checked`, `updated_at`, NUT-20 keys, and accounting columns are still reachable.
- [x] Remove only fallbacks proven unreachable under the supported schema.
- [x] Remove the obsolete persisted melt-quote `outputs` field and reset after confirming the current schema and CRUD no longer use it.
- [x] Keep migrations required to construct or upgrade supported databases.
- [x] Keep `m018`, `m020`, `m028`, `m032`, and `m037` unless a separately approved schema-baseline change replaces them.
- [x] Keep migration numbering and ordering intact.
- [x] Leave `m004_p2sh_locks` intact unless removing it is proven safe for both fresh and upgraded databases.
- [x] Add focused current-schema loading tests for any removed fallback.
- [x] Run SQLite and PostgreSQL-relevant model/migration tests where available, plus Ruff, mypy, and `git diff --check`.
- [x] Update this milestone to **Complete** with validation results.
- [x] Commit the milestone files and this plan using a focused Conventional Commit.

### Success criteria

- Only dead runtime compatibility is removed.
- Fresh databases and all supported upgrade paths still migrate successfully.
- Current quote loading and persistence remain unchanged.
- No schema, migration order, or database business logic changes unintentionally.
- The implementation and updated plan are committed together.

### Validation record

- `MintKeyset.duplicate_keyset_id` was removed after a tracked-source audit found no runtime, constructor, or serialization users.
- Current mint and wallet schemas always contain `amount_paid`, `amount_issued`, and `updated_at`; only their unreachable column-presence checks were removed. Existing null-value handling remains unchanged.
- The obsolete persisted `MeltQuote.outputs` field, row loader, and pending-state reset were removed. Migration `m028` remains responsible for moving any historical pending outputs before dropping that column.
- The melt `payment_preimage`/`proof` mapping remains because the current mint schema and CRUD still store the payment preimage in `proof`, while the current wallet schema uses `payment_preimage`.
- Presence checks for `issued_time`, `last_checked`, `pubkey`, and `privkey` remain because the shared loader serves current mint and wallet schemas with different field sets.
- All mint and wallet migrations remain unchanged, including `m004`, `m018`, `m020`, `m028`, `m032`, and `m037`; migration numbering and ordering remain intact.
- Fresh-schema mint migration and quote persistence tests plus wallet quote CRUD tests: 19 passed.
- Broader current mint database tests: 16 passed.
- Total scoped regression result: 35 passed.
- A PostgreSQL-style datetime row regression covers current accounting-field loading; no local PostgreSQL service was required.
- Focused Ruff lint: passed.
- Focused mypy: passed.
- Ruff formatting reports only unrelated pre-existing formatting in `cashu/mint/db/write.py`; it was left untouched under the no-unrelated-code guardrail.
- `git -c core.whitespace=cr-at-eol diff --check`: passed.
- Tracked-source search found no remaining `duplicate_keyset_id`, persisted melt-quote `outputs` reset, or removed accounting/`updated_at` column-presence check outside the preserved untracked worktree.
- Milestone commit: completed with this plan update.

## Milestone 5: Remove pre-0.15 base64 keyset support

**Status:** Blocked — old-token and old-mint recovery policy required

### Prerequisites

- Define whether pre-0.15 tokens must remain spendable or recoverable.
- Define the minimum supported mint database version.
- Define how old base64 keysets are converted, redeemed, or retired.
- Confirm the removal preserves intentionally retained TokenV3 and version-`00` keyset support.

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

## Milestone 6: Remove old LNbits API support

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

## Milestone 7: Final compatibility sweep and full regression verification

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
