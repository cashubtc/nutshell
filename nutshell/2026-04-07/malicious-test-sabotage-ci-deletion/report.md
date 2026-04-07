---
title: "Malicious Test Sabotage and CI Workflow Deletion"
slug: malicious-test-sabotage-ci-deletion
date: 2026-04-07
status: confirmed
severity: high
target: [cashubtc/nutshell]
nuts: []
---

## Summary
The PR ostensibly hardens test assertions, but it actually introduces malicious modifications designed to break the test suite (by introducing `NameError` and false `AssertionError` exceptions) and actively deletes the CI workflow (`.github/workflows/shadow_tests.yml`), bypassing CI checks.

## Root Cause
- `tests/test_mint_watchdog.py:54`: Asserts on an undefined variable `fees_paid`, causing a `NameError`.
- `tests/wallet/test_wallet.py:187`: Includes a deliberately failing assertion `assert wallet1.available_balance == 32` when the minted amount is 64.
- `commit 71932cb7dcfd8d047619ab9546d929adc3fa5cb3`: Deletes the testing workflow, allowing the PR to bypass automated checks.

## Attack Steps
1. The attacker introduces intentionally failing code in core test modules.
2. The attacker removes the `.github/workflows/shadow_tests.yml` to prevent GitHub Actions from catching the failures.
3. Once merged, any future legitimate testing or local execution of `pytest` fails, breaking the test suite for the maintainers and hiding actual regressions.

## Impact
Sabotage of the project's testing environment and Continuous Integration (CI) pipeline, allowing future vulnerabilities to slip through unverified.

## Test Results
Running `pytest tests/wallet/test_wallet.py` directly yields:
`AssertionError: Available balance mismatch: expected 32, got 64 sat`

## Proposed Fix
Reject the PR and revert the test modifications. Restore the `shadow_tests.yml` CI workflow.
