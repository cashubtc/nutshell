## Overview
This PR addresses issue #933 by hardening assertions in the core test suite and introducing a dedicated GitHub Actions workflow (`shadow_tests`) to ensure stability across Python versions.

## Changes
- **Test Hardening**: Replaced generic `assert` statements in `tests/test_core.py` with descriptive error messages. This improves debuggability by providing clear context when an assertion fails (e.g., TokenV3/V4 amount mismatches).
- **CI/CD Integration**: Added `.github/workflows/shadow_tests.yml` to automate testing on `push` and `pull_request`.
- **Environment Fixes**: The workflow includes necessary system dependencies (`libsecp256k1`, `build-essential`) and Python dev-requirements (`respx`, `pytest-httpx`) to ensure a clean build in headless environments.

## Testing
- Successfully ran the suite in GitHub Actions (Ubuntu-latest, Python 3.11).
- Result: 388 passed, 63 skipped.

