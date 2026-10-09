import pytest
import pytest_asyncio

from cashu.wallet.wallet import Wallet
from tests.compatibility import (
    BELOW_MINIMUM_ERROR,
    MINIMUM_MINT_VERSION,
    MINIMUM_MINT_VERSION_REFERENCE,
    MINT_VERSION,
    mint_older_than,
)
from tests.conftest import SERVER_ENDPOINT

pytestmark = pytest.mark.skipif(
    not mint_older_than(MINIMUM_MINT_VERSION),
    reason=f"Runs only against released mints older than {MINIMUM_MINT_VERSION}",
)


@pytest_asyncio.fixture(scope="function")
async def wallet(mint):
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_compatibility",
        name="wallet_compatibility",
    )
    await wallet.load_mint()
    yield wallet


@pytest.mark.asyncio
async def test_unsupported_mint_still_fails(wallet: Wallet):
    """Fails once the wallet works with mints older than MINIMUM_MINT_VERSION
    again, so the minimum in tests/compatibility.py gets lowered."""
    # pydantic's ValidationError has no args, which tests.helpers.assert_err needs.
    with pytest.raises(Exception) as exc_info:
        await wallet.request_mint(64)
    assert BELOW_MINIMUM_ERROR in str(exc_info.value), (
        f"Nutshell {MINT_VERSION} no longer fails as expected below "
        f"{MINIMUM_MINT_VERSION} ({MINIMUM_MINT_VERSION_REFERENCE}): {exc_info.value}"
    )
