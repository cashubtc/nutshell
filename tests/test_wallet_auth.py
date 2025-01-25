import shutil
from pathlib import Path

import pytest
import pytest_asyncio

from cashu.core.settings import settings
from cashu.wallet.auth.auth import WalletAuth
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import assert_err


@pytest_asyncio.fixture(scope="function")
async def wallet():
    dirpath = Path("test_data/wallet")
    if dirpath.exists() and dirpath.is_dir():
        shutil.rmtree(dirpath)
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet",
        name="wallet",
    )
    await wallet.load_mint()
    yield wallet


@pytest.mark.skipif(
    not settings.mint_require_auth,
    reason="settings.mint_require_auth is False",
)
@pytest.mark.asyncio
async def test_wallet_auth_password(wallet: Wallet):
    auth_wallet = await WalletAuth.with_db(
        url=wallet.url,
        db=wallet.db.db_location,
        username="asd@asd.com",
        password="asdasd",
    )

    requires_auth = await auth_wallet.init_wallet(wallet.mint_info)
    assert requires_auth


@pytest.mark.skipif(
    not settings.mint_require_auth,
    reason="settings.mint_require_auth is False",
)
@pytest.mark.asyncio
async def test_wallet_auth_wrong_password(wallet: Wallet):
    auth_wallet = await WalletAuth.with_db(
        url=wallet.url,
        db=wallet.db.db_location,
        username="asd@asd.com",
        password="wrong_password",
    )

    await assert_err(auth_wallet.init_wallet(wallet.mint_info), "401 Unauthorized")
