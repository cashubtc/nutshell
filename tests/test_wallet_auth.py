import hashlib
import os
import shutil
from pathlib import Path

import pytest
import pytest_asyncio

from cashu.core.base import Unit
from cashu.core.crypto.keys import random_hash
from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import (
    BlindAuthFailedError,
    BlindAuthRateLimitExceededError,
    ClearAuthFailedError,
)
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

    requires_auth = await auth_wallet.init_auth_wallet(
        wallet.mint_info, mint_auth_proofs=False
    )
    assert requires_auth

    # expect JWT (CAT) with format ey*.ey*
    assert auth_wallet.oidc_client.access_token
    assert auth_wallet.oidc_client.access_token.split(".")[0].startswith("ey")
    assert auth_wallet.oidc_client.access_token.split(".")[1].startswith("ey")


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

    await assert_err(auth_wallet.init_auth_wallet(wallet.mint_info), "401 Unauthorized")


@pytest.mark.skipif(
    not settings.mint_require_auth,
    reason="settings.mint_require_auth is False",
)
@pytest.mark.asyncio
async def test_wallet_auth_mint(wallet: Wallet):
    auth_wallet = await WalletAuth.with_db(
        url=wallet.url,
        db=wallet.db.db_location,
        username="asd@asd.com",
        password="asdasd",
    )

    requires_auth = await auth_wallet.init_auth_wallet(wallet.mint_info)
    assert requires_auth

    await auth_wallet.load_proofs()
    assert len(auth_wallet.proofs) == auth_wallet.mint_info.bat_max_mint


@pytest.mark.skipif(
    not settings.mint_require_auth,
    reason="settings.mint_require_auth is False",
)
@pytest.mark.asyncio
async def test_wallet_auth_mint_manually(wallet: Wallet):
    auth_wallet = await WalletAuth.with_db(
        url=wallet.url,
        db=wallet.db.db_location,
        username="asd@asd.com",
        password="asdasd",
    )

    requires_auth = await auth_wallet.init_auth_wallet(
        wallet.mint_info, mint_auth_proofs=False
    )
    assert requires_auth
    assert len(auth_wallet.proofs) == 0

    await auth_wallet.mint_blind_auth()
    assert len(auth_wallet.proofs) == auth_wallet.mint_info.bat_max_mint


@pytest.mark.skipif(
    not settings.mint_require_auth,
    reason="settings.mint_require_auth is False",
)
@pytest.mark.asyncio
async def test_wallet_auth_mint_manually_invalid_cat(wallet: Wallet):
    auth_wallet = await WalletAuth.with_db(
        url=wallet.url,
        db=wallet.db.db_location,
        username="asd@asd.com",
        password="asdasd",
    )

    requires_auth = await auth_wallet.init_auth_wallet(
        wallet.mint_info, mint_auth_proofs=False
    )
    assert requires_auth
    assert len(auth_wallet.proofs) == 0

    # invalidate CAT in the database
    auth_wallet.oidc_client.access_token = random_hash()

    # this is the code executed in auth_wallet.mint_blind_auth():
    clear_auth_token = auth_wallet.oidc_client.access_token
    if not clear_auth_token:
        raise Exception("No clear auth token available.")

    amounts = auth_wallet.mint_info.bat_max_mint * [1]  # 1 AUTH tokens
    secrets = [hashlib.sha256(os.urandom(32)).hexdigest() for _ in amounts]
    rs = [PrivateKey(privkey=os.urandom(32), raw=True) for _ in amounts]
    outputs, rs = auth_wallet._construct_outputs(amounts, secrets, rs)

    # should fail because of invalid CAT
    await assert_err(
        auth_wallet.blind_mint_blind_auth(clear_auth_token, outputs),
        ClearAuthFailedError.detail,
    )


@pytest.mark.skipif(
    not settings.mint_require_auth,
    reason="settings.mint_require_auth is False",
)
@pytest.mark.asyncio
async def test_wallet_auth_invoice(wallet: Wallet):
    # should fail, wallet error
    await assert_err(wallet.mint_quote(10, Unit.sat), "Mint requires blind auth")

    auth_wallet = await WalletAuth.with_db(
        url=wallet.url,
        db=wallet.db.db_location,
        username="asd@asd.com",
        password="asdasd",
    )
    requires_auth = await auth_wallet.init_auth_wallet(wallet.mint_info)
    assert requires_auth

    await auth_wallet.load_proofs()
    assert len(auth_wallet.proofs) == auth_wallet.mint_info.bat_max_mint

    wallet.auth_db = auth_wallet.db
    wallet.auth_keyset_id = auth_wallet.keyset_id

    # should succeed
    await wallet.mint_quote(10, Unit.sat)


@pytest.mark.skipif(
    not settings.mint_require_auth,
    reason="settings.mint_require_auth is False",
)
@pytest.mark.asyncio
async def test_wallet_auth_invoice_invalid_bat(wallet: Wallet):
    # should fail, wallet error
    await assert_err(wallet.mint_quote(10, Unit.sat), "Mint requires blind auth")

    auth_wallet = await WalletAuth.with_db(
        url=wallet.url,
        db=wallet.db.db_location,
        username="asd@asd.com",
        password="asdasd",
    )
    requires_auth = await auth_wallet.init_auth_wallet(wallet.mint_info)
    assert requires_auth

    await auth_wallet.load_proofs()
    assert len(auth_wallet.proofs) == auth_wallet.mint_info.bat_max_mint

    # invalidate blind auth proofs
    for p in auth_wallet.proofs:
        await auth_wallet.db.execute(
            f"UPDATE proofs SET secret = '{random_hash()}' WHERE secret = '{p.secret}'"
        )

    wallet.auth_db = auth_wallet.db
    wallet.auth_keyset_id = auth_wallet.keyset_id

    # blind auth failed
    await assert_err(wallet.mint_quote(10, Unit.sat), BlindAuthFailedError.detail)


@pytest.mark.skipif(
    not settings.mint_require_auth,
    reason="settings.mint_require_auth is False",
)
@pytest.mark.asyncio
async def test_wallet_auth_rate_limit(wallet: Wallet):
    auth_wallet = await WalletAuth.with_db(
        url=wallet.url,
        db=wallet.db.db_location,
        username="asd@asd.com",
        password="asdasd",
    )
    requires_auth = await auth_wallet.init_auth_wallet(
        wallet.mint_info, mint_auth_proofs=False
    )
    assert requires_auth

    errored = False
    for _ in range(100):
        try:
            await auth_wallet.mint_blind_auth()
        except Exception as e:
            assert BlindAuthRateLimitExceededError.detail in str(e)
            errored = True
            break

    assert errored

    # should have minted at least twice
    assert len(auth_wallet.proofs) > auth_wallet.mint_info.bat_max_mint
