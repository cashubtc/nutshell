import asyncio
import copy
import secrets
from typing import List

import pytest
import pytest_asyncio

from cashu.core.base import Proof, Secret, SecretKind, Tags
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.helpers import async_unwrap, sum_proofs
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2
from tests.conftest import SERVER_ENDPOINT, mint


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        if str(exc.args[0]) != msg:
            raise Exception(f"Expected error: {msg}, got: {exc.args[0]}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint):
    wallet1 = Wallet1(SERVER_ENDPOINT, "data/wallet_p2sh_1", "wallet1")
    await migrate_databases(wallet1.db, migrations)
    await wallet1.load_mint()
    wallet1.status()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2(mint):
    wallet2 = Wallet2(SERVER_ENDPOINT, "data/wallet_p2sh_2", "wallet2")
    await migrate_databases(wallet2.db, migrations)
    wallet2.private_key = PrivateKey(secrets.token_bytes(32), raw=True)
    await wallet2.load_mint()
    wallet2.status()
    yield wallet2


@pytest.mark.asyncio
async def test_create_p2pk_pubkey(wallet1: Wallet):
    await wallet1.mint(64)
    pubkey = await wallet1.create_p2pk_pubkey()
    PublicKey(bytes.fromhex(pubkey), raw=True)


@pytest.mark.asyncio
async def test_p2sh(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    _ = await wallet1.create_p2sh_address_and_store()  # receiver side
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8)  # sender side

    frst_proofs, scnd_proofs = await wallet2.redeem(send_proofs)  # receiver side
    assert len(frst_proofs) == 0
    assert len(scnd_proofs) == 1
    assert sum_proofs(scnd_proofs) == 8
    assert wallet2.balance == 8


@pytest.mark.asyncio
async def test_p2sh_receive_with_wrong_wallet(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    wallet1_address = await wallet1.create_p2sh_address_and_store()  # receiver side
    secret_lock = await wallet1.create_p2sh_lock(wallet1_address)  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock
    )  # sender side
    await assert_err(wallet2.redeem(send_proofs), "lock not found.")  # wrong receiver
