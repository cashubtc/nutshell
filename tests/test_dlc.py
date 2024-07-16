from hashlib import sha256
from random import randint, shuffle
from cashu.lightning.base import InvoiceResponse, PaymentStatus
from cashu.wallet.wallet import Wallet
from cashu.core.secret import Secret, SecretKind
from cashu.core.errors import CashuError
from tests.conftest import SERVER_ENDPOINT
from hashlib import sha256
from tests.helpers import (
    pay_if_regtest
)

import pytest
import pytest_asyncio
from loguru import logger

from typing import Union
from cashu.core.crypto.dlc import merkle_root, merkle_verify, sorted_merkle_hash

@pytest_asyncio.fixture(scope="function")
async def wallet():
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet",
        name="wallet",
    )
    await wallet.load_mint()
    yield wallet

async def assert_err(f, msg: Union[str, CashuError]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        error_message: str = str(exc.args[0])
        if isinstance(msg, CashuError):
            if msg.detail not in error_message:
                raise Exception(
                    f"CashuError. Expected error: {msg.detail}, got: {error_message}"
                )
            return
        if msg not in error_message:
            raise Exception(f"Expected error: {msg}, got: {error_message}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


@pytest.mark.asyncio
async def test_merkle_hash():
    data = [b'\x01', b'\x02']
    target = '25dfd29c09617dcc9852281c030e5b3037a338a4712a42a21c907f259c6412a0'
    h = sorted_merkle_hash(data[1], data[0])
    assert h.hex() == target, f'sorted_merkle_hash test fail: {h.hex() = }'
    h = sorted_merkle_hash(data[0], data[1])
    assert h.hex() == target, f'sorted_merkle_hash reverse test fail: {h.hex() = }'

@pytest.mark.asyncio
async def test_merkle_root():
    target = '0ee849f3b077380cd2cf5c76c6d63bcaa08bea89c1ef9914e5bc86c174417cb3'
    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(16)]
    root, _ = merkle_root(leafs)
    assert root.hex() == target, f"merkle_root test fail: {root.hex() = }"

@pytest.mark.asyncio
async def test_merkle_verify():
    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(16)]
    root, branch_hashes = merkle_root(leafs, 0)
    assert merkle_verify(root, leafs[0], branch_hashes), "merkle_verify test fail"

    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(53)]
    root, branch_hashes = merkle_root(leafs, 0)
    assert merkle_verify(root, leafs[0], branch_hashes), "merkle_verify test fail"

    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(18)]
    shuffle(leafs)
    index = randint(0, len(leafs)-1)
    root, branch_hashes = merkle_root(leafs, index)
    assert merkle_verify(root, leafs[index], branch_hashes), "merkle_verify test fail"

@pytest.mark.asyncio
async def test_swap_for_dlc_locked(wallet: Wallet):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)
    root_hash = sha256("TESTING".encode()).hexdigest()
    threshold = 1000
    _, dlc_locked = await wallet.split(minted, 64, dlc_data=(root_hash, threshold))
    print(f"{dlc_locked = }")
    assert wallet.balance == 64
    assert wallet.available_balance == 64
    assert all([Secret.deserialize(p.secret).kind == SecretKind.SCT.value for p in dlc_locked])

@pytest.mark.asyncio
async def test_unlock_dlc_locked(wallet: Wallet):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)
    root_hash = sha256("TESTING".encode()).hexdigest()
    threshold = 1000
    _, dlc_locked = await wallet.split(minted, 64, dlc_data=(root_hash, threshold))
    _, unlocked = await wallet.split(dlc_locked, 64)
    print(f"{unlocked = }")
    assert wallet.balance == 64
    assert wallet.available_balance == 64
    assert all([bytes.fromhex(p.secret) for p in unlocked])

@pytest.mark.asyncio
async def test_partial_swap_for_dlc_locked(wallet: Wallet):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)
    root_hash = sha256("TESTING".encode()).hexdigest()
    threshold = 1000
    kept, dlc_locked = await wallet.split(minted, 15, dlc_data=(root_hash, threshold))
    assert wallet.balance == 64
    assert wallet.available_balance == 64
    assert all([bytes.fromhex(p.secret) for p in kept])
    assert all([Secret.deserialize(p.secret).kind == SecretKind.SCT.value for p in dlc_locked])

@pytest.mark.asyncio
async def test_cheat1_spend_locked_proofs(wallet: Wallet):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)
    root_hash = sha256("TESTING".encode()).hexdigest()
    threshold = 1000
    _, dlc_locked = await wallet.split(minted, 64, dlc_data=(root_hash, threshold))
    
    # We pretend we don't know the backup secret, and try to spend the proofs
    # with the DLC leaf secret instead
    for p in dlc_locked:
        p.all_spending_conditions = [p.all_spending_conditions[0]]
    strerror = "Mint Error: validation of input spending conditions failed. (Code: 11000)"
    await assert_err(wallet.split(dlc_locked, 64), strerror)