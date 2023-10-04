import shutil
from pathlib import Path
from typing import List, Union

import pytest
import pytest_asyncio

from cashu.core.base import Proof
from cashu.core.errors import CashuError, KeysetNotFoundError
from cashu.core.helpers import sum_proofs
from cashu.core.settings import settings
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2
from tests.conftest import SERVER_ENDPOINT


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


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


async def reset_wallet_db(wallet: Wallet):
    await wallet.db.execute("DELETE FROM proofs")
    await wallet.db.execute("DELETE FROM proofs_used")
    await wallet.db.execute("DELETE FROM keysets")
    await wallet._load_mint()


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    wallet1.status()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2(mint):
    wallet2 = await Wallet2.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet2",
        name="wallet2",
    )
    await wallet2.load_mint()
    wallet2.status()
    yield wallet2


@pytest_asyncio.fixture(scope="function")
async def wallet3(mint):
    dirpath = Path("test_data/wallet3")
    if dirpath.exists() and dirpath.is_dir():
        shutil.rmtree(dirpath)

    wallet3 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet3",
        name="wallet3",
    )
    await wallet3.db.execute("DELETE FROM proofs")
    await wallet3.db.execute("DELETE FROM proofs_used")
    await wallet3.load_mint()
    wallet3.status()
    yield wallet3


@pytest.mark.asyncio
async def test_get_keys(wallet1: Wallet):
    assert wallet1.keys.public_keys
    assert len(wallet1.keys.public_keys) == settings.max_order
    keyset = await wallet1._get_keys(wallet1.url)
    assert keyset.id is not None
    assert keyset.id_deprecated == "1cCNIAZ2X/w1"
    assert keyset.id == "d5c08d2006765ffc"
    assert isinstance(keyset.id, str)
    assert len(keyset.id) > 0


@pytest.mark.asyncio
async def test_get_keyset(wallet1: Wallet):
    assert wallet1.keys.public_keys
    assert len(wallet1.keys.public_keys) == settings.max_order
    # let's get the keys first so we can get a keyset ID that we use later
    keys1 = await wallet1._get_keys(wallet1.url)
    # gets the keys of a specific keyset
    assert keys1.id is not None
    assert keys1.public_keys is not None
    keys2 = await wallet1._get_keys_of_keyset(wallet1.url, keys1.id)
    assert keys2.public_keys is not None
    assert len(keys1.public_keys) == len(keys2.public_keys)


@pytest.mark.asyncio
async def test_get_info(wallet1: Wallet):
    info = await wallet1._get_info(wallet1.url)
    assert info.name


@pytest.mark.asyncio
async def test_get_nonexistent_keyset(wallet1: Wallet):
    await assert_err(
        wallet1._get_keys_of_keyset(wallet1.url, "nonexistent"),
        KeysetNotFoundError(),
    )


@pytest.mark.asyncio
async def test_get_keyset_ids(wallet1: Wallet):
    keyset = await wallet1._get_keyset_ids(wallet1.url)
    assert isinstance(keyset, list)
    assert len(keyset) > 0
    assert keyset[-1] == wallet1.keyset_id


@pytest.mark.asyncio
async def test_mint(wallet1: Wallet):
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_mint_amounts(wallet1: Wallet):
    """Mint predefined amounts"""
    invoice = await wallet1.request_mint(64)
    amts = [1, 1, 1, 2, 2, 4, 16]
    await wallet1.mint(amount=sum(amts), split=amts, hash=invoice.hash)
    assert wallet1.balance == 27
    assert wallet1.proof_amounts == amts


@pytest.mark.asyncio
async def test_mint_amounts_wrong_sum(wallet1: Wallet):
    """Mint predefined amounts"""
    amts = [1, 1, 1, 2, 2, 4, 16]
    await assert_err(
        wallet1.mint(amount=sum(amts) + 1, split=amts),
        "split must sum to amount",
    )


@pytest.mark.asyncio
async def test_mint_amounts_wrong_order(wallet1: Wallet):
    """Mint amount that is not part in 2^n"""
    amts = [1, 2, 3]
    await assert_err(
        wallet1.mint(amount=sum(amts), split=[1, 2, 3]),
        f"Can only mint amounts with 2^n up to {2**settings.max_order}.",
    )


@pytest.mark.asyncio
async def test_split(wallet1: Wallet):
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    assert wallet1.balance == 64
    p1, p2 = await wallet1.split(wallet1.proofs, 20)
    assert wallet1.balance == 64
    assert sum_proofs(p1) == 44
    assert [p.amount for p in p1] == [4, 8, 32]
    assert sum_proofs(p2) == 20
    assert [p.amount for p in p2] == [4, 16]
    assert all([p.id == wallet1.keyset_id for p in p1])
    assert all([p.id == wallet1.keyset_id for p in p2])


@pytest.mark.asyncio
async def test_split_to_send(wallet1: Wallet):
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    keep_proofs, spendable_proofs = await wallet1.split_to_send(
        wallet1.proofs, 32, set_reserved=True
    )
    get_spendable = await wallet1._select_proofs_to_send(wallet1.proofs, 32)
    assert keep_proofs == get_spendable

    assert sum_proofs(spendable_proofs) == 32
    assert wallet1.balance == 64
    assert wallet1.available_balance == 32


@pytest.mark.asyncio
async def test_split_more_than_balance(wallet1: Wallet):
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    await assert_err(
        wallet1.split(wallet1.proofs, 128),
        # "Mint Error: inputs do not have same amount as outputs",
        "amount too large.",
    )
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_melt(wallet1: Wallet):
    # mint twice so we have enough to pay the second invoice back
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    assert wallet1.balance == 128
    total_amount, fee_reserve_sat = await wallet1.get_pay_amount_with_fees(invoice.pr)
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, total_amount)

    await wallet1.pay_lightning(
        send_proofs, invoice=invoice.pr, fee_reserve_sat=fee_reserve_sat
    )
    assert wallet1.balance == 128 - total_amount


@pytest.mark.asyncio
async def test_split_to_send_more_than_balance(wallet1: Wallet):
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    await assert_err(
        wallet1.split_to_send(wallet1.proofs, 128, set_reserved=True),
        "balance too low.",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_double_spend(wallet1: Wallet):
    invoice = await wallet1.request_mint(64)
    doublespend = await wallet1.mint(64, hash=invoice.hash)
    await wallet1.split(wallet1.proofs, 20)
    await assert_err(
        wallet1.split(doublespend, 20),
        "Mint Error: Token already spent.",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_duplicate_proofs_double_spent(wallet1: Wallet):
    invoice = await wallet1.request_mint(64)
    doublespend = await wallet1.mint(64, hash=invoice.hash)
    await assert_err(
        wallet1.split(wallet1.proofs + doublespend, 20),
        "Mint Error: proofs already pending.",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_send_and_redeem(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    _, spendable_proofs = await wallet1.split_to_send(
        wallet1.proofs, 32, set_reserved=True
    )
    await wallet2.redeem(spendable_proofs)
    assert wallet2.balance == 32

    assert wallet1.balance == 64
    assert wallet1.available_balance == 32
    await wallet1.invalidate(spendable_proofs)
    assert wallet1.balance == 32
    assert wallet1.available_balance == 32


@pytest.mark.asyncio
async def test_invalidate_unspent_proofs(wallet1: Wallet):
    """Try to invalidate proofs that have not been spent yet. Should not work!"""
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    await wallet1.invalidate(wallet1.proofs)
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_invalidate_unspent_proofs_without_checking(wallet1: Wallet):
    """Try to invalidate proofs that have not been spent yet but force no check."""
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    await wallet1.invalidate(wallet1.proofs, check_spendable=False)
    assert wallet1.balance == 0


@pytest.mark.asyncio
async def test_split_invalid_amount(wallet1: Wallet):
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    await assert_err(
        wallet1.split(wallet1.proofs, -1),
        "amount must be positive.",
    )


@pytest.mark.asyncio
async def test_token_state(wallet1: Wallet):
    invoice = await wallet1.request_mint(64)
    await wallet1.mint(64, hash=invoice.hash)
    assert wallet1.balance == 64
    resp = await wallet1.check_proof_state(wallet1.proofs)
    assert resp.dict()["spendable"]
    assert resp.dict()["pending"]
