import pytest
import pytest_asyncio

from cashu.core.split import amount_split
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        if msg not in str(exc.args[0]):
            raise Exception(f"Expected error: {msg}, got: {exc.args[0]}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1


def set_ledger_keyset_fees(fee_ppk: int, ledger: Ledger):
    for keyset in ledger.keysets.values():
        keyset.input_fee_ppk = fee_ppk


@pytest.mark.asyncio
async def test_get_fees_for_proofs(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, split=[1] * 64, id=invoice.id)

    # two proofs

    set_ledger_keyset_fees(100, ledger)
    proofs = [wallet1.proofs[0], wallet1.proofs[1]]
    fees = ledger.get_fees_for_proofs(proofs)
    assert fees == 1

    set_ledger_keyset_fees(1234, ledger)
    fees = ledger.get_fees_for_proofs(proofs)
    assert fees == 3

    set_ledger_keyset_fees(0, ledger)
    fees = ledger.get_fees_for_proofs(proofs)
    assert fees == 0

    set_ledger_keyset_fees(1, ledger)
    fees = ledger.get_fees_for_proofs(proofs)
    assert fees == 1

    # ten proofs

    ten_proofs = wallet1.proofs[:10]
    set_ledger_keyset_fees(100, ledger)
    fees = ledger.get_fees_for_proofs(ten_proofs)
    assert fees == 1

    set_ledger_keyset_fees(101, ledger)
    fees = ledger.get_fees_for_proofs(ten_proofs)
    assert fees == 2

    # three proofs

    three_proofs = wallet1.proofs[:3]
    set_ledger_keyset_fees(333, ledger)
    fees = ledger.get_fees_for_proofs(three_proofs)
    assert fees == 1

    set_ledger_keyset_fees(334, ledger)
    fees = ledger.get_fees_for_proofs(three_proofs)
    assert fees == 2


@pytest.mark.asyncio
async def test_split_with_fees(wallet1: Wallet, ledger: Ledger):
    # set fees to 100 ppk
    set_ledger_keyset_fees(100, ledger)
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)

    send_proofs, _ = await wallet1.select_to_send(wallet1.proofs, 10)
    fees = ledger.get_fees_for_proofs(send_proofs)
    assert fees == 1
    outputs = await wallet1.construct_outputs(amount_split(9))

    promises = await ledger.split(proofs=send_proofs, outputs=outputs)
    assert len(promises) == len(outputs)
    assert [p.amount for p in promises] == [p.amount for p in outputs]


@pytest.mark.asyncio
async def test_split_with_high_fees(wallet1: Wallet, ledger: Ledger):
    # set fees to 100 ppk
    set_ledger_keyset_fees(1234, ledger)
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)

    send_proofs, _ = await wallet1.select_to_send(wallet1.proofs, 10)
    fees = ledger.get_fees_for_proofs(send_proofs)
    assert fees == 3
    outputs = await wallet1.construct_outputs(amount_split(7))

    promises = await ledger.split(proofs=send_proofs, outputs=outputs)
    assert len(promises) == len(outputs)
    assert [p.amount for p in promises] == [p.amount for p in outputs]


@pytest.mark.asyncio
async def test_split_not_enough_fees(wallet1: Wallet, ledger: Ledger):
    # set fees to 100 ppk
    set_ledger_keyset_fees(100, ledger)
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)

    send_proofs, _ = await wallet1.select_to_send(wallet1.proofs, 10)
    fees = ledger.get_fees_for_proofs(send_proofs)
    assert fees == 1
    # with 10 sat input, we request 10 sat outputs but fees are 1 sat so the swap will fail
    outputs = await wallet1.construct_outputs(amount_split(10))

    await assert_err(
        ledger.split(proofs=send_proofs, outputs=outputs), "are not balanced"
    )
