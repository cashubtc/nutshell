from typing import Optional

import pytest
import pytest_asyncio

from cashu.core.helpers import sum_proofs
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.split import amount_split
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import get_real_invoice, is_fake, is_regtest, pay_if_regtest


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


def set_ledger_keyset_fees(
    fee_ppk: int, ledger: Ledger, wallet: Optional[Wallet] = None
):
    for keyset in ledger.keysets.values():
        keyset.input_fee_ppk = fee_ppk

    if wallet:
        for wallet_keyset in wallet.keysets.values():
            wallet_keyset.input_fee_ppk = fee_ppk


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
@pytest.mark.skipif_with_fees(is_regtest, reason="only works with FakeWallet")
async def test_wallet_fee(wallet1: Wallet, ledger: Ledger):
    # THIS TEST IS A FAKE, WE SET THE WALLET FEES MANUALLY IN set_ledger_keyset_fees
    # It would be better to test if the wallet can get the fees from the mint itself
    # but the ledger instance does not update the responses from the `mint` that is running in the background
    # so we just pretend here and test really nothing...

    # set fees to 100 ppk
    set_ledger_keyset_fees(100, ledger, wallet1)

    # check if all wallet keysets have the correct fees
    for keyset in wallet1.keysets.values():
        assert keyset.input_fee_ppk == 100


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


@pytest.mark.asyncio
@pytest.mark.skipif_with_fees(is_regtest, reason="only works with FakeWallet")
async def test_melt_internal(wallet1: Wallet, ledger: Ledger):
    # set fees to 100 ppk
    set_ledger_keyset_fees(100, ledger, wallet1)

    # mint twice so we have enough to pay the second invoice back
    invoice = await wallet1.request_mint(128)
    await wallet1.mint(128, id=invoice.id)
    assert wallet1.balance == 128

    # create a mint quote so that we can melt to it internally
    invoice_to_pay = await wallet1.request_mint(64)
    invoice_payment_request = invoice_to_pay.bolt11

    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )
    assert not melt_quote.paid
    assert melt_quote.amount == 64
    assert melt_quote.fee_reserve == 0

    melt_quote_pre_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert not melt_quote_pre_payment.paid, "melt quote should not be paid"

    # let's first try to melt without enough funds
    send_proofs, fees = await wallet1.select_to_send(wallet1.proofs, 63)
    # this should fail because we need 64 + 1 sat fees
    assert sum_proofs(send_proofs) == 64
    await assert_err(
        ledger.melt(proofs=send_proofs, quote=melt_quote.quote),
        "not enough inputs provided for melt",
    )

    # the wallet respects the fees for coin selection
    send_proofs, fees = await wallet1.select_to_send(wallet1.proofs, 64)
    # includes 1 sat fees
    assert sum_proofs(send_proofs) == 65
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post_payment.paid, "melt quote should be paid"


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_melt_external_with_fees(wallet1: Wallet, ledger: Ledger):
    # set fees to 100 ppk
    set_ledger_keyset_fees(100, ledger)

    # mint twice so we have enough to pay the second invoice back
    invoice = await wallet1.request_mint(128)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(128, id=invoice.id)
    assert wallet1.balance == 128

    invoice_dict = get_real_invoice(64)
    invoice_payment_request = invoice_dict["payment_request"]

    mint_quote = await wallet1.melt_quote(invoice_payment_request)
    total_amount = mint_quote.amount + mint_quote.fee_reserve
    send_proofs, fee = await wallet1.select_to_send(wallet1.proofs, total_amount)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )

    melt_quote_pre_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert not melt_quote_pre_payment.paid, "melt quote should not be paid"

    assert not melt_quote.paid, "melt quote should not be paid"
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post_payment.paid, "melt quote should be paid"
