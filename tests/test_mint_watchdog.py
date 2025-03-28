import pytest
import pytest_asyncio

from cashu.core.base import Amount, MeltQuoteState, Method, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    get_real_invoice,
    is_fake,
    pay_if_regtest,
)


@pytest_asyncio.fixture(scope="function")
async def wallet():
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet",
        name="wallet",
    )
    await wallet.load_mint()
    yield wallet


@pytest.mark.asyncio
async def test_check_balances_and_abort(ledger: Ledger):
    ok = await ledger.check_balances_and_abort(
        ledger.backends[Method.bolt11][Unit.sat],
        None,
        Amount(Unit.sat, 0),
        Amount(Unit.sat, 0),
        Amount(Unit.sat, 0),
    )
    assert ok


@pytest.mark.asyncio
async def test_balance_update_on_mint(wallet: Wallet, ledger: Ledger):
    balance_before, fees_paid_before = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    balance_after, fees_paid_after = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )
    assert balance_after == balance_before + 64
    assert fees_paid_after == fees_paid_before


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_melt_internal(wallet: Wallet, ledger: Ledger):
    settings.fakewallet_brr = False
    # mint twice so we have enough to pay the second invoice back
    mint_quote = await wallet.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(128, quote_id=mint_quote.quote)
    assert wallet.balance == 128

    balance_before, fees_paid_before = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )

    # create a mint quote so that we can melt to it internally
    payment_amount = 64
    mint_quote_to_pay = await wallet.request_mint(payment_amount)
    invoice_payment_request = mint_quote_to_pay.request

    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )

    if not settings.debug_mint_only_deprecated:
        melt_quote_response_pre_payment = await wallet.get_melt_quote(melt_quote.quote)
        assert (
            not melt_quote_response_pre_payment.state == MeltQuoteState.paid.value
        ), "melt quote should not be paid"
        assert melt_quote_response_pre_payment.amount == payment_amount

    melt_quote_pre_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert not melt_quote_pre_payment.paid, "melt quote should not be paid"
    assert melt_quote_pre_payment.unpaid

    keep_proofs, send_proofs = await wallet.swap_to_send(wallet.proofs, payment_amount)
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)
    await wallet.invalidate(send_proofs, check_spendable=True)
    assert wallet.balance == 64

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post_payment.paid, "melt quote should be paid"

    balance_after, fees_paid_after = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )

    # balance should have dropped
    assert balance_after == balance_before - payment_amount
    assert fees_paid_after == fees_paid_before

    # now mint
    await wallet.mint(payment_amount, quote_id=mint_quote_to_pay.quote)
    assert wallet.balance == 128

    balance_after, fees_paid_after = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )

    # balance should be back
    assert balance_after == balance_before
    assert fees_paid_after == fees_paid_before


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_balance_update_on_melt_external(wallet: Wallet, ledger: Ledger):
    # mint twice so we have enough to pay the second invoice back
    mint_quote = await wallet.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(128, quote_id=mint_quote.quote)
    assert wallet.balance == 128

    balance_before, fees_paid_before = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )

    invoice_dict = get_real_invoice(64)
    invoice_payment_request = invoice_dict["payment_request"]

    mint_quote = await wallet.melt_quote(invoice_payment_request)

    total_amount = mint_quote.amount + mint_quote.fee_reserve
    keep_proofs, send_proofs = await wallet.swap_to_send(wallet.proofs, total_amount)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )

    if not settings.debug_mint_only_deprecated:
        melt_quote_response_pre_payment = await wallet.get_melt_quote(melt_quote.quote)
        assert (
            melt_quote_response_pre_payment.state == MeltQuoteState.unpaid.value
        ), "melt quote should not be paid"
        assert melt_quote_response_pre_payment.amount == melt_quote.amount

    melt_quote_resp = await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)
    fees_paid = melt_quote.fee_reserve - (
        sum([b.amount for b in melt_quote_resp.change]) if melt_quote_resp.change else 0
    )

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post_payment.paid, "melt quote should be paid"

    balance_after, fees_paid_after = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )
    assert balance_after == balance_before - 64 - fees_paid
    assert fees_paid_after == fees_paid_before
