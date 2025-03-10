import asyncio

import bolt11
import pytest
import pytest_asyncio

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Method, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    SLEEP_TIME,
    cancel_invoice,
    get_hold_invoice,
    get_real_invoice,
    get_real_invoice_cln,
    is_fake,
    pay_if_regtest,
    pay_real_invoice,
    settle_invoice,
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
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_lightning_create_invoice(ledger: Ledger):
    invoice = await ledger.backends[Method.bolt11][Unit.sat].create_invoice(
        Amount(Unit.sat, 1000)
    )
    assert invoice.ok
    assert invoice.payment_request
    assert invoice.checking_id

    # TEST 2: check the invoice status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_invoice_status(
        invoice.checking_id
    )
    assert status.pending

    # settle the invoice
    await pay_if_regtest(invoice.payment_request)

    # TEST 3: check the invoice status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_invoice_status(
        invoice.checking_id
    )
    assert status.settled


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_lightning_create_invoice_balance_change(ledger: Ledger):
    invoice_amount = 1000  # sat
    invoice = await ledger.backends[Method.bolt11][Unit.sat].create_invoice(
        Amount(Unit.sat, invoice_amount)
    )
    assert invoice.ok
    assert invoice.payment_request
    assert invoice.checking_id

    # TEST 2: check the invoice status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_invoice_status(
        invoice.checking_id
    )
    assert status.pending

    status = await ledger.backends[Method.bolt11][Unit.sat].status()
    balance_before = status.balance

    # settle the invoice
    await pay_if_regtest(invoice.payment_request)

    # TEST 3: check the invoice status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_invoice_status(
        invoice.checking_id
    )
    assert status.settled

    status = await ledger.backends[Method.bolt11][Unit.sat].status()
    balance_after = status.balance

    assert balance_after == balance_before + invoice_amount


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_lightning_get_payment_quote(ledger: Ledger):
    invoice_dict = get_real_invoice(64)
    request = invoice_dict["payment_request"]
    payment_quote = await ledger.backends[Method.bolt11][Unit.sat].get_payment_quote(
        PostMeltQuoteRequest(request=request, unit=Unit.sat.name)
    )
    assert payment_quote.amount == Amount(Unit.sat, 64)
    assert payment_quote.checking_id


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_lightning_pay_invoice(ledger: Ledger):
    invoice_dict = get_real_invoice(64)
    request = invoice_dict["payment_request"]
    quote = MeltQuote(
        quote="test",
        method=Method.bolt11.name,
        unit=Unit.sat.name,
        state=MeltQuoteState.unpaid,
        request=request,
        checking_id="test",
        amount=64,
        fee_reserve=0,
    )
    payment = await ledger.backends[Method.bolt11][Unit.sat].pay_invoice(quote, 1000)
    assert payment.settled
    assert payment.preimage
    assert payment.checking_id
    assert not payment.error_message

    # TEST 2: check the payment status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_payment_status(
        payment.checking_id
    )
    assert status.settled
    assert status.preimage
    assert not status.error_message


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_lightning_pay_invoice_failure(ledger: Ledger):
    # create an invoice with the external CLN node and pay it with the external LND – so that our mint backend can't pay it
    request = get_real_invoice_cln(64)
    # pay the invoice so that the attempt later fails
    pay_real_invoice(request)

    # we call get_payment_quote to get a checking_id that we will use to check for the failed pending state later with get_payment_status
    payment_quote = await ledger.backends[Method.bolt11][Unit.sat].get_payment_quote(
        PostMeltQuoteRequest(request=request, unit=Unit.sat.name)
    )
    checking_id = payment_quote.checking_id

    # TEST 1: check the payment status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_payment_status(
        checking_id
    )
    assert status.unknown

    # TEST 2: pay the invoice
    quote = MeltQuote(
        quote="test",
        method=Method.bolt11.name,
        unit=Unit.sat.name,
        state=MeltQuoteState.unpaid,
        request=request,
        checking_id="test",
        amount=64,
        fee_reserve=0,
    )
    payment = await ledger.backends[Method.bolt11][Unit.sat].pay_invoice(quote, 1000)

    assert payment.failed
    assert not payment.preimage
    assert payment.error_message
    assert not payment.checking_id

    # TEST 3: check the payment status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_payment_status(
        checking_id
    )

    assert status.failed or status.unknown
    assert not status.preimage


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_lightning_pay_invoice_pending_success(ledger: Ledger):
    # create a hold invoice
    preimage, invoice_dict = get_hold_invoice(64)
    request = str(invoice_dict["payment_request"])

    # we call get_payment_quote to get a checking_id that we will use to check for the failed pending state later with get_payment_status
    payment_quote = await ledger.backends[Method.bolt11][Unit.sat].get_payment_quote(
        PostMeltQuoteRequest(request=request, unit=Unit.sat.name)
    )
    checking_id = payment_quote.checking_id

    # pay the invoice
    quote = MeltQuote(
        quote="test",
        method=Method.bolt11.name,
        unit=Unit.sat.name,
        state=MeltQuoteState.unpaid,
        request=request,
        checking_id=checking_id,
        amount=64,
        fee_reserve=0,
    )

    async def pay():
        payment = await ledger.backends[Method.bolt11][Unit.sat].pay_invoice(
            quote, 1000
        )
        return payment

    task = asyncio.create_task(pay())
    await asyncio.sleep(SLEEP_TIME)

    # check the payment status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_payment_status(
        quote.checking_id
    )
    assert status.pending

    # settle the invoice
    settle_invoice(preimage=preimage)
    await asyncio.sleep(SLEEP_TIME)

    # collect the payment
    payment = await task
    assert payment.settled
    assert payment.preimage
    assert payment.checking_id
    assert not payment.error_message

    # check the payment status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_payment_status(
        quote.checking_id
    )
    assert status.settled
    assert status.preimage
    assert not status.error_message


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_lightning_pay_invoice_pending_failure(ledger: Ledger):
    # create a hold invoice
    preimage, invoice_dict = get_hold_invoice(64)
    request = str(invoice_dict["payment_request"])
    payment_hash = bolt11.decode(request).payment_hash

    # we call get_payment_quote to get a checking_id that we will use to check for the failed pending state later with get_payment_status
    payment_quote = await ledger.backends[Method.bolt11][Unit.sat].get_payment_quote(
        PostMeltQuoteRequest(request=request, unit=Unit.sat.name)
    )
    checking_id = payment_quote.checking_id

    # pay the invoice
    quote = MeltQuote(
        quote="test",
        method=Method.bolt11.name,
        unit=Unit.sat.name,
        state=MeltQuoteState.unpaid,
        request=request,
        checking_id=checking_id,
        amount=64,
        fee_reserve=0,
    )

    async def pay():
        payment = await ledger.backends[Method.bolt11][Unit.sat].pay_invoice(
            quote, 1000
        )
        return payment

    task = asyncio.create_task(pay())
    await asyncio.sleep(SLEEP_TIME)

    # check the payment status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_payment_status(
        quote.checking_id
    )
    assert status.pending

    # cancel the invoice
    cancel_invoice(payment_hash)
    await asyncio.sleep(SLEEP_TIME)

    # collect the payment
    payment = await task
    assert payment.failed
    assert not payment.preimage
    # assert payment.error_message

    # check the payment status
    status = await ledger.backends[Method.bolt11][Unit.sat].get_payment_status(
        quote.checking_id
    )
    assert (
        status.failed or status.unknown
    )  # some backends send unknown instead of failed if they can't find the payment
    assert not status.preimage
    # assert status.error_message


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_pending_quote(wallet: Wallet, ledger: Ledger):
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.swap_to_send(wallet.proofs, total_amount)
    asyncio.create_task(ledger.melt(proofs=send_proofs, quote=quote.quote))
    # asyncio.create_task(
    #     wallet.melt(
    #         proofs=send_proofs,
    #         invoice=invoice_payment_request,
    #         fee_reserve_sat=quote.fee_reserve,
    #         quote_id=quote.quote,
    #     )
    # )
    await asyncio.sleep(SLEEP_TIME)

    # expect that melt quote is still pending
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes

    # expect that proofs are still pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
    assert all([s.pending for s in states])

    # only now settle the invoice
    settle_invoice(preimage=preimage)
    await asyncio.sleep(SLEEP_TIME)

    # expect that proofs are now spent
    states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
    assert all([s.spent for s in states])

    # expect that no melt quote is pending
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes
