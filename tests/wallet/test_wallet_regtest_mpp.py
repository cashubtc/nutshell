import asyncio
import threading
from typing import List

import bolt11
import pytest
import pytest_asyncio

from cashu.core.base import MeltQuote, MeltQuoteState, Method, Proof
from cashu.lightning.base import PaymentResponse
from cashu.lightning.clnrest import CLNRestWallet
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    SLEEP_TIME,
    assert_err,
    cancel_invoice,
    get_hold_invoice,
    is_fake,
    partial_pay_real_invoice,
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
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_pay_mpp(wallet: Wallet, ledger: Ledger):
    # make sure that mpp is supported by the bolt11-sat backend
    if not ledger.backends[Method["bolt11"]][wallet.unit].supports_mpp:
        pytest.skip("backend does not support mpp")

    # make sure wallet knows the backend supports mpp
    assert wallet.mint_info.supports_mpp("bolt11", wallet.unit)

    # top up wallet twice so we have enough for two payments
    topup_mint_quote = await wallet.request_mint(128)
    await pay_if_regtest(topup_mint_quote.request)
    proofs1 = await wallet.mint(128, quote_id=topup_mint_quote.quote)
    assert wallet.balance == 128

    # this is the invoice we want to pay in two parts
    preimage, invoice_dict = get_hold_invoice(64)
    invoice_payment_request = str(invoice_dict["payment_request"])

    async def _mint_pay_mpp(invoice: str, amount: int, proofs: List[Proof]):
        # wallet pays 32 sat of the invoice
        quote = await wallet.melt_quote(invoice, amount_msat=amount * 1000)
        assert quote.amount == amount
        await wallet.melt(
            proofs,
            invoice,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )

    def mint_pay_mpp(invoice: str, amount: int, proofs: List[Proof]):
        asyncio.run(_mint_pay_mpp(invoice, amount, proofs))

    # call pay_mpp twice in parallel to pay the full invoice
    t1 = threading.Thread(
        target=mint_pay_mpp, args=(invoice_payment_request, 32, proofs1)
    )
    t2 = threading.Thread(
        target=partial_pay_real_invoice, args=(invoice_payment_request, 32, 1)
    )

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert wallet.balance == 64


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_pay_mpp_incomplete_payment(wallet: Wallet, ledger: Ledger):
    # make sure that mpp is supported by the bolt11-sat backend
    if not ledger.backends[Method["bolt11"]][wallet.unit].supports_mpp:
        pytest.skip("backend does not support mpp")

    # This test cannot be done with CLN because we only have one mint
    # and CLN hates multiple partial payment requests
    if isinstance(ledger.backends[Method["bolt11"]][wallet.unit], CLNRestWallet):
        pytest.skip("CLN cannot perform this test")

    # make sure wallet knows the backend supports mpp
    assert wallet.mint_info.supports_mpp("bolt11", wallet.unit)

    # top up wallet twice so we have enough for three payments
    topup_mint_quote = await wallet.request_mint(128)
    await pay_if_regtest(topup_mint_quote.request)
    proofs1 = await wallet.mint(128, quote_id=topup_mint_quote.quote)
    assert wallet.balance == 128

    topup_mint_quote = await wallet.request_mint(128)
    await pay_if_regtest(topup_mint_quote.request)
    proofs2 = await wallet.mint(128, quote_id=topup_mint_quote.quote)
    assert wallet.balance == 256

    topup_mint_quote = await wallet.request_mint(128)
    await pay_if_regtest(topup_mint_quote.request)
    proofs3 = await wallet.mint(128, quote_id=topup_mint_quote.quote)
    assert wallet.balance == 384

    # this is the invoice we want to pay in two parts
    preimage, invoice_dict = get_hold_invoice(64)
    invoice_payment_request = str(invoice_dict["payment_request"])

    async def pay_mpp(amount: int, proofs: List[Proof], delay: float = 0.0):
        await asyncio.sleep(delay)
        # wallet pays 32 sat of the invoice
        quote = await wallet.melt_quote(
            invoice_payment_request, amount_msat=amount * 1000
        )
        assert quote.amount == amount
        await wallet.melt(
            proofs,
            invoice_payment_request,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )

    # instead: call pay_mpp twice in the background, sleep for a bit, then check if the payment was successful (it should not be)
    asyncio.create_task(pay_mpp(32, proofs1))
    asyncio.create_task(pay_mpp(16, proofs2, delay=0.5))
    await asyncio.sleep(2)

    # payment is still pending because the full amount has not been paid
    assert wallet.balance == 384

    # send the remaining 16 sat to complete the payment
    asyncio.create_task(pay_mpp(16, proofs3, delay=0.5))
    await asyncio.sleep(2)

    assert wallet.balance <= 384 - 64


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_internal_mpp_melt_quotes(wallet: Wallet, ledger: Ledger):
    # make sure that mpp is supported by the bolt11-sat backend
    if not ledger.backends[Method["bolt11"]][wallet.unit].supports_mpp:
        pytest.skip("backend does not support mpp")

    # create a mint quote
    mint_quote = await wallet.request_mint(128)

    # try and create a multi-part melt quote
    await assert_err(
        wallet.melt_quote(mint_quote.request, 100 * 1000), "internal mpp not allowed"
    )


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_pay_mpp_cancel_payment(wallet: Wallet, ledger: Ledger):
    # make sure that mpp is supported by the bolt11-sat backend
    if not ledger.backends[Method["bolt11"]][wallet.unit].supports_mpp:
        pytest.skip("backend does not support mpp")

    # make sure wallet knows the backend supports mpp
    assert wallet.mint_info.supports_mpp("bolt11", wallet.unit)

    # top up wallet so we have enough for the payment
    topup_mint_quote = await wallet.request_mint(128)
    await pay_if_regtest(topup_mint_quote.request)
    proofs1 = await wallet.mint(128, quote_id=topup_mint_quote.quote)
    assert wallet.balance == 128

    # create a hold invoice that we can cancel
    preimage, invoice_dict = get_hold_invoice(64)
    invoice_payment_request = str(invoice_dict.get("payment_request", ""))
    invoice_obj = bolt11.decode(invoice_payment_request)
    payment_hash = invoice_obj.payment_hash

    async def _mint_pay_mpp(invoice: str, amount: int, proofs: List[Proof]):
        # wallet pays 32 sat of the invoice
        quote = await wallet.melt_quote(invoice, amount_msat=amount * 1000)
        assert quote.amount == amount
        await wallet.melt(
            proofs,
            invoice,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )

    def mint_pay_mpp(invoice: str, amount: int, proofs: List[Proof]):
        asyncio.run(_mint_pay_mpp(invoice, amount, proofs))

    # start the MPP payment
    t1 = threading.Thread(
        target=mint_pay_mpp, args=(invoice_payment_request, 32, proofs1)
    )
    t1.start()
    await asyncio.sleep(SLEEP_TIME)

    # cancel the invoice
    cancel_invoice(payment_hash)
    await asyncio.sleep(SLEEP_TIME)

    # check the payment status
    status = await ledger.backends[Method["bolt11"]][wallet.unit].get_payment_status(
        payment_hash
    )
    assert status.failed  # some backends return unknown instead of failed
    assert not status.preimage  # no preimage since payment failed

    # check that the proofs are unspent since payment failed
    states = await wallet.check_proof_state(proofs1)
    assert all([s.unspent for s in states.states])


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_pay_mpp_cancel_payment_pay_partial_invoice(
    wallet: Wallet, ledger: Ledger
):
    # create a hold invoice that we can cancel
    preimage, invoice_dict = get_hold_invoice(64)
    invoice_payment_request = str(invoice_dict.get("payment_request", ""))
    invoice_obj = bolt11.decode(invoice_payment_request)
    payment_hash = invoice_obj.payment_hash

    # Use a shared container to store the result
    result_container = []

    async def _mint_pay_mpp(invoice: str, amount: int) -> PaymentResponse:
        ret = await ledger.backends[Method["bolt11"]][wallet.unit].pay_invoice(
            MeltQuote(
                request=invoice,
                amount=amount,
                fee_reserve=0,
                quote="",
                method="bolt11",
                checking_id="",
                unit=wallet.unit.name,
                state=MeltQuoteState.pending,
            ),
            0,
        )
        return ret

    # Create a wrapper function that will store the result
    def thread_func():
        result = asyncio.run(_mint_pay_mpp(invoice_payment_request, 32))
        result_container.append(result)

    t1 = threading.Thread(target=thread_func)
    t1.start()
    await asyncio.sleep(SLEEP_TIME)

    # cancel the invoice
    cancel_invoice(payment_hash)
    await asyncio.sleep(SLEEP_TIME)

    t1.join()
    # Get the result from the container
    assert result_container[0].failed
