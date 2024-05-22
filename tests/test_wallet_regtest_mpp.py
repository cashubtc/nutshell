import asyncio
from typing import List

import pytest
import pytest_asyncio

from cashu.core.base import Method, Proof
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
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_pay_mpp(wallet: Wallet, ledger: Ledger):
    # make sure that mpp is supported by the bolt11-sat backend
    if not ledger.backends[Method["bolt11"]][wallet.unit].supports_mpp:
        pytest.skip("backend does not support mpp")

    # make sure wallet knows the backend supports mpp
    assert wallet.mint_info.supports_mpp("bolt11", wallet.unit)

    # top up wallet twice so we have enough for two payments
    topup_invoice = await wallet.request_mint(128)
    pay_if_regtest(topup_invoice.bolt11)
    proofs1 = await wallet.mint(128, id=topup_invoice.id)
    assert wallet.balance == 128

    topup_invoice = await wallet.request_mint(128)
    pay_if_regtest(topup_invoice.bolt11)
    proofs2 = await wallet.mint(128, id=topup_invoice.id)
    assert wallet.balance == 256

    # this is the invoice we want to pay in two parts
    invoice_dict = get_real_invoice(64)
    invoice_payment_request = invoice_dict["payment_request"]

    async def pay_mpp(amount: int, proofs: List[Proof], delay: float = 0.0):
        await asyncio.sleep(delay)
        # wallet pays 32 sat of the invoice
        quote = await wallet.melt_quote(invoice_payment_request, amount=32)
        assert quote.amount == amount
        await wallet.melt(
            proofs,
            invoice_payment_request,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )

    # call pay_mpp twice in parallel to pay the full invoice
    # we delay the second payment so that the wallet doesn't derive the same blindedmessages twice due to a race condition
    await asyncio.gather(pay_mpp(32, proofs1), pay_mpp(32, proofs2, delay=0.5))

    assert wallet.balance <= 256 - 64


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_pay_mpp_incomplete_payment(wallet: Wallet, ledger: Ledger):
    # make sure that mpp is supported by the bolt11-sat backend
    if not ledger.backends[Method["bolt11"]][wallet.unit].supports_mpp:
        pytest.skip("backend does not support mpp")

    # make sure wallet knows the backend supports mpp
    assert wallet.mint_info.supports_mpp("bolt11", wallet.unit)

    # top up wallet twice so we have enough for two payments
    topup_invoice = await wallet.request_mint(128)
    pay_if_regtest(topup_invoice.bolt11)
    proofs1 = await wallet.mint(128, id=topup_invoice.id)
    assert wallet.balance == 128

    topup_invoice = await wallet.request_mint(128)
    pay_if_regtest(topup_invoice.bolt11)
    proofs2 = await wallet.mint(128, id=topup_invoice.id)
    assert wallet.balance == 256

    # this is the invoice we want to pay in two parts
    invoice_dict = get_real_invoice(64)
    invoice_payment_request = invoice_dict["payment_request"]

    async def pay_mpp(amount: int, proofs: List[Proof], delay: float = 0.0):
        await asyncio.sleep(delay)
        # wallet pays 32 sat of the invoice
        quote = await wallet.melt_quote(invoice_payment_request, amount=32)
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

    assert wallet.balance == 256
