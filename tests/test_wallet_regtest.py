import asyncio

import bolt11
import pytest
import pytest_asyncio

from cashu.core.base import ProofSpentState
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    SLEEP_TIME,
    cancel_invoice,
    get_hold_invoice,
    is_fake,
    pay_if_regtest,
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
async def test_regtest_pending_quote(wallet: Wallet, ledger: Ledger):
    # fill wallet
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    await wallet.mint(64, id=invoice.id)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.split_to_send(wallet.proofs, total_amount)
    asyncio.create_task(
        wallet.melt(
            proofs=send_proofs,
            invoice=invoice_payment_request,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )
    )
    await asyncio.sleep(SLEEP_TIME)

    states = await wallet.check_proof_state(send_proofs)
    assert all([s.state == ProofSpentState.pending for s in states.states])

    settle_invoice(preimage=preimage)

    await asyncio.sleep(SLEEP_TIME)

    states = await wallet.check_proof_state(send_proofs)
    assert all([s.state == ProofSpentState.spent for s in states.states])


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_failed_quote(wallet: Wallet, ledger: Ledger):
    # fill wallet
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    await wallet.mint(64, id=invoice.id)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])
    invoice_obj = bolt11.decode(invoice_payment_request)
    preimage_hash = invoice_obj.payment_hash

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.split_to_send(wallet.proofs, total_amount)
    asyncio.create_task(
        wallet.melt(
            proofs=send_proofs,
            invoice=invoice_payment_request,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )
    )
    await asyncio.sleep(SLEEP_TIME)

    states = await wallet.check_proof_state(send_proofs)
    assert all([s.state == ProofSpentState.pending for s in states.states])

    cancel_invoice(preimage_hash=preimage_hash)

    await asyncio.sleep(SLEEP_TIME)

    states = await wallet.check_proof_state(send_proofs)
    assert all([s.state == ProofSpentState.unspent for s in states.states])
