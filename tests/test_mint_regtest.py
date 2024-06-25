import asyncio

import pytest
import pytest_asyncio

from cashu.core.base import SpentState
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    SLEEP_TIME,
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
    pay_if_regtest(invoice.bolt11)
    await wallet.mint(64, id=invoice.id)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.split_to_send(wallet.proofs, total_amount)
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
    assert all([s.state == SpentState.pending for s in states])

    # only now settle the invoice
    settle_invoice(preimage=preimage)
    await asyncio.sleep(SLEEP_TIME)

    # expect that proofs are now spent
    states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
    assert all([s.state == SpentState.spent for s in states])

    # expect that no melt quote is pending
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes
