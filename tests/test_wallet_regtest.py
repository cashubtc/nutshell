import asyncio

import bolt11
import pytest
import pytest_asyncio

from cashu.mint.ledger import Ledger
from cashu.wallet.crud import get_proofs
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
    assert all([s.pending for s in states.states])

    settle_invoice(preimage=preimage)

    await asyncio.sleep(SLEEP_TIME)

    states = await wallet.check_proof_state(send_proofs)
    assert all([s.spent for s in states.states])


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_failed_quote(wallet: Wallet, ledger: Ledger):
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])
    invoice_obj = bolt11.decode(invoice_payment_request)
    preimage_hash = invoice_obj.payment_hash

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.swap_to_send(wallet.proofs, total_amount)
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
    assert all([s.pending for s in states.states])

    cancel_invoice(preimage_hash=preimage_hash)

    await asyncio.sleep(SLEEP_TIME)

    states = await wallet.check_proof_state(send_proofs)
    assert all([s.unspent for s in states.states])


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_melt_fail_restore_pending_batch_check(
    wallet: Wallet, ledger: Ledger
):
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])
    invoice_obj = bolt11.decode(invoice_payment_request)
    preimage_hash = invoice_obj.payment_hash

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.swap_to_send(
        wallet.proofs, total_amount, set_reserved=True
    )

    # verify that the proofs are reserved
    proofs_db = await get_proofs(db=wallet.db, melt_id=quote.quote)
    assert all([p.reserved for p in proofs_db])

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
    assert all([s.pending for s in states.states])

    cancel_invoice(preimage_hash=preimage_hash)

    await asyncio.sleep(SLEEP_TIME)

    # test get_spent_proofs_check_states_batched: verify that no proofs are spent
    spent_proofs = await wallet.get_spent_proofs_check_states_batched(send_proofs)
    assert len(spent_proofs) == 0

    # test get_melt_quote: verify that the proofs are not reserved anymore
    quote_later = await wallet.get_melt_quote(quote.quote)
    assert quote_later
    assert quote_later.paid is False
    proofs_db_later = await get_proofs(db=wallet.db, melt_id=quote.quote)
    assert all([p.reserved is False for p in proofs_db_later])
