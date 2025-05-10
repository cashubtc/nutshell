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
async def test_regtest_get_melt_quote_melt_fail_restore_pending_batch_check(
    wallet: Wallet, ledger: Ledger
):
    # simulates a payment that fails on the mint and whether the wallet is able to
    # restore the state of all proofs (set unreserved)
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

    # fail the payment, melt will unset the proofs as reserved
    cancel_invoice(preimage_hash=preimage_hash)

    await asyncio.sleep(SLEEP_TIME)

    # test get_spent_proofs_check_states_batched: verify that no proofs are spent
    spent_proofs = await wallet.get_spent_proofs_check_states_batched(send_proofs)
    assert len(spent_proofs) == 0

    proofs_db_later = await get_proofs(db=wallet.db, melt_id=quote.quote)
    assert all([p.reserved is False for p in proofs_db_later])


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_get_melt_quote_wallet_crash_melt_fail_restore_pending_batch_check(
    wallet: Wallet, ledger: Ledger
):
    # simulates a payment failure but the wallet crashed, we confirm that wallet.get_melt_quote() will correctly
    # recover the state of the proofs and set them as unreserved
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
    assert len(send_proofs) == 2

    task = asyncio.create_task(
        wallet.melt(
            proofs=send_proofs,
            invoice=invoice_payment_request,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )
    )
    await asyncio.sleep(SLEEP_TIME)

    # verify that the proofs are reserved
    proofs_db = await get_proofs(db=wallet.db, melt_id=quote.quote)
    assert len(proofs_db) == 2
    assert all([p.reserved for p in proofs_db])

    # simulate a and kill the task
    task.cancel()

    await asyncio.sleep(SLEEP_TIME)

    states = await wallet.check_proof_state(send_proofs)
    assert all([s.pending for s in states.states])

    # fail the payment, melt will unset the proofs as reserved
    cancel_invoice(preimage_hash=preimage_hash)

    await asyncio.sleep(SLEEP_TIME)

    # get the melt quote, this should restore the state of the proofs
    melt_quote = await wallet.get_melt_quote(quote.quote)
    assert melt_quote
    assert melt_quote.unpaid

    # verify that get_melt_quote unset all proofs as not pending anymore
    proofs_db_later = await get_proofs(db=wallet.db, melt_id=quote.quote)
    assert len(proofs_db_later) == 0


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_regtest_wallet_crash_melt_succeed_restore_pending_batch_check(
    wallet: Wallet, ledger: Ledger
):
    # simulates a payment that succeeds but the wallet crashes in the mean time
    # we then call get_spent_proofs_check_states_batched to check the proof states
    # and the wallet should then invalidate the reserved proofs

    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])
    # invoice_obj = bolt11.decode(invoice_payment_request)
    # preimage_hash = invoice_obj.payment_hash

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.swap_to_send(
        wallet.proofs, total_amount, set_reserved=True
    )

    # verify that the proofs are reserved
    proofs_db = await get_proofs(db=wallet.db, melt_id=quote.quote)
    assert all([p.reserved for p in proofs_db])

    task = asyncio.create_task(
        wallet.melt(
            proofs=send_proofs,
            invoice=invoice_payment_request,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )
    )
    await asyncio.sleep(SLEEP_TIME)

    # simulate a and kill the task
    task.cancel()
    await asyncio.sleep(SLEEP_TIME)
    # verify that the proofs are still reserved
    proofs_db = await get_proofs(db=wallet.db, melt_id=quote.quote)
    assert all([p.reserved for p in proofs_db])

    # verify that the proofs are still pending
    states = await wallet.check_proof_state(send_proofs)
    assert all([s.pending for s in states.states])

    # succeed the payment
    settle_invoice(preimage=preimage)

    await asyncio.sleep(SLEEP_TIME)

    # get the melt quote
    melt_quote = await wallet.get_melt_quote(quote.quote)
    assert melt_quote
    assert melt_quote.paid

    # verify that get_melt_quote unset all proofs as not pending anymore
    proofs_db_later = await get_proofs(db=wallet.db, melt_id=quote.quote)
    assert len(proofs_db_later) == 0
