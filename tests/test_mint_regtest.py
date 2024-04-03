import pytest
import pytest_asyncio

from cashu.core.base import Proof, SpentState
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    get_real_invoice,
    is_fake,
    pay_if_regtest,
)


@pytest_asyncio.fixture(scope="function")
async def wallet(mint):
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet",
        name="wallet",
    )
    await wallet.load_mint()
    yield wallet


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="is_fake")
async def test_pending_melt_startup_routine(wallet: Wallet, ledger: Ledger):
    """
    Test for startup routine that checks the melt quotes for pending proofs in the db.

    We first make a payment s.th. there is a successful lightning payment in the backend.
    We then create an artificial melt quote and create fake pending proofs that correspond to it. We then run the
    startup routine of the ledger and expect that the pending proofs are removed from the db and the proofs are marked
    as spent.

    Args:
        wallet (Wallet): _description_
        ledger (Ledger): _description_
    """
    # fill wallet
    topup_invoice = await wallet.request_mint(128)
    pay_if_regtest(topup_invoice.bolt11)
    await wallet.mint(128, id=topup_invoice.id)
    assert wallet.balance == 128

    invoice_dict = get_real_invoice(64)
    invoice_payment_request = invoice_dict["payment_request"]

    quote = await wallet.get_pay_amount_with_fees(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.split_to_send(wallet.proofs, total_amount)
    melt_response = await wallet.pay_lightning(
        proofs=send_proofs,
        invoice=invoice_payment_request,
        fee_reserve_sat=quote.fee_reserve,
        quote_id=quote.quote,
    )
    assert melt_response.paid, "Payment not paid"

    pending_proof = Proof(amount=123, C="asdasd", secret="asdasd", id="asdasd")
    await ledger.crud.set_proof_pending(
        db=ledger.db,
        proof=pending_proof,
        quote_id=quote.quote,
    )

    # expect that proofs are pending
    states = await ledger.check_proofs_state([pending_proof.Y])
    assert all([s.state == SpentState.pending for s in states])

    # run startup routinge
    await ledger.startup_ledger()

    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are spent
    states = await ledger.check_proofs_state([pending_proof.Y])
    assert all([s.state == SpentState.spent for s in states])

    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="is_fake")
async def test_pending_failed_melt_startup_routine(wallet: Wallet, ledger: Ledger):
    # fill wallet
    topup_invoice = await wallet.request_mint(128)
    pay_if_regtest(topup_invoice.bolt11)
    await wallet.mint(128, id=topup_invoice.id)
    assert wallet.balance == 128

    invoice_dict = get_real_invoice(64)
    invoice_payment_request = invoice_dict["payment_request"]

    quote = await wallet.get_pay_amount_with_fees(invoice_payment_request)

    pending_proof = Proof(amount=123, C="asdasd", secret="asdasd", id="asdasd")
    await ledger.crud.set_proof_pending(
        db=ledger.db,
        proof=pending_proof,
        quote_id=quote.quote,
    )

    # expect that proofs are pending
    states = await ledger.check_proofs_state([pending_proof.Y])
    assert all([s.state == SpentState.pending for s in states])

    # run startup routinge, this checks whether there is an associated payment in the backend
    # to the melt quote. Since it was never paid, the pending proofs should be removed from the db.
    await ledger.startup_ledger()

    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are unspent
    states = await ledger.check_proofs_state([pending_proof.Y])
    assert all([s.state == SpentState.unspent for s in states])

    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes
