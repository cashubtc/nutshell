from typing import List, Tuple

import pytest
import pytest_asyncio

from cashu.core.base import MeltQuote, MeltQuoteState, Proof
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    is_regtest,
)

SEED = "TEST_PRIVATE_KEY"
DERIVATION_PATH = "m/0'/0'/0'"
DECRYPTON_KEY = "testdecryptionkey"
ENCRYPTED_SEED = "U2FsdGVkX1_7UU_-nVBMBWDy_9yDu4KeYb7MH8cJTYQGD4RWl82PALH8j-HKzTrI"


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        assert exc.args[0] == msg, Exception(
            f"Expected error: {msg}, got: {exc.args[0]}"
        )


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_mint_api_deprecated",
        name="wallet_mint_api_deprecated",
    )
    await wallet1.load_mint()
    yield wallet1


async def create_pending_melts(
    ledger: Ledger, check_id: str = "checking_id"
) -> Tuple[Proof, MeltQuote]:
    """Helper function for startup tests for fakewallet. Creates fake pending melt
    quote and fake proofs that are in the pending table that look like they're being
    used to pay the pending melt quote."""
    quote_id = "quote_id"
    quote = MeltQuote(
        quote=quote_id,
        method="bolt11",
        request="asdasd",
        checking_id=check_id,
        unit="sat",
        state=MeltQuoteState.pending,
        amount=100,
        fee_reserve=1,
    )
    await ledger.crud.store_melt_quote(
        quote=quote,
        db=ledger.db,
    )
    pending_proof = Proof(amount=123, C="asdasd", secret="asdasd", id=quote_id)
    await ledger.crud.set_proof_pending(
        db=ledger.db,
        proof=pending_proof,
        quote_id=quote_id,
    )
    # expect a pending melt quote
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes
    return pending_proof, quote


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_fakewallet_pending_quote_get_melt_quote_success(ledger: Ledger):
    """Startup routine test. Expects that a pending proofs are removed form the pending db
    after the startup routine determines that the associated melt quote was paid."""
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentResult.SETTLED.name

    # get_melt_quote should check the payment status and update the db
    quote2 = await ledger.get_melt_quote(quote_id=quote.quote)
    assert quote2.state == MeltQuoteState.paid

    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are spent
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].spent


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_fakewallet_pending_quote_get_melt_quote_pending(ledger: Ledger):
    """Startup routine test. Expects that a pending proofs are removed form the pending db
    after the startup routine determines that the associated melt quote was paid."""
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentResult.PENDING.name

    # get_melt_quote should check the payment status and update the db
    quote2 = await ledger.get_melt_quote(quote_id=quote.quote)
    assert quote2.state == MeltQuoteState.pending

    # expect that pending tokens are still in db
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes

    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_fakewallet_pending_quote_get_melt_quote_failed(ledger: Ledger):
    """Startup routine test. Expects that a pending proofs are removed form the pending db
    after the startup routine determines that the associated melt quote was paid."""
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentResult.FAILED.name

    # get_melt_quote should check the payment status and update the db
    quote2 = await ledger.get_melt_quote(quote_id=quote.quote)
    assert quote2.state == MeltQuoteState.unpaid

    # expect that pending tokens are still in db
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].unspent


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_fakewallet_pending_quote_get_melt_quote_unknown(ledger: Ledger):
    """Startup routine test. Expects that a pending proofs are removed form the pending db
    after the startup routine determines that the associated melt quote was paid."""
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentResult.UNKNOWN.name

    # get_melt_quote(..., purge_unknown=True) should check the payment status and update the db
    quote2 = await ledger.get_melt_quote(quote_id=quote.quote, purge_unknown=True)
    assert quote2.state == MeltQuoteState.unpaid

    # expect that pending tokens are still in db
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].unspent
