import pytest
import pytest_asyncio

from cashu.core.base import MeltQuoteState, MintQuoteState, ProofSpentState
from cashu.core.models import PostMeltQuoteRequest
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    assert_err,
    is_github_actions,
    is_postgres,
    pay_if_regtest,
)


@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
@pytest.mark.skipif(is_github_actions, reason="GITHUB_ACTIONS")
async def test_mint_proofs_pending(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    proofs = wallet1.proofs.copy()

    proofs_states_before_split = await wallet1.check_proof_state(proofs)
    assert all(
        [s.state == ProofSpentState.unspent for s in proofs_states_before_split.states]
    )

    await ledger.db_write._set_proofs_pending(proofs)

    proof_states = await wallet1.check_proof_state(proofs)
    assert all([s.state == ProofSpentState.pending for s in proof_states.states])
    await assert_err(wallet1.split(wallet1.proofs, 20), "proofs are pending.")

    await ledger.db_write._unset_proofs_pending(proofs)

    await wallet1.split(proofs, 20)

    proofs_states_after_split = await wallet1.check_proof_state(proofs)
    assert all(
        [s.state == ProofSpentState.spent for s in proofs_states_after_split.states]
    )


@pytest.mark.asyncio
async def test_mint_quote(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    assert invoice is not None
    quote = await ledger.crud.get_mint_quote(quote_id=invoice.id, db=ledger.db)
    assert quote is not None
    assert quote.quote == invoice.id
    assert quote.amount == 128
    assert quote.unit == "sat"
    assert not quote.paid
    assert quote.checking_id == invoice.payment_hash
    # assert quote.paid_time is None
    assert quote.created_time


@pytest.mark.asyncio
async def test_mint_quote_state_transitions(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    assert invoice is not None
    quote = await ledger.crud.get_mint_quote(quote_id=invoice.id, db=ledger.db)
    assert quote is not None
    assert quote.quote == invoice.id
    assert quote.state == MintQuoteState.unpaid

    # set pending again
    async def set_state(quote, state):
        quote.state = state

    # set pending
    await assert_err(
        set_state(quote, MintQuoteState.pending),
        "Cannot change state of an unpaid mint quote",
    )

    # set unpaid
    await assert_err(
        set_state(quote, MintQuoteState.unpaid),
        "Cannot change state of an unpaid mint quote",
    )

    # set paid
    quote.state = MintQuoteState.paid

    # set unpaid
    await assert_err(
        set_state(quote, MintQuoteState.unpaid),
        "Cannot change state of a paid mint quote to unpaid.",
    )

    # set pending
    quote.state = MintQuoteState.pending

    # set paid again
    quote.state = MintQuoteState.paid

    # set pending again
    quote.state = MintQuoteState.pending

    # set issued
    quote.state = MintQuoteState.issued

    # set pending again
    await assert_err(
        set_state(quote, MintQuoteState.pending),
        "Cannot change state of an issued mint quote.",
    )


@pytest.mark.asyncio
async def test_get_mint_quote_by_request(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    assert invoice is not None
    quote = await ledger.crud.get_mint_quote(request=invoice.bolt11, db=ledger.db)
    assert quote is not None
    assert quote.quote == invoice.id
    assert quote.amount == 128
    assert quote.unit == "sat"
    assert not quote.paid
    # assert quote.paid_time is None
    assert quote.created_time


@pytest.mark.asyncio
async def test_melt_quote(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    assert invoice is not None
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice.bolt11, unit="sat")
    )
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.quote == melt_quote.quote
    assert quote.amount == 128
    assert quote.unit == "sat"
    assert not quote.paid
    assert quote.checking_id == invoice.payment_hash
    # assert quote.paid_time is None
    assert quote.created_time


@pytest.mark.asyncio
async def test_melt_quote_set_pending(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    assert invoice is not None
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice.bolt11, unit="sat")
    )
    assert melt_quote is not None
    assert melt_quote.state == MeltQuoteState.unpaid.value
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.quote == melt_quote.quote
    assert quote.state == MeltQuoteState.unpaid
    previous_state = quote.state
    await ledger.db_write._set_melt_quote_pending(quote)
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.state == MeltQuoteState.pending

    # set unpending
    await ledger.db_write._unset_melt_quote_pending(quote, previous_state)
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.state == previous_state


@pytest.mark.asyncio
async def test_melt_quote_state_transitions(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    assert invoice is not None
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice.bolt11, unit="sat")
    )
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.quote == melt_quote.quote
    assert quote.state == MeltQuoteState.unpaid

    # set pending
    quote.state = MeltQuoteState.pending

    # set unpaid
    quote.state = MeltQuoteState.unpaid

    # set paid
    quote.state = MeltQuoteState.paid

    # set pending again
    async def set_state(quote, state):
        quote.state = state

    await assert_err(
        set_state(quote, MeltQuoteState.pending),
        "Cannot change state of a paid melt quote.",
    )


@pytest.mark.asyncio
async def test_mint_quote_set_pending(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    assert invoice is not None
    quote = await ledger.crud.get_mint_quote(quote_id=invoice.id, db=ledger.db)
    assert quote is not None
    assert quote.state == MintQuoteState.unpaid

    # pay_if_regtest pays on regtest, get_mint_quote pays on FakeWallet
    pay_if_regtest(invoice.bolt11)
    _ = await ledger.get_mint_quote(invoice.id)

    quote = await ledger.crud.get_mint_quote(quote_id=invoice.id, db=ledger.db)
    assert quote is not None
    assert quote.state == MintQuoteState.paid

    previous_state = MintQuoteState.paid
    await ledger.db_write._set_mint_quote_pending(quote.quote)
    quote = await ledger.crud.get_mint_quote(quote_id=invoice.id, db=ledger.db)
    assert quote is not None
    assert quote.state == MintQuoteState.pending

    # try to mint while pending
    await assert_err(wallet1.mint(128, id=invoice.id), "Mint quote already pending.")

    # set unpending
    await ledger.db_write._unset_mint_quote_pending(quote.quote, previous_state)

    quote = await ledger.crud.get_mint_quote(quote_id=invoice.id, db=ledger.db)
    assert quote is not None
    assert quote.state == previous_state
    assert quote.state == MintQuoteState.paid

    # # set paid and mint again
    # quote.state = MintQuoteState.paid
    # await ledger.crud.update_mint_quote(quote=quote, db=ledger.db)

    await wallet1.mint(quote.amount, id=quote.quote)

    # check if quote is issued
    quote = await ledger.crud.get_mint_quote(quote_id=invoice.id, db=ledger.db)
    assert quote is not None
    assert quote.state == MintQuoteState.issued


@pytest.mark.asyncio
@pytest.mark.skipif(not is_postgres, reason="only works with Postgres")
async def test_postgres_working():
    assert is_postgres
    assert True
