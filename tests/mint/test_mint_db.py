import asyncio
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import WebSocket

from cashu.core.base import MeltQuoteState, MintQuoteState
from cashu.core.json_rpc.base import (
    JSONRPCMethods,
    JSONRPCNotficationParams,
    JSONRPCNotification,
    JSONRPCSubscriptionKinds,
)
from cashu.core.models import PostMeltQuoteRequest, PostMeltQuoteResponse
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    assert_err,
    is_deprecated_api_only,
    is_github_actions,
    pay_if_regtest,
)

payment_request = (
    "lnbc1u1p5qeft3sp5jn5cqclnxvucfqtjm8qnlar2vhevcuudpccv7tsuglruj3qm579spp5ygdhy0t7xu53myke8z3z024xhz4kzgk9fcqk64sp0fyeqzhmaswqdqqcqpjrzjq0euzzxv65mts5ngg8c2t3vzz2aeuevy5845jvyqulqucd8c9kkhzrtp55qq63qqqqqqqqqqqqqzwyqqyg9qxpqysgqscprcpnk8whs3askqhgu6z5a4hupyn8du2aahdcf00s5pxrs4g94sv9f95xdn4tu0wec7kfyzj439wu9z27k6m6e3q4ysjquf5agx7gp0eeye4"
) 


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet",
        name="wallet",
    )
    await wallet.load_mint()
    yield wallet


@pytest.mark.asyncio
@pytest.mark.skipif(is_github_actions, reason="GITHUB_ACTIONS")
async def test_mint_proofs_pending(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    proofs = wallet.proofs.copy()

    proofs_states_before_split = await wallet.check_proof_state(proofs)
    assert all([s.unspent for s in proofs_states_before_split.states])

    await ledger.db_write._verify_spent_proofs_and_set_pending(proofs, ledger.keysets)

    proof_states = await wallet.check_proof_state(proofs)
    assert all([s.pending for s in proof_states.states])
    await assert_err(wallet.split(wallet.proofs, 20), "proofs are pending.")

    await ledger.db_write._unset_proofs_pending(proofs, ledger.keysets)

    await wallet.split(proofs, 20)

    proofs_states_after_split = await wallet.check_proof_state(proofs)
    assert all([s.spent for s in proofs_states_after_split.states])


@pytest.mark.asyncio
async def test_mint_quote(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.amount == 128
    assert quote.unit == "sat"
    assert not quote.paid
    # assert quote.paid_time is None
    assert quote.created_time


@pytest.mark.asyncio
async def test_mint_quote_state_transitions(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.unpaid

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
async def test_get_mint_quote_by_request(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    quote = await ledger.crud.get_mint_quote(request=mint_quote.request, db=ledger.db)
    assert quote is not None
    assert quote.amount == 128
    assert quote.unit == "sat"
    assert not quote.paid
    # assert quote.paid_time is None
    assert quote.created_time


@pytest.mark.asyncio
async def test_melt_quote(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote.request, unit="sat")
    )
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.quote == melt_quote.quote
    assert quote.amount == 128
    assert quote.unit == "sat"
    assert not quote.paid
    # assert quote.paid_time is None
    assert quote.created_time


@pytest.mark.asyncio
async def test_melt_quote_set_pending(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote.request, unit="sat")
    )
    assert melt_quote is not None
    assert melt_quote.state == MeltQuoteState.unpaid.value
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.quote == melt_quote.quote
    assert quote.unpaid
    previous_state = quote.state
    await ledger.db_write._set_melt_quote_pending(quote)
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.pending

    # set unpending
    await ledger.db_write._unset_melt_quote_pending(quote, previous_state)
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.state == previous_state


@pytest.mark.asyncio
async def test_melt_quote_state_transitions(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote.request, unit="sat")
    )
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.quote == melt_quote.quote
    assert quote.unpaid

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
async def test_mint_quote_set_pending(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    mint_quote = await ledger.crud.get_mint_quote(
        quote_id=mint_quote.quote, db=ledger.db
    )
    assert mint_quote is not None
    assert mint_quote.unpaid

    # pay_if_regtest pays on regtest, get_mint_quote pays on FakeWallet
    await pay_if_regtest(mint_quote.request)
    _ = await ledger.get_mint_quote(mint_quote.quote)

    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.paid

    previous_state = MintQuoteState.paid
    await ledger.db_write._set_mint_quote_pending(quote.quote)
    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.pending

    # try to mint while pending
    await assert_err(
        wallet.mint(128, quote_id=mint_quote.quote), "Mint quote already pending."
    )

    # set unpending
    await ledger.db_write._unset_mint_quote_pending(quote.quote, previous_state)

    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.state == previous_state
    assert quote.paid

    # # set paid and mint again
    # quote.state = MintQuoteState.paid
    # await ledger.crud.update_mint_quote(quote=quote, db=ledger.db)

    await wallet.mint(quote.amount, quote_id=quote.quote)

    # check if quote is issued
    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.issued


@pytest.mark.asyncio
async def test_db_events_add_client(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote.request, unit="sat")
    )
    assert melt_quote is not None
    assert melt_quote.state == MeltQuoteState.unpaid.value
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.quote == melt_quote.quote
    assert quote.unpaid

    # add event client
    websocket_mock = AsyncMock(spec=WebSocket)
    client = ledger.events.add_client(websocket_mock, ledger.db, ledger.crud)
    asyncio.create_task(client.start())
    await asyncio.sleep(0.1)
    websocket_mock.accept.assert_called_once()

    # add subscription
    client.add_subscription(
        JSONRPCSubscriptionKinds.BOLT11_MELT_QUOTE, [quote.quote], "subId"
    )
    quote_pending = await ledger.db_write._set_melt_quote_pending(quote)
    await asyncio.sleep(0.1)
    notification = JSONRPCNotification(
        method=JSONRPCMethods.SUBSCRIBE.value,
        params=JSONRPCNotficationParams(
            subId="subId", payload=PostMeltQuoteResponse.from_melt_quote(quote_pending).dict()
        ).dict(),
    )

    websocket_mock.send_text.assert_called_with(notification.json())

    # remove subscription
    client.remove_subscription("subId")

@pytest.mark.asyncio
async def test_db_update_mint_quote_state(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    await ledger.db_write._update_mint_quote_state(mint_quote.quote, MintQuoteState.paid)
    
    mint_quote_db = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert mint_quote_db.state == MintQuoteState.paid

    # Update it to issued
    await ledger.db_write._update_mint_quote_state(mint_quote_db.quote, MintQuoteState.issued)

    # Try and revert it back to unpaid
    await assert_err(ledger.db_write._update_mint_quote_state(mint_quote_db.quote, MintQuoteState.unpaid), "Cannot change state of an issued mint quote.")

@pytest.mark.asyncio
@pytest.mark.skipif(
    is_deprecated_api_only,
    reason=("Deprecated API")
)
async def test_db_update_melt_quote_state(wallet: Wallet, ledger: Ledger):
    melt_quote = await wallet.melt_quote(payment_request)
    await ledger.db_write._update_melt_quote_state(melt_quote.quote, MeltQuoteState.paid)

    melt_quote_db = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert melt_quote_db.state == MeltQuoteState.paid

    await assert_err(ledger.db_write._update_melt_quote_state(melt_quote.quote, MeltQuoteState.unpaid), "Cannot change state of a paid melt quote.")