import asyncio
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import WebSocket

from cashu.core.base import MeltQuoteState, MintQuoteState
from cashu.core.errors import ProofsArePendingError
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

payment_request = "lnbc1u1p5qeft3sp5jn5cqclnxvucfqtjm8qnlar2vhevcuudpccv7tsuglruj3qm579spp5ygdhy0t7xu53myke8z3z024xhz4kzgk9fcqk64sp0fyeqzhmaswqdqqcqpjrzjq0euzzxv65mts5ngg8c2t3vzz2aeuevy5845jvyqulqucd8c9kkhzrtp55qq63qqqqqqqqqqqqqzwyqqyg9qxpqysgqscprcpnk8whs3askqhgu6z5a4hupyn8du2aahdcf00s5pxrs4g94sv9f95xdn4tu0wec7kfyzj439wu9z27k6m6e3q4ysjquf5agx7gp0eeye4"


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
    await assert_err(wallet.split(wallet.proofs, 20), ProofsArePendingError.detail)

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
    assert quote.state != MintQuoteState.paid
    # assert quote.paid_time is None
    assert quote.created_time


@pytest.mark.asyncio
async def test_mint_quote_state_transitions(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote is not None
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
async def test_get_mint_quote_by_request(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    quote = await ledger.crud.get_mint_quote(request=mint_quote.request, db=ledger.db)
    assert quote is not None
    assert quote.amount == 128
    assert quote.unit == "sat"
    assert quote.state != MintQuoteState.paid
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
    assert quote.state != MeltQuoteState.paid
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
    assert quote.state == MeltQuoteState.unpaid
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
async def test_mint_quote_set_pending(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    mint_quote = await ledger.crud.get_mint_quote(
        quote_id=mint_quote.quote, db=ledger.db
    )
    assert mint_quote is not None
    assert mint_quote.state == MintQuoteState.unpaid

    # pay_if_regtest pays on regtest, get_mint_quote pays on FakeWallet
    await pay_if_regtest(mint_quote.request)
    _ = await ledger.get_mint_quote(mint_quote.quote)

    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.state == MintQuoteState.paid

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
    assert quote.state == MintQuoteState.paid

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
    assert quote.state == MeltQuoteState.unpaid

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
    await asyncio.sleep(0.1)
    quote_pending = await ledger.db_write._set_melt_quote_pending(quote)
    await asyncio.sleep(0.1)
    notification = JSONRPCNotification(
        method=JSONRPCMethods.SUBSCRIBE.value,
        params=JSONRPCNotficationParams(
            subId="subId", payload=PostMeltQuoteResponse.from_melt_quote(quote_pending).model_dump()
        ).model_dump(),
    )

    websocket_mock.send_text.assert_called_with(notification.model_dump_json())

    # remove subscription
    client.remove_subscription("subId")


@pytest.mark.asyncio
async def test_db_update_mint_quote_state(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(128)
    await ledger.db_write._update_mint_quote_state(
        mint_quote.quote, MintQuoteState.paid
    )

    mint_quote_db = await ledger.crud.get_mint_quote(
        quote_id=mint_quote.quote, db=ledger.db
    )
    assert mint_quote_db
    assert mint_quote_db.state == MintQuoteState.paid

    # Update it to issued
    await ledger.db_write._update_mint_quote_state(
        mint_quote_db.quote, MintQuoteState.issued
    )

    # Try and revert it back to unpaid
    await assert_err(
        ledger.db_write._update_mint_quote_state(
            mint_quote_db.quote, MintQuoteState.unpaid
        ),
        "Cannot change state of an issued mint quote.",
    )


@pytest.mark.asyncio
@pytest.mark.skipif(is_deprecated_api_only, reason=("Deprecated API"))
async def test_db_update_melt_quote_state(wallet: Wallet, ledger: Ledger):
    melt_quote = await wallet.melt_quote(payment_request)
    await ledger.db_write._update_melt_quote_state(
        melt_quote.quote, MeltQuoteState.paid
    )

    melt_quote_db = await ledger.crud.get_melt_quote(
        quote_id=melt_quote.quote, db=ledger.db
    )
    assert melt_quote_db
    assert melt_quote_db.state == MeltQuoteState.paid

    await assert_err(
        ledger.db_write._update_melt_quote_state(
            melt_quote.quote, MeltQuoteState.unpaid
        ),
        "Cannot change state of a paid melt quote.",
    )


# Tests for get_melt_quotes_by_checking_id CRUD method
@pytest.mark.asyncio
async def test_get_melt_quotes_by_checking_id_empty(ledger: Ledger):
    """Test that get_melt_quotes_by_checking_id returns empty list for non-existent checking_id."""

    quotes = await ledger.crud.get_melt_quotes_by_checking_id(
        checking_id="non_existent_id", db=ledger.db
    )
    assert quotes == []


@pytest.mark.asyncio
async def test_get_melt_quotes_by_checking_id_single(ledger: Ledger):
    """Test that get_melt_quotes_by_checking_id returns a single quote when only one exists."""
    from cashu.core.base import MeltQuote

    checking_id = "test_checking_id_single"
    quote = MeltQuote(
        quote="quote_id_1",
        method="bolt11",
        request="lnbc123",
        checking_id=checking_id,
        unit="sat",
        amount=100,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )
    await ledger.crud.store_melt_quote(quote=quote, db=ledger.db)

    quotes = await ledger.crud.get_melt_quotes_by_checking_id(
        checking_id=checking_id, db=ledger.db
    )

    assert len(quotes) == 1
    assert quotes[0].quote == "quote_id_1"
    assert quotes[0].checking_id == checking_id


@pytest.mark.asyncio
async def test_get_melt_quotes_by_checking_id_multiple(ledger: Ledger):
    """Test that get_melt_quotes_by_checking_id returns all quotes with the same checking_id."""
    from cashu.core.base import MeltQuote

    checking_id = "test_checking_id_multiple"

    quote1 = MeltQuote(
        quote="quote_id_m1",
        method="bolt11",
        request="lnbc123",
        checking_id=checking_id,
        unit="sat",
        amount=100,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )
    quote2 = MeltQuote(
        quote="quote_id_m2",
        method="bolt11",
        request="lnbc456",
        checking_id=checking_id,
        unit="sat",
        amount=200,
        fee_reserve=2,
        state=MeltQuoteState.paid,
    )
    quote3 = MeltQuote(
        quote="quote_id_m3",
        method="bolt11",
        request="lnbc789",
        checking_id=checking_id,
        unit="sat",
        amount=300,
        fee_reserve=3,
        state=MeltQuoteState.unpaid,
    )

    await ledger.crud.store_melt_quote(quote=quote1, db=ledger.db)
    await ledger.crud.store_melt_quote(quote=quote2, db=ledger.db)
    await ledger.crud.store_melt_quote(quote=quote3, db=ledger.db)

    quotes = await ledger.crud.get_melt_quotes_by_checking_id(
        checking_id=checking_id, db=ledger.db
    )

    assert len(quotes) == 3
    quote_ids = {q.quote for q in quotes}
    assert quote_ids == {"quote_id_m1", "quote_id_m2", "quote_id_m3"}


@pytest.mark.asyncio
async def test_get_melt_quotes_by_checking_id_different_checking_ids(ledger: Ledger):
    """Test that get_melt_quotes_by_checking_id only returns quotes with the specified checking_id."""
    from cashu.core.base import MeltQuote

    checking_id_1 = "test_checking_id_diff_1"
    checking_id_2 = "test_checking_id_diff_2"

    quote1 = MeltQuote(
        quote="quote_id_diff_1",
        method="bolt11",
        request="lnbc123",
        checking_id=checking_id_1,
        unit="sat",
        amount=100,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )
    quote2 = MeltQuote(
        quote="quote_id_diff_2",
        method="bolt11",
        request="lnbc456",
        checking_id=checking_id_2,
        unit="sat",
        amount=200,
        fee_reserve=2,
        state=MeltQuoteState.unpaid,
    )

    await ledger.crud.store_melt_quote(quote=quote1, db=ledger.db)
    await ledger.crud.store_melt_quote(quote=quote2, db=ledger.db)

    quotes_1 = await ledger.crud.get_melt_quotes_by_checking_id(
        checking_id=checking_id_1, db=ledger.db
    )
    assert len(quotes_1) == 1
    assert quotes_1[0].quote == "quote_id_diff_1"

    quotes_2 = await ledger.crud.get_melt_quotes_by_checking_id(
        checking_id=checking_id_2, db=ledger.db
    )
    assert len(quotes_2) == 1
    assert quotes_2[0].quote == "quote_id_diff_2"


@pytest.mark.asyncio
async def test_mint_quote_paid_time_update(wallet: Wallet, ledger: Ledger):
    import time
    # Create a mint quote
    mint_quote = await wallet.request_mint(128)
    
    # Check that paid_time is None initially
    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.unpaid
    assert quote.paid_time is None
    assert quote.created_time is not None

    # Simulate payment
    await pay_if_regtest(mint_quote.request)
    
    # Trigger check at mint (this updates the state in DB)
    _ = await ledger.get_mint_quote(mint_quote.quote)
    # Check that paid_time is now set
    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.paid
    assert quote.paid_time is not None
    assert isinstance(quote.paid_time, int)
    assert quote.paid_time >= quote.created_time
    # Ensure it's recent (within last minute)
    assert quote.paid_time > int(time.time()) - 60


@pytest.mark.asyncio
async def test_crud_get_mint_quotes_by_pubkeys(ledger: Ledger):
    import time

    from cashu.core.base import MintQuote

    pubkey1 = "02" + "00" * 32
    pubkey2 = "03" + "00" * 32
    
    quote1 = MintQuote(
        quote="quote_pubkey_1",
        method="bolt11",
        request="lnbc1",
        checking_id="chk1",
        unit="sat",
        amount=100,
        state=MintQuoteState.unpaid,
        pubkey=pubkey1,
        created_time=int(time.time()) - 100,
    )
    quote2 = MintQuote(
        quote="quote_pubkey_2",
        method="bolt11",
        request="lnbc2",
        checking_id="chk2",
        unit="sat",
        amount=200,
        state=MintQuoteState.paid,
        pubkey=pubkey1,
        created_time=int(time.time()),
    )
    quote3 = MintQuote(
        quote="quote_pubkey_3",
        method="bolt11",
        request="lnbc3",
        checking_id="chk3",
        unit="sat",
        amount=300,
        state=MintQuoteState.unpaid,
        pubkey=pubkey2,
        created_time=int(time.time()) + 100,
    )
    
    await ledger.crud.store_mint_quote(quote=quote1, db=ledger.db)
    await ledger.crud.store_mint_quote(quote=quote2, db=ledger.db)
    await ledger.crud.store_mint_quote(quote=quote3, db=ledger.db)
    
    # Test single pubkey (results should be sorted by created_time desc)
    quotes_1 = await ledger.crud.get_mint_quotes_by_pubkeys(pubkeys=[pubkey1], db=ledger.db)
    assert len(quotes_1) == 2
    assert quotes_1[0].quote == "quote_pubkey_2"  # Newest first
    assert quotes_1[1].quote == "quote_pubkey_1"
    
    # Test multiple pubkeys
    quotes_1_and_2 = await ledger.crud.get_mint_quotes_by_pubkeys(pubkeys=[pubkey1, pubkey2], db=ledger.db)
    assert len(quotes_1_and_2) == 3
    assert quotes_1_and_2[0].quote == "quote_pubkey_3"
    assert quotes_1_and_2[1].quote == "quote_pubkey_2"
    assert quotes_1_and_2[2].quote == "quote_pubkey_1"
    
    # Test no pubkeys
    quotes_empty = await ledger.crud.get_mint_quotes_by_pubkeys(pubkeys=[], db=ledger.db)
    assert len(quotes_empty) == 0

    # Test unknown pubkey
    quotes_unknown = await ledger.crud.get_mint_quotes_by_pubkeys(pubkeys=["02" + "11" * 32], db=ledger.db)
    assert len(quotes_unknown) == 0


@pytest.mark.asyncio
async def test_ledger_get_mint_quotes_by_pubkeys(wallet: Wallet, ledger: Ledger):
    from cashu.core.crypto.secp import PrivateKey
    from cashu.core.models import PostMintQuoteRequest
    from cashu.core.p2pk import schnorr_sign
    
    privkey = PrivateKey()
    pubkey = privkey.public_key.format(compressed=True).hex()
    
    # Create two mint quotes for the same pubkey
    response1 = await ledger.mint_quote(PostMintQuoteRequest(amount=64, unit="sat", pubkey=pubkey))
    response2 = await ledger.mint_quote(PostMintQuoteRequest(amount=128, unit="sat", pubkey=pubkey))
    
    signature = schnorr_sign(bytes.fromhex(pubkey), privkey).hex()
    
    # Fetch quotes via Ledger
    quotes = await ledger.get_mint_quotes_by_pubkeys(
        pubkeys=[pubkey], pubkey_signatures=[signature]
    )
    
    assert len(quotes) == 2
    fetched_quote_ids = {q.quote for q in quotes}
    assert response1.quote in fetched_quote_ids
    assert response2.quote in fetched_quote_ids

    # Pay one quote and verify the state updates
    await pay_if_regtest(response1.request)
    
    # Fake wallet doesn't update state until we call get_mint_quote (or in this case, get_mint_quotes_by_pubkeys)
    # The get_mint_quotes_by_pubkeys method should trigger a status check for unpaid quotes
    updated_quotes = await ledger.get_mint_quotes_by_pubkeys(
        pubkeys=[pubkey], pubkey_signatures=[signature]
    )
    
    paid_quotes = [q for q in updated_quotes if q.paid]
    
    # response1 must be paid now
    assert response1.quote in {q.quote for q in paid_quotes}

    # Test error cases
    bad_signature = signature[:-2] + "00"
    await assert_err(
        ledger.get_mint_quotes_by_pubkeys(
            pubkeys=[pubkey], pubkey_signatures=[bad_signature]
        ),
        f"invalid signature for pubkey {pubkey}",
    )
    
    await assert_err(
        ledger.get_mint_quotes_by_pubkeys(
            pubkeys=[pubkey], pubkey_signatures=[]
        ),
        "pubkeys and pubkey_signatures must have the same length",
    )
