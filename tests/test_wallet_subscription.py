import asyncio

import pytest
import pytest_asyncio

from cashu.core.base import Method, MintQuoteState, ProofSpentState, ProofState
from cashu.core.json_rpc.base import JSONRPCNotficationParams
from cashu.core.nuts import WEBSOCKETS_NUT
from cashu.core.settings import settings
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    is_fake,
    pay_if_regtest,
)


@pytest_asyncio.fixture(scope="function")
async def wallet(mint):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_subscriptions",
        name="wallet_subscriptions",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_wallet_subscription_mint(wallet: Wallet):
    if not wallet.mint_info.supports_nut(WEBSOCKETS_NUT):
        pytest.skip("No websocket support")

    if not wallet.mint_info.supports_websocket_mint_quote(
        Method["bolt11"], wallet.unit
    ):
        pytest.skip("No websocket support for bolt11_mint_quote")

    triggered = False
    msg_stack: list[JSONRPCNotficationParams] = []

    def callback(msg: JSONRPCNotficationParams):
        nonlocal triggered, msg_stack
        triggered = True
        msg_stack.append(msg)
        asyncio.run(wallet.mint(int(invoice.amount), id=invoice.id))

    invoice, sub = await wallet.request_mint_with_callback(128, callback=callback)
    await pay_if_regtest(invoice.bolt11)
    wait = settings.fakewallet_delay_incoming_payment or 2
    await asyncio.sleep(wait + 2)

    assert triggered
    assert len(msg_stack) == 3

    assert msg_stack[0].payload["paid"] is False
    assert msg_stack[0].payload["state"] == MintQuoteState.unpaid.value

    assert msg_stack[1].payload["paid"] is True
    assert msg_stack[1].payload["state"] == MintQuoteState.paid.value

    assert msg_stack[2].payload["paid"] is True
    assert msg_stack[2].payload["state"] == MintQuoteState.issued.value


@pytest.mark.asyncio
async def test_wallet_subscription_swap(wallet: Wallet):
    if not wallet.mint_info.supports_nut(WEBSOCKETS_NUT):
        pytest.skip("No websocket support")

    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    await wallet.mint(64, id=invoice.id)

    triggered = False
    msg_stack: list[JSONRPCNotficationParams] = []

    def callback(msg: JSONRPCNotficationParams):
        nonlocal triggered, msg_stack
        triggered = True
        msg_stack.append(msg)

    n_subscriptions = len(wallet.proofs)
    state, sub = await wallet.check_proof_state_with_callback(
        wallet.proofs, callback=callback
    )

    _ = await wallet.split_to_send(wallet.proofs, 64)

    wait = 1
    await asyncio.sleep(wait)
    assert triggered

    # we receive 3 messages for each subscription:
    # initial state (UNSPENT), pending state (PENDING), spent state (SPENT)
    assert len(msg_stack) == n_subscriptions * 3

    # the first one is the UNSPENT state
    pending_stack = msg_stack[:n_subscriptions]
    for msg in pending_stack:
        proof_state = ProofState.model_validate(msg.payload)
        assert proof_state.state == ProofSpentState.unspent

    # the second one is the PENDING state
    spent_stack = msg_stack[n_subscriptions : n_subscriptions * 2]
    for msg in spent_stack:
        proof_state = ProofState.model_validate(msg.payload)
        assert proof_state.state == ProofSpentState.pending

    # the third one is the SPENT state
    spent_stack = msg_stack[n_subscriptions * 2 :]
    for msg in spent_stack:
        proof_state = ProofState.model_validate(msg.payload)
        assert proof_state.state == ProofSpentState.spent
