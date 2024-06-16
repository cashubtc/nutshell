import asyncio

import pytest
import pytest_asyncio

from cashu.core.json_rpc.base import JSONRPCNotficationParams
from cashu.core.nuts import WEBSOCKETS_NUT
from cashu.core.settings import settings
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
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
async def test_wallet_subscription(wallet: Wallet):
    assert wallet.mint_info.supports_nut(WEBSOCKETS_NUT)
    triggered = False
    msg_stack: list[JSONRPCNotficationParams] = []

    def callback(msg: JSONRPCNotficationParams):
        nonlocal triggered, msg_stack
        triggered = True
        msg_stack.append(msg)
        asyncio.run(wallet.mint(int(invoice.amount), id=invoice.id))

    invoice, sub = await wallet.request_mint_with_callback(128, callback=callback)
    pay_if_regtest(invoice.bolt11)
    wait = settings.fakewallet_delay_incoming_payment or 2
    await asyncio.sleep(wait + 2)
    assert triggered
    assert len(msg_stack) == 2

    assert msg_stack[0].payload["paid"] is True
    assert msg_stack[0].payload["issued"] is False

    assert msg_stack[1].payload["paid"] is True
    assert msg_stack[1].payload["issued"] is True
