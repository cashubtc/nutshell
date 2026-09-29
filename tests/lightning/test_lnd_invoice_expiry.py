import time
from unittest.mock import AsyncMock, Mock

import bolt11
import pytest

from cashu.core.base import MeltQuote, MeltQuoteState, Unit
from cashu.core.errors import QuoteExpiredError
from cashu.core.models import PostMeltQuoteRequest
from cashu.lightning.base import PaymentResult
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet
from tests.helpers import get_fake_invoice


@pytest.fixture(params=[LndRestWallet, LndRPCWallet], ids=["rest", "grpc"])
def backend(request, monkeypatch):
    wallet = object.__new__(request.param)
    wallet.unit = Unit.sat
    wallet.supports_mpp = True
    wallet.endpoint = "lnd.test"
    wallet.combined_creds = None
    wallet.client = Mock()
    channel = Mock(side_effect=AssertionError("must not contact LND"))
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.grpc.aio.secure_channel", channel
    )
    yield wallet
    assert wallet.client.mock_calls == []
    channel.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("expiry", [60, None], ids=["explicit", "bolt11-default"])
async def test_expired_invoice_is_rejected_before_fee_probe(backend, expiry):
    invoice = get_fake_invoice(2, date=int(time.time()) - 7200, expiry=expiry)

    with pytest.raises(QuoteExpiredError, match="invoice expired"):
        await backend.get_payment_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice)
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("amount", [1, 2], ids=["partial", "full"])
@pytest.mark.parametrize("expiry", [60, None], ids=["explicit", "bolt11-default"])
async def test_expired_invoice_is_not_submitted(backend, monkeypatch, amount, expiry):
    invoice = get_fake_invoice(2, date=int(time.time()) - 7200, expiry=expiry)
    quote = MeltQuote(
        quote="expired-invoice",
        method="bolt11",
        request=invoice,
        checking_id=bolt11.decode(invoice).payment_hash,
        unit="sat",
        amount=amount,
        fee_reserve=1,
        state=MeltQuoteState.pending,
    )
    partial_payment = AsyncMock()
    monkeypatch.setattr(backend, "pay_partial_invoice", partial_payment)

    response = await backend.pay_invoice(quote, fee_limit_msat=1000)

    assert response.result == PaymentResult.FAILED
    assert response.error_message == "invoice expired"
    partial_payment.assert_not_awaited()
