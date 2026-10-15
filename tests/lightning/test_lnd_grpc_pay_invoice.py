from types import SimpleNamespace
from typing import Any

import pytest

from cashu.core.base import MeltQuote, MeltQuoteState, Unit
from cashu.lightning.base import PaymentResult
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet


def _quote(request: str, amount: int = 1) -> MeltQuote:
    return MeltQuote(
        quote="q1",
        method="bolt11",
        request=request,
        checking_id="checking-1",
        unit="sat",
        amount=amount,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )


class FakePayment:
    status = 2
    payment_hash = "11" * 32
    fee_msat = 7
    payment_preimage = "ab" * 32
    failure_reason = 0


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled, expected", [(True, True), (False, False)])
async def test_lndrpc_pay_invoice_sends_allow_self_payment(
    monkeypatch, enabled, expected
):
    wallet = object.__new__(LndRPCWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = False
    wallet.endpoint = "localhost:10009"
    wallet.combined_creds = None

    captured: dict[str, Any] = {}

    class FakeStub:
        def __init__(self, channel):
            pass

        async def SendPaymentV2(self, request):
            captured["request"] = request
            yield FakePayment()

    class FakeChannel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.grpc.aio.secure_channel",
        lambda *args, **kwargs: FakeChannel(),
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.routerstub.RouterStub",
        FakeStub,
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.bolt11.decode",
        lambda request: SimpleNamespace(amount_msat=1000),
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.settings.mint_lnd_allow_self_payment",
        enabled,
    )

    result = await wallet.pay_invoice(
        _quote("lnbc1fake", amount=1), fee_limit_msat=1000
    )
    assert result.result == PaymentResult.SETTLED
    assert captured["request"].allow_self_payment is expected
