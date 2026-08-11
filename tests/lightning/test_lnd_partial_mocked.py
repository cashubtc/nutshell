from types import SimpleNamespace

import grpc.aio
import pytest
from httpx import Response

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Unit
from cashu.lightning.base import PaymentResult
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet


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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enabled, error_contains", [(True, "QueryRoutes API"), (False, "target not found")]
)
async def test_lndrest_pay_partial_invoice_self_payment(
    monkeypatch, enabled, error_contains
):
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = True
    wallet.endpoint = "http://localhost:8080"
    wallet.macaroon = "macaroon"
    wallet.cert = None

    class MockClient:
        async def post(self, url, **kwargs):
            if "/v1/graph/routes/" in url:
                return Response(status_code=500, json={"message": "target not found"})
            return Response(status_code=200, json={})

    wallet.client = MockClient()

    monkeypatch.setattr(
        "cashu.lightning.lndrest.bolt11.decode",
        lambda request: SimpleNamespace(
            amount_msat=2000,
            tags=SimpleNamespace(get=lambda x: SimpleNamespace(data="fake_pubkey")),
        ),
    )
    monkeypatch.setattr(
        "cashu.lightning.lndrest.settings.mint_lnd_allow_self_payment",
        enabled,
    )

    result = await wallet.pay_partial_invoice(
        _quote("lnbc1fake", amount=1),
        amount=Amount(unit=Unit.sat, amount=1),
        fee_limit_msat=1000,
    )
    assert result.result == PaymentResult.FAILED
    assert error_contains in result.error_message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enabled, error_contains", [(True, "QueryRoutes API"), (False, "target not found")]
)
async def test_lndrpc_pay_partial_invoice_self_payment(
    monkeypatch, enabled, error_contains
):
    wallet = object.__new__(LndRPCWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = True
    wallet.endpoint = "localhost:10009"
    wallet.combined_creds = None

    class MockStub:
        def __init__(self, channel):
            pass

        async def QueryRoutes(self, request):
            raise grpc.aio.AioRpcError(
                code=grpc.StatusCode.UNKNOWN,
                initial_metadata=None,
                trailing_metadata=None,
                details="target not found",
            )

    class MockChannel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.grpc.aio.secure_channel",
        lambda *args, **kwargs: MockChannel(),
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.lightningstub.LightningStub",
        MockStub,
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.routerstub.RouterStub",
        MockStub,
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.bolt11.decode",
        lambda request: SimpleNamespace(
            amount_msat=2000,
            tags=SimpleNamespace(get=lambda x: SimpleNamespace(data="fake_pubkey")),
        ),
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.settings.mint_lnd_allow_self_payment",
        enabled,
    )

    result = await wallet.pay_partial_invoice(
        _quote("lnbc1fake", amount=1),
        amount=Amount(unit=Unit.sat, amount=1),
        fee_limit_msat=1000,
    )
    assert result.result == PaymentResult.FAILED
    assert error_contains in result.error_message
