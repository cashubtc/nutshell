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
    wallet.cert = False

    class MockClient:
        async def get(self, url, **kwargs):
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
    assert result.error_message
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
    assert result.error_message
    assert error_contains in result.error_message


@pytest.mark.asyncio
@pytest.mark.parametrize("wallet_cls", [LndRestWallet, LndRPCWallet])
@pytest.mark.parametrize("amount_msat", [1, 16_001])
async def test_mpp_routes_preserve_exact_msat_and_invoice_total(
    monkeypatch, wallet_cls, amount_msat
):
    import base64

    from cashu.lightning.lnd_grpc.protos import lightning_pb2 as lnrpc
    from tests.mint.test_mint_invoice_amount import invoice_response

    invoice = invoice_response(17_000)
    assert invoice.payment_request
    wallet = object.__new__(wallet_cls)
    wallet.unit = Unit.sat
    wallet.supports_mpp = True
    wallet.endpoint = "unused"
    wallet.combined_creds = None
    captured = {}

    class Client:
        async def get(self, url, params, timeout):
            assert url.endswith("/0")
            assert params == {
                "amt_msat": str(amount_msat),
                "fee_limit.fixed_msat": "2000",
                "use_mission_control": "true",
            }
            captured["route_requested"] = True
            return Response(
                200,
                json={
                    "routes": [
                        {
                            "total_fees_msat": "0",
                            "hops": [{"amt_to_forward_msat": str(amount_msat)}],
                        }
                    ]
                },
            )

        async def post(self, url, json, timeout):
            assert url == "/v2/router/route/send"
            hop = json["route"]["hops"][-1]
            assert int(hop["amt_to_forward_msat"]) == amount_msat
            assert hop["mpp_record"]["total_amt_msat"] == 17_000
            return Response(
                200,
                json={
                    "status": "SUCCEEDED",
                    "route": json["route"],
                    "preimage": base64.b64encode(b"\x11" * 32).decode(),
                },
            )

    class Channel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    class Stub:
        def __init__(self, channel):
            pass

        async def QueryRoutes(self, request):
            assert request.amt == 0
            assert request.amt_msat == amount_msat
            assert request.fee_limit.fixed_msat == 2000
            captured["route_requested"] = True
            return lnrpc.QueryRoutesResponse(
                routes=[lnrpc.Route(hops=[lnrpc.Hop(amt_to_forward_msat=amount_msat)])]
            )

        async def SendToRouteV2(self, request):
            hop = request.route.hops[-1]
            assert hop.amt_to_forward_msat == amount_msat
            assert hop.mpp_record.total_amt_msat == 17_000
            return lnrpc.HTLCAttempt(
                status=lnrpc.HTLCAttempt.SUCCEEDED,
                route=request.route,
                preimage=b"\x11" * 32,
            )

    wallet.client = Client()
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.grpc.aio.secure_channel",
        lambda *args: Channel(),
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.lightningstub.LightningStub", Stub
    )
    monkeypatch.setattr("cashu.lightning.lnd_grpc.lnd_grpc.routerstub.RouterStub", Stub)
    quote = _quote(invoice.payment_request, amount=(amount_msat + 999) // 1000)
    quote.amount_msat = amount_msat
    quote.amount_option_type = "nut-15"
    result = await wallet.pay_invoice(quote, 2000)
    assert result.settled
    assert captured["route_requested"]
