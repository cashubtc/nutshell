import json
from types import SimpleNamespace

import httpx
import pytest

from cashu.core.base import MeltQuote, MeltQuoteState, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.lightning.clnrest import CLNRestWallet
from cashu.lightning.fake import FakeWallet
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet
from tests.mint.test_mint_invoice_amount import invoice_response


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "backend_cls", [FakeWallet, LndRestWallet, LndRPCWallet, CLNRestWallet]
)
@pytest.mark.parametrize("unit,expected", [(Unit.sat, 17), (Unit.msat, 16_001)])
async def test_amountless_backend_quote(backend_cls, unit, expected):
    backend = object.__new__(backend_cls)
    backend.unit = unit
    # LND must use the configured fee reserve: its invoice-based probe needs an amount.
    request = PostMeltQuoteRequest(
        unit=unit.name,
        request=invoice_response(None).payment_request,
        options={"amountless": {"amount_msat": 16_001}},
    )
    quote = await backend.get_payment_quote(request)
    assert quote.amount.unit == unit
    assert quote.amount.amount == expected
    assert quote.fee.unit == unit
    assert quote.fee.amount > 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "backend_cls", [FakeWallet, LndRestWallet, LndRPCWallet, CLNRestWallet]
)
async def test_amountless_backend_pays_exact_msat(monkeypatch, backend_cls):
    invoice = invoice_response(None)
    quote = MeltQuote(
        quote="test",
        method="bolt11",
        request=invoice.payment_request,
        checking_id=invoice.checking_id,
        unit="sat",
        amount=17,
        amount_msat=16_001,
        fee_reserve=2,
        state=MeltQuoteState.unpaid,
    )
    backend = object.__new__(backend_cls)
    backend.unit = Unit.sat
    backend.supports_mpp = False
    captured = {}

    class Stream:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def aiter_lines(self):
            yield json.dumps(
                {
                    "result": {
                        "status": "SUCCEEDED",
                        "payment_hash": invoice.checking_id,
                        "payment_preimage": "11" * 32,
                        "fee_msat": "0",
                    }
                }
            )

    def stream(*args, json, **kwargs):
        captured.update(json)
        return Stream()

    async def post(*args, data, **kwargs):
        captured.update(data)
        return httpx.Response(
            200,
            json={
                "payment_preimage": "11" * 32,
                "amount_msat": 16_001,
                "amount_sent_msat": 16_001,
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

        async def SendPaymentV2(self, request):
            captured["amt_msat"] = request.amt_msat
            captured["payment_request"] = request.payment_request
            yield SimpleNamespace(
                status=2,
                payment_hash=invoice.checking_id,
                payment_preimage="11" * 32,
                fee_msat=0,
            )

    backend.client = SimpleNamespace(stream=stream, post=post)
    backend.endpoint = "unused"
    backend.combined_creds = None
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.grpc.aio.secure_channel",
        lambda *a: Channel(),
    )
    monkeypatch.setattr("cashu.lightning.lnd_grpc.lnd_grpc.routerstub.RouterStub", Stub)
    if backend_cls is FakeWallet:

        def update_balance(invoice, incoming):
            captured["amt_msat"] = invoice.amount_msat

        monkeypatch.setattr(backend, "update_balance", update_balance)
    result = await backend.pay_invoice(quote, 2000)
    assert result.settled
    if backend_cls is CLNRestWallet:
        assert captured["amount_msat"] == 16_001
        assert "partial_msat" not in captured
        assert captured["invstring"] == quote.request
    else:
        assert int(captured["amt_msat"]) == 16_001
