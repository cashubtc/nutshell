import base64
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from cashu.core.base import Amount, Unit
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet

AMOUNTS = [(Unit.msat, n, n) for n in (1, 999, 1000, 1001, 1999, 1_000_001)] + [
    (Unit.sat, 1, 1000),
    (Unit.sat, 123, 123_000),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("unit,amount,expected_msat", AMOUNTS)
async def test_lndrest_creates_exact_invoice(unit, amount, expected_msat):
    wallet = object.__new__(LndRestWallet)
    wallet.unit = unit
    payment_hash = bytes.fromhex("11" * 32)
    wallet.client = AsyncMock()
    wallet.client.post.return_value = httpx.Response(
        200,
        json={
            "payment_request": "lnbc1test",
            "r_hash": base64.b64encode(payment_hash).decode(),
        },
    )

    response = await wallet.create_invoice(
        Amount(unit, amount), memo="precision test", expiry=120
    )

    wallet.client.post.assert_awaited_once_with(
        url="/v1/invoices",
        json={
            "value_msat": str(expected_msat),
            "private": True,
            "memo": "precision test",
            "expiry": 120,
        },
    )
    assert response.ok
    assert response.checking_id == payment_hash.hex()


@pytest.mark.asyncio
@pytest.mark.parametrize("unit,amount,expected_msat", AMOUNTS)
async def test_lndrpc_creates_exact_invoice(monkeypatch, unit, amount, expected_msat):
    wallet = object.__new__(LndRPCWallet)
    wallet.unit = unit
    wallet.endpoint = "localhost:10009"
    wallet.combined_creds = None
    payment_hash = bytes.fromhex("11" * 32)
    stub = SimpleNamespace(
        AddInvoice=AsyncMock(
            return_value=SimpleNamespace(
                payment_request="lnbc1test", r_hash=payment_hash
            )
        )
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.grpc.aio.secure_channel",
        lambda *args: AsyncMock(),
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.lightningstub.LightningStub",
        lambda channel: stub,
    )

    response = await wallet.create_invoice(
        Amount(unit, amount), memo="precision test", expiry=120
    )

    stub.AddInvoice.assert_awaited_once()
    request = stub.AddInvoice.call_args.args[0]
    assert request.value_msat == expected_msat
    assert request.value == 0
    assert request.private
    assert request.memo == "precision test"
    assert request.expiry == 120
    assert response.ok
    assert response.checking_id == payment_hash.hex()
