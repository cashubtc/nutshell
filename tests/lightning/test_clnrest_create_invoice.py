from unittest.mock import AsyncMock

import httpx
import pytest

from cashu.core.base import Amount, Unit
from cashu.lightning.base import Unsupported
from cashu.lightning.clnrest import CLNRestWallet


@pytest.fixture
def wallet():
    wallet = object.__new__(CLNRestWallet)
    wallet.unit = Unit.sat
    wallet.client = AsyncMock()
    wallet.client.post.return_value = httpx.Response(
        200, json={"payment_hash": "invoice-id", "bolt11": "lnbc1invoice"}
    )
    return wallet


@pytest.mark.parametrize("unit", [Unit.sat, Unit.msat])
def test_clnrest_accepts_supported_units(wallet, unit):
    wallet.assert_unit_supported(unit)


@pytest.mark.parametrize("unit", [Unit.usd, Unit.eur, Unit.btc, Unit.auth])
def test_clnrest_rejects_unsupported_units(wallet, unit):
    with pytest.raises(Unsupported, match=f"^Unit {unit.name} is not supported$"):
        wallet.assert_unit_supported(unit)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unit, value, msat", [(Unit.sat, 2, 2000), (Unit.msat, 1501, 1501)]
)
@pytest.mark.parametrize("memo", [None, "invoice memo"])
async def test_create_invoice_sends_amount_and_memo(wallet, unit, value, msat, memo):
    result = await wallet.create_invoice(Amount(unit, value), memo=memo)

    wallet.client.post.assert_awaited_once()
    args, kwargs = wallet.client.post.call_args
    assert args == ("/v1/invoice",)
    data = kwargs["data"]
    label = data["label"]
    assert isinstance(label, str) and label
    assert data == {"amount_msat": msat, "description": memo, "label": label}
    assert result.ok is True
    assert result.checking_id == "invoice-id"
    assert result.payment_request == "lnbc1invoice"
    assert result.error_message is None


@pytest.mark.asyncio
async def test_create_invoice_uses_distinct_labels(wallet):
    await wallet.create_invoice(Amount(Unit.sat, 1))
    await wallet.create_invoice(Amount(Unit.sat, 1))

    labels = [
        call.kwargs["data"]["label"] for call in wallet.client.post.call_args_list
    ]
    assert labels[0] != labels[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("description_hash", [None, b"hash"])
async def test_create_invoice_sends_unhashed_description_and_options(
    wallet, description_hash
):
    result = await wallet.create_invoice(
        Amount(Unit.sat, 2),
        memo="overridden memo",
        description_hash=description_hash,
        unhashed_description="café ☕".encode("utf-8"),
        expiry=123,
        preimage="ab" * 32,
    )

    data = wallet.client.post.call_args.kwargs["data"]
    assert data == {
        "amount_msat": 2000,
        "description": "café ☕",
        "label": data["label"],
        "expiry": 123,
        "preimage": "ab" * 32,
    }
    assert result.ok is True


@pytest.mark.asyncio
async def test_create_invoice_rejects_description_hash_without_description(wallet):
    with pytest.raises(
        Unsupported,
        match=(
            "^'description_hash' unsupported by CLNRestWallet, "
            "provide 'unhashed_description'$"
        ),
    ):
        await wallet.create_invoice(Amount(Unit.sat, 1), description_hash=b"hash")

    wallet.client.post.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_invoice_rejects_unsupported_amount_unit(wallet):
    with pytest.raises(Unsupported, match="^Unit usd is not supported$"):
        await wallet.create_invoice(Amount(Unit.usd, 1))

    wallet.client.post.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response, error",
    [
        (httpx.Response(200, json={"message": "invoice rejected"}), "invoice rejected"),
        (httpx.Response(400, json={"message": "invalid amount"}), "invalid amount"),
        (httpx.Response(503, text="backend unavailable"), "backend unavailable"),
        (
            httpx.Response(400, json={"error": "bad request"}),
            '{"error": "bad request"}',
        ),
    ],
)
async def test_create_invoice_returns_backend_errors(wallet, response, error):
    wallet.client.post.return_value = response

    result = await wallet.create_invoice(Amount(Unit.sat, 1))

    assert result.ok is False
    assert result.error_message == error
    assert result.checking_id is None
    assert result.payment_request is None
