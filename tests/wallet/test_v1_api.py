import httpx
import pytest

from cashu.core.base import BlindedMessage, Proof
from cashu.core.db import Database
from cashu.wallet.v1_api import LedgerAPI


@pytest.mark.asyncio
async def test_melt_includes_prefer_async(tmp_path):
    db = Database("wallet", str(tmp_path))
    api = LedgerAPI(url="http://example.com", db=db)
    api.keysets = [object()]
    api.mint_info = None

    captured = {}

    async def mock_request(method, path, noprefix=False, **kwargs):
        captured["json"] = kwargs.get("json")
        return httpx.Response(
            200,
            request=httpx.Request(method, f"{api.url.rstrip('/')}/{path}"),
            json={
                "quote": "quote",
                "amount": 1,
                "unit": "sat",
                "request": "req",
                "fee_reserve": 0,
                "paid": False,
                "state": "UNPAID",
                "expiry": 1,
                "payment_preimage": None,
                "change": [],
            },
        )

    api._request = mock_request

    proofs = [Proof(id="id", amount=1, secret="secret", C="sig")]
    outputs = [BlindedMessage(id="id", amount=1, B_="b")]

    await api.melt("quote", proofs, outputs, prefer_async=True)
    assert captured["json"]["prefer_async"] is True

    await api.httpx.aclose()
