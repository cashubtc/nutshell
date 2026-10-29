import importlib
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from cashu.core.base import BlindedSignature
from cashu.core.errors import TransactionError
from cashu.core.models import PostMeltQuoteResponse
from cashu.core.nuts import nut20
from cashu.core.settings import settings
from cashu.mint import router as router_module
from cashu.mint.cache import RedisCache
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    get_fake_invoice,
    get_real_invoice,
    is_regtest,
    pay_if_regtest,
)
from tests.mint.test_mint_app_router import _build_router_app

CACHED_ENDPOINTS = (
    "/v1/mint/bolt11",
    "/v1/mint/bolt11/batch",
    "/v1/melt/bolt11",
    "/v1/swap",
)


@pytest.fixture(params=CACHED_ENDPOINTS, ids=["mint", "batch_mint", "melt", "swap"])
def cached_endpoint(request):
    return request.param


class FakeRedis:
    def __init__(self):
        self.now = 0
        self.values = {}
        self.ttls = []
        self.closed = False

    async def get(self, key):
        value = self.values.get(key)
        if value is not None and value[1] <= self.now:
            return None
        return value[0] if value is not None else None

    async def set(self, name, value, ex):
        self.ttls.append(ex)
        self.values[name] = (value, self.now + ex)

    async def ping(self):
        return True

    async def close(self):
        self.closed = True


@pytest.fixture
def response_cache(request, monkeypatch):
    cache = FakeRedis()
    with monkeypatch.context() as patch:
        patch.setattr(
            settings, "mint_redis_cache_enabled", getattr(request, "param", True)
        )
        patch.setattr(settings, "mint_redis_cache_url", "redis://test")
        patch.setattr(settings, "mint_redis_cache_ttl", 12)
        patch.setattr("cashu.mint.cache.from_url", lambda url, **kwargs: cache)
        # The cache backends are selected when the routes are imported, so the
        # router has to be reloaded with the patched settings and Redis.
        importlib.reload(router_module)
        # Expire the local cache and the fake Redis with the same clock.
        patch.setattr("cashu.mint.cache.time.monotonic", lambda: cache.now)
        patch.setattr(router_module.limiter, "enabled", False)
        completed = set()
        calls = []

        def process(path, operation):
            calls.append((path, operation))
            if operation == "error":
                raise TransactionError("request failed")
            key = (path, operation)
            if key in completed:
                raise TransactionError("request already processed")
            completed.add(key)
            return [BlindedSignature(id="00" * 8, amount=1, C_="02" + "11" * 32)]

        async def mint(outputs, quote_id, signature):
            return process("/v1/mint/bolt11", quote_id)

        async def mint_batch(payload):
            return process("/v1/mint/bolt11/batch", payload.quotes[0])

        async def melt(proofs, quote, outputs):
            process("/v1/melt/bolt11", quote)
            return PostMeltQuoteResponse(
                quote=quote,
                amount=1,
                unit="sat",
                method="bolt11",
                request="invoice",
                fee_reserve=1,
                state="PAID",
                expiry=123,
                payment_preimage="11" * 32,
            )

        async def swap(proofs, outputs):
            return process("/v1/swap", proofs[0].secret)

        patch.setattr(
            router_module,
            "ledger",
            SimpleNamespace(
                mint=mint,
                mint_batch=mint_batch,
                melt=melt,
                swap=swap,
            ),
        )
        try:
            with TestClient(_build_router_app()) as client:
                yield client, cache, calls
        finally:
            # Restore the router even if a test fails or the client cannot start.
            patch.undo()
            importlib.reload(router_module)


def request_payload(path, operation="first"):
    outputs = [{"id": "00" * 8, "amount": 1, "B_": "02" + "22" * 32}]
    inputs = [{"id": "00" * 8, "amount": 1, "secret": operation, "C": "02" + "33" * 32}]
    if path == "/v1/mint/bolt11":
        return {"quote": operation, "outputs": outputs}
    if path == "/v1/mint/bolt11/batch":
        return {"quotes": [operation], "outputs": outputs}
    if path == "/v1/melt/bolt11":
        return {"quote": operation, "inputs": inputs, "outputs": outputs}
    assert path == "/v1/swap"
    return {"inputs": inputs, "outputs": outputs}


def test_cache_hit_miss_and_expiry(cached_endpoint, response_cache):
    client, cache, calls = response_cache
    payload = request_payload(cached_endpoint)
    first = client.post(cached_endpoint, json=payload)
    repeated = client.post(cached_endpoint, json=payload)
    assert first.status_code == repeated.status_code == 200
    assert first.json() == repeated.json()
    assert len(calls) == 1

    different = client.post(
        cached_endpoint, json=request_payload(cached_endpoint, "different")
    )
    assert different.status_code == 200
    assert len(calls) == 2
    assert cache.ttls == [12, 12]

    cache.now = 12
    expired = client.post(cached_endpoint, json=payload)
    assert expired.status_code == 400
    assert len(calls) == 3


def test_failed_responses_are_not_cached(cached_endpoint, response_cache):
    client, cache, calls = response_cache
    payload = request_payload(cached_endpoint, "error")
    assert client.post(cached_endpoint, json=payload).status_code == 400
    assert client.post(cached_endpoint, json=payload).status_code == 400
    assert len(calls) == 2
    assert cache.values == {}


@pytest.mark.parametrize("response_cache", [False], indirect=True)
def test_cache_replays_from_memory_without_redis(cached_endpoint, response_cache):
    client, cache, calls = response_cache
    payload = request_payload(cached_endpoint)
    assert client.post(cached_endpoint, json=payload).status_code == 200
    assert client.post(cached_endpoint, json=payload).status_code == 200
    assert len(calls) == 1
    assert cache.values == {}
    assert cache.ttls == []


@pytest.mark.asyncio
async def test_redis_cache_connection_lifecycle(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", True)
    monkeypatch.setattr(settings, "mint_redis_cache_url", "redis://test")
    monkeypatch.setattr("cashu.mint.cache.from_url", lambda url, **kwargs: redis)
    cache = RedisCache()
    await cache.test_connection()
    assert cache.initialized
    await cache.disconnect()
    assert redis.closed


@pytest_asyncio.fixture
async def wallet(ledger: Ledger, tmp_path):
    wallet = await Wallet.with_db(url=SERVER_ENDPOINT, db=str(tmp_path))
    await wallet.load_mint()
    yield wallet
    await wallet.db.engine.dispose()


@pytest.mark.asyncio
async def test_api_cached_responses(cached_endpoint, wallet: Wallet):
    amounts = [32, 32]
    melt_quote = None
    if cached_endpoint == "/v1/melt/bolt11":
        amounts = [32]
    quotes = []
    for amount in amounts if cached_endpoint.endswith("/batch") else [64]:
        quote = await wallet.request_mint(amount)
        if cached_endpoint == "/v1/melt/bolt11":
            invoice = (
                get_real_invoice(32)["payment_request"]
                if is_regtest
                else get_fake_invoice(32)
            )
            melt_quote = await wallet.melt_quote(invoice)
        await pay_if_regtest(quote.request)
        quotes.append(quote)

    secrets, rs, _ = await wallet.generate_secrets_from_to(
        10010, 10010 + len(amounts) - 1
    )
    outputs, _ = wallet._construct_outputs(amounts, secrets, rs)
    payload = {"outputs": [o.model_dump() for o in outputs]}

    if cached_endpoint in ("/v1/mint/bolt11", "/v1/mint/bolt11/batch"):
        signatures = []
        for quote in quotes:
            assert quote.privkey
            signatures.append(
                nut20.sign_mint_quote(quote.quote, outputs, quote.privkey)
            )
        if cached_endpoint.endswith("/batch"):
            payload.update(
                quotes=[q.quote for q in quotes],
                quote_amounts=amounts,
                signatures=signatures,
            )
        else:
            payload.update(quote=quotes[0].quote, signature=signatures[0])
    else:
        proofs = await wallet.mint(64, quotes[0].quote)
        payload["inputs"] = [p.model_dump() for p in proofs]
        if cached_endpoint == "/v1/melt/bolt11":
            payload["quote"] = melt_quote.quote

    async with httpx.AsyncClient(base_url=SERVER_ENDPOINT, timeout=30) as client:
        first = await client.post(cached_endpoint, json=payload)
        repeated = await client.post(cached_endpoint, json=payload)
    assert first.status_code == repeated.status_code == 200, (first.text, repeated.text)
    if cached_endpoint == "/v1/melt/bolt11":
        assert first.json()["state"] == "PAID", first.text
    assert first.text == repeated.text
