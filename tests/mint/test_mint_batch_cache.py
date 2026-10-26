import importlib
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from cashu.core.base import BlindedSignature
from cashu.core.errors import QuoteAlreadyIssuedError
from cashu.core.settings import settings
from cashu.mint import router as router_module
from cashu.mint.features import LedgerFeatures
from tests.mint.test_mint_app_router import _build_router_app


@pytest.fixture
def batch_cache(monkeypatch):
    class FakeRedis:
        now = 0

        def __init__(self):
            self.values = {}
            self.ttls = []

        async def exists(self, key):
            if key in self.values and self.values[key][1] <= self.now:
                del self.values[key]
            return key in self.values

        async def get(self, key):
            return self.values[key][0]

        async def set(self, name, value, ex):
            self.ttls.append(ex)
            self.values[name] = (value, self.now + ex)

    cache = FakeRedis()
    with monkeypatch.context() as patch:
        patch.setattr(settings, "mint_redis_cache_enabled", True)
        patch.setattr(settings, "mint_redis_cache_url", "redis://test")
        patch.setattr(settings, "mint_redis_cache_ttl", 12)
        patch.setattr("cashu.mint.cache.from_url", lambda url: cache)
        importlib.reload(router_module)
        issued = set()
        calls = []

        async def mint_batch(payload):
            calls.append(payload)
            if any(q in issued for q in payload.quotes):
                raise QuoteAlreadyIssuedError()
            issued.update(payload.quotes)
            return [BlindedSignature(id="00" * 8, amount=1, C_="02" + "11" * 32)]

        patch.setattr(router_module, "ledger", SimpleNamespace(mint_batch=mint_batch))
        with TestClient(_build_router_app()) as client:
            yield client, cache, calls
    # Cache decorators are selected at import time. Restore the router for other tests.
    importlib.reload(router_module)


def test_batch_mint_cache_hit_miss_and_expiry(batch_cache):
    client, cache, calls = batch_cache
    payload = {
        "quotes": ["quote-1"],
        "outputs": [{"id": "00" * 8, "amount": 1, "B_": "02" + "22" * 32}],
    }
    first = client.post("/v1/mint/bolt11/batch", json=payload)
    repeated = client.post("/v1/mint/bolt11/batch", json=payload)
    assert first.status_code == repeated.status_code == 200
    assert first.json() == repeated.json()
    assert len(calls) == 1

    different = client.post(
        "/v1/mint/bolt11/batch", json={**payload, "quotes": ["quote-2"]}
    )
    assert different.status_code == 200
    assert len(calls) == 2
    assert cache.ttls == [12, 12]

    cache.now = 12
    expired = client.post("/v1/mint/bolt11/batch", json=payload)
    assert expired.status_code == 400
    assert len(calls) == 3


def test_batch_mint_cache_advertised_with_ttl(batch_cache):
    features = object.__new__(LedgerFeatures).add_cache_features({})
    assert {"method": "POST", "path": "/v1/mint/bolt11/batch"} in features[19][
        "cached_endpoints"
    ]
    assert features[19]["ttl"] == 12


def test_batch_mint_cache_not_advertised_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", False)
    assert 19 not in object.__new__(LedgerFeatures).add_cache_features({})
