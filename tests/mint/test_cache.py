import asyncio
from unittest.mock import AsyncMock

import pytest
from fastapi import Request
from pydantic import BaseModel
from redis.exceptions import ConnectionError, TimeoutError

from cashu.core.errors import CashuError
from cashu.core.nuts.nuts import CACHE_NUT
from cashu.core.settings import settings
from cashu.mint.cache import MemoryCache, RedisCache
from cashu.mint.features import LedgerFeatures


class Payload(BaseModel):
    value: int


def request(path="/v1/swap"):
    return Request({"type": "http", "method": "POST", "path": path, "headers": []})


@pytest.fixture
def cache(monkeypatch):
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", False)
    return RedisCache()


@pytest.fixture
def redis_cache(monkeypatch):
    redis = AsyncMock()
    redis.get.return_value = None
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", True)
    monkeypatch.setattr(settings, "mint_redis_cache_url", "redis://cache")
    monkeypatch.setattr("cashu.mint.cache.from_url", lambda url, **kwargs: redis)
    return RedisCache(), redis


def test_memory_expiry_and_replay_does_not_extend_ttl(monkeypatch):
    now = 100
    monkeypatch.setattr("cashu.mint.cache.time.monotonic", lambda: now)
    memory = MemoryCache(10, 100)
    memory.set("key", b"value", 10)
    now = 109
    assert memory.get("key") == b"value"
    now = 110
    assert memory.get("key") is None
    assert memory.size == 0


def test_memory_entry_limit_evicts_oldest():
    memory = MemoryCache(2, 100)
    memory.set("one", b"1", None)
    memory.set("two", b"2", None)
    assert memory.get("one") == b"1"
    memory.set("three", b"3", None)
    assert memory.get("one") is None
    assert memory.get("two") == b"2"
    assert memory.get("three") == b"3"


def test_memory_byte_limit_and_oversized_response():
    memory = MemoryCache(10, 8)
    memory.set("one", b"1", None)
    memory.set("two", b"2", None)
    memory.set("x", b"12345678", None)
    assert memory.size == 8
    assert memory.get("one") == b"1"
    assert memory.get("two") == b"2"
    assert memory.get("x") is None
    memory.set("z", b"1234", None)
    assert memory.size == 5
    assert memory.get("one") is None
    assert memory.get("two") is None


def test_memory_prunes_expired_entries_on_insert(monkeypatch):
    now = 100
    monkeypatch.setattr("cashu.mint.cache.time.monotonic", lambda: now)
    memory = MemoryCache(10, 100)
    memory.set("old", b"1", 10)
    now = 110
    memory.set("new", b"2", 10)
    assert list(memory.entries) == ["new"]
    assert memory.size == 4


@pytest.mark.asyncio
async def test_local_replay_and_distinct_requests(cache):
    route = AsyncMock(return_value=Payload(value=42))
    cached_route = cache.cache()(route)
    assert await cached_route(request(), Payload(value=1)) == Payload(value=42)
    response = await cached_route(request(), Payload(value=1))
    assert response == {"value": 42}
    response["value"] = 0
    assert await cached_route(request(), Payload(value=1)) == {"value": 42}
    await cached_route(request(), Payload(value=2))
    await cached_route(request("/v1/mint/bolt11"), Payload(value=1))
    assert route.await_count == 3
    assert not cache._inflight


@pytest.mark.asyncio
async def test_local_replay_expires(cache, monkeypatch):
    now = 100
    monkeypatch.setattr("cashu.mint.cache.time.monotonic", lambda: now)
    monkeypatch.setattr(settings, "mint_redis_cache_ttl", 10)
    route = AsyncMock(return_value=Payload(value=42))
    cached_route = cache.cache()(route)
    await cached_route(request(), Payload(value=1))
    now = 110
    await cached_route(request(), Payload(value=1))
    assert route.await_count == 2


@pytest.mark.asyncio
async def test_failures_are_not_cached(cache):
    route = AsyncMock(side_effect=[CashuError("failed"), Payload(value=42)])
    cached_route = cache.cache()(route)
    with pytest.raises(CashuError, match="failed"):
        await cached_route(request(), Payload(value=1))
    assert not cache._inflight
    assert await cached_route(request(), Payload(value=1)) == Payload(value=42)
    assert route.await_count == 2


@pytest.mark.asyncio
async def test_identical_requests_share_inflight_result(cache):
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    @cache.cache()
    async def route(request, payload):
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return payload

    first = asyncio.create_task(route(request(), Payload(value=1)))
    await entered.wait()
    second = asyncio.create_task(route(request(), Payload(value=1)))
    # An unrelated request can complete while the first request is still pending.
    other = cache.cache()(AsyncMock(return_value=Payload(value=2)))
    assert await other(request(), Payload(value=2)) == Payload(value=2)
    release.set()
    assert await asyncio.gather(first, second) == [Payload(value=1)] * 2
    assert calls == 1
    assert not cache._inflight


@pytest.mark.asyncio
async def test_cancelled_caller_does_not_cancel_operation(cache):
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    @cache.cache()
    async def route(request, payload):
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return payload

    first = asyncio.create_task(route(request(), Payload(value=1)))
    await entered.wait()
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    release.set()
    assert await route(request(), Payload(value=1)) == Payload(value=1)
    assert await route(request(), Payload(value=1)) == {"value": 1}
    assert calls == 1


@pytest.mark.asyncio
async def test_concurrent_failure_is_shared_and_can_be_retried(cache):
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    @cache.cache()
    async def route(request, payload):
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        raise CashuError("failed")

    first = asyncio.create_task(route(request(), Payload(value=1)))
    await entered.wait()
    second = asyncio.create_task(route(request(), Payload(value=1)))
    # Let the second caller join the pending operation before releasing it.
    await asyncio.sleep(0)
    release.set()
    results = await asyncio.gather(first, second, return_exceptions=True)
    assert all(isinstance(result, CashuError) for result in results)
    assert calls == 1
    assert not cache._inflight
    with pytest.raises(CashuError, match="failed"):
        await route(request(), Payload(value=1))
    assert calls == 2


@pytest.mark.asyncio
async def test_disconnect_waits_for_pending_operations(cache):
    entered, release = asyncio.Event(), asyncio.Event()

    @cache.cache()
    async def route(request, payload):
        entered.set()
        await release.wait()
        return payload

    pending = asyncio.create_task(route(request(), Payload(value=1)))
    await entered.wait()
    closing = asyncio.create_task(cache.disconnect())
    await asyncio.sleep(0)
    assert not closing.done()
    release.set()
    await closing
    assert await pending == Payload(value=1)
    assert not cache._inflight


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [ConnectionError, TimeoutError])
async def test_redis_unavailable_at_startup(redis_cache, error):
    cache, redis = redis_cache
    redis.ping.side_effect = error("unavailable")
    redis.get.side_effect = error("unavailable")
    redis.set.side_effect = error("unavailable")
    await cache.test_connection()
    assert cache.initialized is False
    route = AsyncMock(return_value=Payload(value=42))
    cached_route = cache.cache()(route)
    assert await cached_route(request(), Payload(value=1)) == Payload(value=42)
    assert await cached_route(request(), Payload(value=1)) == {"value": 42}
    route.assert_awaited_once()
    await cache.disconnect()
    redis.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_redis_write_failure_preserves_success_and_replay(redis_cache):
    cache, redis = redis_cache
    redis.set.side_effect = ConnectionError("disconnected after operation")
    route = AsyncMock(return_value=Payload(value=42))
    cached_route = cache.cache()(route)
    assert await cached_route(request(), Payload(value=1)) == Payload(value=42)
    assert await cached_route(request(), Payload(value=1)) == {"value": 42}
    route.assert_awaited_once()
    redis.get.assert_awaited_once()


@pytest.mark.asyncio
async def test_local_copy_survives_redis_disconnect(redis_cache):
    cache, redis = redis_cache
    route = AsyncMock(return_value=Payload(value=42))
    cached_route = cache.cache()(route)
    await cached_route(request(), Payload(value=1))
    redis.get.side_effect = ConnectionError("disconnected")
    assert await cached_route(request(), Payload(value=1)) == {"value": 42}
    route.assert_awaited_once()
    assert redis.get.await_count == 1


@pytest.mark.asyncio
async def test_redis_recovers_after_outage(redis_cache):
    cache, redis = redis_cache
    redis.get.side_effect = [ConnectionError("disconnected"), b'{"value":99}']
    redis.set.side_effect = ConnectionError("disconnected")
    route = AsyncMock(return_value=Payload(value=42))
    cached_route = cache.cache()(route)
    await cached_route(request(), Payload(value=1))
    assert await cached_route(request(), Payload(value=2)) == {"value": 99}
    route.assert_awaited_once()
    assert cache._redis_available is True


@pytest.mark.asyncio
async def test_redis_hit_uses_existing_key_and_skips_route(redis_cache):
    cache, redis = redis_cache
    redis.get.return_value = b'{"value":99}'
    route = AsyncMock()
    assert await cache.cache()(route)(request(), Payload(value=1)) == {"value": 99}
    redis.get.assert_awaited_once_with('/v1/swap{"value":1}')
    route.assert_not_awaited()
    redis.set.assert_not_awaited()


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("ttl", [None, 123])
def test_cache_features_advertised_for_both_backends(monkeypatch, enabled, ttl):
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", enabled)
    monkeypatch.setattr(settings, "mint_redis_cache_ttl", ttl)
    features = LedgerFeatures().add_cache_features({})[CACHE_NUT]
    assert features["cached_endpoints"] == [
        {"method": "POST", "path": "/v1/mint/bolt11"},
        {"method": "POST", "path": "/v1/melt/bolt11"},
        {"method": "POST", "path": "/v1/swap"},
    ]
    assert features.get("ttl") == ttl
