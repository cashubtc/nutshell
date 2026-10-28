import asyncio
import functools
import hashlib
import json
import time
from collections import OrderedDict
from typing import Any, Optional, Union

from fastapi import Request
from loguru import logger
from pydantic import BaseModel
from redis.asyncio import Redis, from_url
from redis.asyncio.cluster import RedisCluster
from redis.exceptions import RedisError

from ..core.errors import CashuError
from ..core.settings import settings


class MemoryCache:
    """Bounded, process-local storage of serialized responses, oldest first."""

    def __init__(self, max_entries: int, max_bytes: int):
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.entries: OrderedDict[str, tuple[Optional[float], bytes]] = OrderedDict()
        self.size = 0

    def _remove(self, key: str):
        _, value = self.entries.pop(key)
        self.size -= len(key) + len(value)

    def get(self, key: str) -> Optional[bytes]:
        entry = self.entries.get(key)
        if entry is None:
            return None
        expires, value = entry
        if expires is not None and expires <= time.monotonic():
            self._remove(key)
            return None
        return value

    def set(self, key: str, value: bytes, ttl: Optional[int]):
        if key in self.entries:
            self._remove(key)
        now = time.monotonic()
        while self.entries:
            oldest = next(iter(self.entries))
            expires, _ = self.entries[oldest]
            if expires is None or expires > now:
                break
            self._remove(oldest)
        size = len(key) + len(value)
        if size > self.max_bytes or (ttl is not None and ttl <= 0):
            return
        while self.entries and (
            len(self.entries) >= self.max_entries or self.size + size > self.max_bytes
        ):
            self._remove(next(iter(self.entries)))
        self.entries[key] = (now + ttl if ttl is not None else None, value)
        self.size += size


class RedisCache:
    """Response replay with a local cache and an optional shared Redis cache."""

    def __init__(self):
        self.initialized = False
        self.redis: Union[Redis, Any] = None
        self.memory = MemoryCache(
            settings.mint_memory_cache_max_entries, settings.mint_memory_cache_max_bytes
        )
        self._inflight: dict[str, asyncio.Task] = {}
        self._redis_available = settings.mint_redis_cache_enabled
        if settings.mint_redis_cache_enabled:
            if settings.mint_redis_cache_url is None:
                raise CashuError("Redis cache url not provided")
            factory = (
                RedisCluster.from_url if settings.mint_redis_cache_cluster else from_url
            )
            self.redis = factory(
                settings.mint_redis_cache_url,
                socket_connect_timeout=1,
                socket_timeout=1,
            )

    def _redis_failed(self):
        if self._redis_available:
            logger.warning("Redis cache unavailable; using process-local response cache.")
        self._redis_available = False

    async def test_connection(self):
        if self.redis is None:
            return
        try:
            await self.redis.ping()
            logger.success("Connected to Redis caching server.")
            self.initialized = True
            self._redis_available = True
        except RedisError:
            self._redis_failed()

    async def _execute(self, func, request: Request, payload: BaseModel, key: str):
        # Retain the existing Redis key format so deployed caches remain readable.
        memory_key = hashlib.sha256(key.encode()).hexdigest()
        try:
            cached = self.memory.get(memory_key)
            if cached is not None:
                return json.loads(cached)
            if self.redis is not None:
                try:
                    cached = await self.redis.get(key)
                    self._redis_available = True
                    if cached is not None:
                        return json.loads(cached)
                except RedisError:
                    self._redis_failed()

            result = await func(request, payload)
            serialized = result.model_dump_json()
            self.memory.set(
                memory_key, serialized.encode(), settings.mint_redis_cache_ttl
            )
            if self.redis is not None:
                try:
                    await self.redis.set(
                        name=key, value=serialized, ex=settings.mint_redis_cache_ttl
                    )
                    self._redis_available = True
                except RedisError:
                    self._redis_failed()
            return result
        finally:
            self._inflight.pop(key, None)

    @staticmethod
    def _consume_exception(task: asyncio.Task):
        # A disconnected caller may leave a task running without an awaiting wallet.
        if not task.cancelled():
            task.exception()

    def cache(self):
        def decorator(func):
            @functools.wraps(func)
            async def wrapper(request: Request, payload: BaseModel):
                key = request.url.path + payload.model_dump_json()
                task = self._inflight.get(key)
                if task is None:
                    task = asyncio.create_task(self._execute(func, request, payload, key))
                    self._inflight[key] = task
                    task.add_done_callback(self._consume_exception)
                # Finish and cache successful operations even if the caller disconnects.
                return await asyncio.shield(task)

            return wrapper

        return decorator

    async def disconnect(self):
        if self._inflight:
            await asyncio.gather(*self._inflight.values(), return_exceptions=True)
        if self.redis is not None:
            await self.redis.close()
        self.initialized = False
