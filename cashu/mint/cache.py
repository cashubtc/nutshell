import asyncio
import functools
import json

from fastapi import Request
from loguru import logger
from pydantic import BaseModel
from redis.asyncio import from_url
from redis.exceptions import ConnectionError

from ..core.errors import CashuError
from ..core.settings import settings


class RedisCache:
    initialized = False
    expiry = settings.mint_redis_cache_ttl

    def __init__(self):
        if settings.mint_redis_cache_enabled:
            if settings.mint_redis_cache_url is None:
                raise CashuError("Redis cache url not provided")
            self.redis = from_url(settings.mint_redis_cache_url)
            asyncio.create_task(self.test_connection())

    async def test_connection(self):
        # PING
        try:
            await self.redis.ping()
            logger.success("Connected to Redis caching server.")
            self.initialized = True
        except ConnectionError as e:
            logger.error("Redis connection error.")
            raise e

    def cache(self):
        def passthrough(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                logger.trace(f"cache wrapper on route {func.__name__}")
                result = await func(*args, **kwargs)
                return result

            return wrapper

        def decorator(func):
            @functools.wraps(func)
            async def wrapper(request: Request, payload: BaseModel):
                logger.trace(f"cache wrapper on route {func.__name__}")
                key = request.url.path + payload.json()
                logger.trace(f"KEY: {key}")
                # Check if we have a value under this key
                if await self.redis.exists(key):
                    logger.trace("Returning a cached response...")
                    resp = await self.redis.get(key)
                    if resp:
                        return json.loads(resp)
                    else:
                        raise Exception(f"Found no cached response for key {key}")
                result = await func(request, payload)
                await self.redis.set(name=key, value=result.json(), ex=self.expiry)
                return result

            return wrapper

        return passthrough if not settings.mint_redis_cache_enabled else decorator

    async def disconnect(self):
        if self.initialized:
            await self.redis.close()
