import functools
import json

from loguru import logger
from redis.asyncio import from_url
from redis.exceptions import ConnectionError

from ..core.errors import CashuError
from ..core.settings import settings


class RedisCache:
    def __init__(self):
        if settings.mint_redis_cache_enabled:
            if settings.mint_redis_cache_url is None:
                raise CashuError("Redis cache url not provided")
            self.redis = from_url(settings.mint_redis_cache_url)
            # PING
            try:
                self.redis.ping()
                logger.info("PONG from redis ✅")
            except ConnectionError as e:
                logger.error("redis connection error 💀")
                raise e

    def cache(self, expire):
        def passthrough(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                logger.debug(f"cache wrapper on route {func.__name__}")
                result = await func(*args, **kwargs)
                return result
            return wrapper
        def decorator(func):
            @functools.wraps(func)
            async def wrapper(request, payload):
                logger.debug(f"cache wrapper on route {func.__name__}")
                key = request.url.path + payload.json()
                logger.debug(f"KEY: {key}")
                # Check if we have a value under this key
                if await self.redis.exists(key):
                    return json.loads(await self.redis.get(key))
                result = await func(request, payload)
                # Cache a successful result for `expire` seconds
                await self.redis.setex(key, expire, result.json())
                return result
            return wrapper
        return (
            passthrough
            if not settings.mint_redis_cache_enabled
            else decorator
        )
    
    async def disconnect(self):
        await self.redis.close()