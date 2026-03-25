import functools
import json
from typing import Any, Dict, Type, Union, get_type_hints

from fastapi import Request
from loguru import logger
from pydantic import BaseModel, ValidationError
from redis.asyncio import from_url
from redis.exceptions import ConnectionError

from ..core.errors import CashuError
from ..core.settings import settings


class CacheDeserializationError(CashuError):
    """Raised when cached data fails validation."""
    pass


class CacheDataIntegrityError(CashuError):
    """Raised when cached data fails integrity check."""
    pass


class RedisCache:
    initialized = False

    def __init__(self):
        if settings.mint_redis_cache_enabled:
            if settings.mint_redis_cache_url is None:
                raise CashuError("Redis cache url not provided")
            self.redis = from_url(settings.mint_redis_cache_url)

    async def test_connection(self):
        # PING
        try:
            await self.redis.ping()
            logger.success("Connected to Redis caching server.")
            self.initialized = True
        except ConnectionError as e:
            logger.error("Redis connection error.")
            raise e

    def _validate_cache_data(
        self, 
        data: Any, 
        key: str,
        expected_type: Type[BaseModel] = None
    ) -> Union[Dict[str, Any], BaseModel]:
        """
        Validate deserialized cache data structure.
        
        Security Fix for Issue #926:
        - Ensures data is a dictionary (expected for all cached responses)
        - Optionally validates against Pydantic model for type safety
        - Provides logging for security monitoring
        - Raises explicit error for invalid data
        
        Args:
            data: Deserialized data from Redis
            key: Cache key for error reporting
            expected_type: Optional Pydantic model to validate against
            
        Returns:
            Validated dictionary or Pydantic model instance
            
        Raises:
            CacheDeserializationError: If data has invalid type
            CacheDataIntegrityError: If data fails Pydantic validation
        """
        # Step 1: Basic type validation
        if not isinstance(data, dict):
            logger.error(
                f"Security Alert: Invalid cache data type for key {key}. "
                f"Expected dict, got {type(data).__name__}. "
                f"This may indicate cache poisoning or corruption."
            )
            raise CacheDeserializationError(
                f"Invalid cache data type: expected dict, got {type(data).__name__}"
            )
        
        # Step 2: Pydantic model validation (if type hint available)
        if expected_type is not None:
            try:
                validated_model = expected_type.model_validate(data)
                logger.trace(f"Cache data validated against {expected_type.__name__}")
                return validated_model
            except ValidationError as e:
                logger.error(
                    f"Security Alert: Cache data failed validation for key {key}. "
                    f"Expected type: {expected_type.__name__}. "
                    f"Errors: {e.errors()}"
                )
                raise CacheDataIntegrityError(
                    f"Cache data failed validation: {e.errors()}"
                ) from e
        
        logger.trace(f"Cache data validated for key {key}")
        return data

    def _get_return_type(self, func) -> Type[BaseModel]:
        """
        Extract return type annotation from function.
        
        Args:
            func: The decorated function
            
        Returns:
            Return type annotation or None
        """
        try:
            hints = get_type_hints(func)
            return hints.get('return')
        except Exception:
            return None

    def cache(self):
        def passthrough(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                logger.trace(f"cache wrapper on route {func.__name__}")
                result = await func(*args, **kwargs)
                return result

            return wrapper

        def decorator(func):
            # Get the expected return type for validation
            return_type = self._get_return_type(func)
            
            @functools.wraps(func)
            async def wrapper(request: Request, payload: BaseModel):
                logger.trace(f"cache wrapper on route {func.__name__}")
                key = request.url.path + payload.model_dump_json()
                logger.trace(f"KEY: {key}")
                
                # Check if we have a value under this key
                if await self.redis.exists(key):
                    logger.trace("Returning a cached response...")
                    resp = await self.redis.get(key)
                    
                    if resp:
                        # SECURITY FIX (Issue #926): Validate data before returning
                        try:
                            # Step 1: Parse JSON safely
                            data = json.loads(resp)
                            
                            # Step 2: Validate data structure and type
                            validated_data = self._validate_cache_data(
                                data, 
                                key,
                                expected_type=return_type
                            )
                            
                            return validated_data
                            
                        except json.JSONDecodeError as e:
                            # Log potential attack or corruption
                            logger.error(
                                f"Security Alert: Invalid JSON in cache for key {key}. "
                                f"Possible data corruption or injection attempt. "
                                f"Error: {str(e)}"
                            )
                            # Delete corrupted cache entry to force fresh execution
                            await self.redis.delete(key)
                            raise CacheDeserializationError(
                                f"Invalid JSON in cache for key {key}"
                            ) from e
                            
                        except (CacheDeserializationError, CacheDataIntegrityError):
                            # Delete invalid cache entry
                            await self.redis.delete(key)
                            raise
                    else:
                        raise Exception(f"Found no cached response for key {key}")
                
                # Execute function and cache result
                result = await func(request, payload)
                
                # Cache the result as JSON
                await self.redis.set(
                    name=key,
                    value=result.model_dump_json(),
                    ex=settings.mint_redis_cache_ttl
                )
                return result

            return wrapper

        return passthrough if not settings.mint_redis_cache_enabled else decorator

    async def disconnect(self):
        if self.initialized:
            await self.redis.close()