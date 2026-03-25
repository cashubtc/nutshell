"""Tests for cache deserialization validation (Issue #924)."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_cache_rejects_invalid_json():
    """Cache should handle corrupted JSON data gracefully."""
    from cashu.mint.cache import RedisCache

    with patch("cashu.mint.cache.settings") as mock_settings:
        mock_settings.mint_redis_cache_enabled = True
        mock_settings.mint_redis_cache_url = "redis://localhost"
        mock_settings.mint_redis_cache_ttl = 60

        cache = RedisCache()
        cache.redis = AsyncMock()
        cache.redis.exists = AsyncMock(return_value=True)
        cache.redis.get = AsyncMock(return_value=b"not valid json{{{")
        cache.redis.delete = AsyncMock()

        @cache.cache()
        async def dummy_route(request, payload):
            return MagicMock()

        mock_request = MagicMock()
        mock_request.url.path = "/test"
        mock_payload = MagicMock()
        mock_payload.model_dump_json.return_value = "{}"

        with pytest.raises(ValueError, match="Corrupted cache entry"):
            await dummy_route(mock_request, mock_payload)

        cache.redis.delete.assert_called_once()


@pytest.mark.asyncio
async def test_cache_rejects_non_dict_data():
    """Cache should reject non-dict deserialized data."""
    from cashu.mint.cache import RedisCache

    with patch("cashu.mint.cache.settings") as mock_settings:
        mock_settings.mint_redis_cache_enabled = True
        mock_settings.mint_redis_cache_url = "redis://localhost"
        mock_settings.mint_redis_cache_ttl = 60

        cache = RedisCache()
        cache.redis = AsyncMock()
        cache.redis.exists = AsyncMock(return_value=True)
        cache.redis.get = AsyncMock(return_value=json.dumps([1, 2, 3]).encode())
        cache.redis.delete = AsyncMock()

        @cache.cache()
        async def dummy_route(request, payload):
            return MagicMock()

        mock_request = MagicMock()
        mock_request.url.path = "/test"
        mock_payload = MagicMock()
        mock_payload.model_dump_json.return_value = "{}"

        with pytest.raises(ValueError, match="Invalid cache data type"):
            await dummy_route(mock_request, mock_payload)


@pytest.mark.asyncio
async def test_cache_accepts_valid_dict():
    """Cache should accept valid dict data."""
    from cashu.mint.cache import RedisCache

    with patch("cashu.mint.cache.settings") as mock_settings:
        mock_settings.mint_redis_cache_enabled = True
        mock_settings.mint_redis_cache_url = "redis://localhost"
        mock_settings.mint_redis_cache_ttl = 60

        cache = RedisCache()
        cache.redis = AsyncMock()
        cache.redis.exists = AsyncMock(return_value=True)
        cache.redis.get = AsyncMock(
            return_value=json.dumps({"status": "ok"}).encode()
        )

        @cache.cache()
        async def dummy_route(request, payload):
            return MagicMock()

        mock_request = MagicMock()
        mock_request.url.path = "/test"
        mock_payload = MagicMock()
        mock_payload.model_dump_json.return_value = "{}"

        result = await dummy_route(mock_request, mock_payload)
        assert result == {"status": "ok"}
