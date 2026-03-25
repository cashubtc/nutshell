"""Tests for cache deserialization validation (Issue #924)."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_cache_calls_original_on_invalid_json():
    """On corrupted JSON, cache should delete entry and call the original function."""
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
        cache.redis.set = AsyncMock()

        expected_result = MagicMock()
        expected_result.model_dump_json.return_value = '{"ok": true}'

        @cache.cache()
        async def dummy_route(request, payload):
            return expected_result

        mock_request = MagicMock()
        mock_request.url.path = "/test"
        mock_payload = MagicMock()
        mock_payload.model_dump_json.return_value = "{}"

        result = await dummy_route(mock_request, mock_payload)
        cache.redis.delete.assert_called_once()
        assert result is expected_result


@pytest.mark.asyncio
async def test_cache_calls_original_on_non_dict():
    """On non-dict cache data, cache should delete entry and call the original function."""
    from cashu.mint.cache import RedisCache

    with patch("cashu.mint.cache.settings") as mock_settings:
        mock_settings.mint_redis_cache_enabled = True
        mock_settings.mint_redis_cache_url = "redis://localhost"
        mock_settings.mint_redis_cache_ttl = 60

        cache = RedisCache()
        cache.redis = AsyncMock()
        cache.redis.exists = AsyncMock(return_value=True)
        cache.redis.get = AsyncMock(return_value=b'[1, 2, 3]')
        cache.redis.delete = AsyncMock()
        cache.redis.set = AsyncMock()

        expected_result = MagicMock()
        expected_result.model_dump_json.return_value = '{"ok": true}'

        @cache.cache()
        async def dummy_route(request, payload):
            return expected_result

        mock_request = MagicMock()
        mock_request.url.path = "/test"
        mock_payload = MagicMock()
        mock_payload.model_dump_json.return_value = "{}"

        result = await dummy_route(mock_request, mock_payload)
        cache.redis.delete.assert_called_once()
        assert result is expected_result


@pytest.mark.asyncio
async def test_cache_returns_valid_dict():
    """Valid dict cache data should be returned directly."""
    from cashu.mint.cache import RedisCache

    with patch("cashu.mint.cache.settings") as mock_settings:
        mock_settings.mint_redis_cache_enabled = True
        mock_settings.mint_redis_cache_url = "redis://localhost"
        mock_settings.mint_redis_cache_ttl = 60

        cache = RedisCache()
        cache.redis = AsyncMock()
        cache.redis.exists = AsyncMock(return_value=True)
        cache.redis.get = AsyncMock(return_value=b'{"status": "ok", "amount": 100}')
        cache.redis.delete = AsyncMock()

        @cache.cache()
        async def dummy_route(request, payload):
            return MagicMock()

        mock_request = MagicMock()
        mock_request.url.path = "/test"
        mock_payload = MagicMock()
        mock_payload.model_dump_json.return_value = "{}"

        result = await dummy_route(mock_request, mock_payload)
        assert result == {"status": "ok", "amount": 100}
        cache.redis.delete.assert_not_called()
