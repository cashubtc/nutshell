from unittest.mock import patch

import pytest
from starlette.requests import Request
from starlette.websockets import WebSocket

from cashu.core.settings import settings
from cashu.mint.limit import (
    _get_client_ip,
    _rate_limit_exceeded_handler,
    assert_limit,
    get_remote_address_excluding_local,
    get_ws_remote_address,
    limit_websocket,
)


def test_get_client_ip_proxy_trust_enabled():
    settings.mint_rate_limit_proxy_trust = True

    # Test CF-Connecting-IP
    scope = {
        "type": "http",
        "headers": [(b"cf-connecting-ip", b"203.0.113.1")],
        "client": ("127.0.0.1", 8000),
    }
    request = Request(scope)
    assert _get_client_ip(request) == "203.0.113.1"

    # Test X-Forwarded-For
    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"203.0.113.2, 198.51.100.1")],
        "client": ("127.0.0.1", 8000),
    }
    request = Request(scope)
    assert _get_client_ip(request) == "198.51.100.1"

    # Test fallback to client IP
    scope = {
        "type": "http",
        "headers": [],
        "client": ("203.0.113.3", 8000),
    }
    request = Request(scope)
    assert _get_client_ip(request) == "203.0.113.3"


def test_get_client_ip_ignores_headers_from_untrusted_peer(monkeypatch):
    monkeypatch.setattr(settings, "mint_rate_limit_proxy_trust", True)
    monkeypatch.setattr(settings, "mint_forwarded_allow_ips", "127.0.0.1")
    # a client connecting directly cannot choose its rate-limit bucket
    scope = {
        "type": "http",
        "headers": [
            (b"cf-connecting-ip", b"203.0.113.1"),
            (b"x-forwarded-for", b"203.0.113.2"),
        ],
        "client": ("198.51.100.7", 8000),
    }
    assert _get_client_ip(Request(scope)) == "198.51.100.7"

    # behind a trusted proxy that appends, a spoofed leading entry is ignored
    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"6.6.6.6, 198.51.100.7")],
        "client": ("127.0.0.1", 8000),
    }
    assert _get_client_ip(Request(scope)) == "198.51.100.7"

    # trusted networks and '*' are honoured
    monkeypatch.setattr(settings, "mint_forwarded_allow_ips", "10.0.0.0/8")
    scope = {
        "type": "http",
        "headers": [(b"cf-connecting-ip", b"203.0.113.1")],
        "client": ("10.1.2.3", 8000),
    }
    assert _get_client_ip(Request(scope)) == "203.0.113.1"
    monkeypatch.setattr(settings, "mint_forwarded_allow_ips", "*")
    scope["client"] = ("198.51.100.7", 8000)
    assert _get_client_ip(Request(scope)) == "203.0.113.1"


def test_get_client_ip_trusted_proxy_edge_cases(monkeypatch):
    monkeypatch.setattr(settings, "mint_rate_limit_proxy_trust", True)

    # a peer that is not an IP literal is matched by name; an invalid
    # entry in the list is skipped rather than raising
    monkeypatch.setattr(settings, "mint_forwarded_allow_ips", "not-an-ip, proxy.local")
    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"203.0.113.9")],
        "client": ("proxy.local", 8000),
    }
    assert _get_client_ip(Request(scope)) == "203.0.113.9"
    scope["client"] = ("other.local", 8000)
    assert _get_client_ip(Request(scope)) == "other.local"
    scope["client"] = ("198.51.100.7", 8000)
    assert _get_client_ip(Request(scope)) == "198.51.100.7"

    # when every forwarded entry is itself a trusted proxy, the leftmost wins
    monkeypatch.setattr(settings, "mint_forwarded_allow_ips", "10.0.0.0/8")
    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"10.0.0.2, 10.0.0.3")],
        "client": ("10.0.0.4", 8000),
    }
    assert _get_client_ip(Request(scope)) == "10.0.0.2"


def test_get_client_ip_proxy_trust_disabled():
    settings.mint_rate_limit_proxy_trust = False

    # Test headers are ignored
    scope = {
        "type": "http",
        "headers": [
            (b"cf-connecting-ip", b"203.0.113.1"),
            (b"x-forwarded-for", b"203.0.113.2"),
        ],
        "client": ("203.0.113.3", 8000),
    }
    request = Request(scope)
    assert _get_client_ip(request) == "203.0.113.3"


def test_get_ws_remote_address_proxy_trust_enabled():
    settings.mint_rate_limit_proxy_trust = True

    # Test CF-Connecting-IP
    scope = {
        "type": "websocket",
        "headers": [(b"cf-connecting-ip", b"203.0.113.1")],
        "client": ("127.0.0.1", 8000),
    }

    async def dummy_receive():
        pass

    async def dummy_send(msg):
        pass

    ws = WebSocket(scope, dummy_receive, dummy_send)
    assert get_ws_remote_address(ws) == "203.0.113.1"

    # Test X-Forwarded-For
    scope = {
        "type": "websocket",
        "headers": [(b"x-forwarded-for", b"203.0.113.2, 198.51.100.1")],
        "client": ("127.0.0.1", 8000),
    }
    ws = WebSocket(scope, dummy_receive, dummy_send)
    assert get_ws_remote_address(ws) == "198.51.100.1"

    # Test fallback to client IP
    scope = {
        "type": "websocket",
        "headers": [],
        "client": ("203.0.113.3", 8000),
    }
    ws = WebSocket(scope, dummy_receive, dummy_send)
    assert get_ws_remote_address(ws) == "203.0.113.3"


def test_get_ws_remote_address_proxy_trust_disabled():
    settings.mint_rate_limit_proxy_trust = False

    # Test headers are ignored
    scope = {
        "type": "websocket",
        "headers": [
            (b"cf-connecting-ip", b"203.0.113.1"),
            (b"x-forwarded-for", b"203.0.113.2"),
        ],
        "client": ("203.0.113.3", 8000),
    }

    async def dummy_receive():
        pass

    async def dummy_send(msg):
        pass

    ws = WebSocket(scope, dummy_receive, dummy_send)
    assert get_ws_remote_address(ws) == "203.0.113.3"

    # Test no client host
    scope = {
        "type": "websocket",
        "headers": [],
        "client": None,
    }
    ws = WebSocket(scope, dummy_receive, dummy_send)
    assert get_ws_remote_address(ws) == "127.0.0.1"


def test_rate_limit_exceeded_handler():
    settings.mint_rate_limit_proxy_trust = True
    scope = {
        "type": "http",
        "headers": [(b"cf-connecting-ip", b"203.0.113.1")],
        "client": ("127.0.0.1", 8000),
    }
    request = Request(scope)
    response = _rate_limit_exceeded_handler(request, Exception("Test"))
    assert response.status_code == 429
    assert response.body == b'{"detail":"Rate limit exceeded."}'


def test_get_remote_address_excluding_local():
    settings.mint_rate_limit_proxy_trust = True
    # Test remote
    scope = {
        "type": "http",
        "headers": [(b"cf-connecting-ip", b"203.0.113.1")],
        "client": ("127.0.0.1", 8000),
    }
    request = Request(scope)
    assert get_remote_address_excluding_local(request) == "203.0.113.1"

    # Test local
    scope = {
        "type": "http",
        "headers": [],
        "client": ("127.0.0.1", 8000),
    }
    request = Request(scope)
    assert get_remote_address_excluding_local(request) == ""


def test_limit_websocket():
    settings.mint_rate_limit_proxy_trust = True

    async def dummy_receive():
        pass

    async def dummy_send(msg):
        pass

    # Local shouldn't limit
    scope_local = {
        "type": "websocket",
        "headers": [],
        "client": ("127.0.0.1", 8000),
    }
    ws_local = WebSocket(scope_local, dummy_receive, dummy_send)

    # This shouldn't raise exception
    limit_websocket(ws_local)

    # Remote should limit
    scope_remote = {
        "type": "websocket",
        "headers": [],
        "client": ("203.0.113.1", 8000),
    }
    ws_remote = WebSocket(scope_remote, dummy_receive, dummy_send)

    with patch("cashu.mint.limit.assert_limit") as mock_assert:
        limit_websocket(ws_remote)
        mock_assert.assert_called_once_with("203.0.113.1")


def test_assert_limit():
    # It uses a global slowapi Limiter
    with patch("cashu.mint.limit.limiter._limiter.hit") as mock_hit:
        mock_hit.return_value = False
        with pytest.raises(Exception, match="Rate limit exceeded"):
            assert_limit("1.2.3.4", limit=10)

        mock_hit.return_value = True
        # Shouldn't raise
        assert_limit("1.2.3.4", limit=10)
