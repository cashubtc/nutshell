from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner
from starlette.requests import Request
from starlette.websockets import WebSocket
from uvicorn import Server

from cashu.core.settings import settings
from cashu.mint import app as mint_app
from cashu.mint import limit
from cashu.mint.main import main


@pytest.fixture(params=["http", "websocket"])
def resolve_key(request, monkeypatch):
    protocol = request.param
    configs = []
    monkeypatch.setattr(Server, "run", lambda server: configs.append(server.config))

    async def resolve(peer, headers, allow_ips, *, proxy_trust=True, cloudflare=False):
        monkeypatch.setattr(settings, "mint_forwarded_allow_ips", allow_ips)
        monkeypatch.setattr(settings, "mint_rate_limit_proxy_trust", proxy_trust)
        monkeypatch.setattr(settings, "mint_trust_cloudflare_connecting_ip", cloudflare)

        keys = []
        if protocol == "websocket":
            monkeypatch.setattr(limit, "assert_limit", keys.append)

        async def capture(scope, receive, send):
            if protocol == "http":
                keys.append(limit.get_remote_address_excluding_local(Request(scope)))
            else:
                limit.limit_websocket(WebSocket(scope, receive, send))

        monkeypatch.setattr(mint_app, "app", capture)
        result = CliRunner().invoke(main)
        assert result.exit_code == 0, result.exception
        config = configs.pop()
        config.load()
        scope = {
            "type": protocol,
            "scheme": "http" if protocol == "http" else "ws",
            "client": (peer, 12345) if peer is not None else None,
            "headers": headers,
        }
        await config.loaded_app(scope, AsyncMock(), AsyncMock())
        return keys[0] if keys else ""

    return resolve


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "peer, allow_ips, expected",
    [
        ("127.0.0.1", "127.0.0.1", "198.51.100.2"),
        ("192.0.2.1", "127.0.0.1", "192.0.2.1"),
        ("192.0.2.1", "*", "198.51.100.1"),
        ("192.0.2.1", "127.0.0.1,*", "192.0.2.1"),
        ("192.0.2.1", "192.0.2.0/24", "198.51.100.2"),
        ("192.0.2.1", "192.0.2.3/24", "192.0.2.1"),
        ("proxy.local", "proxy.local", "198.51.100.2"),
        ("proxy.local", "other.local", "proxy.local"),
        ("192.0.2.1", "192.0.2.0/24,198.51.100.0/24", "198.51.100.1"),
        (None, "127.0.0.1", "unknown"),
        (None, "*", "198.51.100.1"),
    ],
)
async def test_forwarded_client(resolve_key, peer, allow_ips, expected):
    headers = [
        (b"x-forwarded-for", b"198.51.100.1, 198.51.100.2"),
        (b"cf-connecting-ip", b"203.0.113.1"),
    ]
    assert await resolve_key(peer, headers, allow_ips) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "peer, values, expected",
    [
        ("127.0.0.1", [b"203.0.113.1"], "203.0.113.1"),
        ("127.0.0.1", [b" 2001:db8::1 "], "2001:db8::1"),
        ("127.0.0.1", [], "198.51.100.2"),
        ("127.0.0.1", [b"invalid"], "198.51.100.2"),
        ("127.0.0.1", [b"203.0.113.1", b"203.0.113.2"], "198.51.100.2"),
        ("192.0.2.1", [b"203.0.113.1"], "192.0.2.1"),
    ],
)
async def test_verified_cloudflare_client(resolve_key, peer, values, expected):
    headers = [(b"cf-connecting-ip", value) for value in values]
    headers.append((b"x-forwarded-for", b"198.51.100.2"))
    assert await resolve_key(peer, headers, "127.0.0.1", cloudflare=True) == expected


@pytest.mark.asyncio
async def test_forwarding_disabled(resolve_key):
    headers = [
        (b"x-forwarded-for", b"198.51.100.1"),
        (b"cf-connecting-ip", b"203.0.113.1"),
    ]
    key = await resolve_key(
        "192.0.2.1", headers, "*", proxy_trust=False, cloudflare=True
    )
    assert key == "192.0.2.1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "peer, headers, expected",
    [
        (None, [], "unknown"),
        ("", [], "unknown"),
        ("127.0.0.1", [], ""),
        ("127.0.0.1", [(b"cf-connecting-ip", b"203.0.113.1")], "127.0.0.1"),
        ("192.0.2.1", [(b"x-forwarded-for", b"127.0.0.1")], "127.0.0.1"),
    ],
)
async def test_local_exemption(resolve_key, peer, headers, expected):
    assert await resolve_key(peer, headers, "192.0.2.1") == expected
