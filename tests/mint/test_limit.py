import asyncio
import sys
from unittest.mock import AsyncMock

import httpx
import pytest
import websockets
from click.testing import CliRunner
from starlette.requests import Request
from starlette.responses import Response
from starlette.websockets import WebSocket
from uvicorn import Config, Server
from uvicorn.protocols.utils import get_client_addr

from cashu.core.settings import settings
from cashu.mint import app as mint_app
from cashu.mint import limit
from cashu.mint.main import main


@pytest.fixture(params=["http", "websocket"])
def resolve_key(request, monkeypatch):
    protocol = request.param
    configs = []
    monkeypatch.setattr(Server, "run", lambda server: configs.append(server.config))

    async def resolve(
        peer,
        headers,
        allow_ips,
        *,
        proxy_trust=True,
        cloudflare=False,
        direct=False,
        uds=None,
        server=None,
        log_address=None,
    ):
        monkeypatch.setattr(settings, "mint_forwarded_allow_ips", allow_ips)
        monkeypatch.setattr(settings, "mint_rate_limit_proxy_trust", proxy_trust)
        monkeypatch.setattr(settings, "mint_trust_cloudflare_connecting_ip", cloudflare)

        keys = []
        if protocol == "websocket":
            monkeypatch.setattr(limit, "assert_limit", keys.append)

        async def capture(scope, receive, send):
            if protocol == "http":
                keys.append(limit.get_remote_address_excluding_local(Request(scope)))
                await Response()(scope, receive, send)
            else:
                limit.limit_websocket(WebSocket(scope, receive, send))

        monkeypatch.setattr(mint_app.app.router, "middleware_stack", capture)
        monkeypatch.setattr(mint_app.app, "middleware_stack", None)
        if direct:
            config = Config("cashu.mint.app:app", forwarded_allow_ips=allow_ips)
        else:
            result = CliRunner().invoke(main, [f"--uds={uds}"] if uds else [])
            assert result.exit_code == 0, result.exception
            config = configs.pop()
        config.load()
        scope = {
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "server": server,
            "path": "/test-rate-key",
            "query_string": b"",
            "method": "GET",
            "type": protocol,
            "scheme": "http" if protocol == "http" else "ws",
            "client": (peer, 12345) if peer is not None else None,
            "headers": headers,
        }
        await config.loaded_app(scope, AsyncMock(), AsyncMock())
        if log_address is not None:
            assert get_client_addr(scope) == log_address
        assert scope["headers"] == headers
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


@pytest.mark.asyncio
async def test_direct_asgi_cloudflare(resolve_key):
    headers = [(b"cf-connecting-ip", b"203.0.113.15")]
    key = await resolve_key(
        "127.0.0.1", headers, "127.0.0.1", cloudflare=True, direct=True
    )
    assert key == "203.0.113.15"


@pytest.mark.asyncio
async def test_direct_asgi_keeps_server_resolved_client(resolve_key):
    headers = [
        (b"x-forwarded-for", b"192.0.2.10"),
        (b"cf-connecting-ip", b"203.0.113.15"),
    ]
    key = await resolve_key("127.0.0.1", headers, "*", cloudflare=True, direct=True)
    assert key == "192.0.2.10"


@pytest.mark.asyncio
async def test_verified_client_in_access_log(resolve_key):
    headers = [
        (b"x-forwarded-for", b"192.0.2.10"),
        (b"cf-connecting-ip", b"203.0.113.15"),
    ]
    key = await resolve_key(
        "127.0.0.1", headers, "127.0.0.1", cloudflare=True, log_address="203.0.113.15:0"
    )
    assert key == "203.0.113.15"


@pytest.mark.asyncio
async def test_allowlisted_unix_listener_keeps_clients_distinct(resolve_key):
    path = "/run/mint.sock"
    for address in ("192.0.2.1", "192.0.2.2"):
        headers = [(b"x-forwarded-for", address.encode())]
        assert await resolve_key(None, headers, path, uds=path) == address
        assert (
            await resolve_key(None, headers, path, server=(path, None), direct=True)
            == address
        )
    assert await resolve_key(None, [], path, uds=path) == "unknown"
    assert await resolve_key(None, headers, path, uds="/run/other.sock") == "unknown"
    assert await resolve_key(None, headers, path) == "unknown"


@pytest.mark.asyncio
async def test_direct_loopback_with_proxy_trust_disabled(resolve_key):
    headers = [(b"x-forwarded-proto", b"https")]
    assert await resolve_key("127.0.0.1", headers, "*", proxy_trust=False) == ""


@pytest.mark.skipif(sys.platform == "win32", reason="asyncio Unix sockets required")
@pytest.mark.asyncio
@pytest.mark.parametrize("outer_proxy", [False, True])
async def test_uvicorn_unix_listener(tmp_path, monkeypatch, outer_proxy):
    path = str(tmp_path / "mint.sock")
    monkeypatch.setattr(settings, "mint_rate_limit_proxy_trust", True)
    monkeypatch.setattr(settings, "mint_forwarded_allow_ips", path)
    monkeypatch.setattr(settings, "mint_trust_cloudflare_connecting_ip", outer_proxy)
    monkeypatch.setattr(mint_app.app, "middleware_stack", None)

    async def echo_address(scope, receive, send):
        if scope["type"] == "http":
            key = limit.get_remote_address_excluding_local(Request(scope))
            await Response(key)(scope, receive, send)
        else:
            ws = WebSocket(scope, receive, send)
            await ws.accept()
            await ws.send_text(limit.get_ws_remote_address(ws))
            await ws.close()

    monkeypatch.setattr(mint_app.app.router, "middleware_stack", echo_address)
    server = Server(
        Config(
            "cashu.mint.app:app",
            uds=path,
            lifespan="off",
            forwarded_allow_ips="*" if outer_proxy else "127.0.0.1",
        )
    )
    task = asyncio.create_task(server.serve())
    try:

        async def wait_for_startup():
            while not server.started:
                if task.done():
                    await task
                    pytest.fail("Uvicorn exited during startup")
                await asyncio.sleep(0.01)

        await asyncio.wait_for(wait_for_startup(), timeout=10)
        transport = httpx.AsyncHTTPTransport(uds=path)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://localhost"
        ) as client:
            for address in ("192.0.2.1", "192.0.2.2"):
                headers = {"x-forwarded-for": address}
                if outer_proxy:
                    headers = {
                        "x-forwarded-for": "192.0.2.10",
                        "cf-connecting-ip": address,
                    }
                response = await client.get("/test-rate-key", headers=headers)
                assert response.status_code == 200
                assert response.text == address
                async with websockets.unix_connect(
                    path, uri="ws://localhost/test-rate-key", extra_headers=headers
                ) as ws:
                    assert await ws.recv() == address
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=10)
