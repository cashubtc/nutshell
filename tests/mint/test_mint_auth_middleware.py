from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request, Response

from cashu.core.errors import ClearAuthFailedError
from cashu.core.settings import settings
from cashu.mint.auth.base import User
from cashu.mint.middleware import BlindAuthMiddleware, ClearAuthMiddleware


def _request(path: str, headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": headers or [],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )


@pytest.mark.asyncio
async def test_clear_auth_middleware_skips_unprotected_paths(monkeypatch):
    middleware = ClearAuthMiddleware(FastAPI())
    monkeypatch.setattr(settings, "mint_require_auth", True)
    fake_auth_ledger = SimpleNamespace(
        mint_info=SimpleNamespace(
            requires_clear_auth_path=lambda method, path: False,
        )
    )
    monkeypatch.setattr("cashu.mint.middleware.auth_ledger", fake_auth_ledger)

    async def call_next(request: Request) -> Response:
        return Response(content=b"ok", status_code=200)

    response = await middleware.dispatch(_request("/v1/info"), call_next)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_clear_auth_middleware_requires_header_on_protected_paths(monkeypatch):
    middleware = ClearAuthMiddleware(FastAPI())
    monkeypatch.setattr(settings, "mint_require_auth", True)
    fake_auth_ledger = SimpleNamespace(
        mint_info=SimpleNamespace(
            requires_clear_auth_path=lambda method, path: True,
        )
    )
    monkeypatch.setattr("cashu.mint.middleware.auth_ledger", fake_auth_ledger)

    async def call_next(request: Request) -> Response:
        raise AssertionError("call_next should not be reached")

    with pytest.raises(Exception, match="Missing clear auth token"):
        await middleware.dispatch(_request("/v1/auth/blind/mint"), call_next)


@pytest.mark.asyncio
async def test_clear_auth_middleware_attaches_authenticated_user(monkeypatch):
    middleware = ClearAuthMiddleware(FastAPI())
    monkeypatch.setattr(settings, "mint_require_auth", True)
    expected_user = User(id="alice")

    class AuthLedger:
        mint_info = SimpleNamespace(
            requires_clear_auth_path=lambda method, path: True,
        )

        async def verify_clear_auth(self, clear_auth_token: str) -> User:
            assert clear_auth_token == "token"
            return expected_user

    monkeypatch.setattr("cashu.mint.middleware.auth_ledger", AuthLedger())

    async def call_next(request: Request) -> Response:
        assert request.state.user is expected_user
        return Response(content=b"ok", status_code=200)

    response = await middleware.dispatch(
        _request("/v1/auth/blind/mint", [(b"clear-auth", b"token")]),
        call_next,
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_clear_auth_middleware_propagates_auth_failures(monkeypatch):
    middleware = ClearAuthMiddleware(FastAPI())
    monkeypatch.setattr(settings, "mint_require_auth", True)

    class AuthLedger:
        mint_info = SimpleNamespace(
            requires_clear_auth_path=lambda method, path: True,
        )

        async def verify_clear_auth(self, clear_auth_token: str) -> User:
            raise ClearAuthFailedError()

    monkeypatch.setattr("cashu.mint.middleware.auth_ledger", AuthLedger())

    async def call_next(request: Request) -> Response:
        raise AssertionError("call_next should not be reached")

    with pytest.raises(ClearAuthFailedError):
        await middleware.dispatch(
            _request("/v1/auth/blind/mint", [(b"clear-auth", b"token")]),
            call_next,
        )


@pytest.mark.asyncio
async def test_blind_auth_middleware_skips_unprotected_paths(monkeypatch):
    middleware = BlindAuthMiddleware(FastAPI())
    monkeypatch.setattr(settings, "mint_require_auth", True)
    fake_auth_ledger = SimpleNamespace(
        mint_info=SimpleNamespace(
            requires_blind_auth_path=lambda method, path: False,
        )
    )
    monkeypatch.setattr("cashu.mint.middleware.auth_ledger", fake_auth_ledger)

    async def call_next(request: Request) -> Response:
        return Response(content=b"ok", status_code=200)

    response = await middleware.dispatch(_request("/v1/info"), call_next)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_blind_auth_middleware_requires_header_on_protected_paths(monkeypatch):
    middleware = BlindAuthMiddleware(FastAPI())
    monkeypatch.setattr(settings, "mint_require_auth", True)
    fake_auth_ledger = SimpleNamespace(
        mint_info=SimpleNamespace(
            requires_blind_auth_path=lambda method, path: True,
        )
    )
    monkeypatch.setattr("cashu.mint.middleware.auth_ledger", fake_auth_ledger)

    async def call_next(request: Request) -> Response:
        raise AssertionError("call_next should not be reached")

    with pytest.raises(Exception, match="Missing blind auth token"):
        await middleware.dispatch(_request("/v1/mint/quote/bolt11"), call_next)


@pytest.mark.asyncio
async def test_blind_auth_middleware_wraps_protected_paths(monkeypatch):
    middleware = BlindAuthMiddleware(FastAPI())
    monkeypatch.setattr(settings, "mint_require_auth", True)
    entered = {"value": False}

    class AuthLedger:
        mint_info = SimpleNamespace(
            requires_blind_auth_path=lambda method, path: True,
        )

        @asynccontextmanager
        async def verify_blind_auth(self, blind_auth_token: str):
            assert blind_auth_token == "bat"
            entered["value"] = True
            yield

    monkeypatch.setattr("cashu.mint.middleware.auth_ledger", AuthLedger())

    async def call_next(request: Request) -> Response:
        return Response(content=b"ok", status_code=200)

    response = await middleware.dispatch(
        _request("/v1/mint/quote/bolt11", [(b"blind-auth", b"bat")]),
        call_next,
    )
    assert entered["value"] is True
    assert response.status_code == 200
