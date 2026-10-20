from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from cashu.core.base import AuthProof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.nuts import nut22
from cashu.core.settings import settings
from cashu.mint.middleware import WebSocketAuthMiddleware


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [False, True])
async def test_v3_bat_authorizes_the_websocket_upgrade(monkeypatch, valid):
    key = PrivateKey((3).to_bytes(32, "big"))
    target = "/v1/ws?q=a%20b&b=2"
    proof = AuthProof(
        id="02" + "ab" * 32, secret=key.public_key.format().hex(), C="aa" * 48
    )
    proof.witness = nut22.sign_request(key, "GET", target if valid else "/v1/swap", b"")
    events = []

    @asynccontextmanager
    async def authorize(token, **request):
        presented = AuthProof.from_base64(token)
        if not nut22.verify_bat_request_witness(presented, **request):
            raise ValueError("Invalid authorization")
        events.append("authorized")
        yield
        events.append("spent")

    fake = SimpleNamespace(
        mint_info=SimpleNamespace(
            requires_blind_auth_path=lambda method, path: method == "GET"
            and path == "/v1/ws",
            requires_clear_auth_path=lambda method, path: False,
        ),
        verify_blind_auth=authorize,
    )
    monkeypatch.setattr(settings, "mint_require_auth", True)
    monkeypatch.setattr("cashu.mint.middleware.auth_ledger", fake)

    async def app(scope, receive, send):
        await send({"type": "websocket.accept"})
        events.append("connected")
        await send({"type": "websocket.close", "code": 1000})

    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "websocket.connect"}

    scope = {
        "type": "websocket",
        "path": "/cashu/v1/ws",
        "raw_path": b"/cashu/v1/ws",
        "root_path": "/cashu",
        "query_string": b"q=a%20b&b=2",
        "headers": [(b"blind-auth", proof.to_base64().encode())],
    }
    await WebSocketAuthMiddleware(app)(scope, receive, send)
    if valid:
        assert events == ["authorized", "spent", "connected"]
        assert sent[0]["type"] == "websocket.accept"
    else:
        assert events == []
        assert sent == [{"type": "websocket.close", "code": 1008}]


@pytest.mark.parametrize(
    "raw,mount,expected",
    [
        (b"/cashu/v1/swap?b=2&a=1", "/cashu", "/v1/swap?b=2&a=1"),
        (b"/ca%20shu/v1/swap?q=a%20b", "/ca shu", "/v1/swap?q=a%20b"),
        (b"/cashu/v1%2Fswap", "/cashu", "/v1%2Fswap"),
    ],
)
def test_request_targets_preserve_endpoint_encoding(raw, mount, expected):
    assert nut22.relative_request_target(raw, mount) == expected
