from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response, StreamingResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel

from cashu.core.base import (
    BlindedSignature,
    ProofSpentState,
    ProofState,
    Unit,
)
from cashu.core.errors import NotAllowedError
from cashu.core.settings import settings
from cashu.mint import app as app_module
from cashu.mint import middleware as middleware_module
from cashu.mint import router as router_module
from cashu.mint.cache import RedisCache


def _build_router_app() -> FastAPI:
    app = FastAPI()
    middleware_module.add_middlewares(app)
    app.middleware("http")(app_module.catch_exceptions)
    app.add_exception_handler(
        RequestValidationError,
        middleware_module.request_validation_exception_handler,
    )
    app.include_router(router_module.router)
    return app


def _dummy_keyset(keyset_id: str, active: bool = True):
    return SimpleNamespace(
        id=keyset_id,
        unit=Unit.sat,
        active=active,
        input_fee_ppk=1,
        public_keys_hex={1: "aa"},
        final_expiry=123,
    )


def _dummy_ledger():
    active = _dummy_keyset("active", active=True)
    inactive = _dummy_keyset("inactive", active=False)
    mint_info = SimpleNamespace(
        name="Mint",
        pubkey="02" * 33,
        version="Nutshell/1.0",
        description="Short",
        description_long="Long",
        contact=[],
        nuts={4: {"supported": True}},
        icon_url="https://mint.test/icon.png",
        tos_url="https://mint.test/tos",
        motd="Hello",
    )

    async def mint_quote(payload):
        return SimpleNamespace(
            quote="quote-1",
            request="lnbc1",
            amount=payload.amount,
            unit=payload.unit,
            paid=False,
            state=SimpleNamespace(value="UNPAID"),
            expiry=123,
            pubkey=payload.pubkey,
        )

    async def get_mint_quote(quote):
        return SimpleNamespace(
            quote=quote,
            request="lnbc1",
            amount=1,
            unit="sat",
            paid=False,
            state=SimpleNamespace(value="UNPAID"),
            expiry=123,
            pubkey=None,
        )

    async def melt_quote(payload):
        return router_module.PostMeltQuoteResponse(
            quote="melt-1",
            amount=1,
            unit="sat",
            request=payload.request,
            fee_reserve=1,
            state="UNPAID",
            expiry=123,
        )

    async def get_melt_quote(quote):
        return SimpleNamespace(
            quote=quote,
            amount=1,
            unit="sat",
            request="lnbc1",
            fee_reserve=1,
            paid=False,
            state=SimpleNamespace(value="UNPAID"),
            expiry=123,
            payment_preimage=None,
            change=None,
        )

    async def melt(proofs, quote, outputs):
        return router_module.PostMeltQuoteResponse(
            quote=quote,
            amount=1,
            unit="sat",
            request="lnbc1",
            fee_reserve=1,
            state="PAID",
            expiry=123,
            payment_preimage="11" * 32,
        )

    async def swap(proofs, outputs):
        return [BlindedSignature(id="active", amount=1, C_="aa")]

    async def restore(outputs):
        return outputs, [BlindedSignature(id="active", amount=1, C_="aa")]

    async def get_proofs_states(Ys):
        return [ProofState(Y=Ys[0], state=ProofSpentState.unspent)]

    db_read = SimpleNamespace(get_proofs_states=get_proofs_states)
    return SimpleNamespace(
        keyset=active,
        keysets={active.id: active, inactive.id: inactive},
        mint_info=mint_info,
        mint_quote=mint_quote,
        get_mint_quote=get_mint_quote,
        melt_quote=melt_quote,
        get_melt_quote=get_melt_quote,
        melt=melt,
        swap=swap,
        restore=restore,
        db_read=db_read,
    )


def test_create_app_sets_metadata():
    app = app_module.create_app()
    assert app.title == "Nutshell Mint"
    assert app.version == settings.version


def test_catch_exceptions_maps_cashu_errors_to_json():
    app = FastAPI()
    app.middleware("http")(app_module.catch_exceptions)

    @app.get("/cashu-error")
    async def cashu_error_route():
        raise NotAllowedError("nope")

    client = TestClient(app)
    response = client.get("/cashu-error")
    assert response.status_code == 400
    assert response.json() == {"detail": "nope", "code": NotAllowedError.code}


def test_catch_exceptions_maps_generic_errors_to_json():
    app = FastAPI()
    app.middleware("http")(app_module.catch_exceptions)

    @app.get("/boom")
    async def boom_route():
        raise RuntimeError("boom")

    client = TestClient(app)
    response = client.get("/boom")
    assert response.status_code == 400
    assert response.json() == {"detail": "boom", "code": 0}


@pytest.mark.asyncio
async def test_request_validation_exception_handler_logs_query_params(monkeypatch):
    captured: dict[str, dict | None] = {"detail": None}
    request = router_module.Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/test",
            "query_string": b"a=1",
            "headers": [],
        }
    )
    exc = RequestValidationError(
        [{"loc": ("query", "value"), "msg": "Field required", "type": "missing"}]
    )
    monkeypatch.setattr(
        middleware_module.logger,
        "error",
        lambda detail: captured.__setitem__("detail", detail),
    )

    response = await middleware_module.request_validation_exception_handler(
        request, exc
    )
    assert response.status_code == 422
    assert captured["detail"] is not None
    assert captured["detail"]["query_params"] == {"a": "1"}


def test_compression_middleware_prefers_brotli_over_other_encodings():
    app = FastAPI()
    app.add_middleware(middleware_module.CompressionMiddleware)

    @app.get("/data")
    async def data_route():
        return {"hello": "world"}

    client = TestClient(app)
    response = client.get("/data", headers={"Accept-Encoding": "br, gzip, deflate"})
    assert response.headers["content-encoding"] == "br"
    assert response.json() == {"hello": "world"}


@pytest.mark.asyncio
async def test_compression_middleware_streaming_response_bypasses_compression():
    middleware = middleware_module.CompressionMiddleware(FastAPI())
    request = router_module.Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/stream",
            "headers": [(b"accept-encoding", b"gzip")],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )

    async def call_next(request):
        async def generator():
            yield b"chunk-1"
            yield b"chunk-2"

        return StreamingResponse(generator(), media_type="text/plain")

    response = await middleware.dispatch(request, call_next)
    assert isinstance(response, Response)
    assert response.headers.get("content-encoding") is None


def test_router_endpoints_work_in_process(monkeypatch):
    monkeypatch.setattr(router_module, "ledger", _dummy_ledger())
    app = _build_router_app()
    client = TestClient(app)

    info = client.get("/v1/info")
    assert info.status_code == 200
    assert info.json()["name"] == "Mint"

    keys = client.get("/v1/keys")
    assert keys.status_code == 200
    assert len(keys.json()["keysets"]) == 1

    keysets = client.get("/v1/keysets")
    assert keysets.status_code == 200
    assert len(keysets.json()["keysets"]) == 2

    keyset = client.get("/v1/keys/active")
    assert keyset.status_code == 200
    assert keyset.json()["keysets"][0]["id"] == "active"


def test_router_keyset_lookup_returns_cashu_error(monkeypatch):
    monkeypatch.setattr(router_module, "ledger", _dummy_ledger())
    app = _build_router_app()
    client = TestClient(app)

    response = client.get("/v1/keys/missing")
    assert response.status_code == 400
    assert "keyset" in response.json()["detail"].lower()


def test_router_checkstate_and_restore_routes(monkeypatch):
    monkeypatch.setattr(router_module, "ledger", _dummy_ledger())
    app = _build_router_app()
    client = TestClient(app)

    state = client.post("/v1/checkstate", json={"Ys": ["Y1"]})
    assert state.status_code == 200
    assert state.json()["states"][0]["state"] == ProofSpentState.unspent.value

    restore = client.post(
        "/v1/restore",
        json={"outputs": [{"id": "active", "amount": 1, "B_": "ab"}]},
    )
    assert restore.status_code == 200
    assert restore.json()["outputs"][0]["B_"] == "ab"
    assert restore.json()["signatures"][0]["id"] == "active"


def test_router_restore_requires_outputs(monkeypatch):
    monkeypatch.setattr(router_module, "ledger", _dummy_ledger())
    app = _build_router_app()
    client = TestClient(app)

    response = client.post("/v1/restore", json={"outputs": []})
    assert response.status_code == 400
    assert response.json() == {"detail": "no outputs provided.", "code": 0}


def test_router_quote_routes_and_swap(monkeypatch):
    monkeypatch.setattr(router_module, "ledger", _dummy_ledger())
    app = _build_router_app()
    client = TestClient(app)

    mint_quote = client.post(
        "/v1/mint/quote/bolt11",
        json={"unit": "sat", "amount": 2, "description": "memo", "pubkey": None},
    )
    assert mint_quote.status_code == 200
    assert mint_quote.json()["quote"] == "quote-1"

    melt_quote = client.post(
        "/v1/melt/quote/bolt11",
        json={"unit": "sat", "request": "lnbc1"},
    )
    assert melt_quote.status_code == 200
    assert melt_quote.json()["quote"] == "melt-1"

    melt_get = client.get("/v1/melt/quote/bolt11/melt-1")
    assert melt_get.status_code == 200
    assert melt_get.json()["quote"] == "melt-1"

    swap = client.post(
        "/v1/swap",
        json={
            "inputs": [{"id": "active", "amount": 1, "secret": "sec", "C": "00"}],
            "outputs": [{"id": "active", "amount": 1, "B_": "ab"}],
        },
    )
    assert swap.status_code == 200
    assert swap.json()["signatures"][0]["id"] == "active"


@pytest.mark.asyncio
async def test_redis_cache_hit_and_miss(monkeypatch):
    set_calls: list[tuple[str, int]] = []
    closed = False

    class FakeRedis:
        def __init__(self):
            self.store = {}

        async def exists(self, key):
            return key in self.store

        async def get(self, key):
            return self.store.get(key)

        async def set(self, name, value, ex):
            self.store[name] = value
            set_calls.append((name, ex))

        async def ping(self):
            return True

        async def close(self):
            nonlocal closed
            closed = True

    class Payload(BaseModel):
        value: int

    fake_redis = FakeRedis()
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", True)
    monkeypatch.setattr(settings, "mint_redis_cache_url", "redis://cache")
    monkeypatch.setattr(settings, "mint_redis_cache_ttl", 12)
    monkeypatch.setattr("cashu.mint.cache.from_url", lambda url: fake_redis)
    cache = RedisCache()

    @cache.cache()
    async def cached_route(request, payload):
        return Payload(value=payload.value + 1)

    request = router_module.Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/test",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )
    payload = Payload(value=2)

    first = await cached_route(request, payload)
    second = await cached_route(request, payload)

    assert first == Payload(value=3)
    assert second == {"value": 3}
    assert len(set_calls) == 1

    await cache.test_connection()
    assert cache.initialized is True
    await cache.disconnect()
    assert closed is True
