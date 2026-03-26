from types import MethodType
from typing import Any, cast

import httpx
import pytest

from cashu.core.base import Proof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.db import Database
from cashu.core.settings import settings
from cashu.wallet.v1_api import LedgerAPI


class DummyMintInfo:
    def __init__(self, blind: bool = False, clear: bool = False):
        self.blind = blind
        self.clear = clear

    def requires_blind_auth_path(self, method: str, path: str) -> bool:
        return self.blind

    def requires_clear_auth_path(self, method: str, path: str) -> bool:
        return self.clear


class DummyHTTPXClient:
    def __init__(self, response: httpx.Response):
        self.response = response
        self.calls: list[tuple[str, str, dict]] = []

    async def request(self, method: str, path: str, **kwargs):
        self.calls.append((method, path, kwargs))
        return self.response


def _response(status_code: int, json_data=None, *, text: str = "") -> httpx.Response:
    request = httpx.Request("GET", "https://mint.test/v1/test")
    if json_data is not None:
        return httpx.Response(status_code, json=json_data, request=request)
    return httpx.Response(status_code, text=text, request=request)


@pytest.fixture
def api(tmp_path):
    wallet_db = Database("wallet", str(tmp_path))
    ledger_api = LedgerAPI(url="https://mint.test", db=wallet_db)
    ledger_api.mint_info = None
    ledger_api.auth_db = None
    ledger_api.auth_keyset_id = None
    return ledger_api


def test_raise_on_error_request_uses_detail_and_code(api: LedgerAPI):
    response = _response(400, {"detail": "boom", "code": 1234})
    with pytest.raises(Exception, match=r"Mint Error: boom \(Code: 1234\)"):
        api.raise_on_error_request(response)


def test_raise_on_error_request_raises_http_status_for_non_json(api: LedgerAPI):
    response = _response(500, text="server exploded")
    with pytest.raises(httpx.HTTPStatusError):
        api.raise_on_error_request(response)


def test_raise_on_unsupported_version_404_has_clear_message(api: LedgerAPI):
    response = _response(404, {"detail": "not found"})
    with pytest.raises(Exception, match="does not support endpoint GET /v1/keys"):
        api.raise_on_unsupported_version(response, "GET /v1/keys")


@pytest.mark.asyncio
async def test_request_adds_blind_auth_header(monkeypatch, api: LedgerAPI):
    api.mint_info = cast(Any, DummyMintInfo(blind=True))
    api.auth_db = api.db
    api.auth_keyset_id = "auth-keyset"

    proof = Proof(id="auth-id", amount=1, secret="blind-secret", C="blind-C")
    invalidated = {"proof": None}

    async def fake_get_proofs(*, db, id):
        assert db is api.auth_db
        assert id == "auth-keyset"
        return [proof]

    async def fake_invalidate_proof(*, proof, db):
        invalidated["proof"] = proof
        assert db is api.auth_db

    monkeypatch.setattr("cashu.wallet.v1_api.get_proofs", fake_get_proofs)
    monkeypatch.setattr("cashu.wallet.v1_api.invalidate_proof", fake_invalidate_proof)

    cast(Any, api).httpx = DummyHTTPXClient(_response(200, {"ok": True}))
    await api._request("POST", "swap", json={"k": "v"})

    method, path, kwargs = cast(Any, api).httpx.calls[0]
    assert method == "POST"
    assert path == "v1/swap"
    assert kwargs["headers"]["Blind-auth"].startswith("authA")
    assert invalidated["proof"] == proof


@pytest.mark.asyncio
async def test_request_blind_auth_requires_auth_db(api: LedgerAPI):
    api.mint_info = cast(Any, DummyMintInfo(blind=True))
    api.auth_db = None
    api.auth_keyset_id = "auth-keyset"
    cast(Any, api).httpx = DummyHTTPXClient(_response(200, {"ok": True}))

    with pytest.raises(Exception, match="no auth database"):
        await api._request("POST", "swap")


@pytest.mark.asyncio
async def test_request_blind_auth_requires_keyset_id(api: LedgerAPI):
    api.mint_info = cast(Any, DummyMintInfo(blind=True))
    api.auth_db = api.db
    api.auth_keyset_id = None
    cast(Any, api).httpx = DummyHTTPXClient(_response(200, {"ok": True}))

    with pytest.raises(Exception, match="no auth keyset id"):
        await api._request("POST", "swap")


@pytest.mark.asyncio
async def test_request_blind_auth_requires_tokens(monkeypatch, api: LedgerAPI):
    api.mint_info = cast(Any, DummyMintInfo(blind=True))
    api.auth_db = api.db
    api.auth_keyset_id = "auth-keyset"

    async def fake_get_proofs(*, db, id):
        return []

    monkeypatch.setattr("cashu.wallet.v1_api.get_proofs", fake_get_proofs)
    cast(Any, api).httpx = DummyHTTPXClient(_response(200, {"ok": True}))

    with pytest.raises(Exception, match="no blind auth tokens were found"):
        await api._request("POST", "swap")


@pytest.mark.asyncio
async def test_request_adds_clear_auth_header(api: LedgerAPI):
    api.mint_info = cast(Any, DummyMintInfo(clear=True))
    cast(Any, api).httpx = DummyHTTPXClient(_response(200, {"ok": True}))

    await api._request("POST", "swap", clear_auth_token="clear-token")
    _, path, kwargs = cast(Any, api).httpx.calls[0]
    assert path == "v1/swap"
    assert kwargs["headers"]["Clear-auth"] == "clear-token"


@pytest.mark.asyncio
async def test_request_clear_auth_requires_token(api: LedgerAPI):
    api.mint_info = cast(Any, DummyMintInfo(clear=True))
    cast(Any, api).httpx = DummyHTTPXClient(_response(200, {"ok": True}))

    with pytest.raises(Exception, match="no clear auth token is set"):
        await api._request("POST", "swap", clear_auth_token=None)


@pytest.mark.asyncio
async def test_request_respects_noprefix(api: LedgerAPI):
    cast(Any, api).httpx = DummyHTTPXClient(_response(200, {"ok": True}))
    await api._request("GET", "/v1/info", noprefix=True)
    _, path, _ = cast(Any, api).httpx.calls[0]
    assert path == "/v1/info"


@pytest.mark.asyncio
async def test_init_sets_http_client_configuration(monkeypatch, api: LedgerAPI):
    created_kwargs = {}

    class FakeAsyncClient:
        def __init__(self, **kwargs):
            created_kwargs.update(kwargs)

    monkeypatch.setattr("cashu.wallet.v1_api.httpx.AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(settings, "tor", False)
    monkeypatch.setattr(settings, "socks_proxy", None)
    monkeypatch.setattr(settings, "http_proxy", None)

    await api._init_s()

    assert created_kwargs["base_url"] == "https://mint.test"
    assert created_kwargs["headers"]["Client-version"] == settings.version
    assert created_kwargs["verify"] is (not settings.debug)


@pytest.mark.asyncio
async def test_get_keys_parses_response(monkeypatch, api: LedgerAPI):
    pubkey_hex = PrivateKey().public_key.format().hex()
    response = _response(
        200,
        {
            "keysets": [
                {
                    "id": "keyset-1",
                    "unit": "sat",
                    "active": True,
                    "input_fee_ppk": 0,
                    "keys": {"1": pubkey_hex},
                }
            ]
        },
    )

    async def fake_request(self, method, path, **kwargs):
        assert method == "GET"
        assert path == "keys"
        return response

    monkeypatch.setattr(api, "_request", MethodType(fake_request, api))
    keysets = await api._get_keys()
    assert len(keysets) == 1
    assert keysets[0].id == "keyset-1"
    assert keysets[0].public_keys[1].format().hex() == pubkey_hex


@pytest.mark.asyncio
async def test_get_keyset_uses_urlsafe_keyset_id(monkeypatch, api: LedgerAPI):
    pubkey_hex = PrivateKey().public_key.format().hex()
    response = _response(
        200,
        {
            "keysets": [
                {
                    "id": "server-id",
                    "unit": "sat",
                    "active": True,
                    "input_fee_ppk": 0,
                    "keys": {"1": pubkey_hex},
                }
            ]
        },
    )

    async def fake_request(self, method, path, **kwargs):
        assert path == "keys/a-_b"
        return response

    monkeypatch.setattr(api, "_request", MethodType(fake_request, api))
    keyset = await api._get_keyset("a+/b")
    assert keyset.id == "a+/b"


@pytest.mark.asyncio
async def test_get_keysets_raises_for_empty_response(monkeypatch, api: LedgerAPI):
    async def fake_request(self, method, path, **kwargs):
        return _response(200, {"keysets": []})

    monkeypatch.setattr(api, "_request", MethodType(fake_request, api))
    with pytest.raises(Exception, match="did not receive any keysets"):
        await api._get_keysets()


@pytest.mark.asyncio
async def test_get_info_uses_unprefixed_path(monkeypatch, api: LedgerAPI):
    async def fake_request(self, method, path, **kwargs):
        assert method == "GET"
        assert path == "/v1/info"
        assert kwargs["noprefix"] is True
        return _response(200, {"name": "MintName", "version": "1.0.0"})

    monkeypatch.setattr(api, "_request", MethodType(fake_request, api))
    mint_info = await api._get_info()
    assert mint_info.name == "MintName"


@pytest.mark.asyncio
async def test_get_keys_raises_when_endpoint_not_supported(monkeypatch, api: LedgerAPI):
    async def fake_request(self, method, path, **kwargs):
        return _response(404, {"detail": "not found"})

    monkeypatch.setattr(api, "_request", MethodType(fake_request, api))
    with pytest.raises(Exception, match="does not support endpoint Get /v1/keys"):
        await api._get_keys()
