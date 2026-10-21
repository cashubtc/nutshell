import json
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from cashu.mint import limit


def _request() -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "headers": []})


def test_rate_limit_exceeded_handler_returns_429(monkeypatch):
    monkeypatch.setattr(limit, "get_remote_address", lambda request: "203.0.113.4")
    response = limit._rate_limit_exceeded_handler(_request(), Exception("boom"))
    assert response.status_code == 429
    assert json.loads(response.body) == {"detail": "Rate limit exceeded."}


def test_get_remote_address_excluding_local(monkeypatch):
    monkeypatch.setattr(limit, "get_remote_address", lambda request: "127.0.0.1")
    assert limit.get_remote_address_excluding_local(_request()) == ""

    monkeypatch.setattr(limit, "get_remote_address", lambda request: "198.51.100.2")
    assert limit.get_remote_address_excluding_local(_request()) == "198.51.100.2"


def test_assert_limit_allows_when_hit_succeeds(monkeypatch):
    class FakeLimiter:
        def __init__(self):
            self._limiter = self
            self.calls = []

        def hit(self, item, identifier):
            self.calls.append((item.amount, identifier))
            return True

    fake = FakeLimiter()
    monkeypatch.setattr(limit, "limiter", fake)
    limit.assert_limit("client-1", limit=12)
    assert fake.calls == [(12, "client-1")]


def test_assert_limit_raises_when_rate_exceeded(monkeypatch):
    class FakeLimiter:
        def __init__(self):
            self._limiter = self

        def hit(self, item, identifier):
            return False

    monkeypatch.setattr(limit, "limiter", FakeLimiter())
    with pytest.raises(Exception, match="Rate limit exceeded"):
        limit.assert_limit("client-2", limit=1)


def test_get_ws_remote_address_defaults_to_localhost():
    ws_without_client = SimpleNamespace(client=None, headers={})
    ws_without_host = SimpleNamespace(client=SimpleNamespace(host=None), headers={})
    ws_remote = SimpleNamespace(client=SimpleNamespace(host="198.51.100.5"), headers={})

    assert limit.get_ws_remote_address(ws_without_client) == "127.0.0.1"
    assert limit.get_ws_remote_address(ws_without_host) == "127.0.0.1"
    assert limit.get_ws_remote_address(ws_remote) == "198.51.100.5"


def test_limit_websocket_skips_localhost_and_limits_remote(monkeypatch):
    called = []
    monkeypatch.setattr(
        limit, "assert_limit", lambda identifier: called.append(identifier)
    )

    local_ws = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={})
    remote_ws = SimpleNamespace(client=SimpleNamespace(host="203.0.113.7"), headers={})

    limit.limit_websocket(local_ws)
    limit.limit_websocket(remote_ws)
    assert called == ["203.0.113.7"]
