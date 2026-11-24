import json
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from cashu.mint import limit


def _request(host: str) -> Request:
    return Request({"type": "http", "headers": [], "client": (host, 12345)})


def test_rate_limit_exceeded_handler_returns_429():
    response = limit._rate_limit_exceeded_handler(_request("203.0.113.4"), Exception())
    assert response.status_code == 429
    assert json.loads(response.body) == {"detail": "Rate limit exceeded."}


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


def test_get_ws_remote_address():
    assert limit.get_ws_remote_address(SimpleNamespace(client=None)) == "unknown"
    ws = SimpleNamespace(client=SimpleNamespace(host="198.51.100.5"))
    assert limit.get_ws_remote_address(ws) == "198.51.100.5"
