from types import SimpleNamespace

import pytest

from cashu.mint import admin


class DummyDB:
    def table_with_schema(self, table: str) -> str:
        return table

    def timestamp_from_seconds(self, seconds):
        return int(seconds)

    async def fetchone(self, query, values=None):
        if "FROM promises" in query:
            return {"c": 10}
        if "FROM proofs_used" in query:
            return {"c": 11}
        if "FROM proofs_pending" in query:
            return {"c": 12}
        if "FROM mint_quotes" in query and "created_time" not in query:
            return {"c": 13}
        if "FROM melt_quotes" in query and "created_time" not in query:
            return {"c": 14}
        if "FROM mint_quotes" in query and "created_time" in query:
            assert values and "since" in values
            return {"c": 2}
        if "FROM melt_quotes" in query and "created_time" in query:
            assert values and "since" in values
            return {"c": 3}
        raise AssertionError(f"unexpected query: {query}")


@pytest.mark.asyncio
async def test_get_admin_monitor_snapshot(monkeypatch):
    monkeypatch.setattr(admin, "ledger", SimpleNamespace(db=DummyDB()))
    monkeypatch.setattr(admin.settings, "cashu_dir", "/tmp")

    snapshot = await admin.get_admin_monitor_snapshot()

    assert snapshot["db"] == {
        "promises": 10,
        "proofs_used": 11,
        "proofs_pending": 12,
        "mint_quotes": 13,
        "melt_quotes": 14,
    }
    assert snapshot["requests"] == {
        "mint_quotes_last_24h": 2,
        "melt_quotes_last_24h": 3,
    }
    assert "disk_total_bytes" in snapshot["host"]
    assert "process_cpu_seconds" in snapshot["host"]


def test_require_admin_key_accepts_valid_key(monkeypatch):
    monkeypatch.setattr(admin.settings, "mint_admin_api_key", "secret")
    admin.require_admin_key("secret")


@pytest.mark.parametrize("provided", [None, "wrong"])
def test_require_admin_key_rejects_invalid_key(monkeypatch, provided):
    monkeypatch.setattr(admin.settings, "mint_admin_api_key", "secret")
    with pytest.raises(admin.MintAdminAuthError):
        admin.require_admin_key(provided)


def test_require_admin_key_rejects_when_disabled(monkeypatch):
    monkeypatch.setattr(admin.settings, "mint_admin_api_key", None)
    with pytest.raises(admin.MintAdminAuthError):
        admin.require_admin_key("anything")
