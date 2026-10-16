import json

import pytest

from cashu.core.base import MintKeyset
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.mint.auth import migrations as auth_migrations
from cashu.mint.auth.crud import AuthLedgerCrudSqlite


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["0.20.0", "0.21.0"])
@pytest.mark.parametrize("amounts", [[1], [1, 2, 4]])
async def test_auth_keyset_roundtrip_preserves_amounts(tmp_path, version, amounts):
    db = Database("auth", str(tmp_path))
    crud = AuthLedgerCrudSqlite()
    keyset = MintKeyset(
        seed="auth-keyset-test-seed",
        derivation_path="m/0'/0'/0'",
        amounts=amounts,
        version=version,
    )
    try:
        await migrate_databases(db, auth_migrations)
        await crud.store_keyset(db=db, keyset=keyset)
        row = await db.fetchone(
            "SELECT amounts FROM keysets WHERE id = :id", {"id": keyset.id}
        )
        assert row and json.loads(row["amounts"]) == amounts
        loaded = await crud.get_keyset(db=db, id=keyset.id)
        assert len(loaded) == 1
        assert loaded[0].amounts == amounts
        assert loaded[0].id == keyset.id
        assert loaded[0].public_keys_hex == keyset.public_keys_hex
    finally:
        await db.engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["0.20.0", "0.21.0"])
async def test_auth_keyset_loads_existing_null_amounts(tmp_path, monkeypatch, version):
    monkeypatch.setattr(settings, "max_order", 3)
    db = Database("auth", str(tmp_path))
    crud = AuthLedgerCrudSqlite()
    keyset = MintKeyset(
        seed="auth-keyset-test-seed", derivation_path="m/0'/0'/0'", version=version
    )
    try:
        await migrate_databases(db, auth_migrations)
        await crud.store_keyset(db=db, keyset=keyset)
        # Older auth CRUD inserts omitted the amounts column.
        await db.execute(
            "UPDATE keysets SET amounts = NULL WHERE id = :id", {"id": keyset.id}
        )
        loaded = await crud.get_keyset(db=db, id=keyset.id)
        assert len(loaded) == 1
        assert loaded[0].amounts == [1, 2, 4]
        assert loaded[0].id == keyset.id
        assert loaded[0].public_keys_hex == keyset.public_keys_hex
    finally:
        await db.engine.dispose()
