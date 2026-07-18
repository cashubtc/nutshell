import pytest

from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.mint import migrations as mint_migrations


@pytest.mark.asyncio
async def test_m029_witness_cleanup():
    db = Database("mint", "./test_data/mig_witness_cleanup")

    # Ensure schema is at latest so tables exist
    await migrate_databases(db, mint_migrations)

    long_witness = "a" * 1025
    short_witness = "b" * 10

    async with db.connect() as conn:
        # Insert into proofs_used
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('proofs_used')} (amount, id, c, secret, y, witness, created, melt_quote)
            VALUES (1, 'kid', 'c_used_long', 's_used_long', 'y_used_long', :w, {db.timestamp_now}, NULL)
            """,
            {"w": long_witness},
        )
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('proofs_used')} (amount, id, c, secret, y, witness, created, melt_quote)
            VALUES (1, 'kid', 'c_used_short', 's_used_short', 'y_used_short', :w, {db.timestamp_now}, NULL)
            """,
            {"w": short_witness},
        )

        # Insert into proofs_pending
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('proofs_pending')} (amount, id, c, secret, y, witness, created, melt_quote)
            VALUES (1, 'kid', 'c_pend_long', 's_pend_long', 'y_pend_long', :w, {db.timestamp_now}, NULL)
            """,
            {"w": long_witness},
        )
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('proofs_pending')} (amount, id, c, secret, y, witness, created, melt_quote)
            VALUES (1, 'kid', 'c_pend_short', 's_pend_short', 'y_pend_short', :w, {db.timestamp_now}, NULL)
            """,
            {"w": short_witness},
        )

    # Run the migration under test directly
    await mint_migrations.m029_remove_overlong_witness_values(db)

    # Validate cleanup
    async with db.connect() as conn:
        row = await conn.fetchone(
            f"SELECT witness FROM {db.table_with_schema('proofs_used')} WHERE secret = 's_used_long'"
        )
        assert row["witness"] is None

        row = await conn.fetchone(
            f"SELECT witness FROM {db.table_with_schema('proofs_used')} WHERE secret = 's_used_short'"
        )
        assert row["witness"] == short_witness

        row = await conn.fetchone(
            f"SELECT witness FROM {db.table_with_schema('proofs_pending')} WHERE secret = 's_pend_long'"
        )
        assert row["witness"] is None

        row = await conn.fetchone(
            f"SELECT witness FROM {db.table_with_schema('proofs_pending')} WHERE secret = 's_pend_short'"
        )
        assert row["witness"] == short_witness


@pytest.mark.asyncio
async def test_auth_m003_migration():
    import os
    import shutil

    from cashu.core.base import MintKeyset
    from cashu.mint.auth import migrations as auth_migrations
    from cashu.mint.crud import LedgerCrudSqlite

    db_path = "./test_data/mig_auth"
    if os.path.exists(db_path):
        shutil.rmtree(db_path)
    db = Database("auth", db_path)

    # Migrate auth database to latest
    await migrate_databases(db, auth_migrations)

    # Verify that keysets table now has the final_expiry column
    async with db.connect() as conn:
        columns = await conn.fetchall(
            f"PRAGMA table_info({db.table_with_schema('keysets')})"
        )
        assert any(col["name"] == "final_expiry" for col in columns)

    # Verify that we can successfully store a keyset (which uses the final_expiry column)
    crud = LedgerCrudSqlite()
    keyset = MintKeyset(
        seed="test_seed",
        derivation_path="m/0'/0'/0'",
        version="0.15.0",
        final_expiry=123456789,
    )
    await crud.store_keyset(db=db, keyset=keyset)

    # Verify that the keyset was stored and final_expiry value is set correctly
    retrieved = await crud.get_keyset(db=db, id=keyset.id)
    assert len(retrieved) == 1
    assert retrieved[0].final_expiry == 123456789

    # Clean up
    if os.path.exists(db_path):
        shutil.rmtree(db_path)
