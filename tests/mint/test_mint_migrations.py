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
