from datetime import datetime, timezone

import pytest

from cashu.core.base import MeltQuote, MeltQuoteState, MintQuote, MintQuoteState
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.mint import migrations as mint_migrations
from cashu.mint.crud import LedgerCrudSqlite


@pytest.mark.asyncio
async def test_current_quote_schema_loads_current_fields(tmp_path):
    db = Database("mint", str(tmp_path / "current_quote_schema"))
    await migrate_databases(db, mint_migrations)
    crud = LedgerCrudSqlite()

    async with db.connect() as conn:
        mint_columns = {
            row["name"]
            for row in await conn.fetchall(
                f"PRAGMA table_info({db.table_with_schema('mint_quotes')})"
            )
        }
        melt_columns = {
            row["name"]
            for row in await conn.fetchall(
                f"PRAGMA table_info({db.table_with_schema('melt_quotes')})"
            )
        }

    assert {"amount_paid", "amount_issued", "updated_at"} <= mint_columns
    assert "proof" in melt_columns
    assert "payment_preimage" not in melt_columns
    assert "outputs" not in melt_columns

    mint_quote = MintQuote(
        quote="mint-quote",
        method="bolt11",
        request="mint-request",
        checking_id="mint-checking-id",
        unit="sat",
        amount=100,
        state=MintQuoteState.paid,
        created_time=1000,
        paid_time=1200,
        amount_paid=40,
        amount_issued=20,
        updated_at=1500,
    )
    await crud.store_mint_quote(quote=mint_quote, db=db)
    loaded_mint_quote = await crud.get_mint_quote(quote_id=mint_quote.quote, db=db)
    assert loaded_mint_quote is not None
    assert loaded_mint_quote.amount_paid == 40
    assert loaded_mint_quote.amount_issued == 20
    assert loaded_mint_quote.updated_at == 1500

    melt_quote = MeltQuote(
        quote="melt-quote",
        method="bolt11",
        request="melt-request",
        checking_id="melt-checking-id",
        unit="sat",
        amount=100,
        fee_reserve=2,
        state=MeltQuoteState.paid,
        created_time=1000,
        paid_time=1200,
        fee_paid=1,
        payment_preimage="11" * 32,
        expiry=2000,
    )
    await crud.store_melt_quote(quote=melt_quote, db=db)
    loaded_melt_quote = await crud.get_melt_quote(quote_id=melt_quote.quote, db=db)
    assert loaded_melt_quote is not None
    assert loaded_melt_quote.payment_preimage == "11" * 32

    await db.engine.dispose()


def test_current_mint_quote_postgres_row_loads_accounting_fields():
    row = {
        "quote": "mint-quote",
        "method": "bolt11",
        "request": "mint-request",
        "checking_id": "mint-checking-id",
        "unit": "sat",
        "amount": 100,
        "state": MintQuoteState.paid.value,
        "created_time": datetime.fromtimestamp(1000, timezone.utc),
        "paid_time": datetime.fromtimestamp(1200, timezone.utc),
        "issued_time": None,
        "last_checked": None,
        "pubkey": None,
        "amount_paid": 40,
        "amount_issued": 20,
        "updated_at": datetime.fromtimestamp(1500, timezone.utc),
    }

    quote = MintQuote.from_row(row)  # type: ignore[arg-type]

    assert quote.amount_paid == 40
    assert quote.amount_issued == 20
    assert quote.updated_at == 1500


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
