import json

import pytest

from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.mint import migrations as mint_migrations


@pytest.mark.asyncio
async def test_m026_keyset_specific_balance_views():
    db = Database("mint", "./test_data/mig_keyset_specific_balance_views")

    # Ensure schema is at latest so tables exist
    await migrate_databases(db, mint_migrations)

    async with db.connect() as conn:
        # Determine target keyset id the migration will use
        krow = await conn.fetchone(
            f"SELECT id FROM {db.table_with_schema('keysets')} WHERE id LIKE '00%' ORDER BY first_seen LIMIT 1"
        )
        if not krow:
            await conn.execute(
                f"""
                INSERT INTO {db.table_with_schema('keysets')} (
                    id, derivation_path, seed, active, version, unit, input_fee_ppk, amounts, balance, fees_paid
                ) VALUES (
                    :id, :dp, :seed, 1, :ver, :unit, 0, '[]', 0, 0
                )
                """,
                {
                    "id": "00_test_keyset",
                    "dp": "m/0'/0'/0'",
                    "seed": "seed",
                    "ver": "0.18.1",
                    "unit": "sat",
                },
            )
            krow = await conn.fetchone(
                f"SELECT id FROM {db.table_with_schema('keysets')} WHERE id LIKE '00%' ORDER BY first_seen LIMIT 1"
            )
        assert krow is not None, "Expected at least one keyset with id starting '00'"
        target_id = krow["id"]

        # Insert rows with NULL id into promises, proofs_used, proofs_pending
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('promises')} (amount, id, b_, c_, created)
            VALUES (1, NULL, 'bm026_1', 'cm026_1', {db.timestamp_now})
            """
        )
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('proofs_used')} (amount, id, c, secret, y, witness, created, melt_quote)
            VALUES (1, NULL, 'cu1', 'su1', 'yu1', NULL, {db.timestamp_now}, NULL)
            """
        )
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('proofs_pending')} (amount, id, c, secret, y, witness, created, melt_quote)
            VALUES (1, NULL, 'cp1', 'sp1', 'yp1', NULL, {db.timestamp_now}, NULL)
            """
        )

    # Run the migration under test directly
    await mint_migrations.m026_keyset_specific_balance_views(db)

    # Validate that NULL ids were set to target keyset id and views recreated
    async with db.connect() as conn:
        prow = await conn.fetchone(
            f"SELECT id FROM {db.table_with_schema('promises')} WHERE b_ = 'bm026_1'"
        )
        assert prow is not None and prow["id"] == target_id

        urow = await conn.fetchone(
            f"SELECT id FROM {db.table_with_schema('proofs_used')} WHERE secret = 'su1'"
        )
        assert urow is not None and urow["id"] == target_id

        prow2 = await conn.fetchone(
            f"SELECT id FROM {db.table_with_schema('proofs_pending')} WHERE secret = 'sp1'"
        )
        assert prow2 is not None and prow2["id"] == target_id

        # Views should exist after migration
        v_balance = await conn.fetchone(
            f"SELECT name FROM sqlite_master WHERE type='view' AND name='{db.table_with_schema('balance')}'"
        )
        assert v_balance is not None


@pytest.mark.asyncio
async def test_m025_add_amounts_to_keysets():
    db = Database("mint", "./test_data/mig_add_amounts_to_keysets")

    # Ensure schema is at latest so base tables exist
    await migrate_databases(db, mint_migrations)

    async with db.connect() as conn:
        # If amounts already present, recreate keysets without it to simulate pre-m025
        cols = await conn.fetchall("PRAGMA table_info(keysets)")
        col_names = {c["name"] for c in cols}
        if "amounts" in col_names:
            await conn.execute(
                f"CREATE TABLE {db.table_with_schema('keysets_pre25')} AS "
                f"SELECT id, derivation_path, seed, valid_from, valid_to, first_seen, active, version, unit, encrypted_seed, seed_encryption_method, input_fee_ppk FROM {db.table_with_schema('keysets')}"
            )
            await conn.execute(f"DROP TABLE {db.table_with_schema('keysets')}")
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('keysets_pre25')} RENAME TO {db.table_with_schema('keysets')}"
            )

    # Run the migration under test directly
    await mint_migrations.m025_add_amounts_to_keysets(db)

    # Validate amounts column exists and defaulted to '[]'
    async with db.connect() as conn:
        cols2 = await conn.fetchall("PRAGMA table_info(keysets)")
        names2 = {c["name"] for c in cols2}
        assert "amounts" in names2

        # All rows should have '[]' after migration
        r = await conn.fetchone(
            f"SELECT COUNT(*) as cnt FROM {db.table_with_schema('keysets')} WHERE amounts = '[]'"
        )
        # If there are zero rows, it's still ok structurally; else ensure all set
        if r is not None:
            total = await conn.fetchone(
                f"SELECT COUNT(*) as cnt FROM {db.table_with_schema('keysets')}"
            )
            assert r["cnt"] == (total["cnt"] if total else 0)


async def test_m027_add_balance_to_keysets_and_log_table():
    db = Database("mint", "./test_data/mig_add_balance_to_keysets")

    # Ensure schema is at latest so base tables/views exist
    await migrate_databases(db, mint_migrations)

    async with db.connect() as conn:
        # Ensure at least one keyset exists; if not, create a minimal one
        existing = await conn.fetchone(
            f"SELECT id FROM {db.table_with_schema('keysets')} LIMIT 1"
        )
        if not existing:
            await conn.execute(
                f"""
                INSERT INTO {db.table_with_schema('keysets')} (
                    id, derivation_path, seed, active, version, unit, input_fee_ppk, amounts, balance, fees_paid
                ) VALUES (
                    :id, :dp, :seed, 1, :ver, :unit, 0, '[]', 0, 0
                )
                """,
                {
                    "id": "kid_test",
                    "dp": "m/0'/0'/0'",
                    "seed": "seed",
                    "ver": "0.18.1",
                    "unit": "sat",
                },
            )

        # Pick any existing keyset id (created during startup/init)
        ks = await conn.fetchone(
            f"SELECT id FROM {db.table_with_schema('keysets')} LIMIT 1"
        )
        assert ks is not None, "Expected at least one keyset present"
        keyset_id = ks["id"]

        # Recreate keysets table without the post-m027 columns to simulate pre-m027 schema
        await conn.execute(
            f"CREATE TABLE {db.table_with_schema('keysets_pre27')} AS "
            f"SELECT id, derivation_path, seed, valid_from, valid_to, first_seen, active, version, unit, encrypted_seed, seed_encryption_method, input_fee_ppk, amounts "
            f"FROM {db.table_with_schema('keysets')}"
        )
        await conn.execute(f"DROP TABLE {db.table_with_schema('keysets')}")
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('keysets_pre27')} RENAME TO {db.table_with_schema('keysets')}"
        )

        # Insert promises with non-null c_ so they count towards balance view
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('promises')} (amount, id, b_, c_, created)
            VALUES (2, :id, 'b1', 'c1', {db.timestamp_now})
            """,
            {"id": keyset_id},
        )
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('promises')} (amount, id, b_, c_, created)
            VALUES (3, :id, 'b2', 'c2', {db.timestamp_now})
            """,
            {"id": keyset_id},
        )

    # Run the migration under test directly
    await mint_migrations.m027_add_balance_to_keysets_and_log_table(db)

    # Validate balance/fees columns created and balance populated from view, and balance_log table exists
    async with db.connect() as conn:
        # Check columns presence
        cols = await conn.fetchall("PRAGMA table_info(keysets)")
        col_names = {c["name"] for c in cols}
        assert "balance" in col_names and "fees_paid" in col_names

        # Check computed balance (2 + 3) for our keyset
        row = await conn.fetchone(
            f"SELECT balance, fees_paid FROM {db.table_with_schema('keysets')} WHERE id = :id",
            {"id": keyset_id},
        )
        assert row is not None
        assert row["balance"] == 5
        assert row["fees_paid"] == 0

        # Check balance_log table exists with expected columns
        blog_cols = await conn.fetchall("PRAGMA table_info(balance_log)")
        blog_names = {c["name"] for c in blog_cols}
        assert {
            "unit",
            "keyset_balance",
            "keyset_fees_paid",
            "backend_balance",
            "time",
        }.issubset(blog_names)


@pytest.mark.asyncio
async def test_m028_promises_c_allow_null_add_melt_quote():
    db = Database("mint", "./test_data/mig_promises_c_allow_null_add_melt_quote")

    # Ensure schema is at latest so base tables exist
    await migrate_databases(db, mint_migrations)

    # Prepare a pending melt quote that has stored outputs to be migrated into promises
    outputs = [
        {"amount": 5, "id": "kid", "B_": "bhex1"},
        {"amount": 7, "id": "kid", "B_": "bhex2"},
    ]

    async with db.connect() as conn:
        # Recreate the pre-m028 columns so the migration has something meaningful to do
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('melt_quotes')} ADD COLUMN outputs TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('melt_quotes')} ADD COLUMN change TEXT"
        )

        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('melt_quotes')} (
                quote, method, request, checking_id, unit, amount, fee_reserve,
                paid, created_time, paid_time, fee_paid, proof, state, expiry, outputs
            ) VALUES (
                'q_pending', 'bolt11', 'req', 'chk', 'sat', 12, NULL,
                0, {db.timestamp_now}, NULL, NULL, NULL, 'PENDING', NULL, :outputs
            )
            """,
            {"outputs": json.dumps(outputs)},
        )

    # Run the migration under test directly
    await mint_migrations.m028_promises_c_allow_null_add_melt_quote(db)

    # Validate that outputs were migrated into promises with c_ NULL and melt_quote set
    async with db.connect() as conn:
        row1 = await conn.fetchone(
            f"SELECT amount, id, b_, c_, melt_quote FROM {db.table_with_schema('promises')} WHERE b_ = 'bhex1'"
        )
        assert row1 is not None
        assert row1["amount"] == 5 and row1["id"] == "kid"
        assert row1["c_"] is None
        assert row1["melt_quote"] == "q_pending"

        row2 = await conn.fetchone(
            f"SELECT amount, id, b_, c_, melt_quote FROM {db.table_with_schema('promises')} WHERE b_ = 'bhex2'"
        )
        assert row2 is not None
        assert row2["amount"] == 7 and row2["id"] == "kid"
        assert row2["c_"] is None
        assert row2["melt_quote"] == "q_pending"

        # Validate that melt_quotes no longer has obsolete columns
        cols = await conn.fetchall("PRAGMA table_info(melt_quotes)")
        col_names = {c["name"] for c in cols}
        assert "outputs" not in col_names
        assert "change" not in col_names


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
