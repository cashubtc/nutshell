from ...core.db import Connection, Database


async def m000_create_migrations_table(conn: Connection):
    await conn.execute(
        f"""
    CREATE TABLE IF NOT EXISTS {conn.table_with_schema('dbversions')} (
        db TEXT PRIMARY KEY,
        version INT NOT NULL
    )
    """
    )


async def m001_initial(db: Database):
    async with db.connect() as conn:
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('users')} (
                    id TEXT PRIMARY KEY,
                    last_access TIMESTAMP,

                    UNIQUE (id)
                );
            """
        )
        # columns: (id, seed, encrypted_seed, seed_encryption_method, derivation_path, valid_from, valid_to, first_seen, active, version, unit, input_fee_ppk)
        await conn.execute(
            f"""
                    CREATE TABLE IF NOT EXISTS {db.table_with_schema('keysets')} (
                        id TEXT NOT NULL,
                        seed TEXT NOT NULL,
                        encrypted_seed TEXT,
                        seed_encryption_method TEXT,
                        derivation_path TEXT NOT NULL,
                        valid_from TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                        valid_to TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                        first_seen TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                        active BOOL DEFAULT TRUE,
                        version TEXT,
                        unit TEXT NOT NULL,
                        input_fee_ppk INT,
                        amounts TEXT,

                        UNIQUE (derivation_path)
                    );
                """
        )

        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('promises')} (
                    id TEXT NOT NULL,
                    amount {db.big_int} NOT NULL,
                    b_ TEXT NOT NULL,
                    c_ TEXT NOT NULL,
                    dleq_e TEXT,
                    dleq_s TEXT,
                    created TIMESTAMP,

                    UNIQUE (b_)

                );
            """
        )
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('proofs_used')} (
                    id TEXT NOT NULL,
                    amount {db.big_int} NOT NULL,
                    c TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    y TEXT NOT NULL,
                    witness TEXT,
                    created TIMESTAMP,
                    melt_quote TEXT,

                    UNIQUE (secret)

                );
            """
        )

        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('proofs_pending')} (
                    id TEXT NOT NULL,
                    amount {db.big_int} NOT NULL,
                    c TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    y TEXT NOT NULL,
                    witness TEXT,
                    created TIMESTAMP,
                    melt_quote TEXT,

                    UNIQUE (secret)

                );
            """
        )


async def m002_add_balance_to_keysets_and_log_table(db: Database):
    async with db.connect() as conn:
        await conn.execute(
            f"""
                ALTER TABLE {db.table_with_schema('keysets')}
                ADD COLUMN balance INTEGER NOT NULL DEFAULT 0
            """
        )
        await conn.execute(
            f"""
                ALTER TABLE {db.table_with_schema('keysets')}
                ADD COLUMN fees_paid INTEGER NOT NULL DEFAULT 0
            """
        )


async def m003_add_final_expiry_to_keysets(db: Database):
    """
    Add the final_expiry column to the auth keysets table for keysets v2 support.
    """
    async with db.connect() as conn:
        await conn.execute(
            f"""
                ALTER TABLE {db.table_with_schema('keysets')}
                ADD COLUMN final_expiry INTEGER NULL
            """
        )


async def m004_remove_dleq_from_promises(db: Database):
    """Remove deterministically generated DLEQ proofs from persisted promises."""
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('promises')} DROP COLUMN dleq_e"
        )
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('promises')} DROP COLUMN dleq_s"
        )


async def m005_align_promises_with_mint_schema(db: Database):
    """
    Align the auth promises table with the columns the shared LedgerCrudSqlite writes.
    """
    async with db.connect() as conn:
        if conn.type == "SQLITE":
            await conn.execute("PRAGMA foreign_keys=OFF;")
            await conn.execute(
                f"""
                    CREATE TABLE IF NOT EXISTS {db.table_with_schema("promises_new")} (
                        id TEXT NOT NULL,
                        amount {db.big_int} NOT NULL,
                        b_ TEXT NOT NULL,
                        c_ TEXT,
                        created TIMESTAMP,
                        signed_at TIMESTAMP,
                        mint_quote TEXT,
                        melt_quote TEXT,
                        swap_id TEXT,
                        order_index INTEGER DEFAULT 0,

                        UNIQUE (b_)

                    );
                """
            )
            await conn.execute(
                f"INSERT INTO {db.table_with_schema('promises_new')} (id, amount, b_, c_, created) "
                f"SELECT id, amount, b_, c_, created FROM {db.table_with_schema('promises')}"
            )
            await conn.execute(f"DROP TABLE {db.table_with_schema('promises')}")
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('promises_new')} RENAME TO {db.table_with_schema('promises')}"
            )
            await conn.execute("PRAGMA foreign_keys=ON;")
        else:
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('promises')} ADD COLUMN IF NOT EXISTS mint_quote TEXT"
            )
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('promises')} ADD COLUMN IF NOT EXISTS melt_quote TEXT"
            )
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('promises')} ADD COLUMN IF NOT EXISTS swap_id TEXT"
            )
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('promises')} ADD COLUMN IF NOT EXISTS signed_at TIMESTAMP"
            )
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('promises')} ADD COLUMN IF NOT EXISTS order_index INTEGER DEFAULT 0"
            )
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('promises')} ALTER COLUMN c_ DROP NOT NULL"
            )
