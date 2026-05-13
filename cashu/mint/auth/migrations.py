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
    Add final_expiry column to auth keysets table (mirrors mint m031).

    The auth ledger uses LedgerCrudSqlite (not AuthLedgerCrudSqlite —
    see cashu/mint/startup.py), whose INSERT into keysets includes the
    final_expiry column added on the mint side in m031. Auth m001
    already creates the table with the `amounts` column, and m002
    adds `balance`/`fees_paid`, so final_expiry is the last missing
    column to align with the mint schema.

    v3 (BLS) keyset generation — default from Nutshell 0.21.0 — is
    what finally exercises this insert path on the auth ledger, since
    earlier versions reused an existing v0/v1 row.
    """
    async with db.connect() as conn:
        await conn.execute(
            f"""
                ALTER TABLE {db.table_with_schema('keysets')}
                ADD COLUMN final_expiry INTEGER NULL
            """
        )


async def m004_align_promises_with_mint_schema(db: Database):
    """
    Align the auth `promises` table with the mint-side schema.

    The auth ledger uses LedgerCrudSqlite.store_promise (see
    cashu/mint/startup.py), whose INSERT shape evolved over later mint
    migrations:
      - +mint_quote, +swap_id  (mint m023, promises_new rebuild)
      - +melt_quote, +signed_at, c_ becomes nullable  (mint m032-ish)

    The auth migrations chain stopped at the pre-0.16 schema, so auth-
    side blind minting (first exercised by v3 BAT generation at 0.21+)
    trips `no column named mint_quote` and `NOT NULL constraint failed:
    promises.c_`. Auth never populates any of mint_quote / melt_quote /
    swap_id / signed_at, but the columns must exist for the INSERT to
    succeed, and `c_` must be nullable for any future code path that
    inserts before signing.

    SQLite path mirrors the mint-side rebuild; Postgres path mirrors the
    mint-side ALTER chain.
    """
    async with db.connect() as conn:
        if conn.type == "SQLITE":
            await conn.execute("PRAGMA foreign_keys=OFF;")
            await conn.execute(
                f"""
                    CREATE TABLE IF NOT EXISTS {db.table_with_schema('promises_new')} (
                        amount {db.big_int} NOT NULL,
                        id TEXT,
                        b_ TEXT NOT NULL,
                        c_ TEXT,
                        dleq_e TEXT,
                        dleq_s TEXT,
                        created TIMESTAMP,
                        signed_at TIMESTAMP,
                        mint_quote TEXT,
                        melt_quote TEXT,
                        swap_id TEXT,

                        UNIQUE (b_)
                    );
                """
            )
            await conn.execute(
                f"INSERT INTO {db.table_with_schema('promises_new')} "
                f"(amount, id, b_, c_, dleq_e, dleq_s, created) "
                f"SELECT amount, id, b_, c_, dleq_e, dleq_s, created "
                f"FROM {db.table_with_schema('promises')}"
            )
            await conn.execute(f"DROP TABLE {db.table_with_schema('promises')}")
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('promises_new')} "
                f"RENAME TO {db.table_with_schema('promises')}"
            )
            await conn.execute("PRAGMA foreign_keys=ON;")
        else:
            for col, typ in (
                ("mint_quote", "TEXT"),
                ("melt_quote", "TEXT"),
                ("swap_id", "TEXT"),
                ("signed_at", "TIMESTAMP"),
            ):
                await conn.execute(
                    f"ALTER TABLE {db.table_with_schema('promises')} "
                    f"ADD COLUMN {col} {typ}"
                )
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('promises')} "
                f"ALTER COLUMN c_ DROP NOT NULL"
            )
