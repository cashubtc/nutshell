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
