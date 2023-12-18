from ..core.db import Connection, Database, table_with_schema


async def m000_create_migrations_table(conn: Connection):
    await conn.execute(f"""
    CREATE TABLE IF NOT EXISTS {table_with_schema(conn, 'dbversions')} (
        db TEXT PRIMARY KEY,
        version INT NOT NULL
    )
    """)


async def m001_initial(db: Database):
    async with db.connect() as conn:
        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'promises')} (
                    amount {db.big_int} NOT NULL,
                    B_b TEXT NOT NULL,
                    C_b TEXT NOT NULL,

                    UNIQUE (B_b)

                );
            """)

        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'proofs_used')} (
                    amount {db.big_int} NOT NULL,
                    C TEXT NOT NULL,
                    secret TEXT NOT NULL,

                    UNIQUE (secret)

                );
            """)

        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'invoices')} (
                    amount {db.big_int} NOT NULL,
                    pr TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    issued BOOL NOT NULL,

                    UNIQUE (hash)

                );
            """)


async def m002_add_balance_views(db: Database):
    async with db.connect() as conn:
        await conn.execute(f"""
            CREATE VIEW {table_with_schema(db, 'balance_issued')} AS
            SELECT COALESCE(SUM(s), 0) AS balance FROM (
                SELECT SUM(amount) AS s
                FROM {table_with_schema(db, 'promises')}
                WHERE amount > 0
            ) AS balance_issued;
        """)

        await conn.execute(f"""
            CREATE VIEW {table_with_schema(db, 'balance_redeemed')} AS
            SELECT COALESCE(SUM(s), 0) AS balance FROM (
                SELECT SUM(amount) AS s
                FROM {table_with_schema(db, 'proofs_used')}
                WHERE amount > 0
            ) AS balance_redeemed;
        """)

        await conn.execute(f"""
            CREATE VIEW {table_with_schema(db, 'balance')} AS
            SELECT s_issued - s_used FROM (
                SELECT bi.balance AS s_issued, bu.balance AS s_used
                FROM {table_with_schema(db, 'balance_issued')} bi
                CROSS JOIN {table_with_schema(db, 'balance_redeemed')} bu
            ) AS balance;
        """)


async def m003_mint_keysets(db: Database):
    """
    Stores mint keysets from different mints and epochs.
    """
    async with db.connect() as conn:
        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'keysets')} (
                    id TEXT NOT NULL,
                    derivation_path TEXT,
                    valid_from TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                    valid_to TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                    first_seen TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                    active BOOL DEFAULT TRUE,

                    UNIQUE (derivation_path)

                );
            """)
        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'mint_pubkeys')} (
                    id TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    pubkey TEXT NOT NULL,

                    UNIQUE (id, pubkey)

                );
            """)


async def m004_keysets_add_version(db: Database):
    """
    Column that remembers with which version
    """
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'keysets')} ADD COLUMN version TEXT"
        )


async def m005_pending_proofs_table(db: Database) -> None:
    """
    Store pending proofs.
    """
    async with db.connect() as conn:
        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'proofs_pending')} (
                    amount INTEGER NOT NULL,
                    C TEXT NOT NULL,
                    secret TEXT NOT NULL,

                    UNIQUE (secret)

                );
            """)


async def m006_invoices_add_payment_hash(db: Database):
    """
    Column that remembers the payment_hash as we're using
    the column hash as a random identifier now
    (see https://github.com/cashubtc/nuts/pull/14).
    """
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'invoices')} ADD COLUMN payment_hash"
            " TEXT"
        )
        await conn.execute(
            f"UPDATE {table_with_schema(db, 'invoices')} SET payment_hash = hash"
        )


async def m007_proofs_and_promises_store_id(db: Database):
    """
    Column that stores the id of the proof or promise.
    """
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'proofs_used')} ADD COLUMN id TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'proofs_pending')} ADD COLUMN id TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'promises')} ADD COLUMN id TEXT"
        )


async def m008_promises_dleq(db: Database):
    """
    Add columns for DLEQ proof to promises table.
    """
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'promises')} ADD COLUMN e TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'promises')} ADD COLUMN s TEXT"
        )


async def m009_add_out_to_invoices(db: Database):
    # column in invoices for marking whether the invoice is incoming (out=False) or outgoing (out=True)
    async with db.connect() as conn:
        # we have to drop the balance views first and recreate them later
        await conn.execute(f"DROP VIEW IF EXISTS {table_with_schema(db, 'balance')}")
        await conn.execute(
            f"DROP VIEW IF EXISTS {table_with_schema(db, 'balance_issued')}"
        )
        await conn.execute(
            f"DROP VIEW IF EXISTS {table_with_schema(db, 'balance_redeemed')}"
        )

        # rename column pr to bolt11
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'invoices')} RENAME COLUMN pr TO"
            " bolt11"
        )
        # rename column hash to payment_hash
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'invoices')} RENAME COLUMN hash TO id"
        )

    # recreate balance views
    await m002_add_balance_views(db)

    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'invoices')} ADD COLUMN out BOOL"
        )


async def m010_add_index_to_proofs_used(db: Database):
    # create index on proofs_used table for secret
    async with db.connect() as conn:
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS"
            " proofs_used_secret_idx ON"
            f" {table_with_schema(db, 'proofs_used')} (secret)"
        )
