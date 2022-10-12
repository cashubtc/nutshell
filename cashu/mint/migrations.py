from cashu.core.db import Database
from cashu.core.migrations import table_with_schema


async def m000_create_migrations_table(db):
    await db.execute(
        f"""
    CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'dbversions')} (
        db TEXT PRIMARY KEY,
        version INT NOT NULL
    )
    """
    )


async def m001_initial(db: Database):
    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'promises')} (
                amount INTEGER NOT NULL,
                B_b TEXT NOT NULL,
                C_b TEXT NOT NULL,

                UNIQUE (B_b)

            );
        """
    )

    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'proofs_used')} (
                amount INTEGER NOT NULL,
                C TEXT NOT NULL,
                secret TEXT NOT NULL,

                UNIQUE (secret)

            );
        """
    )

    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'invoices')} (
                amount INTEGER NOT NULL,
                pr TEXT NOT NULL,
                hash TEXT NOT NULL,
                issued BOOL NOT NULL,

                UNIQUE (hash)

            );
        """
    )

    # await db.execute(
    #     f"""
    #     CREATE VIEW {table_with_schema(db, 'balance_issued')} AS
    #     SELECT COALESCE(SUM(s), 0) AS balance FROM (
    #         SELECT SUM(amount) AS s
    #         FROM {table_with_schema(db, 'promises')}
    #         WHERE amount > 0
    #     );
    # """
    # )

    # await db.execute(
    #     f"""
    #     CREATE VIEW {table_with_schema(db, 'balance_used')} AS
    #     SELECT COALESCE(SUM(s), 0) AS balance FROM (
    #         SELECT SUM(amount) AS s
    #         FROM {table_with_schema(db, 'proofs_used')}
    #         WHERE amount > 0
    #     );
    # """
    # )

    # await db.execute(
    #     f"""
    #     CREATE VIEW {table_with_schema(db, 'balance')} AS
    #     SELECT s_issued - s_used AS balance FROM (
    #         SELECT bi.balance AS s_issued, bu.balance AS s_used
    #         FROM {table_with_schema(db, 'balance_issued')} bi
    #         CROSS JOIN {table_with_schema(db, 'balance_used')} bu
    #     );
    # """
    # )


async def m003_mint_keysets(db: Database):
    """
    Stores mint keysets from different mints and epochs.
    """
    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'keysets')} (
                id TEXT NOT NULL,
                derivation_path TEXT,
                valid_from TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                valid_to TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                first_seen TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                active BOOL DEFAULT TRUE,

                UNIQUE (derivation_path)

            );
        """
    )
    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'mint_pubkeys')} (
                id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                pubkey TEXT NOT NULL,

                UNIQUE (id, pubkey)

            );
        """
    )


async def m004_keysets_add_version(db: Database):
    """
    Column that remembers with which version
    """
    await db.execute(
        f"ALTER TABLE {table_with_schema(db, 'keysets')} ADD COLUMN version TEXT"
    )
