from ..core.db import Database, table_with_schema


async def m000_create_migrations_table(db: Database):
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
                amount {db.big_int} NOT NULL,
                B_b TEXT NOT NULL,
                C_b TEXT NOT NULL,

                UNIQUE (B_b)

            );
        """
    )

    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'proofs_used')} (
                amount {db.big_int} NOT NULL,
                C TEXT NOT NULL,
                secret TEXT NOT NULL,

                UNIQUE (secret)

            );
        """
    )

    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'invoices')} (
                amount {db.big_int} NOT NULL,
                pr TEXT NOT NULL,
                hash TEXT NOT NULL,
                issued BOOL NOT NULL,

                UNIQUE (hash)

            );
        """
    )

    await db.execute(
        f"""
        CREATE VIEW {table_with_schema(db, 'balance_issued')} AS
        SELECT COALESCE(SUM(s), 0) AS balance FROM (
            SELECT SUM(amount)
            FROM {table_with_schema(db, 'promises')}
            WHERE amount > 0
        ) AS s;
    """
    )

    await db.execute(
        f"""
        CREATE VIEW {table_with_schema(db, 'balance_redeemed')} AS
        SELECT COALESCE(SUM(s), 0) AS balance FROM (
            SELECT SUM(amount)
            FROM {table_with_schema(db, 'proofs_used')}
            WHERE amount > 0
        )  AS s;
    """
    )

    await db.execute(
        f"""
        CREATE VIEW {table_with_schema(db, 'balance')} AS
        SELECT s_issued - s_used FROM (
            SELECT bi.balance AS s_issued, bu.balance AS s_used
            FROM {table_with_schema(db, 'balance_issued')} bi
            CROSS JOIN {table_with_schema(db, 'balance_redeemed')} bu
        )  AS balance;
    """
    )


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


async def m005_pending_proofs_table(db: Database) -> None:
    """
    Store pending proofs.
    """
    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'proofs_pending')} (
                amount INTEGER NOT NULL,
                C TEXT NOT NULL,
                secret TEXT NOT NULL,

                UNIQUE (secret)

            );
        """
    )


async def m006_invoices_add_payment_hash(db: Database):
    """
    Column that remembers the payment_hash as we're using
    the column hash as a random identifier now
    (see https://github.com/cashubtc/nuts/pull/14).
    """
    await db.execute(
        f"ALTER TABLE {table_with_schema(db, 'invoices')} ADD COLUMN payment_hash TEXT"
    )
    await db.execute(
        f"UPDATE {table_with_schema(db, 'invoices')} SET payment_hash = hash"
    )
