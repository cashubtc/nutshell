from ..core.base import Proof
from ..core.db import Connection, Database, table_with_schema, timestamp_now
from ..core.settings import settings


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


async def drop_balance_views(db: Database, conn: Connection):
    await conn.execute(f"DROP VIEW IF EXISTS {table_with_schema(db, 'balance')}")
    await conn.execute(f"DROP VIEW IF EXISTS {table_with_schema(db, 'balance_issued')}")
    await conn.execute(
        f"DROP VIEW IF EXISTS {table_with_schema(db, 'balance_redeemed')}"
    )


async def create_balance_views(db: Database, conn: Connection):
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


async def m002_add_balance_views(db: Database):
    async with db.connect() as conn:
        await create_balance_views(db, conn)


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
        # rename column pr to bolt11
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'invoices')} RENAME COLUMN pr TO"
            " bolt11"
        )
        # rename column hash to payment_hash
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'invoices')} RENAME COLUMN hash TO id"
        )

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


async def m011_add_quote_tables(db: Database):
    async with db.connect() as conn:
        # add column "created" to tables invoices, promises, proofs_used, proofs_pending
        tables = ["invoices", "promises", "proofs_used", "proofs_pending"]
        for table in tables:
            await conn.execute(
                f"ALTER TABLE {table_with_schema(db, table)} ADD COLUMN created"
                " TIMESTAMP"
            )
            await conn.execute(
                f"UPDATE {table_with_schema(db, table)} SET created ="
                f" '{timestamp_now(db)}'"
            )

        # add column "witness" to table proofs_used
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'proofs_used')} ADD COLUMN witness"
            " TEXT"
        )

        # add columns "seed" and "unit" to table keysets
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'keysets')} ADD COLUMN seed TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'keysets')} ADD COLUMN unit TEXT"
        )

        # fill columns "seed" and "unit" in table keysets
        await conn.execute(
            f"UPDATE {table_with_schema(db, 'keysets')} SET seed ="
            f" '{settings.mint_private_key}', unit = 'sat'"
        )

        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'mint_quotes')} (
                    quote TEXT NOT NULL,
                    method TEXT NOT NULL,
                    request TEXT NOT NULL,
                    checking_id TEXT NOT NULL,
                    unit TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    paid BOOL NOT NULL,
                    issued BOOL NOT NULL,
                    created_time TIMESTAMP,
                    paid_time TIMESTAMP,

                    UNIQUE (quote)

                );
            """)

        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'melt_quotes')} (
                    quote TEXT NOT NULL,
                    method TEXT NOT NULL,
                    request TEXT NOT NULL,
                    checking_id TEXT NOT NULL,
                    unit TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    fee_reserve INTEGER,
                    paid BOOL NOT NULL,
                    created_time TIMESTAMP,
                    paid_time TIMESTAMP,
                    fee_paid INTEGER,
                    proof TEXT,

                    UNIQUE (quote)

                );
            """)

        await conn.execute(
            f"INSERT INTO {table_with_schema(db, 'mint_quotes')} (quote, method,"
            " request, checking_id, unit, amount, paid, issued, created_time,"
            " paid_time) SELECT id, 'bolt11', bolt11, COALESCE(payment_hash, 'None'),"
            f" 'sat', amount, False, issued, COALESCE(created, '{timestamp_now(db)}'),"
            f" NULL FROM {table_with_schema(db, 'invoices')} "
        )

        # drop table invoices
        await conn.execute(f"DROP TABLE {table_with_schema(db, 'invoices')}")


async def m012_keysets_uniqueness_with_seed(db: Database):
    # copy table keysets to keysets_old, create a new table keysets
    # with the same columns but with a unique constraint on (seed, derivation_path)
    # and copy the data from keysets_old to keysets, then drop keysets_old
    async with db.connect() as conn:
        await conn.execute(
            f"DROP TABLE IF EXISTS {table_with_schema(db, 'keysets_old')}"
        )
        await conn.execute(
            f"CREATE TABLE {table_with_schema(db, 'keysets_old')} AS"
            f" SELECT * FROM {table_with_schema(db, 'keysets')}"
        )
        await conn.execute(f"DROP TABLE {table_with_schema(db, 'keysets')}")
        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'keysets')} (
                    id TEXT NOT NULL,
                    derivation_path TEXT,
                    seed TEXT,
                    valid_from TIMESTAMP,
                    valid_to TIMESTAMP,
                    first_seen TIMESTAMP,
                    active BOOL DEFAULT TRUE,
                    version TEXT,
                    unit TEXT,

                    UNIQUE (seed, derivation_path)

                );
            """)
        await conn.execute(
            f"INSERT INTO {table_with_schema(db, 'keysets')} (id,"
            " derivation_path, valid_from, valid_to, first_seen,"
            " active, version, seed, unit) SELECT id, derivation_path,"
            " valid_from, valid_to, first_seen, active, version, seed,"
            f" unit FROM {table_with_schema(db, 'keysets_old')}"
        )
        await conn.execute(f"DROP TABLE {table_with_schema(db, 'keysets_old')}")


async def m013_keysets_add_encrypted_seed(db: Database):
    async with db.connect() as conn:
        # set keysets table unique constraint to id
        # copy table keysets to keysets_old, create a new table keysets
        # with the same columns but with a unique constraint on id
        # and copy the data from keysets_old to keysets, then drop keysets_old
        await conn.execute(
            f"DROP TABLE IF EXISTS {table_with_schema(db, 'keysets_old')}"
        )
        await conn.execute(
            f"CREATE TABLE {table_with_schema(db, 'keysets_old')} AS"
            f" SELECT * FROM {table_with_schema(db, 'keysets')}"
        )
        await conn.execute(f"DROP TABLE {table_with_schema(db, 'keysets')}")
        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'keysets')} (
                    id TEXT NOT NULL,
                    derivation_path TEXT,
                    seed TEXT,
                    valid_from TIMESTAMP,
                    valid_to TIMESTAMP,
                    first_seen TIMESTAMP,
                    active BOOL DEFAULT TRUE,
                    version TEXT,
                    unit TEXT,

                    UNIQUE (id)

                );
            """)
        await conn.execute(
            f"INSERT INTO {table_with_schema(db, 'keysets')} (id,"
            " derivation_path, valid_from, valid_to, first_seen,"
            " active, version, seed, unit) SELECT id, derivation_path,"
            " valid_from, valid_to, first_seen, active, version, seed,"
            f" unit FROM {table_with_schema(db, 'keysets_old')}"
        )
        await conn.execute(f"DROP TABLE {table_with_schema(db, 'keysets_old')}")

        # add columns encrypted_seed and seed_encryption_method to keysets
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'keysets')} ADD COLUMN encrypted_seed"
            " TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'keysets')} ADD COLUMN"
            " seed_encryption_method TEXT"
        )


async def m014_proofs_add_Y_column(db: Database):
    # get all proofs_used and proofs_pending from the database and compute Y for each of them
    async with db.connect() as conn:
        rows = await conn.fetchall(
            f"SELECT * FROM {table_with_schema(db, 'proofs_used')}"
        )
        # Proof() will compute Y from secret upon initialization
        proofs_used = [Proof(**r) for r in rows]

        rows = await conn.fetchall(
            f"SELECT * FROM {table_with_schema(db, 'proofs_pending')}"
        )
        proofs_pending = [Proof(**r) for r in rows]
    async with db.connect() as conn:
        # we have to drop the balance views first and recreate them later
        await drop_balance_views(db, conn)

        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'proofs_used')} ADD COLUMN Y TEXT"
        )
        for proof in proofs_used:
            await conn.execute(
                f"UPDATE {table_with_schema(db, 'proofs_used')} SET Y = '{proof.Y}'"
                f" WHERE secret = '{proof.secret}'"
            )
        # Copy proofs_used to proofs_used_old and create a new table proofs_used
        # with the same columns but with a unique constraint on (Y)
        # and copy the data from proofs_used_old to proofs_used, then drop proofs_used_old
        await conn.execute(
            f"DROP TABLE IF EXISTS {table_with_schema(db, 'proofs_used_old')}"
        )
        await conn.execute(
            f"CREATE TABLE {table_with_schema(db, 'proofs_used_old')} AS"
            f" SELECT * FROM {table_with_schema(db, 'proofs_used')}"
        )
        await conn.execute(f"DROP TABLE {table_with_schema(db, 'proofs_used')}")
        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'proofs_used')} (
                    amount INTEGER NOT NULL,
                    C TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    id TEXT,
                    Y TEXT,
                    created TIMESTAMP,
                    witness TEXT,

                    UNIQUE (Y)

                );
            """)
        await conn.execute(
            f"INSERT INTO {table_with_schema(db, 'proofs_used')} (amount, C, "
            "secret, id, Y, created, witness) SELECT amount, C, secret, id, Y,"
            f" created, witness FROM {table_with_schema(db, 'proofs_used_old')}"
        )
        await conn.execute(f"DROP TABLE {table_with_schema(db, 'proofs_used_old')}")

        # add column Y to proofs_pending
        await conn.execute(
            f"ALTER TABLE {table_with_schema(db, 'proofs_pending')} ADD COLUMN Y TEXT"
        )
        for proof in proofs_pending:
            await conn.execute(
                f"UPDATE {table_with_schema(db, 'proofs_pending')} SET Y = '{proof.Y}'"
                f" WHERE secret = '{proof.secret}'"
            )

        # Copy proofs_pending to proofs_pending_old and create a new table proofs_pending
        # with the same columns but with a unique constraint on (Y)
        # and copy the data from proofs_pending_old to proofs_pending, then drop proofs_pending_old
        await conn.execute(
            f"DROP TABLE IF EXISTS {table_with_schema(db, 'proofs_pending_old')}"
        )

        await conn.execute(
            f"CREATE TABLE {table_with_schema(db, 'proofs_pending_old')} AS"
            f" SELECT * FROM {table_with_schema(db, 'proofs_pending')}"
        )

        await conn.execute(f"DROP TABLE {table_with_schema(db, 'proofs_pending')}")
        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'proofs_pending')} (
                    amount INTEGER NOT NULL,
                    C TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    Y TEXT,
                    id TEXT,
                    created TIMESTAMP,

                    UNIQUE (Y)

                );
            """)
        await conn.execute(
            f"INSERT INTO {table_with_schema(db, 'proofs_pending')} (amount, C, "
            "secret, Y, id, created) SELECT amount, C, secret, Y, id, created"
            f" FROM {table_with_schema(db, 'proofs_pending_old')}"
        )

        await conn.execute(f"DROP TABLE {table_with_schema(db, 'proofs_pending_old')}")

        # recreate the balance views
        await create_balance_views(db, conn)


async def m015_add_index_Y_to_proofs_used(db: Database):
    # create index on proofs_used table for Y
    async with db.connect() as conn:
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS"
            " proofs_used_Y_idx ON"
            f" {table_with_schema(db, 'proofs_used')} (Y)"
        )
