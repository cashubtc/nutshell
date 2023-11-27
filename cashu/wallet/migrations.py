from ..core.db import Connection, Database


async def m000_create_migrations_table(conn: Connection):
    await conn.execute("""
    CREATE TABLE IF NOT EXISTS dbversions (
        db TEXT PRIMARY KEY,
        version INT NOT NULL
    )
    """)


async def m001_initial(db: Database):
    async with db.connect() as conn:
        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS proofs (
                    amount {db.big_int} NOT NULL,
                    C TEXT NOT NULL,
                    secret TEXT NOT NULL,

                    UNIQUE (secret)

                );
            """)

        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS proofs_used (
                    amount {db.big_int} NOT NULL,
                    C TEXT NOT NULL,
                    secret TEXT NOT NULL,

                    UNIQUE (secret)

                );
            """)

        await conn.execute("""
            CREATE VIEW IF NOT EXISTS balance AS
            SELECT COALESCE(SUM(s), 0) AS balance FROM (
                SELECT SUM(amount) AS s
                FROM proofs
                WHERE amount > 0
            );
        """)

        await conn.execute("""
            CREATE VIEW IF NOT EXISTS balance_used AS
            SELECT COALESCE(SUM(s), 0) AS used FROM (
                SELECT SUM(amount) AS s
                FROM proofs_used
                WHERE amount > 0
            );
        """)


async def m002_add_proofs_reserved(db: Database):
    """
    Column for marking proofs as reserved when they are being sent.
    """
    async with db.connect() as conn:
        await conn.execute("ALTER TABLE proofs ADD COLUMN reserved BOOL")


async def m003_add_proofs_sendid_and_timestamps(db: Database):
    """
    Column with unique ID for each initiated send attempt
    so proofs can be later grouped together for each send attempt.
    """
    async with db.connect() as conn:
        await conn.execute("ALTER TABLE proofs ADD COLUMN send_id TEXT")
        await conn.execute("ALTER TABLE proofs ADD COLUMN time_created TIMESTAMP")
        await conn.execute("ALTER TABLE proofs ADD COLUMN time_reserved TIMESTAMP")
        await conn.execute("ALTER TABLE proofs_used ADD COLUMN time_used TIMESTAMP")


async def m004_p2sh_locks(db: Database):
    """
    DEPRECATED: Stores P2SH addresses and unlock scripts.
    """
    # async with db.connect() as conn:
    # await conn.execute("""
    #         CREATE TABLE IF NOT EXISTS p2sh (
    #             address TEXT NOT NULL,
    #             script TEXT NOT NULL,
    #             signature TEXT NOT NULL,
    #             used BOOL NOT NULL,

    #             UNIQUE (address, script, signature)

    #         );
    #     """)


async def m005_wallet_keysets(db: Database):
    """
    Stores mint keysets from different mints and epochs.
    """
    async with db.connect() as conn:
        await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS keysets (
                    id TEXT,
                    mint_url TEXT,
                    valid_from TIMESTAMP DEFAULT {db.timestamp_now},
                    valid_to TIMESTAMP DEFAULT {db.timestamp_now},
                    first_seen TIMESTAMP DEFAULT {db.timestamp_now},
                    active BOOL DEFAULT TRUE,

                    UNIQUE (id, mint_url)

                );
            """)

        await conn.execute("ALTER TABLE proofs ADD COLUMN id TEXT")
        await conn.execute("ALTER TABLE proofs_used ADD COLUMN id TEXT")


async def m006_invoices(db: Database):
    """
    Stores Lightning invoices.
    """
    async with db.connect() as conn:
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS invoices (
                amount INTEGER NOT NULL,
                pr TEXT NOT NULL,
                hash TEXT,
                preimage TEXT,
                paid BOOL DEFAULT FALSE,
                time_created TIMESTAMP DEFAULT {db.timestamp_now},
                time_paid TIMESTAMP DEFAULT {db.timestamp_now},

                UNIQUE (hash)

            );
        """)


async def m007_nostr(db: Database):
    """
    Stores timestamps of nostr operations.
    """
    async with db.connect() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS nostr (
                type TEXT NOT NULL,
                last TIMESTAMP DEFAULT NULL
            )
            """)
        await conn.execute(
            """
            INSERT INTO nostr
                (type, last)
            VALUES (?, ?)
            """,
            (
                "dm",
                None,
            ),
        )


async def m008_keysets_add_public_keys(db: Database):
    """
    Stores public keys of mint in a new column of table keysets.
    """
    async with db.connect() as conn:
        await conn.execute("ALTER TABLE keysets ADD COLUMN public_keys TEXT")


async def m009_privatekey_and_determinstic_key_derivation(db: Database):
    async with db.connect() as conn:
        await conn.execute("ALTER TABLE keysets ADD COLUMN counter INTEGER DEFAULT 0")
        await conn.execute("ALTER TABLE proofs ADD COLUMN derivation_path TEXT")
        await conn.execute("ALTER TABLE proofs_used ADD COLUMN derivation_path TEXT")
        await conn.execute("""
                CREATE TABLE IF NOT EXISTS seed (
                seed TEXT NOT NULL,
                mnemonic TEXT NOT NULL,

                UNIQUE (seed, mnemonic)
                );
            """)
        # await conn.execute("INSERT INTO secret_derivation (counter) VALUES (0)")


async def m010_add_proofs_dleq(db: Database):
    """
    Columns to store DLEQ proofs for proofs.
    """
    async with db.connect() as conn:
        await conn.execute("ALTER TABLE proofs ADD COLUMN dleq TEXT")


async def m010_add_ids_to_proofs_and_out_to_invoices(db: Database):
    """
    Columns that store mint and melt id for proofs and invoices.
    """
    async with db.connect() as conn:
        print("Running wallet migrations")
        await conn.execute("ALTER TABLE proofs ADD COLUMN mint_id TEXT")
        await conn.execute("ALTER TABLE proofs ADD COLUMN melt_id TEXT")

        await conn.execute("ALTER TABLE proofs_used ADD COLUMN mint_id TEXT")
        await conn.execute("ALTER TABLE proofs_used ADD COLUMN melt_id TEXT")

        # column in invoices for marking whether the invoice is incoming (out=False) or outgoing (out=True)
        await conn.execute("ALTER TABLE invoices ADD COLUMN out BOOL")
        # rename column pr to bolt11
        await conn.execute("ALTER TABLE invoices RENAME COLUMN pr TO bolt11")
        # rename column hash to payment_hash
        await conn.execute("ALTER TABLE invoices RENAME COLUMN hash TO id")
        # add column payment_hash
        await conn.execute("ALTER TABLE invoices ADD COLUMN payment_hash TEXT")


async def m011_keysets_add_unit(db: Database):
    async with db.connect() as conn:
        # add column for storing the unit of a keyset
        await conn.execute("ALTER TABLE keysets ADD COLUMN unit TEXT")
        await conn.execute("UPDATE keysets SET unit = 'sat'")
