from ..core.db import Database


async def m000_create_migrations_table(db: Database):
    await db.execute(
        """
    CREATE TABLE IF NOT EXISTS dbversions (
        db TEXT PRIMARY KEY,
        version INT NOT NULL
    )
    """
    )


async def m001_initial(db: Database):
    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS proofs (
                amount {db.big_int} NOT NULL,
                C TEXT NOT NULL,
                secret TEXT NOT NULL,

                UNIQUE (secret)

            );
        """
    )

    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS proofs_used (
                amount {db.big_int} NOT NULL,
                C TEXT NOT NULL,
                secret TEXT NOT NULL,

                UNIQUE (secret)

            );
        """
    )

    await db.execute(
        """
        CREATE VIEW IF NOT EXISTS balance AS
        SELECT COALESCE(SUM(s), 0) AS balance FROM (
            SELECT SUM(amount) AS s
            FROM proofs
            WHERE amount > 0
        );
    """
    )

    await db.execute(
        """
        CREATE VIEW IF NOT EXISTS balance_used AS
        SELECT COALESCE(SUM(s), 0) AS used FROM (
            SELECT SUM(amount) AS s
            FROM proofs_used
            WHERE amount > 0
        );
    """
    )


async def m002_add_proofs_reserved(db: Database):
    """
    Column for marking proofs as reserved when they are being sent.
    """

    await db.execute("ALTER TABLE proofs ADD COLUMN reserved BOOL")


async def m003_add_proofs_sendid_and_timestamps(db: Database):
    """
    Column with unique ID for each initiated send attempt
    so proofs can be later grouped together for each send attempt.
    """
    await db.execute("ALTER TABLE proofs ADD COLUMN send_id TEXT")
    await db.execute("ALTER TABLE proofs ADD COLUMN time_created TIMESTAMP")
    await db.execute("ALTER TABLE proofs ADD COLUMN time_reserved TIMESTAMP")
    await db.execute("ALTER TABLE proofs_used ADD COLUMN time_used TIMESTAMP")


async def m004_p2sh_locks(db: Database):
    """
    Stores P2SH addresses and unlock scripts.
    """
    await db.execute(
        """
            CREATE TABLE IF NOT EXISTS p2sh (
                address TEXT NOT NULL,
                script TEXT NOT NULL,
                signature TEXT NOT NULL,
                used BOOL NOT NULL,

                UNIQUE (address, script, signature)

            );
        """
    )


async def m005_wallet_keysets(db: Database):
    """
    Stores mint keysets from different mints and epochs.
    """
    await db.execute(
        f"""
            CREATE TABLE IF NOT EXISTS keysets (
                id TEXT,
                mint_url TEXT,
                valid_from TIMESTAMP DEFAULT {db.timestamp_now},
                valid_to TIMESTAMP DEFAULT {db.timestamp_now},
                first_seen TIMESTAMP DEFAULT {db.timestamp_now},
                active BOOL DEFAULT TRUE,

                UNIQUE (id, mint_url)

            );
        """
    )

    await db.execute("ALTER TABLE proofs ADD COLUMN id TEXT")
    await db.execute("ALTER TABLE proofs_used ADD COLUMN id TEXT")


async def m006_invoices(db: Database):
    """
    Stores Lightning invoices.
    """
    await db.execute(
        f"""
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
    """
    )


async def m007_nostr(db: Database):
    """
    Stores timestamps of nostr operations.
    """
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS nostr (
            type TEXT NOT NULL,
            last TIMESTAMP DEFAULT NULL
        )
        """
    )
    await db.execute(
        f"""
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
    await db.execute("ALTER TABLE keysets ADD COLUMN public_keys TEXT")
