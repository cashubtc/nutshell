from core.db import Database


async def m000_create_migrations_table(db):
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
        """
            CREATE TABLE IF NOT EXISTS proofs (
                amount INTEGER NOT NULL,
                C TEXT NOT NULL,
                secret TEXT NOT NULL,

                UNIQUE (secret)

            );
        """
    )

    await db.execute(
        """
            CREATE TABLE IF NOT EXISTS proofs_used (
                amount INTEGER NOT NULL,
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


async def m002_add_proofs_reserved(db):
    """
    Column for marking proofs as reserved when they are being sent.
    """

    await db.execute("ALTER TABLE proofs ADD COLUMN reserved BOOL")


async def m003_add_proofs_sendid_and_timestamps(db):
    """
    Column with unique ID for each initiated send attempt
    so proofs can be later grouped together for each send attempt.
    """
    await db.execute("ALTER TABLE proofs ADD COLUMN send_id TEXT")
    await db.execute("ALTER TABLE proofs ADD COLUMN time_created TIMESTAMP")
    await db.execute("ALTER TABLE proofs ADD COLUMN time_reserved TIMESTAMP")
    await db.execute("ALTER TABLE proofs_used ADD COLUMN time_used TIMESTAMP")
