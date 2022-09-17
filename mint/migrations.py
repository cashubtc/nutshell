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
            CREATE TABLE IF NOT EXISTS promises (
                amount INTEGER NOT NULL,
                B_b TEXT NOT NULL,
                C_b TEXT NOT NULL,

                UNIQUE (B_b)

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
            CREATE TABLE IF NOT EXISTS invoices (
                amount INTEGER NOT NULL,
                pr TEXT NOT NULL,
                hash TEXT NOT NULL,
                issued BOOL NOT NULL,

                UNIQUE (hash)

            );
        """
    )

    await db.execute(
        """
        CREATE VIEW IF NOT EXISTS balance_issued AS
        SELECT COALESCE(SUM(s), 0) AS balance FROM (
            SELECT SUM(amount) AS s
            FROM promises
            WHERE amount > 0
        );
    """
    )

    await db.execute(
        """
        CREATE VIEW IF NOT EXISTS balance_used AS
        SELECT COALESCE(SUM(s), 0) AS balance FROM (
            SELECT SUM(amount) AS s
            FROM proofs_used
            WHERE amount > 0
        );
    """
    )

    await db.execute(
        """
        CREATE VIEW IF NOT EXISTS balance AS
        SELECT s_issued - s_used AS balance FROM (
            SELECT bi.balance AS s_issued, bu.balance AS s_used
            FROM balance_issued bi
            CROSS JOIN balance_used bu
        );
    """
    )
