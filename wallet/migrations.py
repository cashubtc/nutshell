from core.db import Database

# from wallet import db


async def m001_initial(db: Database):
    await db.execute(
        """
            CREATE TABLE IF NOT EXISTS proofs (
                amount INTEGER NOT NULL,
                C_x TEXT NOT NULL,
                C_y TEXT NOT NULL,
                secret TEXT NOT NULL,

                UNIQUE (secret)

            );
        """
    )

    await db.execute(
        """
            CREATE TABLE IF NOT EXISTS proofs_used (
                amount INTEGER NOT NULL,
                C_x TEXT NOT NULL,
                C_y TEXT NOT NULL,
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
