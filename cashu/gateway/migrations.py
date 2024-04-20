from ..core.db import Connection, Database, table_with_schema


async def m000_create_migrations_table(conn: Connection):
    await conn.execute(
        f"""
    CREATE TABLE IF NOT EXISTS {table_with_schema(conn, 'dbversions')} (
        db TEXT PRIMARY KEY,
        version INT NOT NULL
    )
    """
    )


async def m001_initial(db: Database):
    async with db.connect() as conn:
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {table_with_schema(db, 'melt_quotes')} (
                    quote TEXT NOT NULL,
                    method TEXT NOT NULL,
                    request TEXT NOT NULL,
                    checking_id TEXT NOT NULL,
                    expiry TIMESTAMP NOT NULL,
                    unit TEXT NOT NULL,
                    amount {db.big_int} NOT NULL,
                    fee_reserve {db.big_int},
                    paid BOOL NOT NULL,
                    created_time TIMESTAMP,
                    paid_time TIMESTAMP,
                    fee_paid {db.big_int},
                    proof TEXT,

                    UNIQUE (quote)

                );
            """
        )
