from ..core.db import POSTGRES, Database


async def create_keyset_accounting(db: Database) -> None:
    """Add a durable journal without changing existing accounting totals."""
    async with db.connect() as conn:
        if db.type == POSTGRES:
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema('keysets')} "
                "ALTER COLUMN balance TYPE BIGINT, ALTER COLUMN fees_paid TYPE BIGINT"
            )
        await conn.execute(
            f"""CREATE TABLE {db.table_with_schema('keyset_accounting')} (
                event_id TEXT PRIMARY KEY,
                keyset_id TEXT NOT NULL,
                balance_delta {db.big_int} NOT NULL,
                fees_delta {db.big_int} NOT NULL
            )"""
        )
        await conn.execute(
            f"CREATE INDEX keyset_accounting_keyset_idx ON "
            f"{db.table_with_schema('keyset_accounting')} (keyset_id)"
        )
        await conn.execute(
            f"""CREATE VIEW {db.table_with_schema('keyset_accounting_totals')} AS
                SELECT k.id,
                    k.balance + COALESCE((
                        SELECT SUM(balance_delta)
                        FROM {db.table_with_schema('keyset_accounting')}
                        WHERE keyset_id = k.id
                    ), 0) AS balance,
                    k.fees_paid + COALESCE((
                        SELECT SUM(fees_delta)
                        FROM {db.table_with_schema('keyset_accounting')}
                        WHERE keyset_id = k.id
                    ), 0) AS fees_paid
                FROM {db.table_with_schema('keysets')} AS k"""
        )
