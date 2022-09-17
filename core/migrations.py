import re

from loguru import logger

from core.db import COCKROACH, POSTGRES, SQLITE, Database


async def migrate_databases(db: Database, migrations_module):
    """Creates the necessary databases if they don't exist already; or migrates them."""

    async def set_migration_version(conn, db_name, version):
        await conn.execute(
            """
            INSERT INTO dbversions (db, version) VALUES (?, ?)
            ON CONFLICT (db) DO UPDATE SET version = ?
            """,
            (db_name, version, version),
        )

    async def run_migration(db, migrations_module):
        db_name = migrations_module.__name__.split(".")[-2]
        for key, migrate in migrations_module.__dict__.items():
            match = match = matcher.match(key)
            if match:
                version = int(match.group(1))
                if version > current_versions.get(db_name, 0):
                    await migrate(db)

                    if db.schema == None:
                        await set_migration_version(db, db_name, version)
                    else:
                        async with db.connect() as conn:
                            await set_migration_version(conn, db_name, version)

    async with db.connect() as conn:
        if conn.type == SQLITE:
            exists = await conn.fetchone(
                "SELECT * FROM sqlite_master WHERE type='table' AND name='dbversions'"
            )
        elif conn.type in {POSTGRES, COCKROACH}:
            exists = await conn.fetchone(
                "SELECT * FROM information_schema.tables WHERE table_name = 'dbversions'"
            )

        if not exists:
            await migrations_module.m000_create_migrations_table(conn)

        rows = await (await conn.execute("SELECT * FROM dbversions")).fetchall()
        current_versions = {row["db"]: row["version"] for row in rows}
        matcher = re.compile(r"^m(\d\d\d)_")
        await run_migration(conn, migrations_module)
