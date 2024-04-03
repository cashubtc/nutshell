import os
import re
import time

from loguru import logger

from ..core.db import COCKROACH, POSTGRES, SQLITE, Database, table_with_schema
from ..core.settings import settings


async def backup_database(db: Database, version: int = 0) -> str:
    # for postgres: use pg_dump
    # for sqlite: use sqlite3

    # skip backups if db_backup_path is None
    # and if version is 0 (fresh database)
    if not settings.db_backup_path or not version:
        return ""

    filename = f"backup_{db.name}_{int(time.time())}_v{version}"
    try:
        # create backup directory if it doesn't exist
        os.makedirs(os.path.join(settings.db_backup_path), exist_ok=True)
    except Exception as e:
        logger.error(
            f"Error creating backup directory: {e}. Run with BACKUP_DB_MIGRATION=False"
            " to disable backups before database migrations."
        )
        raise e
    filepath = os.path.join(settings.db_backup_path, filename)

    if db.type == SQLITE:
        filepath = f"{filepath}.sqlite3"
        logger.info(f"Creating {db.type} backup of {db.name} db to {filepath}")
        os.system(f"cp {db.path} {filepath}")
    elif db.type in {POSTGRES, COCKROACH}:
        filepath = f"{filepath}.dump"
        logger.info(f"Creating {db.type} backup of {db.name} db to {filepath}")
        os.system(f"pg_dump --dbname={db.db_location} --file={filepath}")

    return filepath


async def migrate_databases(db: Database, migrations_module):
    """Creates the necessary databases if they don't exist already; or migrates them."""

    async def set_migration_version(conn, db_name, version):
        await conn.execute(
            f"""
            INSERT INTO {table_with_schema(db, 'dbversions')} (db, version) VALUES (?, ?)
            ON CONFLICT (db) DO UPDATE SET version = ?
            """,
            (db_name, version, version),
        )

    async def run_migration(db, migrations_module):
        db_name = migrations_module.__name__.split(".")[-2]
        # we first check whether any migration is needed and create a backup if so
        migration_needed = False
        for key, migrate in migrations_module.__dict__.items():
            match = matcher.match(key)
            if match:
                version = int(match.group(1))
                if version > current_versions.get(db_name, 0):
                    migration_needed = True
                    break
        if migration_needed and settings.db_backup_path:
            logger.debug(f"Creating backup of {db_name} db")
            current_version = current_versions.get(db_name, 0)
            await backup_database(db, current_version)

        # then we run the migrations
        for key, migrate in migrations_module.__dict__.items():
            match = matcher.match(key)
            if match:
                version = int(match.group(1))
                if version > current_versions.get(db_name, 0):
                    logger.debug(f"Migrating {db_name} db: {key}")
                    await migrate(db)

                    if db.schema is None:
                        await set_migration_version(db, db_name, version)
                    else:
                        async with db.connect() as conn:
                            await set_migration_version(conn, db_name, version)

    async with db.connect() as conn:  # type: ignore
        exists = None
        if conn.type == SQLITE:
            exists = await conn.fetchone(
                "SELECT * FROM sqlite_master WHERE type='table' AND"
                f" name='{table_with_schema(db, 'dbversions')}'"
            )
        elif conn.type in {POSTGRES, COCKROACH}:
            exists = await conn.fetchone(
                "SELECT * FROM information_schema.tables WHERE table_name ="
                f" '{table_with_schema(db, 'dbversions')}'"
            )

        if not exists:
            await migrations_module.m000_create_migrations_table(conn)

        rows = await (
            await conn.execute(f"SELECT * FROM {table_with_schema(db, 'dbversions')}")
        ).fetchall()
        current_versions = {row["db"]: row["version"] for row in rows}
        matcher = re.compile(r"^m(\d\d\d)_")
    await run_migration(db, migrations_module)
