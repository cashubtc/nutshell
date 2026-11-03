import asyncio
import threading

import aiosqlite
import pytest
from sqlalchemy import event

from cashu.core.db import Database, LockOptions


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation, cancellations, statement_fails",
    [
        ("execute", 1, False),
        ("fetchone", 1, False),
        ("fetchall", 1, False),
        ("execute", 2, False),
        ("execute", 1, True),
    ],
)
async def test_cancelled_sqlite_statement_rolls_back_and_releases_lock(
    tmp_path, monkeypatch, operation, cancellations, statement_fails
):
    db = Database("mint", str(tmp_path))
    statement_ready = asyncio.Event()
    release_statement = threading.Event()
    loop = asyncio.get_running_loop()
    column = "missing_column" if statement_fails else "value"
    query = f"SELECT {column} FROM cancellation_values WHERE id = 1"
    original_execute = aiosqlite.Connection._execute
    reader = None

    @event.listens_for(db.engine.sync_engine, "connect")
    def set_busy_timeout(connection, record):
        cursor = connection.cursor()
        try:
            cursor.execute("PRAGMA busy_timeout=100")
        finally:
            cursor.close()

    async def pause_statement(self, fn, *args, **kwargs):
        if fn.__name__ == "execute" and args and args[0] == query:

            def execute_and_pause():
                try:
                    return fn(*args, **kwargs)
                finally:
                    loop.call_soon_threadsafe(statement_ready.set)
                    if not release_statement.wait(timeout=10):
                        raise TimeoutError("SQLite statement was not released")

            return await original_execute(self, execute_and_pause)
        return await original_execute(self, fn, *args, **kwargs)

    async def read_in_transaction():
        async with db.connect(locks=[LockOptions(table="cancellation_values")]) as conn:
            await conn.execute("UPDATE cancellation_values SET value = 1 WHERE id = 1")
            await getattr(conn, operation)(query)

    try:
        await db.execute(
            "CREATE TABLE cancellation_values (id INTEGER PRIMARY KEY, value INTEGER)"
        )
        await db.execute("INSERT INTO cancellation_values VALUES (1, 0)")
        monkeypatch.setattr(aiosqlite.Connection, "_execute", pause_statement)
        reader = asyncio.create_task(read_in_transaction())
        await asyncio.wait_for(statement_ready.wait(), timeout=10)
        for _ in range(cancellations):
            reader.cancel()
            await asyncio.sleep(0)
        release_statement.set()
        with pytest.raises(asyncio.CancelledError) as cancelled:
            await reader

        # Retain the cancellation traceback while checking rollback and usability.
        assert cancelled.type is asyncio.CancelledError
        row = await db.fetchone("SELECT value FROM cancellation_values WHERE id = 1")
        assert row["value"] == 0
        await db.execute("UPDATE cancellation_values SET value = 2 WHERE id = 1")
        row = await db.fetchone("SELECT value FROM cancellation_values WHERE id = 1")
        assert row["value"] == 2
    finally:
        release_statement.set()
        if reader is not None:
            if not reader.done():
                reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
        await db.engine.dispose()
