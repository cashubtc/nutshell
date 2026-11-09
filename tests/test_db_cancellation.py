import asyncio
import threading
import time

import aiosqlite
import anyio
import pytest
from sqlalchemy import event

from cashu.core.db import Database, LockOptions


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cancellation_mode", ["asyncio", "anyio_scope", "anyio_task_group"]
)
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
    tmp_path, monkeypatch, operation, cancellations, statement_fails, cancellation_mode
):
    db = Database("mint", str(tmp_path))
    statement_ready = asyncio.Event()
    release_statement = threading.Event()
    loop = asyncio.get_running_loop()
    column = "missing_column" if statement_fails else "value"
    query = f"SELECT {column} FROM cancellation_values WHERE id = 1"
    original_execute = aiosqlite.Connection._execute
    reader = None
    cancel_scope = None
    transaction_task = None
    cancelled_errors = []

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
        nonlocal transaction_task
        transaction_task = asyncio.current_task()
        try:
            async with db.connect(locks=[LockOptions(table="cancellation_values")]) as conn:
                await conn.execute("UPDATE cancellation_values SET value = 1 WHERE id = 1")
                await getattr(conn, operation)(query)
        except asyncio.CancelledError as exc:
            cancelled_errors.append(exc)
            raise

    async def run_reader():
        nonlocal cancel_scope
        if cancellation_mode == "asyncio":
            await read_in_transaction()
        elif cancellation_mode == "anyio_scope":
            with anyio.CancelScope() as cancel_scope:
                await read_in_transaction()
        else:
            async with anyio.create_task_group() as group:
                cancel_scope = group.cancel_scope
                group.start_soon(read_in_transaction)

    try:
        await db.execute(
            "CREATE TABLE cancellation_values (id INTEGER PRIMARY KEY, value INTEGER)"
        )
        await db.execute("INSERT INTO cancellation_values VALUES (1, 0)")
        monkeypatch.setattr(aiosqlite.Connection, "_execute", pause_statement)
        reader = asyncio.create_task(run_reader())
        await asyncio.wait_for(statement_ready.wait(), timeout=10)
        if cancel_scope is not None:
            cancel_scope.cancel()
        else:
            reader.cancel()
        await asyncio.sleep(0)
        for _ in range(cancellations - 1):
            assert transaction_task is not None
            transaction_task.cancel("independent cancellation")
            await asyncio.sleep(0)

        cpu_start = time.thread_time()
        wall_start = time.monotonic()
        await asyncio.sleep(0.2)
        cpu_elapsed = time.thread_time() - cpu_start
        wall_elapsed = time.monotonic() - wall_start
        assert not reader.done()
        release_statement.set()
        if cancellation_mode == "asyncio" or (
            cancellation_mode == "anyio_scope" and cancellations > 1
        ):
            with pytest.raises(asyncio.CancelledError):
                await reader
        else:
            await reader

        # Retain the cancellation traceback while checking rollback and usability.
        assert len(cancelled_errors) == 1
        if cancellations > 1:
            assert cancelled_errors[0].args == ("independent cancellation",)
        assert cpu_elapsed < wall_elapsed * 0.5
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


@pytest.mark.asyncio
@pytest.mark.parametrize("cancellation_mode", ["asyncio", "anyio_scope", "mixed"])
@pytest.mark.parametrize("statement_outcome", ["acquired", "timeout"])
async def test_cancelled_sqlite_lock_wait_releases_lock(
    tmp_path, cancellation_mode, statement_outcome
):
    db = Database("mint", str(tmp_path))
    lock = LockOptions(table="cancellation_values")
    lock_statement = db._lock_statement(lock)
    statement_started = asyncio.Event()
    transaction_entered = asyncio.Event()
    loop = asyncio.get_running_loop()
    cancel_scope = None
    waiter = None
    cancelled_errors = []

    def trace_statement(statement):
        if statement == lock_statement:
            loop.call_soon_threadsafe(statement_started.set)

    async def acquire_in_transaction():
        try:
            async with db.connect(locks=[lock]) as conn:
                transaction_entered.set()
                await conn.execute("UPDATE cancellation_values SET value = 2 WHERE id = 1")
        except asyncio.CancelledError as exc:
            cancelled_errors.append(exc)
            raise

    async def run_waiter():
        nonlocal cancel_scope
        if cancellation_mode == "asyncio":
            await acquire_in_transaction()
        else:
            with anyio.CancelScope() as cancel_scope:
                await acquire_in_transaction()

    try:
        await db.execute(
            "CREATE TABLE cancellation_values (id INTEGER PRIMARY KEY, value INTEGER)"
        )
        await db.execute("INSERT INTO cancellation_values VALUES (1, 0)")
        async with db.connect(locks=[lock]) as blocker:
            await blocker.execute("UPDATE cancellation_values SET value = 1 WHERE id = 1")

            @event.listens_for(db.engine.sync_engine, "connect")
            def configure_waiter(connection, record):
                cursor = connection.cursor()
                try:
                    cursor.execute("PRAGMA busy_timeout=1500")
                finally:
                    cursor.close()
                connection.run_async(
                    lambda driver: driver.set_trace_callback(trace_statement)
                )

            waiter = asyncio.create_task(run_waiter())
            await asyncio.wait_for(statement_started.wait(), timeout=10)
            assert not waiter.done()
            if cancel_scope is not None:
                cancel_scope.cancel()
            else:
                waiter.cancel()
            await asyncio.sleep(0)
            if cancellation_mode == "mixed":
                waiter.cancel()

            await asyncio.sleep(0.1)
            assert not waiter.done()
            if statement_outcome == "acquired":
                await blocker.txn.rollback()

            if cancellation_mode == "anyio_scope":
                await asyncio.wait_for(waiter, timeout=10)
            else:
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(waiter, timeout=10)

        assert not transaction_entered.is_set()
        assert len(cancelled_errors) == 1
        if cancellation_mode == "mixed":
            assert cancelled_errors[0].args == ()
        row = await db.fetchone("SELECT value FROM cancellation_values WHERE id = 1")
        assert row["value"] == (0 if statement_outcome == "acquired" else 1)
        await db.execute("UPDATE cancellation_values SET value = 3 WHERE id = 1")
        row = await db.fetchone("SELECT value FROM cancellation_values WHERE id = 1")
        assert row["value"] == 3
    finally:
        if waiter is not None:
            if not waiter.done():
                waiter.cancel()
            await asyncio.gather(waiter, return_exceptions=True)
        await db.engine.dispose()
