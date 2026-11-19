import asyncio
import datetime
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from itertools import groupby
from typing import Any, Mapping, Optional, Sequence, Union

import anyio
from loguru import logger
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import AsyncAdaptedQueuePool, NullPool
from sqlalchemy.sql.expression import TextClause

from cashu.core.settings import settings

POSTGRES = "POSTGRES"
COCKROACH = "COCKROACH"
SQLITE = "SQLITE"


def mask_db_location(db_location: str) -> str:
    """Hide everything after the scheme of a database URL so it can be logged."""
    scheme, separator, _ = db_location.partition("://")
    return f"{scheme}{separator}********" if separator else db_location


@dataclass(frozen=True)
class LockOptions:
    """Describe locks, optionally restricted to a backend with ``only_on``."""

    table: str
    select_statement: Optional[str] = None
    parameters: Mapping[str, Any] = field(default_factory=dict)
    timeout: Optional[float] = None
    advisory_key: Optional[int] = None
    only_on: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.table:
            raise ValueError("Lock table must not be empty.")
        if self.timeout is not None and self.timeout <= 0:
            raise ValueError("Lock timeout must be greater than zero.")
        if self.advisory_key is not None:
            if self.select_statement:
                raise ValueError("An advisory lock cannot also select rows.")
            if type(self.advisory_key) is not int:
                raise TypeError("Advisory lock key must be an integer.")
            if self.advisory_key < -(2**63) or self.advisory_key > 2**63 - 1:
                raise ValueError("Advisory lock key must be a signed 64-bit integer.")

    def resolve(self, db: "Database") -> Sequence["LockOptions"]:
        """Expand a lock option into the resources required by this database."""
        return (self,)


class Compat:
    type: Optional[str] = "<inherited>"
    schema: Optional[str] = "<inherited>"

    @property
    def epoch_now(self) -> str:
        """Database time in Unix seconds, for comparing persisted leases."""
        if self.type in {POSTGRES, COCKROACH}:
            return "EXTRACT(EPOCH FROM clock_timestamp())"
        return "((julianday('now') - 2440587.5) * 86400.0)"

    def interval_seconds(self, seconds: int) -> str:
        if self.type in {POSTGRES, COCKROACH}:
            return f"interval '{seconds} seconds'"
        elif self.type == SQLITE:
            return f"{seconds}"
        return "<nothing>"

    @property
    def timestamp_now(self) -> str:
        if self.type in {POSTGRES, COCKROACH}:
            return "now()"
        elif self.type == SQLITE:
            # return "(strftime('%s', 'now'))"
            return str(int(time.time()))
        return "<nothing>"

    @property
    def serial_primary_key(self) -> str:
        if self.type in {POSTGRES, COCKROACH}:
            return "SERIAL PRIMARY KEY"
        elif self.type == SQLITE:
            return "INTEGER PRIMARY KEY AUTOINCREMENT"
        return "<nothing>"

    @property
    def references_schema(self) -> str:
        if self.type in {POSTGRES, COCKROACH}:
            return f"{self.schema}."
        elif self.type == SQLITE:
            return ""
        return "<nothing>"

    @property
    def big_int(self) -> str:
        if self.type in {POSTGRES}:
            return "BIGINT"
        return "INT"

    def table_with_schema(self, table: str):
        return f"{self.references_schema if self.schema else ''}{table}"


# https://docs.sqlalchemy.org/en/14/core/connections.html#sqlalchemy.engine.CursorResult
class Connection(Compat):
    def __init__(self, conn: AsyncSession, txn, typ, name, schema):
        self.conn = conn
        self.txn = txn
        self.type = typ
        self.name = name
        self.schema = schema
        self._sqlite_exclusive_lock_acquired = False
        self._advisory_locks_acquired: set[int] = set()

    def rewrite_query(self, query) -> TextClause:
        if self.type in {POSTGRES, COCKROACH}:
            query = query.replace("%", "%%")
            query = query.replace("?", "%s")
        return text(query)

    async def fetchall(self, query: str, values: dict = {}):
        result = await self.execute(query, values)
        return [
            r._mapping for r in result.all()
        ]  # will return [] if result list is empty

    async def fetchone(self, query: str, values: dict = {}):
        result = await self.execute(query, values)
        r = result.fetchone()
        return r._mapping if r is not None else None

    async def execute(self, query: str, values: dict = {}):
        statement = self.conn.execute(self.rewrite_query(query), values)
        if self.type != SQLITE:
            return await statement

        # Finish the statement and close its cursor before cancellation reaches
        # the transaction context, so rollback can release SQLite's write lock.
        task = asyncio.create_task(statement)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            cancellation = exc

        with anyio.CancelScope(shield=True):
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError as exc:
                    cancellation = exc
                except Exception:
                    break
        if not task.cancelled():
            task.exception()
        raise cancellation


class Database(Compat):
    _connection: Optional[AsyncSession] = None

    def __init__(self, db_name: str, db_location: str):
        self.name = db_name
        self.db_location = db_location
        self.db_location_is_url = "://" in self.db_location
        if self.db_location_is_url:
            # raise Exception("Remote databases not supported. Use SQLite.")
            database_uri = self.db_location

            if database_uri.startswith("cockroachdb://"):
                self.type = COCKROACH
            else:
                self.type = POSTGRES
                database_uri = database_uri.replace(
                    "postgres://", "postgresql+asyncpg://"
                )
                database_uri = database_uri.replace(
                    "postgresql://", "postgresql+asyncpg://"
                )
                # Disble prepared statement cache: https://docs.sqlalchemy.org/en/14/dialects/postgresql.html#prepared-statement-cache
                database_uri += "?prepared_statement_cache_size=0"
        else:
            if not os.path.exists(self.db_location):
                logger.info(f"Creating database directory: {self.db_location}")
                os.makedirs(self.db_location)
            self.path = os.path.join(self.db_location, f"{self.name}.sqlite3")
            database_uri = f"sqlite+aiosqlite:///{self.path}?check_same_thread=false"
            self.type = SQLITE

        self.schema = self.name
        if self.name.startswith("ext_"):
            self.schema = self.name[4:]
        else:
            self.schema = None

        kwargs = {}
        if not settings.db_connection_pool:
            kwargs["poolclass"] = NullPool
        elif self.type == POSTGRES:
            kwargs["poolclass"] = AsyncAdaptedQueuePool  # type: ignore[assignment]
            kwargs["pool_size"] = 5 if "test" in settings.cashu_dir else 50  # type: ignore[assignment]
            kwargs["max_overflow"] = 10 if "test" in settings.cashu_dir else 100  # type: ignore[assignment]
            kwargs["connect_args"] = {  # type: ignore[assignment]
                "server_settings": {
                    "lock_timeout": str(settings.mint_database_lock_timeout)
                }
            }

        self.engine = create_async_engine(database_uri, **kwargs)

        # Ensure SQLite enforces foreign keys on every connection
        if self.type == SQLITE:

            @event.listens_for(self.engine.sync_engine, "connect")
            def _set_sqlite_pragma(dbapi_connection, connection_record):
                try:
                    cursor = dbapi_connection.cursor()
                    cursor.execute("PRAGMA foreign_keys=ON;")
                    cursor.execute("PRAGMA journal_mode=WAL;")
                    cursor.close()
                except Exception as e:
                    logger.warning(f"Could not enable SQLite PRAGMAs: {e}")

        self.async_session = sessionmaker(
            self.engine,  # type: ignore
            expire_on_commit=False,
            class_=AsyncSession,  # type: ignore
        )

    @asynccontextmanager
    async def get_connection(
        self,
        conn: Optional[Connection] = None,
        locks: Optional[Sequence[LockOptions]] = None,
    ):
        """Either yield the existing database connection (passthrough) or create a new one.

        Args:
            conn (Optional[Connection], optional): Connection object. Defaults to None.
            locks (Optional[Sequence[LockOptions]], optional): Ordered locks to acquire.
                Variants are resolved and backend restrictions applied before acquisition.
                If more than one timeout is provided, the shortest applies to
                acquisition of the complete lock set.

        Yields:
            Connection: Connection object.
        """
        if conn is not None:
            logger.trace("Reusing existing connection")
            if locks:
                resolved = self._resolve_locks(locks)
                deadline = time.monotonic() + self._lock_timeout(resolved)
                await self._acquire_locks(conn, resolved, retry_deadline=deadline)
            yield conn
        else:
            logger.trace("get_connection: Creating new connection")
            async with self.connect(locks=locks) as new_conn:
                yield new_conn

    @asynccontextmanager
    async def connect(
        self,
        locks: Optional[Sequence[LockOptions]] = None,
    ):
        locks = self._resolve_locks(locks or ())

        async def _handle_lock_retry(retry_delay, timeout, start_time) -> float:
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, timeout - (time.time() - start_time))
            return retry_delay

        def _is_lock_exception(e):
            if (
                "database is locked" in str(e)
                or "could not obtain lock" in str(e)
                or "lock timeout" in str(e).lower()
                or "lock_not_available" in str(e).lower()
                or "55p03" in str(e).lower()  # lock_not_available postgres error code
            ):
                logger.trace(f"Lock exception: {e}")
                return True

        timeout = self._lock_timeout(locks)
        start_time = time.time()
        retry_delay = 0.1
        random_int = int(time.time() * 1000)
        trial = 0

        while time.time() - start_time < timeout:
            trial += 1
            session: AsyncSession = self.async_session()  # type: ignore
            connection_ready = False
            with anyio.CancelScope() as cleanup_scope:
                try:
                    logger.trace(
                        f"Connecting to database trial: {trial} ({random_int})"
                    )
                    async with session.begin() as txn:  # type: ignore
                        try:
                            logger.trace("Connected to database. Starting transaction")
                            wconn = Connection(
                                session, txn, self.type, self.name, self.schema
                            )
                            await self._acquire_locks(wconn, locks)
                            connection_ready = True
                            logger.trace(
                                f"> Yielding connection. Locks: {locks} - trial {trial} ({random_int})"
                            )
                            yield wconn
                            logger.trace(
                                f"< Connection yielded. Unlock: {locks} - trial {trial} ({random_int})"
                            )
                            return
                        except asyncio.CancelledError:
                            cleanup_scope.shield = True
                            raise
                except Exception as e:
                    if not connection_ready and _is_lock_exception(e):
                        retry_delay = await _handle_lock_retry(
                            retry_delay, timeout, start_time
                        )
                    else:
                        logger.error(
                            f"Error in session trial: {trial} ({random_int}): {e}"
                        )
                        raise
                finally:
                    cleanup_scope.shield = True
                    logger.trace(f"Closing session trial: {trial} ({random_int})")
                    await session.close()

        raise Exception(
            f"failed to acquire database locks {locks} after {timeout}s and {trial} trials ({random_int})"
        )

    def _resolve_locks(self, locks: Sequence[LockOptions]) -> tuple[LockOptions, ...]:
        return tuple(
            resolved
            for lock in locks
            if lock.only_on is None or lock.only_on == self.type
            for resolved in lock.resolve(self)
        )

    def _lock_timeout(self, locks: Sequence[LockOptions]) -> float:
        return min((lock.timeout for lock in locks if lock.timeout), default=5)

    async def _acquire_locks(
        self,
        wconn: Connection,
        locks: Sequence[LockOptions],
        retry_deadline: Optional[float] = None,
    ) -> None:
        if not locks:
            return

        locks = self._order_locks(locks)

        # SQLite locks the entire database for writes. One exclusive lock
        # covers every requested table and must not be started twice on the
        # same transaction.
        if self.type == SQLITE:
            if not wconn._sqlite_exclusive_lock_acquired:
                await self._acquire_lock(wconn, locks[0])
                wconn._sqlite_exclusive_lock_acquired = True
            return

        for _, table_locks in groupby(locks, key=lambda lock: lock.table):
            keys: set[int] = set()
            for lock in table_locks:
                if self.type == POSTGRES and lock.advisory_key is not None:
                    keys.add(lock.advisory_key)
                else:
                    await self._acquire_lock(wconn, lock)
            missing_keys = sorted(keys - wconn._advisory_locks_acquired)
            if missing_keys:
                await self._acquire_advisory_locks(wconn, missing_keys, retry_deadline)

    def _order_locks(self, locks: Sequence[LockOptions]) -> tuple[LockOptions, ...]:
        """Order tables before acquiring their row and advisory locks."""
        return tuple(sorted(locks, key=lambda lock: lock.table))

    async def _acquire_advisory_locks(
        self, conn: Connection, keys: list[int], retry_deadline: Optional[float]
    ) -> None:
        # Scan the sorted array in order and stop at the first busy key.
        # A fresh transaction rolls back partial acquisition before retrying.
        # A reused transaction keeps its locks and can retry the remaining suffix.
        remaining = keys
        delay = 0.1
        while True:
            busy = await conn.fetchone(
                """
                SELECT key FROM unnest(CAST(:keys AS bigint[])) AS requested(key)
                WHERE NOT pg_try_advisory_xact_lock(key)
                LIMIT 1
                """,
                {"keys": remaining},
            )
            if busy is None:
                conn._advisory_locks_acquired.update(keys)
                return
            if retry_deadline is None:
                break
            time_left = retry_deadline - time.monotonic()
            if time_left <= 0:
                break
            remaining = remaining[remaining.index(busy["key"]) :]
            await asyncio.sleep(min(delay, time_left))
            delay *= 2
        raise RuntimeError("could not obtain lock on advisory resource")

    async def _acquire_lock(
        self,
        wconn: Connection,
        lock: LockOptions,
    ) -> None:
        """Acquire a table or row lock.

        Args:
            wconn (Connection): Connection object.
            lock (LockOptions): Lock target and acquisition options.
        """
        try:
            logger.trace(
                f"Acquiring lock on {lock.table} with statement {self._lock_statement(lock)} parameters: {lock.parameters}"
            )
            await wconn.execute(self._lock_statement(lock), dict(lock.parameters))
            logger.trace(f"Success: Acquired lock on {lock.table}")
            return
        except Exception as e:
            if (
                (
                    self.type == POSTGRES
                    and "could not obtain lock on relation" in str(e)
                )
                or (self.type == COCKROACH and "already locked" in str(e))
                or (self.type == SQLITE and "database is locked" in str(e))
            ):
                logger.trace(f"Table {lock.table} is already locked: {e}")
            else:
                logger.trace(f"Failed to acquire lock on {lock.table}: {e}")

            raise e

    async def fetchall(self, query: str, values: dict = {}) -> list:
        async with self.connect() as conn:
            result = await conn.execute(query, values)
            return [r._mapping for r in result.all()]

    async def fetchone(self, query: str, values: dict = {}):
        async with self.connect() as conn:
            result = await conn.execute(query, values)
            r = result.fetchone()
            return r._mapping if r is not None else None

    async def execute(self, query: str, values: dict = {}):
        async with self.connect() as conn:
            return await conn.execute(query, values)

    @asynccontextmanager
    async def reuse_conn(self, conn: Connection):
        yield conn

    def _lock_statement(self, lock: LockOptions) -> str:
        # with postgres, we can lock a row with a SELECT statement with FOR UPDATE NOWAIT
        if lock.select_statement:
            if self.type == POSTGRES:
                return f"SELECT 1 FROM {self.table_with_schema(lock.table)} WHERE {lock.select_statement} FOR UPDATE NOWAIT;"

        if self.type == POSTGRES:
            return f"LOCK TABLE {self.table_with_schema(lock.table)} IN EXCLUSIVE MODE NOWAIT;"
        elif self.type == COCKROACH:
            return f"LOCK TABLE {lock.table};"
        elif self.type == SQLITE:
            return "BEGIN EXCLUSIVE TRANSACTION;"
        return "<nothing>"

    def timestamp_from_seconds(
        self, seconds: Union[int, float, None]
    ) -> Union[str, None]:
        if seconds is None:
            return None
        seconds = int(seconds)
        if self.type in {POSTGRES, COCKROACH}:
            return datetime.datetime.fromtimestamp(seconds).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        elif self.type == SQLITE:
            return str(seconds)
        return None

    def timestamp_now_str(self) -> str:
        timestamp = self.timestamp_from_seconds(time.time())
        if timestamp is None:
            raise Exception("Timestamp is None")
        return timestamp

    def to_timestamp(
        self, timestamp: Union[str, datetime.datetime]
    ) -> Union[str, datetime.datetime, None]:
        if not timestamp:
            return None
        if self.type in {POSTGRES, COCKROACH}:
            # return datetime.datetime
            if isinstance(timestamp, datetime.datetime):
                return timestamp
            elif isinstance(timestamp, str):
                return datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        elif self.type == SQLITE:
            # return str
            if isinstance(timestamp, datetime.datetime):
                return timestamp.strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(timestamp, str):
                return timestamp
        return "<nothing>"
