import asyncio
import datetime
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence, Union

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

@dataclass(frozen=True)
class LockOptions:
    """Describes one table or row lock in an ordered transaction lock set."""

    table: str
    select_statement: Optional[str] = None
    parameters: Mapping[str, Any] = field(default_factory=dict)
    timeout: Optional[float] = None

    def __post_init__(self) -> None:
        if not self.table:
            raise ValueError("Lock table must not be empty.")
        if self.timeout is not None and self.timeout <= 0:
            raise ValueError("Lock timeout must be greater than zero.")


class Compat:
    type: Optional[str] = "<inherited>"
    schema: Optional[str] = "<inherited>"

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

    def rewrite_query(self, query) -> TextClause:
        if self.type in {POSTGRES, COCKROACH}:
            query = query.replace("%", "%%")
            query = query.replace("?", "%s")
        return text(query)

    async def fetchall(self, query: str, values: dict = {}):
        result = await self.conn.execute(self.rewrite_query(query), values)
        return [
            r._mapping for r in result.all()
        ]  # will return [] if result list is empty

    async def fetchone(self, query: str, values: dict = {}):
        result = await self.conn.execute(self.rewrite_query(query), values)
        r = result.fetchone()
        return r._mapping if r is not None else None

    async def execute(self, query: str, values: dict = {}):
        return await self.conn.execute(self.rewrite_query(query), values)


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
                If more than one timeout is provided, the shortest applies to
                acquisition of the complete lock set.

        Yields:
            Connection: Connection object.
        """
        locks = tuple(locks or ())
        if conn is not None:
            logger.trace("Reusing existing connection")
            await self._acquire_locks(conn, locks)
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
        locks = tuple(locks or ())

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

        configured_timeouts = [lock.timeout for lock in locks if lock.timeout]
        timeout = min(configured_timeouts, default=5)
        start_time = time.time()
        retry_delay = 0.1
        random_int = int(time.time() * 1000)
        trial = 0

        while time.time() - start_time < timeout:
            trial += 1
            session: AsyncSession = self.async_session()  # type: ignore
            connection_ready = False
            try:
                logger.trace(f"Connecting to database trial: {trial} ({random_int})")
                async with session.begin() as txn:  # type: ignore
                    logger.trace("Connected to database. Starting transaction")
                    wconn = Connection(session, txn, self.type, self.name, self.schema)
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
            except Exception as e:
                if not connection_ready and _is_lock_exception(e):
                    retry_delay = await _handle_lock_retry(
                        retry_delay, timeout, start_time
                    )
                else:
                    logger.error(f"Error in session trial: {trial} ({random_int}): {e}")
                    raise
            finally:
                logger.trace(f"Closing session trial: {trial} ({random_int})")
                await session.close()

        raise Exception(
            f"failed to acquire database locks {locks} after {timeout}s and {trial} trials ({random_int})"
        )

    async def _acquire_locks(
        self,
        wconn: Connection,
        locks: Sequence[LockOptions],
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

        for lock in locks:
            await self._acquire_lock(wconn, lock)

    def _order_locks(
        self, locks: Sequence[LockOptions]
    ) -> tuple[LockOptions, ...]:
        """Return locks ordered by table name."""
        return tuple(sorted(locks, key=lambda lock: lock.table))

    async def _acquire_lock(
        self,
        wconn: Connection,
        lock: LockOptions,
    ) -> None:
        """Acquire a lock on a table or a row in a table.

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
