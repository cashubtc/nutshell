import asyncio
import datetime
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Optional, Union

from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import AsyncAdaptedQueuePool, NullPool
from sqlalchemy.sql.expression import TextClause

from cashu.core.settings import settings

POSTGRES = "POSTGRES"
COCKROACH = "COCKROACH"
SQLITE = "SQLITE"


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
            kwargs["pool_size"] = 50  # type: ignore[assignment]
            kwargs["max_overflow"] = 100  # type: ignore[assignment]

        self.engine = create_async_engine(database_uri, **kwargs)
        self.async_session = sessionmaker(
            self.engine,  # type: ignore
            expire_on_commit=False,
            class_=AsyncSession,  # type: ignore
        )

    @asynccontextmanager
    async def get_connection(
        self,
        conn: Optional[Connection] = None,
        lock_table: Optional[str] = None,
        lock_select_statement: Optional[str] = None,
        lock_timeout: Optional[float] = None,
    ):
        """Either yield the existing database connection (passthrough) or create a new one.

        Args:
            conn (Optional[Connection], optional): Connection object. Defaults to None.
            lock_table (Optional[str], optional): Table to lock. Defaults to None.
            lock_select_statement (Optional[str], optional): Lock select statement. Defaults to None.
            lock_timeout (Optional[float], optional): Lock timeout. Defaults to None.

        Yields:
            Connection: Connection object.
        """
        if conn is not None:
            # Yield the existing connection
            logger.trace("Reusing existing connection")
            yield conn
        else:
            logger.trace("get_connection: Creating new connection")
            async with self.connect(
                lock_table, lock_select_statement, lock_timeout
            ) as new_conn:
                yield new_conn

    @asynccontextmanager
    async def connect(
        self,
        lock_table: Optional[str] = None,
        lock_select_statement: Optional[str] = None,
        lock_timeout: Optional[float] = None,
    ):
        async def _handle_lock_retry(retry_delay, timeout, start_time) -> float:
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, timeout - (time.time() - start_time))
            return retry_delay

        def _is_lock_exception(e):
            if "database is locked" in str(e) or "could not obtain lock" in str(e):
                logger.trace(f"Lock exception: {e}")
                return True

        timeout = lock_timeout or 5  # default to 5 seconds
        start_time = time.time()
        retry_delay = 0.1
        random_int = int(time.time() * 1000)
        trial = 0

        while time.time() - start_time < timeout:
            trial += 1
            session: AsyncSession = self.async_session()  # type: ignore
            try:
                logger.trace(f"Connecting to database trial: {trial} ({random_int})")
                async with session.begin() as txn:  # type: ignore
                    logger.trace("Connected to database. Starting transaction")
                    wconn = Connection(session, txn, self.type, self.name, self.schema)
                    if lock_table:
                        await self.acquire_lock(
                            wconn, lock_table, lock_select_statement
                        )
                    logger.trace(
                        f"> Yielding connection. Lock: {lock_table} - trial {trial} ({random_int})"
                    )
                    yield wconn
                    logger.trace(
                        f"< Connection yielded. Unlock: {lock_table} - trial {trial} ({random_int})"
                    )
                    return
            except Exception as e:
                if _is_lock_exception(e):
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
            f"failed to acquire database lock on {lock_table} after {timeout}s and {trial} trials ({random_int})"
        )

    async def acquire_lock(
        self,
        wconn: Connection,
        lock_table: str,
        lock_select_statement: Optional[str] = None,
    ):
        """Acquire a lock on a table or a row in a table.

        Args:
            wconn (Connection): Connection object.
            lock_table (str): Table to lock.
            lock_select_statement (Optional[str], optional):
            lock_timeout (Optional[float], optional):

        Raises:
            Exception: _description_
        """
        if lock_select_statement:
            assert (
                len(re.findall(r"^[^=]+='[^']+'$", lock_select_statement)) == 1
            ), "lock_select_statement must have exactly one {column}='{value}' pattern."
        try:
            logger.trace(
                f"Acquiring lock on {lock_table} with statement {self.lock_table(lock_table, lock_select_statement)}"
            )
            await wconn.execute(self.lock_table(lock_table, lock_select_statement))
            logger.trace(f"Success: Acquired lock on {lock_table}")
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
                logger.trace(f"Table {lock_table} is already locked: {e}")
            else:
                logger.trace(f"Failed to acquire lock on {lock_table}: {e}")

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

    def lock_table(
        self,
        table: str,
        lock_select_statement: Optional[str] = None,
    ) -> str:
        # with postgres, we can lock a row with a SELECT statement with FOR UPDATE NOWAIT
        if lock_select_statement:
            if self.type == POSTGRES:
                return f"SELECT 1 FROM {self.table_with_schema(table)} WHERE {lock_select_statement} FOR UPDATE NOWAIT;"

        if self.type == POSTGRES:
            return (
                f"LOCK TABLE {self.table_with_schema(table)} IN EXCLUSIVE MODE NOWAIT;"
            )
        elif self.type == COCKROACH:
            return f"LOCK TABLE {table};"
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

    def to_timestamp(self, timestamp_str: str) -> Union[str, datetime.datetime]:
        if not timestamp_str:
            timestamp_str = self.timestamp_now_str()
        if self.type in {POSTGRES, COCKROACH}:
            return datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        elif self.type == SQLITE:
            return timestamp_str
        return "<nothing>"
