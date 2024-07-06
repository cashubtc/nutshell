import asyncio
import datetime
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Optional, Union

import psycopg2
from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool, QueuePool

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


class Connection(Compat):
    def __init__(self, conn: AsyncConnection, txn, typ, name, schema):
        self.conn = conn
        self.txn = txn
        self.type = typ
        self.name = name
        self.schema = schema

    def rewrite_query(self, query) -> str:
        if self.type in {POSTGRES, COCKROACH}:
            query = query.replace("%", "%%")
            query = query.replace("?", "%s")
        return text(query)

    async def fetchall(self, query: str, values: dict = {}) -> list:
        result = await self.conn.execute(self.rewrite_query(query), values)
        return result.all()

    async def fetchone(self, query: str, values: dict = {}):
        result = await self.conn.execute(self.rewrite_query(query), values)
        return result.fetchone()

    async def execute(self, query: str, values: dict = {}):
        return await self.conn.execute(self.rewrite_query(query), values)


class Database(Compat):
    _connection: Optional[AsyncConnection] = None

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

            import psycopg2  # type: ignore

            def _parse_timestamp(value, _):
                f = "%Y-%m-%d %H:%M:%S.%f"
                if "." not in value:
                    f = "%Y-%m-%d %H:%M:%S"
                return time.mktime(datetime.datetime.strptime(value, f).timetuple())

            psycopg2.extensions.register_type(  # type: ignore
                psycopg2.extensions.new_type(  # type: ignore
                    psycopg2.extensions.DECIMAL.values,  # type: ignore
                    "DEC2FLOAT",
                    lambda value, curs: float(value) if value is not None else None,
                )
            )
            psycopg2.extensions.register_type(  # type: ignore
                psycopg2.extensions.new_type(  # type: ignore
                    (1082, 1083, 1266),
                    "DATE2INT",
                    lambda value, curs: (
                        time.mktime(value.timetuple()) if value is not None else None  # type: ignore
                    ),
                )
            )

            # psycopg2.extensions.register_type(
            #     psycopg2.extensions.new_type(
            #         (1184, 1114), "TIMESTAMP2INT", _parse_timestamp
            #     )
            # )
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
        else:
            kwargs["poolclass"] = QueuePool
            kwargs["pool_size"] = 10
            kwargs["max_overflow"] = 20

        self.engine = create_async_engine(database_uri, **kwargs)

    async def initialize_connection(self):
        self._connection = await self.engine.connect()

    @property
    def connection(self):
        if self._connection is None:
            raise Exception("Connection not initialized")
        return self._connection

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
        connection: Optional[AsyncConnection] = None

        if self._connection is None:
            await self.initialize_connection()
            assert self._connection is not None, "Connection not initialized"

        # if connection is in transaction, create a new connection
        if self._connection.in_transaction():
            logger.trace("Connection is in transaction. Creating new connection")
            connection = await self.engine.connect()
        else:
            connection = self._connection

        async def _handle_lock_retry(retry_delay, timeout, start_time):
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, timeout - (time.time() - start_time))

        def _is_lock_exception(e):
            return "database is locked" in str(e) or "could not obtain lock" in str(e)

        timeout = lock_timeout or 5  # default to 5 seconds
        start_time = time.time()
        retry_delay = 0.1
        random_int = int(time.time() * 1000)
        trial = 0
        while time.time() - start_time < timeout:
            trial += 1
            try:
                logger.trace("Connecting to database trial: {trial} ({random_int})")
                async with connection.begin() as txn:  # type: ignore
                    logger.trace("Connected to database. Starting transaction")
                    wconn = Connection(
                        connection, txn, self.type, self.name, self.schema
                    )
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
            except psycopg2.errors.LockNotAvailable as e:
                logger.trace(f"Table {lock_table} is already locked: {e}")
                await _handle_lock_retry(retry_delay, timeout, start_time)
            except Exception as e:
                if _is_lock_exception(e):
                    await _handle_lock_retry(retry_delay, timeout, start_time)
                else:
                    raise e
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
            return result.all()

    async def fetchone(self, query: str, values: dict = {}):
        async with self.connect() as conn:
            result = await conn.execute(query, values)
            return result.fetchone()

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
