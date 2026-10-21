from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from asyncpg.exceptions import DeadlockDetectedError, InsufficientPrivilegeError
from sqlalchemy.exc import DBAPIError

from cashu.core.db import Database
from tests.conftest import reset_postgres_database


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type, failures, expected_attempts",
    [
        (DeadlockDetectedError, 0, 1),
        (DeadlockDetectedError, 1, 2),
        (DeadlockDetectedError, 3, 3),
        (InsufficientPrivilegeError, 1, 1),
    ],
)
async def test_reset_postgres_retries_only_deadlocks(
    error_type, failures, expected_attempts
):
    error = DBAPIError("DROP SCHEMA public CASCADE;", None, error_type())
    connections = []
    rolled_back = []

    @asynccontextmanager
    async def connect():
        conn = AsyncMock()
        connections.append(conn)
        if len(connections) <= failures:
            conn.execute.side_effect = error
        try:
            yield conn
        except DBAPIError:
            rolled_back.append(conn)
            raise

    db = MagicMock(spec=Database, connect=connect)
    if error_type is DeadlockDetectedError and failures < 3:
        await reset_postgres_database(db)
        assert [call.args[0] for call in connections[-1].execute.await_args_list] == [
            "DROP SCHEMA public CASCADE;",
            "CREATE SCHEMA public;",
        ]
    else:
        with pytest.raises(DBAPIError) as exc:
            await reset_postgres_database(db)
        assert exc.value is error

    assert len(connections) == expected_attempts
    assert len(rolled_back) == min(failures, expected_attempts)
