from abc import ABC, abstractmethod
from typing import Optional

from ...core.db import Connection, Database
from .base import User


class AuthLedgerCrud(ABC):
    """
    Database interface for Nutshell auth ledger.
    """

    @abstractmethod
    async def create_user(
        self,
        *,
        db: Database,
        user: User,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def get_user(
        self,
        *,
        db: Database,
        user_id: str,
        conn: Optional[Connection] = None,
    ) -> Optional[User]: ...

    async def update_user(
        self,
        *,
        db: Database,
        user_id: str,
        conn: Optional[Connection] = None,
    ) -> None: ...


class AuthLedgerCrudSqlite(AuthLedgerCrud):
    """Implementation of AuthLedgerCrud for sqlite.

    Args:
        AuthLedgerCrud (ABC): Abstract base class for AuthLedgerCrud.
    """

    async def create_user(
        self,
        *,
        db: Database,
        user: User,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {db.table_with_schema('users')}
            (id)
            VALUES (:id)
            """,
            {"id": user.id},
        )

    async def get_user(
        self,
        *,
        db: Database,
        user_id: str,
        conn: Optional[Connection] = None,
    ) -> Optional[User]:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('users')}
            WHERE id = :user_id
            """,
            {"user_id": user_id},
        )
        return User(**row) if row else None

    async def update_user(
        self,
        *,
        db: Database,
        user_id: str,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            UPDATE {db.table_with_schema('users')}
            SET last_access = :last_access
            WHERE id = :user_id
            """,
            {
                "last_access": db.to_timestamp(db.timestamp_now_str()),
                "user_id": user_id,
            },
        )
