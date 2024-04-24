from abc import ABC, abstractmethod
from typing import Any, List, Optional, Tuple

from ..core.base import (
    MeltQuote,
)
from ..core.db import (
    Connection,
    Database,
    table_with_schema,
    timestamp_from_seconds,
)


class GatewayCrud(ABC):
    @abstractmethod
    async def store_melt_quote(
        self,
        *,
        mint: str,
        quote: MeltQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        ...

    @abstractmethod
    async def get_melt_quote(
        self,
        *,
        quote_id: str,
        db: Database,
        checking_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Tuple[str, MeltQuote]:
        ...

    @abstractmethod
    async def update_melt_quote(
        self,
        *,
        quote: MeltQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        ...


class GatewayCrudSqlite(GatewayCrud):
    async def store_melt_quote(
        self,
        *,
        mint: str,
        quote: MeltQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {table_with_schema(db, 'melt_quotes')}
            (mint, quote, method, request, expiry, checking_id, unit, amount, fee_reserve, paid, created_time, paid_time, fee_paid, proof)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mint,
                quote.quote,
                quote.method,
                quote.request,
                quote.expiry,
                quote.checking_id,
                quote.unit,
                quote.amount,
                quote.fee_reserve or 0,
                quote.paid,
                timestamp_from_seconds(db, quote.created_time),
                timestamp_from_seconds(db, quote.paid_time),
                quote.fee_paid,
                quote.proof,
            ),
        )

    async def get_melt_quote(
        self,
        *,
        quote_id: str,
        db: Database,
        checking_id: Optional[str] = None,
        request: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Tuple[str, MeltQuote]:
        clauses = []
        values: List[Any] = []
        if quote_id:
            clauses.append("quote = ?")
            values.append(quote_id)
        if checking_id:
            clauses.append("checking_id = ?")
            values.append(checking_id)
        if request:
            clauses.append("request = ?")
            values.append(request)
        where = ""
        if clauses:
            where = f"WHERE {' AND '.join(clauses)}"
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {table_with_schema(db, 'melt_quotes')}
            {where}
            """,
            tuple(values),
        )
        if row is None:
            raise ValueError("Quote not found")

        mint = row["mint"]
        return (mint, MeltQuote.from_row(row))

    async def update_melt_quote(
        self,
        *,
        quote: MeltQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"UPDATE {table_with_schema(db, 'melt_quotes')} SET paid = ?, fee_paid = ?,"
            " paid_time = ?, proof = ? WHERE quote = ?",
            (
                quote.paid,
                quote.fee_paid,
                timestamp_from_seconds(db, quote.paid_time),
                quote.proof,
                quote.quote,
            ),
        )
