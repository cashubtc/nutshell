from abc import ABC, abstractmethod
from typing import Any, List, Optional

from ..core.base import (
    BlindedSignature,
    Invoice,
    MeltQuote,
    MintKeyset,
    MintQuote,
    Proof,
)
from ..core.db import Connection, Database, table_with_schema


class LedgerCrud(ABC):
    """
    Database interface for Cashu mint.

    This class needs to be overloaded by any app that imports the Cashu mint and wants
    to use their own database.
    """

    @abstractmethod
    async def get_keyset(
        self,
        *,
        db: Database,
        id: str = "",
        derivation_path: str = "",
        conn: Optional[Connection] = None,
    ) -> List[MintKeyset]: ...

    @abstractmethod
    async def get_secrets_used(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[List[str]]: ...

    @abstractmethod
    async def invalidate_proof(
        self,
        *,
        db: Database,
        proof: Proof,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def get_proofs_pending(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]: ...

    @abstractmethod
    async def set_proof_pending(
        self,
        *,
        db: Database,
        proof: Proof,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def unset_proof_pending(
        self, *, proof: Proof, db: Database, conn: Optional[Connection] = None
    ) -> None: ...

    @abstractmethod
    async def store_keyset(
        self,
        *,
        db: Database,
        keyset: MintKeyset,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def store_promise(
        self,
        *,
        db: Database,
        amount: int,
        B_: str,
        C_: str,
        id: str,
        e: str = "",
        s: str = "",
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def get_promise(
        self,
        *,
        db: Database,
        B_: str,
        conn: Optional[Connection] = None,
    ) -> Optional[BlindedSignature]: ...

    @abstractmethod
    async def store_lightning_invoice(
        self,
        *,
        db: Database,
        invoice: Invoice,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def update_lightning_invoice(
        self,
        *,
        db: Database,
        id: str,
        issued: bool,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def get_lightning_invoice(
        self,
        *,
        db: Database,
        id: Optional[str] = None,
        checking_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Optional[Invoice]: ...

    @abstractmethod
    async def store_mint_quote(
        self,
        *,
        quote: MintQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def get_mint_quote(
        self,
        *,
        quote_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]: ...

    @abstractmethod
    async def update_mint_quote(
        self,
        *,
        quote_id: str,
        issued: bool,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def store_melt_quote(
        self,
        *,
        quote: MeltQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def get_melt_quote(
        self,
        *,
        quote_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]: ...

    @abstractmethod
    async def update_melt_quote(
        self,
        *,
        quote_id: str,
        issued: bool,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None: ...


class LedgerCrudSqlite(LedgerCrud):
    """Implementation of LedgerCrud for sqlite.

    Args:
        LedgerCrud (ABC): Abstract base class for LedgerCrud.
    """

    async def store_promise(
        self,
        *,
        db: Database,
        amount: int,
        B_: str,
        C_: str,
        id: str,
        e: str = "",
        s: str = "",
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {table_with_schema(db, 'promises')}
            (amount, B_b, C_b, e, s, id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                amount,
                B_,
                C_,
                e,
                s,
                id,
            ),
        )

    async def get_promise(
        self,
        *,
        db: Database,
        B_: str,
        conn: Optional[Connection] = None,
    ) -> Optional[BlindedSignature]:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {table_with_schema(db, 'promises')}
            WHERE B_b = ?
            """,
            (str(B_),),
        )
        return BlindedSignature(amount=row[0], C_=row[2], id=row[3]) if row else None

    async def get_secrets_used(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[List[str]]:
        rows = await (conn or db).fetchall(f"""
            SELECT secret from {table_with_schema(db, 'proofs_used')}
            """)
        return [row[0] for row in rows] if rows else None

    async def invalidate_proof(
        self,
        *,
        db: Database,
        proof: Proof,
        conn: Optional[Connection] = None,
    ) -> None:
        # we add the proof and secret to the used list
        await (conn or db).execute(
            f"""
            INSERT INTO {table_with_schema(db, 'proofs_used')}
            (amount, C, secret, id)
            VALUES (?, ?, ?, ?)
            """,
            (
                proof.amount,
                str(proof.C),
                str(proof.secret),
                str(proof.id),
            ),
        )

    async def get_proofs_pending(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        rows = await (conn or db).fetchall(f"""
            SELECT * from {table_with_schema(db, 'proofs_pending')}
            """)
        return [Proof(**r) for r in rows]

    async def set_proof_pending(
        self,
        *,
        db: Database,
        proof: Proof,
        conn: Optional[Connection] = None,
    ) -> None:
        # we add the proof and secret to the used list
        await (conn or db).execute(
            f"""
            INSERT INTO {table_with_schema(db, 'proofs_pending')}
            (amount, C, secret)
            VALUES (?, ?, ?)
            """,
            (
                proof.amount,
                str(proof.C),
                str(proof.secret),
            ),
        )

    async def unset_proof_pending(
        self,
        *,
        proof: Proof,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            DELETE FROM {table_with_schema(db, 'proofs_pending')}
            WHERE secret = ?
            """,
            (str(proof["secret"]),),
        )

    async def store_mint_quote(
        self,
        *,
        quote: MintQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {table_with_schema(db, 'mint_quotes')}
            (quote, method, request, checking_id, symbol, amount, issued)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                quote.quote,
                quote.method,
                quote.request,
                quote.checking_id,
                quote.symbol,
                quote.amount,
                quote.issued,
            ),
        )

    async def get_mint_quote(
        self,
        *,
        quote_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {table_with_schema(db, 'mint_quotes')}
            WHERE quote = ?
            """,
            (quote_id,),
        )
        row_dict = dict(row)
        return MintQuote(**row_dict) if row_dict else None

    async def update_mint_quote(
        self,
        *,
        quote_id: str,
        issued: bool,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"UPDATE {table_with_schema(db, 'mint_quotes')} SET issued = ? WHERE"
            " quote = ?",
            (
                issued,
                quote_id,
            ),
        )

    async def store_melt_quote(
        self,
        *,
        quote: MeltQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {table_with_schema(db, 'melt_quotes')}
            (quote, method, request, checking_id, symbol, amount, issued)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                quote.quote,
                quote.method,
                quote.request,
                quote.checking_id,
                quote.symbol,
                quote.amount,
                quote.issued,
            ),
        )

    async def get_melt_quote(
        self,
        *,
        quote_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {table_with_schema(db, 'melt_quotes')}
            WHERE quote = ?
            """,
            (quote_id,),
        )
        if row is None:
            return None
        row_dict = dict(row)
        return MintQuote(**row_dict) if row_dict else None

    async def update_melt_quote(
        self,
        *,
        quote_id: str,
        issued: bool,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"UPDATE {table_with_schema(db, 'melt_quotes')} SET issued = ? WHERE"
            " quote = ?",
            (
                issued,
                quote_id,
            ),
        )

    async def store_lightning_invoice(
        self,
        *,
        db: Database,
        invoice: Invoice,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {table_with_schema(db, 'invoices')}
            (amount, bolt11, id, issued, payment_hash, out)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                invoice.amount,
                invoice.bolt11,
                invoice.id,
                invoice.issued,
                invoice.payment_hash,
                invoice.out,
            ),
        )

    async def get_lightning_invoice(
        self,
        *,
        db: Database,
        id: Optional[str] = None,
        checking_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Optional[Invoice]:
        clauses = []
        values: List[Any] = []
        if id:
            clauses.append("id = ?")
            values.append(id)
        if checking_id:
            clauses.append("payment_hash = ?")
            values.append(checking_id)
        where = ""
        if clauses:
            where = f"WHERE {' AND '.join(clauses)}"
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {table_with_schema(db, 'invoices')}
            {where}
            """,
            tuple(values),
        )
        row_dict = dict(row)
        return Invoice(**row_dict) if row_dict else None


    async def update_lightning_invoice(
        self,
        *,
        db: Database,
        id: str,
        issued: bool,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"UPDATE {table_with_schema(db, 'invoices')} SET issued = ? WHERE id = ?",
            (
                issued,
                id,
            ),
        )

    async def store_keyset(
        self,
        *,
        db: Database,
        keyset: MintKeyset,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(  # type: ignore
            f"""
            INSERT INTO {table_with_schema(db, 'keysets')}
            (id, derivation_path, valid_from, valid_to, first_seen, active, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                keyset.id,
                keyset.derivation_path,
                keyset.valid_from or db.timestamp_now,
                keyset.valid_to or db.timestamp_now,
                keyset.first_seen or db.timestamp_now,
                True,
                keyset.version,
            ),
        )

    async def get_keyset(
        self,
        *,
        db: Database,
        id: str = "",
        derivation_path: str = "",
        conn: Optional[Connection] = None,
    ) -> List[MintKeyset]:
        clauses = []
        values: List[Any] = []
        clauses.append("active = ?")
        values.append(True)
        if id:
            clauses.append("id = ?")
            values.append(id)
        if derivation_path:
            clauses.append("derivation_path = ?")
            values.append(derivation_path)
        where = ""
        if clauses:
            where = f"WHERE {' AND '.join(clauses)}"

        rows = await (conn or db).fetchall(  # type: ignore
            f"""
            SELECT * from {table_with_schema(db, 'keysets')}
            {where}
            """,
            tuple(values),
        )
        return [MintKeyset(**row) for row in rows]
