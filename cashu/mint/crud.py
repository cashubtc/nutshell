from abc import ABC, abstractmethod
from typing import Any, List, Optional

from ..core.base import (
    BlindedSignature,
    MeltQuote,
    MintKeyset,
    MintQuote,
    Proof,
)
from ..core.db import (
    Connection,
    Database,
    table_with_schema,
    timestamp_from_seconds,
    timestamp_now,
)


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
        seed: str = "",
        conn: Optional[Connection] = None,
    ) -> List[MintKeyset]: ...

    @abstractmethod
    async def get_spent_proofs(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]: ...

    async def get_proof_used(
        self,
        *,
        Y: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[Proof]: ...

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
        proofs: List[Proof],
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
    async def get_balance(
        self,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> int: ...

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
    async def get_mint_quote_by_checking_id(
        self,
        *,
        checking_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]: ...

    @abstractmethod
    async def update_mint_quote(
        self,
        *,
        quote: MintQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None: ...

    # @abstractmethod
    # async def update_mint_quote_paid(
    #     self,
    #     *,
    #     quote_id: str,
    #     paid: bool,
    #     db: Database,
    #     conn: Optional[Connection] = None,
    # ) -> None: ...

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
        checking_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Optional[MeltQuote]: ...

    @abstractmethod
    async def update_melt_quote(
        self,
        *,
        quote: MeltQuote,
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
            (amount, B_b, C_b, e, s, id, created)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                amount,
                B_,
                C_,
                e,
                s,
                id,
                timestamp_now(db),
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

    async def get_spent_proofs(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        rows = await (conn or db).fetchall(f"""
            SELECT * from {table_with_schema(db, 'proofs_used')}
            """)
        return [Proof(**r) for r in rows] if rows else []

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
            (amount, C, secret, Y, id, witness, created)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proof.amount,
                proof.C,
                proof.secret,
                proof.Y,
                proof.id,
                proof.witness,
                timestamp_now(db),
            ),
        )

    async def get_proofs_pending(
        self,
        *,
        proofs: List[Proof],
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        rows = await (conn or db).fetchall(
            f"""
            SELECT * from {table_with_schema(db, 'proofs_pending')}
            WHERE Y IN ({','.join(['?']*len(proofs))})
            """,
            tuple(proof.Y for proof in proofs),
        )
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
            (amount, C, secret, Y, created)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                proof.amount,
                proof.C,
                proof.secret,
                proof.Y,
                timestamp_now(db),
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
            (proof.secret,),
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
            (quote, method, request, checking_id, unit, amount, issued, paid, created_time, paid_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                quote.quote,
                quote.method,
                quote.request,
                quote.checking_id,
                quote.unit,
                quote.amount,
                quote.issued,
                quote.paid,
                timestamp_from_seconds(db, quote.created_time),
                timestamp_from_seconds(db, quote.paid_time),
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
        return MintQuote.from_row(row) if row else None

    async def get_mint_quote_by_checking_id(
        self,
        *,
        checking_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {table_with_schema(db, 'mint_quotes')}
            WHERE checking_id = ?
            """,
            (checking_id,),
        )
        return MintQuote.from_row(row) if row else None

    async def update_mint_quote(
        self,
        *,
        quote: MintQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"UPDATE {table_with_schema(db, 'mint_quotes')} SET issued = ?, paid = ?,"
            " paid_time = ? WHERE quote = ?",
            (
                quote.issued,
                quote.paid,
                timestamp_from_seconds(db, quote.paid_time),
                quote.quote,
            ),
        )

    # async def update_mint_quote_paid(
    #     self,
    #     *,
    #     quote_id: str,
    #     paid: bool,
    #     db: Database,
    #     conn: Optional[Connection] = None,
    # ) -> None:
    #     await (conn or db).execute(
    #         f"UPDATE {table_with_schema(db, 'mint_quotes')} SET paid = ? WHERE"
    #         " quote = ?",
    #         (
    #             paid,
    #             quote_id,
    #         ),
    #     )

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
            (quote, method, request, checking_id, unit, amount, fee_reserve, paid, created_time, paid_time, fee_paid, proof)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                quote.quote,
                quote.method,
                quote.request,
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
    ) -> Optional[MeltQuote]:
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
            return None
        return MeltQuote.from_row(row) if row else None

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
            (id, seed, encrypted_seed, seed_encryption_method, derivation_path, valid_from, valid_to, first_seen, active, version, unit)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                keyset.id,
                keyset.seed,
                keyset.encrypted_seed,
                keyset.seed_encryption_method,
                keyset.derivation_path,
                keyset.valid_from or timestamp_now(db),
                keyset.valid_to or timestamp_now(db),
                keyset.first_seen or timestamp_now(db),
                True,
                keyset.version,
                keyset.unit.name,
            ),
        )

    async def get_balance(
        self,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> int:
        row = await (conn or db).fetchone(f"""
            SELECT * from {table_with_schema(db, 'balance')}
            """)
        assert row, "Balance not found"
        return int(row[0])

    async def get_keyset(
        self,
        *,
        db: Database,
        id: Optional[str] = None,
        derivation_path: Optional[str] = None,
        seed: Optional[str] = None,
        unit: Optional[str] = None,
        active: Optional[bool] = None,
        conn: Optional[Connection] = None,
    ) -> List[MintKeyset]:
        clauses = []
        values: List[Any] = []
        if active is not None:
            clauses.append("active = ?")
            values.append(active)
        if id is not None:
            clauses.append("id = ?")
            values.append(id)
        if derivation_path is not None:
            clauses.append("derivation_path = ?")
            values.append(derivation_path)
        if seed is not None:
            clauses.append("seed = ?")
            values.append(seed)
        if unit is not None:
            clauses.append("unit = ?")
            values.append(unit)
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

    async def get_proof_used(
        self,
        *,
        Y: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[Proof]:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {table_with_schema(db, 'proofs_used')}
            WHERE Y = ?
            """,
            (Y,),
        )
        return Proof(**row) if row else None
