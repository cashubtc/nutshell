import json
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
    ) -> List[MintKeyset]:
        ...

    @abstractmethod
    async def get_spent_proofs(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        ...

    async def get_proof_used(
        self,
        *,
        Y: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[Proof]:
        ...

    @abstractmethod
    async def invalidate_proof(
        self,
        *,
        db: Database,
        proof: Proof,
        quote_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        ...

    @abstractmethod
    async def get_all_melt_quotes_from_pending_proofs(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[MeltQuote]:
        ...

    @abstractmethod
    async def get_pending_proofs_for_quote(
        self,
        *,
        quote_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        ...

    @abstractmethod
    async def get_proofs_pending(
        self,
        *,
        Ys: List[str],
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        ...

    @abstractmethod
    async def set_proof_pending(
        self,
        *,
        db: Database,
        proof: Proof,
        quote_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        ...

    @abstractmethod
    async def unset_proof_pending(
        self,
        *,
        proof: Proof,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        ...

    @abstractmethod
    async def store_keyset(
        self,
        *,
        db: Database,
        keyset: MintKeyset,
        conn: Optional[Connection] = None,
    ) -> None:
        ...

    @abstractmethod
    async def get_balance(
        self,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> int:
        ...

    @abstractmethod
    async def store_promise(
        self,
        *,
        db: Database,
        amount: int,
        b_: str,
        c_: str,
        id: str,
        e: str = "",
        s: str = "",
        conn: Optional[Connection] = None,
    ) -> None:
        ...

    @abstractmethod
    async def get_promise(
        self,
        *,
        db: Database,
        b_: str,
        conn: Optional[Connection] = None,
    ) -> Optional[BlindedSignature]:
        ...

    @abstractmethod
    async def store_mint_quote(
        self,
        *,
        quote: MintQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        ...

    @abstractmethod
    async def get_mint_quote(
        self,
        *,
        quote_id: Optional[str] = None,
        checking_id: Optional[str] = None,
        request: Optional[str] = None,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]:
        ...

    @abstractmethod
    async def get_mint_quote_by_request(
        self,
        *,
        request: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]:
        ...

    @abstractmethod
    async def update_mint_quote(
        self,
        *,
        quote: MintQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        ...

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
    ) -> None:
        ...

    @abstractmethod
    async def get_melt_quote(
        self,
        *,
        quote_id: Optional[str] = None,
        checking_id: Optional[str] = None,
        request: Optional[str] = None,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MeltQuote]:
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
        b_: str,
        c_: str,
        id: str,
        e: str = "",
        s: str = "",
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {db.table_with_schema('promises')}
            (amount, b_, c_, dleq_e, dleq_s, id, created)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                amount,
                b_,
                c_,
                e,
                s,
                id,
                db.timestamp_now_str(),
            ),
        )

    async def get_promise(
        self,
        *,
        db: Database,
        b_: str,
        conn: Optional[Connection] = None,
    ) -> Optional[BlindedSignature]:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('promises')}
            WHERE b_ = ?
            """,
            (str(b_),),
        )
        return BlindedSignature.from_row(row) if row else None

    async def get_spent_proofs(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        rows = await (conn or db).fetchall(
            f"""
            SELECT * from {db.table_with_schema('proofs_used')}
            """
        )
        return [Proof(**r) for r in rows] if rows else []

    async def invalidate_proof(
        self,
        *,
        db: Database,
        proof: Proof,
        quote_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        # we add the proof and secret to the used list
        await (conn or db).execute(
            f"""
            INSERT INTO {db.table_with_schema('proofs_used')}
            (amount, c, secret, y, id, witness, created, melt_quote)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proof.amount,
                proof.C,
                proof.secret,
                proof.Y,
                proof.id,
                proof.witness,
                db.timestamp_now_str(),
                quote_id,
            ),
        )

    async def get_all_melt_quotes_from_pending_proofs(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[MeltQuote]:
        rows = await (conn or db).fetchall(
            f"""
            SELECT * from {db.table_with_schema('melt_quotes')} WHERE quote in (SELECT DISTINCT melt_quote FROM {db.table_with_schema('proofs_pending')})
            """
        )
        return [MeltQuote.from_row(r) for r in rows]

    async def get_pending_proofs_for_quote(
        self,
        *,
        quote_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        rows = await (conn or db).fetchall(
            f"""
            SELECT * from {db.table_with_schema('proofs_pending')}
            WHERE melt_quote = ?
            """,
            (quote_id,),
        )
        return [Proof(**r) for r in rows]

    async def get_proofs_pending(
        self,
        *,
        Ys: List[str],
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        rows = await (conn or db).fetchall(
            f"""
            SELECT * from {db.table_with_schema('proofs_pending')}
            WHERE y IN ({','.join(['?']*len(Ys))})
            """,
            tuple(Ys),
        )
        return [Proof(**r) for r in rows]

    async def set_proof_pending(
        self,
        *,
        db: Database,
        proof: Proof,
        quote_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        # we add the proof and secret to the used list
        await (conn or db).execute(
            f"""
            INSERT INTO {db.table_with_schema('proofs_pending')}
            (amount, c, secret, y, id, witness, created, melt_quote)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proof.amount,
                proof.C,
                proof.secret,
                proof.Y,
                proof.id,
                proof.witness,
                db.timestamp_now_str(),
                quote_id,
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
            DELETE FROM {db.table_with_schema('proofs_pending')}
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
            INSERT INTO {db.table_with_schema('mint_quotes')}
            (quote, method, request, checking_id, unit, amount, issued, paid, state, created_time, paid_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                quote.state.name,
                db.timestamp_from_seconds(quote.created_time),
                db.timestamp_from_seconds(quote.paid_time),
            ),
        )

    async def get_mint_quote(
        self,
        *,
        quote_id: Optional[str] = None,
        checking_id: Optional[str] = None,
        request: Optional[str] = None,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]:
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
        if not any(clauses):
            raise ValueError("No search criteria")

        where = f"WHERE {' AND '.join(clauses)}"
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('mint_quotes')}
            {where}
            """,
            tuple(values),
        )
        if row is None:
            return None
        return MintQuote.from_row(row) if row else None

    async def get_mint_quote_by_request(
        self,
        *,
        request: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('mint_quotes')}
            WHERE request = ?
            """,
            (request,),
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
            f"UPDATE {db.table_with_schema('mint_quotes')} SET issued = ?, paid = ?,"
            " state = ?, paid_time = ? WHERE quote = ?",
            (
                quote.issued,
                quote.paid,
                quote.state.name,
                db.timestamp_from_seconds(quote.paid_time),
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
    #         f"UPDATE {db.table_with_schema('mint_quotes')} SET paid = ? WHERE"
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
            INSERT INTO {db.table_with_schema('melt_quotes')}
            (quote, method, request, checking_id, unit, amount, fee_reserve, paid, state, created_time, paid_time, fee_paid, proof, change, expiry)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                quote.state.name,
                db.timestamp_from_seconds(quote.created_time),
                db.timestamp_from_seconds(quote.paid_time),
                quote.fee_paid,
                quote.payment_preimage,
                json.dumps(quote.change) if quote.change else None,
                db.timestamp_from_seconds(quote.expiry),
            ),
        )

    async def get_melt_quote(
        self,
        *,
        quote_id: Optional[str] = None,
        checking_id: Optional[str] = None,
        request: Optional[str] = None,
        db: Database,
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
        if not any(clauses):
            raise ValueError("No search criteria")
        where = f"WHERE {' AND '.join(clauses)}"

        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('melt_quotes')}
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
            f"UPDATE {db.table_with_schema('melt_quotes')} SET paid = ?, state = ?,"
            " fee_paid = ?, paid_time = ?, proof = ?, change = ? WHERE quote = ?",
            (
                quote.paid,
                quote.state.name,
                quote.fee_paid,
                db.timestamp_from_seconds(quote.paid_time),
                quote.payment_preimage,
                json.dumps([s.dict() for s in quote.change]) if quote.change else None,
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
            INSERT INTO {db.table_with_schema('keysets')}
            (id, seed, encrypted_seed, seed_encryption_method, derivation_path, valid_from, valid_to, first_seen, active, version, unit, input_fee_ppk)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                keyset.id,
                keyset.seed,
                keyset.encrypted_seed,
                keyset.seed_encryption_method,
                keyset.derivation_path,
                keyset.valid_from or db.timestamp_now_str(),
                keyset.valid_to or db.timestamp_now_str(),
                keyset.first_seen or db.timestamp_now_str(),
                True,
                keyset.version,
                keyset.unit.name,
                keyset.input_fee_ppk,
            ),
        )

    async def get_balance(
        self,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> int:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('balance')}
            """
        )
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
            SELECT * from {db.table_with_schema('keysets')}
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
            SELECT * from {db.table_with_schema('proofs_used')}
            WHERE y = ?
            """,
            (Y,),
        )
        return Proof(**row) if row else None
