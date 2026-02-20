import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from ..core.base import (
    Amount,
    BlindedMessage,
    BlindedSignature,
    MeltQuote,
    MintBalanceLogEntry,
    MintKeyset,
    MintQuote,
    MintQuoteState,
    Proof,
    Unit,
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
        unit: str = "",
        derivation_path: str = "",
        seed: str = "",
        conn: Optional[Connection] = None,
    ) -> List[MintKeyset]: ...

    @abstractmethod
    async def get_proofs_used(
        self,
        *,
        Ys: List[str],
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]: ...

    @abstractmethod
    async def invalidate_proof(
        self,
        *,
        db: Database,
        proof: Proof,
        quote_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def get_all_melt_quotes_from_pending_proofs(
        self,
        *,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[MeltQuote]: ...

    @abstractmethod
    async def get_pending_proofs_for_quote(
        self,
        *,
        quote_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]: ...

    @abstractmethod
    async def get_proofs_pending(
        self,
        *,
        Ys: List[str],
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]: ...

    @abstractmethod
    async def set_proof_pending(
        self,
        *,
        db: Database,
        proof: Proof,
        quote_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def unset_proof_pending(
        self,
        *,
        proof: Proof,
        db: Database,
        conn: Optional[Connection] = None,
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
    async def update_keyset(
        self,
        *,
        db: Database,
        keyset: MintKeyset,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def bump_keyset_balance(
        self,
        *,
        db: Database,
        keyset: MintKeyset,
        amount: int,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def bump_keyset_fees_paid(
        self,
        *,
        db: Database,
        keyset: MintKeyset,
        amount: int,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def get_balance(
        self,
        keyset: MintKeyset,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Tuple[Amount, Amount]: ...

    @abstractmethod
    async def store_blinded_message(
        self,
        *,
        db: Database,
        amount: int,
        b_: str,
        id: str,
        mint_id: Optional[str] = None,
        melt_id: Optional[str] = None,
        swap_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def delete_blinded_messages_melt_id(
        self,
        *,
        db: Database,
        melt_id: str,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def update_blinded_message_signature(
        self,
        *,
        db: Database,
        amount: int,
        b_: str,
        c_: str,
        e: str = "",
        s: str = "",
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def get_blinded_messages_melt_id(
        self,
        *,
        db: Database,
        melt_id: str,
        conn: Optional[Connection] = None,
    ) -> List[BlindedMessage]: ...

    @abstractmethod
    async def get_blind_signatures_melt_id(
        self,
        *,
        db: Database,
        melt_id: str,
        conn: Optional[Connection] = None,
    ) -> List[BlindedSignature]: ...

    @abstractmethod
    async def get_blind_signature(
        self,
        *,
        db: Database,
        b_: str,
        conn: Optional[Connection] = None,
    ) -> Optional[BlindedSignature]: ...

    @abstractmethod
    async def get_outputs(
        self,
        *,
        db: Database,
        b_s: List[str],
        conn: Optional[Connection] = None,
    ) -> List[BlindedMessage]: ...

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
        quote_id: Optional[str] = None,
        checking_id: Optional[str] = None,
        request: Optional[str] = None,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MintQuote]: ...

    @abstractmethod
    async def get_mint_quotes(
        self,
        *,
        quote_ids: List[str],
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[MintQuote]: ...

    @abstractmethod
    async def get_mint_quote_by_request(
        self,
        *,
        request: str,
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

    @abstractmethod
    async def update_mint_quotes_state(
        self,
        *,
        quote_ids: List[str],
        state: MintQuoteState,
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
        quote_id: Optional[str] = None,
        checking_id: Optional[str] = None,
        request: Optional[str] = None,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MeltQuote]: ...

    @abstractmethod
    async def get_melt_quotes_by_checking_id(
        self,
        *,
        checking_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[MeltQuote]: ...

    @abstractmethod
    async def get_melt_quote_by_request(
        self,
        *,
        request: str,
        db: Database,
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

    @abstractmethod
    async def store_balance_log(
        self,
        backend_balance: Amount,
        keyset_balance: Amount,
        keyset_fees_paid: Amount,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None: ...

    @abstractmethod
    async def get_last_balance_log_entry(
        self,
        *,
        unit: Unit,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> MintBalanceLogEntry | None: ...


class LedgerCrudSqlite(LedgerCrud):
    """Implementation of LedgerCrud for sqlite.

    Args:
        LedgerCrud (ABC): Abstract base class for LedgerCrud.
    """

    async def store_blinded_message(
        self,
        *,
        db: Database,
        amount: int,
        b_: str,
        id: str,
        mint_id: Optional[str] = None,
        melt_id: Optional[str] = None,
        swap_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {db.table_with_schema('promises')}
            (amount, b_, id, created, mint_quote, melt_quote, swap_id)
            VALUES (:amount, :b_, :id, :created, :mint_quote, :melt_quote, :swap_id)
            """,
            {
                "amount": amount,
                "b_": b_,
                "id": id,
                "created": db.to_timestamp(db.timestamp_now_str()),
                "mint_quote": mint_id,
                "melt_quote": melt_id,
                "swap_id": swap_id,
            },
        )

    async def get_blinded_messages_melt_id(
        self,
        *,
        db: Database,
        melt_id: str,
        conn: Optional[Connection] = None,
    ) -> List[BlindedMessage]:
        rows = await (conn or db).fetchall(
            f"""
            SELECT * from {db.table_with_schema('promises')}
            WHERE melt_quote = :melt_id AND c_ IS NULL
            """,
            {"melt_id": melt_id},
        )
        return [BlindedMessage.from_row(r) for r in rows] if rows else []

    async def get_blind_signatures_melt_id(
        self,
        *,
        db: Database,
        melt_id: str,
        conn: Optional[Connection] = None,
    ) -> List[BlindedSignature]:
        rows = await (conn or db).fetchall(
            f"""
                SELECT * from {db.table_with_schema('promises')}
                WHERE melt_quote = :melt_id AND c_ IS NOT NULL
                """,
            {"melt_id": melt_id},
        )
        return [BlindedSignature.from_row(r) for r in rows] if rows else []  # type: ignore

    async def delete_blinded_messages_melt_id(
        self,
        *,
        db: Database,
        melt_id: str,
        conn: Optional[Connection] = None,
    ) -> None:
        """Deletes a blinded message (promise) that has not been signed yet (c_ is NULL) with the given quote ID."""
        await (conn or db).execute(
            f"""
            DELETE FROM {db.table_with_schema('promises')}
            WHERE melt_quote = :melt_id AND c_ IS NULL
            """,
            {
                "melt_id": melt_id,
            },
        )

    async def update_blinded_message_signature(
        self,
        *,
        db: Database,
        amount: int,
        b_: str,
        c_: str,
        e: str = "",
        s: str = "",
        conn: Optional[Connection] = None,
    ) -> None:
        existing = await (conn or db).fetchone(
            f"""
                SELECT * from {db.table_with_schema('promises')}
                WHERE b_ = :b_
                """,
            {"b_": str(b_)},
        )
        if existing is None:
            raise ValueError("blinded message does not exist")

        await (conn or db).execute(
            f"""
            UPDATE {db.table_with_schema('promises')}
            SET amount = :amount, c_ = :c_, dleq_e = :dleq_e, dleq_s = :dleq_s, signed_at = :signed_at
            WHERE b_ = :b_;
            """,
            {
                "b_": b_,
                "amount": amount,
                "c_": c_,
                "dleq_e": e,
                "dleq_s": s,
                "signed_at": db.to_timestamp(db.timestamp_now_str()),
            },
        )

    async def get_blind_signature(
        self,
        *,
        db: Database,
        b_: str,
        conn: Optional[Connection] = None,
    ) -> Optional[BlindedSignature]:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('promises')}
            WHERE b_ = :b_ AND c_ IS NOT NULL
            """,
            {"b_": str(b_)},
        )
        return BlindedSignature.from_row(row) if row else None  # type: ignore

    async def get_outputs(
        self,
        *,
        db: Database,
        b_s: List[str],
        conn: Optional[Connection] = None,
    ) -> List[BlindedMessage]:
        rows = await (conn or db).fetchall(
            f"""
            SELECT * from {db.table_with_schema('promises')}
            WHERE b_ IN ({','.join([f":b_{i}" for i in range(len(b_s))])})
            """,
            {f"b_{i}": b_s[i] for i in range(len(b_s))},
        )
        # could be unsigned (BlindedMessage) or signed (BlindedSignature), but BlindedMessage is a subclass of BlindedSignature
        return [BlindedMessage.from_row(r) for r in rows] if rows else []  # type: ignore

    async def invalidate_proof(
        self,
        *,
        db: Database,
        proof: Proof,
        quote_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {db.table_with_schema('proofs_used')}
            (amount, c, secret, y, id, witness, created, melt_quote)
            VALUES (:amount, :c, :secret, :y, :id, :witness, :created, :melt_quote)
            """,
            {
                "amount": proof.amount,
                "c": proof.C,
                "secret": proof.secret,
                "y": proof.Y,
                "id": proof.id,
                "witness": proof.witness,
                "created": db.to_timestamp(db.timestamp_now_str()),
                "melt_quote": quote_id,
            },
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
        return [MeltQuote.from_row(r) for r in rows]  # type: ignore

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
            WHERE melt_quote = :quote_id
            """,
            {"quote_id": quote_id},
        )
        return [Proof(**r) for r in rows]

    async def get_proofs_pending(
        self,
        *,
        Ys: List[str],
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        query = f"""
        SELECT * from {db.table_with_schema('proofs_pending')}
        WHERE y IN ({','.join([f":y_{i}" for i in range(len(Ys))])})
        """
        values = {f"y_{i}": Ys[i] for i in range(len(Ys))}
        rows = await (conn or db).fetchall(query, values)
        return [Proof(**r) for r in rows]

    async def set_proof_pending(
        self,
        *,
        db: Database,
        proof: Proof,
        quote_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {db.table_with_schema('proofs_pending')}
            (amount, c, secret, y, id, witness, created, melt_quote)
            VALUES (:amount, :c, :secret, :y, :id, :witness, :created, :melt_quote)
            """,
            {
                "amount": proof.amount,
                "c": proof.C,
                "secret": proof.secret,
                "y": proof.Y,
                "id": proof.id,
                "witness": proof.witness,
                "created": db.to_timestamp(db.timestamp_now_str()),
                "melt_quote": quote_id,
            },
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
            WHERE secret = :secret
            """,
            {"secret": proof.secret},
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
            (quote, method, request, checking_id, unit, amount, paid, issued, state, created_time, paid_time, pubkey)
            VALUES (:quote, :method, :request, :checking_id, :unit, :amount, :paid, :issued, :state, :created_time, :paid_time, :pubkey)
            """,
            {
                "quote": quote.quote,
                "method": quote.method,
                "request": quote.request,
                "checking_id": quote.checking_id,
                "unit": quote.unit,
                "amount": quote.amount,
                "paid": quote.paid,  # this is deprecated! we need to store it because we have a NOT NULL constraint | we could also remove the column but sqlite doesn't support that (we would have to make a new table)
                "issued": quote.issued,  # this is deprecated! we need to store it because we have a NOT NULL constraint | we could also remove the column but sqlite doesn't support that (we would have to make a new table)
                "state": quote.state.value,
                "created_time": db.to_timestamp(
                    db.timestamp_from_seconds(quote.created_time) or ""
                ),
                "paid_time": db.to_timestamp(
                    db.timestamp_from_seconds(quote.paid_time) or ""
                )
                if quote.paid_time
                else None,
                "pubkey": quote.pubkey or "",
            },
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
        values: Dict[str, Any] = {}
        if quote_id:
            clauses.append("quote = :quote_id")
            values["quote_id"] = quote_id
        if checking_id:
            clauses.append("checking_id = :checking_id")
            values["checking_id"] = checking_id
        if request:
            clauses.append("request = :request")
            values["request"] = request
        if not any(clauses):
            raise ValueError("No search criteria")
        where = f"WHERE {' AND '.join(clauses)}"
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('mint_quotes')}
            {where}
            """,
            values,
        )
        if row is None:
            return None
        return MintQuote.from_row(row) if row else None  # type: ignore

    async def get_mint_quotes(
        self,
        *,
        quote_ids: List[str],
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[MintQuote]:
        if not quote_ids:
            return []
        query = f"""
            SELECT * from {db.table_with_schema('mint_quotes')}
            WHERE quote IN ({','.join([f":quote_{i}" for i in range(len(quote_ids))])})
            """
        values = {f"quote_{i}": quote_ids[i] for i in range(len(quote_ids))}
        rows = await (conn or db).fetchall(query, values)
        if not rows:
            return []
        
        # Build a map and preserve order from request
        quote_map = {MintQuote.from_row(row).quote: MintQuote.from_row(row) for row in rows}
        return [quote_map[qid] for qid in quote_ids if qid in quote_map]

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
            WHERE request = :request
            """,
            {"request": request},
        )
        return MintQuote.from_row(row) if row else None  # type: ignore

    async def update_mint_quote(
        self,
        *,
        quote: MintQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"UPDATE {db.table_with_schema('mint_quotes')} SET state = :state, paid_time = :paid_time WHERE quote = :quote",
            {
                "state": quote.state.value,
                "paid_time": db.to_timestamp(
                    db.timestamp_from_seconds(quote.paid_time) or ""
                )
                if quote.paid_time
                else None,
                "quote": quote.quote,
            },
        )

    async def update_mint_quotes_state(
        self,
        *,
        quote_ids: List[str],
        state: MintQuoteState,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        if not quote_ids:
            return
        await (conn or db).execute(
            f"""
            UPDATE {db.table_with_schema('mint_quotes')}
            SET state = :state
            WHERE quote IN ({','.join([f":quote_{i}" for i in range(len(quote_ids))])})
            """,
            {
                "state": state.value,
                **{f"quote_{i}": quote_ids[i] for i in range(len(quote_ids))},
            },
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
            INSERT INTO {db.table_with_schema('melt_quotes')}
            (quote, method, request, checking_id, unit, amount, fee_reserve, state, paid, created_time, paid_time, fee_paid, proof, expiry)
            VALUES (:quote, :method, :request, :checking_id, :unit, :amount, :fee_reserve, :state, :paid, :created_time, :paid_time, :fee_paid, :proof, :expiry)
            """,
            {
                "quote": quote.quote,
                "method": quote.method,
                "request": quote.request,
                "checking_id": quote.checking_id,
                "unit": quote.unit,
                "amount": quote.amount,
                "fee_reserve": quote.fee_reserve or 0,
                "state": quote.state.value,
                "paid": quote.paid,  # this is deprecated! we need to store it because we have a NOT NULL constraint | we could also remove the column but sqlite doesn't support that (we would have to make a new table)
                "created_time": db.to_timestamp(
                    db.timestamp_from_seconds(quote.created_time) or ""
                ),
                "paid_time": db.to_timestamp(
                    db.timestamp_from_seconds(quote.paid_time) or ""
                )
                if quote.paid_time
                else None,
                "fee_paid": quote.fee_paid,
                "proof": quote.payment_preimage,
                "expiry": db.to_timestamp(
                    db.timestamp_from_seconds(quote.expiry) or ""
                ),
            },
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
        values: Dict[str, Any] = {}
        if quote_id:
            clauses.append("quote = :quote_id")
            values["quote_id"] = quote_id
        if checking_id:
            clauses.append("checking_id = :checking_id")
            values["checking_id"] = checking_id
        if request:
            clauses.append("request = :request")
            values["request"] = request
        if not any(clauses):
            raise ValueError("No search criteria")
        where = f"WHERE {' AND '.join(clauses)}"
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('melt_quotes')}
            {where}
            """,
            values,
        )

        change = None
        if row:
            change = await self.get_blind_signatures_melt_id(
                db=db, melt_id=row["quote"], conn=conn
            )

        return MeltQuote.from_row(row, change) if row else None  # type: ignore

    async def get_melt_quote_by_request(
        self,
        *,
        request: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Optional[MeltQuote]:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('melt_quotes')}
            WHERE request = :request
            """,
            {"request": request},
        )
        return MeltQuote.from_row(row) if row else None  # type: ignore

    async def update_melt_quote(
        self,
        *,
        quote: MeltQuote,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            UPDATE {db.table_with_schema('melt_quotes')} SET state = :state, fee_paid = :fee_paid, paid_time = :paid_time, proof = :proof, checking_id = :checking_id WHERE quote = :quote
            """,
            {
                "state": quote.state.value,
                "fee_paid": quote.fee_paid,
                "paid_time": db.to_timestamp(
                    db.timestamp_from_seconds(quote.paid_time) or ""
                )
                if quote.paid_time
                else None,
                "proof": quote.payment_preimage,
                "quote": quote.quote,
                "checking_id": quote.checking_id,
            },
        )

    async def store_keyset(
        self,
        *,
        db: Database,
        keyset: MintKeyset,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            INSERT INTO {db.table_with_schema('keysets')}
            (id, seed, encrypted_seed, seed_encryption_method, derivation_path, valid_from, valid_to, first_seen, active, version, unit, input_fee_ppk, amounts, balance)
            VALUES (:id, :seed, :encrypted_seed, :seed_encryption_method, :derivation_path, :valid_from, :valid_to, :first_seen, :active, :version, :unit, :input_fee_ppk, :amounts, :balance)
            """,
            {
                "id": keyset.id,
                "seed": keyset.seed,
                "encrypted_seed": keyset.encrypted_seed,
                "seed_encryption_method": keyset.seed_encryption_method,
                "derivation_path": keyset.derivation_path,
                "valid_from": db.to_timestamp(
                    keyset.valid_from or db.timestamp_now_str()
                ),
                "valid_to": db.to_timestamp(keyset.valid_to or db.timestamp_now_str()),
                "first_seen": db.to_timestamp(
                    keyset.first_seen or db.timestamp_now_str()
                ),
                "active": True,
                "version": keyset.version,
                "unit": keyset.unit.name,
                "input_fee_ppk": keyset.input_fee_ppk,
                "amounts": json.dumps(keyset.amounts),
                "balance": keyset.balance,
            },
        )

    async def bump_keyset_balance(
        self,
        *,
        db: Database,
        keyset: MintKeyset,
        amount: int,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            UPDATE {db.table_with_schema('keysets')}
            SET balance = balance + :amount
            WHERE id = :id
            """,
            {"amount": amount, "id": keyset.id},
        )

    async def bump_keyset_fees_paid(
        self,
        *,
        db: Database,
        keyset: MintKeyset,
        amount: int,
        conn: Optional[Connection] = None,
    ) -> None:
        await (conn or db).execute(
            f"""
            UPDATE {db.table_with_schema('keysets')}
            SET fees_paid = fees_paid + :amount
            WHERE id = :id
            """,
            {"amount": amount, "id": keyset.id},
        )

    async def get_balance(
        self,
        keyset: MintKeyset,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Tuple[Amount, Amount]:
        row = await (conn or db).fetchone(
            f"""
            SELECT balance, fees_paid FROM {db.table_with_schema('keysets')}
            WHERE id = :id
            """,
            {
                "id": keyset.id,
            },
        )

        if row is None:
            return Amount(keyset.unit, 0), Amount(keyset.unit, 0)

        return Amount(keyset.unit, int(row["balance"])), Amount(
            keyset.unit, int(row["fees_paid"])
        )

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
        values: Dict = {}
        if active is not None:
            clauses.append("active = :active")
            values["active"] = active
        if id is not None:
            clauses.append("id = :id")
            values["id"] = id
        if derivation_path is not None:
            clauses.append("derivation_path = :derivation_path")
            values["derivation_path"] = derivation_path
        if seed is not None:
            clauses.append("seed = :seed")
            values["seed"] = seed
        if unit is not None:
            clauses.append("unit = :unit")
            values["unit"] = unit
        where = ""
        if clauses:
            where = f"WHERE {' AND '.join(clauses)}"

        rows = await (conn or db).fetchall(  # type: ignore
            f"""
            SELECT * from {db.table_with_schema('keysets')}
            {where}
            """,
            values,
        )
        return [MintKeyset.from_row(row) for row in rows]  # type: ignore

    async def update_keyset(
        self,
        *,
        db: Database,
        keyset: MintKeyset,
        conn: Optional[Connection] = None,
    ) -> None:
        logger.debug(f"Updating keyset {keyset.id}, which has {keyset.active = }")
        await (conn or db).execute(
            f"""
            UPDATE {db.table_with_schema('keysets')}
            SET seed = :seed, encrypted_seed = :encrypted_seed, seed_encryption_method = :seed_encryption_method, derivation_path = :derivation_path, valid_from = :valid_from, valid_to = :valid_to, first_seen = :first_seen, active = :active, version = :version, unit = :unit, input_fee_ppk = :input_fee_ppk
            WHERE id = :id
            """,
            {
                "id": keyset.id,
                "seed": keyset.seed,
                "encrypted_seed": keyset.encrypted_seed,
                "seed_encryption_method": keyset.seed_encryption_method,
                "derivation_path": keyset.derivation_path,
                "valid_from": db.to_timestamp(
                    keyset.valid_from or db.timestamp_now_str()
                ),
                "valid_to": db.to_timestamp(keyset.valid_to or db.timestamp_now_str()),
                "first_seen": db.to_timestamp(
                    keyset.first_seen or db.timestamp_now_str()
                ),
                "active": keyset.active,
                "version": keyset.version,
                "unit": keyset.unit.name,
                "input_fee_ppk": keyset.input_fee_ppk,
                "balance": keyset.balance,
            },
        )

    async def get_proofs_used(
        self,
        *,
        Ys: List[str],
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[Proof]:
        query = f"""
        SELECT * from {db.table_with_schema('proofs_used')}
        WHERE y IN ({','.join([f":y_{i}" for i in range(len(Ys))])})
        """
        values = {f"y_{i}": Ys[i] for i in range(len(Ys))}
        rows = await (conn or db).fetchall(query, values)
        return [Proof(**r) for r in rows] if rows else []

    async def store_balance_log(
        self,
        backend_balance: Amount,
        keyset_balance: Amount,
        keyset_fees_paid: Amount,
        db: Database,
        conn: Optional[Connection] = None,
    ):
        if backend_balance.unit != keyset_balance.unit:
            raise ValueError("Units do not match")

        await (conn or db).execute(
            f"""
            INSERT INTO {db.table_with_schema('balance_log')}
            (unit, backend_balance, keyset_balance, keyset_fees_paid, time)
            VALUES (:unit, :backend_balance, :keyset_balance, :keyset_fees_paid, :time)
            """,
            {
                "unit": backend_balance.unit.name,
                "backend_balance": backend_balance.amount,
                "keyset_balance": keyset_balance.amount,
                "keyset_fees_paid": keyset_fees_paid.amount,
                "time": db.to_timestamp(db.timestamp_now_str()),
            },
        )

    async def get_last_balance_log_entry(
        self,
        *,
        unit: Unit,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> MintBalanceLogEntry | None:
        row = await (conn or db).fetchone(
            f"""
            SELECT * from {db.table_with_schema('balance_log')}
            WHERE unit = :unit
            ORDER BY time DESC
            LIMIT 1
            """,
            {"unit": unit.name},
        )

        return MintBalanceLogEntry.from_row(row) if row else None

    async def get_melt_quotes_by_checking_id(
        self,
        *,
        checking_id: str,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[MeltQuote]:
        results = await (conn or db).fetchall(
            f"""
            SELECT * FROM {db.table_with_schema('melt_quotes')}
            WHERE checking_id = :checking_id
            """,
            {"checking_id": checking_id},
        )
        return [MeltQuote.from_row(row) for row in results]  # type: ignore
