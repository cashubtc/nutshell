import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..core.base import (
    Amount,
    BlindedSignature,
    MeltQuote,
    MintBalanceLogEntry,
    MintKeyset,
    MintQuote,
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
    async def get_balance(
        self,
        keyset: MintKeyset,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Amount: ...

    @abstractmethod
    async def get_unit_balance(
        self,
        unit: Unit,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Amount: ...

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
    ) -> None: ...

    @abstractmethod
    async def get_promise(
        self,
        *,
        db: Database,
        b_: str,
        conn: Optional[Connection] = None,
    ) -> Optional[BlindedSignature]: ...

    @abstractmethod
    async def get_promises(
        self,
        *,
        db: Database,
        b_s: List[str],
        conn: Optional[Connection] = None,
    ) -> List[BlindedSignature]: ...

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
        mint_balance: Amount,
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
            VALUES (:amount, :b_, :c_, :dleq_e, :dleq_s, :id, :created)
            """,
            {
                "amount": amount,
                "b_": b_,
                "c_": c_,
                "dleq_e": e,
                "dleq_s": s,
                "id": id,
                "created": db.to_timestamp(db.timestamp_now_str()),
            },
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
            WHERE b_ = :b_
            """,
            {"b_": str(b_)},
        )
        return BlindedSignature.from_row(row) if row else None  # type: ignore

    async def get_promises(
        self,
        *,
        db: Database,
        b_s: List[str],
        conn: Optional[Connection] = None,
    ) -> List[BlindedSignature]:
        rows = await (conn or db).fetchall(
            f"""
            SELECT * from {db.table_with_schema('promises')}
            WHERE b_ IN ({','.join([f":b_{i}" for i in range(len(b_s))])})
            """,
            {f"b_{i}": b_s[i] for i in range(len(b_s))},
        )
        return [BlindedSignature.from_row(r) for r in rows] if rows else []  # type: ignore

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
                ),
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
                ),
                "quote": quote.quote,
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
            (quote, method, request, checking_id, unit, amount, fee_reserve, state, paid, created_time, paid_time, fee_paid, proof, outputs, change, expiry)
            VALUES (:quote, :method, :request, :checking_id, :unit, :amount, :fee_reserve, :state, :paid, :created_time, :paid_time, :fee_paid, :proof, :outputs, :change, :expiry)
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
                ),
                "fee_paid": quote.fee_paid,
                "proof": quote.payment_preimage,
                "outputs": json.dumps(quote.outputs) if quote.outputs else None,
                "change": json.dumps(quote.change) if quote.change else None,
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
        return MeltQuote.from_row(row) if row else None  # type: ignore

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
            UPDATE {db.table_with_schema('melt_quotes')} SET state = :state, fee_paid = :fee_paid, paid_time = :paid_time, proof = :proof, outputs = :outputs, change = :change, checking_id = :checking_id WHERE quote = :quote
            """,
            {
                "state": quote.state.value,
                "fee_paid": quote.fee_paid,
                "paid_time": db.to_timestamp(
                    db.timestamp_from_seconds(quote.paid_time) or ""
                ),
                "proof": quote.payment_preimage,
                "outputs": (
                    json.dumps([s.dict() for s in quote.outputs])
                    if quote.outputs
                    else None
                ),
                "change": (
                    json.dumps([s.dict() for s in quote.change])
                    if quote.change
                    else None
                ),
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
            (id, seed, encrypted_seed, seed_encryption_method, derivation_path, valid_from, valid_to, first_seen, active, version, unit, input_fee_ppk, amounts)
            VALUES (:id, :seed, :encrypted_seed, :seed_encryption_method, :derivation_path, :valid_from, :valid_to, :first_seen, :active, :version, :unit, :input_fee_ppk, :amounts)
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
            },
        )

    async def get_balance(
        self,
        keyset: MintKeyset,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Amount:
        row = await (conn or db).fetchone(
            f"""
            SELECT balance FROM {db.table_with_schema('balance')}
            WHERE keyset = :keyset
            """,
            {
                "keyset": keyset.id,
            },
        )

        if row is None:
            return Amount(keyset.unit, 0)

        # sqlalchemy index of first element
        key = next(iter(row))
        return Amount(keyset.unit, int(row[key]))

    async def get_unit_balance(
        self,
        unit: Unit,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Amount:
        keysets = await self.get_keyset(db=db, unit=unit.name, conn=conn)
        balance = Amount(unit, 0)
        for keyset in keysets:
            balance += await self.get_balance(keyset, db=db, conn=conn)

        return balance

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
        mint_balance: Amount,
        db: Database,
        conn: Optional[Connection] = None,
    ):
        if backend_balance.unit != mint_balance.unit:
            raise ValueError("Units do not match")

        await (conn or db).execute(
            f"""
            INSERT INTO {db.table_with_schema('balance_log')}
            (unit, backend_balance, mint_balance, time)
            VALUES (:unit, :backend_balance, :mint_balance, :time)
            """,
            {
                "unit": backend_balance.unit.name,
                "backend_balance": backend_balance.amount,
                "mint_balance": mint_balance.amount,
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
