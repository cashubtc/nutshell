from typing import Any, List, Optional

from ..core.base import BlindedSignature, Invoice, MintKeyset, Proof
from ..core.db import Connection, Database, table_with_schema


class LedgerCrud:
    """
    Database interface for Cashu mint.

    This class needs to be overloaded by any app that imports the Cashu mint and wants
    to use their own database.
    """

    async def get_keyset(
        self,
        db: Database,
        id: str = "",
        derivation_path: str = "",
        conn: Optional[Connection] = None,
    ):
        return await get_keyset(
            db=db,
            id=id,
            derivation_path=derivation_path,
            conn=conn,
        )

    async def get_lightning_invoice(
        self,
        db: Database,
        id: str,
        conn: Optional[Connection] = None,
    ) -> Optional[Invoice]:
        return await get_lightning_invoice(
            db=db,
            id=id,
            conn=conn,
        )

    async def get_secrets_used(
        self,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> List[str]:
        return await get_secrets_used(
            db=db,
            conn=conn,
        )

    async def get_proof_used(
        self,
        db: Database,
        proof: Proof,
        conn: Optional[Connection] = None,
    ) -> Optional[Proof]:
        return await get_proof_used(
            db=db,
            proof=proof,
            conn=conn,
        )

    async def invalidate_proof(
        self,
        db: Database,
        proof: Proof,
        conn: Optional[Connection] = None,
    ):
        return await invalidate_proof(
            db=db,
            proof=proof,
            conn=conn,
        )

    async def get_proofs_pending(
        self,
        db: Database,
        conn: Optional[Connection] = None,
    ):
        return await get_proofs_pending(db=db, conn=conn)

    async def set_proof_pending(
        self,
        db: Database,
        proof: Proof,
        conn: Optional[Connection] = None,
    ):
        return await set_proof_pending(
            db=db,
            proof=proof,
            conn=conn,
        )

    async def unset_proof_pending(
        self, proof: Proof, db: Database, conn: Optional[Connection] = None
    ):
        return await unset_proof_pending(
            proof=proof,
            db=db,
            conn=conn,
        )

    async def store_keyset(
        self,
        db: Database,
        keyset: MintKeyset,
        conn: Optional[Connection] = None,
    ):
        return await store_keyset(
            db=db,
            keyset=keyset,
            conn=conn,
        )

    async def store_lightning_invoice(
        self,
        db: Database,
        invoice: Invoice,
        conn: Optional[Connection] = None,
    ):
        return await store_lightning_invoice(
            db=db,
            invoice=invoice,
            conn=conn,
        )

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
    ):
        return await store_promise(
            db=db,
            amount=amount,
            B_=B_,
            C_=C_,
            id=id,
            e=e,
            s=s,
            conn=conn,
        )

    async def get_promise(
        self,
        db: Database,
        B_: str,
        conn: Optional[Connection] = None,
    ):
        return await get_promise(
            db=db,
            B_=B_,
            conn=conn,
        )

    async def update_lightning_invoice(
        self,
        db: Database,
        id: str,
        issued: bool,
        conn: Optional[Connection] = None,
    ):
        return await update_lightning_invoice(
            db=db,
            id=id,
            issued=issued,
            conn=conn,
        )

    async def get_balance(
        self,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> int:
        return await get_balance(
            db=db,
            conn=conn,
        )


async def store_promise(
    *,
    db: Database,
    amount: int,
    B_: str,
    C_: str,
    id: str,
    e: str = "",
    s: str = "",
    conn: Optional[Connection] = None,
):
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
    db: Database,
    B_: str,
    conn: Optional[Connection] = None,
):
    row = await (conn or db).fetchone(
        f"""
        SELECT * from {table_with_schema(db, 'promises')}
        WHERE B_b = ?
        """,
        (str(B_),),
    )
    return BlindedSignature(amount=row[0], C_=row[2], id=row[3]) if row else None


async def get_secrets_used(
    db: Database,
    conn: Optional[Connection] = None,
) -> List[str]:
    rows = await (conn or db).fetchall(f"""
        SELECT secret from {table_with_schema(db, 'proofs_used')}
        """)
    return [row[0] for row in rows]


async def invalidate_proof(
    db: Database,
    proof: Proof,
    conn: Optional[Connection] = None,
):
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
    db: Database,
    conn: Optional[Connection] = None,
):
    rows = await (conn or db).fetchall(f"""
        SELECT * from {table_with_schema(db, 'proofs_pending')}
        """)
    return [Proof(**r) for r in rows]


async def get_proof_used(
    db: Database,
    proof: Proof,
    conn: Optional[Connection] = None,
) -> Optional[Proof]:
    row = await (conn or db).fetchone(
        f"""
        SELECT 1 from {table_with_schema(db, 'proofs_used')}
        WHERE secret = ?
        """,
        (str(proof.secret),),
    )
    return Proof(**row) if row else None


async def set_proof_pending(
    db: Database,
    proof: Proof,
    conn: Optional[Connection] = None,
):
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
    proof: Proof,
    db: Database,
    conn: Optional[Connection] = None,
):
    await (conn or db).execute(
        f"""
        DELETE FROM {table_with_schema(db, 'proofs_pending')}
        WHERE secret = ?
        """,
        (str(proof["secret"]),),
    )


async def store_lightning_invoice(
    db: Database,
    invoice: Invoice,
    conn: Optional[Connection] = None,
):
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
    db: Database,
    *,
    id: Optional[str] = None,
    payment_hash: Optional[str] = None,
    conn: Optional[Connection] = None,
):
    clauses = []
    values: List[Any] = []
    if id:
        clauses.append("id = ?")
        values.append(id)
    if payment_hash:
        clauses.append("payment_hash = ?")
        values.append(payment_hash)
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
    db: Database,
    id: str,
    issued: bool,
    conn: Optional[Connection] = None,
):
    await (conn or db).execute(
        f"UPDATE {table_with_schema(db, 'invoices')} SET issued = ? WHERE id = ?",
        (
            issued,
            id,
        ),
    )


async def store_keyset(
    db: Database,
    keyset: MintKeyset,
    conn: Optional[Connection] = None,
):
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
    db: Database,
    id: str = "",
    derivation_path: str = "",
    conn: Optional[Connection] = None,
):
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


async def get_balance(
    db: Database,
    conn: Optional[Connection] = None,
) -> int:
    row = await (conn or db).fetchone(f"""
        SELECT * from {table_with_schema(db, 'balance')}
        """)
    assert row, "Balance not found"
    return int(row[0])
