import secrets
from typing import Optional

from core.base import Proof
from core.db import Connection, Database


async def store_proof(
    proof: Proof,
    db: Database,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        """
        INSERT INTO proofs
          (amount, C, secret)
        VALUES (?, ?, ?)
        """,
        (
            proof.amount,
            str(proof.C),
            str(proof.secret),
        ),
    )


async def get_proofs(
    db: Database,
    conn: Optional[Connection] = None,
):

    rows = await (conn or db).fetchall(
        """
        SELECT * from proofs
        """
    )
    return [Proof.from_row(r) for r in rows]


async def get_reserved_proofs(
    db: Database,
    conn: Optional[Connection] = None,
):

    rows = await (conn or db).fetchall(
        """
        SELECT * from proofs
        WHERE reserved
        """
    )
    return [Proof.from_row(r) for r in rows]


async def invalidate_proof(
    proof: Proof,
    db: Database,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        f"""
        DELETE FROM proofs
        WHERE secret = ?
        """,
        str(proof["secret"]),
    )

    await (conn or db).execute(
        """
        INSERT INTO proofs_used
          (amount, C, secret)
        VALUES (?, ?, ?)
        """,
        (
            proof.amount,
            str(proof.C),
            str(proof.secret),
        ),
    )


async def update_proof_reserved(
    proof: Proof,
    reserved: bool,
    db: Database,
    conn: Optional[Connection] = None,
):
    await (conn or db).execute(
        "UPDATE proofs SET reserved = ? WHERE secret = ?",
        (reserved, str(proof.secret)),
    )
