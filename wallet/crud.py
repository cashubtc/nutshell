import time
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
          (amount, C, secret, time_created)
        VALUES (?, ?, ?, ?)
        """,
        (proof.amount, str(proof.C), str(proof.secret), int(time.time())),
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
          (amount, C, secret, time_used)
        VALUES (?, ?, ?, ?)
        """,
        (proof.amount, str(proof.C), str(proof.secret), int(time.time())),
    )


async def update_proof_reserved(
    proof: Proof,
    reserved: bool,
    send_id: str = None,
    db: Database = None,
    conn: Optional[Connection] = None,
):
    clauses = []
    values = []
    clauses.append("reserved = ?")
    values.append(reserved)

    if send_id:
        clauses.append("send_id = ?")
        values.append(send_id)

    if reserved:
        # set the time of reserving
        clauses.append("time_reserved = ?")
        values.append(int(time.time()))

    await (conn or db).execute(
        f"UPDATE proofs SET {', '.join(clauses)} WHERE secret = ?",
        (*values, str(proof.secret)),
    )
