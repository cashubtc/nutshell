import secrets
from typing import Optional
from core.db import Connection, Database


async def store_promise(
    amount: int,
    B_x: str,
    B_y: str,
    C_x: str,
    C_y: str,
    db: Database,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        """
        INSERT INTO promises
          (amount, B_x, B_y, C_x, C_y)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            amount,
            str(B_x),
            str(B_y),
            str(C_x),
            str(C_y),
        ),
    )


async def get_proofs_used(
    db: Database,
    conn: Optional[Connection] = None,
):

    rows = await (conn or db).fetchall(
        """
        SELECT secret from proofs_used
        """
    )
    return [row[0] for row in rows]


async def invalidate_proof(
    proof: dict,
    db: Database,
    conn: Optional[Connection] = None,
):

    # we add the proof and secret to the used list
    await (conn or db).execute(
        """
        INSERT INTO proofs_used
          (amount, C_x, C_y, secret)
        VALUES (?, ?, ?, ?)
        """,
        (
            proof["amount"],
            str(proof["C"]["x"]),
            str(proof["C"]["y"]),
            str(proof["secret"]),
        ),
    )
