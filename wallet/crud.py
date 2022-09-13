import secrets
from typing import Optional
from core.db import Connection, Database

# from wallet import db
from core.base import Proof


async def store_proof(
    proof: Proof,
    db: Database,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        """
        INSERT INTO proofs
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


async def invalidate_proof(
    proof: dict,
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
