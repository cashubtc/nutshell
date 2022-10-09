from typing import Optional

from cashu.core.base import Invoice, MintKeyset, Proof
from cashu.core.db import Connection, Database


async def store_promise(
    amount: int,
    B_: str,
    C_: str,
    db: Database,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        """
        INSERT INTO promises
          (amount, B_b, C_b)
        VALUES (?, ?, ?)
        """,
        (
            amount,
            str(B_),
            str(C_),
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
    proof: Proof,
    db: Database,
    conn: Optional[Connection] = None,
):

    # we add the proof and secret to the used list
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


async def store_lightning_invoice(
    invoice: Invoice,
    db: Database,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        """
        INSERT INTO invoices
          (amount, pr, hash, issued)
        VALUES (?, ?, ?, ?)
        """,
        (
            invoice.amount,
            invoice.pr,
            invoice.hash,
            invoice.issued,
        ),
    )


async def get_lightning_invoice(
    hash: str,
    db: Database,
    conn: Optional[Connection] = None,
):

    row = await (conn or db).fetchone(
        """
        SELECT * from invoices
        WHERE hash = ?
        """,
        (hash,),
    )
    return Invoice.from_row(row)


async def update_lightning_invoice(
    hash: str,
    issued: bool,
    db: Database,
    conn: Optional[Connection] = None,
):
    await (conn or db).execute(
        "UPDATE invoices SET issued = ? WHERE hash = ?",
        (
            issued,
            hash,
        ),
    )


async def store_keyset(
    keyset: MintKeyset,
    mint_url: str = None,
    db: Database = None,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        """
        INSERT INTO keysets
          (id, derivation_path, valid_from, valid_to, first_seen, active)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            keyset.id,
            keyset.derivation_path,
            keyset.valid_from,
            keyset.valid_to,
            keyset.first_seen,
            True,
        ),
    )


async def get_keyset(
    id: str = None,
    derivation_path: str = None,
    db: Database = None,
    conn: Optional[Connection] = None,
):
    clauses = []
    values = []
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

    rows = await (conn or db).fetchall(
        f"""
        SELECT * from keysets
        {where}
        """,
        tuple(values),
    )
    return [MintKeyset.from_row(row) for row in rows]
