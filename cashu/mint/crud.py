from typing import Any, List, Optional

from cashu.core.base import Invoice, MintKeyset, Proof
from cashu.core.db import Connection, Database
from cashu.core.migrations import table_with_schema


class LedgerCrud:
    """
    Database interface for Cashu mint.

    This class needs to be overloaded by any app that imports the Cashu mint.
    """

    async def get_keyset(*args, **kwags):

        return await get_keyset(*args, **kwags)

    async def get_lightning_invoice(*args, **kwags):

        return await get_lightning_invoice(*args, **kwags)

    async def get_proofs_used(*args, **kwags):

        return await get_proofs_used(*args, **kwags)

    async def invalidate_proof(*args, **kwags):

        return await invalidate_proof(*args, **kwags)

    async def store_keyset(*args, **kwags):

        return await store_keyset(*args, **kwags)

    async def store_lightning_invoice(*args, **kwags):

        return await store_lightning_invoice(*args, **kwags)

    async def store_promise(*args, **kwags):

        return await store_promise(*args, **kwags)

    async def update_lightning_invoice(*args, **kwags):

        return await update_lightning_invoice(*args, **kwags)


async def store_promise(
    db: Database,
    amount: int,
    B_: str,
    C_: str,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        f"""
        INSERT INTO {table_with_schema(db, 'promises')}
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
        f"""
        SELECT secret from {table_with_schema(db, 'proofs_used')}
        """
    )
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
    db: Database,
    invoice: Invoice,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        f"""
        INSERT INTO {table_with_schema(db, 'invoices')}
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
    db: Database,
    hash: str,
    conn: Optional[Connection] = None,
):

    row = await (conn or db).fetchone(
        f"""
        SELECT * from {table_with_schema(db, 'invoices')}
        WHERE hash = ?
        """,
        (hash,),
    )
    return Invoice.from_row(row)


async def update_lightning_invoice(
    db: Database,
    hash: str,
    issued: bool,
    conn: Optional[Connection] = None,
):
    await (conn or db).execute(
        f"UPDATE {table_with_schema(db, 'invoices')} SET issued = ? WHERE hash = ?",
        (
            issued,
            hash,
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
    id: str = None,
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
    return [MintKeyset.from_row(row) for row in rows]
