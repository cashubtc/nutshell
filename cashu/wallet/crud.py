import json
import time
from typing import Any, List, Optional

from ..core.base import Invoice, KeyBase, P2SHScript, Proof, WalletKeyset
from ..core.db import Connection, Database


async def store_proof(
    proof: Proof,
    db: Database,
    conn: Optional[Connection] = None,
):
    await (conn or db).execute(
        """
        INSERT INTO proofs
          (id, amount, C, secret, time_created)
        VALUES (?, ?, ?, ?, ?)
        """,
        (proof.id, proof.amount, str(proof.C), str(proof.secret), int(time.time())),
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
    return [Proof(**dict(r)) for r in rows]


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
    return [Proof(**r) for r in rows]


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
        (str(proof["secret"]),),
    )

    await (conn or db).execute(
        """
        INSERT INTO proofs_used
          (amount, C, secret, time_used, id)
        VALUES (?, ?, ?, ?, ?)
        """,
        (proof.amount, str(proof.C), str(proof.secret), int(time.time()), proof.id),
    )


async def update_proof_reserved(
    proof: Proof,
    reserved: bool,
    send_id: str = "",
    db: Optional[Database] = None,
    conn: Optional[Connection] = None,
):
    clauses = []
    values: List[Any] = []
    clauses.append("reserved = ?")
    values.append(reserved)

    if send_id:
        clauses.append("send_id = ?")
        values.append(send_id)

    if reserved:
        # set the time of reserving
        clauses.append("time_reserved = ?")
        values.append(int(time.time()))

    await (conn or db).execute(  # type: ignore
        f"UPDATE proofs SET {', '.join(clauses)} WHERE secret = ?",
        (*values, str(proof.secret)),
    )


async def secret_used(
    secret: str,
    db: Database,
    conn: Optional[Connection] = None,
):
    rows = await (conn or db).fetchone(
        """
        SELECT * from proofs
        WHERE secret = ?
        """,
        (secret,),
    )
    return rows is not None


async def store_p2sh(
    p2sh: P2SHScript,
    db: Database,
    conn: Optional[Connection] = None,
):
    await (conn or db).execute(
        """
        INSERT INTO p2sh
          (address, script, signature, used)
        VALUES (?, ?, ?, ?)
        """,
        (
            p2sh.address,
            p2sh.script,
            p2sh.signature,
            False,
        ),
    )


async def get_unused_locks(
    address: str = "",
    db: Optional[Database] = None,
    conn: Optional[Connection] = None,
):
    clause: List[str] = []
    args: List[str] = []

    clause.append("used = 0")

    if address:
        clause.append("address = ?")
        args.append(address)

    where = ""
    if clause:
        where = f"WHERE {' AND '.join(clause)}"

    rows = await (conn or db).fetchall(  # type: ignore
        f"""
        SELECT * from p2sh
        {where}
        """,
        tuple(args),
    )
    return [P2SHScript(**r) for r in rows]


async def update_p2sh_used(
    p2sh: P2SHScript,
    used: bool,
    db: Optional[Database] = None,
    conn: Optional[Connection] = None,
):
    clauses = []
    values = []
    clauses.append("used = ?")
    values.append(used)

    await (conn or db).execute(  # type: ignore
        f"UPDATE proofs SET {', '.join(clauses)} WHERE address = ?",
        (*values, str(p2sh.address)),
    )


async def store_keyset(
    keyset: WalletKeyset,
    mint_url: str = "",
    db: Optional[Database] = None,
    conn: Optional[Connection] = None,
):
    await (conn or db).execute(  # type: ignore
        """
        INSERT INTO keysets
          (id, mint_url, valid_from, valid_to, first_seen, active, public_keys)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            keyset.id,
            mint_url or keyset.mint_url,
            keyset.valid_from or int(time.time()),
            keyset.valid_to or int(time.time()),
            keyset.first_seen or int(time.time()),
            True,
            keyset.serialize(),
        ),
    )


async def get_keyset(
    id: str = "",
    mint_url: str = "",
    db: Optional[Database] = None,
    conn: Optional[Connection] = None,
):
    clauses = []
    values: List[Any] = []
    clauses.append("active = ?")
    values.append(True)
    if id:
        clauses.append("id = ?")
        values.append(id)
    if mint_url:
        clauses.append("mint_url = ?")
        values.append(mint_url)
    where = ""
    if clauses:
        where = f"WHERE {' AND '.join(clauses)}"

    row = await (conn or db).fetchone(  # type: ignore
        f"""
        SELECT * from keysets
        {where}
        """,
        tuple(values),
    )
    return WalletKeyset.from_row(row) if row is not None else None


async def store_lightning_invoice(
    db: Database,
    invoice: Invoice,
    conn: Optional[Connection] = None,
):
    await (conn or db).execute(
        f"""
        INSERT INTO invoices
          (amount, pr, hash, preimage, paid, time_created, time_paid)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            invoice.amount,
            invoice.pr,
            invoice.hash,
            invoice.preimage,
            invoice.paid,
            invoice.time_created,
            invoice.time_paid,
        ),
    )


async def get_lightning_invoice(
    db: Database,
    hash: str = "",
    conn: Optional[Connection] = None,
):
    clauses = []
    values: List[Any] = []
    if hash:
        clauses.append("hash = ?")
        values.append(hash)

    where = ""
    if clauses:
        where = f"WHERE {' AND '.join(clauses)}"

    row = await (conn or db).fetchone(
        f"""
        SELECT * from invoices
        {where}
        """,
        tuple(values),
    )
    return Invoice(**row)


async def get_lightning_invoices(
    db: Database,
    paid: Optional[bool] = None,
    conn: Optional[Connection] = None,
):
    clauses: List[Any] = []
    values: List[Any] = []

    if paid is not None:
        clauses.append("paid = ?")
        values.append(paid)

    where = ""
    if clauses:
        where = f"WHERE {' AND '.join(clauses)}"

    rows = await (conn or db).fetchall(
        f"""
        SELECT * from invoices
        {where}
        """,
        tuple(values),
    )
    return [Invoice(**r) for r in rows]


async def update_lightning_invoice(
    db: Database,
    hash: str,
    paid: bool,
    time_paid: Optional[int] = None,
    conn: Optional[Connection] = None,
):
    clauses = []
    values: List[Any] = []
    clauses.append("paid = ?")
    values.append(paid)

    if time_paid:
        clauses.append("time_paid = ?")
        values.append(time_paid)

    await (conn or db).execute(
        f"UPDATE invoices SET {', '.join(clauses)} WHERE hash = ?",
        (
            *values,
            hash,
        ),
    )


async def set_nostr_last_check_timestamp(
    db: Database,
    timestamp: int,
    conn: Optional[Connection] = None,
):
    await (conn or db).execute(
        f"UPDATE nostr SET last = ? WHERE type = ?",
        (timestamp, "dm"),
    )


async def get_nostr_last_check_timestamp(
    db: Database,
    conn: Optional[Connection] = None,
):
    row = await (conn or db).fetchone(
        f"""
        SELECT last from nostr WHERE type = ?
        """,
        ("dm",),
    )
    return row[0] if row else None
