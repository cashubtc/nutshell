import json
import time
from typing import Any, List, Optional, Tuple

from ..core.base import Invoice, Proof, WalletKeyset
from ..core.db import Connection, Database


async def store_proof(
    proof: Proof,
    db: Database,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        """
        INSERT INTO proofs
          (id, amount, C, secret, time_created, derivation_path, dleq, mint_id, melt_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            proof.id,
            proof.amount,
            str(proof.C),
            str(proof.secret),
            int(time.time()),
            proof.derivation_path,
            json.dumps(proof.dleq.dict()) if proof.dleq else "",
            proof.mint_id,
            proof.melt_id,
        ),
    )


async def get_proofs(
    *,
    db: Database,
    melt_id: str = "",
    mint_id: str = "",
    table: str = "proofs",
    conn: Optional[Connection] = None,
):
    clauses = []
    values: List[Any] = []

    if melt_id:
        clauses.append("melt_id = ?")
        values.append(melt_id)
    if mint_id:
        clauses.append("mint_id = ?")
        values.append(mint_id)
    where = ""
    if clauses:
        where = f"WHERE {' AND '.join(clauses)}"
    rows = (
        await (conn or db).fetchall(
            f"""
            SELECT * from {table}
            {where}
            """,
            tuple(values),
        ),
    )
    return [Proof.from_dict(dict(r)) for r in rows[0]] if rows else []


async def get_reserved_proofs(
    db: Database,
    conn: Optional[Connection] = None,
) -> List[Proof]:
    rows = await (conn or db).fetchall("""
        SELECT * from proofs
        WHERE reserved
        """)
    return [Proof.from_dict(dict(r)) for r in rows]


async def invalidate_proof(
    proof: Proof,
    db: Database,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        """
        DELETE FROM proofs
        WHERE secret = ?
        """,
        (str(proof["secret"]),),
    )

    await (conn or db).execute(
        """
        INSERT INTO proofs_used
          (amount, C, secret, time_used, id, derivation_path, mint_id, melt_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            proof.amount,
            str(proof.C),
            str(proof.secret),
            int(time.time()),
            proof.id,
            proof.derivation_path,
            proof.mint_id,
            proof.melt_id,
        ),
    )


async def update_proof(
    proof: Proof,
    *,
    reserved: Optional[bool] = None,
    send_id: Optional[str] = None,
    mint_id: Optional[str] = None,
    melt_id: Optional[str] = None,
    db: Optional[Database] = None,
    conn: Optional[Connection] = None,
) -> None:
    clauses = []
    values: List[Any] = []
    clauses.append("reserved = ?")
    values.append(reserved)

    if send_id is not None:
        clauses.append("send_id = ?")
        values.append(send_id)

    if reserved is not None:
        clauses.append("time_reserved = ?")
        values.append(int(time.time()))

    if mint_id is not None:
        clauses.append("mint_id = ?")
        values.append(mint_id)

    if melt_id is not None:
        clauses.append("melt_id = ?")
        values.append(melt_id)

    await (conn or db).execute(  # type: ignore
        f"UPDATE proofs SET {', '.join(clauses)} WHERE secret = ?",
        (*values, str(proof.secret)),
    )


async def secret_used(
    secret: str,
    db: Database,
    conn: Optional[Connection] = None,
) -> bool:
    rows = await (conn or db).fetchone(
        """
        SELECT * from proofs
        WHERE secret = ?
        """,
        (secret,),
    )
    return rows is not None


async def store_keyset(
    keyset: WalletKeyset,
    mint_url: str = "",
    db: Optional[Database] = None,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(  # type: ignore
        """
        INSERT INTO keysets
          (id, mint_url, valid_from, valid_to, first_seen, active, public_keys, unit)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            keyset.id,
            mint_url or keyset.mint_url,
            keyset.valid_from or int(time.time()),
            keyset.valid_to or int(time.time()),
            keyset.first_seen or int(time.time()),
            keyset.active,
            keyset.serialize(),
            keyset.unit.name,
        ),
    )


async def get_keysets(
    id: str = "",
    mint_url: str = "",
    db: Optional[Database] = None,
    conn: Optional[Connection] = None,
) -> List[WalletKeyset]:
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

    row = await (conn or db).fetchall(  # type: ignore
        f"""
        SELECT * from keysets
        {where}
        """,
        tuple(values),
    )
    ret = []
    for r in row:
        keyset = WalletKeyset.from_row(r)
        ret.append(keyset)
    return ret


async def store_lightning_invoice(
    db: Database,
    invoice: Invoice,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        """
        INSERT INTO invoices
          (amount, bolt11, id, payment_hash, preimage, paid, time_created, time_paid, out)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            invoice.amount,
            invoice.bolt11,
            invoice.id,
            invoice.payment_hash,
            invoice.preimage,
            invoice.paid,
            invoice.time_created,
            invoice.time_paid,
            invoice.out,
        ),
    )


async def get_lightning_invoice(
    *,
    db: Database,
    id: str = "",
    payment_hash: str = "",
    out: Optional[bool] = None,
    conn: Optional[Connection] = None,
) -> Optional[Invoice]:
    clauses = []
    values: List[Any] = []
    if id:
        clauses.append("id = ?")
        values.append(id)
    if payment_hash:
        clauses.append("payment_hash = ?")
        values.append(payment_hash)
    if out is not None:
        clauses.append("out = ?")
        values.append(out)

    where = ""
    if clauses:
        where = f"WHERE {' AND '.join(clauses)}"
    query = f"""
        SELECT * from invoices
        {where}
        """
    row = await (conn or db).fetchone(
        query,
        tuple(values),
    )
    return Invoice(**row) if row else None


async def get_lightning_invoices(
    db: Database,
    paid: Optional[bool] = None,
    conn: Optional[Connection] = None,
) -> List[Invoice]:
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
    id: str,
    paid: bool,
    time_paid: Optional[int] = None,
    preimage: Optional[str] = None,
    conn: Optional[Connection] = None,
) -> None:
    clauses = []
    values: List[Any] = []
    clauses.append("paid = ?")
    values.append(paid)

    if time_paid:
        clauses.append("time_paid = ?")
        values.append(time_paid)
    if preimage:
        clauses.append("preimage = ?")
        values.append(preimage)

    await (conn or db).execute(
        f"UPDATE invoices SET {', '.join(clauses)} WHERE id = ?",
        (
            *values,
            id,
        ),
    )


async def bump_secret_derivation(
    db: Database,
    keyset_id: str,
    by: int = 1,
    skip: bool = False,
    conn: Optional[Connection] = None,
) -> int:
    rows = await (conn or db).fetchone(
        "SELECT counter from keysets WHERE id = ?", (keyset_id,)
    )
    # if no counter for this keyset, create one
    if not rows:
        await (conn or db).execute(
            "UPDATE keysets SET counter = ? WHERE id = ?",
            (
                0,
                keyset_id,
            ),
        )
        counter = 0
    else:
        counter = int(rows[0])

    if not skip:
        await (conn or db).execute(
            f"UPDATE keysets SET counter = counter + {by} WHERE id = ?",
            (keyset_id,),
        )
    return counter


async def set_secret_derivation(
    db: Database,
    keyset_id: str,
    counter: int,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        "UPDATE keysets SET counter = ? WHERE id = ?",
        (
            counter,
            keyset_id,
        ),
    )


async def set_nostr_last_check_timestamp(
    db: Database,
    timestamp: int,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        "UPDATE nostr SET last = ? WHERE type = ?",
        (timestamp, "dm"),
    )


async def get_nostr_last_check_timestamp(
    db: Database,
    conn: Optional[Connection] = None,
) -> Optional[int]:
    row = await (conn or db).fetchone(
        """
        SELECT last from nostr WHERE type = ?
        """,
        ("dm",),
    )
    return row[0] if row else None


async def get_seed_and_mnemonic(
    db: Database,
    conn: Optional[Connection] = None,
) -> Optional[Tuple[str, str]]:
    row = await (conn or db).fetchone(
        """
        SELECT seed, mnemonic from seed
        """,
    )
    return (
        (
            row[0],
            row[1],
        )
        if row
        else None
    )


async def store_seed_and_mnemonic(
    db: Database,
    seed: str,
    mnemonic: str,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        """
        INSERT INTO seed
          (seed, mnemonic)
        VALUES (?, ?)
        """,
        (
            seed,
            mnemonic,
        ),
    )
