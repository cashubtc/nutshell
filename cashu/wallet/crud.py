import json
import time
from typing import Any, Dict, List, Optional, Tuple

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
        VALUES (:id, :amount, :C, :secret, :time_created, :derivation_path, :dleq, :mint_id, :melt_id)
        """,
        {
            "id": proof.id,
            "amount": proof.amount,
            "C": str(proof.C),
            "secret": str(proof.secret),
            "time_created": int(time.time()),
            "derivation_path": proof.derivation_path,
            "dleq": json.dumps(proof.dleq.model_dump()) if proof.dleq else "",
            "mint_id": proof.mint_id,
            "melt_id": proof.melt_id,
        },
    )


async def get_proofs(
    *,
    db: Database,
    id: Optional[str] = "",
    melt_id: str = "",
    mint_id: str = "",
    table: str = "proofs",
    conn: Optional[Connection] = None,
):
    clauses = []
    values: Dict[str, Any] = {}

    if id:
        clauses.append("id = :id")
        values["id"] = id
    if melt_id:
        clauses.append("melt_id = :melt_id")
        values["melt_id"] = melt_id
    if mint_id:
        clauses.append("mint_id = :mint_id")
        values["mint_id"] = mint_id
    where = ""
    if clauses:
        where = f"WHERE {' AND '.join(clauses)}"
    rows = await (conn or db).fetchall(
        f"""
        SELECT * from {table}
        {where}
        """,
        values,
    )
    return [Proof.from_dict(dict(r)) for r in rows] if rows else []


async def get_reserved_proofs(
    db: Database,
    conn: Optional[Connection] = None,
) -> List[Proof]:
    rows = await (conn or db).fetchall(
        """
        SELECT * from proofs
        WHERE reserved
        """
    )
    return [Proof.from_dict(dict(r)) for r in rows]


async def invalidate_proof(
    proof: Proof,
    db: Database,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        """
        DELETE FROM proofs
        WHERE secret = :secret
        """,
        {"secret": str(proof["secret"])},
    )

    await (conn or db).execute(
        """
        INSERT INTO proofs_used
          (amount, C, secret, time_used, id, derivation_path, mint_id, melt_id)
        VALUES (:amount, :C, :secret, :time_used, :id, :derivation_path, :mint_id, :melt_id)
        """,
        {
            "amount": proof.amount,
            "C": str(proof.C),
            "secret": str(proof.secret),
            "time_used": int(time.time()),
            "id": proof.id,
            "derivation_path": proof.derivation_path,
            "mint_id": proof.mint_id,
            "melt_id": proof.melt_id,
        },
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
    values: Dict[str, Any] = {}

    if reserved is not None:
        clauses.append("reserved = :reserved")
        values["reserved"] = reserved
        clauses.append("time_reserved = :time_reserved")
        values["time_reserved"] = int(time.time())

    if send_id is not None:
        clauses.append("send_id = :send_id")
        values["send_id"] = send_id

    if mint_id is not None:
        clauses.append("mint_id = :mint_id")
        values["mint_id"] = mint_id

    if melt_id is not None:
        clauses.append("melt_id = :melt_id")
        values["melt_id"] = melt_id

    await (conn or db).execute(  # type: ignore
        f"UPDATE proofs SET {', '.join(clauses)} WHERE secret = :secret",
        {**values, "secret": str(proof.secret)},
    )


async def secret_used(
    secret: str,
    db: Database,
    conn: Optional[Connection] = None,
) -> bool:
    rows = await (conn or db).fetchone(
        """
        SELECT * from proofs
        WHERE secret = :secret
        """,
        {"secret": secret},
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
          (id, mint_url, valid_from, valid_to, first_seen, active, public_keys, unit, input_fee_ppk)
        VALUES (:id, :mint_url, :valid_from, :valid_to, :first_seen, :active, :public_keys, :unit, :input_fee_ppk)
        """,
        {
            "id": keyset.id,
            "mint_url": mint_url or keyset.mint_url,
            "valid_from": keyset.valid_from or int(time.time()),
            "valid_to": keyset.valid_to or int(time.time()),
            "first_seen": keyset.first_seen or int(time.time()),
            "active": keyset.active,
            "public_keys": keyset.serialize(),
            "unit": keyset.unit.name,
            "input_fee_ppk": keyset.input_fee_ppk,
        },
    )


async def get_keysets(
    id: str = "",
    mint_url: Optional[str] = None,
    unit: Optional[str] = None,
    db: Optional[Database] = None,
    conn: Optional[Connection] = None,
) -> List[WalletKeyset]:
    clauses = []
    values: Dict[str, Any] = {}
    if id:
        clauses.append("id = :id")
        values["id"] = id
    if mint_url:
        clauses.append("mint_url = :mint_url")
        values["mint_url"] = mint_url
    if unit:
        clauses.append("unit = :unit")
        values["unit"] = unit
    where = ""
    if clauses:
        where = f"WHERE {' AND '.join(clauses)}"

    rows = await (conn or db).fetchall(  # type: ignore
        f"""
        SELECT * from keysets
        {where}
        """,
        values,
    )
    return [WalletKeyset.from_row(r) for r in rows]


async def update_keyset(
    keyset: WalletKeyset,
    db: Database,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        """
        UPDATE keysets
        SET active = :active
        WHERE id = :id
        """,
        {
            "active": keyset.active,
            "id": keyset.id,
        },
    )


async def store_lightning_invoice(
    db: Database,
    invoice: Invoice,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        """
        INSERT INTO invoices
          (amount, bolt11, id, payment_hash, preimage, paid, time_created, time_paid, out)
        VALUES (:amount, :bolt11, :id, :payment_hash, :preimage, :paid, :time_created, :time_paid, :out)
        """,
        {
            "amount": invoice.amount,
            "bolt11": invoice.bolt11,
            "id": invoice.id,
            "payment_hash": invoice.payment_hash,
            "preimage": invoice.preimage,
            "paid": invoice.paid,
            "time_created": invoice.time_created,
            "time_paid": invoice.time_paid,
            "out": invoice.out,
        },
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
    values: Dict[str, Any] = {}
    if id:
        clauses.append("id = :id")
        values["id"] = id
    if payment_hash:
        clauses.append("payment_hash = :payment_hash")
        values["payment_hash"] = payment_hash
    if out is not None:
        clauses.append("out = :out")
        values["out"] = out

    where = ""
    if clauses:
        where = f"WHERE {' AND '.join(clauses)}"
    query = f"""
        SELECT * from invoices
        {where}
        """
    row = await (conn or db).fetchone(
        query,
        values,
    )
    return Invoice(**row) if row else None


async def get_lightning_invoices(
    db: Database,
    paid: Optional[bool] = None,
    pending: Optional[bool] = None,
    conn: Optional[Connection] = None,
) -> List[Invoice]:
    clauses = []
    values: Dict[str, Any] = {}

    if paid is not None and not pending:
        clauses.append("paid = :paid")
        values["paid"] = paid

    if pending:
        clauses.append("paid = :paid")
        values["paid"] = False
        clauses.append("out = :out")
        values["out"] = False

    where = ""
    if clauses:
        where = f"WHERE {' AND '.join(clauses)}"

    rows = await (conn or db).fetchall(
        f"""
        SELECT * from invoices
        {where}
        """,
        values,
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
    values: Dict[str, Any] = {}
    clauses.append("paid = :paid")
    values["paid"] = paid

    if time_paid:
        clauses.append("time_paid = :time_paid")
        values["time_paid"] = time_paid
    if preimage:
        clauses.append("preimage = :preimage")
        values["preimage"] = preimage

    await (conn or db).execute(
        f"UPDATE invoices SET {', '.join(clauses)} WHERE id = :id",
        {**values, "id": id},
    )


async def bump_secret_derivation(
    db: Database,
    keyset_id: str,
    by: int = 1,
    skip: bool = False,
    conn: Optional[Connection] = None,
) -> int:
    rows = await (conn or db).fetchone(
        "SELECT counter from keysets WHERE id = :keyset_id", {"keyset_id": keyset_id}
    )
    # if no counter for this keyset, create one
    if not rows:
        await (conn or db).execute(
            "UPDATE keysets SET counter = :counter WHERE id = :keyset_id",
            {
                "counter": 0,
                "keyset_id": keyset_id,
            },
        )
        counter = 0
    else:
        counter = int(rows[0])

    if not skip:
        await (conn or db).execute(
            "UPDATE keysets SET counter = counter + :by WHERE id = :keyset_id",
            {"by": by, "keyset_id": keyset_id},
        )
    return counter


async def set_secret_derivation(
    db: Database,
    keyset_id: str,
    counter: int,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        "UPDATE keysets SET counter = :counter WHERE id = :keyset_id",
        {
            "counter": counter,
            "keyset_id": keyset_id,
        },
    )


async def set_nostr_last_check_timestamp(
    db: Database,
    timestamp: int,
    conn: Optional[Connection] = None,
) -> None:
    await (conn or db).execute(
        "UPDATE nostr SET last = :last WHERE type = :type",
        {"last": timestamp, "type": "dm"},
    )


async def get_nostr_last_check_timestamp(
    db: Database,
    conn: Optional[Connection] = None,
) -> Optional[int]:
    row = await (conn or db).fetchone(
        """
        SELECT last from nostr WHERE type = :type
        """,
        {"type": "dm"},
    )
    return row[0] if row else None


async def get_seed_and_mnemonic(
    db: Database,
    conn: Optional[Connection] = None,
) -> Optional[Tuple[str, str]]:
    row = await (conn or db).fetchone(
        """
        SELECT seed, mnemonic from seed
        """
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
        VALUES (:seed, :mnemonic)
        """,
        {
            "seed": seed,
            "mnemonic": mnemonic,
        },
    )
