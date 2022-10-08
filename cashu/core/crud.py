from typing import Optional

from cashu.core.base import KeyBase, Keyset
from cashu.core.db import Connection, Database


async def store_keyset(
    keyset: Keyset,
    mint_url: str,
    db: Database,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        """
        INSERT INTO keysets
          (id, mint_url, valid_from, valid_to, first_seen, active)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            keyset.id,
            mint_url,
            keyset.valid_from,
            keyset.valid_to,
            keyset.first_seen,
            True,
        ),
    )


async def get_keyset(
    id: str = None,
    mint_url: str = None,
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
    if mint_url:
        clauses.append("mint_url = ?")
        values.append(mint_url)
    where = ""
    if clauses:
        where = f"WHERE {' AND '.join(clauses)}"

    row = await (conn or db).fetchone(
        f"""
        SELECT * from keysets
        {where}
        """,
        tuple(values),
    )
    return Keyset.from_row(row)


async def store_mint_pubkey(
    key: KeyBase,
    db: Database,
    conn: Optional[Connection] = None,
):

    await (conn or db).execute(
        """
        INSERT INTO mint_pubkeys
          (id, amount, pubkey)
        VALUES (?, ?, ?)
        """,
        (key.id, key.amount, key.pubkey),
    )
