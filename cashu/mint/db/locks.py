import hashlib
from typing import List, Optional, Sequence

from ...core.db import POSTGRES, Database, LockOptions


def proof_locks(
    db: Database, Ys: Sequence[str], *, timeout: Optional[float] = 1
) -> List[LockOptions]:
    """Coordinate proof transitions using stable, ordered nullifier lock keys."""
    if not Ys:
        return []
    if db.type != POSTGRES:
        return [LockOptions(table="proofs_pending", timeout=timeout)]

    namespace = f"cashu:proofs:v1:{db.table_with_schema('proofs_pending')}\0".encode()
    keys = {
        int.from_bytes(
            hashlib.sha256(namespace + bytes.fromhex(Y)).digest()[:8],
            "big",
            signed=True,
        )
        for Y in Ys
    }
    return [
        LockOptions(table="proofs_pending", advisory_key=key, timeout=timeout)
        for key in sorted(keys)
    ]
