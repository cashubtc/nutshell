import hashlib
from dataclasses import dataclass, field
from typing import Optional, Sequence

from ...core.db import POSTGRES, Database, LockOptions


@dataclass(frozen=True)
class ProofLockOptions(LockOptions):
    """Coordinate proof transitions using stable, ordered nullifier lock keys."""

    table: str = field(default="proofs_pending", init=False)
    timeout: Optional[float] = 1
    Ys: Sequence[str] = field(kw_only=True)

    def resolve(self, db: Database) -> Sequence[LockOptions]:
        if not self.Ys:
            return []
        if db.type != POSTGRES:
            return [LockOptions(table=self.table, timeout=self.timeout)]

        namespace = f"cashu:proofs:v1:{db.table_with_schema(self.table)}\0".encode()
        keys = {
            int.from_bytes(
                hashlib.sha256(namespace + bytes.fromhex(Y)).digest()[:8],
                "big",
                signed=True,
            )
            for Y in self.Ys
        }
        return [
            LockOptions(table=self.table, advisory_key=key, timeout=self.timeout)
            for key in sorted(keys)
        ]
