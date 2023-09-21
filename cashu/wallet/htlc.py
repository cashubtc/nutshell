import hashlib
from datetime import datetime, timedelta
from typing import List, Optional

from ..core import bolt11 as bolt11
from ..core.base import (
    Proof,
)
from ..core.db import Database
from ..core.htlc import (
    HTLCSecret,
)
from ..core.secret import SecretKind, Tags
from .protocols import SupportsDb


class WalletHTLC(SupportsDb):
    db: Database

    async def create_htlc_lock(
        self,
        preimage: str,
        locktime_seconds: Optional[int] = None,
    ) -> HTLCSecret:
        tags = Tags()
        if locktime_seconds:
            tags["locktime"] = str(
                int((datetime.now() + timedelta(seconds=locktime_seconds)).timestamp())
            )
        periamge_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
        return HTLCSecret(
            kind=SecretKind.HTLC,
            data=periamge_hash,
            tags=tags,
        )

    async def add_htlc_preimage_to_proofs(
        self, proofs: List[Proof], preimage: str
    ) -> List[Proof]:
        for p, s in zip(proofs, preimage):
            p.htlcpreimage = s
        return proofs
