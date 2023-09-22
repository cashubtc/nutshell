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
        preimage: Optional[str] = None,
        preimage_hash: Optional[str] = None,
        hacklock_pubkey: Optional[str] = None,
        locktime_seconds: Optional[int] = None,
        timelock_pubkey: Optional[str] = None,
    ) -> HTLCSecret:
        tags = Tags()
        if locktime_seconds:
            tags["locktime"] = str(
                int((datetime.now() + timedelta(seconds=locktime_seconds)).timestamp())
            )
        if timelock_pubkey:
            tags["pubkeys"] = timelock_pubkey

        if not preimage_hash and preimage:
            preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()

        assert preimage_hash, "preimage_hash or preimage must be provided"

        if hacklock_pubkey:
            tags["refund"] = hacklock_pubkey

        return HTLCSecret(
            kind=SecretKind.HTLC,
            data=preimage_hash,
            tags=tags,
        )

    async def add_htlc_preimage_to_proofs(
        self, proofs: List[Proof], preimage: str
    ) -> List[Proof]:
        for p, s in zip(proofs, preimage):
            p.htlcpreimage = s
        return proofs
