import hashlib
from datetime import datetime, timedelta
from typing import List, Optional

from ..core.base import HTLCWitness, Proof
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
        *,
        preimage: Optional[str] = None,
        preimage_hash: Optional[str] = None,
        hashlock_pubkey: Optional[str] = None,
        locktime_seconds: Optional[int] = None,
        locktime_pubkey: Optional[str] = None,
    ) -> HTLCSecret:
        tags = Tags()
        if locktime_seconds:
            tags["locktime"] = str(
                int((datetime.now() + timedelta(seconds=locktime_seconds)).timestamp())
            )
        if locktime_pubkey:
            tags["refund"] = locktime_pubkey

        if not preimage_hash and preimage:
            preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()

        assert preimage_hash, "preimage_hash or preimage must be provided"

        if hashlock_pubkey:
            tags["pubkeys"] = hashlock_pubkey

        return HTLCSecret(
            kind=SecretKind.HTLC.value,
            data=preimage_hash,
            tags=tags,
        )

    async def add_htlc_preimage_to_proofs(
        self, proofs: List[Proof], preimage: str
    ) -> List[Proof]:
        for p in proofs:
            p.witness = HTLCWitness(preimage=preimage).json()
        return proofs
