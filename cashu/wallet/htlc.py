import hashlib
from datetime import datetime, timedelta
from typing import List

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
        preimage: str | None = None,
        preimage_hash: str | None = None,
        hashlock_pubkeys: List[str] | None = None,
        hashlock_n_sigs: int | None = None,
        locktime_seconds: int | None = None,
        locktime_pubkeys: List[str] | None = None,
    ) -> HTLCSecret:
        tags = Tags()
        if locktime_seconds:
            tags["locktime"] = str(
                int((datetime.now() + timedelta(seconds=locktime_seconds)).timestamp())
            )
        if locktime_pubkeys:
            tags["refund"] = locktime_pubkeys

        if not preimage_hash and preimage:
            preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()

        assert preimage_hash, "preimage_hash or preimage must be provided"

        if hashlock_pubkeys:
            tags["pubkeys"] = hashlock_pubkeys

        if hashlock_n_sigs:
            tags["n_sigs"] = str(hashlock_n_sigs)

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
