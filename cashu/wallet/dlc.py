from ..core.secret import Secret
from ..core.crypto.secp import PrivateKey
from ..core.crypto.dlc import list_hash, merkle_root
from ..core.base import Proof, DLCWitness
from .protocols import SupportsDb, SupportsPrivateKey
from loguru import logger
from typing import List, Optional

class DLCSecret:
    secret: str
    blinding_factor: PrivateKey
    derivation_path: str
    all_spending_conditions: Optional[List[str]]

    def __init__(self, **kwargs):
        self.secret = kwargs['secret']
        self.blinding_factor = kwargs['blinding_factor']
        self.derivation_path = kwargs['derivation_path']
        self.all_spending_conditions = kwargs['all_spending_conditions']

class WalletSCT(SupportsPrivateKey, SupportsDb):
    # ---------- SCT ----------

    async def add_sct_witnesses_to_proofs(
        self,
        proofs: List[Proof]
    ) -> List[Proof]:
        """Add SCT witness data to proofs"""
        logger.debug(f"Unlocking {len(proofs)} proofs locked to DLC root {proofs[0].dlc_root}")
        for p in proofs:
            all_spending_conditions = p.all_spending_conditions
            assert all_spending_conditions is not None, "add_sct_witnesses_to_proof: What the duck is going on here"
            leaf_hashes = list_hash(all_spending_conditions)
            # We are assuming the backup secret is the last (and second) entry
            merkle_root_bytes, merkle_proof_bytes = merkle_root(
                leaf_hashes,
                len(leaf_hashes)-1,
            )
            # If this check fails we are in deep trouble
            assert merkle_proof_bytes is not None, "add_sct_witnesses_to_proof: What the duck is going on here"
            assert merkle_root_bytes.hex() == Secret.deserialize(p.secret).data, "add_sct_witnesses_to_proof: What the duck is going on here"
            backup_secret = all_spending_conditions[-1]
            p.witness = DLCWitness(
                leaf_secret=backup_secret,
                merkle_proof=[m.hex() for m in merkle_proof_bytes]
            ).json()
        return proofs