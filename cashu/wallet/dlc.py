from ..core.secret import Secret, SecretKind
from ..core.crypto.secp import PrivateKey
from ..core.crypto.dlc import list_hash, merkle_root
from ..core.base import Proof, DLCWitness
from .protocols import SupportsDb, SupportsPrivateKey
from loguru import logger
from typing import List, Optional

class SecretMetadata:
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

    async def _add_sct_witnesses_to_proofs(self, proofs: List[Proof], backup: bool = False) -> List[Proof]:
        """Adds witnesses to proofs.

        This method parses the secret of each proof and determines the correct
        witness type and adds it to the proof if we have it available.

        Args:
            proofs (List[Proof]): List of proofs to add witnesses to
            backup (bool): use the backup secret for the leaf secret in the witness
        Returns:
            List[Proof]: List of proofs with witnesses added
        """

        # iterate through proofs and produce witnesses for each

        # first we check whether all tokens have serialized secrets as their secret
        try:
            for p in proofs:
                Secret.deserialize(p.secret)
        except Exception:
            # if not, we do not add witnesses (treat as regular token secret)
            return proofs
        logger.debug("Spending conditions detected.")
        if all(
            [Secret.deserialize(p.secret).kind == SecretKind.SCT.value for p in proofs]
        ):
            logger.debug("DLC redemption detected")
            proofs = await self.add_sct_witnesses_to_proofs(proofs=proofs, backup=backup)

        return proofs

    async def add_sct_witnesses_to_proofs(
        self,
        proofs: List[Proof],
        backup: bool = False,
    ) -> List[Proof]:
        """Add SCT witness data to proofs"""
        logger.trace(f"Unlocking {len(proofs)} proofs locked to DLC root {proofs[0].dlc_root}")
        for p in proofs:
            all_spending_conditions = p.all_spending_conditions
            assert all_spending_conditions is not None, "add_sct_witnesses_to_proof: What the duck is going on here"
            leaf_hashes = list_hash(all_spending_conditions)
            # We are assuming the backup secret is the last (and second) entry
            merkle_root_bytes, merkle_proof_bytes = merkle_root(
                leaf_hashes,
                len(leaf_hashes)-1 if backup else 0,
            )
            # If this check fails we are in deep trouble
            assert merkle_proof_bytes is not None, "add_sct_witnesses_to_proof: What the duck is going on here"
            assert merkle_root_bytes.hex() == Secret.deserialize(p.secret).data, "add_sct_witnesses_to_proof: What the duck is going on here"
            leaf_secret = all_spending_conditions[-1] if backup else all_spending_conditions[0]
            p.witness = DLCWitness(
                leaf_secret=leaf_secret,
                merkle_proof=[m.hex() for m in merkle_proof_bytes]
            ).json()
        return proofs
    
    async def filter_proofs_by_dlc_root(self, dlc_root: str, proofs: List[Proof]) -> List[Proof]:
        """Returns a list of proofs each having DLC root equal to `dlc_root`
        """
        return list(filter(lambda p: p.dlc_root == dlc_root, proofs))
    
    async def filter_non_dlc_proofs(self, proofs: List[Proof]) -> List[Proof]:
        return list(filter(lambda p: p.dlc_root is None or p.dlc_root == "", proofs))