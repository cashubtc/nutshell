from .ledger import Ledger
from ..core.models import PostDlcRegistrationRequest, PostDlcRegistrationResponse
from ..core.base import DlcBadInput, DlcFundingProof, Proof, DLCWitness
from ..core.secret import Secret, SecretKind
from ..core.crypto.dlc import list_hash, merkle_verify
from ..core.errors import TransactionError
from ..core.nuts import DLC_NUT


from hashlib import sha256
from loguru import logger
from typing import List, Dict, Optional

class LedgerDLC(Ledger):

    async def _verify_dlc_input_spending_conditions(self, dlc_root: str, p: Proof) -> bool:
        if not p.witness:
            return False
        witness = DLCWitness.from_witness(p.witness)
        leaf_secret = Secret.deserialize(witness.leaf_secret)
        secret = Secret.deserialize(p.secret)
        # Verify secret is of kind SCT
        if secret.kind != SecretKind.SCT.value:
            return False
        # Verify leaf_secret is of kind DLC
        if leaf_secret.kind != SecretKind.DLC.value:
            return False
        # Verify dlc_root is the one referenced in the secret
        if leaf_secret.data != dlc_root:
            return False
        # (Optional?) Verify inclusion of leaf_secret in the SCT root hash
        leaf_hash_bytes = sha256(witness.leaf_secret.encode()).digest()
        merkle_proof_bytes = [bytes.fromhex(m) for m in witness.merkle_proof]
        sct_root_hash_bytes = bytes.fromhex(secret.data)
        if not merkle_verify(sct_root_hash_bytes, leaf_hash_bytes, merkle_proof_bytes):
            return False

        return True


    async def _verify_dlc_inputs(self, dlc_root: str, proofs: Optional[List[Proof]]):
        # Verify inputs
        if not proofs:
            raise TransactionError("no proofs provided.")
        # Verify amounts of inputs
        if not all([self._verify_amount(p.amount) for p in proofs]):
            raise TransactionError("invalid amount.")
        # Verify secret criteria
        if not all([self._verify_secret_criteria(p) for p in proofs]):
            raise TransactionError("secrets do not match criteria.")
        # verify that only unique proofs were used
        if not self._verify_no_duplicate_proofs(proofs):
            raise TransactionError("duplicate proofs.")
        # Verify ecash signatures
        if not all([self._verify_proof_bdhke(p) for p in proofs]):
            raise TransactionError("could not verify proofs.")
        # Verify input spending conditions
        if not all([self._verify_dlc_input_spending_conditions(dlc_root, p) for p in proofs]):
            raise TransactionError("validation of input spending conditions failed.")
    

    async def _verify_dlc_amount_fees_coverage(self, funding_amount: int, proofs: List[Proof]):
        # Verify proofs of the same denomination
        u = self.keysets[proofs[0].id].unit
        if not all([self.keysets[p.id].unit == u for p in proofs]):
            raise TransactionError("all the inputs must be of the same denomination")
        fees = self.mint_features()[DLC_NUT]
        assert isinstance(fees, dict)
        fees = fees['fees']
        assert isinstance(fees, dict)
        amount_provided = sum([p.amount for p in proofs])
        amount_needed = funding_amount + fees['base'] + (funding_amount * fees['ppk'] // 1000)
        if amount_needed < amount_provided:
            raise TransactionError("funds provided do not cover the DLC funding amount")

    # UNFINISHED
    async def register_dlc(self, request: PostDlcRegistrationRequest):
        logger.trace("swap called")
        is_atomic = request.atomic
        funded: List[DlcFundingProof] = []
        errors: List[DlcFundingProof] = []
        for registration in request.registrations:
            try:
                logger.trace(f"processing registration {registration.dlc_root}")
                await self._verify_dlc_inputs(registration.dlc_root, registration.inputs)
                assert registration.inputs is not None
                await self._verify_dlc_amount_fees_coverage(registration.funding_amount, registration.inputs)
                await self.db_write._verify_spent_proofs_and_set_pending(registration.inputs)
            except TransactionError as e:
                # I know this is horrificly out of spec -- I want to get it to work
                errors.append(DlcFundingProof(
                    dlc_root=registration.dlc_root,
                    bad_inputs=[DlcBadInput(
                        index=-1,
                        detail=e.detail
                    )]
                ))

