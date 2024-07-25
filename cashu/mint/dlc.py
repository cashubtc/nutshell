from .ledger import Ledger
from ..core.models import PostDlcRegistrationRequest, PostDlcRegistrationResponse
from ..core.base import DlcBadInput, DlcFundingProof, Proof, DLCWitness, Unit
from ..core.secret import Secret, SecretKind
from ..core.crypto.dlc import merkle_verify
from ..core.errors import (
    TransactionError,
    DlcVerificationFail,
    NotAllowedError,
    NoSecretInProofsError,
    SecretTooLongError,
    CashuError,
)
from ..core.nuts import DLC_NUT


from hashlib import sha256
from loguru import logger
from typing import List, Dict, Optional, Tuple

class LedgerDLC(Ledger):

    async def filter_sct_proofs(self, proofs: List[Proof]) -> Tuple[List[Proof], List[Proof]]:
        sct_proofs = list(filter(lambda p: Secret.deserialize(p.secret).kind == SecretKind.SCT.value, proofs))
        non_sct_proofs = list(filter(lambda p: p not in sct_proofs, proofs))
        return (sct_proofs, non_sct_proofs)

    def _verify_dlc_input_spending_conditions(self, dlc_root: str, p: Proof) -> bool:
        if not p.witness:
            return False
        try:
            witness = DLCWitness.from_witness(p.witness)
            leaf_secret = Secret.deserialize(witness.leaf_secret)
            secret = Secret.deserialize(p.secret)
        except Exception as e:
            return False
        # Verify leaf_secret is of kind DLC
        if leaf_secret.kind != SecretKind.DLC.value:
            return False
        # Verify dlc_root is the one referenced in the secret
        if leaf_secret.data != dlc_root:
            return False
        # Verify inclusion of leaf_secret in the SCT root hash
        leaf_hash_bytes = sha256(witness.leaf_secret.encode()).digest()
        merkle_proof_bytes = [bytes.fromhex(m) for m in witness.merkle_proof]
        sct_root_hash_bytes = bytes.fromhex(secret.data)
        if not merkle_verify(sct_root_hash_bytes, leaf_hash_bytes, merkle_proof_bytes):
            return False

        return True


    async def _verify_dlc_inputs(
        self,
        dlc_root: str,
        proofs: List[Proof],
    ):
        """
            Verifies all inputs to the DLC
            
            Args:
                dlc_root (hex str): root of the DLC contract
                proofs: (List[Proof]): proofs to be verified

            Raises:
                DlcVerificationFail   
        """
        # After we have collected all of the errors
        # We use this to raise a DlcVerificationFail
        def raise_if_err(err):
            if len(err) > 0:
                logger.error("Failed to verify DLC inputs")
                raise DlcVerificationFail(bad_inputs=err)
        
        # We cannot just raise an exception if one proof fails and call it a day
        # for every proof we need to collect its index and motivation of failure
        # and report them

        # Verify inputs
        if not proofs:
            raise TransactionError("no proofs provided.")

        errors = []
        # Verify amounts of inputs
        for i, p in enumerate(proofs):
            try:
                self._verify_amount(p.amount)
            except NotAllowedError as e:
                errors.append(DlcBadInput(
                    index=i,
                    detail=e.detail
                ))
        raise_if_err(errors)

        # Verify secret criteria
        for i, p in enumerate(proofs):
            try:
                self._verify_secret_criteria(p)
            except (SecretTooLongError, NoSecretInProofsError) as e:
                errors.append(DlcBadInput(
                    index=i,
                    detail=e.detail
                ))
        raise_if_err(errors)

        # verify that only unique proofs were used
        if not self._verify_no_duplicate_proofs(proofs):
            raise TransactionError("duplicate proofs.")

        # Verify ecash signatures
        for i, p in enumerate(proofs):
            valid = False
            exc = None
            try:
                # _verify_proof_bdhke can also raise an AssertionError...
                assert self._verify_proof_bdhke(p), "invalid e-cash signature"
            except AssertionError as e:
                errors.append(DlcBadInput(
                    index=i,
                    detail=str(e)
                ))   
        raise_if_err(errors)

        # Verify proofs of the same denomination
        # REASONING: proofs could be usd, eur. We don't want mixed stuff.
        u = self.keysets[proofs[0].id].unit
        for i, p in enumerate(proofs):
            if self.keysets[p.id].unit != u:
                errors.append(DlcBadInput(
                    index=i,
                    detail="all the inputs must be of the same denomination"
                ))
        raise_if_err(errors)

        # Split SCT and non-SCT
        # REASONING: the submitter of the registration does not need to dlc lock their proofs
        sct_proofs, non_sct_proofs = await self.filter_sct_proofs(proofs)
        # Verify spending conditions
        for i, p in enumerate(sct_proofs):
            # _verify_dlc_input_spending_conditions does not raise any error
            # it handles all of them and return either true or false. ALWAYS.
            if not self._verify_dlc_input_spending_conditions(dlc_root, p):
                errors.append(DlcBadInput(
                    index=i,
                    detail="dlc input spending conditions verification failed"
                )) 
        for i, p in enumerate(non_sct_proofs):
            valid = False
            exc = None
            try:
                valid = self._verify_input_spending_conditions(p)
            except CashuError as e:
                exc = e
            if not valid:
                errors.append(DlcBadInput(
                    index=i,
                    detail=exc.detail if exc else "input spending conditions verification failed" 
                ))
        raise_if_err(errors)
        
                
    async def get_dlc_fees(self, fa_unit: str) -> Dict[str, int]:
        try:
            fees = self.mint_features()[DLC_NUT]
            assert isinstance(fees, dict)
            fees = fees['fees']
            assert isinstance(fees, dict)
            fees = fees[fa_unit]
            assert isinstance(fees, dict)
            return fees
        except Exception as e:
            raise TransactionError("could not get fees for the specified funding_amount denomination")

    async def _verify_dlc_amount_fees_coverage(
        self,
        funding_amount: int,
        fa_unit: str,
        proofs: List[Proof],
    ) -> int:
        """
            Verifies the sum of the inputs is enough to cover
            the funding amount + fees
            
            Args:
                funding_amount (int): funding amount of the contract
                fa_unit (str): ONE OF ('sat', 'msat', 'eur', 'usd', 'btc'). The unit in which funding_amount
                    should be evaluated.
                proofs: (List[Proof]): proofs to be verified

            Returns:
                (int): amount provided by the proofs

            Raises:
                TransactionError
                     
        """
        u = self.keysets[proofs[0].id].unit
        # Verify registration's funding_amount unit is the same as the proofs
        if Unit[fa_unit] != u:
            raise TransactionError("funding amount unit is not the same as the proofs")
        fees = await self.get_dlc_fees(fa_unit)
        amount_provided = sum([p.amount for p in proofs])
        amount_needed = funding_amount + fees['base'] + (funding_amount * fees['ppk'] // 1000)
        if amount_provided < amount_needed:
            raise TransactionError("funds provided do not cover the DLC funding amount")
        return amount_provided

    async def _verify_dlc_amount_threshold(self, funding_amount: int, proofs: List[Proof]):
        """For every SCT proof verify that secret's threshold is less or equal to
            the funding_amount
        """
        sct_proofs, _ = await self.filter_sct_proofs(proofs)
        sct_secrets = [Secret.deserialize(p.secret) for p in sct_proofs]
        if not all([int(s.tags.get_tag('threshold')) <= funding_amount for s in sct_secrets]):
            raise TransactionError("Some inputs' funding thresholds were not met")

    # UNFINISHED
    async def register_dlc(self, request: PostDlcRegistrationRequest):
        logger.trace("register called")
        is_atomic = request.atomic
        funded: List[DlcFundingProof] = []
        errors: List[DlcFundingProof] = []
        for registration in request.registrations:
            try:
                logger.trace(f"processing registration {registration.dlc_root}")
                assert registration.inputs is not None # mypy give me a break
                await self._verify_dlc_inputs(registration.dlc_root, registration.inputs)
                amount_provided = await self._verify_dlc_amount_fees_coverage(
                    registration.funding_amount,
                    registration.unit,
                    registration.inputs
                )
                await self._verify_dlc_amount_threshold(amount_provided, registration.inputs)
                # Some flavour of this function: we need to insert a check inside the db lock
                # to verify there isn't some other contract with the same dlc root.
                # await self.db_write._verify_spent_proofs_and_set_pending(registration.inputs)
            except (TransactionError, DlcVerificationFail) as e:
                logger.error(f"registration {registration.dlc_root} failed")
                # Generic Error
                if isinstance(e, TransactionError):
                    errors.append(DlcFundingProof(
                        dlc_root=registration.dlc_root,
                        bad_inputs=[DlcBadInput(
                            index=-1,
                            detail=e.detail
                        )]
                    ))
                # DLC verification fail
                else:
                    errors.append(DlcFundingProof(
                        dlc_root=registration.dlc_root,
                        bad_inputs=e.bad_inputs,
                    ))

