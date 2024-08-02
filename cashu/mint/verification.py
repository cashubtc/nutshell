from typing import Dict, List, Literal, Optional, Tuple, Union

import json

from loguru import logger
from hashlib import sha256

from ..core.base import (
    BlindedMessage,
    BlindedSignature,
    Method,
    MintKeyset,
    Proof,
    Unit,
    DlcBadInput,
    DLCWitness,
    DlcOutcome,
)
from ..core.crypto import b_dhke
from ..core.crypto.dlc import merkle_verify
from ..core.crypto.secp import PublicKey
from ..core.db import Connection, Database
from ..core.errors import (
    CashuError,
    NoSecretInProofsError,
    NotAllowedError,
    SecretTooLongError,
    TransactionError,
    TransactionUnitError,
    DlcVerificationFail,
    DlcSettlementFail,
)
from ..core.settings import settings
from ..lightning.base import LightningBackend
from ..mint.crud import LedgerCrud
from .conditions import LedgerSpendingConditions
from .db.read import DbReadHelper
from .db.write import DbWriteHelper
from .protocols import SupportsBackends, SupportsDb, SupportsKeysets
from .dlc import LedgerDLC
from ..core.secret import Secret, SecretKind
class LedgerVerification(
    LedgerSpendingConditions, LedgerDLC, SupportsKeysets, SupportsDb, SupportsBackends
):
    """Verification functions for the ledger."""

    keyset: MintKeyset
    keysets: Dict[str, MintKeyset]
    crud: LedgerCrud
    db: Database
    db_read: DbReadHelper
    db_write: DbWriteHelper
    lightning: Dict[Unit, LightningBackend]

    async def verify_inputs_and_outputs(
        self,
        *,
        proofs: List[Proof],
        outputs: Optional[List[BlindedMessage]] = None,
        conn: Optional[Connection] = None,
    ):
        """Checks all proofs and outputs for validity.

        Args:
            proofs (List[Proof]): List of proofs to check.
            outputs (Optional[List[BlindedMessage]], optional): List of outputs to check.
                Must be provided for a swap but not for a melt. Defaults to None.
            conn (Optional[Connection], optional): Database connection. Defaults to None.

        Raises:
            Exception: Scripts did not validate.
            Exception: Criteria for provided secrets not met.
            Exception: Duplicate proofs provided.
            Exception: BDHKE verification failed.
        """
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
        if not all([self._verify_input_spending_conditions(p) for p in proofs]):
            raise TransactionError("validation of input spending conditions failed.")

        if outputs is None:
            # If no outputs are provided, we are melting
            return

        # Verify input and output amounts
        self._verify_equation_balanced(proofs, outputs)

        # Verify outputs
        await self._verify_outputs(outputs, conn=conn)

        # Verify inputs and outputs together
        if not self._verify_input_output_amounts(proofs, outputs):
            raise TransactionError("input amounts less than output.")
        # Verify that input keyset units are the same as output keyset unit
        # We have previously verified that all outputs have the same keyset id in `_verify_outputs`
        assert outputs[0].id, "output id not set"
        if not all(
            [
                self.keysets[p.id].unit == self.keysets[outputs[0].id].unit
                for p in proofs
            ]
        ):
            raise TransactionError("input and output keysets have different units.")

        # Verify output spending conditions
        if outputs and not self._verify_output_spending_conditions(proofs, outputs):
            raise TransactionError("validation of output spending conditions failed.")

    async def _verify_outputs(
        self,
        outputs: List[BlindedMessage],
        skip_amount_check=False,
        conn: Optional[Connection] = None,
    ):
        """Verify that the outputs are valid."""
        logger.trace(f"Verifying {len(outputs)} outputs.")
        if not outputs:
            raise TransactionError("no outputs provided.")
        # Verify all outputs have the same keyset id
        if not all([o.id == outputs[0].id for o in outputs]):
            raise TransactionError("outputs have different keyset ids.")
        # Verify that the keyset id is known and active
        if outputs[0].id not in self.keysets:
            raise TransactionError("keyset id unknown.")
        if not self.keysets[outputs[0].id].active:
            raise TransactionError("keyset id inactive.")
        # Verify amounts of outputs
        # we skip the amount check for NUT-8 change outputs (which can have amount 0)
        if not skip_amount_check:
            if not all([self._verify_amount(o.amount) for o in outputs]):
                raise TransactionError("invalid amount.")
        # verify that only unique outputs were used
        if not self._verify_no_duplicate_outputs(outputs):
            raise TransactionError("duplicate outputs.")
        # verify that outputs have not been signed previously
        signed_before = await self._check_outputs_issued_before(outputs, conn)
        if any(signed_before):
            raise TransactionError("outputs have already been signed before.")
        logger.trace(f"Verified {len(outputs)} outputs.")

    async def _check_outputs_issued_before(
        self,
        outputs: List[BlindedMessage],
        conn: Optional[Connection] = None,
    ) -> List[bool]:
        """Checks whether the provided outputs have previously been signed by the mint
        (which would lead to a duplication error later when trying to store these outputs again).

        Args:
            outputs (List[BlindedMessage]): Outputs to check

        Returns:
            result (List[bool]): Whether outputs are already present in the database.
        """
        async with self.db.get_connection(conn) as conn:
            promises = await self.crud.get_promises(
                b_s=[output.B_ for output in outputs], db=self.db, conn=conn
            )
        return [True if promise else False for promise in promises]

    def _verify_secret_criteria(self, proof: Proof) -> Literal[True]:
        """Verifies that a secret is present and is not too long (DOS prevention)."""
        if proof.secret is None or proof.secret == "":
            raise NoSecretInProofsError()
        if len(proof.secret) > settings.mint_max_secret_length:
            raise SecretTooLongError(
                f"secret too long. max: {settings.mint_max_secret_length}"
            )
        return True

    def _verify_proof_bdhke(self, proof: Proof) -> bool:
        """Verifies that the proof of promise was issued by this ledger."""
        assert proof.id in self.keysets, f"keyset {proof.id} unknown"
        logger.trace(
            f"Validating proof {proof.secret} with keyset"
            f" {self.keysets[proof.id].id}."
        )
        # use the appropriate active keyset for this proof.id
        private_key_amount = self.keysets[proof.id].private_keys[proof.amount]

        C = PublicKey(bytes.fromhex(proof.C), raw=True)
        valid = b_dhke.verify(private_key_amount, C, proof.secret)
        if valid:
            logger.trace("Proof verified.")
        else:
            logger.trace(f"Proof verification failed for {proof.secret} – {proof.C}.")
        return valid

    def _verify_input_output_amounts(
        self, inputs: List[Proof], outputs: List[BlindedMessage]
    ) -> bool:
        """Verifies that inputs have at least the same amount as outputs"""
        input_amount = sum([p.amount for p in inputs])
        output_amount = sum([o.amount for o in outputs])
        return input_amount >= output_amount

    def _verify_no_duplicate_proofs(self, proofs: List[Proof]) -> bool:
        secrets = [p.secret for p in proofs]
        if len(secrets) != len(list(set(secrets))):
            return False
        return True

    def _verify_no_duplicate_outputs(self, outputs: List[BlindedMessage]) -> bool:
        B_s = [od.B_ for od in outputs]
        if len(B_s) != len(list(set(B_s))):
            return False
        return True

    def _verify_amount(self, amount: int) -> int:
        """Any amount used should be positive and not larger than 2^MAX_ORDER."""
        valid = amount > 0 and amount < 2**settings.max_order
        if not valid:
            raise NotAllowedError("invalid amount: " + str(amount))
        return amount

    def _verify_units_match(
        self,
        proofs: List[Proof],
        outs: Union[List[BlindedSignature], List[BlindedMessage]],
    ) -> Unit:
        """Verifies that the units of the inputs and outputs match."""
        units_proofs = [self.keysets[p.id].unit for p in proofs]
        units_outputs = [self.keysets[o.id].unit for o in outs if o.id]
        if not len(set(units_proofs)) == 1:
            raise TransactionUnitError("inputs have different units.")
        if not len(set(units_outputs)) == 1:
            raise TransactionUnitError("outputs have different units.")
        if not units_proofs[0] == units_outputs[0]:
            raise TransactionUnitError("input and output keysets have different units.")
        return units_proofs[0]

    def get_fees_for_proofs(self, proofs: List[Proof]) -> int:
        if not len(set([self.keysets[p.id].unit for p in proofs])) == 1:
            raise TransactionUnitError("inputs have different units.")
        fee = (sum([self.keysets[p.id].input_fee_ppk for p in proofs]) + 999) // 1000
        return fee

    def _verify_equation_balanced(
        self,
        proofs: List[Proof],
        outs: List[BlindedMessage],
    ) -> None:
        """Verify that Σinputs - Σoutputs = 0.
        Outputs can be BlindedSignature or BlindedMessage.
        """
        if not proofs:
            raise TransactionError("no proofs provided.")
        if not outs:
            raise TransactionError("no outputs provided.")

        _ = self._verify_units_match(proofs, outs)
        sum_inputs = sum(self._verify_amount(p.amount) for p in proofs)
        fees_inputs = self.get_fees_for_proofs(proofs)
        sum_outputs = sum(self._verify_amount(p.amount) for p in outs)
        if not sum_outputs + fees_inputs - sum_inputs == 0:
            raise TransactionError(
                f"inputs ({sum_inputs}) - fees ({fees_inputs}) vs outputs ({sum_outputs}) are not balanced."
            )

    def _verify_and_get_unit_method(
        self, unit_str: str, method_str: str
    ) -> Tuple[Unit, Method]:
        """Verify that the unit is supported by the ledger."""
        method = Method[method_str]
        unit = Unit[unit_str]

        if not any([unit == k.unit for k in self.keysets.values()]):
            raise NotAllowedError(f"unit '{unit.name}' not supported in any keyset.")

        if not self.backends.get(method) or unit not in self.backends[method]:
            raise NotAllowedError(
                f"no support for method '{method.name}' with unit '{unit.name}'."
            )

        return unit, method
    
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
        def raise_if_err(err):
            if len(err) > 0:
                logger.error("Failed to verify DLC inputs")
                raise DlcVerificationFail(bad_inputs=err)
        sct_proofs, _ = await self.filter_sct_proofs(proofs)
        dlc_witnesses = [DLCWitness.from_witness(p.witness or "") for p in sct_proofs]
        dlc_secrets = [Secret.deserialize(w.leaf_secret) for w in dlc_witnesses]
        errors = []
        for i, s in enumerate(dlc_secrets):
            if s.tags.get_tag('threshold') is not None:
                threshold = None
                try:
                    threshold = int(s.tags.get_tag('threshold'))
                except Exception:
                    pass
                if threshold is not None and funding_amount < threshold:
                    errors.append(DlcBadInput(
                        index=i,
                        detail="Threshold amount not respected"
                    ))
        raise_if_err(errors)
    
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

    async def _verify_dlc_payout(self, P: str):
        try:
            payout = json.loads(P)
            if not isinstance(payout, dict):
                raise DlcSettlementFail(detail="Provided payout structure is not a dictionary")
            if not all([isinstance(k, str) and isinstance(v, int) for k, v in payout.items()]):
                raise DlcSettlementFail(detail="Provided payout structure is not a dictionary mapping strings to integers")
            for v in payout.values():
                try:
                    b = bytes.fromhex(v)
                    if b[0] != b'\x02':
                        raise DlcSettlementFail(detail="Provided payout structure contains incorrect public keys")
                except ValueError as e:
                    raise DlcSettlementFail(detail=str(e))
        except json.JSONDecodeError as e:
            raise DlcSettlementFail(detail="cannot decode the provided payout structure")

    async def _verify_dlc_inclusion(self, dlc_root: str, outcome: DlcOutcome, merkle_proof: List[str]):
        # Verify payout structure
        await self._verify_dlc_payout(outcome.P)
