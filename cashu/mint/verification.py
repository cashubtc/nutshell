from typing import List, Literal, Optional, Set, Union

from loguru import logger

from ..core.base import (
    BlindedMessage,
    BlindedSignature,
    MintKeyset,
    MintKeysets,
    Proof,
)
from ..core.crypto import b_dhke
from ..core.crypto.secp import PublicKey
from ..core.db import Database
from ..core.errors import (
    NoSecretInProofsError,
    NotAllowedError,
    SecretTooLongError,
    TokenAlreadySpentError,
    TransactionError,
)
from ..core.settings import settings
from ..mint.crud import LedgerCrud
from .conditions import LedgerSpendingConditions
from .protocols import SupportsDb, SupportsKeysets


class LedgerVerification(LedgerSpendingConditions, SupportsKeysets, SupportsDb):
    """Verification functions for the ledger."""

    keyset: MintKeyset
    keysets: MintKeysets
    secrets_used: Set[str] = set()
    crud: LedgerCrud
    db: Database

    async def verify_inputs_and_outputs(
        self, proofs: List[Proof], outputs: Optional[List[BlindedMessage]] = None
    ):
        """Checks all proofs and outputs for validity.

        Args:
            proofs (List[Proof]): List of proofs to check.
            outputs (Optional[List[BlindedMessage]], optional): List of outputs to check.
            Must be provided for /split but not for /melt. Defaults to None.

        Raises:
            Exception: Scripts did not validate.
            Exception: Criteria for provided secrets not met.
            Exception: Duplicate proofs provided.
            Exception: BDHKE verification failed.
        """
        # Verify inputs
        # Verify proofs are spendable
        spendable = await self._check_proofs_spendable(proofs)
        if not all(spendable):
            raise TokenAlreadySpentError()
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

        if not outputs:
            return

        # Verify input and output amounts
        self._verify_equation_balanced(proofs, outputs)

        # Verify outputs
        self._verify_outputs(outputs)

        # Verify inputs and outputs together
        if not self._verify_input_output_amounts(proofs, outputs):
            raise TransactionError("input amounts less than output.")
        # Verify output spending conditions
        if outputs and not self._verify_output_spending_conditions(proofs, outputs):
            raise TransactionError("validation of output spending conditions failed.")

    def _verify_outputs(self, outputs: List[BlindedMessage]):
        """Verify that the outputs are valid."""
        # Verify amounts of outputs
        if not all([self._verify_amount(o.amount) for o in outputs]):
            raise TransactionError("invalid amount.")
        # verify that only unique outputs were used
        if not self._verify_no_duplicate_outputs(outputs):
            raise TransactionError("duplicate outputs.")

    async def _check_proofs_spendable(self, proofs: List[Proof]) -> List[bool]:
        """Checks whether the proof was already spent."""
        spendable_states = []
        if settings.mint_cache_secrets:
            # check used secrets in memory
            for p in proofs:
                spendable_state = p.secret not in self.secrets_used
                spendable_states.append(spendable_state)
        else:
            # check used secrets in database
            async with self.db.connect() as conn:
                for p in proofs:
                    spendable_state = (
                        await self.crud.get_proof_used(db=self.db, proof=p, conn=conn)
                        is None
                    )
                    spendable_states.append(spendable_state)
        return spendable_states

    def _verify_secret_criteria(self, proof: Proof) -> Literal[True]:
        """Verifies that a secret is present and is not too long (DOS prevention)."""
        if proof.secret is None or proof.secret == "":
            raise NoSecretInProofsError()
        if len(proof.secret) > 512:
            raise SecretTooLongError()
        return True

    def _verify_proof_bdhke(self, proof: Proof):
        """Verifies that the proof of promise was issued by this ledger."""
        # if no keyset id is given in proof, assume the current one
        if not proof.id:
            private_key_amount = self.keyset.private_keys[proof.amount]
        else:
            assert proof.id in self.keysets.keysets, f"keyset {proof.id} unknown"
            logger.trace(
                f"Validating proof with keyset {self.keysets.keysets[proof.id].id}."
            )
            # use the appropriate active keyset for this proof.id
            private_key_amount = self.keysets.keysets[proof.id].private_keys[
                proof.amount
            ]

        C = PublicKey(bytes.fromhex(proof.C), raw=True)
        return b_dhke.verify(private_key_amount, C, proof.secret)

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
        logger.trace(f"Verifying amount {amount} is valid: {valid}")
        if not valid:
            raise NotAllowedError("invalid amount: " + str(amount))
        return amount

    def _verify_equation_balanced(
        self,
        proofs: List[Proof],
        outs: Union[List[BlindedSignature], List[BlindedMessage]],
    ) -> None:
        """Verify that Σinputs - Σoutputs = 0.
        Outputs can be BlindedSignature or BlindedMessage.
        """
        sum_inputs = sum(self._verify_amount(p.amount) for p in proofs)
        sum_outputs = sum(self._verify_amount(p.amount) for p in outs)
        assert sum_outputs - sum_inputs == 0, TransactionError(
            "inputs do not have same amount as outputs."
        )
