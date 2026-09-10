from typing import List, Literal, Optional, Tuple, Union

from coincurve import PublicKeyXOnly
from loguru import logger

from ..core.base import (
    BlindedMessage,
    BlindedSignature,
    MeltQuote,
    Method,
    MintQuote,
    Proof,
    Unit,
)
from ..core.crypto import b_dhke
from ..core.crypto.bls import PublicKey as BlsPublicKey
from ..core.crypto.bls_dhke import keyed_verification
from ..core.crypto.keys import PublicKey, is_bls_keyset
from ..core.crypto.nutroot import (
    NUTROOT_MAX_WITNESS_LENGTH,
    NutrootWitness,
    is_nutroot_point_secret,
    keyset_id_transcript_bytes,
    secret_transcript_bytes,
    verify_script_path_spend,
)
from ..core.crypto.secp import PublicKey as SecpPublicKey
from ..core.crypto.transcript import (
    TransactionShape,
    TranscriptBlindedOutput,
    TranscriptProofInput,
    TranscriptQuote,
    transaction_inputs,
)
from ..core.db import Connection
from ..core.errors import (
    InvalidProofsError,
    KeysetInactiveError,
    NoSecretInProofsError,
    NotAllowedError,
    OutputsAlreadySignedError,
    OutputsArePendingError,
    SecretTooLongError,
    TransactionDuplicateInputsError,
    TransactionDuplicateOutputsError,
    TransactionError,
    TransactionMultipleUnitsError,
    TransactionUnitError,
    TransactionUnitMismatchError,
    WitnessTooLongError,
)
from ..core.nuts import nut20
from ..core.settings import settings
from .conditions import LedgerSpendingConditions
from .protocols import SupportsBackends, SupportsDb, SupportsKeysets


class LedgerVerification(
    LedgerSpendingConditions, SupportsKeysets, SupportsDb, SupportsBackends
):
    """Verification functions for the ledger."""

    async def verify_inputs_and_outputs(
        self,
        *,
        proofs: List[Proof],
        outputs: Optional[List[BlindedMessage]] = None,
        conn: Optional[Connection] = None,
        transcript_outputs: Optional[List[BlindedMessage]] = None,
        melt_quote: Optional[MeltQuote] = None,
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
        # 1. Verify inputs
        await self._verify_inputs(proofs)

        if outputs is not None:
            # 2. Verify outputs
            await self._verify_outputs(outputs, conn=conn)

            # 3. Verify inputs and outputs together
            self._verify_inputs_and_outputs_together(proofs, outputs)

        # 4. Verify nutroot transaction witnesses (v3 point secrets).
        # For melt, `outputs` is None here (change blanks are verified earlier)
        # and the request's outputs arrive as `transcript_outputs`.
        if outputs is not None or transcript_outputs is not None or melt_quote is not None:
            self._verify_nutroot_transaction_witnesses(
                proofs,
                outputs if outputs is not None else (transcript_outputs or []),
                melt_quote,
            )

    async def _verify_transaction(
        self,
        *,
        proofs: List[Proof],
        outputs: Optional[List[BlindedMessage]] = None,
        quote: Optional[str] = None,
        conn: Optional[Connection] = None,
        skip_output_amount_check: bool = False,
        expected_output_unit: Optional[Unit] = None,
        verify_input_output_balance: bool = True,
        melt_quote: Optional[MeltQuote] = None,
    ) -> None:
        # 1. Verify the inputs generically: amounts, secret and witness
        # criteria, duplicate-input prevention, ECASH signature validity, and
        # whether the proofs are still spendable.
        await self._verify_inputs(proofs)

        # 2. Verify NUT-10 spending conditions (P2PK, HTLC, and grouped
        # SIG_ALL rules) at the transaction level.
        self._verify_input_output_spending_conditions(proofs, outputs or [], quote)

        # Melts can omit NUT-08 change outputs or provide an empty array. Those
        # skip the output checks but still carry a transaction the v3 witnesses
        # sign, so this is a guard rather than an early return.
        if outputs is not None and (outputs or verify_input_output_balance):
            # 3. Verify the outputs generically: keyset consistency, amount rules,
            # duplicate-output prevention, and that the blinded messages have not
            # already been stored or signed by the mint.
            await self._verify_outputs(
                outputs,
                skip_amount_check=skip_output_amount_check,
                expected_unit=expected_output_unit,
                conn=conn,
            )

            # 4. For transaction types that require normal input/output balance
            # and unit checks (such as swaps), verify those combined invariants.
            if verify_input_output_balance:
                # This checks the amount equation and unit compatibility between
                # the spent inputs and the created outputs.
                self._verify_inputs_and_outputs_together(proofs, outputs)

        # 5. Verify nutroot transaction witnesses (v3 point secrets). One
        # transcript per transaction, so this runs on every path, including a
        # melt whose only output is the quote itself.
        self._verify_nutroot_transaction_witnesses(proofs, outputs or [], melt_quote)

    async def _verify_inputs(
        self,
        proofs: List[Proof],
    ):
        """Verify that the proofs are valid and can be spent."""
        logger.trace(f"Verifying {len(proofs)} proofs.")
        if not proofs:
            raise TransactionError("no proofs provided.")
        # Verify amounts of inputs
        if not all([self._verify_amount(p.amount) for p in proofs]):
            raise TransactionError("invalid amount.")
        # Verify secret criteria
        if not all([self._verify_secret_criteria(p) for p in proofs]):
            raise TransactionError("secrets do not match criteria.")
        # Verify witness criteria
        if not all([self._verify_input_witness_criteria(p) for p in proofs]):
            raise TransactionError("input witness data does not match criteria.")
        # verify that only unique proofs were used
        if not self._verify_no_duplicate_proofs(proofs):
            raise TransactionDuplicateInputsError()
        # Verify ecash signatures
        if not all([self._verify_proof_bdhke(p) for p in proofs]):
            raise InvalidProofsError()
        # NUT-10 spending conditions are intentionally not checked here.
        # For swap and melt, those are verified at the transaction level by
        # `_verify_input_output_spending_conditions(...)`, which `_verify_transaction(...)`
        # calls right after `_verify_inputs(...)`. Blind-auth uses this generic
        # proof-validation path and does not rely on NUT-10 spending-condition
        # enforcement here.
        # Verify proofs are not already spent (raises ProofsAlreadySpentError)
        await self.db_read._verify_proofs_spendable(proofs)

        logger.trace(f"Verified {len(proofs)} proofs.")

    def _verify_proofs_unit(self, proofs: List[Proof], expected_unit: Unit) -> None:
        """Verifies that all proofs have the expected unit and valid keysets."""
        if not proofs:
            raise TransactionError("no proofs provided.")
        for p in proofs:
            if p.id not in self.keysets:
                raise TransactionError(f"keyset {p.id} unknown")
            if self.keysets[p.id].unit != expected_unit:
                raise TransactionError(
                    f"proof unit {self.keysets[p.id].unit.name} does not match quote unit {expected_unit.name}"
                )

    async def _verify_outputs(
        self,
        outputs: List[BlindedMessage],
        skip_amount_check=False,
        expected_unit: Optional[Unit] = None,
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
            raise KeysetInactiveError()
        if expected_unit and self.keysets[outputs[0].id].unit != expected_unit:
            raise TransactionError(
                f"output unit {self.keysets[outputs[0].id].unit.name} does not match quote unit {expected_unit.name}"
            )
        # Verify that all blinded messages are valid curve points
        if not all([self._verify_blinded_message(o) for o in outputs]):
            raise TransactionError("invalid blinded message.")
        # Verify amounts of outputs
        # we skip the amount check for NUT-8 change outputs (which can have amount 0)
        if not skip_amount_check:
            if not all([self._verify_amount(o.amount) for o in outputs]):
                raise TransactionError("invalid amount.")
        # verify that only unique outputs were used
        if not self._verify_no_duplicate_outputs(outputs):
            raise TransactionDuplicateOutputsError()
        # verify that outputs have not been stored or signed before
        stored_before = await self._check_outputs_pending_or_issued_before(
            outputs, conn
        )
        if stored_before:
            signed_outputs = [o for o in stored_before if o.C_ is not None]
            if any(o.C_ for o in signed_outputs):
                raise OutputsAlreadySignedError()
            else:
                raise OutputsArePendingError()

        logger.trace(f"Verified {len(outputs)} outputs.")

    @staticmethod
    def _verify_nutroot_transaction_witnesses(
        proofs: List[Proof],
        outputs: List[BlindedMessage],
        melt_quote: Optional[MeltQuote] = None,
    ) -> None:
        """Verify v3 point-secret input witnesses over the transaction transcript.

        One shared transcript per transaction, one input digest per input
        (NUT-10): every v3 input must carry a witness, a key path signature
        being a BIP-340 signature over its input digest by the secret's key
        and a script path witness resolving leaf to root to tweak before
        evaluating. Anything missing or invalid rejects the transaction.
        v0-v2 inputs keep their own rules and are skipped here, so mixed
        transactions verify per input as specified.
        """
        if not proofs or (not outputs and melt_quote is None):
            return
        if not any(is_nutroot_point_secret(p.secret, p.id) for p in proofs):
            return
        _, proof_contexts, _ = transaction_inputs(
            TransactionShape(
                proof_inputs=[
                    TranscriptProofInput(
                        amount=p.amount,
                        keyset_id=keyset_id_transcript_bytes(p.id),
                        secret=secret_transcript_bytes(p.secret, p.id),
                        C=bytes.fromhex(p.C),
                    )
                    for p in proofs
                ],
                blinded_outputs=[
                    TranscriptBlindedOutput(
                        amount=o.amount,
                        keyset_id=keyset_id_transcript_bytes(o.id),
                        B_=bytes.fromhex(o.B_),
                    )
                    for o in outputs
                ],
                melt_quote_outputs=(
                    [TranscriptQuote(amount=melt_quote.amount, quote_id=melt_quote.quote)]
                    if melt_quote is not None
                    else None
                ),
            )
        )
        for proof in proofs:
            if not is_nutroot_point_secret(proof.secret, proof.id):
                continue  # v0-v2 input: NUT-10/11/14 rules apply to it instead
            digest = proof_contexts[secret_transcript_bytes(proof.secret, proof.id)].digest
            # Stored with the spent proof, opening the NUT-07 commitment: the
            # witness verifies only against this input digest. A failure below
            # aborts the transaction, so nothing unverified is ever persisted.
            proof.digest = digest.hex()
            if proof.witness is None:
                # Inputs sign (NUT-10): with spend_info live in both wallets,
                # every legitimate spender of a point secret can sign.
                raise TransactionError("missing nutroot transaction witness.")
            try:
                witness = NutrootWitness.model_validate_json(proof.witness)
            except Exception:
                raise TransactionError("invalid nutroot transaction witness.")
            if witness.is_script_path:
                # Script path: leaf -> root -> tweak -> P, then evaluate (NUT-10).
                try:
                    verify_script_path_spend(
                        SecpPublicKey(bytes.fromhex(proof.secret)), digest, witness
                    )
                except Exception as e:
                    raise TransactionError(
                        f"invalid nutroot script path witness: {e}"
                    )
                continue
            # Key path: exactly one BIP-340 signature by the secret's key
            # (NUT-10); anything more is rejected, not skipped.
            try:
                signature = bytes.fromhex(witness.signatures[0])
                pubkey = PublicKeyXOnly(bytes.fromhex(proof.secret)[1:])
                valid = pubkey.verify(signature, digest)
            except Exception:
                raise TransactionError("invalid nutroot transaction witness.")
            if not valid:
                raise TransactionError("invalid nutroot transaction witness.")

    def _verify_inputs_and_outputs_together(
        self,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
    ):
        """Verify criteria that depend on both inputs and outputs."""
        # Verify that inputs > outputs (excluding fees)
        self._verify_input_output_amounts(proofs, outputs)

        # Verify input and output amounts are balanced (inputs = outputs + fees)
        self._verify_equation_balanced(proofs, outputs)

        # Verify that input keyset units are the same as output keyset unit
        self._verify_units_match(proofs, outputs)

    async def _check_outputs_pending_or_issued_before(
        self,
        outputs: List[BlindedMessage],
        conn: Optional[Connection] = None,
    ) -> List[BlindedMessage]:
        """Checks whether the provided outputs have previously stored (as blinded messages,
        or signed as blind signatures) by the mint.

        Args:
            outputs (List[BlindedMessage]): Outputs to check

        Returns:
            result (List[BlindedMessage]): List of booleans indicating whether each output was already stored before
        """
        async with self.db.get_connection(conn) as conn:
            promises = await self.crud.get_outputs(
                b_s=[output.B_ for output in outputs], db=self.db, conn=conn
            )
        return promises

    def _verify_secret_criteria(self, proof: Proof) -> Literal[True]:
        """Verifies that a secret is present and is not too long (DOS prevention)."""
        if proof.secret is None or proof.secret == "":
            raise NoSecretInProofsError()
        if len(proof.secret) > settings.mint_max_secret_length:
            raise SecretTooLongError(
                f"secret too long. max: {settings.mint_max_secret_length}"
            )
        return True

    def _verify_input_witness_criteria(self, proof: Proof) -> Literal[True]:
        """Verifies max length of input witness data"""
        max_length = (
            NUTROOT_MAX_WITNESS_LENGTH
            if is_bls_keyset(proof.id)
            else settings.mint_max_witness_length
        )
        if proof.witness is not None and len(proof.witness) > max_length:
            raise WitnessTooLongError(
                f"input witness data too long. max: {max_length}"
            )
        return True

    def _verify_proof_bdhke(self, proof: Proof) -> bool:
        """Verifies that the proof of promise was issued by this ledger."""
        assert proof.id in self.keysets, f"keyset {proof.id} unknown"
        logger.trace(
            f"Validating proof {proof.secret} with keyset {self.keysets[proof.id].id}."
        )
        # use the appropriate active keyset for this proof.id
        keyset = self.keysets[proof.id]
        private_key_amount = keyset.private_keys[proof.amount]

        is_v3 = is_bls_keyset(proof.id)

        C_generic: PublicKey
        if is_v3:
            try:
                C_generic = BlsPublicKey(bytes.fromhex(proof.C)) # type: ignore[assignment]
            except Exception:
                return False
            valid = keyed_verification(private_key_amount, C_generic, proof.secret) # type: ignore
        else:
            try:
                C_generic = SecpPublicKey(bytes.fromhex(proof.C)) # type: ignore[assignment]
            except Exception:
                return False
            valid = b_dhke.verify(private_key_amount, C_generic, proof.secret) # type: ignore
            
        if valid:
            logger.trace("Proof verified.")
        else:
            logger.trace(f"Proof verification failed for {proof.secret} – {proof.C}.")
        return valid

    def _verify_input_output_amounts(
        self, inputs: List[Proof], outputs: List[BlindedMessage]
    ) -> None:
        """Verifies that inputs have at least the same amount as outputs"""
        input_amount = sum([p.amount for p in inputs])
        output_amount = sum([o.amount for o in outputs])
        if not input_amount >= output_amount:
            raise TransactionError(
                f"input amounts ({input_amount}) less than output amounts ({output_amount})."
            )

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

    def _verify_blinded_message(self, output: BlindedMessage) -> bool:
        """Verifies that a blinded message is a valid curve point."""
        try:
            public_key_cls = BlsPublicKey if is_bls_keyset(output.id) else SecpPublicKey
            public_key_cls(bytes.fromhex(output.B_))
        except (TypeError, ValueError):
            return False
        return True

    def _verify_inputs_outputs_units_match(
        self, proofs: List[Proof], outputs: List[BlindedMessage]
    ) -> bool:
        """Verifies that the units of the inputs and outputs match."""
        units_proofs = [self.keysets[p.id].unit for p in proofs]
        units_outputs = [self.keysets[o.id].unit for o in outputs]
        if not len(set(units_proofs)) == 1:
            raise TransactionMultipleUnitsError("inputs have different units.")
        if not len(set(units_outputs)) == 1:
            raise TransactionMultipleUnitsError("outputs have different units.")
        if not units_proofs[0] == units_outputs[0]:
            raise TransactionUnitMismatchError()
        return True

    def _verify_amount(self, amount: int) -> int:
        """Any amount used should be positive and not larger than 2^MAX_ORDER."""
        valid = amount > 0 and amount < 2**settings.max_order
        if not valid:
            raise NotAllowedError(f"invalid amount: {amount}")
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
            raise TransactionMultipleUnitsError("inputs have different units.")
        if not len(set(units_outputs)) == 1:
            raise TransactionMultipleUnitsError("outputs have different units.")
        if not units_proofs[0] == units_outputs[0]:
            raise TransactionUnitMismatchError()
        return units_proofs[0]

    def get_fees_for_proofs(self, proofs: List[Proof]) -> int:
        if not len({self.keysets[p.id].unit for p in proofs}) == 1:
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

    def _verify_mint_quote_witness(
        self,
        quote: MintQuote,
        outputs: List[BlindedMessage],
        signature: Optional[str],
        batch_quotes: "Optional[List[tuple]]" = None,
    ) -> bool:
        """Verify signature on quote id and outputs"""
        if not quote.pubkey:
            if outputs and is_bls_keyset(outputs[0].id):
                # A quote is a transaction input and inputs sign (NUT-10), so an
                # unlocked quote has no key to sign with: minting onto a v3 keyset
                # requires a locked quote (NUT-10).
                raise TransactionError(
                    "minting on a v3 keyset requires a locked quote."
                )
            return True
        if not signature:
            return False
        if outputs and is_bls_keyset(outputs[0].id):
            # V3: the quote is a transaction input; its lock key signs the
            # quote input digest (key or script path). For batch mints the
            # digest covers every quote input.
            return nut20.verify_mint_quote_v3(
                quote.quote,
                quote.amount,
                outputs,
                quote.pubkey,
                signature,
                batch_quotes=batch_quotes,
            )
        return nut20.verify_mint_quote(quote.quote, outputs, quote.pubkey, signature)
