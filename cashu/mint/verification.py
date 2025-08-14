from typing import Dict, List, Literal, Optional, Tuple, Union

from loguru import logger

from ..core.base import (
    Amount,
    BlindedMessage,
    BlindedSignature,
    Method,
    MintKeyset,
    MintQuote,
    Proof,
    Unit,
)
from ..core.crypto import b_dhke
from ..core.crypto.secp import PublicKey
from ..core.db import Connection
from ..core.errors import (
    InvalidProofsError,
    NoSecretInProofsError,
    NotAllowedError,
    OutputsAlreadySignedError,
    SecretTooLongError,
    TransactionDuplicateInputsError,
    TransactionDuplicateOutputsError,
    TransactionError,
    TransactionMultipleUnitsError,
    TransactionUnitError,
    TransactionUnitMismatchError,
)
from ..core.nuts import nut20
from ..core.settings import settings
from .conditions import LedgerSpendingConditions
from .protocols import SupportsBackends, SupportsDb, SupportsKeysets


def get_mint_limits():
    """Parse mint limits from the unified configuration."""
    from ..core.base import Unit, Amount
    
    # Initialize default empty maps
    max_mint_map: Dict[Unit, Optional[Amount]] = {
        Unit.sat: None,
        Unit.msat: None,
        Unit.eur: None,
        Unit.usd: None,
    }
    max_melt_map: Dict[Unit, Optional[Amount]] = {
        Unit.sat: None,
        Unit.msat: None,
        Unit.eur: None,
        Unit.usd: None,
    }
    max_balance_map: Dict[Unit, Optional[Amount]] = {
        Unit.sat: None,
        Unit.msat: None,
        Unit.eur: None,
        Unit.usd: None,
    }
    
    # Parse unified mint_limits configuration
    if settings.mint_limits:
        logger.info("Using unified mint_limits configuration")
        for limit_config in settings.mint_limits:
            if len(limit_config) != 4:
                logger.warning(f"Invalid mint_limits entry: {limit_config}. Expected format: [unit, max_mint, max_melt, max_balance]")
                continue
            
            unit_str, max_mint, max_melt, max_balance = limit_config
            try:
                unit = Unit[unit_str]
                
                # Create Amount objects for each limit (handle None values)
                if max_mint is not None:
                    if unit in [Unit.sat, Unit.msat]:
                        max_mint_map[unit] = Amount(unit=unit, amount=int(max_mint))
                    else:
                        max_mint_map[unit] = Amount.from_float(unit=unit, amount=float(max_mint))
                
                if max_melt is not None:
                    if unit in [Unit.sat, Unit.msat]:
                        max_melt_map[unit] = Amount(unit=unit, amount=int(max_melt))
                    else:
                        max_melt_map[unit] = Amount.from_float(unit=unit, amount=float(max_melt))
                
                if max_balance is not None:
                    if unit in [Unit.sat, Unit.msat]:
                        max_balance_map[unit] = Amount(unit=unit, amount=int(max_balance))
                    else:
                        max_balance_map[unit] = Amount.from_float(unit=unit, amount=float(max_balance))
                        
            except (KeyError, ValueError, TypeError) as e:
                logger.warning(f"Invalid unit or limit value in mint_limits: {limit_config}. Error: {e}")
                continue

    return (max_mint_map, max_melt_map, max_balance_map)


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
    ):
        """Checks all proofs and outputs for validity.

        Warning: Does NOT check if the proofs were already spent. Use `db_write._verify_proofs_spendable` for that.

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
            raise TransactionDuplicateInputsError()
        # Verify ecash signatures
        if not all([self._verify_proof_bdhke(p) for p in proofs]):
            raise InvalidProofsError()
        # Verify SIG_INPUTS spending conditions
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

        # Verify SIG_ALL spending conditions
        self._verify_input_output_spending_conditions(proofs, outputs)

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
            raise TransactionDuplicateOutputsError()
        # verify that outputs have not been signed previously
        signed_before = await self._check_outputs_issued_before(outputs, conn)
        if any(signed_before):
            raise OutputsAlreadySignedError()
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
    ) -> bool:
        """Verify signature on quote id and outputs"""
        if not quote.pubkey:
            return True
        if not signature:
            return False
        return nut20.verify_mint_quote(quote.quote, outputs, quote.pubkey, signature)

    def _verify_mint_limits(
        self,
        amount: Amount,
    ) -> None:

        def get_active_unit_balance(unit: Unit):
            active_keyset: MintKeyset = next(
                filter(lambda k: k.active and k.unit == unit, self.keysets.values())
            )
            return active_keyset.balance

        unit = amount.unit
        (max_mint_map, _, max_balance_map) = get_mint_limits()

        # Check max peg-in
        if (max_mint_map[unit]
            and amount.amount > max_mint_map[unit].amount     # type: ignore
        ):
            raise NotAllowedError(f"Cannot mint more than {max_mint_map[unit]}.")

        # Check max balance
        if max_balance_map[unit]:
            balance_unit = get_active_unit_balance(unit=unit)
            if amount.amount + balance_unit > max_balance_map[unit].amount:     # type: ignore
                raise NotAllowedError("Mint has reached maximum balance.")
            
        # --- DEPRECATED ---
        if settings.mint_max_peg_in and unit == Unit.sat:
            logger.warning("Mint is using DEPRECATED limits settings")
            if amount.amount > settings.mint_max_peg_in:
                raise NotAllowedError(f"Cannot mint more than {settings.mint_max_peg_in} sat.")
        
        if settings.mint_max_balance and unit == Unit.sat:
            logger.warning("Mint is using DEPRECATED limits settings")
            balance_sat = get_active_unit_balance(unit=unit)
            if amount.amount + balance_sat > settings.mint_max_balance:
                raise NotAllowedError("Mint has reached maximum balance.")
        # --- END DEPRECATED ---

    
    def _verify_melt_limits(
        self,
        amount: Amount,
    ) -> None:

        unit = amount.unit
        (_, max_melt_map, _) = get_mint_limits()

        # Check max peg-out
        if (max_melt_map[unit]
            and amount.amount > max_melt_map[unit].amount    # type: ignore
        ):
            raise NotAllowedError(f"Cannot melt more than {max_melt_map[unit]}.") # type: ignore

        # --- DEPRECATED ---
        if settings.mint_max_peg_out and unit == Unit.sat:
            logger.warning("Mint is using DEPRECATED limits settings")
            if amount.amount > settings.mint_max_peg_out:
                raise NotAllowedError(f"Cannot melt more than {settings.mint_max_peg_out} sat.")
        # --- END DEPRECATED ---
