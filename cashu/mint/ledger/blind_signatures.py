from typing import List, Optional, Tuple

from loguru import logger

from ...core.base import DLEQ, BlindedMessage, BlindedSignature, MintKeyset
from ...core.crypto import b_dhke
from ...core.crypto.secp import PrivateKey, PublicKey
from ...core.db import Connection
from ...core.errors import TransactionError
from ...core.split import amount_split
from ..verification import LedgerVerification


class LedgerBlindSignatures(LedgerVerification):
    async def _generate_change_promises(
        self,
        fee_provided: int,
        fee_paid: int,
        outputs: Optional[List[BlindedMessage]],
        melt_id: Optional[str] = None,
        keyset: Optional[MintKeyset] = None,
    ) -> List[BlindedSignature]:
        """Generates a set of new promises (blinded signatures) from a set of blank outputs
        (outputs with no or ignored amount) by looking at the difference between the Lightning
        fee reserve provided by the wallet and the actual Lightning fee paid by the mint.

        If there is a positive difference, produces maximum `n_return_outputs` new outputs
        with values close or equal to the fee difference. If the given number of `outputs` matches
        the equation defined in NUT-08, we can be sure to return the overpaid fee perfectly.
        Otherwise, a smaller amount will be returned.

        Args:
            input_amount (int): Amount of the proofs provided by the client.
            output_amount (int): Amount of the melt request to be paid.
            output_fee_paid (int): Actually paid melt network fees.
            outputs (Optional[List[BlindedMessage]]): Outputs to sign for returning the overpaid fees.

        Raises:
            Exception: Output validation failed.

        Returns:
            List[BlindedSignature]: Signatures on the outputs.
        """
        # we make sure that the fee is positive
        overpaid_fee = fee_provided - fee_paid

        if overpaid_fee <= 0 or outputs is None:
            if overpaid_fee < 0:
                logger.error(
                    f"Overpaid fee is negative ({overpaid_fee}). This should not happen."
                )
            return []

        logger.debug(
            f"Lightning fee was: {fee_paid}. User provided: {fee_provided}. "
            f"Returning difference: {overpaid_fee}."
        )

        return_amounts = amount_split(overpaid_fee)

        # We return at most as many outputs as were provided or as many as are
        # required to pay back the overpaid fee.
        n_return_outputs = min(len(outputs), len(return_amounts))

        # we only need as many outputs as we have change to return
        outputs = outputs[:n_return_outputs]

        # we sort the return_amounts in descending order so we only
        # take the largest values in the next step
        return_amounts_sorted = sorted(return_amounts, reverse=True)
        # we need to imprint these amounts into the blanket outputs
        for i in range(len(outputs)):
            outputs[i].amount = return_amounts_sorted[i]  # type: ignore
        if not self._verify_no_duplicate_outputs(outputs):
            raise TransactionError("duplicate promises.")
        return_promises = await self._sign_blinded_messages(outputs)
        # delete remaining unsigned blank outputs from db
        if melt_id:
            await self.crud.delete_blinded_messages_melt_id(melt_id=melt_id, db=self.db)
        return return_promises

    async def _store_blinded_messages(
        self,
        outputs: List[BlindedMessage],
        keyset: Optional[MintKeyset] = None,
        mint_id: Optional[str] = None,
        melt_id: Optional[str] = None,
        swap_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        """Stores a blinded message in the database.

        Args:
            outputs (List[BlindedMessage]): Blinded messages to store.
            keyset (Optional[MintKeyset], optional): Keyset to use. Uses default keyset if not given. Defaults to None.
            conn: (Optional[Connection], optional): Database connection to reuse. Will create a new one if not given. Defaults to None.
        """
        async with self.db.get_connection(conn) as conn:
            for i, output in enumerate(outputs):
                keyset = keyset or self.keysets[output.id]
                if output.id not in self.keysets:
                    raise TransactionError(f"keyset {output.id} not found")
                if output.id != keyset.id:
                    raise TransactionError("keyset id does not match output id")
                if not keyset.active:
                    raise TransactionError("keyset is not active")
                logger.trace(f"Storing blinded message with keyset {keyset.id}.")
                await self.crud.store_blinded_message(
                    id=keyset.id,
                    amount=output.amount,
                    b_=output.B_,
                    mint_id=mint_id,
                    melt_id=melt_id,
                    swap_id=swap_id,
                    order_index=i,
                    db=self.db,
                    conn=conn,
                )
                logger.trace(f"Stored blinded message for {output.amount}")

    async def _sign_blinded_messages(
        self,
        outputs: List[BlindedMessage],
        conn: Optional[Connection] = None,
    ) -> list[BlindedSignature]:
        """Generates a promises (Blind signatures) for given amount and returns a pair (amount, C').

        Important: When a promises is once created it should be considered issued to the user since the user
        will always be able to restore promises later through the backup restore endpoint. That means that additional
        checks in the code that might decide not to return these promises should be avoided once this function is
        called. Only call this function if the transaction is fully validated!

        Args:
            B_s (List[BlindedMessage]): Blinded secret (point on curve)
            keyset (Optional[MintKeyset], optional): Which keyset to use. Private keys will be taken from this keyset.
                If not given will use the keyset of the first output. Defaults to None.
            conn: (Optional[Connection], optional): Database connection to reuse. Will create a new one if not given. Defaults to None.
        Returns:
            list[BlindedSignature]: Generated BlindedSignatures.
        """
        promises: List[
            Tuple[str, PublicKey, int, PublicKey, PrivateKey, PrivateKey]
        ] = []
        for output in outputs:
            B_ = PublicKey(bytes.fromhex(output.B_))
            if output.id not in self.keysets:
                raise TransactionError(f"keyset {output.id} not found")
            keyset = self.keysets[output.id]
            if output.id != keyset.id:
                raise TransactionError("keyset id does not match output id")
            if not keyset.active:
                raise TransactionError("keyset is not active")
            keyset_id = output.id
            logger.trace(f"Generating promise with keyset {keyset_id}.")
            private_key_amount = keyset.private_keys[output.amount]
            C_, e, s = b_dhke.step2_bob(B_, private_key_amount)
            promises.append((keyset_id, B_, output.amount, C_, e, s))

        keyset = keyset or self.keyset

        signatures = []
        async with self.db.get_connection(conn) as conn:
            for promise in promises:
                keyset_id, B_, amount, C_, e, s = promise
                logger.trace(f"crud: _generate_promise storing promise for {amount}")
                await self.crud.update_blinded_message_signature(
                    amount=amount,
                    b_=B_.format().hex(),
                    c_=C_.format().hex(),
                    e=e.to_hex(),
                    s=s.to_hex(),
                    db=self.db,
                    conn=conn,
                )
                logger.trace(f"crud: _generate_promise stored promise for {amount}")
                signature = BlindedSignature(
                    id=keyset_id,
                    amount=amount,
                    C_=C_.format().hex(),
                    dleq=DLEQ(e=e.to_hex(), s=s.to_hex()),
                )
                signatures.append(signature)

                # bump keyset balance
                await self.crud.bump_keyset_balance(
                    db=self.db, keyset=self.keysets[keyset_id], amount=amount, conn=conn
                )

            return signatures
