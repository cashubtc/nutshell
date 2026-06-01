from typing import Dict, List, Optional, Tuple

from loguru import logger

from ...core.base import BlindedMessage, BlindedSignature, MintKeyset, Proof
from .blind_signatures import LedgerBlindSignatures


class LedgerSwap(LedgerBlindSignatures):
    async def swap(
        self,
        *,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
        keyset: Optional[MintKeyset] = None,
    ) -> List[BlindedSignature]:
        """Consumes proofs and prepares new promises based on the amount swap. Used for swapping tokens
        Before sending or for redeeming tokens for new ones that have been received by another wallet.

        Args:
            proofs (List[Proof]): Proofs to be invalidated for the swap.
            outputs (List[BlindedMessage]): New outputs that should be signed in return.
            keyset (Optional[MintKeyset], optional): Keyset to use. Uses default keyset if not given. Defaults to None.

        Raises:
            Exception: Validation of proofs or outputs failed

        Returns:
            List[BlindedSignature]: New promises (signatures) for the outputs.
        """
        logger.trace("swap called")
        # verify spending inputs, outputs, and spending conditions
        await self.verify_inputs_and_outputs(proofs=proofs, outputs=outputs)
        await self.db_write._verify_spent_proofs_and_set_pending(
            proofs, keysets=self.keysets
        )
        try:
            Ys = [p.Y for p in proofs]
            lock_parameters = {f"y{i}": y for i, y in enumerate(Ys)}
            ys_list = ", ".join(f":y{i}" for i in range(len(Ys)))
            async with self.db.get_connection(
                lock_table="proofs_pending",
                lock_select_statement=f"y IN ({ys_list})",
                lock_parameters=lock_parameters,
            ) as conn:
                await self._store_blinded_messages(outputs, keyset=keyset, conn=conn)

                # Calculate fees
                proofs_by_keyset: Dict[str, List[Proof]] = {}
                for p in proofs:
                    proofs_by_keyset.setdefault(p.id, []).append(p)
                keyset_fees = {}
                for keyset_id, keyset_proofs in proofs_by_keyset.items():
                    keyset_fees[keyset_id] = self.get_fees_for_proofs(keyset_proofs)

                await self.db_write.invalidate_proofs(
                    proofs=proofs,
                    keysets=self.keysets,
                    keyset_fees=keyset_fees,
                    conn=conn,
                )
                promises = await self._sign_blinded_messages(outputs, conn)
        except Exception as e:
            logger.trace(f"swap failed: {e}")
            raise e
        finally:
            # delete proofs from pending list
            await self.db_write._unset_proofs_pending(proofs, keysets=self.keysets)

        logger.trace("swap successful")
        return promises

    async def restore(
        self, outputs: List[BlindedMessage]
    ) -> Tuple[List[BlindedMessage], List[BlindedSignature]]:
        signatures: List[BlindedSignature] = []
        return_outputs: List[BlindedMessage] = []
        async with self.db.get_connection() as conn:
            for output in outputs:
                logger.trace(f"looking for promise: {output}")
                promise = await self.crud.get_blind_signature(
                    b_=output.B_, db=self.db, conn=conn
                )
                if promise is not None:
                    signatures.append(promise)
                    return_outputs.append(output)
                    logger.trace(f"promise found: {promise}")
        return return_outputs, signatures
