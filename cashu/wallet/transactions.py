import uuid
from typing import Dict, List, Tuple, Union

from loguru import logger

from ..core.base import (
    Proof,
    Unit,
    WalletKeyset,
)
from ..core.db import Database
from ..core.helpers import amount_summary, sum_proofs
from ..wallet.crud import (
    update_proof,
)
from .protocols import SupportsDb, SupportsKeysets


class WalletTransactions(SupportsDb, SupportsKeysets):
    keysets: Dict[str, WalletKeyset]  # holds keysets
    keyset_id: str
    db: Database
    unit: Unit

    def get_fees_for_keyset(self, amounts: List[int], keyset: WalletKeyset) -> int:
        fees = max((sum([keyset.input_fee_ppk for a in amounts]) + 999) // 1000, 0)
        return fees

    def get_fees_for_proofs(self, proofs: List[Proof]) -> int:
        # for each proof, find the keyset with the same id and sum the fees
        fees = max(
            (sum([self.keysets[p.id].input_fee_ppk for p in proofs]) + 999) // 1000, 0
        )
        return fees

    def get_fees_for_proofs_ppk(self, proofs: List[Proof]) -> int:
        return sum([self.keysets[p.id].input_fee_ppk for p in proofs])

    # async def _select_proofs_to_send_legacy(
    #     self, proofs: List[Proof], amount_to_send: int, tolerance: int = 0
    # ) -> List[Proof]:
    #     send_proofs: List[Proof] = []
    #     NO_SELECTION: List[Proof] = []

    #     logger.trace(f"proofs: {[p.amount for p in proofs]}")
    #     # sort proofs by amount (descending)
    #     sorted_proofs = sorted(proofs, key=lambda p: p.amount, reverse=True)
    #     # only consider proofs smaller than the amount we want to send (+ tolerance) for coin selection
    #     fee_for_single_proof = self.get_fees_for_proofs([sorted_proofs[0]])
    #     sorted_proofs = [
    #         p
    #         for p in sorted_proofs
    #         if p.amount <= amount_to_send + tolerance + fee_for_single_proof
    #     ]
    #     if not sorted_proofs:
    #         logger.info(
    #             f"no small-enough proofs to send. Have: {[p.amount for p in proofs]}"
    #         )
    #         return NO_SELECTION

    #     target_amount = amount_to_send

    #     # compose the target amount from the remaining_proofs
    #     logger.debug(f"sorted_proofs: {[p.amount for p in sorted_proofs]}")
    #     for p in sorted_proofs:
    #         if sum_proofs(send_proofs) + p.amount <= target_amount + tolerance:
    #             send_proofs.append(p)
    #             target_amount = amount_to_send + self.get_fees_for_proofs(send_proofs)

    #     if sum_proofs(send_proofs) < amount_to_send:
    #         logger.info("could not select proofs to reach target amount (too little).")
    #         return NO_SELECTION

    #     fees = self.get_fees_for_proofs(send_proofs)
    #     logger.debug(f"Selected sum of proofs: {sum_proofs(send_proofs)}, fees: {fees}")
    #     return send_proofs

    async def _select_proofs_to_send(
        self,
        proofs: List[Proof],
        amount_to_send: Union[int, float],
        *,
        include_fees: bool = False,
    ) -> List[Proof]:
        """Select proofs to send based on the amount to send and the proofs available. Implements a simple coin selection algorithm.
        Can be used for selecting proofs to send an offline transaction.

        Args:
            proofs (List[Proof]): List of proofs to select from
            amount_to_send (Union[int, float]): Amount to select proofs for
            include_fees (bool, optional): Whether to include fees necessary to redeem the tokens in the selection. Defaults to False.

        Returns:
            List[Proof]: _description_
        """
        # check that enough spendable proofs exist
        if sum_proofs(proofs) < amount_to_send:
            return []

        logger.trace(
            f"_select_proofs_to_send – amount_to_send: {amount_to_send} – amounts we have: {amount_summary(proofs, self.unit)} (sum: {sum_proofs(proofs)})"
        )

        sorted_proofs = sorted(proofs, key=lambda p: p.amount)

        next_bigger = next(
            (p for p in sorted_proofs if p.amount > amount_to_send), None
        )

        smaller_proofs = [p for p in sorted_proofs if p.amount <= amount_to_send]
        smaller_proofs = sorted(smaller_proofs, key=lambda p: p.amount, reverse=True)

        if not smaller_proofs and next_bigger:
            logger.trace(
                "> no proofs smaller than amount_to_send, adding next bigger proof"
            )
            return [next_bigger]

        if not smaller_proofs and not next_bigger:
            logger.trace("> no proofs to select from")
            return []

        remainder = amount_to_send
        selected_proofs = [smaller_proofs[0]]
        fee_ppk = self.get_fees_for_proofs_ppk(selected_proofs) if include_fees else 0
        logger.debug(f"adding proof: {smaller_proofs[0].amount} – fee: {fee_ppk} ppk")
        remainder -= smaller_proofs[0].amount - fee_ppk / 1000
        logger.debug(f"remainder: {remainder}")
        if remainder > 0:
            logger.trace(
                f"> selecting more proofs from {amount_summary(smaller_proofs[1:], self.unit)} sum: {sum_proofs(smaller_proofs[1:])} to reach {remainder}"
            )
            selected_proofs += await self._select_proofs_to_send(
                smaller_proofs[1:], remainder, include_fees=include_fees
            )
        sum_selected_proofs = sum_proofs(selected_proofs)

        if sum_selected_proofs < amount_to_send and next_bigger:
            logger.trace("> adding next bigger proof")
            return [next_bigger]

        logger.trace(
            f"_select_proofs_to_send - selected proof amounts: {amount_summary(selected_proofs, self.unit)} (sum: {sum_proofs(selected_proofs)})"
        )
        return selected_proofs

    async def _select_proofs_to_split(
        self, proofs: List[Proof], amount_to_send: int
    ) -> Tuple[List[Proof], int]:
        """
        Selects proofs that can be used with the current mint. Implements a simple coin selection algorithm.

        The algorithm has two objectives: Get rid of all tokens from old epochs and include additional proofs from
        the current epoch starting from the proofs with the largest amount.

        Rules:
        1) Proofs that are not marked as reserved
        2) Include all proofs from inactive keysets (old epochs) to get rid of them
        3) If the target amount is not reached, add proofs of the current keyset until it is.

        Args:
            proofs (List[Proof]): List of proofs to select from
            amount_to_send (int): Amount to select proofs for

        Returns:
            List[Proof]: List of proofs to send (including fees)
            int: Fees for the transaction

        Raises:
            Exception: If the balance is too low to send the amount
        """
        logger.debug(
            f"_select_proofs_to_split - amounts we have: {amount_summary(proofs, self.unit)}"
        )
        send_proofs: List[Proof] = []

        # check that enough spendable proofs exist
        if sum_proofs(proofs) < amount_to_send:
            raise Exception("balance too low.")

        # add all proofs from inactive keysets
        proofs_inactive_keysets = [p for p in proofs if not self.keysets[p.id].active]
        send_proofs += proofs_inactive_keysets

        # coinselect based on amount only from the current keyset
        # start with the proofs with the largest amount and add them until the target amount is reached
        proofs_current_epoch = [
            p for p in proofs if p.id == self.keysets[self.keyset_id].id
        ]
        sorted_proofs_of_current_keyset = sorted(
            proofs_current_epoch, key=lambda p: p.amount
        )

        while sum_proofs(send_proofs) < amount_to_send + self.get_fees_for_proofs(
            send_proofs
        ):
            proof_to_add = sorted_proofs_of_current_keyset.pop()
            send_proofs.append(proof_to_add)

        logger.trace(
            f"_select_proofs_to_split – selected proof amounts: {[p.amount for p in send_proofs]}"
        )
        fees = self.get_fees_for_proofs(send_proofs)
        return send_proofs, fees

    async def set_reserved(self, proofs: List[Proof], reserved: bool) -> None:
        """Mark a proof as reserved or reset it in the wallet db to avoid reuse when it is sent.

        Args:
            proofs (List[Proof]): List of proofs to mark as reserved
            reserved (bool): Whether to mark the proofs as reserved or not
        """
        uuid_str = str(uuid.uuid1())
        for proof in proofs:
            proof.reserved = True
            await update_proof(proof, reserved=reserved, send_id=uuid_str, db=self.db)
