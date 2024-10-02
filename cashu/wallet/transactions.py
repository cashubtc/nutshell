import uuid
from typing import Dict, List, Union

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

    def coinselect(
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
            f"coinselect – amount_to_send: {amount_to_send} – amounts we have: {amount_summary(proofs, self.unit)} (sum: {sum_proofs(proofs)})"
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
            selected_proofs += self.coinselect(
                smaller_proofs[1:], remainder, include_fees=include_fees
            )
        sum_selected_proofs = sum_proofs(selected_proofs)

        if sum_selected_proofs < amount_to_send and next_bigger:
            logger.trace("> adding next bigger proof")
            return [next_bigger]

        logger.trace(
            f"coinselect - selected proof amounts: {amount_summary(selected_proofs, self.unit)} (sum: {sum_proofs(selected_proofs)})"
        )
        return selected_proofs

    def coinselect_fee(self, proofs: List[Proof], amount: int) -> int:
        proofs_send = self.coinselect(proofs, amount, include_fees=True)
        return self.get_fees_for_proofs(proofs_send)

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
