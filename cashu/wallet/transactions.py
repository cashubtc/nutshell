import uuid
from typing import Dict, List, Optional, Tuple, Union

from loguru import logger

from ..core.base import (
    Proof,
    Unit,
    WalletKeyset,
)
from ..core.db import Database
from ..core.helpers import amount_summary, sum_proofs
from ..core.settings import settings
from ..core.split import amount_split
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
        logger.trace(f"adding proof: {smaller_proofs[0].amount} – fee: {fee_ppk} ppk")
        remainder -= smaller_proofs[0].amount - fee_ppk / 1000
        logger.trace(f"remainder: {remainder}")
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

    def get_allowed_amounts(self):
        """
        Infer the allowed amounts from the current keyset's public keys.

        Returns:
            List[int]: A sorted list of allowed token amounts for the current keyset.

        Raises:
            Exception: If no active keyset is set.
        """

        if not self.keyset_id or self.keyset_id not in self.keysets:
            raise Exception("No active keyset")
        return sorted(list(self.keysets[self.keyset_id].public_keys.keys()))

    def split_wallet_state(self, amount: int) -> List[int]:
        """This function produces an amount split for outputs based on the current state of the wallet.
        Its objective is to fill up the wallet so that it reaches `n_target` coins of each amount.

        Args:
            amount (int): Amount to split

        Returns:
            List[int]: List of amounts to mint
        """
        # read the target count for each amount from settings
        n_target = settings.wallet_target_amount_count
        amounts_we_have = [p.amount for p in self.proofs if p.reserved is not True]
        amounts_we_have.sort()

        all_possible_amounts = self.get_allowed_amounts()

        amounts_we_want_ll = [
            [a] * max(0, n_target - amounts_we_have.count(a))
            for a in all_possible_amounts
        ]
        # flatten list of lists to list
        amounts_we_want = [item for sublist in amounts_we_want_ll for item in sublist]
        # sort by increasing amount
        amounts_we_want.sort()

        logger.trace(
            f"Amounts we have: {[(a, amounts_we_have.count(a)) for a in set(amounts_we_have)]}"
        )
        amounts: list[int] = []
        while sum(amounts) < amount and amounts_we_want:
            if sum(amounts) + amounts_we_want[0] > amount:
                break
            amounts.append(amounts_we_want.pop(0))

        remaining_amount = amount - sum(amounts)
        if remaining_amount > 0:
            amounts += amount_split(remaining_amount)
        amounts.sort()

        logger.trace(f"Amounts we want: {amounts}")
        if sum(amounts) != amount:
            raise Exception(f"Amounts do not sum to {amount}.")

        return amounts

    def determine_output_amounts(
        self,
        proofs: List[Proof],
        amount: int,
        include_fees: bool = False,
        keyset_id_outputs: Optional[str] = None,
    ) -> Tuple[List[int], List[int]]:
        """This function generates a suitable amount split for the outputs to keep and the outputs to send. It
        calculates the amount to keep based on the wallet state and the amount to send based on the amount
        provided.

        Amount to keep is based on the proofs we have in the wallet
        Amount to send is optimally split based on the amount provided plus optionally the fees required to receive them.

        Args:
            proofs (List[Proof]): Proofs to be split.
            amount (int): Amount to be sent.
            include_fees (bool, optional): If True, the fees are included in the amount to send (output of
                this method, to be sent in the future). This is not the fee that is required to swap the
                `proofs` (input to this method). Defaults to False.
            keyset_id_outputs (str, optional): The keyset ID of the outputs to be produced, used to determine the
                fee if `include_fees` is set.

        Returns:
            Tuple[List[int], List[int]]: Two lists of amounts, one for keeping and one for sending.
        """
        # create a suitable amount split based on the proofs provided
        total = sum_proofs(proofs)
        keep_amt, send_amt = total - amount, amount

        if include_fees:
            keyset_id = keyset_id_outputs or self.keyset_id
            tmp_proofs = [Proof(id=keyset_id) for _ in amount_split(send_amt)]
            fee = self.get_fees_for_proofs(tmp_proofs)
            keep_amt -= fee
            send_amt += fee

        logger.trace(f"Keep amount: {keep_amt}, send amount: {send_amt}")
        logger.trace(f"Total input: {sum_proofs(proofs)}")
        # generate optimal split for outputs to send
        send_amounts = amount_split(send_amt)

        # we subtract the input fee for the entire transaction from the amount to keep
        keep_amt -= self.get_fees_for_proofs(proofs)
        logger.trace(f"Keep amount: {keep_amt}")

        # we determine the amounts to keep based on the wallet state
        keep_amounts = self.split_wallet_state(keep_amt)

        return keep_amounts, send_amounts

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
