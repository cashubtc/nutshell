import math
import uuid
from typing import Dict, List, Tuple, Union

from loguru import logger

from ..core.base import (
    Proof,
    Unit,
    WalletKeyset,
)
from ..core.db import Database
from ..core.helpers import sum_proofs
from ..wallet.crud import (
    update_proof,
)
from .protocols import SupportsDb, SupportsKeysets


class WalletTransactions(SupportsDb, SupportsKeysets):
    keysets: Dict[str, WalletKeyset]  # holds keysets
    keyset_id: str
    db: Database
    mint_keyset_ids: List[str]  # holds active keyset ids of the mint
    unit: Unit

    def get_fees_for_proofs(self, proofs: List[Proof]) -> int:
        return math.ceil(len(proofs) * 0.1)

    async def _select_proofs_to_send(
        self, proofs: List[Proof], amount_to_send: int, tolerance: int = 0
    ) -> Tuple[List[Proof], int]:
        send_proofs: List[Proof] = []
        # select proofs that are not reserved
        proofs = [p for p in proofs if not p.reserved]
        # select proofs that are in the active keysets of the mint
        proofs = [p for p in proofs if p.id in self.mint_keyset_ids or not p.id]
        # sort proofs by amount (descending)
        sorted_proofs = sorted(proofs, key=lambda p: p.amount, reverse=True)
        remaining_proofs = sorted_proofs.copy()

        # start with the lowest possible fee (single proof)
        fees_single_proof = self.get_fees_for_proofs([Proof()])

        # find the smallest proof with an amount larger than the target amount
        larger_proof: Union[None, Proof] = None
        if len(sorted_proofs) > 1:
            for proof in sorted_proofs:
                if proof.amount > amount_to_send + fees_single_proof:
                    larger_proof = proof
                    remaining_proofs.pop(0)
                else:
                    break

        # compose the target amount from the remaining_proofs
        while sum_proofs(send_proofs) < amount_to_send + self.get_fees_for_proofs(
            send_proofs
        ):
            proof_to_add = remaining_proofs.pop(0)
            send_proofs.append(proof_to_add)

        # if the larger proof is cheaper to spend, we use it
        if larger_proof and sum_proofs(send_proofs) > larger_proof.amount:
            send_proofs = [larger_proof]

        fees = self.get_fees_for_proofs(send_proofs)
        return send_proofs, fees

    async def _select_proofs_to_split(
        self, proofs: List[Proof], amount_to_send: int
    ) -> Tuple[List[Proof], int]:
        """
        Selects proofs that can be used with the current mint. Implements a simple coin selection algorithm.

        The algorithm has two objectives: Get rid of all tokens from old epochs and include additional proofs from
        the current epoch starting from the proofs with the largest amount.

        Rules:
        1) Proofs that are not marked as reserved
        2) Proofs that have a keyset id that is in self.mint_keyset_ids (all active keysets of mint)
        3) Include all proofs that have an older keyset than the current keyset of the mint (to get rid of old epochs).
        4) If the target amount is not reached, add proofs of the current keyset until it is.

        Args:
            proofs (List[Proof]): List of proofs to select from
            amount_to_send (int): Amount to select proofs for

        Returns:
            List[Proof]: List of proofs to send (including fees)
            int: Fees for the transaction

        Raises:
            Exception: If the balance is too low to send the amount
        """
        send_proofs: List[Proof] = []

        # select proofs that are not reserved
        proofs = [p for p in proofs if not p.reserved]

        # select proofs that are in the active keysets of the mint
        proofs = [p for p in proofs if p.id in self.mint_keyset_ids or not p.id]

        # check that enough spendable proofs exist
        if sum_proofs(proofs) < amount_to_send:
            raise Exception("balance too low.")

        # add all proofs that have an older keyset than the current keyset of the mint
        proofs_old_epochs = [
            p for p in proofs if p.id != self.keysets[self.keyset_id].id
        ]
        send_proofs += proofs_old_epochs

        # coinselect based on amount only from the current keyset
        # start with the proofs with the largest amount and add them until the target amount is reached
        proofs_current_epoch = [
            p for p in proofs if p.id == self.keysets[self.keyset_id].id
        ]
        sorted_proofs_of_current_keyset = sorted(
            proofs_current_epoch, key=lambda p: p.amount
        )

        fees = self.get_fees_for_proofs(send_proofs)

        while sum_proofs(send_proofs) < amount_to_send + self.get_fees_for_proofs(
            send_proofs
        ):
            proof_to_add = sorted_proofs_of_current_keyset.pop()
            send_proofs.append(proof_to_add)

        logger.trace(f"selected proof amounts: {[p.amount for p in send_proofs]}")
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
