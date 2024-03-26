import math
from typing import List, Optional, Tuple, Union

from loguru import logger

from ..core.base import (
    Proof,
)
from ..core.db import Database
from ..core.helpers import sum_proofs
from ..core.p2pk import Secret
from .protocols import SupportsDb, SupportsKeysets


class WalletTransactions(SupportsDb, SupportsKeysets):
    keyset_id: str
    db: Database
    mint_keyset_ids: List[str]  # holds active keyset ids of the mint

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
    proofs_old_epochs = [p for p in proofs if p.id != self.keysets[self.keyset_id].id]
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


async def get_pay_amount_with_fees(self, invoice: str):
    """
    Decodes the amount from a Lightning invoice and returns the
    total amount (amount+fees) to be paid.
    """
    melt_quote = await self.melt_quote(invoice)
    logger.debug(f"Mint wants {self.unit.str(melt_quote.fee_reserve)} as fee reserve.")
    return melt_quote


async def select_to_send(
    self,
    proofs: List[Proof],
    amount: int,
    set_reserved: bool = False,
    offline: bool = False,
    tolerance: int = 0,
) -> Tuple[List[Proof], int]:
    """
    Selects proofs such that a certain amount can be sent.

    Args:
        proofs (List[Proof]): Proofs to split
        amount (int): Amount to split to
        set_reserved (bool, optional): If set, the proofs are marked as reserved.

    Returns:
        List[Proof]: Proofs to send
        int: Fees for the transaction
    """
    # TODO: load mint from database for offline mode!
    await self.load_mint()

    send_proofs, fees = await self._select_proofs_to_send(proofs, amount, tolerance)
    if not send_proofs and offline:
        raise Exception(
            "Could not select proofs in offline mode. Available amounts:"
            f" {set([p.amount for p in proofs])}"
        )

    if not send_proofs and not offline:
        # we set the proofs as reserved later
        _, send_proofs = await self.split_to_send(proofs, amount, set_reserved=False)

    if set_reserved:
        await self.set_reserved(send_proofs, reserved=True)
    return send_proofs, fees


async def split_to_send(
    self,
    proofs: List[Proof],
    amount: int,
    secret_lock: Optional[Secret] = None,
    set_reserved: bool = False,
) -> Tuple[List[Proof], List[Proof]]:
    """
    Splits proofs such that a certain amount can be sent.

    Args:
        proofs (List[Proof]): Proofs to split
        amount (int): Amount to split to
        secret_lock (Optional[str], optional): If set, a custom secret is used to lock new outputs. Defaults to None.
        set_reserved (bool, optional): If set, the proofs are marked as reserved. Should be set to False if a payment attempt
        is made with the split that could fail (like a Lightning payment). Should be set to True if the token to be sent is
        displayed to the user to be then sent to someone else. Defaults to False.

    Returns:
        Tuple[List[Proof], List[Proof]]: Tuple of proofs to keep and proofs to send
    """

    spendable_proofs, fees = await self._select_proofs_to_split(proofs, amount)
    print(f"Amount to send: {self.unit.str(amount)} (+ {self.unit.str(fees)} fees)")
    if secret_lock:
        logger.debug(f"Spending conditions: {secret_lock}")
    keep_proofs, send_proofs = await self.split(spendable_proofs, amount, secret_lock)
    if set_reserved:
        await self.set_reserved(send_proofs, reserved=True)
    return keep_proofs, send_proofs
