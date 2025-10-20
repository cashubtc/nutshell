import time
from hashlib import sha256
from typing import Optional

from ..base import Proof
from ..errors import TransactionError
from ..htlc import HTLCSecret
from ..secret import Secret, SecretKind


def verify_htlc_spending_conditions(
    proof: Proof,
    preimage: Optional[str] = None,
) -> bool:
    """
    Verifies an HTLC spending condition.
    Either the preimage is provided or the locktime has passed and a refund is requested.
    """
    secret = Secret.deserialize(proof.secret)
    if not secret.kind or secret.kind != SecretKind.HTLC:
        raise TransactionError("not an HTLC secret.")
    htlc_secret = HTLCSecret.from_secret(secret)

    # if a preimage is provided, the proof is spendable if the hash of the preimage
    # matches the hash in the secret
    if preimage:
        # Add a length check for the preimage
        if len(preimage) != 64:
            raise TransactionError("HTLC preimage must be 64 characters hex.")
        if htlc_secret.data != sha256(bytes.fromhex(preimage)).hexdigest():
            raise TransactionError("invalid preimage for HTLC.")
        return True

    # if no preimage is provided, we check the locktime
    now = time.time()
    if not htlc_secret.locktime or htlc_secret.locktime > now:
        raise TransactionError("HTLC locktime has not passed yet.")

    # locktime has passed.
    return True
