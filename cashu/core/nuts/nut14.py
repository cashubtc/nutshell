import time
from hashlib import sha256

from ..base import Proof
from ..errors import TransactionError
from ..htlc import HTLCSecret
from ..secret import Secret, SecretKind


def verify_htlc_spending_conditions(
    proof: Proof,
) -> bool:
    """
    Verifies an HTLC spending condition.
    Either the preimage is provided or the locktime has passed and a refund is requested.
    """
    secret = Secret.deserialize(proof.secret)
    if not secret.kind or secret.kind != SecretKind.HTLC.value:
        raise TransactionError("not an HTLC secret.")
    htlc_secret = HTLCSecret.from_secret(secret)
    preimage = proof.htlcpreimage
    now = time.time()
    locktime = htlc_secret.locktime
    locktime_passed = locktime is not None and locktime <= now

    # Hash-lock path stays valid forever
    if preimage:
        try:
            if len(preimage) != 64:
                raise TransactionError("HTLC preimage must be 64 characters hex.")
            if sha256(bytes.fromhex(preimage)).digest() != bytes.fromhex(
                htlc_secret.data
            ):
                raise TransactionError("HTLC preimage does not match.")
        except ValueError:
            raise TransactionError("invalid preimage for HTLC: not a hex string.")
        return True

    # Refund path unlocks once the timelock has expired
    if locktime_passed:
        return True

    raise TransactionError("no HTLC preimage provided")
