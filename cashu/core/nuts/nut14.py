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
    # hash lock
    if not proof.htlcpreimage:
        raise TransactionError("no HTLC preimage provided")
    # verify correct preimage (the hashlock) if the locktime hasn't passed
    now = time.time()
    if not htlc_secret.locktime or htlc_secret.locktime > now:
        try:
            if len(proof.htlcpreimage) != 64:
                raise TransactionError("HTLC preimage must be 64 characters hex.")
            if not sha256(
                bytes.fromhex(proof.htlcpreimage)
            ).digest() == bytes.fromhex(htlc_secret.data):
                raise TransactionError("HTLC preimage does not match.")
        except ValueError:
            raise TransactionError("invalid preimage for HTLC: not a hex string.")
    return True

