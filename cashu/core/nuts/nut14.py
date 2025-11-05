import time
from hashlib import sha256

from ..base import Proof
from ..errors import TransactionError
from ..secret import Secret, SecretKind
from .nut11 import P2PKSecret


class HTLCSecret(P2PKSecret, Secret):
    @classmethod
    def from_secret(cls, secret: Secret):
        assert SecretKind(secret.kind) == SecretKind.HTLC, "Secret is not a HTLC secret"
        # NOTE: exclude tags in .dict() because it doesn't deserialize it properly
        # need to add it back in manually with tags=secret.tags
        return cls(**secret.dict(exclude={"tags"}), tags=secret.tags)


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
            if not sha256(bytes.fromhex(proof.htlcpreimage)).digest() == bytes.fromhex(
                htlc_secret.data
            ):
                raise TransactionError("HTLC preimage does not match.")
        except ValueError:
            raise TransactionError("invalid preimage for HTLC: not a hex string.")
    return True
