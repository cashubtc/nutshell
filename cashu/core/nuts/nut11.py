from hashlib import sha256
from typing import List

from ..base import BlindedMessage, Proof
from .nut20 import int_to_minimal_bytes


def sigall_message_to_sign(proofs: List[Proof], outputs: List[BlindedMessage]) -> str:
    """
    Creates the message to sign for SIG_ALL spending conditions.

    The message is the concatenation of each proof's secret and C fields,
    followed by each output's amount and B_ fields.
    """

    message = "".join([p.secret + p.C for p in proofs])
    message += "".join([str(o.amount) + o.B_ for o in outputs])

    return message


def rerandomized_sigall_digest(
    proofs: List[Proof], outputs: List[BlindedMessage]
) -> bytes:
    """Tagged digest for V2 mint-rerandomized swaps; ordinary SIG_ALL is unchanged."""
    message = bytearray()

    def frame(data: bytes) -> None:
        message.extend(len(data).to_bytes(4, "big"))
        message.extend(data)

    frame(b"")  # empty swap-context frame
    for proof in proofs:
        frame(proof.secret.encode("utf-8"))
        frame(bytes.fromhex(proof.C))
    for output in outputs:
        frame(int_to_minimal_bytes(output.amount))
        # Breaking transcript update: commit to the original compressed point's
        # 32-byte SHA-256 digest directly, without a length frame.
        message.extend(sha256(bytes.fromhex(output.B_)).digest())

    tag_hash = sha256(b"Cashu_SigAllRerandomized_v1").digest()
    return sha256(tag_hash + tag_hash + message).digest()
