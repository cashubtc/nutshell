from typing import List

from ..base import BlindedMessage, Proof


def sigall_message_to_sign(proofs: List[Proof], outputs: List[BlindedMessage]) -> str:
    """
    Creates the message to sign for sigall spending conditions.
    The message is a concatenation of all proof secrets and signatures + all output attributes (amount, id, B_).
    """

    # Concatenate all proof secrets
    message = "".join([p.secret + p.C for p in proofs])

    # Concatenate all output attributes
    message += "".join([str(o.amount) + o.id + o.B_ for o in outputs])

    return message
