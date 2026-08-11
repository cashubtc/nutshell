from typing import List

from ..base import BlindedMessage, Proof


def sigall_message_to_sign(proofs: List[Proof], outputs: List[BlindedMessage]) -> str:
    """
    Creates the message to sign for SIG_ALL spending conditions.

    The message is the concatenation of each proof's secret and C fields,
    followed by each output's amount and B_ fields.
    """

    message = "".join([p.secret + p.C for p in proofs])
    message += "".join([str(o.amount) + o.B_ for o in outputs])

    return message
