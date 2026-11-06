from hashlib import sha256
from typing import List, Optional

from ..base import BlindedMessage, Proof
from .nut20 import int_to_minimal_bytes

SIGALL_SIG_TAG_V1 = "Cashu_SigAllSig_v1"


def tagged_hash(tag: str, message: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || message)."""
    tag_hash = sha256(tag.encode("utf-8")).digest()
    return sha256(tag_hash + tag_hash + message).digest()


def _len_prefixed(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def sigall_message_to_sign_v1(
    proofs: List[Proof],
    outputs: List[BlindedMessage],
    quote_id: Optional[str] = None,
) -> bytes:
    """
    Creates the NUT-11 v1 SIG_ALL message: typed records of length-framed fields.

    Each proof is 0x11 || secret || C, each output 0x21 || amount || SHA256(B_),
    and a melt ends with 0x22 || quote id. The value signed is
    `sigall_message_hash_v1`, not the SHA-256 of this message.
    """
    msg = bytearray()
    for p in proofs:
        msg += b"\x11" + _len_prefixed(p.secret.encode("utf-8"))
        msg += _len_prefixed(bytes.fromhex(p.C))
    for o in outputs:
        msg += b"\x21" + _len_prefixed(int_to_minimal_bytes(o.amount))
        msg += _len_prefixed(sha256(bytes.fromhex(o.B_)).digest())
    if quote_id:
        msg += b"\x22" + _len_prefixed(quote_id.encode("utf-8"))
    return bytes(msg)


def sigall_message_hash_v1(
    proofs: List[Proof],
    outputs: List[BlindedMessage],
    quote_id: Optional[str] = None,
) -> bytes:
    """32-byte NUT-11 v1 SIG_ALL digest, signed directly with Schnorr."""
    return tagged_hash(
        SIGALL_SIG_TAG_V1, sigall_message_to_sign_v1(proofs, outputs, quote_id)
    )


def sigall_message_to_sign(proofs: List[Proof], outputs: List[BlindedMessage]) -> str:
    """
    Creates the message to sign for SIG_ALL spending conditions.

    The message is the concatenation of each proof's secret and C fields,
    followed by each output's amount and B_ fields.
    """

    message = "".join([p.secret + p.C for p in proofs])
    message += "".join([str(o.amount) + o.B_ for o in outputs])

    return message
