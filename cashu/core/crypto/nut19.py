from hashlib import sha256
from typing import List

from secp import PrivateKey, PublicKey

from ..base import BlindedMessage


def construct_message(quote_id: str, outputs: List[BlindedMessage]) -> bytes:
    serialized_outputs = bytes.fromhex("".join([o.B_ for o in outputs]))
    msgbytes = sha256(
        quote_id.encode("utf-8")
        + serialized_outputs
    ).digest()
    return msgbytes

def sign_mint_quote(
    quote_id: str,
    outputs: List[BlindedMessage],
    privkey: PrivateKey,
) -> str:
    msgbytes = construct_message(quote_id, outputs)
    sig = privkey.schnorr_sign(msgbytes)
    return sig.hex()

def verify_mint_quote(
    quote_id: str,
    outputs: List[BlindedMessage],
    pubkey: PublicKey,
    signature: str,
) -> bool:
    msgbytes = construct_message(quote_id, outputs)
    sig = bytes.fromhex(signature)
    return pubkey.schnorr_verify(msgbytes, sig)