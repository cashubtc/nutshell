from hashlib import sha256
from typing import List

from coincurve import PublicKeyXOnly

from ..base import BlindedMessage
from ..crypto.secp import PrivateKey


def generate_keypair() -> tuple[str, str]:
    privkey = PrivateKey()
    assert privkey.public_key
    pubkey = privkey.public_key
    return privkey.to_hex(), pubkey.format().hex()


def construct_message(quote_id: str, outputs: List[BlindedMessage]) -> bytes:
    serialized_outputs = b"".join([o.B_.encode("utf-8") for o in outputs])
    msgbytes = sha256(quote_id.encode("utf-8") + serialized_outputs).digest()
    return msgbytes


def sign_mint_quote(
    quote_id: str,
    outputs: List[BlindedMessage],
    private_key: str,
) -> str:

    privkey = PrivateKey(bytes.fromhex(private_key))
    msgbytes = construct_message(quote_id, outputs)
    sig = privkey.sign_schnorr(msgbytes)
    return sig.hex()


def verify_mint_quote(
    quote_id: str,
    outputs: List[BlindedMessage],
    public_key: str,
    signature: str,
) -> bool:
    pubkey = PublicKeyXOnly(bytes.fromhex(public_key)[1:])
    msgbytes = construct_message(quote_id, outputs)
    sig = bytes.fromhex(signature)
    return pubkey.verify(sig, msgbytes)
