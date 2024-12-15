from hashlib import sha256
from typing import List

from ..base import BlindedMessage
from ..crypto.secp import PrivateKey, PublicKey


def generate_keypair() -> tuple[str, str]:
    privkey = PrivateKey()
    assert privkey.pubkey
    pubkey = privkey.pubkey
    return privkey.serialize(), pubkey.serialize(True).hex()


def construct_message(quote_id: str, outputs: List[BlindedMessage]) -> bytes:
    serialized_outputs = b"".join([o.B_.encode("utf-8") for o in outputs])
    msgbytes = sha256(quote_id.encode("utf-8") + serialized_outputs).digest()
    return msgbytes


def sign_mint_quote(
    quote_id: str,
    outputs: List[BlindedMessage],
    private_key: str,
) -> str:
    privkey = PrivateKey(bytes.fromhex(private_key), raw=True)
    msgbytes = construct_message(quote_id, outputs)
    sig = privkey.schnorr_sign(msgbytes, None, raw=True)
    return sig.hex()


def verify_mint_quote(
    quote_id: str,
    outputs: List[BlindedMessage],
    public_key: str,
    signature: str,
) -> bool:
    pubkey = PublicKey(bytes.fromhex(public_key), raw=True)
    msgbytes = construct_message(quote_id, outputs)
    sig = bytes.fromhex(signature)
    return pubkey.schnorr_verify(msgbytes, sig, None, raw=True)
