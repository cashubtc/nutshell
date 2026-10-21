from hashlib import sha256
from typing import List

from coincurve import PublicKeyXOnly
from loguru import logger

from ..base import BlindedMessage
from ..crypto.secp import PrivateKey


def generate_keypair() -> tuple[str, str]:
    privkey = PrivateKey()
    assert privkey.public_key
    pubkey = privkey.public_key
    return privkey.to_hex(), pubkey.format().hex()


def int_to_minimal_bytes(val: int) -> bytes:
    if val == 0:
        return b""
    return val.to_bytes((val.bit_length() + 7) // 8, "big")


def construct_message(quote_id: str, outputs: List[BlindedMessage]) -> bytes:
    dst = b"Cashu_MintQuoteSig_v1"
    quote_bytes = quote_id.encode("utf-8")
    msg = dst + len(quote_bytes).to_bytes(4, "big") + quote_bytes
    for o in outputs:
        amount_bytes = int_to_minimal_bytes(o.amount)
        b_bytes = bytes.fromhex(o.B_)
        msg += len(amount_bytes).to_bytes(4, "big") + amount_bytes
        msg += len(b_bytes).to_bytes(4, "big") + b_bytes
    return sha256(msg).digest()


def sign_mint_quote(
    quote_id: str,
    outputs: List[BlindedMessage],
    private_key: str,
) -> str:
    privkey = PrivateKey(bytes.fromhex(private_key))
    msgbytes = construct_message(quote_id, outputs)
    sig = privkey.sign_schnorr(msgbytes)
    return sig.hex()


def construct_message_legacy(quote_id: str, outputs: List[BlindedMessage]) -> bytes:
    serialized_outputs = b"".join([o.B_.encode("utf-8") for o in outputs])
    msgbytes = sha256(quote_id.encode("utf-8") + serialized_outputs).digest()
    return msgbytes


def verify_mint_quote(
    quote_id: str,
    outputs: List[BlindedMessage],
    public_key: str,
    signature: str,
) -> bool:
    pubkey = PublicKeyXOnly(bytes.fromhex(public_key)[1:])
    sig = bytes.fromhex(signature)

    # Try verifying with the new spec method first
    msgbytes = construct_message(quote_id, outputs)
    try:
        if pubkey.verify(sig, msgbytes):
            return True
    except Exception:
        pass

    # Fallback to the legacy method for backward compatibility
    # Deprecated since version 0.20.2
    logger.warning(
        "Using legacy NUT-20 signature verification. This fallback is deprecated since version 0.20.2."
    )
    msgbytes_legacy = construct_message_legacy(quote_id, outputs)
    try:
        return pubkey.verify(sig, msgbytes_legacy)
    except Exception:
        return False
