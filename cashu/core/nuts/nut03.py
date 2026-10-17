"""Additive unpoisonable V2 swap output derivation."""

from hashlib import sha256
from typing import List

from ..base import BlindedMessage
from ..crypto.secp import PrivateKey, PublicKey

SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
TWEAK_TAG = b"Cashu_UnpoisonableTweak_secp256k1_v1"


class PointAtInfinity(ValueError):
    """Adding the tweak to a valid point produced infinity."""


def derive_tweak(randomness: bytes) -> bytes:
    if len(randomness) != 32:
        raise ValueError("R must be 32 bytes")
    tag = sha256(TWEAK_TAG).digest()
    for counter in range(2**32):
        candidate = sha256(tag + tag + randomness + counter.to_bytes(4, "big")).digest()
        if 0 < int.from_bytes(candidate, "big") < SECP256K1_ORDER:
            return candidate
    raise ValueError("could not derive a nonzero tweak")


def tweak_outputs(
    outputs: List[BlindedMessage], randomness: bytes
) -> List[BlindedMessage]:
    tweak_point = PrivateKey(derive_tweak(randomness)).public_key
    tweaked = []
    for output in outputs:
        original = PublicKey(bytes.fromhex(output.B_))
        try:
            point = original.combine([tweak_point])
        except ValueError as exc:
            raise PointAtInfinity() from exc
        tweaked.append(output.model_copy(update={"B_": point.format().hex()}))
    return tweaked
