import hashlib
import hmac
import json
import os
from typing import Any, Mapping, Optional

import rfc8785
from coincurve import PrivateKey, PublicKeyXOnly

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MINT_IDENTITY_DOMAIN_SEPARATOR = b"Cashu_Mint_Identity_v1"


def derive_mint_identity_key(seed: bytes) -> PrivateKey:
    """Derive the NUT-06 mint identity key using rejection-sampled HMAC-SHA256."""
    for counter in range(256):
        digest = hmac.digest(
            seed, MINT_IDENTITY_DOMAIN_SEPARATOR + bytes([counter]), hashlib.sha256
        )
        scalar = int.from_bytes(digest, "big")
        if 0 < scalar < SECP256K1_ORDER:
            return PrivateKey(digest)
    raise RuntimeError("could not derive a valid mint identity key")


def canonicalize_mint_info(info: Mapping[str, Any]) -> bytes:
    """Return the RFC 8785 payload, excluding the NUT-06 unsigned fields."""
    payload = dict(info)
    payload.pop("signature", None)
    payload.pop("time", None)
    normalized = json.loads(json.dumps(payload))
    return rfc8785.dumps(normalized)


def sign_mint_info(
    info: Mapping[str, Any],
    private_key: PrivateKey,
    aux_randomness: Optional[bytes] = None,
) -> bytes:
    message_hash = hashlib.sha256(canonicalize_mint_info(info)).digest()
    return private_key.sign_schnorr(
        message_hash, aux_randomness if aux_randomness is not None else os.urandom(32)
    )


def verify_mint_info_signature(
    info: Mapping[str, Any], signature: bytes, pubkey: bytes
) -> bool:
    message_hash = hashlib.sha256(canonicalize_mint_info(info)).digest()
    return PublicKeyXOnly(pubkey[1:]).verify(signature, message_hash)
