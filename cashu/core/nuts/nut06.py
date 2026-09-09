import hashlib
import hmac
import json
import os
import time
from typing import Any, Mapping, Optional

import rfc8785
from coincurve import PrivateKey, PublicKeyXOnly

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MINT_IDENTITY_DOMAIN_SEPARATOR = b"Cashu_Mint_Identity_v1"
MINT_INFO_TAG_HASH = hashlib.sha256(b"Cashu_MintInfo_v1").digest()
MINT_INFO_CHALLENGE_BYTES = 32
MINT_INFO_TIME_WINDOW = 3600


def derive_mint_identity_key(seed: bytes) -> PrivateKey:
    """Derive the NUT-06 mint identity key using rejection-sampled HMAC-SHA256."""
    for counter in range(256):
        digest = hmac.digest(
            seed, MINT_IDENTITY_DOMAIN_SEPARATOR + bytes([counter]), hashlib.sha256
        )
        scalar = int.from_bytes(digest, "big")
        if 0 < scalar < SECP256K1_ORDER:
            return PrivateKey(digest)
    raise Exception("could not derive a valid mint identity key")


def canonicalize_mint_info(info: Mapping[str, Any]) -> bytes:
    """Return the RFC 8785 payload, excluding only the NUT-06 signature."""
    payload = dict(info)
    payload.pop("signature", None)
    normalized = json.loads(json.dumps(payload))
    return rfc8785.dumps(normalized)


def mint_info_message_hash(info: Mapping[str, Any]) -> bytes:
    """Hash the canonical payload with the BIP-340 Cashu_MintInfo_v1 tag."""
    return hashlib.sha256(
        MINT_INFO_TAG_HASH + MINT_INFO_TAG_HASH + canonicalize_mint_info(info)
    ).digest()


def is_valid_mint_info_challenge(challenge: object) -> bool:
    """Check the challenge's length before inspecting its lowercase hex encoding."""
    return (
        isinstance(challenge, str)
        and len(challenge) == 2 * MINT_INFO_CHALLENGE_BYTES
        and all(char in "0123456789abcdef" for char in challenge)
    )


def sign_mint_info(
    info: Mapping[str, Any],
    private_key: PrivateKey,
    aux_randomness: Optional[bytes] = None,
) -> bytes:
    message_hash = mint_info_message_hash(info)
    return private_key.sign_schnorr(
        message_hash, aux_randomness if aux_randomness is not None else os.urandom(32)
    )


def verify_mint_info_signature(
    info: Mapping[str, Any],
    signature: bytes,
    pubkey: bytes,
    verifier_time: Optional[int] = None,
    expected_challenge: Optional[str] = None,
) -> bool:
    if len(signature) != 64 or len(pubkey) != 33 or pubkey[0] not in (2, 3):
        return False
    if expected_challenge is not None and (
        not is_valid_mint_info_challenge(info.get("challenge"))
        or info["challenge"] != expected_challenge
    ):
        return False
    mint_time = info.get("time")
    if isinstance(mint_time, bool) or not isinstance(mint_time, int):
        return False
    now = int(time.time()) if verifier_time is None else verifier_time
    if abs(mint_time - now) > MINT_INFO_TIME_WINDOW:
        return False
    message_hash = mint_info_message_hash(info)
    try:
        return PublicKeyXOnly(pubkey[1:]).verify(signature, message_hash)
    except ValueError:
        return False
