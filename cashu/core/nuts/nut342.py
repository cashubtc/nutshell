import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_SIZE = 12
_GAP_SIZE = 4
_TAG_SIZE = 16
_MAX_GAP = 2**32 - 1


def encrypt_d_gap(d_gap: int, blinding_factor: bytes) -> str:
    """Encrypt a NUT-342 recovery gap with the output blinding factor."""
    if not 0 <= d_gap <= _MAX_GAP:
        raise ValueError("d_gap must fit in an unsigned 32-bit integer")
    key = hashlib.sha256(blinding_factor).digest()[:16]
    nonce = os.urandom(_NONCE_SIZE)
    encrypted = AESGCM(key).encrypt(nonce, d_gap.to_bytes(_GAP_SIZE, "big"), None)
    return (nonce + encrypted).hex()


def decrypt_d_gap(encrypted_d_gap: str, blinding_factor: bytes) -> int:
    """Decrypt and authenticate NUT-342 recovery gap metadata."""
    payload = bytes.fromhex(encrypted_d_gap)
    expected_size = _NONCE_SIZE + _GAP_SIZE + _TAG_SIZE
    if len(payload) != expected_size:
        raise ValueError("invalid encrypted d_gap length")
    key = hashlib.sha256(blinding_factor).digest()[:16]
    plaintext = AESGCM(key).decrypt(payload[:_NONCE_SIZE], payload[_NONCE_SIZE:], None)
    return int.from_bytes(plaintext, "big")
