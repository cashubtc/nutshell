import hashlib
import os
from typing import List, Optional, Tuple

from .crypto.secp import PrivateKey, PublicKey

# Domain separator for P2BK blinding scalar derivation
P2BK_DOMAIN_SEPARATOR = b"Cashu_P2BK_v1"

# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def _compressed_pubkey(pubkey_hex: str) -> str:
    """Ensure a pubkey is in compressed SEC1 format (33 bytes / 66 hex chars).
    Silently adds '02' prefix to bare 32-byte (BIP-340 / Nostr) x-only keys.
    """
    raw = bytes.fromhex(pubkey_hex)
    if len(raw) == 32:
        # x-only key, add 02 prefix
        return "02" + pubkey_hex
    if len(raw) == 33 and raw[0] in (0x02, 0x03):
        return pubkey_hex
    raise ValueError(f"Invalid pubkey length: {len(raw)} bytes")

def ecdh_shared_secret(point: PublicKey, scalar: PrivateKey) -> bytes:
    """Compute x-only ECDH shared secret Zx = x(scalar * point)"""
    shared_point = point.multiply(bytes.fromhex(scalar.to_hex()))
    # compressed format is prefix (1 byte) + x-coordinate (32 bytes)
    compressed = shared_point.format(compressed=True)
    return compressed[1:]  # strip the 02/03 prefix to get Zx

def derive_blinding_scalar(zx: bytes, slot_index: int) -> int:
    """Derive a deterministic blinding scalar r_i from ECDH shared secret and slot index."""
    i_byte = bytes([slot_index & 0xFF])
    data = P2BK_DOMAIN_SEPARATOR + zx + i_byte
    r = int.from_bytes(hashlib.sha256(data).digest(), "big")
    if r == 0 or r >= SECP256K1_ORDER:
        # retry with 0xff appended
        data_retry = data + b"\xff"
        r = int.from_bytes(hashlib.sha256(data_retry).digest(), "big")
        if r == 0 or r >= SECP256K1_ORDER:
            raise ValueError("P2BK: blinding scalar derivation failed")
    return r

def _scalar_to_privkey(scalar: int) -> PrivateKey:
    """Convert an integer scalar to a PrivateKey."""
    return PrivateKey(scalar.to_bytes(32, "big"))

def _pubkey_x(pubkey: PublicKey) -> bytes:
    """Get the x-coordinate (32 bytes) from a compressed public key."""
    return pubkey.format(compressed=True)[1:]

def blind_pubkeys(
    data_pubkey: str, 
    additional_pubkeys: List[str], 
    refund_pubkeys: List[str], 
    receiver_pubkey: str,
    ephemeral_privkey: Optional[PrivateKey] = None,
) -> Tuple[str, List[str], List[str], str]:
    """blind all pubkeys in a P2PK secret using ECDH.

    Args:
        data_pubkey: The main locking pubkey.
        additional_pubkeys: Additional pubkeys from the "pubkeys" tag.
        refund_pubkeys: Refund pubkeys from the "refund" tag.
        receiver_pubkey: The receiver's long-lived pubkey P (used for ECDH).
        ephemeral_privkey: Optional ephemeral private key. Generated if None.

    Returns:
        Tuple of (blinded_data_pubkey, blinded_additional, blinded_refund, ephemeral_pubkey_hex)
    """
    receiver_pubkey_hex = _compressed_pubkey(receiver_pubkey)
    receiver_pk = PublicKey(bytes.fromhex(receiver_pubkey_hex))

    if ephemeral_privkey is None:
        ephemeral_privkey = PrivateKey(os.urandom(32))

    assert ephemeral_privkey.public_key
    ephemeral_pubkey_hex = ephemeral_privkey.public_key.format(compressed=True).hex()

    # compute ECDH shared secret Zx = x(e * P)
    zx = ecdh_shared_secret(receiver_pk, ephemeral_privkey)

    # collect all pubkeys in slot order: [data, ...pubkeys, ...refund]
    all_pubkeys = [data_pubkey] + additional_pubkeys + refund_pubkeys
    blinded = []
    for i, pk_hex in enumerate(all_pubkeys):
        pk_hex = _compressed_pubkey(pk_hex)
        pk = PublicKey(bytes.fromhex(pk_hex))
        r_i = derive_blinding_scalar(zx, i)
        blinding_point = _scalar_to_privkey(r_i).public_key
        assert blinding_point
        blinded_pk = pk + blinding_point  # P' = P + r_i*G
        blinded.append(blinded_pk.format(compressed=True).hex())

    # split back into data, pubkeys, refund
    blinded_data = blinded[0]
    blinded_additional = blinded[1 : 1 + len(additional_pubkeys)]
    blinded_refund = blinded[1 + len(additional_pubkeys) :]

    return blinded_data, blinded_additional, blinded_refund, ephemeral_pubkey_hex


def derive_blinded_private_key(
    privkey: PrivateKey,
    ephemeral_pubkey_hex: str,
    blinded_pubkey_hex: str,
    slot_index: int,
) -> Optional[PrivateKey]:
    """derive the blinded private key for a given slot.

    Args:
        privkey: Receiver's long-lived private key p.
        ephemeral_pubkey_hex: Sender's ephemeral public key E (hex, 33 bytes).
        blinded_pubkey_hex: The blinded public key P' from the secret.
        slot_index: The slot index i.

    Returns:
        The blinded PrivateKey k, or None if this slot is not for this key.
    """
    ephemeral_pubkey_hex = _compressed_pubkey(ephemeral_pubkey_hex)
    E = PublicKey(bytes.fromhex(ephemeral_pubkey_hex))

    # Zx = x(p * E)
    zx = ecdh_shared_secret(E, privkey)

    r_i = derive_blinding_scalar(zx, slot_index)

    # R_i = r_i * G
    r_i_key = _scalar_to_privkey(r_i)
    R_i = r_i_key.public_key
    assert R_i

    # Unblind: P = P' - R_i
    blinded_pubkey_hex = _compressed_pubkey(blinded_pubkey_hex)
    P_prime = PublicKey(bytes.fromhex(blinded_pubkey_hex))
    P = P_prime - R_i  # type: ignore

    # Verify x(P) == x(p*G)
    assert privkey.public_key
    pG = privkey.public_key
    if _pubkey_x(P) != _pubkey_x(pG):
        return None  # this slot is not for this key

    # Parity check
    p_int = int.from_bytes(bytes.fromhex(privkey.to_hex()), "big")
    P_prefix = P.format(compressed=True)[0]
    pG_prefix = pG.format(compressed=True)[0]

    if P_prefix == pG_prefix:
        # standard derivation: k = (p + r_i) mod n
        k = (p_int + r_i) % SECP256K1_ORDER
    else:
        # negated derivation: k = (-p + r_i) mod n
        k = ((-p_int) + r_i) % SECP256K1_ORDER

    return _scalar_to_privkey(k)