import base64
import hashlib
import random
from typing import Dict, List, Optional, TYPE_CHECKING

from bip32 import BIP32

from .secp import PrivateKey, PublicKey

if TYPE_CHECKING:
    from ..base import Unit


def derive_keys(mnemonic: str, derivation_path: str, amounts: List[int]):
    """
    Deterministic derivation of keys for 2^n values.
    """
    bip32 = BIP32.from_seed(mnemonic.encode())
    orders_str = [f"/{a}'" for a in range(len(amounts))]
    return {
        a: PrivateKey(
            bip32.get_privkey_from_path(derivation_path + orders_str[i]),
            raw=True,
        )
        for i, a in enumerate(amounts)
    }


def derive_keys_deprecated_pre_0_15(
    seed: str, amounts: List[int], derivation_path: str = ""
):
    """
    Deterministic derivation of keys for 2^n values.
    """
    return {
        a: PrivateKey(
            hashlib.sha256((seed + derivation_path + str(i)).encode("utf-8")).digest()[
                :32
            ],
            raw=True,
        )
        for i, a in enumerate(amounts)
    }


def derive_pubkey(seed: str) -> PublicKey:
    pubkey = PrivateKey(
        hashlib.sha256((seed).encode("utf-8")).digest()[:32],
        raw=True,
    ).pubkey
    assert pubkey
    return pubkey


def derive_pubkeys(keys: Dict[int, PrivateKey], amounts: List[int]):
    return {amt: keys[amt].pubkey for amt in amounts}


def derive_keyset_id(keys: Dict[int, PublicKey]):
    """Deterministic derivation keyset_id from set of public keys (version 00)."""
    # sort public keys by amount
    sorted_keys = dict(sorted(keys.items()))
    pubkeys_concat = b"".join([p.serialize() for _, p in sorted_keys.items()])
    return f"00{hashlib.sha256(pubkeys_concat).hexdigest()[:14]}"


def derive_keyset_id_v2(
    keys: Dict[int, PublicKey], 
    unit: "Unit", 
    final_expiry: Optional[int] = None
) -> str:
    """
    Deterministic derivation keyset_id v2 from set of public keys (version 01).
    
    Args:
        keys: Dictionary mapping amounts to public keys
        unit: The unit of the keyset (e.g., Unit.sat, Unit.usd)
        final_expiry: Optional unix epoch timestamp for keyset expiration
        
    Returns:
        Full 33-byte keyset ID (version byte + 32-byte hash) as hex string
    """
    # sort public keys by amount in ascending order
    sorted_keys = dict(sorted(keys.items()))
    
    # concatenate all public keys to one byte array
    keyset_id_bytes = b"".join([p.serialize() for p in sorted_keys.values()])
    
    # add the lowercase unit string to the byte array
    keyset_id_bytes += f"unit:{unit.name}".encode("utf-8")
    
    # if a final expiration is specified, add it
    if final_expiry is not None:
        keyset_id_bytes += f"final_expiry:{final_expiry}".encode("utf-8")
    
    # SHA256 hash the concatenated byte array
    hash_digest = hashlib.sha256(keyset_id_bytes).hexdigest()
    
    # prefix with version byte 01
    return f"01{hash_digest}"


def derive_keyset_short_id(keyset_id: str) -> str:
    """
    Derive the short keyset ID (8 bytes) from a full keyset ID.
    
    Args:
        keyset_id: Full keyset ID (either version 00 or 01)
        
    Returns:
        Short keyset ID (version byte + first 7 bytes of hash)
    """
    # For version 00, keep existing behavior (already short)
    if keyset_id.startswith("00"):
        return keyset_id
    
    # For version 01, return first 16 chars (8 bytes in hex)
    if keyset_id.startswith("01"):
        return keyset_id[:16]
    
    raise ValueError(f"Unsupported keyset version in ID: {keyset_id}")


def get_keyset_id_version(keyset_id: str) -> str:
    """Extract the version from a keyset ID."""
    if len(keyset_id) < 2:
        raise ValueError("Invalid keyset ID: too short")
    return keyset_id[:2]


def is_keyset_id_v2(keyset_id: str) -> bool:
    """Check if a keyset ID is version 2 (starts with '01')."""
    return keyset_id.startswith("01")


def derive_keyset_id_deprecated(keys: Dict[int, PublicKey]):
    """DEPRECATED 0.15.0: Deterministic derivation keyset_id from set of public keys.
    DEPRECATION: This method produces base64 keyset ids. Use `derive_keyset_id` instead.
    """
    # sort public keys by amount
    sorted_keys = dict(sorted(keys.items()))
    pubkeys_concat = "".join([p.serialize().hex() for _, p in sorted_keys.items()])
    return base64.b64encode(
        hashlib.sha256((pubkeys_concat).encode("utf-8")).digest()
    ).decode()[:12]


def random_hash() -> str:
    """Returns a base64-urlsafe encoded random hash."""
    return base64.urlsafe_b64encode(
        bytes([random.getrandbits(8) for i in range(30)])
    ).decode()
