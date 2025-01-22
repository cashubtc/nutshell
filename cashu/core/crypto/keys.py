import base64
import hashlib
import random
from typing import Dict, List

from bip32 import BIP32

from .secp import PrivateKey, PublicKey


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
    """Deterministic derivation keyset_id from set of public keys."""
    # sort public keys by amount
    sorted_keys = dict(sorted(keys.items()))
    pubkeys_concat = b"".join([p.serialize() for _, p in sorted_keys.items()])
    return f"00{hashlib.sha256(pubkeys_concat).hexdigest()[:14]}"


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
