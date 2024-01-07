import base64
import hashlib
import random
from typing import Dict

from bip32 import BIP32

from ..settings import settings
from .secp import PrivateKey, PublicKey


def derive_keys(mnemonic: str, derivation_path: str):
    """
    Deterministic derivation of keys for 2^n values.
    """
    bip32 = BIP32.from_seed(mnemonic.encode())
    orders_str = [f"/{i}'" for i in range(settings.max_order)]
    return {
        2
        ** i: PrivateKey(
            bip32.get_privkey_from_path(derivation_path + orders_str[i]),
            raw=True,
        )
        for i in range(settings.max_order)
    }


def derive_keys_sha256(master_key: str, derivation_path: str = ""):
    """
    Deterministic derivation of keys for 2^n values.
    TODO: Implement BIP32.
    """
    return {
        2
        ** i: PrivateKey(
            hashlib.sha256(
                (master_key + derivation_path + str(i)).encode("utf-8")
            ).digest()[:32],
            raw=True,
        )
        for i in range(settings.max_order)
    }


def derive_pubkey(master_key: str):
    return PrivateKey(
        hashlib.sha256((master_key).encode("utf-8")).digest()[:32],
        raw=True,
    ).pubkey


def derive_pubkeys(keys: Dict[int, PrivateKey]):
    return {amt: keys[amt].pubkey for amt in [2**i for i in range(settings.max_order)]}


def derive_keyset_id(keys: Dict[int, PublicKey]):
    """Deterministic derivation keyset_id from set of public keys."""
    # sort public keys by amount
    sorted_keys = dict(sorted(keys.items()))
    pubkeys_concat = b"".join([p.serialize() for _, p in sorted_keys.items()])
    return "00" + hashlib.sha256(pubkeys_concat).hexdigest()[:14]


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
