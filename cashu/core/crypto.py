import base64
import hashlib
from typing import Dict, List

from cashu.core.secp import PrivateKey, PublicKey
from cashu.core.settings import MAX_ORDER

# entropy = bytes([random.getrandbits(8) for i in range(16)])
# mnemonic = bip39.mnemonic_from_bytes(entropy)
# seed = bip39.mnemonic_to_seed(mnemonic)
# root = bip32.HDKey.from_seed(seed, version=NETWORKS["main"]["xprv"])

# bip44_xprv = root.derive("m/44h/1h/0h")
# bip44_xpub = bip44_xprv.to_public()


def derive_keys(master_key: str, derivation_path: str = ""):
    """
    Deterministic derivation of keys for 2^n values.
    TODO: Implement BIP32.
    """
    return {
        2
        ** i: PrivateKey(
            hashlib.sha256((str(master_key) + derivation_path + str(i)).encode("utf-8"))
            .hexdigest()
            .encode("utf-8")[:32],
            raw=True,
        )
        for i in range(MAX_ORDER)
    }


def derive_pubkeys(keys: Dict[int, PrivateKey]):
    return {amt: keys[amt].pubkey for amt in [2**i for i in range(MAX_ORDER)]}


def derive_keyset_id(keys: Dict[int, PublicKey]):
    """Deterministic derivation keyset_id from set of public keys."""
    # sort public keys by amount
    sorted_keys = dict(sorted(keys.items()))
    pubkeys_concat = "".join([p.serialize().hex() for _, p in sorted_keys.items()])
    return base64.b64encode(
        hashlib.sha256((pubkeys_concat).encode("utf-8")).digest()
    ).decode()[:12]
