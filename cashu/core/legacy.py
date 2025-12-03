import hashlib

from ..core.crypto.secp import PrivateKey
from ..core.settings import settings


def derive_keys_backwards_compatible_insecure_pre_0_12(
    seed: str, derivation_path: str = ""
):
    """
    WARNING: Broken key derivation for backwards compatibility with 0.11.
    """
    return {
        2**i: PrivateKey(
            hashlib.sha256((seed + derivation_path + str(i)).encode("utf-8"))
            .hexdigest()
            .encode("utf-8")[:32]
        )
        for i in range(settings.max_order)
    }
