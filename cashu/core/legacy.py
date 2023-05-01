import hashlib

from secp256k1 import PrivateKey, PublicKey

from ..core.settings import settings


def hash_to_point_pre_0_3_3(secret_msg):
    """
    NOTE: Clients pre 0.3.3 used a different hash_to_curve

    Generates x coordinate from the message hash and checks if the point lies on the curve.
    If it does not, it tries computing again a new x coordinate from the hash of the coordinate.
    """
    point = None
    msg = secret_msg
    while point is None:
        _hash = hashlib.sha256(msg).hexdigest().encode("utf-8")  # type: ignore
        try:
            # We construct compressed pub which has x coordinate encoded with even y
            _hash = list(_hash[:33])  # take the 33 bytes and get a list of bytes
            _hash[0] = 0x02  # set first byte to represent even y coord
            _hash = bytes(_hash)
            point = PublicKey(_hash, raw=True)
        except:
            msg = _hash

    return point


def verify_pre_0_3_3(a, C, secret_msg):
    Y = hash_to_point_pre_0_3_3(secret_msg.encode("utf-8"))
    return C == Y.mult(a)  # type: ignore


def derive_keys_backwards_compatible_insecure_pre_0_12(
    master_key: str, derivation_path: str = ""
):
    """
    WARNING: Broken key derivation for backwards compatibility with 0.11.
    """
    return {
        2
        ** i: PrivateKey(
            hashlib.sha256((master_key + derivation_path + str(i)).encode("utf-8"))
            .hexdigest()
            .encode("utf-8")[:32],
            raw=True,
        )
        for i in range(settings.max_order)
    }
