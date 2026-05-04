import os
from typing import Optional


import pyblst
curve_order = 52435875175126190479447740508185965837690552500527637822603658699938581184513
_G2_HEX = '93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'



class PrivateKey:
    def __init__(self, privkey: bytes = b"", scalar: Optional[int] = None):
        if scalar is not None:
            self.scalar = scalar % curve_order
        elif privkey:
            self.scalar = int.from_bytes(privkey, "big") % curve_order
        else:
            self.scalar = int.from_bytes(os.urandom(32), "big") % curve_order

    @property
    def private_key(self) -> bytes:
        return self.scalar.to_bytes(32, "big")

    def to_hex(self) -> str:
        return self.private_key.hex()

    def get_g2_public_key(self) -> "PublicKey":
        pt = pyblst.BlstP2Element().uncompress(bytes.fromhex(_G2_HEX)).scalar_mul(self.scalar)
        return PublicKey(point=pt, group="G2")

    @property
    def public_key(self) -> "PublicKey":
        return self.get_g2_public_key()


class PublicKey:
    def __init__(self, compressed: bytes = b"", point=None, group="G1"):
        self.group = group
        try:
            if point is not None:
                self.point = point
            elif compressed:
                if self.group == "G1":
                    self.point = pyblst.BlstP1Element().uncompress(compressed)
                else:
                    self.point = pyblst.BlstP2Element().uncompress(compressed)
            else:
                raise ValueError("Must provide point or compressed bytes")
        except Exception:
            raise ValueError("The public key could not be parsed or is invalid.")

    def format(self, compressed: bool = True) -> bytes:
        return self.point.compress()

    def serialize(self) -> bytes:
        return self.format()

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            return self.point == other.point
        return False

    def __mul__(self, scalar):
        if isinstance(scalar, PrivateKey):
            return PublicKey(point=self.point.scalar_mul(scalar.scalar), group=self.group)
        elif isinstance(scalar, int):
            return PublicKey(point=self.point.scalar_mul(scalar), group=self.group)
        raise TypeError("Can't multiply with non-scalar")
