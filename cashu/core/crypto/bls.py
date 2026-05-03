import os
from typing import Optional

from py_ecc.bls.point_compression import (
    compress_G1,
    compress_G2,
    decompress_G1,
    decompress_G2,
)
from py_ecc.optimized_bls12_381 import (
    G2,
    curve_order,
    eq,
    multiply,
)


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
        pt = multiply(G2, self.scalar)
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
                    z = int.from_bytes(compressed, "big")
                    self.point = decompress_G1(z)  # type: ignore
                else:
                    z1 = int.from_bytes(compressed[:48], "big")
                    z2 = int.from_bytes(compressed[48:], "big")
                    self.point = decompress_G2((z1, z2))  # type: ignore
            else:
                raise ValueError("Must provide point or compressed bytes")
        except Exception:
            raise ValueError("The public key could not be parsed or is invalid.")

    def format(self, compressed: bool = True) -> bytes:
        if self.group == "G1":
            z = compress_G1(self.point)
            return z.to_bytes(48, "big")
        else:
            z1, z2 = compress_G2(self.point)
            return z1.to_bytes(48, "big") + z2.to_bytes(48, "big")

    def serialize(self) -> bytes:
        return self.format()

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            return eq(self.point, other.point)
        return False

    def __mul__(self, scalar):
        if isinstance(scalar, PrivateKey):
            return PublicKey(point=multiply(self.point, scalar.scalar), group=self.group)
        elif isinstance(scalar, int):
            return PublicKey(point=multiply(self.point, scalar), group=self.group)
        raise TypeError("Can't multiply with non-scalar")
