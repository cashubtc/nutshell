import os
from typing import Optional

import pyblst

curve_order = 52435875175126190479447740508185965837690552500527637822603658699938581184513
_G2_HEX = '93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'

# Canonical compressed encodings of the BLS12-381 identity (point at infinity):
# top bit = compression flag, second bit = infinity flag, remaining bytes zero.
# blst's `uncompress` validates canonical encoding and on-curve, but accepts the
# identity and does NOT check prime-order subgroup membership; both checks are
# required by NUT-00 Point Validation and are enforced in PublicKey below.
_G1_IDENTITY = bytes.fromhex('c0' + '00' * 47)
_G2_IDENTITY = bytes.fromhex('c0' + '00' * 95)


def _is_in_subgroup(point, group: str) -> bool:
    """
    NUT-00 Point Validation: a point P is in the prime-order subgroup iff P * q == 0.

    pyblst does not expose blst's fast endomorphism-based `in_g1` / `in_g2` / `KeyValidate`
    predicates, so we fall back to the textbook test by scalar-multiplying by the subgroup
    order. This costs ~one full scalar multiplication per parsed point. When pyblst grows
    a predicate, swap this for the fast check.
    """
    identity = _G1_IDENTITY if group == "G1" else _G2_IDENTITY
    return point.scalar_mul(curve_order).compress() == identity



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
                # Internally-constructed point; trusted (already passed validation when parsed
                # from bytes, or produced from scalar mul of a validated generator).
                self.point = point
            elif compressed:
                # External bytes: full NUT-00 Point Validation. blst's uncompress already
                # rejects non-canonical encodings (BLST_BAD_ENCODING) and off-curve points;
                # we add the identity and subgroup checks it does not perform.
                if self.group == "G1":
                    self.point = pyblst.BlstP1Element().uncompress(compressed)
                    if self.point.compress() == _G1_IDENTITY:
                        raise ValueError("G1 point at infinity")
                    if not _is_in_subgroup(self.point, "G1"):
                        raise ValueError("G1 point not in prime-order subgroup")
                else:
                    self.point = pyblst.BlstP2Element().uncompress(compressed)
                    if self.point.compress() == _G2_IDENTITY:
                        raise ValueError("G2 point at infinity")
                    if not _is_in_subgroup(self.point, "G2"):
                        raise ValueError("G2 point not in prime-order subgroup")
            else:
                raise ValueError("Must provide point or compressed bytes")
        except ValueError:
            raise
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
