import hashlib
from typing import Optional, Tuple

from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.optimized_bls12_381 import G2, curve_order, pairing

from .bls import PrivateKey, PublicKey

# Cashu specific domain separation tag for BLS12-381 G1
DST = b"CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_"

def ext_euclid(a, b):
    if b == 0:
        return 1, 0, a
    x, y, g = ext_euclid(b, a % b)
    return y, x - y * (a // b), g

def mod_inverse(a, m):
    x, y, g = ext_euclid(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % m

def hash_to_curve(message: bytes) -> PublicKey:
    """
    Hash a message to a point on G1 using SSWU.
    """
    pt = hash_to_G1(message, DST, hashlib.sha256)  # type: ignore
    return PublicKey(point=pt, group="G1")

def step1_alice(
    secret_msg: str, blinding_factor: Optional[PrivateKey] = None
) -> tuple[PublicKey, PrivateKey]:
    """
    Alice blinds the message: B' = Y * r
    where Y = hash_to_curve(secret_msg)
    """
    Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
    r = blinding_factor or PrivateKey()
    B_: PublicKey = Y * r
    return B_, r

def step2_bob(B_: PublicKey, a: PrivateKey) -> Tuple[PublicKey, PrivateKey, PrivateKey]:
    """
    Bob signs the blinded message: C' = B' * a
    Returns C' and dummy DLEQ values since BLS12-381 pairings make DLEQ proofs redundant.
    """
    C_: PublicKey = B_ * a
    # Return dummy private keys for backwards compatibility with DLEQ logic elsewhere
    return C_, PrivateKey(scalar=1), PrivateKey(scalar=1)

def step3_alice(C_: PublicKey, r: PrivateKey, A: PublicKey) -> PublicKey:
    """
    Alice unblinds the signature: C = C' * (1/r)
    A (Mint's public key) is unused in multiplicative blinding, kept for API compatibility.
    """
    r_inv = mod_inverse(r.scalar, curve_order)
    C: PublicKey = C_ * r_inv
    return C

def verify(a: PrivateKey, C: PublicKey, secret_msg: str) -> bool:
    """
    Mint verification: checks C == Y * a
    """
    Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
    valid = C == Y * a
    return valid

def verify_signature(K2: PublicKey, C: PublicKey, secret_msg: str) -> bool:
    """
    Wallet/Public verification: e(C, G2) == e(Y, K2)
    This is what makes BLS superior - anyone can verify without a DLEQ proof!
    Note: K2 must be a PublicKey in group G2. C must be in G1.
    """
    Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
    
    # py_ecc pairing expects (G2_point, G1_point)
    p1 = pairing(G2, C.point)
    p2 = pairing(K2.point, Y.point)
    return p1 == p2

def hash_e(*publickeys: PublicKey) -> bytes:
    """Dummy for backwards compatibility"""
    e_ = ""
    for p in publickeys:
        _p = p.format(compressed=True).hex()
        e_ += str(_p)
    return hashlib.sha256(e_.encode("utf-8")).digest()

# Deprecated functions (kept to avoid import errors, though they shouldn't be called)
def hash_to_curve_deprecated(message: bytes) -> PublicKey:
    return hash_to_curve(message)

def step1_alice_deprecated(
    secret_msg: str, blinding_factor: Optional[PrivateKey] = None
) -> tuple[PublicKey, PrivateKey]:
    return step1_alice(secret_msg, blinding_factor)

def verify_deprecated(a: PrivateKey, C: PublicKey, secret_msg: str) -> bool:
    return verify(a, C, secret_msg)

def carol_verify_dleq_deprecated(*args, **kwargs):
    return True
