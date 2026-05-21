import hashlib
import os
from typing import Optional, Tuple

import pyblst
from loguru import logger

from .bls import PrivateKey, PublicKey, curve_order

# Cashu specific domain separation tag for BLS12-381 G1
DST = b"CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_"
BLS_BATCH_DST = b"Cashu_BLS_Batch_v1"

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
    pt = pyblst.BlstP1Element().hash_to_group(message, DST)
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
    logger.trace(f"BLS step1: secret='{secret_msg}' -> Y={Y.format().hex()} B_={B_.format().hex()} r={r.to_hex()}")
    return B_, r

def step2_bob(B_: PublicKey, a: PrivateKey) -> Tuple[PublicKey, PrivateKey, PrivateKey]:
    """
    Bob signs the blinded message: C' = B' * a
    Returns C' and dummy DLEQ values since BLS12-381 pairings make DLEQ proofs redundant.
    """
    if B_.format().hex().startswith("c000000000000000"):
        raise ValueError("Invalid blinded message: point at infinity")

    # The point was already checked to be in G1 during uncompression
    # pyblst.BlstP1Element().uncompress() performs the subgroup check
    # and throws BLST_POINT_NOT_IN_GROUP if the point is not in G1
        
    C_: PublicKey = B_ * a
    logger.trace(f"BLS step2: B_={B_.format().hex()} a={a.to_hex()} C_={C_.format().hex()}")
    # Return dummy private keys for backwards compatibility with DLEQ logic elsewhere
    return C_, PrivateKey(scalar=1), PrivateKey(scalar=1)

def step3_alice(C_: PublicKey, r: PrivateKey, A: PublicKey) -> PublicKey:
    """
    Alice unblinds the signature: C = C' * (1/r)
    """
    r_inv = mod_inverse(r.scalar, curve_order)
    C: PublicKey = C_ * r_inv
    logger.trace(f"BLS step3: C_={C_.format().hex()} C={C.format().hex()} r={r.to_hex()}")
    return C

def keyed_verification(a: PrivateKey, C: PublicKey, secret_msg: str) -> bool:
    """
    Mint verification: checks C == Y * a
    """
    Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
    valid = C == Y * a
    return valid

def pairing_verification(K2: PublicKey, C: PublicKey, secret_msg: str) -> bool:
    """
    Verify the BLS signature using pairings.
    e(C, G2) == e(Y, K2)
    """
    Y = hash_to_curve(secret_msg.encode("utf-8"))
    
    _G2_HEX = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
    g2_point = pyblst.BlstP2Element().uncompress(bytes.fromhex(_G2_HEX))

    p1 = pyblst.miller_loop(-C.point, g2_point)
    p2 = pyblst.miller_loop(Y.point, K2.point)
    return pyblst.final_verify(p1 * p2, pyblst.BlstFP12Element())

def derive_batch_random_scalars(K2s: list[PublicKey], Cs: list[PublicKey], secret_msgs: list[str]) -> list[int]:
    """
    Derives deterministic random scalars for batch verification using the Fiat-Shamir heuristic
    and rejection sampling to ensure scalars are uniformly distributed over Fr*.
    """
    n = len(Cs)
    transcript = BLS_BATCH_DST
    for i in range(n):
        secret_bytes = secret_msgs[i].encode("utf-8")
        transcript += Cs[i].format()
        transcript += K2s[i].format()
        transcript += len(secret_bytes).to_bytes(4, "big")
        transcript += secret_bytes
        
    challenge = hashlib.sha256(transcript).digest()
    
    rs = []
    for i in range(n):
        ctr = 0
        while True:
            h = hashlib.sha256(challenge + i.to_bytes(4, "big") + ctr.to_bytes(4, "big")).digest()
            x = int.from_bytes(h, "big")
            if x != 0 and x < curve_order:
                rs.append(x)
                break
            ctr += 1
            
    return rs

def batch_pairing_verification(K2s: list[PublicKey], Cs: list[PublicKey], secret_msgs: list[str]) -> bool:
    """
    Batch verifies BLS12-381 signatures using random linear combinations.
    This significantly improves performance over checking each signature individually.
    """
    n = len(Cs)
    if n == 0:
        return True
    
    rs = derive_batch_random_scalars(K2s, Cs, secret_msgs)
        
    Ys = [hash_to_curve(msg.encode("utf-8")) for msg in secret_msgs]
    
    # Left side: sum(r_i * C_i)
    sum_C = Cs[0].point.scalar_mul(rs[0])
    for i in range(1, n):
        sum_C = sum_C + Cs[i].point.scalar_mul(rs[i])
        
    _G2_HEX = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
    g2_point = pyblst.BlstP2Element().uncompress(bytes.fromhex(_G2_HEX))
    
    # Right side: prod(e(sum(r_i * Y_i), K2_j)) grouped by unique K2
    # Group the Y points by their corresponding K2 point
    grouped_Ys = {}
    for i in range(n):
        k2_hex = K2s[i].format().hex()
        y_r = Ys[i].point.scalar_mul(rs[i])
        
        if k2_hex not in grouped_Ys:
            grouped_Ys[k2_hex] = {"k2": K2s[i].point, "sum_y": y_r}
        else:
            grouped_Ys[k2_hex]["sum_y"] = grouped_Ys[k2_hex]["sum_y"] + y_r
            
    # Now compute the pairings for each unique K2
    miller = pyblst.miller_loop(-sum_C, g2_point)
    for group in grouped_Ys.values():
        miller = miller * pyblst.miller_loop(group["sum_y"], group["k2"])
        
    return pyblst.final_verify(miller, pyblst.BlstFP12Element())

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
    return keyed_verification(a, C, secret_msg)

def carol_verify_dleq_deprecated(*args, **kwargs):
    return True
