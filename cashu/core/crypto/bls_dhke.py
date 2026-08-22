import hashlib
from typing import Optional, Tuple, Union

import pyblst
from loguru import logger

from ..errors import TransactionError
from .bls import G2, PrivateKey, PublicKey, curve_order
from .secp import PublicKey as SecpPublicKey

# Cashu specific domain separation tag for BLS12-381 G1
DST = b"CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_"
BLS_BATCH_DST = b"Cashu_BLS_Batch_v1"

def hash_to_curve(message: bytes) -> PublicKey:
    """
    Hash a message to a point on G1 using SSWU.
    """
    pt = pyblst.BlstP1Element().hash_to_group(message, DST)
    return PublicKey(point=pt, group="G1")

def secret_to_hash_input(secret_msg: Union[str, bytes]) -> bytes:
    """Map a v3 secret string to its hash-to-curve input.

    v3 keysets carry nutroot point secrets only: 33-byte compressed points,
    written as 66-char hex in JSON, hashed as the raw bytes. NUT-10 well-known
    secrets and plain text secrets belong to legacy/v1/v2 keysets and are
    refused here. Only BLS (v3) code paths reach this function.

    Bytes pass through as an already-mapped hash input, which is how the
    primitive's own test vectors drive it.
    """
    if isinstance(secret_msg, bytes):
        return secret_msg
    # Lowercase is the canonical wire form (one spelling per secret): the wallet
    # side hashes upper-case hex differently, so accepting both here would let a
    # proof verify at the mint while its owner computes another Y for it.
    if secret_msg != secret_msg.lower():
        raise TransactionError("v3 point secrets must be lowercase hex.")
    if len(secret_msg) == 66 and secret_msg[:2] in ("02", "03"):
        try:
            raw = bytes.fromhex(secret_msg)
            SecpPublicKey(raw)  # on-curve check, not just the shape
            return raw
        except (ValueError, TypeError):
            pass
    raise TransactionError("v3 keysets take point secrets only.")


def step1_alice(
    secret_msg: Union[str, bytes], blinding_factor: Optional[PrivateKey] = None
) -> tuple[PublicKey, PrivateKey]:
    """
    Alice blinds the message: B' = Y * r
    where Y = hash_to_curve(secret_msg)
    """
    Y: PublicKey = hash_to_curve(secret_to_hash_input(secret_msg))
    r = blinding_factor or PrivateKey()
    B_: PublicKey = Y * r
    logger.trace(f"BLS step1: secret={secret_msg!r} -> Y={Y.format().hex()} B_={B_.format().hex()} r={r.to_hex()}")
    return B_, r

def step2_bob(B_: PublicKey, a: PrivateKey) -> Tuple[PublicKey, PrivateKey, PrivateKey]:
    """
    Bob signs the blinded message: C' = B' * a
    Returns C' and dummy DLEQ values since BLS12-381 pairings make DLEQ proofs redundant.
    """
    if B_.is_infinity():
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
    r_inv = pow(r.scalar, -1, curve_order)
    C: PublicKey = C_ * r_inv
    logger.trace(f"BLS step3: C_={C_.format().hex()} C={C.format().hex()} r={r.to_hex()}")
    return C

def keyed_verification(a: PrivateKey, C: PublicKey, secret_msg: str) -> bool:
    """
    Mint verification: checks C == Y * a
    """
    Y: PublicKey = hash_to_curve(secret_to_hash_input(secret_msg))
    return C == Y * a

def pairing_verification(K2: PublicKey, C: PublicKey, secret_msg: str) -> bool:
    """
    Verify the BLS signature using pairings.
    e(C, G2) == e(Y, K2)
    """
    Y = hash_to_curve(secret_to_hash_input(secret_msg))
    
    p1 = pyblst.miller_loop(-C.point, G2)
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
        secret_bytes = secret_to_hash_input(secret_msgs[i])
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
        
    Ys = [hash_to_curve(secret_to_hash_input(msg)) for msg in secret_msgs]
    
    # Left side: sum(r_i * C_i)
    sum_C = Cs[0].point.scalar_mul(rs[0])
    for i in range(1, n):
        sum_C = sum_C + Cs[i].point.scalar_mul(rs[i])
        
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
    miller = pyblst.miller_loop(-sum_C, G2)
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
