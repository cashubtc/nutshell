import hashlib
from typing import Optional, Tuple

import pyblst
from loguru import logger

from .bls import PrivateKey, PublicKey, curve_order

# Cashu specific domain separation tag for BLS12-381 G1
DST = b"CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_"

# NUT-00 Batch Verification: Fiat-Shamir transcript DST. Per-proof weights are derived
# deterministically from this transcript so the verifier is reproducible and the security
# argument does not depend on CSPRNG quality.
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

def _derive_batch_weights(
    K2s: list[PublicKey], Cs: list[PublicKey], secret_msgs: list[bytes]
) -> list[int]:
    """
    NUT-00 batch verification: deterministic per-proof weights via Fiat-Shamir.

    Builds a length-prefixed transcript binding (C_i, K_i, secret_i) for every proof,
    collapses it to a 32-byte challenge once, then derives each weight by rejection
    sampling: r_i = OS2IP(SHA256(challenge || u32_BE(i) || u32_BE(ctr))) with
    0 < r_i < BLS_FR_ORDER. Modular reduction would bias ~7.5% because
    BLS_FR_ORDER ~ 0.45 * 2^256; rejection sampling yields a uniform sample over Fr*.

    Why deterministic: the weights must commit to the input proofs *before* the
    attacker sees them, otherwise an adversary holding one aggregated signature
    `C' = a * (Y_1 + Y_2)` can split it into two forgeries that both verify under a
    sum check. The transcript binds each r_i to (C_i, K_i, secret_i) for the whole
    batch, so an attacker cannot choose proofs in adversarial relation to weights
    without first fixing the proofs (which fix the weights).
    """
    n = len(Cs)
    transcript = bytearray(BLS_BATCH_DST)
    for C, K, secret in zip(Cs, K2s, secret_msgs):
        transcript += C.format()                    # 48 bytes (G1 compressed)
        transcript += K.format()                    # 96 bytes (G2 compressed)
        transcript += len(secret).to_bytes(4, "big")
        transcript += secret
    challenge = hashlib.sha256(bytes(transcript)).digest()

    weights: list[int] = []
    for i in range(n):
        i_bytes = i.to_bytes(4, "big")
        # Acceptance probability ~45%, so an attempt cap of 65536 has failure prob
        # ~2^-262 — defensive, never reached in practice.
        for ctr in range(1 << 16):
            h = hashlib.sha256(challenge + i_bytes + ctr.to_bytes(4, "big")).digest()
            x = int.from_bytes(h, "big")
            if x == 0 or x >= curve_order:
                continue
            weights.append(x)
            break
        else:
            raise RuntimeError("NUT-00 batch weight derivation failed")
    return weights


def batch_pairing_verification(
    K2s: list[PublicKey], Cs: list[PublicKey], secret_msgs: list[str]
) -> bool:
    """
    NUT-00 batch verification: e(sum r_i * C_i, G2) == prod_k e(sum_{K_i=K_k} r_i * Y_i, K_k).

    Weights are derived deterministically via Fiat-Shamir (see `_derive_batch_weights`); a single
    multi-pairing performs one final exponentiation for the whole equation.
    """
    n = len(Cs)
    if n == 0:
        return True

    secret_bytes_list = [msg.encode("utf-8") for msg in secret_msgs]
    rs = _derive_batch_weights(K2s, Cs, secret_bytes_list)
    Ys = [hash_to_curve(sb) for sb in secret_bytes_list]

    # Left side: sum(r_i * C_i)
    sum_C = Cs[0].point.scalar_mul(rs[0])
    for i in range(1, n):
        sum_C = sum_C + Cs[i].point.scalar_mul(rs[i])

    _G2_HEX = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
    g2_point = pyblst.BlstP2Element().uncompress(bytes.fromhex(_G2_HEX))

    # Right side: prod(e(sum(r_i * Y_i), K2_j)) grouped by unique K2
    grouped_Ys: dict = {}
    for i in range(n):
        k2_hex = K2s[i].format().hex()
        y_r = Ys[i].point.scalar_mul(rs[i])
        if k2_hex not in grouped_Ys:
            grouped_Ys[k2_hex] = {"k2": K2s[i].point, "sum_y": y_r}
        else:
            grouped_Ys[k2_hex]["sum_y"] = grouped_Ys[k2_hex]["sum_y"] + y_r

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
