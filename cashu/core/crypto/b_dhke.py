# Don't trust me with cryptography.

"""
Implementation of https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406

Bob (Mint):
A = a*G
return A

Alice (Client):
Y = hash_to_curve(secret_message)
r = random blinding factor
B'= Y + r*G
return B'

Bob:
C' = a*B'
  (= a*Y + a*r*G)
return C'

Alice:
C = C' - r*A
 (= C' - a*r*G)
 (= a*Y)
return C, secret_message

Bob:
Y = hash_to_curve(secret_message)
C == a*Y
If true, C must have originated from Bob


# DLEQ Proof

(These steps occur once Bob returns C')

Bob:
r = random nonce
R1 = r*G
R2 = r*B'
e = hash(R1,R2,A,C')
s = r + e*a
return e, s

Alice:
R1 = s*G - e*A
R2 = s*B' - e*C'
e == hash(R1,R2,A,C')

If true, a in A = a*G must be equal to a in C' = a*B'

# Schnorr Proof - sub-proof of DLEQ proof

Alice:
k = random nonce
K1 = k*G
K2 = k*A
f = hash(K1,K2,B',C',Y,C)
t = k + t*k
return f, t

Carol:
Y = hash_to_curve(secret)
K1 = t*G - f*B' + f*Y
K2 = t*A - f*C' + f*C
f == hash(K1,K2,B',C',Y,C)
"""

import hashlib
from typing import Optional, Tuple

from secp256k1 import PrivateKey, PublicKey


def hash_to_curve(message: bytes) -> PublicKey:
    """Generates a point from the message hash and checks if the point lies on the curve.
    If it does not, iteratively tries to compute a new point from the hash."""
    point = None
    msg_to_hash = message
    while point is None:
        _hash = hashlib.sha256(msg_to_hash).digest()
        try:
            # will error if point does not lie on curve
            point = PublicKey(b"\x02" + _hash, raw=True)
        except Exception:
            msg_to_hash = _hash
    return point


def step1_alice(
    secret_msg: str, blinding_factor: Optional[PrivateKey] = None
) -> tuple[PublicKey, PrivateKey]:
    Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
    r = blinding_factor or PrivateKey()
    B_: PublicKey = Y + r.pubkey  # type: ignore
    return B_, r


def step2_bob(B_: PublicKey, a: PrivateKey) -> Tuple[PublicKey, PrivateKey, PrivateKey]:
    C_: PublicKey = B_.mult(a)  # type: ignore
    # produce dleq proof
    e, s = step2_bob_dleq(B_, a)
    return C_, e, s


def step3_alice(C_: PublicKey, r: PrivateKey, A: PublicKey) -> PublicKey:
    C: PublicKey = C_ - A.mult(r)  # type: ignore
    return C


def verify(a: PrivateKey, C: PublicKey, secret_msg: str) -> bool:
    Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
    return C == Y.mult(a)  # type: ignore


def hash_e(*publickeys: PublicKey) -> bytes:
    e_ = ""
    for p in publickeys:
        _p = p.serialize(compressed=False).hex()
        e_ += str(_p)
    e = hashlib.sha256(e_.encode("utf-8")).digest()
    return e


def step2_bob_dleq(
    B_: PublicKey, a: PrivateKey, p_bytes: bytes = b""
) -> Tuple[PrivateKey, PrivateKey]:
    if p_bytes:
        # deterministic p for testing
        p = PrivateKey(privkey=p_bytes, raw=True)
    else:
        # normally, we generate a random p
        p = PrivateKey()

    R1 = p.pubkey  # R1 = pG
    assert R1
    R2: PublicKey = B_.mult(p)  # R2 = pB_ # type: ignore
    C_: PublicKey = B_.mult(a)  # C_ = aB_ # type: ignore
    A = a.pubkey
    assert A
    e = hash_e(R1, R2, A, C_)  # e = hash(R1, R2, A, C_)
    s = p.tweak_add(a.tweak_mul(e))  # s = p + ek
    spk = PrivateKey(s, raw=True)
    epk = PrivateKey(e, raw=True)
    return epk, spk


def verify_dleq(
    *,
    B_: PublicKey,
    C_: PublicKey,
    e: PrivateKey,
    s: PrivateKey,
    A: PublicKey,
):
    R1 = s.pubkey - A.mult(e)  # type: ignore
    R2 = B_.mult(s) - C_.mult(e)  # type: ignore
    e_bytes = e.private_key
    return e_bytes == hash_e(R1, R2, A, C_)


def carol_verify_dleq(
    *,
    B_: PublicKey,
    C_: PublicKey,
    e: PrivateKey,
    s: PrivateKey,
    A: PublicKey,
    f: PrivateKey,
    t: PrivateKey,
    C: PublicKey,
    secret_msg: str,
):
    # verify dleq proof that mint signature is valid
    assert verify_dleq(B_=B_, C_=C_, e=e, s=s, A=A)
    # verify schnorr proof that Alice sent us valid C_ and B_
    assert carol_schnorr_r_verify(
        A=A, B_=B_, secret_msg=secret_msg, C=C, C_=C_, f=f, t=t
    )
    return True


def alice_verify_dleq(
    *,
    secret_msg: str,
    r: PrivateKey,
    C: PublicKey,
    e: PrivateKey,
    s: PrivateKey,
    A: PublicKey,
):
    Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
    C_: PublicKey = C + A.mult(r)  # type: ignore
    B_: PublicKey = Y + r.pubkey  # type: ignore
    return verify_dleq(B_=B_, C_=C_, e=e, s=s, A=A)


def alice_schnorr_r(
    r: PrivateKey,
    A: PublicKey,
    B_: PublicKey,
    C_: PublicKey,
    C: PublicKey,
    secret_msg: str,
    k_bytes: bytes = b"",
) -> Tuple[PrivateKey, PrivateKey]:
    if k_bytes:
        # deterministic k for testing
        k = PrivateKey(privkey=k_bytes, raw=True)
    else:
        # normally, we generate a random k
        k = PrivateKey()

    K1 = k.pubkey  # K1 = kG
    assert K1
    K2 = A.mult(k)  # K2 = kA # type: ignore

    Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
    f = hash_e(K1, K2, A, B_, C_, Y, C)
    t = k.tweak_add(r.tweak_mul(f))  # t = p + fk
    tpk = PrivateKey(t, raw=True)
    fpk = PrivateKey(f, raw=True)
    return fpk, tpk


def carol_schnorr_r_verify(
    *,
    A: PublicKey,
    B_: PublicKey,
    secret_msg: str,
    C: PublicKey,
    C_: PublicKey,
    f: PrivateKey,
    t: PrivateKey,
):
    Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
    K1 = t.pubkey - B_.mult(f) + Y.mult(f)  # type: ignore
    K2 = A.mult(t) - C_.mult(f) + C.mult(f)  # type: ignore

    f_bytes = f.private_key

    return f_bytes == hash_e(K1, K2, A, B_, C_, Y, C)
