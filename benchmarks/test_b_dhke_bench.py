# tests/benchmarks/test_b_dhke_bench.py

import hashlib
import os

import pytest
from secp256k1 import PrivateKey as SPrivateKey
from secp256k1 import PublicKey as SPublicKey

from cashu.core.crypto import b_dhke as b_dhke_coincurve
from cashu.core.crypto.b_dhke import DOMAIN_SEPARATOR
from cashu.core.crypto.secp import PrivateKey as CCPrivateKey
from cashu.core.crypto.secp import PublicKey as CCPublicKey

SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)


# ---- shared helpers (mirroring benches/b_dhke_bench.py) ----


def hash_to_curve_generic(message: bytes, pubkey_cls):
    msg_to_hash = hashlib.sha256(DOMAIN_SEPARATOR + message).digest()
    counter = 0
    while counter < 2**16:
        _hash = hashlib.sha256(msg_to_hash + counter.to_bytes(4, "little")).digest()
        try:
            if pubkey_cls is CCPublicKey:
                return CCPublicKey(b"\x02" + _hash)
            else:
                return SPublicKey(b"\x02" + _hash, raw=True)
        except Exception:
            counter += 1
    raise ValueError("No valid point found")


def sp_hash_to_curve(message: bytes) -> SPublicKey:
    return hash_to_curve_generic(message, SPublicKey)


def sp_pubkey_add(P: SPublicKey, Q: SPublicKey) -> SPublicKey:
    """P + Q using secp256k1-py PublicKey.combine.

    We create a fresh PublicKey instance with its own context.
    """
    res = SPublicKey()
    res.combine([P.public_key, Q.public_key])
    return res


def sp_pubkey_mul_scalar(P: SPublicKey, scalar32: bytes) -> SPublicKey:
    return P.tweak_mul(scalar32)


def sp_pubkey_neg(P: SPublicKey) -> SPublicKey:
    neg_scalar = (SECP256K1_ORDER - 1).to_bytes(32, "big")
    return P.tweak_mul(neg_scalar)


def sp_pubkey_sub(P: SPublicKey, Q: SPublicKey) -> SPublicKey:
    return sp_pubkey_add(P, sp_pubkey_neg(Q))


def cc_roundtrip(secret_msg: str, a_priv: CCPrivateKey) -> CCPublicKey:
    A = a_priv.public_key
    B_, r = b_dhke_coincurve.step1_alice(secret_msg)
    C_, e, s = b_dhke_coincurve.step2_bob(B_, a_priv)
    C = b_dhke_coincurve.step3_alice(C_, r, A)
    return C


def sp_step1_alice(secret_msg: str, blinding_factor: SPrivateKey | None = None):
    Y = sp_hash_to_curve(secret_msg.encode("utf-8"))
    r = blinding_factor or SPrivateKey()
    B_ = sp_pubkey_add(Y, r.pubkey)
    return B_, r


def sp_step2_bob(B_: SPublicKey, a: SPrivateKey) -> SPublicKey:
    return sp_pubkey_mul_scalar(B_, a.private_key)


def sp_step3_alice(C_: SPublicKey, r: SPrivateKey, A: SPublicKey) -> SPublicKey:
    Ar = sp_pubkey_mul_scalar(A, r.private_key)
    return sp_pubkey_sub(C_, Ar)


def sp_roundtrip(secret_msg: str, a_priv: SPrivateKey) -> SPublicKey:
    A = a_priv.pubkey
    B_, r = sp_step1_alice(secret_msg)
    C_ = sp_step2_bob(B_, a_priv)
    C = sp_step3_alice(C_, r, A)
    return C


# ---- DLEQ helpers ----


def sp_hash_e(*pubkeys: SPublicKey) -> bytes:
    e_ = ""
    for p in pubkeys:
        e_ += p.serialize(compressed=False).hex()
    return hashlib.sha256(e_.encode("utf-8")).digest()


def sp_step2_bob_dleq(
    B_: SPublicKey, a: SPrivateKey, p_bytes: bytes | None = None
):
    if p_bytes is not None:
        p = SPrivateKey(p_bytes)
    else:
        p = SPrivateKey()

    R1 = p.pubkey
    R2 = sp_pubkey_mul_scalar(B_, p.private_key)
    C_ = sp_pubkey_mul_scalar(B_, a.private_key)
    A = a.pubkey

    e_bytes = sp_hash_e(R1, R2, A, C_)
    ek_bytes = a.tweak_mul(e_bytes)
    s_bytes = p.tweak_add(ek_bytes)

    return C_, e_bytes, s_bytes


def sp_alice_verify_dleq(
    B_: SPublicKey,
    C_: SPublicKey,
    e_bytes: bytes,
    s_bytes: bytes,
    A: SPublicKey,
) -> bool:
    s_priv = SPrivateKey(s_bytes)
    sG = s_priv.pubkey
    eA = A.tweak_mul(e_bytes)
    R1 = sp_pubkey_sub(sG, eA)

    sB = sp_pubkey_mul_scalar(B_, s_bytes)
    eC = sp_pubkey_mul_scalar(C_, e_bytes)
    R2 = sp_pubkey_sub(sB, eC)

    return sp_hash_e(R1, R2, A, C_) == e_bytes


# ---- pytest-benchmark tests ----


@pytest.fixture(scope="module")
def _fixed_keys():
    secret = "test_message"
    a_bytes = os.urandom(32)
    cc_a = CCPrivateKey(a_bytes)
    sp_a = SPrivateKey(a_bytes)
    return secret, cc_a, sp_a


def test_dhke_roundtrip_bench(benchmark, _fixed_keys):
    secret, cc_a, sp_a = _fixed_keys

    # warmup
    cc_roundtrip(secret, cc_a)
    sp_roundtrip(secret, sp_a)

    def run_coincurve():
        cc_roundtrip(secret, cc_a)

    benchmark.group = "dhke_roundtrip_coincurve"
    benchmark.pedantic(run_coincurve, rounds=5, iterations=1000)


def test_dhke_roundtrip_secp256k1_bench(benchmark, _fixed_keys):
    secret, cc_a, sp_a = _fixed_keys

    def run_secp256k1():
        sp_roundtrip(secret, sp_a)

    benchmark.group = "dhke_roundtrip_secp256k1"
    benchmark.pedantic(run_secp256k1, rounds=5, iterations=1000)


@pytest.fixture(scope="module")
def _dleq_state(_fixed_keys):
    secret, cc_a, sp_a = _fixed_keys

    # coincurve state
    B_cc, r_cc = b_dhke_coincurve.step1_alice(secret)
    C_cc, e_cc, s_cc = b_dhke_coincurve.step2_bob(B_cc, cc_a)
    A_cc = cc_a.public_key

    # secp256k1 state
    B_sp, r_sp = sp_step1_alice(secret)
    C_sp, e_sp, s_sp = sp_step2_bob_dleq(B_sp, sp_a)
    A_sp = sp_a.pubkey

    return (B_cc, C_cc, e_cc, s_cc, A_cc, cc_a), (B_sp, C_sp, e_sp, s_sp, A_sp, sp_a)


def test_dleq_create_coincurve_bench(benchmark, _dleq_state):
    (B_cc, C_cc, e_cc, s_cc, A_cc, cc_a), (B_sp, C_sp, e_sp, s_sp, A_sp, sp_a) = _dleq_state

    def cc_create():
        b_dhke_coincurve.step2_bob_dleq(B_cc, cc_a)

    benchmark.group = "dleq_create_coincurve"
    benchmark.pedantic(cc_create, rounds=5, iterations=2000)


def test_dleq_create_secp256k1_bench(benchmark, _dleq_state):
    (B_cc, C_cc, e_cc, s_cc, A_cc, cc_a), (B_sp, C_sp, e_sp, s_sp, A_sp, sp_a) = _dleq_state

    def sp_create():
        sp_step2_bob_dleq(B_sp, sp_a)

    benchmark.group = "dleq_create_secp256k1"
    benchmark.pedantic(sp_create, rounds=5, iterations=2000)


def test_dleq_verify_coincurve_bench(benchmark, _dleq_state):
    (B_cc, C_cc, e_cc, s_cc, A_cc, cc_a), (B_sp, C_sp, e_sp, s_sp, A_sp, sp_a) = _dleq_state

    def cc_verify():
        assert b_dhke_coincurve.alice_verify_dleq(B_cc, C_cc, e_cc, s_cc, A_cc)

    benchmark.group = "dleq_verify_coincurve"
    benchmark.pedantic(cc_verify, rounds=5, iterations=2000)


def test_dleq_verify_secp256k1_bench(benchmark, _dleq_state):
    (B_cc, C_cc, e_cc, s_cc, A_cc, cc_a), (B_sp, C_sp, e_sp, s_sp, A_sp, sp_a) = _dleq_state

    def sp_verify():
        assert sp_alice_verify_dleq(B_sp, C_sp, e_sp, s_sp, A_sp)

    benchmark.group = "dleq_verify_secp256k1"
    benchmark.pedantic(sp_verify, rounds=5, iterations=2000)
