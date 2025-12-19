# tests/benchmarks/test_schnorr_bench.py

import hashlib
import os

from coincurve import PrivateKey as CCPrivateKey
from coincurve import PublicKeyXOnly as CCPublicKeyXOnly
from secp256k1 import PrivateKey as SPrivateKey
from secp256k1 import PublicKey as SPublicKey

MSG_SIZE = 32


# ---- helpers (mirroring benches/schnorr_bench.py) ----


def cc_keypair():
    sk = CCPrivateKey()
    pkx = CCPublicKeyXOnly(sk.public_key.format()[1:])
    return sk, pkx


def cc_schnorr_sign(sk: CCPrivateKey, msg: bytes) -> bytes:
    digest = hashlib.sha256(msg).digest()
    return sk.sign_schnorr(digest, None)


def cc_schnorr_verify(pkx: CCPublicKeyXOnly, msg: bytes, sig: bytes) -> bool:
    digest = hashlib.sha256(msg).digest()
    return pkx.verify(sig, digest)


def sp_keypair():
    sk = SPrivateKey()
    pk_ser = sk.pubkey.serialize(compressed=True)
    pk = SPublicKey(pk_ser, raw=True)
    return sk, pk


def sp_schnorr_sign(sk: SPrivateKey, msg: bytes) -> bytes:
    digest = hashlib.sha256(msg).digest()
    # NOTE: newer secp256k1-py requires bip340tag argument, but the digest is already BIP340-tagged
    return sk.schnorr_sign(digest, raw=True, bip340tag=None)


def sp_schnorr_verify(pk: SPublicKey, msg: bytes, sig: bytes) -> bool:
    digest = hashlib.sha256(msg).digest()
    return pk.schnorr_verify(digest, sig, raw=True, bip340tag=None)


# ---- pytest-benchmark tests ----


def test_schnorr_sign_coincurve_bench(benchmark):
    msg = os.urandom(MSG_SIZE)
    cc_sk, _ = cc_keypair()

    def cc_sign():
        cc_schnorr_sign(cc_sk, msg)

    benchmark.group = "schnorr_sign_coincurve"
    benchmark.pedantic(cc_sign, rounds=5, iterations=5000)


def test_schnorr_sign_secp256k1_bench(benchmark):
    msg = os.urandom(MSG_SIZE)
    sp_sk, _ = sp_keypair()

    def sp_sign():
        sp_schnorr_sign(sp_sk, msg)

    benchmark.group = "schnorr_sign_secp256k1"
    benchmark.pedantic(sp_sign, rounds=5, iterations=5000)


def test_schnorr_verify_coincurve_bench(benchmark):
    msg = os.urandom(MSG_SIZE)
    cc_sk, cc_pkx = cc_keypair()
    sig_cc = cc_schnorr_sign(cc_sk, msg)

    assert cc_schnorr_verify(cc_pkx, msg, sig_cc)

    def cc_verify():
        cc_schnorr_verify(cc_pkx, msg, sig_cc)

    benchmark.group = "schnorr_verify_coincurve"
    benchmark.pedantic(cc_verify, rounds=5, iterations=5000)


def test_schnorr_verify_secp256k1_bench(benchmark):
    msg = os.urandom(MSG_SIZE)
    sp_sk, sp_pk = sp_keypair()
    sig_sp = sp_schnorr_sign(sp_sk, msg)

    assert sp_schnorr_verify(sp_pk, msg, sig_sp)

    def sp_verify():
        sp_schnorr_verify(sp_pk, msg, sig_sp)

    benchmark.group = "schnorr_verify_secp256k1"
    benchmark.pedantic(sp_verify, rounds=5, iterations=5000)
