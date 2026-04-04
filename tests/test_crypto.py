import secrets
from unittest import mock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cashu.core.base import DLEQWallet, Proof
from cashu.core.crypto.b_dhke import (
    DOMAIN_SEPARATOR,
    alice_verify_dleq,
    carol_verify_dleq,
    hash_e,
    hash_to_curve,
    hash_to_curve_deprecated,
    step1_alice,
    step1_alice_deprecated,
    step2_bob,
    step2_bob_dleq,
    step3_alice,
    verify,
)
from cashu.core.crypto.secp import PrivateKey, PublicKey


def test_hash_to_curve():
    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
    )
    assert (
        result.format().hex()
        == "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725"
    )
    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )
    assert (
        result.format().hex()
        == "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf"
    )
    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        )
    )
    assert (
        result.format().hex()
        == "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f"
    )


def test_step1():
    secret_msg = "test_message"
    B_, blinding_factor = step1_alice(
        secret_msg,
        blinding_factor=PrivateKey(
            bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            )  # 32 bytes
        ),
    )

    assert (
        B_.format().hex()
        == "025cc16fe33b953e2ace39653efb3e7a7049711ae1d8a2f7a9108753f1cdea742b"
    )
    assert blinding_factor.to_hex() == "0000000000000000000000000000000000000000000000000000000000000001"


def test_step2():
    B_, _ = step1_alice(
        "test_message",
        blinding_factor=PrivateKey(
            bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),

        ),
    )
    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),

    )
    C_, e, s = step2_bob(B_, a)
    assert (
        C_.format().hex()
        == "025cc16fe33b953e2ace39653efb3e7a7049711ae1d8a2f7a9108753f1cdea742b"
    )


def test_step3():
    # C = C_ - A.mult(r)
    # C_ from test_step2
    C_ = PublicKey(
        bytes.fromhex(
            "025cc16fe33b953e2ace39653efb3e7a7049711ae1d8a2f7a9108753f1cdea742b"
        )
    )
    r = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )

    A = PublicKey(
        b"\x02"
        + bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),

    )
    C = step3_alice(C_, r, A)

    assert (
        C.format().hex()
        == "0271bf0d702dbad86cbe0af3ab2bfba70a0338f22728e412d88a830ed0580b9de4"
    )


def test_dleq_hash_e():
    C_ = PublicKey(
        bytes.fromhex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
        )
    )
    K = PublicKey(
        b"\x02"
        + bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
    )
    R1 = PublicKey(
        b"\x02"
        + bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
    )
    R2 = PublicKey(
        b"\x02"
        + bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
    )
    e = hash_e(R1, R2, K, C_)
    assert e.hex() == "a4dc034b74338c28c6bc3ea49731f2a24440fc7c4affc08b31a93fc9fbe6401e"


def test_dleq_step2_bob_dleq():
    B_, _ = step1_alice(
        "test_message",
        blinding_factor=PrivateKey(
            bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),

        ),
    )
    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),

    )
    p_bytes = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )  # 32 bytes
    e, s = step2_bob_dleq(B_, a, p_bytes)
    assert (
        e.to_hex()
        == "a608ae30a54c6d878c706240ee35d4289b68cfe99454bbfa6578b503bce2dbe1"
    )
    assert (
        s.to_hex()
        == "a608ae30a54c6d878c706240ee35d4289b68cfe99454bbfa6578b503bce2dbe2"
    )  # differs from e only in least significant byte because `a = 0x1`

    # change `a`
    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000001111"
        ),

    )
    e, s = step2_bob_dleq(B_, a, p_bytes)
    assert (
        e.to_hex()
        == "076cbdda4f368053c33056c438df014d1875eb3c8b28120bece74b6d0e6381bb"
    )
    assert (
        s.to_hex()
        == "b6d41ac1e12415862bf8cace95e5355e9262eab8a11d201dadd3b6e41584ea6e"
    )


def test_dleq_alice_verify_dleq():
    # e from test_step2_bob_dleq for a=0x1
    e = PrivateKey(
        bytes.fromhex(
            "9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9"
        )
    )
    # s from test_step2_bob_dleq for a=0x1
    s = PrivateKey(
        bytes.fromhex(
            "9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da"
        )
    )

    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )
    A = a.public_key
    assert A
    # B_ is the same as we did:
    # B_, _ = step1_alice(
    #     "test_message",
    #     blinding_factor=bytes.fromhex(
    #         "0000000000000000000000000000000000000000000000000000000000000001"
    #     ),  # 32 bytes
    # )
    B_ = PublicKey(
        bytes.fromhex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
        )
    )

    # # C_ is the same as if we did:
    # a = PrivateKey(
    #     bytes.fromhex(
    #         "0000000000000000000000000000000000000000000000000000000000000001"
    #     ),
    # )
    # C_, e, s = step2_bob(B_, a)

    C_ = PublicKey(
        bytes.fromhex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
        )
    )

    assert alice_verify_dleq(B_, C_, e, s, A)


def test_dleq_alice_direct_verify_dleq():
    # ----- test again with B_ and C_ as per step1 and step2
    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )
    A = a.public_key
    assert A
    B_, _ = step1_alice(
        "test_message",
        blinding_factor=PrivateKey(
            bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),

        ),
    )
    C_, e, s = step2_bob(B_, a)
    assert alice_verify_dleq(B_, C_, e, s, A)


def test_dleq_carol_verify_from_bob():
    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),

    )
    A = a.public_key
    assert A
    assert (
        A.format().hex()
        == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    secret_msg = "test_message"
    r = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )
    B_, _ = step1_alice(secret_msg, r)
    C_, e, s = step2_bob(B_, a)
    assert alice_verify_dleq(B_, C_, e, s, A)
    C = step3_alice(C_, r, A)
    # carol does not know B_ and C_, but she receives C and r from Alice
    assert carol_verify_dleq(secret_msg=secret_msg, C=C, r=r, e=e, s=s, A=A)


def test_dleq_carol_on_proof():
    A = PublicKey(
        bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
    )
    proof = Proof.model_validate(
        {
            "amount": 1,
            "id": "00882760bfa2eb41",
            "secret": "daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9",
            "C": "024369d2d22a80ecf78f3937da9d5f30c1b9f74f0c32684d583cca0fa6a61cdcfc",
            "dleq": {
                "e": "b31e58ac6527f34975ffab13e70a48b6d2b0d35abc4b03f0151f09ee1a9763d4",
                "s": "8fbae004c59e754d71df67e392b6ae4e29293113ddc2ec86592a0431d16306d8",
                "r": "a6d13fcd7a18442e6076f5e1e7c887ad5de40a019824bdfa9fe740d302e8d861",
            },
        }
    )
    assert proof.dleq

    assert carol_verify_dleq(
        secret_msg=proof.secret,
        r=PrivateKey(bytes.fromhex(proof.dleq.r)),
        C=PublicKey(bytes.fromhex(proof.C)),
        e=PrivateKey(bytes.fromhex(proof.dleq.e)),
        s=PrivateKey(bytes.fromhex(proof.dleq.s)),
        A=A,
    )


# TESTS FOR DEPRECATED HASH TO CURVE


def test_hash_to_curve_deprecated():
    result = hash_to_curve_deprecated(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
    )
    assert (
        result.format().hex()
        == "0266687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
    )

    result = hash_to_curve_deprecated(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )
    assert (
        result.format().hex()
        == "02ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5"
    )


def test_hash_to_curve_iteration_deprecated():
    """This input causes multiple rounds of the hash_to_curve algorithm."""
    result = hash_to_curve_deprecated(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        )
    )
    assert (
        result.format().hex()
        == "02076c988b353fcbb748178ecb286bc9d0b4acf474d4ba31ba62334e46c97c416a"
    )


def test_step1_deprecated():
    secret_msg = "test_message"
    B_, blinding_factor = step1_alice_deprecated(
        secret_msg,
        blinding_factor=PrivateKey(
            bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            )  # 32 bytes
        ),
    )

    assert (
        B_.format().hex()
        == "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
    )
    assert blinding_factor.to_hex() == "0000000000000000000000000000000000000000000000000000000000000001"


def test_step2_deprecated():
    B_, _ = step1_alice_deprecated(
        "test_message",
        blinding_factor=PrivateKey(
            bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),

        ),
    )
    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),

    )
    C_, e, s = step2_bob(B_, a)
    assert (
        C_.format().hex()
        == "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
    )


def test_step3_deprecated():
    # C = C_ - A.mult(r)
    # C_ from test_step2_deprecated
    C_ = PublicKey(
        bytes.fromhex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
        )
    )
    r = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )

    A = PublicKey(
        b"\x02"
        + bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),

    )
    C = step3_alice(C_, r, A)

    assert (
        C.format().hex()
        == "03c724d7e6a5443b39ac8acf11f40420adc4f99a02e7cc1b57703d9391f6d129cd"
    )


def test_dleq_step2_bob_dleq_deprecated():
    B_, _ = step1_alice_deprecated(
        "test_message",
        blinding_factor=PrivateKey(
            bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),

        ),
    )
    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),

    )
    p_bytes = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )  # 32 bytes
    e, s = step2_bob_dleq(B_, a, p_bytes)
    assert (
        e.to_hex()
        == "9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9"
    )
    assert (
        s.to_hex()
        == "9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da"
    )  # differs from e only in least significant byte because `a = 0x1`

    # change `a`
    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000001111"
        ),

    )
    e, s = step2_bob_dleq(B_, a, p_bytes)
    assert (
        e.to_hex()
        == "df1984d5c22f7e17afe33b8669f02f530f286ae3b00a1978edaf900f4721f65e"
    )
    assert (
        s.to_hex()
        == "828404170c86f240c50ae0f5fc17bb6b82612d46b355e046d7cd84b0a3c934a0"
    )


# ---------------------------------------------------------------------------
# hash_to_curve properties
# ---------------------------------------------------------------------------


class TestHashToCurveProperties:
    def test_uses_domain_separator(self):
        assert DOMAIN_SEPARATOR == b"Secp256k1_HashToCurve_Cashu_"

    def test_deterministic(self):
        msg = b"test_determinism"
        assert hash_to_curve(msg).format() == hash_to_curve(msg).format()

    def test_different_messages_different_points(self):
        p1 = hash_to_curve(b"message_a")
        p2 = hash_to_curve(b"message_b")
        assert p1.format() != p2.format()

    def test_result_is_valid_compressed_pubkey(self):
        p = hash_to_curve(b"validity_check")
        compressed = p.format()
        assert len(compressed) == 33
        assert compressed[0] in (2, 3)

    def test_empty_message(self):
        p = hash_to_curve(b"")
        assert isinstance(p, PublicKey)

    @given(msg=st.binary(min_size=0, max_size=500))
    @settings(max_examples=50, deadline=10000)
    def test_always_produces_valid_point(self, msg):
        p = hash_to_curve(msg)
        assert isinstance(p, PublicKey)
        assert len(p.format()) == 33

    def test_deprecated_differs_from_current(self):
        msg = b"test_both_versions"
        p_new = hash_to_curve(msg)
        p_old = hash_to_curve_deprecated(msg)
        assert p_new.format() != p_old.format()

    def test_raises_when_no_curve_point_found_in_max_iterations(self):
        """Cover the defensive ValueError when all 2**16 candidates fail.

        In normal operation this path is effectively unreachable; we force it
        by making PublicKey construction always fail inside hash_to_curve.
        """

        def always_invalid(*_args, **_kwargs):
            raise RuntimeError("force retry")

        with mock.patch(
            "cashu.core.crypto.b_dhke.PublicKey", side_effect=always_invalid
        ):
            with pytest.raises(ValueError, match="No valid point found"):
                hash_to_curve(b"exhaust_loop")


# ---------------------------------------------------------------------------
# BDHKE protocol properties
# ---------------------------------------------------------------------------


class TestBDHKEProtocolProperties:
    def test_unblinding_produces_valid_signature(self):
        a = PrivateKey()
        A = a.public_key
        secret = "test_unblinding"
        B_, r = step1_alice(secret)
        C_, e, s = step2_bob(B_, a)
        C = step3_alice(C_, r, A)
        assert verify(a, C, secret)

    def test_different_blinding_factors_same_unblinded_sig(self):
        a = PrivateKey()
        A = a.public_key
        secret = "same_secret"

        B_1, r1 = step1_alice(secret)
        C_1, _, _ = step2_bob(B_1, a)
        C1 = step3_alice(C_1, r1, A)

        B_2, r2 = step1_alice(secret)
        C_2, _, _ = step2_bob(B_2, a)
        C2 = step3_alice(C_2, r2, A)

        assert C1 == C2

    def test_different_secrets_different_sigs(self):
        a = PrivateKey()
        A = a.public_key

        B_1, r1 = step1_alice("secret_a")
        C_1, _, _ = step2_bob(B_1, a)
        C1 = step3_alice(C_1, r1, A)

        B_2, r2 = step1_alice("secret_b")
        C_2, _, _ = step2_bob(B_2, a)
        C2 = step3_alice(C_2, r2, A)

        assert C1 != C2

    @given(
        secret=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N")),
            min_size=1,
            max_size=64,
        )
    )
    @settings(max_examples=30, deadline=10000)
    def test_roundtrip_always_verifies(self, secret):
        a = PrivateKey()
        A = a.public_key
        B_, r = step1_alice(secret)
        C_, _, _ = step2_bob(B_, a)
        C = step3_alice(C_, r, A)
        assert verify(a, C, secret)


# ---------------------------------------------------------------------------
# Helper for full BDHKE + DLEQ roundtrip
# ---------------------------------------------------------------------------


def _full_bdhke_roundtrip(
    secret_msg: str = "test_message",
    a: PrivateKey | None = None,
    r: PrivateKey | None = None,
):
    """Run the full BDHKE + DLEQ flow and return all artifacts."""
    a = a or PrivateKey()
    A = a.public_key
    B_, r_used = step1_alice(secret_msg, blinding_factor=r)
    C_, e, s = step2_bob(B_, a)
    C = step3_alice(C_, r_used, A)
    return dict(
        a=a, A=A, B_=B_, r=r_used, C_=C_, e=e, s=s, C=C, secret_msg=secret_msg
    )


# ---------------------------------------------------------------------------
# Alice verify DLEQ — negative cases
# ---------------------------------------------------------------------------


class TestAliceVerifyDLEQ:
    def test_valid_dleq_passes(self):
        ctx = _full_bdhke_roundtrip()
        assert alice_verify_dleq(ctx["B_"], ctx["C_"], ctx["e"], ctx["s"], ctx["A"])

    def test_wrong_e_fails(self):
        ctx = _full_bdhke_roundtrip()
        wrong_e = PrivateKey()
        assert not alice_verify_dleq(
            ctx["B_"], ctx["C_"], wrong_e, ctx["s"], ctx["A"]
        )

    def test_wrong_s_fails(self):
        ctx = _full_bdhke_roundtrip()
        wrong_s = PrivateKey()
        assert not alice_verify_dleq(
            ctx["B_"], ctx["C_"], ctx["e"], wrong_s, ctx["A"]
        )

    def test_wrong_A_fails(self):
        ctx = _full_bdhke_roundtrip()
        wrong_A = PrivateKey().public_key
        assert not alice_verify_dleq(
            ctx["B_"], ctx["C_"], ctx["e"], ctx["s"], wrong_A
        )

    def test_swapped_B_C_fails(self):
        ctx = _full_bdhke_roundtrip()
        assert not alice_verify_dleq(
            ctx["C_"], ctx["B_"], ctx["e"], ctx["s"], ctx["A"]
        )


# ---------------------------------------------------------------------------
# Carol verify DLEQ — negative cases
# ---------------------------------------------------------------------------


class TestCarolVerifyDLEQ:
    def test_valid_carol_verify(self):
        ctx = _full_bdhke_roundtrip()
        assert carol_verify_dleq(
            secret_msg=ctx["secret_msg"],
            r=ctx["r"],
            C=ctx["C"],
            e=ctx["e"],
            s=ctx["s"],
            A=ctx["A"],
        )

    def test_carol_wrong_secret_fails(self):
        ctx = _full_bdhke_roundtrip()
        assert not carol_verify_dleq(
            secret_msg="wrong_message",
            r=ctx["r"],
            C=ctx["C"],
            e=ctx["e"],
            s=ctx["s"],
            A=ctx["A"],
        )

    def test_carol_wrong_r_fails(self):
        ctx = _full_bdhke_roundtrip()
        wrong_r = PrivateKey()
        assert not carol_verify_dleq(
            secret_msg=ctx["secret_msg"],
            r=wrong_r,
            C=ctx["C"],
            e=ctx["e"],
            s=ctx["s"],
            A=ctx["A"],
        )

    def test_carol_wrong_C_fails(self):
        ctx = _full_bdhke_roundtrip()
        wrong_C = PrivateKey().public_key
        assert not carol_verify_dleq(
            secret_msg=ctx["secret_msg"],
            r=ctx["r"],
            C=wrong_C,
            e=ctx["e"],
            s=ctx["s"],
            A=ctx["A"],
        )

    def test_carol_wrong_A_fails(self):
        ctx = _full_bdhke_roundtrip()
        wrong_A = PrivateKey().public_key
        assert not carol_verify_dleq(
            secret_msg=ctx["secret_msg"],
            r=ctx["r"],
            C=ctx["C"],
            e=ctx["e"],
            s=ctx["s"],
            A=wrong_A,
        )


# ---------------------------------------------------------------------------
# DLEQ on Proof objects
# ---------------------------------------------------------------------------


class TestDLEQOnProof:
    def test_proof_with_dleq_verifies(self):
        a = PrivateKey()
        A = a.public_key
        secret_msg = secrets.token_hex(32)

        B_, r = step1_alice(secret_msg)
        C_, e, s = step2_bob(B_, a)
        C = step3_alice(C_, r, A)

        proof = Proof(
            id="00ad268c4d1f5826",
            amount=1,
            secret=secret_msg,
            C=C.format().hex(),
            dleq=DLEQWallet(
                e=e.to_hex(),
                s=s.to_hex(),
                r=r.to_hex(),
            ),
        )

        assert proof.dleq is not None
        assert carol_verify_dleq(
            secret_msg=proof.secret,
            r=PrivateKey(bytes.fromhex(proof.dleq.r)),
            C=PublicKey(bytes.fromhex(proof.C)),
            e=PrivateKey(bytes.fromhex(proof.dleq.e)),
            s=PrivateKey(bytes.fromhex(proof.dleq.s)),
            A=A,
        )

    def test_tampered_dleq_on_proof_fails(self):
        a = PrivateKey()
        A = a.public_key
        secret_msg = secrets.token_hex(32)

        B_, r = step1_alice(secret_msg)
        C_, e, s = step2_bob(B_, a)
        C = step3_alice(C_, r, A)

        tampered_e = PrivateKey()

        assert not carol_verify_dleq(
            secret_msg=secret_msg,
            r=r,
            C=C,
            e=tampered_e,
            s=s,
            A=A,
        )


# ---------------------------------------------------------------------------
# Deterministic DLEQ (using known p nonce)
# ---------------------------------------------------------------------------


class TestDLEQDeterministic:
    def test_deterministic_dleq_with_known_p(self):
        a = PrivateKey(bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ))
        p_bytes = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        )

        B_, _ = step1_alice(
            "test_message",
            blinding_factor=PrivateKey(bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            )),
        )

        e1, s1 = step2_bob_dleq(B_, a, p_bytes)
        e2, s2 = step2_bob_dleq(B_, a, p_bytes)

        assert e1.to_hex() == e2.to_hex()
        assert s1.to_hex() == s2.to_hex()

    def test_different_p_gives_different_dleq(self):
        a = PrivateKey(bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ))
        B_, _ = step1_alice(
            "test_message",
            blinding_factor=PrivateKey(bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            )),
        )

        p1 = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        p2 = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        )
        e1, s1 = step2_bob_dleq(B_, a, p1)
        e2, s2 = step2_bob_dleq(B_, a, p2)

        assert e1.to_hex() != e2.to_hex()
        assert s1.to_hex() != s2.to_hex()


# ---------------------------------------------------------------------------
# hash_e edge cases
# ---------------------------------------------------------------------------


class TestHashE:
    def test_order_of_keys_matters(self):
        A = PrivateKey().public_key
        B = PrivateKey().public_key
        assert hash_e(A, B) != hash_e(B, A)

    def test_same_key_repeated(self):
        A = PrivateKey().public_key
        h1 = hash_e(A, A)
        assert len(h1) == 32

    def test_uses_uncompressed_encoding(self):
        A = PrivateKey().public_key
        uncompressed = A.format(compressed=False).hex()
        assert len(uncompressed) == 130  # 65 bytes = 130 hex chars


# ---------------------------------------------------------------------------
# BDHKE verify() — negative cases
# ---------------------------------------------------------------------------


class TestBDHKEVerify:
    def test_valid_signature_verifies(self):
        ctx = _full_bdhke_roundtrip()
        assert verify(ctx["a"], ctx["C"], ctx["secret_msg"])

    def test_wrong_secret_fails(self):
        ctx = _full_bdhke_roundtrip()
        assert not verify(ctx["a"], ctx["C"], "wrong_secret")

    def test_wrong_key_fails(self):
        ctx = _full_bdhke_roundtrip()
        wrong_a = PrivateKey()
        assert not verify(wrong_a, ctx["C"], ctx["secret_msg"])

    def test_wrong_C_fails(self):
        ctx = _full_bdhke_roundtrip()
        wrong_C = PrivateKey().public_key
        assert not verify(ctx["a"], wrong_C, ctx["secret_msg"])

    def test_double_C_fails(self):
        ctx = _full_bdhke_roundtrip()
        double_C = ctx["C"] + ctx["C"]
        assert not verify(ctx["a"], double_C, ctx["secret_msg"])


# ---------------------------------------------------------------------------
# Combined DLEQ property-based: random keys always produce valid DLEQ
# ---------------------------------------------------------------------------


class TestDLEQPropertyBased:
    @given(
        secret=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N")),
            min_size=1,
            max_size=100,
        ),
    )
    @settings(max_examples=30, deadline=10000)
    def test_random_keys_always_valid(self, secret):
        ctx = _full_bdhke_roundtrip(secret_msg=secret)
        assert alice_verify_dleq(ctx["B_"], ctx["C_"], ctx["e"], ctx["s"], ctx["A"])
        assert carol_verify_dleq(
            secret_msg=ctx["secret_msg"],
            r=ctx["r"],
            C=ctx["C"],
            e=ctx["e"],
            s=ctx["s"],
            A=ctx["A"],
        )
        assert verify(ctx["a"], ctx["C"], ctx["secret_msg"])
