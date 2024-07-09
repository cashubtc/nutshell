from cashu.core.base import Proof
from cashu.core.crypto.b_dhke import (
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
)
from cashu.core.crypto.secp import PrivateKey, PublicKey


def test_hash_to_curve():
    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
    )
    assert (
        result.serialize().hex()
        == "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725"
    )
    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )
    assert (
        result.serialize().hex()
        == "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf"
    )
    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        )
    )
    assert (
        result.serialize().hex()
        == "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f"
    )


def test_step1():
    secret_msg = "test_message"
    B_, blinding_factor = step1_alice(
        secret_msg,
        blinding_factor=PrivateKey(
            privkey=bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            )  # 32 bytes
        ),
    )

    assert (
        B_.serialize().hex()
        == "025cc16fe33b953e2ace39653efb3e7a7049711ae1d8a2f7a9108753f1cdea742b"
    )
    assert blinding_factor.private_key == bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )


def test_step2():
    B_, _ = step1_alice(
        "test_message",
        blinding_factor=PrivateKey(
            privkey=bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            raw=True,
        ),
    )
    a = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    C_, e, s = step2_bob(B_, a)
    assert (
        C_.serialize().hex()
        == "025cc16fe33b953e2ace39653efb3e7a7049711ae1d8a2f7a9108753f1cdea742b"
    )


def test_step3():
    # C = C_ - A.mult(r)
    # C_ from test_step2
    C_ = PublicKey(
        bytes.fromhex(
            "025cc16fe33b953e2ace39653efb3e7a7049711ae1d8a2f7a9108753f1cdea742b"
        ),
        raw=True,
    )
    r = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )

    A = PublicKey(
        pubkey=b"\x02"
        + bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        raw=True,
    )
    C = step3_alice(C_, r, A)

    assert (
        C.serialize().hex()
        == "0271bf0d702dbad86cbe0af3ab2bfba70a0338f22728e412d88a830ed0580b9de4"
    )


def test_dleq_hash_e():
    C_ = PublicKey(
        bytes.fromhex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
        ),
        raw=True,
    )
    K = PublicKey(
        pubkey=b"\x02"
        + bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        raw=True,
    )
    R1 = PublicKey(
        pubkey=b"\x02"
        + bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        raw=True,
    )
    R2 = PublicKey(
        pubkey=b"\x02"
        + bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        raw=True,
    )
    e = hash_e(R1, R2, K, C_)
    assert e.hex() == "a4dc034b74338c28c6bc3ea49731f2a24440fc7c4affc08b31a93fc9fbe6401e"


def test_dleq_step2_bob_dleq():
    B_, _ = step1_alice(
        "test_message",
        blinding_factor=PrivateKey(
            privkey=bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            raw=True,
        ),
    )
    a = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    p_bytes = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )  # 32 bytes
    e, s = step2_bob_dleq(B_, a, p_bytes)
    assert (
        e.serialize()
        == "a608ae30a54c6d878c706240ee35d4289b68cfe99454bbfa6578b503bce2dbe1"
    )
    assert (
        s.serialize()
        == "a608ae30a54c6d878c706240ee35d4289b68cfe99454bbfa6578b503bce2dbe2"
    )  # differs from e only in least significant byte because `a = 0x1`

    # change `a`
    a = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000001111"
        ),
        raw=True,
    )
    e, s = step2_bob_dleq(B_, a, p_bytes)
    assert (
        e.serialize()
        == "076cbdda4f368053c33056c438df014d1875eb3c8b28120bece74b6d0e6381bb"
    )
    assert (
        s.serialize()
        == "b6d41ac1e12415862bf8cace95e5355e9262eab8a11d201dadd3b6e41584ea6e"
    )


def test_dleq_alice_verify_dleq():
    # e from test_step2_bob_dleq for a=0x1
    e = PrivateKey(
        bytes.fromhex(
            "9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9"
        ),
        raw=True,
    )
    # s from test_step2_bob_dleq for a=0x1
    s = PrivateKey(
        bytes.fromhex(
            "9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da"
        ),
        raw=True,
    )

    a = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    A = a.pubkey
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
        ),
        raw=True,
    )

    # # C_ is the same as if we did:
    # a = PrivateKey(
    #     privkey=bytes.fromhex(
    #         "0000000000000000000000000000000000000000000000000000000000000001"
    #     ),
    #     raw=True,
    # )
    # C_, e, s = step2_bob(B_, a)

    C_ = PublicKey(
        bytes.fromhex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
        ),
        raw=True,
    )

    assert alice_verify_dleq(B_, C_, e, s, A)


def test_dleq_alice_direct_verify_dleq():
    # ----- test again with B_ and C_ as per step1 and step2
    a = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    A = a.pubkey
    assert A
    B_, _ = step1_alice(
        "test_message",
        blinding_factor=PrivateKey(
            privkey=bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            raw=True,
        ),
    )
    C_, e, s = step2_bob(B_, a)
    assert alice_verify_dleq(B_, C_, e, s, A)


def test_dleq_carol_verify_from_bob():
    a = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    A = a.pubkey
    assert A
    assert (
        A.serialize().hex()
        == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    secret_msg = "test_message"
    r = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
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
        ),
        raw=True,
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
        r=PrivateKey(bytes.fromhex(proof.dleq.r), raw=True),
        C=PublicKey(bytes.fromhex(proof.C), raw=True),
        e=PrivateKey(bytes.fromhex(proof.dleq.e), raw=True),
        s=PrivateKey(bytes.fromhex(proof.dleq.s), raw=True),
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
        result.serialize().hex()
        == "0266687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
    )

    result = hash_to_curve_deprecated(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )
    assert (
        result.serialize().hex()
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
        result.serialize().hex()
        == "02076c988b353fcbb748178ecb286bc9d0b4acf474d4ba31ba62334e46c97c416a"
    )


def test_step1_deprecated():
    secret_msg = "test_message"
    B_, blinding_factor = step1_alice_deprecated(
        secret_msg,
        blinding_factor=PrivateKey(
            privkey=bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            )  # 32 bytes
        ),
    )

    assert (
        B_.serialize().hex()
        == "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
    )
    assert blinding_factor.private_key == bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )


def test_step2_deprecated():
    B_, _ = step1_alice_deprecated(
        "test_message",
        blinding_factor=PrivateKey(
            privkey=bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            raw=True,
        ),
    )
    a = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    C_, e, s = step2_bob(B_, a)
    assert (
        C_.serialize().hex()
        == "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
    )


def test_step3_deprecated():
    # C = C_ - A.mult(r)
    # C_ from test_step2_deprecated
    C_ = PublicKey(
        bytes.fromhex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
        ),
        raw=True,
    )
    r = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )

    A = PublicKey(
        pubkey=b"\x02"
        + bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        raw=True,
    )
    C = step3_alice(C_, r, A)

    assert (
        C.serialize().hex()
        == "03c724d7e6a5443b39ac8acf11f40420adc4f99a02e7cc1b57703d9391f6d129cd"
    )


def test_dleq_step2_bob_dleq_deprecated():
    B_, _ = step1_alice_deprecated(
        "test_message",
        blinding_factor=PrivateKey(
            privkey=bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            raw=True,
        ),
    )
    a = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    p_bytes = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )  # 32 bytes
    e, s = step2_bob_dleq(B_, a, p_bytes)
    assert (
        e.serialize()
        == "9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9"
    )
    assert (
        s.serialize()
        == "9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da"
    )  # differs from e only in least significant byte because `a = 0x1`

    # change `a`
    a = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000001111"
        ),
        raw=True,
    )
    e, s = step2_bob_dleq(B_, a, p_bytes)
    assert (
        e.serialize()
        == "df1984d5c22f7e17afe33b8669f02f530f286ae3b00a1978edaf900f4721f65e"
    )
    assert (
        s.serialize()
        == "828404170c86f240c50ae0f5fc17bb6b82612d46b355e046d7cd84b0a3c934a0"
    )
