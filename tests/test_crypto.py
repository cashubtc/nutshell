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
        == "0215fdc277c704590f3c3bcc08cf9a8f748f46619b96268cece86442b6c3ac461b"
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
        == "0215fdc277c704590f3c3bcc08cf9a8f748f46619b96268cece86442b6c3ac461b"
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

    C = step3_alice(C_, r)

    assert (
        C.serialize().hex()
        == "025cc16fe33b953e2ace39653efb3e7a7049711ae1d8a2f7a9108753f1cdea742b"
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
        == "600332a05c0722af1feb9ee95b2917eeafaa14cf17852f116f35e059b9c1ea0a"
    )
    assert (
        s.serialize()
        == "600332a05c0722af1feb9ee95b2917eeafaa14cf17852f116f35e059b9c1ea0b"
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
        == "345b33beec35d507701f513cf4cf60aea6a8c9f9c3b576a4fbb0f01f04888d90"
    )
    assert (
        s.serialize()
        == "887e1d5d42b8a3f08679714e0731091912a66ee39b96e53f55de302a113656d4"
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
    C = step3_alice(C_, r)
    # carol does not know B_ and C_, but she receives C and r from Alice
    assert carol_verify_dleq(secret_msg=secret_msg, C=C, r=r, e=e, s=s, A=A)


def test_dleq_carol_on_proof():
    A = PublicKey(
        bytes.fromhex(
            "0381d73b92c7ed013476c3e4e64b4964e9c742c1ecc3375bb55c0520acc56e1233"
        ),
        raw=True,
    )
    proof = Proof.parse_obj(
        {
            "id": "00ad268c4d1f5826",
            "amount": 1,
            "secret": "202caa260a09bdfb97de9d4c2f43fe4858a2a35a3e84b03471f28f92e5fadf97",
            "C": "039eafe0acd4a39935bd878aed21259fa1019fb62f54bd5f160f33cb44898d82f1",
            "dleq": {
                "e": "d9d1ee82155a5630c240607f3ab1d44fbfa5e605b44f0fc9faccfa636215d6bb",
                "s": "46035f798873d26fdaa85b571147253706c176283495352fe879f5749e766bd5",
                "r": "dda903ccb8fac8d031e7057b4270c802f1f6b181672bb3439a7bf2d7c3d516cd",
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
