from cashu.core.crypto.b_dhke import (
    hash_to_curve,
    stamp_step1_bob,
    stamp_step2_alice_verify,
    step1_alice,
    step2_bob,
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
        == "0266687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
    )

    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )
    assert (
        result.serialize().hex()
        == "02ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5"
    )


def test_hash_to_curve_iteration():
    """This input causes multiple rounds of the hash_to_curve algorithm."""
    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        )
    )
    assert (
        result.serialize().hex()
        == "02076c988b353fcbb748178ecb286bc9d0b4acf474d4ba31ba62334e46c97c416a"
    )


def test_step1():
    """"""
    B_, blinding_factor = step1_alice(
        "test_message",
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
    C_ = step2_bob(B_, a)
    assert (
        C_.serialize().hex()
        == "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
    )


def test_step3():
    # C = C_ - A.mult(r)
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


def test_stamp_sign_verify():
    secret_msg = "test_message"
    r = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    B_, _ = step1_alice(secret_msg, blinding_factor=r)
    a = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    A = a.pubkey
    assert A

    C_ = step2_bob(B_, a)
    C = step3_alice(C_, r, A)
    e, s = stamp_step1_bob(secret_msg=secret_msg, C=C, a=a)
    assert stamp_step2_alice_verify(secret_msg=secret_msg, C=C, s=s, e=e, A=A)

    # wrong secret
    secret_msg_wrong = secret_msg + "wrong"
    assert not stamp_step2_alice_verify(secret_msg=secret_msg_wrong, C=C, s=s, e=e, A=A)

    # wrong C
    C_wrong = PublicKey(
        bytes.fromhex(
            "02c724d7e6a5443b39ac8acf11f40420adc4f99a02e7cc1b57703d9391f6d129cd"
        ),
        raw=True,
    )
    assert not stamp_step2_alice_verify(secret_msg=secret_msg, C=C_wrong, s=s, e=e, A=A)

    # wrong s
    s_wrong = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    assert not stamp_step2_alice_verify(secret_msg=secret_msg, C=C, s=s_wrong, e=e, A=A)

    # wrong e
    e_wrong = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        raw=True,
    )
    assert not stamp_step2_alice_verify(secret_msg=secret_msg, C=C, s=s, e=e_wrong, A=A)

    # wrong A
    a_wrong = PrivateKey(
        privkey=bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        ),
        raw=True,
    )
    assert a_wrong.pubkey
    assert not stamp_step2_alice_verify(
        secret_msg=secret_msg, C=C, s=s, e=e, A=a_wrong.pubkey
    )
