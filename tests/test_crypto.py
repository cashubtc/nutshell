from cashu.core.base import Proof
from cashu.core.crypto.b_dhke import (
    alice_verify_dleq,
    carol_verify_dleq,
    derive_dleq_nonce,
    hash_e,
    hash_to_curve,
    step1_alice,
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


def test_dleq_deterministic_nonce_spec_vector():
    # NUT-12 deterministic DLEQ test vector (cashubtc/nuts#368). All values are
    # fixed; the implementation MUST reproduce e and s exactly.
    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        )
    )
    B_ = PublicKey(
        bytes.fromhex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
        )
    )

    A = a.public_key
    assert A
    C_: PublicKey = B_ * a  # type: ignore
    assert (
        A.format(compressed=True).hex()
        == "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    )
    assert (
        C_.format(compressed=True).hex()
        == "0244eccfc7a348274458bb38044c7f3c389b3c2086c7ec18b5812d2877ab937787"
    )

    e, s = step2_bob_dleq(B_, a)
    assert (
        e.to_hex()
        == "2a16ffee280aff3c429045607f9b8e0bf8b35910c44c1b20b9dfaf01b263d7b3"
    )
    assert (
        s.to_hex()
        == "9df27731238334718d120d4f74611a7c668233f988e687ac3fb188f0a34a2dab"
    )

    # Verification (e == hash(R1, R2, A, C_)) MUST pass.
    assert alice_verify_dleq(B_, C_, e, s, A)


def test_dleq_deterministic_nonce_is_reproducible():
    # Same key + same B_ must always yield the same (e, s).
    B_, _ = step1_alice("test_message")
    a = PrivateKey()
    e1, s1 = step2_bob_dleq(B_, a)
    e2, s2 = step2_bob_dleq(B_, a)
    assert e1.to_hex() == e2.to_hex()
    assert s1.to_hex() == s2.to_hex()


def test_dleq_deterministic_nonce_varies_with_context():
    a = PrivateKey()
    other = PrivateKey()
    B1, _ = step1_alice("message_one")
    B2, _ = step1_alice("message_two")

    A = a.public_key
    assert A
    C1: PublicKey = B1 * a  # type: ignore
    C2: PublicKey = B2 * a  # type: ignore

    # Different B_ -> different nonce.
    assert (
        derive_dleq_nonce(a, A, B1, C1).to_hex()
        != derive_dleq_nonce(a, A, B2, C2).to_hex()
    )
    # Different private key -> different nonce for the same context.
    other_A = other.public_key
    assert other_A
    other_C1: PublicKey = B1 * other  # type: ignore
    assert (
        derive_dleq_nonce(a, A, B1, C1).to_hex()
        != derive_dleq_nonce(other, other_A, B1, other_C1).to_hex()
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


def test_nut20_test_vector():
    from hashlib import sha256

    from cashu.core.base import BlindedMessage
    from cashu.core.nuts import nut20

    quote_id = "0192d3c0-7e8a-7c3d-8e9f-1a2b3c4d5e6f"
    outputs = [
        BlindedMessage(
            amount=1,
            id="009a1f293253e41e",
            B_="036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2",
        ),
        BlindedMessage(
            amount=1,
            id="009a1f293253e41e",
            B_="021f8a566c205633d029094747d2e18f44e05993dda7a5f88f496078205f656e59",
        ),
    ]
    pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    privkey_hex = "0000000000000000000000000000000000000000000000000000000000000001"
    expected_msg_to_sign = bytes.fromhex(
        "43617368755f4d696e7451756f74655369675f7631"
        "0000002430313932643363302d376538612d376333642d386539662d316132623363346435653666"
        "000000010100000021036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
        "000000010100000021021f8a566c205633d029094747d2e18f44e05993dda7a5f88f496078205f656e59"
    )
    expected_hash = "c164fd384879f74ab6ea2e7cf13d90ed42e6df9d5de607eeb5c9cc7d36fb1c21"
    expected_sig = "4881093a332ff7c79f3e598ce5b249d64978b47165a0b19c18adf0ced0246228e61e702f0abaf1bf27b92be4336bdbabacfbe4c914076386b3c66fdcd0b3480e"

    msg_hash = nut20.construct_message(quote_id, outputs)
    assert sha256(expected_msg_to_sign).hexdigest() == expected_hash
    assert msg_hash.hex() == expected_hash

    # Verify signature generation and verification
    sig = nut20.sign_mint_quote(quote_id, outputs, privkey_hex)
    assert nut20.verify_mint_quote(quote_id, outputs, pubkey, sig) is True

    # Verify signature verification on test vector's expected signature
    assert nut20.verify_mint_quote(quote_id, outputs, pubkey, expected_sig) is True


def test_nut29_test_vector():
    from hashlib import sha256

    from cashu.core.base import BlindedMessage
    from cashu.core.nuts import nut20

    quote_id = "locked-quote"
    outputs = [
        BlindedMessage(
            amount=1,
            id="009a1f293253e41e",
            B_="036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2",
        ),
        BlindedMessage(
            amount=1,
            id="009a1f293253e41e",
            B_="021f8a566c205633d029094747d2e18f44e05993dda7a5f88f496078205f656e59",
        ),
    ]
    pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    privkey_hex = "0000000000000000000000000000000000000000000000000000000000000001"
    expected_msg_to_sign = bytes.fromhex(
        "43617368755f4d696e7451756f74655369675f7631"
        "0000000c6c6f636b65642d71756f7465"
        "000000010100000021036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
        "000000010100000021021f8a566c205633d029094747d2e18f44e05993dda7a5f88f496078205f656e59"
    )
    expected_hash = "03dc68d6617bba502d8648efd0965bf393841082cf04fd03e5de4bcb5777cdfc"
    expected_sig = "a913e48177027d87e0e38c6f2021763c46997ff4866a4b63ebca800b0776b28519eab37377cf9bc1869e489d7b25747b7a998eaa1c33c2cac7fa168449d8267a"

    msg_hash = nut20.construct_message(quote_id, outputs)
    assert sha256(expected_msg_to_sign).hexdigest() == expected_hash
    assert msg_hash.hex() == expected_hash

    # Verify signature generation and verification
    sig = nut20.sign_mint_quote(quote_id, outputs, privkey_hex)
    assert nut20.verify_mint_quote(quote_id, outputs, pubkey, sig) is True

    # Verify signature verification on test vector's expected signature
    assert nut20.verify_mint_quote(quote_id, outputs, pubkey, expected_sig) is True
