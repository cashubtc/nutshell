from cashu.core.crypto.bls import PrivateKey, PublicKey
from cashu.core.crypto.bls_dhke import (
    batch_pairing_verification,
    hash_to_curve,
    keyed_verification,
    pairing_verification,
    step1_alice,
    step2_bob,
    step3_alice,
)


def test_hash_to_curve():
    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
    )
    assert isinstance(result, PublicKey)
    assert result.group == "G1"
    assert (
        result.format().hex()
        == "a0687086dadc17db3c73fc63d58d61569ca32752a9b92c4e543692bc6b87b293fdcb4e9c870ab6e6d08127deb9382fb9"
    )
    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )
    assert (
        result.format().hex()
        == "8dbdd24f1bc6f485fda14721cb1f15ba72ba34c05f89b5ca38c2a222c07158f471011d50a371cdb365da6bc7ef4139f4"
    )


def test_bls_steps():
    secret_msg = "test_message"

    # Alice step 1
    B_, r = step1_alice(secret_msg)
    assert isinstance(B_, PublicKey)
    assert isinstance(r, PrivateKey)

    # Bob step 2
    a = PrivateKey()  # Mint private key
    C_, dummy_e, dummy_s = step2_bob(B_, a)
    assert dummy_e is None
    assert dummy_s is None
    assert isinstance(C_, PublicKey)

    # Alice step 3
    A = a.public_key  # Mint public key (not strictly needed for unblinding in BLS)
    C = step3_alice(C_, r, A)
    assert isinstance(C, PublicKey)

    # Verification (Mint)
    assert keyed_verification(a, C, secret_msg)

    # Verification (Wallet using Pairings)
    assert pairing_verification(A, C, secret_msg)


def test_batch_pairing_verification():
    secrets = ["msg1", "msg2", "msg3"]
    K2s = []
    Cs = []

    a1 = PrivateKey()
    a2 = PrivateKey()

    # msg1 signed by a1
    B1_, r1 = step1_alice(secrets[0])
    C1_, _, _ = step2_bob(B1_, a1)
    C1 = step3_alice(C1_, r1, a1.public_key)
    K2s.append(a1.public_key)
    Cs.append(C1)

    # msg2 signed by a1
    B2_, r2 = step1_alice(secrets[1])
    C2_, _, _ = step2_bob(B2_, a1)
    C2 = step3_alice(C2_, r2, a1.public_key)
    K2s.append(a1.public_key)
    Cs.append(C2)

    # msg3 signed by a2
    B3_, r3 = step1_alice(secrets[2])
    C3_, _, _ = step2_bob(B3_, a2)
    C3 = step3_alice(C3_, r3, a2.public_key)
    K2s.append(a2.public_key)
    Cs.append(C3)

    assert batch_pairing_verification(K2s, Cs, secrets)

    # Test failure
    Cs[0] = C2  # wrong signature for msg1
    assert not batch_pairing_verification(K2s, Cs, secrets)


def test_deterministic_bls_steps():
    secret_msg = "test_message"

    r = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000003"
        )
    )
    a = PrivateKey(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        )
    )

    B_, _r = step1_alice(secret_msg, r)
    assert _r.to_hex() == r.to_hex()

    C_, dummy_e, dummy_s = step2_bob(B_, a)
    assert dummy_e is None

    A = a.public_key
    C = step3_alice(C_, r, A)

    assert keyed_verification(a, C, secret_msg)
    assert pairing_verification(A, C, secret_msg)

    # Just asserting they don't throw and give specific hex values
    assert (
        B_.format().hex()
        == "8e88c5f6a93f653784a66b033a00e52128499e18b095c2a56f080d1c2a937ffc9ef4600804a48d087bbd1f662f6b068f"
    )
    assert (
        C_.format().hex()
        == "8d52d7a6cbe5e99858d5c15c092d11a0c387c78917471211082a6e5afc2a79680dfa188fafe5d4a51c5398ce160e7a16"
    )
    assert (
        C.format().hex()
        == "b7a4881059133fd91a8753600d9a5e524c65d6224f6fe2d5aef9e59f1507fdad90b3b4d48ee46da5c8dfaa0b88e28b69"
    )
