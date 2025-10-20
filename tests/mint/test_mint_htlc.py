
import pytest
from cashu.core.errors import CashuError
from cashu.core.htlc import (
    BlindingFactor,
    HTLCSecret,
    Tags,
    hash_to_curve,
    step1_alice_carol_check,
    step2_bob_carol_check,
    step3_alice_makes_secret,
    step4_bob_makes_secret,
)


# an HTLC secret is a 32 byte number
def test_htlc_secret_bytes():
    # 256 bits, 32 bytes, 64 hex chars
    secret = "00" * 32
    HTLCSecret(secret)
    # 33 bytes
    with pytest.raises(ValueError):
        HTLCSecret("00" * 33)


def test_htlc_secret_random():
    HTLCSecret.random()
    assert True


def test_htlc():

    # A (sender)
    x1 = HTLCSecret.random()
    Y1 = hash_to_curve(x1.bytes)

    # B (receiver)
    x2 = HTLCSecret.random()
    Y2 = hash_to_curve(x2.bytes)

    # Carol (mint)
    # carol gets Y1, Y2 and computes a blinding factor for A and B
    # that only carol knows
    b_carol_a = BlindingFactor.random()
    b_carol_b = BlindingFactor.random()

    # A
    # A gets the blinding factor from somewhere (a different endpoint)
    # for now, we just pass it in
    C_a = step1_alice_carol_check(Y1, Y2, b_carol_a)
    assert C_a

    # B
    # B gets the blinding factor from somewhere (a different endpoint)
    C_b = step2_bob_carol_check(Y1, Y2, b_carol_b, C_a)
    assert C_b

    # A confirms that C_b is what it expects
    # A gets C_b from somewhere
    assert C_b == C_a + b_carol_b.point

    # A creates the secret for B
    C_b_A = step3_alice_makes_secret(x1, b_carol_a)

    # B gets C_b_A and creates the secret from A
    C_a_B = step4_bob_makes_secret(x2, b_carol_b)
    assert C_a_B

    # check that with C_b_A and C_a_B both parties can derive the same keys
    # A
    A_likes_B = C_a_B + b_carol_a.point
    # B
    B_likes_A = C_b_A + b_carol_b.point
    assert A_likes_B == B_likes_A


def test_htlc_tags():
    tags = Tags()
    tags["a"] = "b"
    assert tags.get_tag("a") == "b"
    assert tags["a"] == "b"
    assert "a" in tags
    assert str(tags) == '[["a", "b"]]'
    tags_dict = tags.to_dict()
    assert tags_dict["a"] == "b"
    tags2 = Tags(tags_dict)
    assert tags2.get_tag("a") == "b"

    tags3 = Tags([["a", "b"]])
    assert tags3.get_tag("a") == "b"


def test_htlc_tags_duplicate():
    with pytest.raises(ValueError):
        Tags([["a", "b"], ["a", "c"]])


def test_htlc_tags_case_insensitive():
    tags = Tags()
    tags.add_tag("a", "b")
    assert tags.get_tag("A") == "b"
    assert tags.get_tag("a") == "b"
    assert "a" in tags
    assert "A" in tags


# test hash that is too large
def test_htlc_hash_too_large():
    with pytest.raises(CashuError, match="Hash is too long"):
        # this is a preimage, not a hash. the name "data" is confusing.
        # it's the preimage to the HTLC lock.
        # we hash it sha256 to get the hash and then check its length.
        # the hash is 32 bytes, so the preimage can't be longer than 32 bytes.
        # let's try to make it longer.
        # this is 65 hex chars = 32.5 bytes, which is too large
        HTLCSecret("0" * 65)

