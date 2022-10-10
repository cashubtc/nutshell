import pytest

from cashu.core.b_dhke import hash_to_curve


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
    result = hash_to_curve(
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        )
    )
    assert (
        result.serialize().hex()
        == "02076c988b353fcbb748178ecb286bc9d0b4acf474d4ba31ba62334e46c97c416a"
    )
