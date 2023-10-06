import pytest

from cashu.core.base import TokenV3
from cashu.core.helpers import calculate_number_of_blank_outputs
from cashu.core.split import amount_split


def test_get_output_split():
    assert amount_split(13) == [1, 4, 8]


def test_tokenv3_deserialize_get_attributes():
    token_str = (
        "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIkplaFpMVTZuQ3BSZCIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogIjBFN2lDazRkVmxSZjVQRjFnNFpWMnci"
        "LCAiQyI6ICIwM2FiNTgwYWQ5NTc3OGVkNTI5NmY4YmVlNjU1ZGJkN2Q2NDJmNWQzMmRlOGUyNDg0NzdlMGI0ZDZhYTg2M2ZjZDUifSwgeyJpZCI6ICJKZWhaTFU2bkNwUmQiLCAiYW"
        "1vdW50IjogOCwgInNlY3JldCI6ICJzNklwZXh3SGNxcXVLZDZYbW9qTDJnIiwgIkMiOiAiMDIyZDAwNGY5ZWMxNmE1OGFkOTAxNGMyNTliNmQ2MTRlZDM2ODgyOWYwMmMzODc3M2M0"
        "NzIyMWY0OTYxY2UzZjIzIn1dLCAibWludCI6ICJodHRwOi8vbG9jYWxob3N0OjMzMzgifV19"
    )
    token = TokenV3.deserialize(token_str)
    assert token.get_amount() == 10
    assert len(token.get_proofs()) == 2


def test_tokenv3_deserialize_serialize_with_dleq():
    token_str = (
        "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjFjQ05JQVoyWC93M"
        "SIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogIjZmZjFiY2VlOGUzMzk2NGE4ZDNjNGQ5NzYwNzdiZ"
        "DI4ZGVkZWJkODYyMDU0MDQzNDY4ZjU5ZDFiZjI1OTQzN2QiLCAiQyI6ICIwM2I3ZD"
        "lkMzIzYTAxOWJlNTE4NzRlOGE5OGY1NDViOTg3Y2JmNmU5MWUwMDc1YTFhZjQ3MjY2NDMxOGRlZ"
        "TQzZTUiLCAiZGxlcSI6IHsiZSI6ICI1ZjkxMGQ4NTc0M2U0OTI0ZjRiNjlkNzhjM"
        "jFjYTc1ZjEzNzg3Zjc3OTE1NWRmMjMzMjJmYTA1YjU5ODdhYzNmIiwgInMiOiAiZTc4Y2U0MzNiZ"
        "WNlZTNjNGU1NzM4ZDdjMzRlNDQyZWQ0MmJkMzk0MjI0ZTc3MjE4OGFjMmI5MzZmM"
        "jA2Y2QxYSIsICJyIjogIjI3MzM3ODNmOTQ4MWZlYzAxNzdlYmM4ZjBhOTI2OWVjOGFkNzU5MDU2ZT"
        "k3MTRiMWEwYTEwMDQ3MmY2Y2Y5YzIifX0sIHsiaWQiOiAiMWNDTklBWjJYL3cxIi"
        "wgImFtb3VudCI6IDgsICJzZWNyZXQiOiAiMmFkNDMyZDRkNTg2MzJiMmRlMzI0ZmQxYmE5OTcyZmE"
        "4MDljNmU3ZGE1ZTkyZWVmYjBiNjYxMmQ5M2Q3ZTAwMCIsICJDIjogIjAzMmFmYjg"
        "zOWQwMmRmMWNhOGY5ZGZjNTI1NzUxN2Q0MzY4YjdiMTc0MzgzM2JlYWUzZDQzNmExYmQwYmJkYjVk"
        "OCIsICJkbGVxIjogeyJlIjogImY0NjM2MzU5YTUzZGQxNGEyNmUyNTMyMDQxZWIx"
        "MDE2OTk1ZTg4NzgwODY0OWFlY2VlNTcwZTA5ZTk2NTU3YzIiLCAicyI6ICJmZWYzMGIzMDcwMDJkMW"
        "VjNWZiZjg0ZGZhZmRkMGEwOTdkNDJlMDYxNTZiNzdiMTMzMmNjNGZjNGNjYWEyOD"
        "JmIiwgInIiOiAiODQ5MjQxNzBlYzc3ZjhjMDNmZDRlZTkyZTA3MjdlMzYyNTliZjRhYTc4NTBjZTc2"
        "NDExMDQ0MmNlNmVlM2FjYyJ9fV0sICJtaW50IjogImh0dHA6Ly9sb2NhbGhvc3Q6MzMzOCJ9XX0="
    )
    token = TokenV3.deserialize(token_str)
    assert token.serialize(include_dleq=True) == token_str


def test_tokenv3_deserialize_serialize():
    token_str = (
        "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIkplaFpMVTZuQ3BSZCIsICJh"
        "bW91bnQiOiAyLCAic2VjcmV0IjogIjBFN2lDazRkVmxSZjVQRjFnNFpWMnci"
        "LCAiQyI6ICIwM2FiNTgwYWQ5NTc3OGVkNTI5NmY4YmVlNjU1ZGJkN2Q2NDJmNWQzMmRlOG"
        "UyNDg0NzdlMGI0ZDZhYTg2M2ZjZDUifSwgeyJpZCI6ICJKZWhaTFU2bkNwUmQiLCAiYW"
        "1vdW50IjogOCwgInNlY3JldCI6ICJzNklwZXh3SGNxcXVLZDZYbW9qTDJnIiwgIkMiOiAiM"
        "DIyZDAwNGY5ZWMxNmE1OGFkOTAxNGMyNTliNmQ2MTRlZDM2ODgyOWYwMmMzODc3M2M0"
        "NzIyMWY0OTYxY2UzZjIzIn1dLCAibWludCI6ICJodHRwOi8vbG9jYWxob3N0OjMzMzgifV19"
    )
    token = TokenV3.deserialize(token_str)
    assert token.serialize() == token_str


def test_tokenv3_deserialize_serialize_no_dleq():
    token_str = (
        "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjFjQ05JQVoyWC93MSIsICJhb"
        "W91bnQiOiAyLCAic2VjcmV0IjogIjZmZjFiY2VlOGUzMzk2NGE4ZDNjNGQ5NzYwNzdiZ"
        "DI4ZGVkZWJkODYyMDU0MDQzNDY4ZjU5ZDFiZjI1OTQzN2QiLCAiQyI6ICIwM2I3ZDlkMzIzY"
        "TAxOWJlNTE4NzRlOGE5OGY1NDViOTg3Y2JmNmU5MWUwMDc1YTFhZjQ3MjY2NDMxOGRlZ"
        "TQzZTUiLCAiZGxlcSI6IHsiZSI6ICI1ZjkxMGQ4NTc0M2U0OTI0ZjRiNjlkNzhjMjFjYTc1Z"
        "jEzNzg3Zjc3OTE1NWRmMjMzMjJmYTA1YjU5ODdhYzNmIiwgInMiOiAiZTc4Y2U0MzNiZ"
        "WNlZTNjNGU1NzM4ZDdjMzRlNDQyZWQ0MmJkMzk0MjI0ZTc3MjE4OGFjMmI5MzZmMjA2Y2QxY"
        "SIsICJyIjogIjI3MzM3ODNmOTQ4MWZlYzAxNzdlYmM4ZjBhOTI2OWVjOGFkNzU5MDU2ZT"
        "k3MTRiMWEwYTEwMDQ3MmY2Y2Y5YzIifX0sIHsiaWQiOiAiMWNDTklBWjJYL3cxIiwgImFtb3"
        "VudCI6IDgsICJzZWNyZXQiOiAiMmFkNDMyZDRkNTg2MzJiMmRlMzI0ZmQxYmE5OTcyZmE"
        "4MDljNmU3ZGE1ZTkyZWVmYjBiNjYxMmQ5M2Q3ZTAwMCIsICJDIjogIjAzMmFmYjgzOWQwMmR"
        "mMWNhOGY5ZGZjNTI1NzUxN2Q0MzY4YjdiMTc0MzgzM2JlYWUzZDQzNmExYmQwYmJkYjVk"
        "OCIsICJkbGVxIjogeyJlIjogImY0NjM2MzU5YTUzZGQxNGEyNmUyNTMyMDQxZWIxMDE2OTk1"
        "ZTg4NzgwODY0OWFlY2VlNTcwZTA5ZTk2NTU3YzIiLCAicyI6ICJmZWYzMGIzMDcwMDJkMW"
        "VjNWZiZjg0ZGZhZmRkMGEwOTdkNDJlMDYxNTZiNzdiMTMzMmNjNGZjNGNjYWEyODJmIiwgIn"
        "IiOiAiODQ5MjQxNzBlYzc3ZjhjMDNmZDRlZTkyZTA3MjdlMzYyNTliZjRhYTc4NTBjZTc2"
        "NDExMDQ0MmNlNmVlM2FjYyJ9fV0sICJtaW50IjogImh0dHA6Ly9sb2NhbGhvc3Q6MzMzOCJ9XX0="
    )
    token_str_no_dleq = (
        "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjFjQ05JQVoyWC93MSIsICJhbW91bn"
        "QiOiAyLCAic2VjcmV0IjogIjZmZjFiY2VlOGUzMzk2NGE4ZDNjNGQ5NzYwNzdiZDI4"
        "ZGVkZWJkODYyMDU0MDQzNDY4ZjU5ZDFiZjI1OTQzN2QiLCAiQyI6ICIwM2I3ZDlkMzIzYTAxOWJlN"
        "TE4NzRlOGE5OGY1NDViOTg3Y2JmNmU5MWUwMDc1YTFhZjQ3MjY2NDMxOGRlZTQzZTU"
        "ifSwgeyJpZCI6ICIxY0NOSUFaMlgvdzEiLCAiYW1vdW50IjogOCwgInNlY3JldCI6ICIyYWQ0MzJkN"
        "GQ1ODYzMmIyZGUzMjRmZDFiYTk5NzJmYTgwOWM2ZTdkYTVlOTJlZWZiMGI2NjEyZD"
        "kzZDdlMDAwIiwgIkMiOiAiMDMyYWZiODM5ZDAyZGYxY2E4ZjlkZmM1MjU3NTE3ZDQzNjhiN2IxNzQz"
        "ODMzYmVhZTNkNDM2YTFiZDBiYmRiNWQ4In1dLCAibWludCI6ICJodHRwOi8vbG9jY"
        "Wxob3N0OjMzMzgifV19"
    )
    token = TokenV3.deserialize(token_str)
    assert token.serialize(include_dleq=False) == token_str_no_dleq


def test_tokenv3_deserialize_with_memo():
    token_str = (
        "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIkplaFpMVTZuQ3BSZCIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogIjBFN2lDazRkVmxSZjV"
        "QRjFnNFpWMnciLCAiQyI6ICIwM2FiNTgwYWQ5NTc3OGVkNTI5NmY4YmVlNjU1ZGJkN2Q2NDJmNWQzMmRlOGUyNDg0NzdlMGI0ZDZhYTg2M2ZjZDUifSwg"
        "eyJpZCI6ICJKZWhaTFU2bkNwUmQiLCAiYW1vdW50IjogOCwgInNlY3JldCI6ICJzNklwZXh3SGNxcXVLZDZYbW9qTDJnIiwgIkMiOiAiMDIyZDAwNGY5Z"
        "WMxNmE1OGFkOTAxNGMyNTliNmQ2MTRlZDM2ODgyOWYwMmMzODc3M2M0NzIyMWY0OTYxY2UzZjIzIn1dLCAibWludCI6ICJodHRwOi8vbG9jYWxob3N0Oj"
        "MzMzgifV0sICJtZW1vIjogIlRlc3QgbWVtbyJ9"
    )
    token = TokenV3.deserialize(token_str)
    assert token.serialize() == token_str
    assert token.memo == "Test memo"


def test_serialize_example_token_nut00():
    token_dict = {
        "token": [
            {
                "mint": "https://8333.space:3338",
                "proofs": [
                    {
                        "id": "9bb9d58392cd823e",
                        "amount": 2,
                        "secret": "EhpennC9qB3iFlW8FZ_pZw",
                        "C": "02c020067db727d586bc3183aecf97fcb800c3f4cc4759f69c626c9db5d8f5b5d4",
                    },
                    {
                        "id": "9bb9d58392cd823e",
                        "amount": 8,
                        "secret": "TmS6Cv0YT5PU_5ATVKnukw",
                        "C": "02ac910bef28cbe5d7325415d5c263026f15f9b967a079ca9779ab6e5c2db133a7",
                    },
                ],
            }
        ],
        "memo": "Thank you.",
    }
    tokenObj = TokenV3.parse_obj(token_dict)
    assert (
        tokenObj.serialize()
        == "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjliYjlkNTgzOTJjZDg"
        "yM2UiLCAiYW1vdW50IjogMiwgInNlY3JldCI6ICJFaHBlbm5DOXFCM2lGbFc4Rlpf"
        "cFp3IiwgIkMiOiAiMDJjMDIwMDY3ZGI3MjdkNTg2YmMzMTgzYWVjZjk3ZmNiODAwY"
        "zNmNGNjNDc1OWY2OWM2MjZjOWRiNWQ4ZjViNWQ0In0sIHsiaWQiOiAiOWJiOWQ1OD"
        "M5MmNkODIzZSIsICJhbW91bnQiOiA4LCAic2VjcmV0IjogIlRtUzZDdjBZVDVQVV8"
        "1QVRWS251a3ciLCAiQyI6ICIwMmFjOTEwYmVmMjhjYmU1ZDczMjU0MTVkNWMyNjMw"
        "MjZmMTVmOWI5NjdhMDc5Y2E5Nzc5YWI2ZTVjMmRiMTMzYTcifV0sICJtaW50IjogI"
        "mh0dHBzOi8vODMzMy5zcGFjZTozMzM4In1dLCAibWVtbyI6ICJUaGFuayB5b3UuIn0="
    )


def test_calculate_number_of_blank_outputs():
    # Example from NUT-08 specification.
    fee_reserve_sat = 1000
    expected_n_blank_outputs = 10
    n_blank_outputs = calculate_number_of_blank_outputs(fee_reserve_sat)
    assert n_blank_outputs == expected_n_blank_outputs


def test_calculate_number_of_blank_outputs_for_small_fee_reserve():
    # There should always be at least one blank output.
    fee_reserve_sat = 1
    expected_n_blank_outputs = 1
    n_blank_outputs = calculate_number_of_blank_outputs(fee_reserve_sat)
    assert n_blank_outputs == expected_n_blank_outputs


def test_calculate_number_of_blank_outputs_for_zero_fee_reserve():
    # Negative fee reserve is not supported.
    fee_reserve_sat = 0
    n_blank_outputs = calculate_number_of_blank_outputs(fee_reserve_sat)
    assert n_blank_outputs == 0


def test_calculate_number_of_blank_outputs_fails_for_negative_fee_reserve():
    # Negative fee reserve is not supported.
    fee_reserve_sat = -1
    with pytest.raises(AssertionError):
        _ = calculate_number_of_blank_outputs(fee_reserve_sat)
