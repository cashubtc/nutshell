import pytest

from cashu.core.base import TokenV3, TokenV4, Unit
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


def test_tokenv3_serialize_example_token_nut00():
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
    tokenObj = TokenV3.model_validate(token_dict)
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


def test_tokenv4_deserialize_get_attributes():
    token_str = "cashuBo2F0gaJhaUgArSaMTR9YJmFwgqNhYQJhc3hAMDZlM2UzZjY4NDRiOGZkOGQ3NDMwODY1MjY3MjQ5YWU3NjdhMzg5MDBjODdkNGE0ZDMxOGY4MTJmNzkzN2ZiMmFjWCEDXDG_wzG35Lu4vcAtiycLSQlNqH65afih9N2SrFJn3GCjYWEIYXN4QDBmNTE5YjgwOWZlNmQ5MzZkMjVhYmU1YjhjYTZhMDRlNDc3OTJjOTI0YTkwZWRmYjU1MmM1ZjkzODJkNzFjMDJhY1ghA4CNH8dD8NNt715E37Ar65X6p6uBUoDbe8JipQp81TIgYW11aHR0cDovL2xvY2FsaG9zdDozMzM4YXVjc2F0"
    token = TokenV4.deserialize(token_str)
    assert token.mint == "http://localhost:3338"
    assert token.amounts == [2, 8]
    assert token.amount == 10
    assert token.unit == Unit.sat.name
    assert token.memo is None
    assert len(token.proofs) == 2


def test_tokenv4_deserialize_serialize():
    token_str = "cashuBo2F0gaJhaUgArSaMTR9YJmFwgqNhYQJhc3hAMDZlM2UzZjY4NDRiOGZkOGQ3NDMwODY1MjY3MjQ5YWU3NjdhMzg5MDBjODdkNGE0ZDMxOGY4MTJmNzkzN2ZiMmFjWCEDXDG_wzG35Lu4vcAtiycLSQlNqH65afih9N2SrFJn3GCjYWEIYXN4QDBmNTE5YjgwOWZlNmQ5MzZkMjVhYmU1YjhjYTZhMDRlNDc3OTJjOTI0YTkwZWRmYjU1MmM1ZjkzODJkNzFjMDJhY1ghA4CNH8dD8NNt715E37Ar65X6p6uBUoDbe8JipQp81TIgYW11aHR0cDovL2xvY2FsaG9zdDozMzM4YXVjc2F0"
    token = TokenV4.deserialize(token_str)
    assert token.serialize() == token_str


def test_tokenv4_deserialize_with_dleq():
    token_str = "cashuBo2F0gaJhaUgArSaMTR9YJmFwgqRhYQhhc3hAY2I4ZWViZWE3OGRjMTZmMWU4MmY5YTZlOWI4YTU3YTM5ZDM2M2M5MzZkMzBmZTI5YmVlZDI2M2MwOGFkOTY2M2FjWCECRmlA6zYOcRSgigEUDv0BBtC2Ag8x8ZOaZUKo8J2_VWdhZKNhZVggscHmr2oHB_x9Bzhgeg2p9Vbq5Ai23olDz2JbmCRx6dlhc1ggrPmtYrRAgEHnYLIQ83cgyFjAjWNqMeNhUadHMxEm0edhclggQ5c_5bES_NhtzunlDls70fhMDWDgo9DY0kk1GuJGM2ikYWECYXN4QDQxN2E2MjZmNWMyNmVhNjliODM0YTZkZTcxYmZiMGY3ZTQ0NDhlZGFkY2FlNGRmNWVhMzM3NDdmOTVhYjRhYjRhY1ghAwyZ1QstFpNe0sppbduQxiePmGVUUk0mWDj5JAFs74-LYWSjYWVYIPyAzLub_bwc60qFkNfETjig-ESZSR8xdpANy1rHwvHKYXNYIOCInwuipARTL8IFT6NoSJqeeSMjlcbPzL-YSmXjDLIuYXJYIOLk-C0Fhba02B0Ut1BjMQqzxVGaO1NJM9Wi_aDQ37jqYW11aHR0cDovL2xvY2FsaG9zdDozMzM4YXVjc2F0"
    token = TokenV4.deserialize(token_str)
    assert token.proofs[0].dleq is not None
    assert token.proofs[0].dleq.e
    assert token.proofs[0].dleq.s
    assert token.proofs[0].dleq.r

    assert token.serialize(include_dleq=True) == token_str


def test_tokenv4_serialize_example_single_keyset_nut00():
    token_dict = {
        "t": [
            {
                "i": bytes.fromhex("00ad268c4d1f5826"),
                "p": [
                    {
                        "a": 1,
                        "s": "9a6dbb847bd232ba76db0df197216b29d3b8cc14553cd27827fc1cc942fedb4e",
                        "c": bytes.fromhex(
                            "038618543ffb6b8695df4ad4babcde92a34a96bdcd97dcee0d7ccf98d472126792"
                        ),
                    },
                ],
            },
        ],
        "d": "Thank you",
        "m": "http://localhost:3338",
        "u": "sat",
    }
    tokenObj = TokenV4.model_validate(token_dict)
    assert (
        tokenObj.serialize()
        == "cashuBpGF0gaJhaUgArSaMTR9YJmFwgaNhYQFhc3hAOWE2ZGJiODQ3YmQyMzJiYTc2ZGIwZGYxOTcyMTZiMjlkM2I4Y2MxNDU1M2NkMjc4MjdmYzFjYzk0MmZlZGI0ZWFjWCEDhhhUP_trhpXfStS6vN6So0qWvc2X3O4NfM-Y1HISZ5JhZGlUaGFuayB5b3VhbXVodHRwOi8vbG9jYWxob3N0OjMzMzhhdWNzYXQ="
    )


def test_tokenv4_serialize_example_token_nut00():
    token_dict = {
        "t": [
            {
                "i": bytes.fromhex("00ffd48b8f5ecf80"),
                "p": [
                    {
                        "a": 1,
                        "s": "acc12435e7b8484c3cf1850149218af90f716a52bf4a5ed347e48ecc13f77388",
                        "c": bytes.fromhex(
                            "0244538319de485d55bed3b29a642bee5879375ab9e7a620e11e48ba482421f3cf"
                        ),
                    },
                ],
            },
            {
                "i": bytes.fromhex("00ad268c4d1f5826"),
                "p": [
                    {
                        "a": 2,
                        "s": "1323d3d4707a58ad2e23ada4e9f1f49f5a5b4ac7b708eb0d61f738f48307e8ee",
                        "c": bytes.fromhex(
                            "023456aa110d84b4ac747aebd82c3b005aca50bf457ebd5737a4414fac3ae7d94d"
                        ),
                    },
                    {
                        "a": 1,
                        "s": "56bcbcbb7cc6406b3fa5d57d2174f4eff8b4402b176926d3a57d3c3dcbb59d57",
                        "c": bytes.fromhex(
                            "0273129c5719e599379a974a626363c333c56cafc0e6d01abe46d5808280789c63"
                        ),
                    },
                ],
            },
        ],
        "m": "http://localhost:3338",
        "u": "sat",
    }
    tokenObj = TokenV4.model_validate(token_dict)

    assert (
        tokenObj.serialize()
        == "cashuBo2F0gqJhaUgA_9SLj17PgGFwgaNhYQFhc3hAYWNjMTI0MzVlN2I4NDg0YzNjZjE4NTAxNDkyMThhZjkwZjcxNmE1MmJmNGE1ZWQzNDdlNDhlY2MxM2Y3NzM4OGFjWCECRFODGd5IXVW-07KaZCvuWHk3WrnnpiDhHki6SCQh88-iYWlIAK0mjE0fWCZhcIKjYWECYXN4QDEzMjNkM2Q0NzA3YTU4YWQyZTIzYWRhNGU5ZjFmNDlmNWE1YjRhYzdiNzA4ZWIwZDYxZjczOGY0ODMwN2U4ZWVhY1ghAjRWqhENhLSsdHrr2Cw7AFrKUL9Ffr1XN6RBT6w659lNo2FhAWFzeEA1NmJjYmNiYjdjYzY0MDZiM2ZhNWQ1N2QyMTc0ZjRlZmY4YjQ0MDJiMTc2OTI2ZDNhNTdkM2MzZGNiYjU5ZDU3YWNYIQJzEpxXGeWZN5qXSmJjY8MzxWyvwObQGr5G1YCCgHicY2FtdWh0dHA6Ly9sb2NhbGhvc3Q6MzMzOGF1Y3NhdA=="
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
