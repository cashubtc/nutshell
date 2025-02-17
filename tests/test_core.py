import pytest

from cashu.core.base import TokenV3, TokenV4, Unit
from cashu.core.helpers import calculate_number_of_blank_outputs
from cashu.core.split import amount_split
from cashu.wallet.helpers import deserialize_token_from_string


def test_get_output_split():
    assert amount_split(13) == [1, 4, 8]
    assert amount_split(0) == []
    assert amount_split(-8) == []


def test_tokenv3_deserialize_get_attributes():
    token_str = "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjAwYWQyNjhjNGQxZjU4MjYiLCAiYW1vdW50IjogOCwgInNlY3JldCI6ICJjNTA5YzM4MmM2NjJkYWJiYjRkMGM1ZjllYTI1NjAwZTNhYjViMTIzYWNlNmNiNzljYTM1OWE4NTQwOGZlY2I3IiwgIkMiOiAiMDMwZTNkNDdkM2NlMjNkZTkzNTM3MjQ1NGJjOTMxMTJjZmExN2VmYWNkYjZjNWM2NDNmODVjOGFmM2JlNWQwMWEwIn0sIHsiaWQiOiAiMDBhZDI2OGM0ZDFmNTgyNiIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogIjgxYjhiYjFhN2Q2MGQwZGZiMjkxNmZjZmU4NzUxZmRhZGJjZTU2NDZmMmEyYTQzY2FkMDY4YjUzNzJlN2M5NGMiLCAiQyI6ICIwMzUxN2E0OGYxMmU0NWQ0YzU4ZGUyMTZhNDNjYzgxNDMwMjMxY2YyYjA4OWQzMjY3MDlkMGYyZDAwYjc0N2VmYzcifV0sICJtaW50IjogImh0dHA6Ly9sb2NhbGhvc3Q6MzMzOCJ9XSwgInVuaXQiOiAic2F0In0="
    token = TokenV3.deserialize(token_str)
    assert token.amount == 10
    assert len(token.proofs) == 2


def test_tokenv3_deserialize_serialize_with_padding():
    token_str = "cashuAeyJ0b2tlbiI6W3sicHJvb2ZzIjpbeyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjgsInNlY3JldCI6ImVmNTRkOTg2NDQxNjA1MjY3YzZhNmU3MzJmZWZlMWRhNzViNWU5ZmY3MzZkODQxNmYwYmE4MmM4OTNlMWUyYWUiLCJDIjoiMDI2OTQ4YWFlY2FiZjJlZGVjYWU1M2YzYWIyMjNkZGFhMTRhNmY4MjJhZWNjZGMxYjAxNmVlODg0NDYwYjBjMTVjIn0seyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjIsInNlY3JldCI6ImZkMmZkZWI1NzI0N2QzZTJlNjg4YmEyZDI1OGYzN2U0NjY4ZjI2MGM1MGUzZDBjOWRkNWE5Njk0YjQ1ZmQ4OWMiLCJDIjoiMDNjNjc0NWQ5MjA1NDAzMTk3NzA1YWIyN2M1YzEzNDMwNjdmYmU1MTZhMTM2NDE4M2MzMTBmZDY5MmZkNGQzM2ZjIn1dLCJtaW50IjoiaHR0cDovL2xvY2FsaG9zdDozMzM4In1dLCJ1bml0Ijoic2F0In0="
    token = TokenV3.deserialize(token_str)
    assert token.serialize() == token_str.strip("=")


def test_tokenv3_deserialize_serialize_no_podding():
    token_str = "cashuAeyJ0b2tlbiI6W3sicHJvb2ZzIjpbeyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjgsInNlY3JldCI6ImVmNTRkOTg2NDQxNjA1MjY3YzZhNmU3MzJmZWZlMWRhNzViNWU5ZmY3MzZkODQxNmYwYmE4MmM4OTNlMWUyYWUiLCJDIjoiMDI2OTQ4YWFlY2FiZjJlZGVjYWU1M2YzYWIyMjNkZGFhMTRhNmY4MjJhZWNjZGMxYjAxNmVlODg0NDYwYjBjMTVjIn0seyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjIsInNlY3JldCI6ImZkMmZkZWI1NzI0N2QzZTJlNjg4YmEyZDI1OGYzN2U0NjY4ZjI2MGM1MGUzZDBjOWRkNWE5Njk0YjQ1ZmQ4OWMiLCJDIjoiMDNjNjc0NWQ5MjA1NDAzMTk3NzA1YWIyN2M1YzEzNDMwNjdmYmU1MTZhMTM2NDE4M2MzMTBmZDY5MmZkNGQzM2ZjIn1dLCJtaW50IjoiaHR0cDovL2xvY2FsaG9zdDozMzM4In1dLCJ1bml0Ijoic2F0In0"
    token = TokenV3.deserialize(token_str)
    assert token.serialize() == token_str


def test_tokenv3_deserialize_serialize_with_dleq():
    token_str = "cashuAeyJ0b2tlbiI6W3sicHJvb2ZzIjpbeyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjgsInNlY3JldCI6IjI4MDliZjk5YTgzOGJkNzU1NjAwNTVmMjFlNzZiNzYwOTEwMGE1M2FhMzJiNDUwMDRiOGEzMzU0NDgwN2Q4N2MiLCJDIjoiMDJhZWFmNmE5OGY1MjQzZGY4YTA0OGIzNzYzMjUzNjYxZTgxMjFkODhlZTIzNGZmM2ZmYjQ2ZWM0YWIyOWIyYmJlIiwiZGxlcSI6eyJlIjoiNThlOGYzYTVkOGE2M2M1NGJkMjM5YzE4ZWJkMWUxZWFiZmJkZWMyMzhkNDBjZWExOGJjOWJmY2M0NjIyNGRjYyIsInMiOiIwNGYwM2FkMTA3MTE4NGQzZWIyOTNlYjRhMWI3MGY1OTQ0Mjg1NmJhYzNmNWJjZDE2OWJkMmVhOGVkNmY0NjlhIiwiciI6IjExZDUwMjRhM2U3N2Q0MzNhN2VjMTgwOGE5NzgzNGY2MzlhYjVkYjZhNjZhNmQzYWZlM2M4NGUyNmEzZWM3MDcifX0seyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjIsInNlY3JldCI6ImY1OGNhNmMwYTA3YWI2YjFmMWUzYjIzYWU3MDc3ODE5MzNiMGExNTExYWYzZWQyMjRmY2FjNzgxM2NhZTQ5OTYiLCJDIjoiMDNiZDVhMWFmN2NkMTY0MjA2MmU5NjRlYTZjOTlhZGRiNWI1YjRhYmY5Y2VmMjhjZWRhYmJhNGFlM2QyYmUyOGRmIiwiZGxlcSI6eyJlIjoiMmQzNTc2YzU3ZTM5ZjFiMzAzN2RmYjdhYmViOTE2M2I2ZGIxMjExMTBjNTZiY2NkYzhmMTcyN2MzZTg4NjQyNyIsInMiOiIzNDg2M2MxNDU5ZmI5MTk4ZjNhNjAyYzZhMWRkYmExNzc0NWUzN2M2ZGNiMjNiMmQxMmU3NGM3YzE3MjZiOWYwIiwiciI6IjYxNzRlNjBiZjU4MGYyOTBiNTIwZjMxYzc5MjBlNTA3MDkxNmJmYzRmZTc0MDNhNjY5ZThlNmEzOThhNGQ3YTcifX1dLCJtaW50IjoiaHR0cDovL2xvY2FsaG9zdDozMzM4In1dLCJ1bml0Ijoic2F0In0"
    token = TokenV3.deserialize(token_str)
    assert token.serialize(include_dleq=True) == token_str


def test_tokenv3_deserialize_serialize_no_dleq():
    token_str = "cashuAeyJ0b2tlbiI6W3sicHJvb2ZzIjpbeyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjgsInNlY3JldCI6IjI4MDliZjk5YTgzOGJkNzU1NjAwNTVmMjFlNzZiNzYwOTEwMGE1M2FhMzJiNDUwMDRiOGEzMzU0NDgwN2Q4N2MiLCJDIjoiMDJhZWFmNmE5OGY1MjQzZGY4YTA0OGIzNzYzMjUzNjYxZTgxMjFkODhlZTIzNGZmM2ZmYjQ2ZWM0YWIyOWIyYmJlIiwiZGxlcSI6eyJlIjoiNThlOGYzYTVkOGE2M2M1NGJkMjM5YzE4ZWJkMWUxZWFiZmJkZWMyMzhkNDBjZWExOGJjOWJmY2M0NjIyNGRjYyIsInMiOiIwNGYwM2FkMTA3MTE4NGQzZWIyOTNlYjRhMWI3MGY1OTQ0Mjg1NmJhYzNmNWJjZDE2OWJkMmVhOGVkNmY0NjlhIiwiciI6IjExZDUwMjRhM2U3N2Q0MzNhN2VjMTgwOGE5NzgzNGY2MzlhYjVkYjZhNjZhNmQzYWZlM2M4NGUyNmEzZWM3MDcifX0seyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjIsInNlY3JldCI6ImY1OGNhNmMwYTA3YWI2YjFmMWUzYjIzYWU3MDc3ODE5MzNiMGExNTExYWYzZWQyMjRmY2FjNzgxM2NhZTQ5OTYiLCJDIjoiMDNiZDVhMWFmN2NkMTY0MjA2MmU5NjRlYTZjOTlhZGRiNWI1YjRhYmY5Y2VmMjhjZWRhYmJhNGFlM2QyYmUyOGRmIiwiZGxlcSI6eyJlIjoiMmQzNTc2YzU3ZTM5ZjFiMzAzN2RmYjdhYmViOTE2M2I2ZGIxMjExMTBjNTZiY2NkYzhmMTcyN2MzZTg4NjQyNyIsInMiOiIzNDg2M2MxNDU5ZmI5MTk4ZjNhNjAyYzZhMWRkYmExNzc0NWUzN2M2ZGNiMjNiMmQxMmU3NGM3YzE3MjZiOWYwIiwiciI6IjYxNzRlNjBiZjU4MGYyOTBiNTIwZjMxYzc5MjBlNTA3MDkxNmJmYzRmZTc0MDNhNjY5ZThlNmEzOThhNGQ3YTcifX1dLCJtaW50IjoiaHR0cDovL2xvY2FsaG9zdDozMzM4In1dLCJ1bml0Ijoic2F0In0"
    token_str_no_dleq = "cashuAeyJ0b2tlbiI6W3sicHJvb2ZzIjpbeyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjgsInNlY3JldCI6IjI4MDliZjk5YTgzOGJkNzU1NjAwNTVmMjFlNzZiNzYwOTEwMGE1M2FhMzJiNDUwMDRiOGEzMzU0NDgwN2Q4N2MiLCJDIjoiMDJhZWFmNmE5OGY1MjQzZGY4YTA0OGIzNzYzMjUzNjYxZTgxMjFkODhlZTIzNGZmM2ZmYjQ2ZWM0YWIyOWIyYmJlIn0seyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjIsInNlY3JldCI6ImY1OGNhNmMwYTA3YWI2YjFmMWUzYjIzYWU3MDc3ODE5MzNiMGExNTExYWYzZWQyMjRmY2FjNzgxM2NhZTQ5OTYiLCJDIjoiMDNiZDVhMWFmN2NkMTY0MjA2MmU5NjRlYTZjOTlhZGRiNWI1YjRhYmY5Y2VmMjhjZWRhYmJhNGFlM2QyYmUyOGRmIn1dLCJtaW50IjoiaHR0cDovL2xvY2FsaG9zdDozMzM4In1dLCJ1bml0Ijoic2F0In0"
    token = TokenV3.deserialize(token_str)
    assert token.serialize(include_dleq=False) == token_str_no_dleq


def test_tokenv3_deserialize_with_memo():
    token_str = "cashuAeyJ0b2tlbiI6W3sicHJvb2ZzIjpbeyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjgsInNlY3JldCI6IjNlNDlhMGQzNzllMWQ1YTY3MjhiYzUwMjM4YTRjZDFlMjBiY2M5MjM4MjAxMDg0MzcyNjdhNWZkZDM2NWZiMDYiLCJDIjoiMDIyYWQwODg5ZmVkNWE0YWNjODEwYTZhZTk4MTc0YjFlZGM2OTkwMWI0OTdkNTYzYmM5NjEyMjVlYzMwOGVkMTVkIn0seyJpZCI6IjAwYWQyNjhjNGQxZjU4MjYiLCJhbW91bnQiOjIsInNlY3JldCI6ImNmNjhhNTQ3ZWY2ZDVhNGFkZTI0ZGM5MDU5ZTE5ZmJkZDU0NmQ5MGE1OWI0ODE5MzdmN2FjNmRiNWMwZjFkMTUiLCJDIjoiMDMyZWQ5ZGQ3MzExMTg1ODk1NTFiM2E5YjJhNTM5YWZlYTcxOTU3OGZhNTI1ZTVmMmJkY2M4YjNlMzhjNjJkOTRjIn1dLCJtaW50IjoiaHR0cDovL2xvY2FsaG9zdDozMzM4In1dLCJtZW1vIjoiVGVzdCBtZW1vIiwidW5pdCI6InNhdCJ9"
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
                        "amount": 2,
                        "id": "009a1f293253e41e",
                        "secret": "407915bc212be61a77e3e6d2aeb4c727980bda51cd06a6afc29e2861768a7837",
                        "C": "02bc9097997d81afb2cc7346b5e4345a9346bd2a506eb7958598a72f0cf85163ea",
                    },
                    {
                        "amount": 8,
                        "id": "009a1f293253e41e",
                        "secret": "fe15109314e61d7756b0f8ee0f23a624acaa3f4e042f61433c728c7057b931be",
                        "C": "029e8e5050b890a7d6c0968db16bc1d5d5fa040ea1de284f6ec69d61299f671059",
                    },
                ],
            }
        ],
        "unit": "sat",
        "memo": "Thank you.",
    }
    tokenObj = TokenV3.parse_obj(token_dict)
    # NOTE: The serialized token here is different from the example in NUT-00 because the order of keys in the JSON is different in our seiralization
    encoded_token = "cashuAeyJ0b2tlbiI6W3sicHJvb2ZzIjpbeyJpZCI6IjAwOWExZjI5MzI1M2U0MWUiLCJhbW91bnQiOjIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJpZCI6IjAwOWExZjI5MzI1M2U0MWUiLCJhbW91bnQiOjgsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dLCJtaW50IjoiaHR0cHM6Ly84MzMzLnNwYWNlOjMzMzgifV0sIm1lbW8iOiJUaGFuayB5b3UuIiwidW5pdCI6InNhdCJ9"
    encoded_token_nut00 = "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91LiJ9"
    assert (
        tokenObj.serialize() == encoded_token
        # NUT-00 example:
        # == encoded_token_nut00
    )

    # to make sure the serialization is correct, we deserialize the token and compare it with the original token
    token_1 = TokenV3.deserialize(encoded_token)
    token_2 = TokenV3.deserialize(encoded_token_nut00)
    assert token_1.serialize() == token_2.serialize()


def test_tokenv4_deserialize_get_attributes():
    token_str = "cashuBo2F0gaJhaUgArSaMTR9YJmFwgqNhYQJhc3hAMDZlM2UzZjY4NDRiOGZkOGQ3NDMwODY1MjY3MjQ5YWU3NjdhMzg5MDBjODdkNGE0ZDMxOGY4MTJmNzkzN2ZiMmFjWCEDXDG_wzG35Lu4vcAtiycLSQlNqH65afih9N2SrFJn3GCjYWEIYXN4QDBmNTE5YjgwOWZlNmQ5MzZkMjVhYmU1YjhjYTZhMDRlNDc3OTJjOTI0YTkwZWRmYjU1MmM1ZjkzODJkNzFjMDJhY1ghA4CNH8dD8NNt715E37Ar65X6p6uBUoDbe8JipQp81TIgYW11aHR0cDovL2xvY2FsaG9zdDozMzM4YXVjc2F0"
    token = TokenV4.deserialize(token_str)
    assert token.mint == "http://localhost:3338"
    assert token.amounts == [2, 8]
    assert token.amount == 10
    assert token.unit == Unit.sat.name
    assert token.memo is None
    assert len(token.proofs) == 2


def test_tokenv4_deserialize_serialize_no_padding():
    token_str = "cashuBo2F0gaJhaUgArSaMTR9YJmFwgqNhYQJhc3hAMDZlM2UzZjY4NDRiOGZkOGQ3NDMwODY1MjY3MjQ5YWU3NjdhMzg5MDBjODdkNGE0ZDMxOGY4MTJmNzkzN2ZiMmFjWCEDXDG_wzG35Lu4vcAtiycLSQlNqH65afih9N2SrFJn3GCjYWEIYXN4QDBmNTE5YjgwOWZlNmQ5MzZkMjVhYmU1YjhjYTZhMDRlNDc3OTJjOTI0YTkwZWRmYjU1MmM1ZjkzODJkNzFjMDJhY1ghA4CNH8dD8NNt715E37Ar65X6p6uBUoDbe8JipQp81TIgYW11aHR0cDovL2xvY2FsaG9zdDozMzM4YXVjc2F0"
    token = TokenV4.deserialize(token_str)
    assert token.serialize() == token_str


def test_tokenv4_deserialize_serialize_with_padding():
    token_str = "cashuBo2F0gaJhaUgArSaMTR9YJmFwgqNhYQJhc3hAMDZlM2UzZjY4NDRiOGZkOGQ3NDMwODY1MjY3MjQ5YWU3NjdhMzg5MDBjODdkNGE0ZDMxOGY4MTJmNzkzN2ZiMmFjWCEDXDG_wzG35Lu4vcAtiycLSQlNqH65afih9N2SrFJn3GCjYWEIYXN4QDBmNTE5YjgwOWZlNmQ5MzZkMjVhYmU1YjhjYTZhMDRlNDc3OTJjOTI0YTkwZWRmYjU1MmM1ZjkzODJkNzFjMDJhY1ghA4CNH8dD8NNt715E37Ar65X6p6uBUoDbe8JipQp81TIgYW11aHR0cDovL2xvY2FsaG9zdDozMzM4YXVjc2F0===="
    token = TokenV4.deserialize(token_str)
    assert token.serialize() == token_str.strip("=")


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
    tokenObj = TokenV4.parse_obj(token_dict)
    assert (
        tokenObj.serialize()
        == "cashuBpGF0gaJhaUgArSaMTR9YJmFwgaNhYQFhc3hAOWE2ZGJiODQ3YmQyMzJiYTc2ZGIwZGYxOTcyMTZiMjlkM2I4Y2MxNDU1M2NkMjc4MjdmYzFjYzk0MmZlZGI0ZWFjWCEDhhhUP_trhpXfStS6vN6So0qWvc2X3O4NfM-Y1HISZ5JhZGlUaGFuayB5b3VhbXVodHRwOi8vbG9jYWxob3N0OjMzMzhhdWNzYXQ"
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
    tokenObj = TokenV4.parse_obj(token_dict)

    assert (
        tokenObj.serialize()
        == "cashuBo2F0gqJhaUgA_9SLj17PgGFwgaNhYQFhc3hAYWNjMTI0MzVlN2I4NDg0YzNjZjE4NTAxNDkyMThhZjkwZjcxNmE1MmJmNGE1ZWQzNDdlNDhlY2MxM2Y3NzM4OGFjWCECRFODGd5IXVW-07KaZCvuWHk3WrnnpiDhHki6SCQh88-iYWlIAK0mjE0fWCZhcIKjYWECYXN4QDEzMjNkM2Q0NzA3YTU4YWQyZTIzYWRhNGU5ZjFmNDlmNWE1YjRhYzdiNzA4ZWIwZDYxZjczOGY0ODMwN2U4ZWVhY1ghAjRWqhENhLSsdHrr2Cw7AFrKUL9Ffr1XN6RBT6w659lNo2FhAWFzeEA1NmJjYmNiYjdjYzY0MDZiM2ZhNWQ1N2QyMTc0ZjRlZmY4YjQ0MDJiMTc2OTI2ZDNhNTdkM2MzZGNiYjU5ZDU3YWNYIQJzEpxXGeWZN5qXSmJjY8MzxWyvwObQGr5G1YCCgHicY2FtdWh0dHA6Ly9sb2NhbGhvc3Q6MzMzOGF1Y3NhdA"
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


def test_parse_token_v3_v4_base64_keyset_id():
    token_dict = {
        "token": [
            {
                "mint": "https://localhost:3338",
                "proofs": [
                    {
                        "amount": 2,
                        "id": "009a1f293253e41e",
                        "secret": "407915bc212be61a77e3e6d2aeb4c727980bda51cd06a6afc29e2861768a7837",
                        "C": "02bc9097997d81afb2cc7346b5e4345a9346bd2a506eb7958598a72f0cf85163ea",
                    },
                ],
            }
        ],
    }

    token_v3 = TokenV3.parse_obj(token_dict)
    token_v3_serialized = token_v3.serialize()

    # this token can be serialized to V4
    token = deserialize_token_from_string(token_v3_serialized)
    assert isinstance(token, TokenV4)

    # Now let's do the same with a base64 token
    token_dict_base64_keyset = token_dict.copy()
    token_dict_base64_keyset["token"][0]["proofs"][0]["id"] = "yjzQhxghPdrr"  # type: ignore

    token_v3_base64_keyset = TokenV3.parse_obj(token_dict_base64_keyset)
    token_v3_base64_keyset_serialized = token_v3_base64_keyset.serialize()

    # this token can not be serialized to V4
    token = deserialize_token_from_string(token_v3_base64_keyset_serialized)
    assert isinstance(token, TokenV3)
