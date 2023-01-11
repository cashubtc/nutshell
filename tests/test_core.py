from cashu.core.split import amount_split


def test_get_output_split():
    assert amount_split(13) == [1, 4, 8]
