try:
    assert (
        1
        == 2
    ), "msg"
    print("passed")
except AssertionError:
    print("failed")
