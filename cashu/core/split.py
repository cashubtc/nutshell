from typing import List


def amount_split(amount: int) -> List[int]:
    """Given an amount returns a list of amounts returned e.g. 13 is [1, 4, 8]."""
    if amount < 0:
        raise Exception("can't split negative amount")
    assert amount >= 0
    rv = []
    for i in range(amount.bit_length()):
        if amount & (1 << i):  # if bit i is set, add 2**i to list
            rv.append(1 << i)
    return rv
