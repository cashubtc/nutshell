from typing import List


def amount_split(amount: int) -> List[int]:
    """Given an amount returns a list of amounts returned e.g. 13 is [1, 4, 8]."""
    if amount <= 0:
        return []
    bits_amt = bin(amount)[::-1][:-2]
    rv = []
    for pos, bit in enumerate(bits_amt):
        if bit == "1":
            rv.append(2**pos)
    return rv
