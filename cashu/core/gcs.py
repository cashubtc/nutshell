import base64
from sqlite3 import Row
from typing import Dict, List, Tuple

import mmh3
from bitarray import bitarray

from ..core.models import GetFilterResponse


def hash_to_range(item: bytes, f: int) -> int:
    """
    Hashes an item to a range using Murmurhash.

    Args:
        item (bytes): The item to hash.
        f (int): The maximum range value.

    Returns:
        int: The hashed value within the specified range.
    """
    h1 = mmh3.hash(item, seed=0, signed=False)
    h2 = mmh3.hash(item, seed=h1, signed=False)
    h = (h1 << 32) | h2
    return (h * f) >> 64

def create_hashed_set(items: List[bytes], m: int) -> List[int]:
    """
    Creates a hashed set of items using a key and a multiplier.

    Args:
        items (List[bytes]): The list of items to hash.
        m (int): The multiplier for the allowed range.

    Returns:
        List[int]: A list of hashed values.
    """
    n = len(items)
    f = n * m

    return [hash_to_range(e, f) for e in items]

# Golomb-encodes `x` into `stream` with remainder of `P` bits 
def golomb_encode(stream: bitarray, offset: int, x: int, P: int) -> int:
    """
    Golomb-encodes a value into a bitarray stream.

    Args:
        stream (bitarray): The bitarray to encode into.
        offset (int): Where in the bitarray to start from.
        x (int): The value to encode.
        P (int): The number of bits for the remainder.

    Returns:
        int: The new offset
    """
    assert x >= 0

    q = x >> P
    r = x & (2**P - 1)

    # Append the quotient in unary coding
    while q > 0:
        stream[offset] = 1
        q -= 1
        offset += 1

    stream[offset] = 0
    offset += 1

    # Append the remainder in binary coding
    for i in range(P):
        stream[offset] = (r >> (P-1-i)) & 1
        offset += 1

    return offset

# Decodes the first occurrence of a delta hash in `stream` starting from `offset`.
# Returns the decoded delta and the new offset.
def golomb_decode(stream: bitarray, offset: int, P: int) -> Tuple[int, int]:
    """
    Decodes a Golomb-encoded value from a bitarray stream.

    Args:
        stream (bitarray): The bitarray to decode from.
        offset (int): The starting offset in the bitarray.
        P (int): The number of bits for the remainder.

    Returns:
        Tuple[int, int]: The decoded value and the new offset.
    """
    q = 0
    while stream[offset] == 1:
        q += 1
        offset += 1

    offset += 1
    
    # Calculate the remainder directly from the bitarray slice
    r = 0
    for i in range(P):
        r = (r << 1) | stream[offset + i]

    x = (q << P) | r
    return x, offset + P

class GCSFilter:
    
    num_items: int
    inv_fpr: int
    rem_bitlength: int
    content: bytes

    def __init__(self, content: bytes, num_items: int, **kwargs):
        self.num_items = num_items
        self.inv_fpr = kwargs.get("inv_fpr", 784931)
        self.rem_bitlength = kwargs.get("rem_bitlength", 19)
        self.content = content

    @classmethod
    def create(cls,
        items: List[bytes],
        p: int = 19,
        m: int = 784931
    ) -> "GCSFilter":
        """
        Turns a list of entries into a Golomb-Coded Set of hashes.

        Args:
            items (List[bytes]): The list of items to encode.
            p (int): The number of bits for the remainder.
            m (int): The inverse of the FPR.

        Returns:
            bytes: The Golomb-Coded Set as a byte array.
        """
        if m.bit_length() > 32:
            raise Exception("GCS Error: m parameter must be smaller than 2^32")
        if len(items).bit_length() > 32:
            raise Exception("GCS Error: number of elements must be smaller than 2^32")
        
        set_items = create_hashed_set(items, m)

        # Sort the items
        sorted_set_items = sorted(set_items)

        output_stream = bitarray(len(sorted_set_items) * (p+3))

        last_value = 0
        offset = 0
        for item in sorted_set_items:
            delta = item - last_value
            offset = golomb_encode(output_stream, offset, delta, p)
            last_value = item

        return cls(
            num_items=len(sorted_set_items),
            content=output_stream[:offset].tobytes(), # Pads to the right with zero up to the byte boundary
            inv_fpr=m,
            rem_bitlength=p,
        )

    def match_many(
        self,
        targets: List[bytes]
    ) -> Dict[bytes, bool]:
        """
        Matches multiple target items against a Golomb-Coded Set.

        Args:
            targets (List[bytes]): The list of target items to match.

        Returns:
            Dict[bytes, bool]: A dictionary indicating which targets are in the set.
        """

        f = self.num_items * self.inv_fpr

        if (f == 0):
            return {target: False for target in targets}

        if len(set(targets)) != len(targets):
            raise Exception("GCS Error: match targets are not unique entries")

        # Map targets to the same range as the set hashes.
        target_hashes: Dict[int, Tuple[bytes, bool]] = {hash_to_range(target, f): (target, False) for target in targets}
        input_stream = bitarray()
        input_stream.frombytes(self.content)

        value = 0
        offset = 0
        for i in range(self.num_items):
            delta, offset = golomb_decode(input_stream, offset, self.rem_bitlength)
            value += delta

            if value in target_hashes:
                target, _ = target_hashes[value]
                target_hashes[value] = (target, True)

        return {target: truth_value for target, truth_value in target_hashes.values()}

    
    @classmethod
    def from_row(cls, row: Row) -> "GCSFilter":
        return cls(
            num_items=row["num_items"],
            content=row["content"],
            inv_fpr=row["inv_fpr"],
            rem_bitlength=row["remainder_bitlength"],
        )

    @classmethod
    def from_resp_wallet(cls, resp: GetFilterResponse) -> "GCSFilter":
        return cls(
            num_items=resp.n,
            content=base64.b64decode(resp.content),
            inv_fpr=resp.m,
            rem_bitlength=resp.p
        )

if __name__ == "__main__":
    import random

    import matplotlib.pyplot as plt

    def get_filter_size(num_elements: int) -> int:
        items = [random.randbytes(32) for _ in range(num_elements)]
        gcs_filter = GCSFilter.create(items)
        return len(gcs_filter.content)

    num_elements_list = [10**i for i in range(2, 10)]  # 10^2 to 10^9
    filter_sizes = []

    print("Calculating filter sizes...")
    for num_elements in num_elements_list:
        print(f"Processing {num_elements} elements...")
        size = get_filter_size(num_elements)
        filter_sizes.append(size)
        print(f"  Filter size: {size} bytes")

    plt.figure(figsize=(10, 6))
    plt.plot(num_elements_list, filter_sizes, marker='o')
    plt.xscale('log')
    plt.yscale('log')
    plt.xlabel('Number of Elements (log scale)')
    plt.ylabel('Filter Size (bytes, log scale)')
    plt.title('GCS Filter Size vs. Number of Elements')
    plt.grid(True, which="both", ls="--")
    plt.show()
