from typing import Dict, List, Tuple
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from bitarray import bitarray
import mmh3


def hash_to_range(item: bytes, f: int) -> int:
    """
    Hashes an item to a range using Murmurhash.

    Args:
        item (bytes): The item to hash.
        f (int): The maximum range value.

    Returns:
        int: The hashed value within the specified range.
    """
    h = mmh3.hash128(item) & (2**64 - 1)
    return (f * h) >> 64

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
def golomb_encode(stream: bitarray, offset: int, x: int, P: int) -> None:
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
        
    @classmethod
    def create(cls,
        items: List[bytes],
        p: int = 19,
        m: int = 784931
    ) -> bytes:
        """
        Turns a list of entries into a Golomb-Coded Set of hashes.

        Args:
            items (List[bytes]): The list of items to encode.
            p (int): The number of bits for the remainder.
            m (int): The multiplier for the allowed range.

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

        # Pads to the right with zero up to the byte boundary
        return output_stream[:offset].tobytes()

    @classmethod
    def match_many(
        cls,
        compressed_set: bytes,
        targets: List[bytes],
        n: int,
        p: int = 19,
        m: int = 784931,
    ) -> Dict[bytes, bool]:
        """
        Matches multiple target items against a Golomb-Coded Set.

        Args:
            compressed_set (bytes): The Golomb-Coded Set as a byte array.
            targets (List[bytes]): The list of target items to match.
            n (int): The number of items in the set.
            p (int): The number of bits for the remainder.
            m (int): The multiplier for the allowed range.

        Returns:
            Dict[bytes, bool]: A dictionary indicating which targets are in the set.
        """
        if m.bit_length() > 32:
            raise Exception("GCS Error: m parameter must be smaller than 2^32")
        if n.bit_length() > 32:
            raise Exception("GCS Error: number of elements must be smaller than 2^32")

        f = n * m

        if len(set(targets)) != len(targets):
            raise Exception("GCS Error: match targets are not unique entries")

        # Map targets to the same range as the set hashes.
        target_hashes: Dict[int, Tuple[bytes, bool]] = {hash_to_range(target, f): (target, False) for target in targets}
         
        input_stream = bitarray()
        input_stream.frombytes(compressed_set)

        value = 0
        offset = 0
        for i in range(n):
            delta, offset = golomb_decode(input_stream, offset, p)
            value += delta

            if value in target_hashes:
                target, _ = target_hashes[value]
                target_hashes[value] = (target, True)

        return {target: truth_value for target, truth_value in target_hashes.values()}

'''
import os

# Generate random data for testing
num_items = 1000000
item_size = 33  # 33 bytes
items = [os.urandom(item_size) for _ in range(num_items)]

# Create a GCS filter
gcs_filter = GCSFilter.create(items)

print(f"{num_items = }, {item_size = }, {len(gcs_filter) = }")

# Test set membership
results = GCSFilter.match_many(gcs_filter, items, num_items)

# Assert all items are found in the filter
assert all(results.values()), "Not all items were found in the GCS filter"

# Test with a non-existent item
non_existent_item = os.urandom(item_size)
results = GCSFilter.match_many(gcs_filter, [non_existent_item], num_items)
assert not any(results.values()), "Non-existent item was incorrectly found in the GCS filter"
'''