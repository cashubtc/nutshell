
from bitarray import bitarray
from hashlib import md5
from typing import List, Tuple

def hash_to_range(item: bytes, f: int, key: bytes) -> int:
    # Rejection sampling
    i = 0
    result = f+1
    while result > f:
        result = int.from_bytes(md5(key + item + i.to_bytes(1, 'big')).digest()[:8], 'big')
        i += 1
    return result

def create_hashed_set(items: List[bytes], key: bytes, m: int) -> List[int]:
    n = len(entries)
    allowed_range = n * m

    return [hash_to_range(e, allowed_range, key) for e in items]

# Golomb-encodes `x` into `stream` with remainder of `P` bits 
def golomb_encode(stream: bitarray, x: int, P: int) -> None:
    assert x > 0

    q = x >> P
    r = x & (2**P - 1)

    # Append the quotient in unary coding
    while q > 0:
        stream.append(1)
        q -= 1
    stream.append(0)

    # Append the remainder in binary coding
    for i in range(P):
        stream.append(int((r >> (P-1-i)) & 1))

# Decodes the first occurrence of a delta hash in `stream` starting from `offset`.
# Returns the decoded delta and the new offset.
def golomb_decode(stream: bitarray, offset: int, P: int) -> Tuple[int, int]:
    q = 0
    while bitarray[offset] == 1:
        q += 1
        offset += 1
    
    # Create a byte array from the bitarray slice
    byte_array = stream[offset:offset + P].tobytes()
    
    # Use numpy.frombuffer to create a uint64 from the byte array
    r = np.frombuffer(byte_array, dtype=np.uint64)[0]

    x = (q << P) + r
    return x, offset + P

class GCSFilter:

    @classmethod
    def create(cls,
        items: List[bytes],
        p: int = 19,
        m: int = 784931,
        key: bytes = b'\x00\x00\x00\x00'
    ) -> bytes:
        '''
            Turns a list of entries into a Golomb-Coded Set of hashes.

            Arguments:

            Returns:

        '''
        if m.bit_length > 32:
            raise Exception("GCS Error: m parameter must be smaller than 2^32")
        if len(items).bit_length > 32:
            raise Exception("GCS Error: number of elements must be smaller than 2^32")
        
        set_items = create_hashed_set(items, key, m)

        # Sort the items
        sorted_set_items = sorted(set_items)

        output_stream = bitarray()

        last_value = 0
        for item in sorted_set_items:
            delta = item - last_value
            golomb_encode(output_stream, delta, p)
            last_value = item

        # Pads to the right with zero up to the byte boundary
        return output_stream.tobytes()

    @classmethod
    def match_many(
        cls,
        compressed_set: bytes,
        targets: List[bytes],
        n: int,
        p: int = 19,
        m: int = 784931,
        key: bytes = b'\x00\x00\x00\x00',
    ) -> Dict[bytes, bool]:
        if m.bit_length > 32:
            raise Exception("GCS Error: m parameter must be smaller than 2^32")
        if n.bit_length > 32:
            raise Exception("GCS Error: number of elements must be smaller than 2^32")

        f = n * m

        if len(set(targets)) != len(targets):
            raise Exception("GCS Error: match targets are not unique entries")

        # Map targets to the same range as the set hashes.
        target_hashes = {hash_to_range(target, f, k): False for target in targets}
        
        input_stream = bitarray(compressed_set)

        value = 0
        offset = 0
        for i in range(n):
            delta, offset = golomb_decode(input_stream, offset, p)
            value += delta

            if value in target_hashes:
                target_hashes[value] = True

        return target_hashes