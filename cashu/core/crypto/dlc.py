from hashlib import sha256
from typing import Optional, Tuple
from secp256k1 import PrivateKey, PublicKey

from typing import List

def sorted_merkle_hash(left: bytes, right: bytes) -> bytes:
    '''Sorts `left` and `right` in non-ascending order and
        computes the hash of their concatenation
    '''
    if int.from_bytes(left, 'big') < int.from_bytes(right, 'big'):
        left, right = right, left
    return sha256(left+right).digest()


def merkle_root(leaf_hashes: List[bytes]) -> bytes:
    '''Computes the root of a list of merkle proofs
    '''
    if len(leaf_hashes) == 0:
        return b""
    elif len(leaf_hashes) == 1:
        return leaf_hashes[0]
    else:
        split = len(leaf_hashes) // 2
        left = merkle_root(leaf_hashes[:split])
        right = merkle_root(leaf_hashes[split:])
        return sorted_merkle_hash(left, right)

def merkle_verify(root: bytes, leaf_hash: bytes, proof: List[bytes]) -> bool:
    '''Verifies that `leaf_hash` belongs to a merkle tree
        that has `root` as root
    '''
    h = leaf_hash
    for branch_hash in proof:
        h = sorted_merkle_hash(h, branch_hash)
    return h == root