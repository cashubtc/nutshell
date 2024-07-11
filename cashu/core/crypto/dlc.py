from hashlib import sha256
from typing import List, Optional, Tuple


def sorted_merkle_hash(left: bytes, right: bytes) -> bytes:
    '''Sorts `left` and `right` in non-ascending order and
        computes the hash of their concatenation
    '''
    if int.from_bytes(left, 'big') < int.from_bytes(right, 'big'):
        left, right = right, left
    return sha256(left+right).digest()


def merkle_root(
    leaf_hashes: List[bytes],
    track_branch: Optional[int] = None
    ) -> Tuple[bytes, Optional[List[bytes]]]:
    '''Computes the root of a list of merkle proofs
        if `track_branch` is set, extracts the hashes for the branch that leads
        to `leaf_hashes[track_branch]`
    '''
    if track_branch is not None:
        if len(leaf_hashes) == 0:
            return b"", []
        elif len(leaf_hashes) == 1:
            return leaf_hashes[0], []
        else:
            split = len(leaf_hashes) // 2
            left, left_branch_hashes = merkle_root(leaf_hashes[:split],
                track_branch if track_branch < split else None)
            right, right_branch_hashes = merkle_root(leaf_hashes[split:],
                track_branch-split if track_branch >= split else None)
            branch_hashes = (left_branch_hashes if
                track_branch < split else right_branch_hashes)
            hashh = sorted_merkle_hash(left, right)
            # Needed to pass mypy checks
            assert branch_hashes is not None, "merkle_root fail: branch_hashes == None"
            branch_hashes.append(right if track_branch < split else left)
            return hashh, branch_hashes
    else:
        if len(leaf_hashes) == 0:
            return b"", None
        elif len(leaf_hashes) == 1:
            return leaf_hashes[0], None
        else:
            split = len(leaf_hashes) // 2
            left, _  = merkle_root(leaf_hashes[:split], None)
            right, _ = merkle_root(leaf_hashes[split:], None)
            hashh = sorted_merkle_hash(left, right)
            return hashh, None

def merkle_verify(root: bytes, leaf_hash: bytes, proof: List[bytes]) -> bool:
    '''Verifies that `leaf_hash` belongs to a merkle tree
        that has `root` as root
    '''
    h = leaf_hash
    for branch_hash in proof:
        h = sorted_merkle_hash(h, branch_hash)
    return h == root