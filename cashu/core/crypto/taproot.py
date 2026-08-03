"""Taproot secrets (v3 keysets) crypto core.

Tagged hashes, canonical TLV, leaf serialization, merkle tree, and tweak
math per taproot-secrets spec sections 2.1, 2.3 and 2.6. BIP341's
commitment machinery with Cashu tags and compressed (not x-only) keys.
Byte-identical with cashu-ts src/crypto/taproot.ts; both are pinned by the
shared vectors in tests/taproot_v3_vectors.json.
"""

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .secp import PrivateKey, PublicKey

TAPROOT_LEAF_TAG = "Cashu_TapLeaf"
TAPROOT_BRANCH_TAG = "Cashu_TapBranch"
TAPROOT_TWEAK_TAG = "Cashu_TapTweak"

TAPROOT_LEAF_VERSION = 0x00

# Leaf type registry (version 0x00). A number means one thing forever.
TAPROOT_LEAF_TYPE: Dict[str, int] = {
    "threshold": 0x01,
    "after": 0x02,
    "hashlock": 0x03,
}
_LEAF_TYPE_NAME = {v: k for k, v in TAPROOT_LEAF_TYPE.items()}

# Leaf body field types. Even = constraint (unknown fails closed), odd =
# annotation (ignorable).
_FIELD_N = 0x02
_FIELD_KEYS = 0x04
_FIELD_TIME = 0x06
_FIELD_HASH = 0x08

# Suggested caps from spec 2.6, pending confirmation.
TAPROOT_MAX_LEAF_BYTES = 1024
TAPROOT_MAX_TREE_DEPTH = 8

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass
class TaprootLeaf:
    """A parsed declarative leaf (version 0x00).

    Keys are 33-byte compressed SEC1. `time` is unix seconds; `hash` is 32
    bytes.
    """

    type: str
    n: int
    keys: List[bytes]
    time: Optional[int] = None
    hash: Optional[bytes] = None


def tagged_hash(tag: str, *messages: bytes) -> bytes:
    """BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || messages)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    h = hashlib.sha256(tag_hash + tag_hash)
    for message in messages:
        h.update(message)
    return h.digest()


def tlv_record(record_type: int, value: bytes) -> bytes:
    """Encode one TLV record: type (1 byte) || length (2 bytes BE) || value."""
    if not 0 <= record_type <= 0xFF:
        raise ValueError(f"Invalid TLV type: {record_type}")
    if len(value) > 0xFFFF:
        raise ValueError(f"TLV value too long: {len(value)} bytes")
    return bytes([record_type]) + len(value).to_bytes(2, "big") + value


def read_tlv_records(
    data: bytes, unique_ascending: bool = False
) -> List[Tuple[int, bytes]]:
    """Decode a TLV stream.

    With unique_ascending (leaf field streams) types must strictly ascend,
    which also forces uniqueness. Container streams repeat types.
    """
    records: List[Tuple[int, bytes]] = []
    offset = 0
    prev_type = -1
    while offset < len(data):
        if len(data) - offset < 3:
            raise ValueError("Truncated TLV record header")
        record_type = data[offset]
        length = int.from_bytes(data[offset + 1 : offset + 3], "big")
        offset += 3
        if len(data) - offset < length:
            raise ValueError("Truncated TLV record value")
        if unique_ascending and record_type <= prev_type:
            raise ValueError("TLV types must strictly ascend")
        prev_type = record_type
        records.append((record_type, data[offset : offset + length]))
        offset += length
    return records


def minimal_be(value: int) -> bytes:
    """Minimal big-endian encoding; zero encodes to zero bytes."""
    if value < 0:
        raise ValueError("Cannot encode negative integer")
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def read_minimal_be(data: bytes) -> int:
    """Decode a minimal big-endian integer; rejects leading zero bytes."""
    if len(data) > 0 and data[0] == 0:
        raise ValueError("Non-minimal integer encoding")
    return int.from_bytes(data, "big")


def serialize_taproot_leaf(leaf: TaprootLeaf) -> bytes:
    """Serialize a leaf to its wire form: leaf_version || leaf_type || field TLVs.

    The returned bytes are the leaf everywhere: spend info, witness, and
    hash preimage.
    """
    if leaf.type not in TAPROOT_LEAF_TYPE:
        raise ValueError(f"Unknown leaf type: {leaf.type}")
    if not 1 <= leaf.n <= 0xFF:
        raise ValueError(f"Invalid threshold n: {leaf.n}")
    if not leaf.keys:
        raise ValueError("Leaf requires at least one key")
    for key in leaf.keys:
        if len(key) != 33:
            raise ValueError(f"Leaf key must be 33 bytes, got {len(key)}")
    fields = tlv_record(_FIELD_N, bytes([leaf.n])) + tlv_record(
        _FIELD_KEYS, b"".join(leaf.keys)
    )
    if leaf.type == "after":
        if leaf.time is None or leaf.time < 0:
            raise ValueError("after leaf requires a unix time")
        fields += tlv_record(_FIELD_TIME, minimal_be(leaf.time))
    if leaf.type == "hashlock":
        if leaf.hash is None or len(leaf.hash) != 32:
            raise ValueError("hashlock leaf requires a 32-byte hash")
        fields += tlv_record(_FIELD_HASH, leaf.hash)
    out = bytes([TAPROOT_LEAF_VERSION, TAPROOT_LEAF_TYPE[leaf.type]]) + fields
    if len(out) > TAPROOT_MAX_LEAF_BYTES:
        raise ValueError(f"Leaf exceeds {TAPROOT_MAX_LEAF_BYTES} bytes")
    return out


def parse_taproot_leaf(data: bytes) -> TaprootLeaf:
    """Parse a serialized leaf.

    Fails closed: unknown leaf version or type, unknown even (constraint)
    fields, missing required fields, and non-canonical streams all raise.
    Unknown odd (annotation) fields are ignored.
    """
    if len(data) < 2:
        raise ValueError("Leaf too short")
    if len(data) > TAPROOT_MAX_LEAF_BYTES:
        raise ValueError(f"Leaf exceeds {TAPROOT_MAX_LEAF_BYTES} bytes")
    if data[0] != TAPROOT_LEAF_VERSION:
        raise ValueError(f"Unknown leaf version: {data[0]}")
    type_name = _LEAF_TYPE_NAME.get(data[1])
    if type_name is None:
        raise ValueError(f"Unknown leaf type: {data[1]}")
    n: Optional[int] = None
    keys: Optional[List[bytes]] = None
    time: Optional[int] = None
    hash_: Optional[bytes] = None
    for record_type, value in read_tlv_records(data[2:], unique_ascending=True):
        if record_type == _FIELD_N:
            if len(value) != 1 or value[0] == 0:
                raise ValueError("Invalid threshold n")
            n = value[0]
        elif record_type == _FIELD_KEYS:
            if len(value) == 0 or len(value) % 33 != 0:
                raise ValueError("keys field length must be a positive multiple of 33")
            keys = [value[i : i + 33] for i in range(0, len(value), 33)]
        elif record_type == _FIELD_TIME:
            time = read_minimal_be(value)
        elif record_type == _FIELD_HASH:
            if len(value) != 32:
                raise ValueError("hash field must be 32 bytes")
            hash_ = value
        elif record_type % 2 == 0:
            raise ValueError(f"Unknown constraint field: {record_type}")
        # Odd = annotation, safe to ignore.
    if n is None or keys is None:
        raise ValueError("Leaf missing required n or keys field")
    if type_name == "after" and time is None:
        raise ValueError("after leaf missing time field")
    if type_name == "hashlock" and hash_ is None:
        raise ValueError("hashlock leaf missing hash field")
    return TaprootLeaf(type=type_name, n=n, keys=keys, time=time, hash=hash_)


def taproot_leaf_hash(serialized_leaf: bytes) -> bytes:
    """tagged_hash("Cashu_TapLeaf", leaf)."""
    return tagged_hash(TAPROOT_LEAF_TAG, serialized_leaf)


def taproot_branch_hash(a: bytes, b: bytes) -> bytes:
    """Branch of two child hashes, sorted pair, no left/right flags."""
    lo, hi = (a, b) if a <= b else (b, a)
    return tagged_hash(TAPROOT_BRANCH_TAG, lo, hi)


def taproot_merkle_root(leaf_hashes: List[bytes]) -> bytes:
    """Fold leaf hashes to a root: pairwise per level, odd hash promoted."""
    if not leaf_hashes:
        raise ValueError("Merkle root of zero leaves")
    level = list(leaf_hashes)
    while len(level) > 1:
        nxt = [
            taproot_branch_hash(level[i], level[i + 1])
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def taproot_merkle_path(leaf_hashes: List[bytes], index: int) -> List[bytes]:
    """Merkle path for the leaf at index: sibling hashes on the way up."""
    if not 0 <= index < len(leaf_hashes):
        raise ValueError(f"Leaf index out of range: {index}")
    path: List[bytes] = []
    level = list(leaf_hashes)
    pos = index
    while len(level) > 1:
        nxt = [
            taproot_branch_hash(level[i], level[i + 1])
            for i in range(0, len(level) - 1, 2)
        ]
        odd = len(level) % 2 == 1
        if odd:
            nxt.append(level[-1])
        if odd and pos == len(level) - 1:
            # Promoted unpaired: no sibling at this level.
            pos = len(nxt) - 1
        else:
            path.append(level[pos + 1] if pos % 2 == 0 else level[pos - 1])
            pos //= 2
        level = nxt
    return path


def taproot_root_from_path(leaf_hash: bytes, path: List[bytes]) -> bytes:
    """Recompute a root from a leaf hash and its merkle path."""
    if len(path) > TAPROOT_MAX_TREE_DEPTH:
        raise ValueError(f"Merkle path exceeds depth {TAPROOT_MAX_TREE_DEPTH}")
    acc = leaf_hash
    for sibling in path:
        acc = taproot_branch_hash(acc, sibling)
    return acc


def taproot_tweak(internal_key: bytes, merkle_root: Optional[bytes] = None) -> int:
    """Tweak scalar tagged_hash("Cashu_TapTweak", K || root) mod n.

    Omit merkle_root for the empty tweak (aggregated keys, spec 3.8).
    """
    if len(internal_key) != 33:
        raise ValueError("Internal key must be 33 bytes")
    if merkle_root is not None:
        digest = tagged_hash(TAPROOT_TWEAK_TAG, internal_key, merkle_root)
    else:
        digest = tagged_hash(TAPROOT_TWEAK_TAG, internal_key)
    return int.from_bytes(digest, "big") % SECP256K1_N


def taproot_tweak_pubkey(
    internal_key: bytes, merkle_root: Optional[bytes] = None
) -> bytes:
    """Tweaked output key P = K + t*G as compressed SEC1 bytes."""
    t = taproot_tweak(internal_key, merkle_root)
    tweak_point = PrivateKey(t.to_bytes(32, "big")).public_key
    assert tweak_point
    P = PublicKey.combine_keys([PublicKey(internal_key), tweak_point])
    return P.format()


def taproot_tweak_seckey(seckey: bytes, merkle_root: Optional[bytes] = None) -> bytes:
    """Tweaked private key p' = (k + t) mod n for the key path."""
    if len(seckey) != 32:
        raise ValueError("Secret key must be 32 bytes")
    k = int.from_bytes(seckey, "big")
    if k == 0 or k >= SECP256K1_N:
        raise ValueError("Invalid secret key")
    K = PrivateKey(seckey).public_key
    assert K
    t = taproot_tweak(K.format(), merkle_root)
    p = (k + t) % SECP256K1_N
    if p == 0:
        raise ValueError("Tweaked secret key is zero")
    return p.to_bytes(32, "big")


def verify_taproot_commitment(
    secret: bytes,
    internal_key: bytes,
    serialized_leaf: bytes,
    merkle_path: List[bytes],
) -> bool:
    """Verify a script-path commitment: leaf -> root (via path) -> tweak -> secret.

    Commitment only; evaluating the revealed leaf is the caller's job.
    """
    if len(secret) != 33:
        raise ValueError("Secret must be 33 bytes")
    root = taproot_root_from_path(taproot_leaf_hash(serialized_leaf), merkle_path)
    return taproot_tweak_pubkey(internal_key, root) == secret


def is_taproot_point_secret(secret: str, keyset_id: str) -> bool:
    """True when a v3 keyset proof's secret is a 33-byte compressed point hex."""
    from .keys import is_bls_keyset

    if not is_bls_keyset(keyset_id):
        return False
    if len(secret) != 66 or secret[:2] not in ("02", "03"):
        return False
    try:
        bytes.fromhex(secret)
    except ValueError:
        return False
    return True
