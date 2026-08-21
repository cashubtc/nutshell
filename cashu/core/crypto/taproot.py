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

TAPROOT_LEAF_TAG = "Cashu_NutrootLeaf"
TAPROOT_BRANCH_TAG = "Cashu_NutrootBranch"
TAPROOT_TWEAK_TAG = "Cashu_NutrootTweak"

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

# Normative caps from spec 2.6. The leaf body excludes the leading version byte.
TAPROOT_MAX_LEAF_BYTES = 1024
TAPROOT_MAX_TREE_DEPTH = 8
# A maximal leaf (hex), 30 Schnorr signatures, an eight-node control path,
# a preimage, and JSON framing fit below this protocol-specific DoS ceiling.
TAPROOT_MAX_WITNESS_LENGTH = 8192
# Largest unix time an `after` leaf may name (2^53 - 1), the point where
# implementations built on IEEE-754 integers stop counting exactly.
TAPROOT_MAX_LEAF_TIME = 2**53 - 1

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
        PublicKey(key)
    if len({key[1:] for key in leaf.keys}) != len(leaf.keys):
        raise ValueError("Leaf must list distinct keys")
    if leaf.n > len(leaf.keys):
        raise ValueError("Threshold exceeds leaf key count")
    fields = tlv_record(_FIELD_N, bytes([leaf.n])) + tlv_record(
        _FIELD_KEYS, b"".join(leaf.keys)
    )
    if leaf.type == "after":
        if leaf.time is None or leaf.time < 0:
            raise ValueError("after leaf requires a unix time")
        if leaf.time > TAPROOT_MAX_LEAF_TIME:
            raise ValueError("time out of range")
        fields += tlv_record(_FIELD_TIME, minimal_be(leaf.time))
    elif leaf.time is not None:
        raise ValueError(f"{leaf.type} leaf must not carry a time field")
    if leaf.type == "hashlock":
        if leaf.hash is None or len(leaf.hash) != 32:
            raise ValueError("hashlock leaf requires a 32-byte hash")
        fields += tlv_record(_FIELD_HASH, leaf.hash)
    elif leaf.hash is not None:
        raise ValueError(f"{leaf.type} leaf must not carry a hash field")
    out = bytes([TAPROOT_LEAF_VERSION, TAPROOT_LEAF_TYPE[leaf.type]]) + fields
    if len(out) - 1 > TAPROOT_MAX_LEAF_BYTES:
        raise ValueError(f"Leaf body exceeds {TAPROOT_MAX_LEAF_BYTES} bytes")
    return out


def parse_taproot_leaf(data: bytes) -> TaprootLeaf:
    """Parse a serialized leaf.

    Fails closed: unknown leaf version or type, unknown even (constraint)
    fields, missing required fields, and non-canonical streams all raise.
    Unknown odd (annotation) fields are ignored.
    """
    if len(data) < 2:
        raise ValueError("Leaf too short")
    if len(data) - 1 > TAPROOT_MAX_LEAF_BYTES:
        raise ValueError(f"Leaf body exceeds {TAPROOT_MAX_LEAF_BYTES} bytes")
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
            for key in keys:
                try:
                    PublicKey(key)
                except ValueError:
                    raise ValueError(
                        "Leaf key must be a valid compressed secp256k1 point"
                    )
            # Signatures verify against the x-only key, so two entries sharing an
            # x coordinate are one signer wearing two hats: a threshold counting
            # them separately would be satisfied by fewer signatures than it names.
            if len({k[1:] for k in keys}) != len(keys):
                raise ValueError("keys field must list distinct keys")
        elif record_type == _FIELD_TIME:
            time = read_minimal_be(value)
            # Bounded so every implementation reads the same leaf. Without a
            # bound a leaf is valid here and unparsable in a wallet whose
            # integers stop earlier, which strands the proof with its holder.
            if time > TAPROOT_MAX_LEAF_TIME:
                raise ValueError("time out of range")
        elif record_type == _FIELD_HASH:
            if len(value) != 32:
                raise ValueError("hash field must be 32 bytes")
            hash_ = value
        elif record_type % 2 == 0:
            raise ValueError(f"Unknown constraint field: {record_type}")
        # Odd = annotation, safe to ignore.
    if n is None or keys is None:
        raise ValueError("Leaf missing required n or keys field")
    if n > len(keys):
        raise ValueError("Threshold exceeds leaf key count")
    if type_name == "after" and time is None:
        raise ValueError("after leaf missing time field")
    if type_name == "hashlock" and hash_ is None:
        raise ValueError("hashlock leaf missing hash field")
    if type_name != "after" and time is not None:
        raise ValueError(f"{type_name} leaf must not carry a time field")
    if type_name != "hashlock" and hash_ is not None:
        raise ValueError(f"{type_name} leaf must not carry a hash field")
    return TaprootLeaf(type=type_name, n=n, keys=keys, time=time, hash=hash_)


def taproot_leaf_hash(serialized_leaf: bytes) -> bytes:
    """tagged_hash("Cashu_NutrootLeaf", leaf)."""
    return tagged_hash(TAPROOT_LEAF_TAG, serialized_leaf)


def taproot_branch_hash(a: bytes, b: bytes) -> bytes:
    """Branch of two child hashes, sorted pair, no left/right flags."""
    lo, hi = (a, b) if a <= b else (b, a)
    return tagged_hash(TAPROOT_BRANCH_TAG, lo, hi)


def taproot_merkle_root(leaf_hashes: List[bytes]) -> bytes:
    """Fold leaf hashes to a root: sorted ascending, then pairwise per
    level, odd hash promoted.

    The sort makes the root a function of the leaf set: any transmitted
    order reconstructs, so a store or codec that does not preserve list
    order cannot invalidate a proof. Slot assignment (spec 2.7) still
    walks the transmitted order; receivers match slot keys by value.

    Depth is a property of the tree, not of one leaf, so the cap is checked
    here and not only on a witness path. A tree of more than 2^8 leaves is
    deeper than the cap, so its long paths cannot be spent. A few of its
    leaves still can: the fold promotes an unpaired leaf to the next level,
    and a leaf promoted often enough keeps a short path (at 300 leaves, 44
    are within the cap). So an oversized tree is part spendable and part
    not, and which part is which falls out of the fold rather than out of
    anything the builder chose. Refuse the whole tree.
    """
    if not leaf_hashes:
        raise ValueError("Merkle root of zero leaves")
    if len(leaf_hashes) > 2**TAPROOT_MAX_TREE_DEPTH:
        raise ValueError(f"Tree exceeds depth {TAPROOT_MAX_TREE_DEPTH}")
    level = sorted(leaf_hashes)
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
    """Merkle path for the leaf at index (an index into the transmitted
    list): sibling hashes on the way up the sorted fold."""
    if not 0 <= index < len(leaf_hashes):
        raise ValueError(f"Leaf index out of range: {index}")
    path: List[bytes] = []
    level = sorted(leaf_hashes)
    # Equal hashes are interchangeable under sorted-pair hashing, so first
    # match is enough.
    pos = level.index(leaf_hashes[index])
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
    if len(leaf_hash) != 32 or any(len(sibling) != 32 for sibling in path):
        raise ValueError("Merkle hashes must be 32 bytes")
    acc = leaf_hash
    for sibling in path:
        acc = taproot_branch_hash(acc, sibling)
    return acc


def taproot_tweak(internal_key: bytes, merkle_root: Optional[bytes] = None) -> int:
    """Tweak scalar tagged_hash("Cashu_NutrootTweak", K || root) mod n.

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
    """The v3 secret P = K + t*G as compressed SEC1 bytes."""
    t = taproot_tweak(internal_key, merkle_root)
    if t == 0:
        return PublicKey(internal_key).format()
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


def secret_transcript_bytes(secret: str, keyset_id: str) -> bytes:
    """Bytes a proof secret contributes to the transaction transcript (spec 2.2.1).

    A v3 point secret contributes its raw 33 bytes; a v0-v2 secret contributes
    its utf8 bytes, which is what mixed transactions need.
    """
    from .keys import is_bls_keyset

    if is_bls_keyset(keyset_id):
        return bytes.fromhex(secret)
    return secret.encode("utf-8")


def keyset_id_transcript_bytes(keyset_id: str) -> bytes:
    """A keyset id as transcript bytes: raw bytes when hex, utf8 otherwise.

    Legacy (pre-v1) keyset ids are base64, and a mixed transaction may carry
    one beside a v3 input. Decoding as hex unconditionally raises instead of
    producing a transcript, so such a transaction could be neither signed nor
    verified. Falling back to utf8 is the rule the secret already follows.
    """
    if not keyset_id:
        raise ValueError("Transcript keyset id must be non-empty")
    try:
        return bytes.fromhex(keyset_id)
    except ValueError:
        return keyset_id.encode("utf-8")


def is_taproot_point_secret(secret: str, keyset_id: str) -> bool:
    """True when a v3 keyset proof's secret is a 33-byte compressed point hex."""
    from .keys import is_bls_keyset

    if not is_bls_keyset(keyset_id):
        return False
    if len(secret) != 66 or secret[:2] not in ("02", "03"):
        return False
    if secret != secret.lower():
        return False  # non-canonical spelling: not a point secret
    try:
        PublicKey(bytes.fromhex(secret))
    except (ValueError, TypeError):
        return False
    return True


def verify_script_path_spend(
    secret: bytes,
    digest: bytes,
    witness: dict,
    now: Optional[float] = None,
    preimage_max_len: int = 32,
) -> None:
    """Verify a script-path witness: commitment, then evaluate the revealed leaf.

    Witness shape (spec 2.3.2): {"leaf": hex, "control": {"K": hex, "path": [hex]},
    "signatures": [hex], "preimage": hex?}. Signatures are BIP-340 over the
    transaction digest. Raises ValueError on any failure (fail closed).
    """
    import hashlib as _hashlib
    import time as _time

    from coincurve import PublicKeyXOnly

    leaf_bytes = bytes.fromhex(witness["leaf"])
    control = witness["control"]
    internal_key = bytes.fromhex(control["K"])
    path = [bytes.fromhex(h) for h in control.get("path", [])]
    if not verify_taproot_commitment(secret, internal_key, leaf_bytes, path):
        raise ValueError("script path commitment does not reach the secret")
    leaf = parse_taproot_leaf(leaf_bytes)  # raises on unknown version/type/fields

    if leaf.type == "after":
        assert leaf.time is not None
        if (now if now is not None else _time.time()) < leaf.time:
            raise ValueError("after leaf locktime not reached")

    if leaf.type == "hashlock":
        assert leaf.hash is not None
        preimage_hex = witness.get("preimage")
        if not isinstance(preimage_hex, str):
            raise ValueError("hashlock leaf requires a preimage")
        preimage = bytes.fromhex(preimage_hex)
        if len(preimage) > preimage_max_len:
            raise ValueError("hashlock preimage too long")
        if _hashlib.sha256(preimage).digest() != leaf.hash:
            raise ValueError("hashlock preimage does not match")

    signatures = witness.get("signatures") or []
    if not isinstance(signatures, list):
        raise ValueError("invalid signatures field")
    unique_sigs = list(dict.fromkeys(signatures))
    satisfied_keys = set()
    for key in leaf.keys:
        for sig_hex in unique_sigs:
            try:
                if PublicKeyXOnly(key[1:]).verify(bytes.fromhex(sig_hex), digest):
                    satisfied_keys.add(key)
                    break
            except Exception:
                continue
    if len(satisfied_keys) < leaf.n:
        raise ValueError(
            f"threshold not met: {len(satisfied_keys)} of {leaf.n} signatures"
        )
