"""Taproot v3 crypto core tests against the shared vectors.

Vectors: tests/taproot_v3_vectors.json (canonical copy lives in cashu-ts
test/vectors/taproot-v3.json; update both in the same commit set).
"""

import hashlib
import json
import os

import pytest
from coincurve import PublicKeyXOnly

from cashu.core.crypto.secp import PrivateKey
from cashu.core.crypto.taproot import (
    TAPROOT_BRANCH_TAG,
    TAPROOT_LEAF_TAG,
    TAPROOT_TWEAK_TAG,
    TaprootLeaf,
    parse_taproot_leaf,
    read_minimal_be,
    read_tlv_records,
    serialize_taproot_leaf,
    tagged_hash,
    taproot_branch_hash,
    taproot_leaf_hash,
    taproot_merkle_path,
    taproot_merkle_root,
    taproot_root_from_path,
    taproot_tweak,
    taproot_tweak_pubkey,
    taproot_tweak_seckey,
    tlv_record,
    verify_taproot_commitment,
)

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

with open(os.path.join(os.path.dirname(__file__), "taproot_v3_vectors.json")) as f:
    VECTORS = json.load(f)

V61 = VECTORS["example_6_1"]
V62 = VECTORS["example_6_2"]


def verify_schnorr_digest(signature: bytes, digest: bytes, pubkey33: bytes) -> bool:
    """BIP-340 verify over an already-hashed 32-byte digest."""
    return PublicKeyXOnly(pubkey33[1:]).verify(signature, digest)


def test_vector_tags_match_module_tags():
    assert VECTORS["tags"]["leaf"] == TAPROOT_LEAF_TAG
    assert VECTORS["tags"]["branch"] == TAPROOT_BRANCH_TAG
    assert VECTORS["tags"]["tweak"] == TAPROOT_TWEAK_TAG


def test_tlv_roundtrip_and_canonical_rules():
    stream = tlv_record(0x02, b"\x01") + tlv_record(
        0x04, bytes.fromhex(V61["carol_pub"])
    )
    records = read_tlv_records(stream, unique_ascending=True)
    assert len(records) == 2
    assert records[0] == (0x02, b"\x01")
    assert records[1][1].hex() == V61["carol_pub"]

    descending = tlv_record(0x04, b"\x01") + tlv_record(0x02, b"\x01")
    with pytest.raises(ValueError, match="ascend"):
        read_tlv_records(descending, unique_ascending=True)
    duplicate = tlv_record(0x02, b"\x01") + tlv_record(0x02, b"\x01")
    with pytest.raises(ValueError, match="ascend"):
        read_tlv_records(duplicate, unique_ascending=True)

    record = tlv_record(0x02, b"\x01\x02\x03")
    with pytest.raises(ValueError, match="Truncated"):
        read_tlv_records(record[:2])
    with pytest.raises(ValueError, match="Truncated"):
        read_tlv_records(record[:5])


def test_minimal_be_integers():
    assert read_minimal_be(bytes.fromhex("68a3be80")) == V61["refund_time"]
    with pytest.raises(ValueError, match="minimal"):
        read_minimal_be(b"\x00\x01")


def test_leaf_serialization_6_1():
    leaf = serialize_taproot_leaf(
        TaprootLeaf(
            type="after",
            n=1,
            keys=[bytes.fromhex(V61["alice_refund_pub"])],
            time=V61["refund_time"],
        )
    )
    assert leaf.hex() == V61["leaf_after"]
    parsed = parse_taproot_leaf(leaf)
    assert parsed.type == "after"
    assert parsed.n == 1
    assert parsed.keys == [bytes.fromhex(V61["alice_refund_pub"])]
    assert parsed.time == V61["refund_time"]
    assert taproot_leaf_hash(leaf).hex() == V61["merkle_root"]


def test_leaf_serialization_6_2():
    melt_to = serialize_taproot_leaf(
        TaprootLeaf(
            type="melt_to",
            n=1,
            keys=[bytes.fromhex(V62["kid_pub"])],
            destination=bytes.fromhex(V62["node_pub"]),
        )
    )
    assert melt_to.hex() == V62["leaf_melt_to"]
    after = serialize_taproot_leaf(
        TaprootLeaf(
            type="after",
            n=1,
            keys=[bytes.fromhex(V62["kid_pub"])],
            time=V62["vest_time"],
        )
    )
    assert after.hex() == V62["leaf_after"]
    assert taproot_leaf_hash(melt_to).hex() == V62["leaf_hash_melt_to"]
    assert taproot_leaf_hash(after).hex() == V62["leaf_hash_after"]


def test_leaf_parsing_fails_closed():
    good = bytes.fromhex(V61["leaf_after"])
    with pytest.raises(ValueError, match="version"):
        parse_taproot_leaf(b"\x01" + good[1:])
    with pytest.raises(ValueError, match="type"):
        parse_taproot_leaf(good[:1] + b"\x7f" + good[2:])

    base_fields = tlv_record(0x02, b"\x01") + tlv_record(
        0x04, bytes.fromhex(V61["carol_pub"])
    )
    unknown_even = b"\x00\x01" + base_fields + tlv_record(0x0C, b"\x01")
    with pytest.raises(ValueError, match="constraint"):
        parse_taproot_leaf(unknown_even)

    unknown_odd = b"\x00\x01" + base_fields + tlv_record(0x0D, b"label")
    parsed = parse_taproot_leaf(unknown_odd)
    assert parsed.type == "threshold"
    assert parsed.n == 1
    assert parsed.keys == [bytes.fromhex(V61["carol_pub"])]

    bad_keys = b"\x00\x01" + tlv_record(0x02, b"\x01") + tlv_record(0x04, b"\x02" * 32)
    with pytest.raises(ValueError, match="multiple of 33"):
        parse_taproot_leaf(bad_keys)


def test_merkle_tree_6_2():
    h_melt = bytes.fromhex(V62["leaf_hash_melt_to"])
    h_after = bytes.fromhex(V62["leaf_hash_after"])
    assert taproot_branch_hash(h_melt, h_after).hex() == V62["merkle_root"]
    assert taproot_branch_hash(h_after, h_melt).hex() == V62["merkle_root"]
    assert taproot_merkle_root([h_melt, h_after]).hex() == V62["merkle_root"]

    path_melt = taproot_merkle_path([h_melt, h_after], 0)
    assert [p.hex() for p in path_melt] == V62["melt_witness"]["control"]["path"]
    assert taproot_root_from_path(h_melt, path_melt).hex() == V62["merkle_root"]
    path_after = taproot_merkle_path([h_melt, h_after], 1)
    assert [p.hex() for p in path_after] == V62["after_witness_path"]
    assert taproot_root_from_path(h_after, path_after).hex() == V62["merkle_root"]


def test_merkle_tree_folding():
    hashes = [hashlib.sha256(bytes([i])).digest() for i in range(1, 5)]
    b12 = taproot_branch_hash(hashes[0], hashes[1])
    b34 = taproot_branch_hash(hashes[2], hashes[3])
    root = taproot_branch_hash(b12, b34)
    assert taproot_merkle_root(hashes) == root
    for i in range(4):
        path = taproot_merkle_path(hashes, i)
        assert len(path) == 2
        assert taproot_root_from_path(hashes[i], path) == root

    three = hashes[:3]
    root3 = taproot_branch_hash(taproot_branch_hash(three[0], three[1]), three[2])
    assert taproot_merkle_root(three) == root3
    path2 = taproot_merkle_path(three, 2)
    assert len(path2) == 1
    assert taproot_root_from_path(three[2], path2) == root3


def test_tweak_math_6_1():
    K = bytes.fromhex(V61["internal_key"])
    root = bytes.fromhex(V61["merkle_root"])
    assert format(taproot_tweak(K, root), "064x") == V61["tweak"]
    assert taproot_tweak_pubkey(K, root).hex() == V61["secret"]

    internal_seckey = (
        int(V61["carol_priv"], 16) + int(V61["p2bk_r"], 16)
    ) % SECP256K1_N
    p_prime = taproot_tweak_seckey(internal_seckey.to_bytes(32, "big"), root)
    assert p_prime.hex() == V61["keypath_priv"]
    pub = PrivateKey(p_prime).public_key
    assert pub and pub.format().hex() == V61["secret"]


def test_tweak_math_6_2():
    K = bytes.fromhex(V62["internal_key"])
    root = bytes.fromhex(V62["merkle_root"])
    assert format(taproot_tweak(K, root), "064x") == V62["tweak"]
    assert taproot_tweak_pubkey(K, root).hex() == V62["secret"]
    p_prime = taproot_tweak_seckey(int(V62["parent_priv"], 16).to_bytes(32, "big"), root)
    pub = PrivateKey(p_prime).public_key
    assert pub and pub.format().hex() == V62["secret"]


def test_vector_signatures_verify():
    assert verify_schnorr_digest(
        bytes.fromhex(V61["keypath_signature"]),
        bytes.fromhex(V61["transcript_digest"]),
        bytes.fromhex(V61["secret"]),
    )
    assert verify_schnorr_digest(
        bytes.fromhex(V61["scriptpath_witness"]["signatures"][0]),
        bytes.fromhex(V61["transcript_digest"]),
        bytes.fromhex(V61["alice_refund_pub"]),
    )
    assert verify_schnorr_digest(
        bytes.fromhex(V62["melt_witness"]["signatures"][0]),
        bytes.fromhex(V62["transcript_digest"]),
        bytes.fromhex(V62["kid_pub"]),
    )


def test_keypath_signature_reproduces():
    p_prime = bytes.fromhex(V61["keypath_priv"])
    sig = PrivateKey(p_prime).sign_schnorr(
        bytes.fromhex(V61["transcript_digest"]), b"\x00" * 32
    )
    assert sig.hex() == V61["keypath_signature"]


def test_script_path_commitment():
    assert verify_taproot_commitment(
        bytes.fromhex(V61["secret"]),
        bytes.fromhex(V61["scriptpath_witness"]["control"]["K"]),
        bytes.fromhex(V61["scriptpath_witness"]["leaf"]),
        [bytes.fromhex(p) for p in V61["scriptpath_witness"]["control"]["path"]],
    )
    assert verify_taproot_commitment(
        bytes.fromhex(V62["secret"]),
        bytes.fromhex(V62["melt_witness"]["control"]["K"]),
        bytes.fromhex(V62["melt_witness"]["leaf"]),
        [bytes.fromhex(p) for p in V62["melt_witness"]["control"]["path"]],
    )
    # Wrong merkle path fails
    assert not verify_taproot_commitment(
        bytes.fromhex(V62["secret"]),
        bytes.fromhex(V62["melt_witness"]["control"]["K"]),
        bytes.fromhex(V62["melt_witness"]["leaf"]),
        [bytes.fromhex(V62["leaf_hash_melt_to"])],
    )
    # Wrong internal key fails
    assert not verify_taproot_commitment(
        bytes.fromhex(V62["secret"]),
        bytes.fromhex(V61["internal_key"]),
        bytes.fromhex(V62["melt_witness"]["leaf"]),
        [bytes.fromhex(p) for p in V62["melt_witness"]["control"]["path"]],
    )
    # Depth cap
    filler = hashlib.sha256(b"\x09").digest()
    with pytest.raises(ValueError, match="depth"):
        taproot_root_from_path(filler, [filler] * 9)


def test_bearer_contrast():
    pub = PrivateKey(bytes.fromhex(V61["bearer_contrast"]["k"])).public_key
    assert pub and pub.format().hex() == V61["bearer_contrast"]["secret"]
