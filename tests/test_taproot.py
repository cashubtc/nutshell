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
from cashu.core.errors import TransactionError

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
    after = serialize_taproot_leaf(
        TaprootLeaf(
            type="after",
            n=1,
            keys=[bytes.fromhex(V62["kid_pub"])],
            time=V62["vest_time"],
        )
    )
    assert after.hex() == V62["leaf_after"]
    # The 6.2 melt_to covenant is a spec extensibility example, not an
    # implemented leaf type; its bytes still pin the tree and tweak math,
    # and parsing it must fail closed as an unknown type.
    melt_to = bytes.fromhex(V62["leaf_melt_to"])
    assert taproot_leaf_hash(melt_to).hex() == V62["leaf_hash_melt_to"]
    assert taproot_leaf_hash(after).hex() == V62["leaf_hash_after"]
    with pytest.raises(ValueError, match="type"):
        parse_taproot_leaf(melt_to)


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

    at_limit = (
        b"\x00\x01"
        + base_fields
        + tlv_record(0x0D, bytes(1024 - 1 - len(base_fields) - 3))
    )
    assert len(at_limit) == 1025
    assert parse_taproot_leaf(at_limit).type == "threshold"
    over_limit = (
        b"\x00\x01"
        + base_fields
        + tlv_record(0x0D, bytes(1024 - len(base_fields) - 3))
    )
    with pytest.raises(ValueError, match="body exceeds"):
        parse_taproot_leaf(over_limit)

    bad_keys = b"\x00\x01" + tlv_record(0x02, b"\x01") + tlv_record(0x04, b"\x02" * 32)
    with pytest.raises(ValueError, match="multiple of 33"):
        parse_taproot_leaf(bad_keys)

    threshold_with_time = (
        b"\x00\x01"
        + base_fields
        + tlv_record(0x06, b"\x01")
    )
    with pytest.raises(ValueError, match="must not carry a time"):
        parse_taproot_leaf(threshold_with_time)

    after_with_hash = (
        b"\x00\x02"
        + base_fields
        + tlv_record(0x06, b"\x01")
        + tlv_record(0x08, b"\x00" * 32)
    )
    with pytest.raises(ValueError, match="must not carry a hash"):
        parse_taproot_leaf(after_with_hash)
    with pytest.raises(ValueError, match="must not carry a time"):
        serialize_taproot_leaf(
            TaprootLeaf(
                type="threshold",
                n=1,
                keys=[bytes.fromhex(V61["carol_pub"])],
                time=1,
            )
        )

    invalid_key = b"\x02" + b"\xff" * 32
    invalid_point = (
        b"\x00\x01"
        + tlv_record(0x02, b"\x01")
        + tlv_record(0x04, invalid_key)
    )
    with pytest.raises(ValueError, match="valid compressed"):
        parse_taproot_leaf(invalid_point)
    with pytest.raises(ValueError):
        serialize_taproot_leaf(
            TaprootLeaf(type="threshold", n=1, keys=[invalid_key])
        )

    impossible_threshold = (
        b"\x00\x01"
        + tlv_record(0x02, b"\x02")
        + tlv_record(0x04, bytes.fromhex(V61["carol_pub"]))
    )
    with pytest.raises(ValueError, match="key count"):
        parse_taproot_leaf(impossible_threshold)
    with pytest.raises(ValueError, match="key count"):
        serialize_taproot_leaf(
            TaprootLeaf(
                type="threshold",
                n=2,
                keys=[bytes.fromhex(V61["carol_pub"])],
            )
        )


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
    # The fold sorts, so build the expected tree over the sorted list.
    s = sorted(hashes)
    b12 = taproot_branch_hash(s[0], s[1])
    b34 = taproot_branch_hash(s[2], s[3])
    root = taproot_branch_hash(b12, b34)
    assert taproot_merkle_root(hashes) == root
    for i in range(4):
        path = taproot_merkle_path(hashes, i)
        assert len(path) == 2
        assert taproot_root_from_path(hashes[i], path) == root

    three = hashes[:3]
    s3 = sorted(three)
    root3 = taproot_branch_hash(taproot_branch_hash(s3[0], s3[1]), s3[2])
    assert taproot_merkle_root(three) == root3
    # The promoted (last sorted) leaf has the single-sibling path.
    promoted = three.index(s3[2])
    path2 = taproot_merkle_path(three, promoted)
    assert len(path2) == 1
    assert taproot_root_from_path(three[promoted], path2) == root3


def test_merkle_root_is_order_independent():
    # The root commits the leaf set: every permutation folds to one root and
    # every path still verifies. Before the sorted fold a reordered 3-leaf
    # list produced a different root, silently invalidating stored proofs.
    from itertools import permutations

    hashes = [hashlib.sha256(bytes([i])).digest() for i in range(1, 4)]
    root = taproot_merkle_root(hashes)
    for perm in permutations(hashes):
        order = list(perm)
        assert taproot_merkle_root(order) == root
        for i in range(len(order)):
            path = taproot_merkle_path(order, i)
            assert taproot_root_from_path(order[i], path) == root


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
    with pytest.raises(ValueError, match="32 bytes"):
        taproot_root_from_path(filler, [filler[1:]])


def test_zero_tweak_keeps_internal_key(monkeypatch):
    from cashu.core.crypto import taproot as taproot_crypto

    internal_key = bytes.fromhex(V61["internal_key"])
    monkeypatch.setattr(taproot_crypto, "taproot_tweak", lambda *_: 0)
    assert taproot_crypto.taproot_tweak_pubkey(internal_key) == internal_key


def test_bearer_contrast():
    pub = PrivateKey(bytes.fromhex(V61["bearer_contrast"]["k"])).public_key
    assert pub and pub.format().hex() == V61["bearer_contrast"]["secret"]


@pytest.mark.asyncio
async def test_nut13_v3_secret_derivation_vectors():
    """The 0x00 branch derives the internal key; the secret is K = k*G (spec 2.4.2)."""
    from cashu.wallet.secrets import WalletSecrets

    nut13 = VECTORS["nut13_v3"]
    secrets = WalletSecrets()
    secrets.seed = nut13["seed_utf8"].encode()
    secrets.keyset_id = nut13["keyset_id"]
    for output in nut13["outputs"]:
        secret, r, path = await secrets.generate_determinstic_secret(output["counter"])
        assert "HMAC-SHA256" in path
        assert secret.hex() == output["secret"]
        assert r.hex() == output["blinding_factor"]
        expected_pub = PrivateKey(bytes.fromhex(output["secret_key"])).public_key
        assert expected_pub and expected_pub.format() == secret


@pytest.mark.asyncio
async def test_nut13_v3_derivation_type_vectors():
    """Each purpose gets its own derivation type over the framed V3 message.

    A quote lock key may be handed over for delegated minting and a leaf key is
    published in the tree, so neither may collide with a proof secret key.
    """
    from cashu.wallet.secrets import WalletSecrets

    nut13 = VECTORS["nut13_v3"]
    secrets = WalletSecrets()
    secrets.seed = nut13["seed_utf8"].encode()
    keyset_id = nut13["keyset_id"]
    for output in nut13["outputs"]:
        offset = secrets.derive_v3_nums_offset(output["counter"], keyset_id)
        assert offset.hex() == output["nums_offset"]
    for leaf in nut13["leaf_keys"]:
        key = secrets.derive_v3_leaf_key(leaf["counter"], keyset_id, leaf["index"])
        assert key.hex() == leaf["privkey"]
        pub = PrivateKey(key).public_key
        assert pub and pub.format().hex() == leaf["pubkey"]
    for lock in nut13["quote_locks"]:
        key = secrets.derive_v3_quote_lock_key(lock["counter"])
        assert key.hex() == lock["privkey"]
        pub = PrivateKey(key).public_key
        assert pub and pub.format().hex() == lock["pubkey"]
    # One counter describes one proof completely, so its components must not collide.
    counter = nut13["outputs"][0]["counter"]
    derived = {
        secrets.derive_v3_secret_key(counter, keyset_id),
        secrets.derive_v3_nums_offset(counter, keyset_id),
        secrets.derive_v3_leaf_key(counter, keyset_id, 0),
        secrets.derive_v3_quote_lock_key(counter),
    }
    assert len(derived) == 4


def test_v3_secret_must_be_lowercase_hex():
    """One spelling per secret: upper-case hex names the same point but the two
    sides hash it differently, so it is refused rather than accepted twice."""
    from cashu.core.crypto.bls_dhke import secret_to_hash_input
    from cashu.core.crypto.taproot import is_taproot_point_secret

    low = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert secret_to_hash_input(low) == bytes.fromhex(low)
    with pytest.raises(TransactionError, match="lowercase"):
        secret_to_hash_input(low.upper())
    v3_keyset = "029e18e63831fcf4764b1f1b574a2b415b07e6f86aa263b8948aae772e92fd3f70"
    assert is_taproot_point_secret(low, v3_keyset)
    assert not is_taproot_point_secret(low.upper(), v3_keyset)
    assert not is_taproot_point_secret("02" + "ff" * 32, v3_keyset)


def test_threshold_leaf_rejects_parity_twin_keys():
    """A key and its parity twin share an x coordinate, so one signature would
    satisfy both entries and an n-of-m would need fewer signatures than it names."""
    from cashu.core.crypto.taproot import serialize_taproot_leaf

    priv = PrivateKey()
    assert priv.public_key
    pub = priv.public_key.format()
    twin = (b"\x03" if pub[0] == 2 else b"\x02") + pub[1:]
    leaf = TaprootLeaf(type="threshold", n=2, keys=[pub, twin])
    with pytest.raises(ValueError, match="distinct keys"):
        serialize_taproot_leaf(leaf)


def test_point_secret_hashes_as_raw_bytes():
    """JSON carries hex; the hash input is the raw 33 bytes (shared Y vector pin)."""
    from cashu.core.crypto.bls_dhke import hash_to_curve, secret_to_hash_input

    output = VECTORS["nut13_v3"]["outputs"][0]
    y = hash_to_curve(secret_to_hash_input(output["secret"]))
    assert y.format().hex() == output["Y"]
    assert secret_to_hash_input(output["secret"]) == bytes.fromhex(output["secret"])
    # v3 takes point secrets only: NUT-10 well-known and plain text secrets are
    # for legacy/v1/v2 keysets and must be refused here.
    for rejected in ("not-a-point", '["P2PK", {"data": "02" + "aa" * 32}]', "ab" * 33):
        with pytest.raises(TransactionError):
            secret_to_hash_input(rejected)

    from cashu.core.crypto.taproot import secret_transcript_bytes

    point = output["secret"]
    assert secret_transcript_bytes(point, VECTORS["nut13_v3"]["keyset_id"]) == bytes.fromhex(point)
    assert secret_transcript_bytes(point, "01" + "11" * 32) == point.encode()


def _tx_from_vector(tx: dict):
    from cashu.core.crypto.transcript import (
        TransactionShape,
        TranscriptBlindedOutput,
        TranscriptProofInput,
        TranscriptQuote,
    )

    return TransactionShape(
        proof_inputs=[
            TranscriptProofInput(
                amount=p["amount"],
                keyset_id=bytes.fromhex(p["keyset_id"]),
                secret=bytes.fromhex(p["secret"]),
                C=bytes.fromhex(p["C"]),
            )
            for p in tx.get("proof_inputs", [])
        ],
        mint_quote_inputs=[
            TranscriptQuote(amount=q["amount"], quote_id=q["quote_id"])
            for q in tx.get("mint_quote_inputs", [])
        ],
        blinded_outputs=[
            TranscriptBlindedOutput(
                amount=o["amount"],
                keyset_id=bytes.fromhex(o["keyset_id"]),
                B_=bytes.fromhex(o["B_"]),
            )
            for o in tx.get("blinded_outputs", [])
        ],
        melt_quote_outputs=[
            TranscriptQuote(amount=q["amount"], quote_id=q["quote_id"])
            for q in tx.get("melt_quote_outputs", [])
        ],
    )


def test_transaction_transcript_vectors():
    from cashu.core.crypto.transcript import (
        TRANSCRIPT_DOMAIN_TAG,
        build_transaction_transcript,
        transaction_digest,
    )

    tv = VECTORS["transcript"]
    assert tv["domain_tag"] == TRANSCRIPT_DOMAIN_TAG
    for name in ("swap", "mint", "melt", "melt_with_change"):
        example = tv[name]
        tx = _tx_from_vector(example["tx"])
        assert build_transaction_transcript(tx).hex() == example["transcript"]
        assert transaction_digest(tx).hex() == example["digest"]


def test_transcript_swap_signature_is_keypath_witness():
    tv = VECTORS["transcript"]["swap"]
    assert verify_schnorr_digest(
        bytes.fromhex(tv["signature"]),
        bytes.fromhex(tv["digest"]),
        bytes.fromhex(tv["tx"]["proof_inputs"][0]["secret"]),
    )


def test_transcript_rejects_empty_sections():
    from cashu.core.crypto.transcript import build_transaction_transcript

    tv = VECTORS["transcript"]["swap"]
    tx = _tx_from_vector(tv["tx"])
    with pytest.raises(ValueError, match="input"):
        build_transaction_transcript(
            type(tx)(blinded_outputs=tx.blinded_outputs)
        )
    with pytest.raises(ValueError, match="output"):
        build_transaction_transcript(type(tx)(proof_inputs=tx.proof_inputs))


def _swap_vector_proofs_and_outputs():
    from cashu.core.base import BlindedMessage, Proof

    tv = VECTORS["transcript"]["swap"]
    proofs = [
        Proof(
            amount=p["amount"],
            id=p["keyset_id"],
            secret=p["secret"],
            C=p["C"],
        )
        for p in tv["tx"]["proof_inputs"]
    ]
    outputs = [
        BlindedMessage(amount=o["amount"], id=o["keyset_id"], B_=o["B_"])
        for o in tv["tx"]["blinded_outputs"]
    ]
    return tv, proofs, outputs


def test_mint_verifies_taproot_transaction_witnesses():
    from cashu.core.errors import TransactionError
    from cashu.mint.verification import LedgerVerification

    verify = LedgerVerification._verify_taproot_transaction_witnesses

    tv, proofs, outputs = _swap_vector_proofs_and_outputs()

    # Absent witness rejects: inputs sign (spec 2.2.2).
    with pytest.raises(TransactionError, match="missing taproot transaction witness"):
        verify(proofs, outputs)

    # Valid witness passes.
    proofs[0].witness = json.dumps({"signatures": [tv["signature"]]})
    verify(proofs, outputs)

    # Tampered signature rejects.
    bad_sig = tv["signature"][:-2] + ("00" if tv["signature"][-2:] != "00" else "01")
    proofs[0].witness = json.dumps({"signatures": [bad_sig]})
    with pytest.raises(TransactionError, match="taproot transaction witness"):
        verify(proofs, outputs)

    # Malformed witness rejects.
    proofs[0].witness = "not-json"
    with pytest.raises(TransactionError, match="taproot transaction witness"):
        verify(proofs, outputs)

    # Witness over a different output set rejects (digest binds outputs).
    proofs[0].witness = json.dumps({"signatures": [tv["signature"]]})
    with pytest.raises(TransactionError, match="taproot transaction witness"):
        verify(proofs, outputs[:1])

    # Non-point secrets skip transaction-level verification entirely.
    proofs[0].secret = "not-a-point-secret"
    proofs[0].witness = "not-json"
    verify(proofs, outputs)


@pytest.mark.asyncio
async def test_wallet_attaches_taproot_witnesses():
    """The wallet re-derives k from the proof's derivation path and signs the transcript."""
    from cashu.core.base import BlindedMessage, Proof
    from cashu.wallet.wallet import Wallet

    tv = VECTORS["transcript"]["swap"]
    n13 = VECTORS["nut13_v3"]
    wallet = Wallet.__new__(Wallet)
    wallet.seed = n13["seed_utf8"].encode()
    proofs = [
        Proof(
            amount=8,
            id=n13["keyset_id"],
            secret=n13["outputs"][0]["secret"],
            C=tv["tx"]["proof_inputs"][0]["C"],
            derivation_path=f"HMAC-SHA256:{n13['keyset_id']}:0",
        )
    ]
    outputs = [
        BlindedMessage(amount=o["amount"], id=o["keyset_id"], B_=o["B_"])
        for o in tv["tx"]["blinded_outputs"]
    ]
    out = wallet._attach_taproot_witnesses(proofs, outputs)
    assert out[0].witness is not None
    signatures = json.loads(out[0].witness)["signatures"]
    assert verify_schnorr_digest(
        bytes.fromhex(signatures[0]),
        bytes.fromhex(tv["digest"]),
        bytes.fromhex(proofs[0].secret),
    )

    # A proof with a foreign derivation path stays unsigned.
    foreign = Proof(
        amount=8,
        id=n13["keyset_id"],
        secret=n13["outputs"][1]["secret"],
        C=tv["tx"]["proof_inputs"][0]["C"],
        derivation_path="m/129372'/0'/0'/0'",
    )
    out2 = wallet._attach_taproot_witnesses([foreign], outputs)
    assert out2[0].witness is None


def test_spend_info_roundtrips_through_tokenv4():
    from cashu.core.base import Proof, SpendInfo, TokenV4, TokenV4Proof, TokenV4Token

    n13 = VECTORS["nut13_v3"]
    proof = Proof(
        id=n13["keyset_id"],
        amount=8,
        secret=n13["outputs"][0]["secret"],
        C="84d1b7291ae5737f3c851aa33cafe0f7afeb5ccb4da086c482bb85b7525e61547f1b5a6d1a01b1fed1f960d1a9d03327",
        spend_info=SpendInfo(
            k=n13["outputs"][0]["secret_key"],
            tree=[VECTORS["example_6_1"]["leaf_after"]],
        ),
    )
    token = TokenV4(
        m="https://mint.test",
        u="sat",
        t=[
            TokenV4Token(
                i=bytes.fromhex(n13["keyset_id"]),
                p=[TokenV4Proof.from_proof(proof)],
            )
        ],
    )
    serialized = token.serialize()
    from cashu.core.base import TokenV4 as TV4

    decoded = TV4.deserialize(serialized)
    out = decoded.proofs[0]
    assert out.spend_info is not None
    assert out.spend_info.k == proof.spend_info.k
    assert out.spend_info.tree == proof.spend_info.tree
    assert out.spend_info.E is None


def test_leaf_forms_match_the_shared_vectors():
    """The leaf types and tree shapes section 6 never shows.

    Includes the odd-count fold: three leaves means leaf 2 is promoted
    unchanged, so its merkle path is a single sibling. A builder and a
    verifier that fold differently reject each other's valid proofs, so this
    has to agree across implementations.
    """
    from cashu.core.crypto.taproot import (
        TaprootLeaf,
        serialize_taproot_leaf,
        taproot_leaf_hash,
        taproot_merkle_path,
        taproot_merkle_root,
    )

    lf = VECTORS["leaf_forms"]
    v = VECTORS["example_6_1"]
    carol = bytes.fromhex(v["carol_pub"])
    alice = bytes.fromhex(v["alice_refund_pub"])

    assert serialize_taproot_leaf(TaprootLeaf(type="threshold", n=1, keys=[carol])).hex() == lf["threshold_1of1"]
    assert (
        serialize_taproot_leaf(TaprootLeaf(type="threshold", n=2, keys=[carol, alice])).hex()
        == lf["threshold_2of2"]
    )
    assert (
        serialize_taproot_leaf(
            TaprootLeaf(type="hashlock", n=1, keys=[carol], hash=bytes.fromhex(lf["hashlock_hash"]))
        ).hex()
        == lf["hashlock"]
    )

    hashes = [taproot_leaf_hash(bytes.fromhex(x)) for x in lf["three_leaf_tree"]]
    assert taproot_merkle_root(hashes).hex() == lf["three_leaf_root"]
    assert [h.hex() for h in taproot_merkle_path(hashes, 2)] == lf["three_leaf_path_index_2"]


def test_empty_tweak_matches_the_shared_vector():
    """Empty tweak (spec 3.8), the form an aggregated key MUST use.

    cashu-ts asserts the same vector. This side has the primitive but no
    receive cascade (that is a wallet-side check and this wallet does not run
    one), so what has to agree across implementations is the math.
    """
    from cashu.core.crypto.taproot import taproot_tweak, taproot_tweak_pubkey

    v = VECTORS["empty_tweak"]
    K = bytes.fromhex(v["internal_key"])
    assert taproot_tweak_pubkey(K).hex() == v["secret"]
    assert f"{taproot_tweak(K):064x}" == v["tweak"]
    # With a root it is a different tweak entirely, which is what stops an empty-tweak secret
    # being mistaken for a tree-committed one.
    assert taproot_tweak(K, bytes(32)) != taproot_tweak(K)


def test_shared_token_vectors_same_spend_info_from_either_encoder():
    """Cross-implementation pin, mirrored in cashu-ts against the same vector file.

    The two encoders differ on what NUT-00 leaves free (cashu-ts writes the
    short keyset id, this one the full id), so what must agree is the
    spend_info: both strings decode to the same fields on both sides.
    """
    from cashu.core.base import Proof, SpendInfo, TokenV4, TokenV4Proof, TokenV4Token

    v = VECTORS["tokens_v4"]
    full_id = VECTORS["nut13_v3"]["keyset_id"]
    for name, shape in v["shapes"].items():
        si = shape["spend_info"]
        proof = Proof(
            id=full_id,
            amount=v["amount"],
            secret=shape["secret"],
            C=v["C"],
            spend_info=SpendInfo(**si),
        )
        token = TokenV4(
            m=v["mint"],
            u=v["unit"],
            t=[
                TokenV4Token(
                    i=bytes.fromhex(full_id), p=[TokenV4Proof.from_proof(proof)]
                )
            ],
        )
        # Our own encoding is pinned, so a change to this encoder is visible, not silent.
        assert token.serialize() == shape["token_nutshell"], name
        for encoded in (shape["token_nutshell"], shape["token_cashu_ts"]):
            out = TokenV4.deserialize(encoded).proofs[0]
            assert out.secret == shape["secret"], name
            assert out.spend_info is not None, name
            assert out.spend_info.k == si.get("k"), name
            assert out.spend_info.E == si.get("E"), name
            assert out.spend_info.K == si.get("K"), name
            assert out.spend_info.u == si.get("u"), name
            assert out.spend_info.tree == si.get("tree"), name
        # The cashu-ts string carries the short keyset id; expanding it is the wallet's job
        # (`_expand_short_keyset_ids`), not the token codec's.
        assert TokenV4.deserialize(shape["token_cashu_ts"]).proofs[0].id == full_id[:16]
        assert TokenV4.deserialize(shape["token_nutshell"]).proofs[0].id == full_id


def test_resolve_v3_secret_key_prefers_spend_info():
    from cashu.core.base import Proof, SpendInfo
    from cashu.wallet.wallet import Wallet

    n13 = VECTORS["nut13_v3"]
    wallet = Wallet.__new__(Wallet)
    wallet.seed = b"a different seed entirely"
    proof = Proof(
        id=n13["keyset_id"],
        amount=8,
        secret=n13["outputs"][0]["secret"],
        C="84d1b7291ae5737f3c851aa33cafe0f7afeb5ccb4da086c482bb85b7525e61547f1b5a6d1a01b1fed1f960d1a9d03327",
        spend_info=SpendInfo(k=n13["outputs"][0]["secret_key"]),
    )
    assert wallet._resolve_v3_secret_key(proof) == bytes.fromhex(
        n13["outputs"][0]["secret_key"]
    )
    # Wrong bearer key and no derivation path -> None
    proof.spend_info = SpendInfo(k="11" * 32)
    assert wallet._resolve_v3_secret_key(proof) is None


def _sign_digest(privkey_int: int, digest: bytes) -> str:
    from cashu.core.crypto.secp import PrivateKey as SecpPrivateKey

    return SecpPrivateKey(privkey_int.to_bytes(32, "big")).sign_schnorr(
        digest, b"\x00" * 32
    ).hex()


def test_script_path_spend_after_leaf_vectors():
    """6.1: refund via the after leaf, evaluated with the vector witness."""
    from cashu.core.crypto.taproot import verify_script_path_spend

    v61 = VECTORS["example_6_1"]
    witness = {
        "leaf": v61["scriptpath_witness"]["leaf"],
        "control": v61["scriptpath_witness"]["control"],
        "signatures": v61["scriptpath_witness"]["signatures"],
    }
    digest = bytes.fromhex(v61["transcript_digest"])
    secret = bytes.fromhex(v61["secret"])
    # After the locktime: passes.
    verify_script_path_spend(secret, digest, witness, now=v61["refund_time"] + 1)
    # Before the locktime: fails closed.
    with pytest.raises(ValueError, match="locktime"):
        verify_script_path_spend(secret, digest, witness, now=v61["refund_time"] - 1)
    # Wrong merkle path: fails.
    bad = dict(witness, control={"K": witness["control"]["K"], "path": [v61["merkle_root"]]})
    with pytest.raises(ValueError, match="commitment"):
        verify_script_path_spend(secret, digest, bad, now=v61["refund_time"] + 1)
    # Wrong signature (kid key 3 signed a different digest): threshold fails.
    bad_sig = dict(witness, signatures=[VECTORS["example_6_2"]["melt_witness"]["signatures"][0]])
    with pytest.raises(ValueError, match="threshold"):
        verify_script_path_spend(secret, digest, bad_sig, now=v61["refund_time"] + 1)


def test_script_path_unknown_leaf_type_fails_closed():
    """6.2: the example melt_to leaf (0x04) is unknown and unsatisfiable."""
    from cashu.core.crypto.taproot import verify_script_path_spend

    v62 = VECTORS["example_6_2"]
    witness = {
        "leaf": v62["melt_witness"]["leaf"],
        "control": v62["melt_witness"]["control"],
        "signatures": v62["melt_witness"]["signatures"],
    }
    with pytest.raises(ValueError, match="Unknown leaf type"):
        verify_script_path_spend(
            bytes.fromhex(v62["secret"]),
            bytes.fromhex(v62["transcript_digest"]),
            witness,
        )


def test_script_path_threshold_and_hashlock():
    """2-of-3 threshold and hashlock leaves, built from well-known test keys."""
    import hashlib as _hashlib

    from cashu.core.crypto.secp import PrivateKey as SecpPrivateKey
    from cashu.core.crypto.taproot import (
        TaprootLeaf,
        serialize_taproot_leaf,
        taproot_leaf_hash,
        taproot_merkle_path,
        taproot_merkle_root,
        taproot_tweak_pubkey,
        verify_script_path_spend,
    )

    keys = {
        i: SecpPrivateKey(i.to_bytes(32, "big")).public_key.format() for i in (3, 4, 9)
    }
    internal_key = SecpPrivateKey((6).to_bytes(32, "big")).public_key.format()
    preimage = b"\x07" * 32
    leaf_threshold = serialize_taproot_leaf(
        TaprootLeaf(type="threshold", n=2, keys=[keys[3], keys[4], keys[9]])
    )
    leaf_hashlock = serialize_taproot_leaf(
        TaprootLeaf(
            type="hashlock",
            n=1,
            keys=[keys[3]],
            hash=_hashlib.sha256(preimage).digest(),
        )
    )
    hashes = [taproot_leaf_hash(leaf_threshold), taproot_leaf_hash(leaf_hashlock)]
    root = taproot_merkle_root(hashes)
    secret = taproot_tweak_pubkey(internal_key, root)
    digest = _hashlib.sha256(b"threshold test transcript").digest()

    # 2-of-3 threshold satisfied by keys 3 and 9.
    verify_script_path_spend(
        secret,
        digest,
        {
            "leaf": leaf_threshold.hex(),
            "control": {
                "K": internal_key.hex(),
                "path": [h.hex() for h in taproot_merkle_path(hashes, 0)],
            },
            "signatures": [_sign_digest(3, digest), _sign_digest(9, digest)],
        },
    )
    # One signature is not enough.
    with pytest.raises(ValueError, match="threshold"):
        verify_script_path_spend(
            secret,
            digest,
            {
                "leaf": leaf_threshold.hex(),
                "control": {
                    "K": internal_key.hex(),
                    "path": [h.hex() for h in taproot_merkle_path(hashes, 0)],
                },
                "signatures": [_sign_digest(3, digest)],
            },
        )
    # Duplicated signature cannot double-count.
    with pytest.raises(ValueError, match="threshold"):
        verify_script_path_spend(
            secret,
            digest,
            {
                "leaf": leaf_threshold.hex(),
                "control": {
                    "K": internal_key.hex(),
                    "path": [h.hex() for h in taproot_merkle_path(hashes, 0)],
                },
                "signatures": [_sign_digest(3, digest), _sign_digest(3, digest)],
            },
        )

    # Hashlock: preimage + signature passes; wrong preimage fails; missing preimage fails.
    hashlock_witness = {
        "leaf": leaf_hashlock.hex(),
        "control": {
            "K": internal_key.hex(),
            "path": [h.hex() for h in taproot_merkle_path(hashes, 1)],
        },
        "signatures": [_sign_digest(3, digest)],
        "preimage": preimage.hex(),
    }
    verify_script_path_spend(secret, digest, hashlock_witness)
    with pytest.raises(ValueError, match="preimage"):
        verify_script_path_spend(
            secret, digest, dict(hashlock_witness, preimage="00" * 32)
        )
    with pytest.raises(ValueError, match="preimage"):
        verify_script_path_spend(
            secret,
            digest,
            {k: v for k, v in hashlock_witness.items() if k != "preimage"},
        )


def test_mint_accepts_script_path_witness_on_swap():
    """The mint routes leaf-bearing witnesses through script-path verification."""
    from cashu.core.errors import TransactionError
    from cashu.mint.verification import LedgerVerification

    verify = LedgerVerification._verify_taproot_transaction_witnesses
    tv, proofs, outputs = _swap_vector_proofs_and_outputs()
    v61 = VECTORS["example_6_1"]

    # Replace the input with the 6.1 tweaked secret, spent via the after leaf,
    # signed by the refund key (4) over this swap's real transcript digest.
    proofs[0].secret = v61["secret"]
    from cashu.core.crypto.transcript import (
        TransactionShape,
        TranscriptBlindedOutput,
        TranscriptProofInput,
        transaction_digest,
    )

    digest = transaction_digest(
        TransactionShape(
            proof_inputs=[
                TranscriptProofInput(
                    amount=p.amount,
                    keyset_id=bytes.fromhex(p.id),
                    secret=bytes.fromhex(p.secret),
                    C=bytes.fromhex(p.C),
                )
                for p in proofs
            ],
            blinded_outputs=[
                TranscriptBlindedOutput(
                    amount=o.amount, keyset_id=bytes.fromhex(o.id), B_=bytes.fromhex(o.B_)
                )
                for o in outputs
            ],
        )
    )
    proofs[0].witness = json.dumps(
        {
            "leaf": v61["scriptpath_witness"]["leaf"],
            "control": v61["scriptpath_witness"]["control"],
            "signatures": [_sign_digest(4, digest)],
        }
    )
    verify(proofs, outputs)  # refund time (2025) has passed in real time

    # Key-path signature by a leaf key does not satisfy the key path.
    proofs[0].witness = json.dumps({"signatures": [_sign_digest(4, digest)]})
    with pytest.raises(TransactionError, match="invalid taproot transaction witness"):
        verify(proofs, outputs)


def test_leaf_time_is_bounded():
    """Bounded so both implementations read the same leaf: unbounded here means
    a leaf a mint commits and spends that a wallet cannot parse, which strands
    the proof with its holder."""
    from cashu.core.crypto.taproot import TAPROOT_MAX_LEAF_TIME

    huge = (
        b"\x00\x02"
        + tlv_record(0x02, b"\x01")
        + tlv_record(0x04, bytes.fromhex(V61["carol_pub"]))
        + tlv_record(0x06, bytes.fromhex("0fffffffffffffff"))
    )
    with pytest.raises(ValueError, match="time out of range"):
        parse_taproot_leaf(huge)
    with pytest.raises(ValueError, match="time out of range"):
        serialize_taproot_leaf(
            TaprootLeaf(
                type="after",
                n=1,
                keys=[bytes.fromhex(V61["carol_pub"])],
                time=TAPROOT_MAX_LEAF_TIME + 1,
            )
        )


def test_tree_depth_cap_applies_to_the_tree():
    """Past 2^8 leaves every merkle path is longer than a verifier accepts, so
    the fallbacks a holder was told they had do not exist (spec 2.6)."""
    from cashu.core.crypto.taproot import TAPROOT_MAX_TREE_DEPTH

    hashes = [
        taproot_leaf_hash(i.to_bytes(32, "big"))
        for i in range(2**TAPROOT_MAX_TREE_DEPTH)
    ]
    taproot_merkle_root(hashes)
    with pytest.raises(ValueError, match="depth"):
        taproot_merkle_root(hashes + [hashes[0]])


def test_keyset_id_transcript_bytes_falls_back_to_utf8():
    """Mixed transactions are normative (spec 5) and a pre-v1 keyset id is
    base64, so hex-decoding it unconditionally makes such a transaction
    impossible to sign or verify rather than merely unusual."""
    from cashu.core.crypto.taproot import keyset_id_transcript_bytes

    assert keyset_id_transcript_bytes("0088553333aabbcc") == bytes.fromhex(
        "0088553333aabbcc"
    )
    assert keyset_id_transcript_bytes("I2yN+iRYfkzT") == b"I2yN+iRYfkzT"
    with pytest.raises(ValueError, match="non-empty"):
        keyset_id_transcript_bytes("")


def test_v3_witness_does_not_travel_in_a_token():
    """A v3 witness signs one transaction's digest, so a token cannot carry a
    usable one; keeping it would sit where the new owner's signature must go."""
    from cashu.core.base import Proof, TokenV4, TokenV4Proof, TokenV4Token

    v3_keyset = "029e18e63831fcf4764b1f1b574a2b415b07e6f86aa263b8948aae772e92fd3f70"
    proof = Proof(
        id=v3_keyset,
        amount=8,
        secret=V61["carol_pub"],
        C="aa" * 48,
        witness='{"signatures":["' + "00" * 64 + '"]}',
    )
    assert TokenV4Proof.from_proof(proof).w is None

    carried = TokenV4Proof.from_proof(proof)
    carried.w = '{"signatures":["' + "00" * 64 + '"]}'  # as a hostile sender would send it
    token = TokenV4(
        m="https://m.example",
        u="sat",
        t=[TokenV4Token(i=bytes.fromhex(v3_keyset), p=[carried])],
    )
    assert token.proofs[0].witness is None
