"""Benchmark for LedgerVerification._verify_nutroot_transaction_witnesses.

Times one call per case (witness JSON parsing, transcript digest, and the
schnorr/merkle/script checks are all inside the timed region). All inputs
are built once up front and sanity-verified before timing.

Run: .venv/bin/python scripts/bench_nutroot_witness.py
"""

import cProfile
import hashlib
import json
import platform
import pstats
import statistics
import time
from typing import Dict, List, Optional, Tuple

from cashu.core.base import BlindedMessage, Proof
from cashu.core.crypto.nutroot import (
    NutrootLeaf,
    keyset_id_transcript_bytes,
    nutroot_leaf_hash,
    nutroot_merkle_path,
    nutroot_merkle_root,
    nutroot_tweak_pubkey,
    nutroot_tweak_seckey,
    secret_transcript_bytes,
    serialize_nutroot_leaf,
)
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.crypto.transcript import (
    TransactionShape,
    TranscriptBlindedOutput,
    TranscriptProofInput,
    transaction_digest,
)
from cashu.core.p2bk import blind_pubkeys, derive_blinded_private_key
from cashu.mint.verification import LedgerVerification

KEYSET_ID = "02" + "00" * 7
PAST_TIME = 1_700_000_000  # 2023-11-14, safely in the past for `after` leaves

VERIFY = LedgerVerification._verify_nutroot_transaction_witnesses


def _key(i: int) -> PrivateKey:
    return PrivateKey(i.to_bytes(32, "big"))


def _pub(i: int) -> str:
    pub = _key(i).public_key
    if pub is None:
        raise RuntimeError("key derivation failed")
    return pub.format().hex()


def _sign(privkey: PrivateKey, digest: bytes) -> str:
    return privkey.sign_schnorr(digest, b"\x00" * 32).hex()


def _fake_bytes(seed: str, n: int) -> str:
    """Deterministic realistic-looking hex (e.g. a 48-byte BLS point)."""
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return out[:n].hex()


def _tx_digest(proofs: List[Proof], outputs: List[BlindedMessage]) -> bytes:
    """Replicates the digest computation inside the function under test."""
    return transaction_digest(
        TransactionShape(
            proof_inputs=[
                TranscriptProofInput(
                    amount=p.amount,
                    keyset_id=keyset_id_transcript_bytes(p.id),
                    secret=secret_transcript_bytes(p.secret, p.id),
                    C=bytes.fromhex(p.C),
                )
                for p in proofs
            ],
            blinded_outputs=[
                TranscriptBlindedOutput(
                    amount=o.amount,
                    keyset_id=keyset_id_transcript_bytes(o.id),
                    B_=bytes.fromhex(o.B_),
                )
                for o in outputs
            ],
        )
    )


def _make_tx(
    secrets: List[str], n_outputs: int, tag: str
) -> Tuple[List[Proof], List[BlindedMessage]]:
    proofs = [
        Proof(
            amount=8,
            id=KEYSET_ID,
            secret=secret,
            C=_fake_bytes(f"{tag}:C:{i}", 48),
        )
        for i, secret in enumerate(secrets)
    ]
    outputs = [
        BlindedMessage(
            amount=8, id=KEYSET_ID, B_=_fake_bytes(f"{tag}:B:{i}", 48)
        )
        for i in range(n_outputs)
    ]
    return proofs, outputs


def _keypath_witness(privkey: PrivateKey, digest: bytes) -> str:
    return json.dumps({"signatures": [_sign(privkey, digest)]})


def _script_tree(
    leaves: List[bytes], internal_i: int
) -> Tuple[str, List[bytes], str]:
    """Commit leaves under an internal key; return (secret, hashes, root hex)."""
    hashes = [nutroot_leaf_hash(leaf) for leaf in leaves]
    root = nutroot_merkle_root(hashes)
    internal_pub = _key(internal_i).public_key
    if internal_pub is None:
        raise RuntimeError("key derivation failed")
    secret = nutroot_tweak_pubkey(internal_pub, root).format().hex()
    return secret, hashes, root.hex()


def _script_witness(
    leaf: bytes,
    hashes: List[bytes],
    index: int,
    internal_i: int,
    sigs: List[str],
    preimage: Optional[bytes] = None,
) -> str:
    control = {
        "K": _pub(internal_i),
        "path": [h.hex() for h in nutroot_merkle_path(hashes, index)],
    }
    witness: Dict[str, object] = {
        "leaf": leaf.hex(),
        "control": control,
        "signatures": sigs,
    }
    if preimage is not None:
        witness["preimage"] = preimage.hex()
    return json.dumps(witness)


def _threshold_leaf(n: int, key_ints: List[int]) -> bytes:
    return serialize_nutroot_leaf(
        NutrootLeaf(type="threshold", n=n, keys=[_key(i).public_key for i in key_ints])  # type: ignore[list-item]
    )


def _after_leaf(key_i: int, when: int = PAST_TIME) -> bytes:
    return serialize_nutroot_leaf(
        NutrootLeaf(type="after", n=1, keys=[_key(key_i).public_key], time=when)  # type: ignore[list-item]
    )


def _hashlock_leaf(key_i: int, preimage: bytes) -> bytes:
    return serialize_nutroot_leaf(
        NutrootLeaf(
            type="hashlock",
            n=1,
            keys=[_key(key_i).public_key],  # type: ignore[list-item]
            hash=hashlib.sha256(preimage).digest(),
        )
    )


def build_cases() -> Dict[str, Tuple[List[Proof], List[BlindedMessage]]]:
    cases: Dict[str, Tuple[List[Proof], List[BlindedMessage]]] = {}

    # 1. keypath_bare: bare internal key, no tree, one signature.
    secret = _pub(101)
    proofs, outputs = _make_tx([secret], 1, "keypath_bare")
    digest = _tx_digest(proofs, outputs)
    proofs[0].witness = _keypath_witness(_key(101), digest)
    cases["keypath_bare"] = (proofs, outputs)

    # 2. keypath_tweaked: 3-leaf tree committed, spent via key path.
    leaves = [
        _threshold_leaf(1, [201]),
        _after_leaf(202),
        _hashlock_leaf(203, b"\x11" * 32),
    ]
    hashes = [nutroot_leaf_hash(leaf) for leaf in leaves]
    root = nutroot_merkle_root(hashes)
    internal = _key(200)
    internal_pub = internal.public_key
    if internal_pub is None:
        raise RuntimeError("key derivation failed")
    secret = nutroot_tweak_pubkey(internal_pub, root).format().hex()
    proofs, outputs = _make_tx([secret], 1, "keypath_tweaked")
    digest = _tx_digest(proofs, outputs)
    tweaked_seckey = nutroot_tweak_seckey(internal, root)
    proofs[0].witness = _keypath_witness(tweaked_seckey, digest)
    cases["keypath_tweaked"] = (proofs, outputs)

    # 3. script_threshold_1of1: single-leaf tree, empty path.
    leaf = _threshold_leaf(1, [301])
    secret, hashes, _ = _script_tree([leaf], 300)
    proofs, outputs = _make_tx([secret], 1, "script_threshold_1of1")
    digest = _tx_digest(proofs, outputs)
    proofs[0].witness = _script_witness(leaf, hashes, 0, 300, [_sign(_key(301), digest)])
    cases["script_threshold_1of1"] = (proofs, outputs)

    # 4. script_threshold_2of3.
    leaf = _threshold_leaf(2, [401, 402, 403])
    secret, hashes, _ = _script_tree([leaf], 400)
    proofs, outputs = _make_tx([secret], 1, "script_threshold_2of3")
    digest = _tx_digest(proofs, outputs)
    sigs = [_sign(_key(401), digest), _sign(_key(403), digest)]
    proofs[0].witness = _script_witness(leaf, hashes, 0, 400, sigs)
    cases["script_threshold_2of3"] = (proofs, outputs)

    # 5. script_after_refund: after leaf, locktime in the past.
    leaf = _after_leaf(501)
    secret, hashes, _ = _script_tree([leaf], 500)
    proofs, outputs = _make_tx([secret], 1, "script_after_refund")
    digest = _tx_digest(proofs, outputs)
    proofs[0].witness = _script_witness(leaf, hashes, 0, 500, [_sign(_key(501), digest)])
    cases["script_after_refund"] = (proofs, outputs)

    # 6. script_hashlock: preimage + one signature.
    preimage = b"\x07" * 32
    leaf = _hashlock_leaf(601, preimage)
    secret, hashes, _ = _script_tree([leaf], 600)
    proofs, outputs = _make_tx([secret], 1, "script_hashlock")
    digest = _tx_digest(proofs, outputs)
    proofs[0].witness = _script_witness(
        leaf, hashes, 0, 600, [_sign(_key(601), digest)], preimage=preimage
    )
    cases["script_hashlock"] = (proofs, outputs)

    # 7. script_multileaf_8: 8 mixed leaves, spend a threshold 1-of-1, path 3.
    preimages = [bytes([i]) * 32 for i in range(8)]
    leaves = [
        _threshold_leaf(1, [700]),
        _after_leaf(701),
        _hashlock_leaf(702, preimages[2]),
        _threshold_leaf(1, [703]),  # spent leaf, index 3
        _threshold_leaf(2, [704, 705]),
        _after_leaf(706),
        _hashlock_leaf(707, preimages[6]),
        _threshold_leaf(1, [708, 709]),
    ]
    secret, hashes, _ = _script_tree(leaves, 710)
    proofs, outputs = _make_tx([secret], 1, "script_multileaf_8")
    digest = _tx_digest(proofs, outputs)
    proofs[0].witness = _script_witness(
        leaves[3], hashes, 3, 710, [_sign(_key(703), digest)]
    )
    cases["script_multileaf_8"] = (proofs, outputs)

    # 8. script_multileaf_64: 64 leaves, path length 6.
    leaves = [_threshold_leaf(1, [800 + i]) for i in range(64)]
    secret, hashes, _ = _script_tree(leaves, 900)
    proofs, outputs = _make_tx([secret], 1, "script_multileaf_64")
    digest = _tx_digest(proofs, outputs)
    proofs[0].witness = _script_witness(
        leaves[17], hashes, 17, 900, [_sign(_key(817), digest)]
    )
    cases["script_multileaf_64"] = (proofs, outputs)

    # 9. script_p2bk_blinded: NUT-28 slot-blinded leaf key.
    receiver = _key(1001)
    receiver_pub = receiver.public_key
    if receiver_pub is None:
        raise RuntimeError("key derivation failed")
    blinded_hex, _, _, ephemeral_hex = blind_pubkeys(
        receiver_pub.format().hex(), [], []
    )
    blinded_seckey = derive_blinded_private_key(receiver, ephemeral_hex, blinded_hex, 0)
    if blinded_seckey is None:
        raise RuntimeError("p2bk: slot 0 did not resolve to the receiver key")
    leaf = serialize_nutroot_leaf(
        NutrootLeaf(type="threshold", n=1, keys=[PublicKey(bytes.fromhex(blinded_hex))])
    )
    secret, hashes, _ = _script_tree([leaf], 1000)
    proofs, outputs = _make_tx([secret], 1, "script_p2bk_blinded")
    digest = _tx_digest(proofs, outputs)
    proofs[0].witness = _script_witness(
        leaf, hashes, 0, 1000, [_sign(blinded_seckey, digest)]
    )
    cases["script_p2bk_blinded"] = (proofs, outputs)

    # 10. multi_input_4_keypath: 4 bare key-path inputs, 4 outputs.
    secrets = [_pub(1100 + i) for i in range(4)]
    proofs, outputs = _make_tx(secrets, 4, "multi_input_4_keypath")
    digest = _tx_digest(proofs, outputs)
    for i, proof in enumerate(proofs):
        proof.witness = _keypath_witness(_key(1100 + i), digest)
    cases["multi_input_4_keypath"] = (proofs, outputs)

    # 11. multi_input_4_script: 4 script-path 1-of-1 inputs, 4 outputs.
    secrets = []
    trees = []
    for i in range(4):
        leaf = _threshold_leaf(1, [1201 + i * 10])
        secret, hashes, _ = _script_tree([leaf], 1200 + i * 10)
        secrets.append(secret)
        trees.append((leaf, hashes))
    proofs, outputs = _make_tx(secrets, 4, "multi_input_4_script")
    digest = _tx_digest(proofs, outputs)
    for i, proof in enumerate(proofs):
        leaf, hashes = trees[i]
        proof.witness = _script_witness(
            leaf, hashes, 0, 1200 + i * 10, [_sign(_key(1201 + i * 10), digest)]
        )
    cases["multi_input_4_script"] = (proofs, outputs)

    return cases


def _time_case(
    proofs: List[Proof], outputs: List[BlindedMessage]
) -> Tuple[float, float, float, int]:
    """Return (mean, median, min) per-call in microseconds and iteration count."""
    for _ in range(50):  # warmup
        VERIFY(proofs, outputs)
    probe = 200
    start = time.perf_counter_ns()
    for _ in range(probe):
        VERIFY(proofs, outputs)
    per_call_s = (time.perf_counter_ns() - start) / probe / 1e9
    n = min(200_000, max(2000, int(0.3 / per_call_s)))
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        VERIFY(proofs, outputs)
        samples.append(time.perf_counter_ns() - t0)
    us = [s / 1000 for s in samples]
    return statistics.mean(us), statistics.median(us), min(us), n


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def _profile_case(name: str, proofs: List[Proof], outputs: List[BlindedMessage]) -> None:
    profiler = cProfile.Profile()
    profiler.enable()
    for _ in range(500):
        VERIFY(proofs, outputs)
    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats("cumulative")
    print(f"\n--- cProfile: {name} (500 calls) ---")
    stats.print_stats(15)


def main() -> None:
    print(f"python: {platform.python_version()}")
    print(f"cpu: {_cpu_model()}")

    cases = build_cases()

    # Sanity: every case must verify once before timing.
    for name, (proofs, outputs) in cases.items():
        try:
            VERIFY(proofs, outputs)
        except Exception as exc:
            print(f"SANITY FAILED for {name}: {exc}")
            raise
    print("all cases sanity-verified OK\n")

    header = f"{'case':<24} {'mean_us':>10} {'median_us':>10} {'min_us':>10} {'N':>8}"
    print(header)
    print("-" * len(header))
    for name, (proofs, outputs) in cases.items():
        mean, median, minimum, n = _time_case(proofs, outputs)
        print(f"{name:<24} {mean:>10.2f} {median:>10.2f} {minimum:>10.2f} {n:>8}")

    _profile_case("keypath_bare", *cases["keypath_bare"])
    _profile_case("script_threshold_2of3", *cases["script_threshold_2of3"])


if __name__ == "__main__":
    main()
