"""Nutroot output construction, ownership checks, and witness assembly."""

import hashlib
import json
import time
from dataclasses import dataclass, replace
from typing import Callable, Collection, Mapping, Optional, Sequence

from .base import NutrootOption, Proof, SpendInfo
from .crypto.nutroot import (
    NUTROOT_NUMS,
    SECP256K1_N,
    NutrootLeaf,
    NutrootWitness,
    nutroot_leaf_hash,
    nutroot_merkle_path,
    nutroot_merkle_root,
    nutroot_tweak_pubkey,
    nutroot_tweak_seckey,
    parse_nutroot_leaf,
    serialize_nutroot_leaf,
    verify_script_path_spend,
)
from .crypto.secp import PrivateKey, PublicKey
from .p2bk import derive_blinding_scalar, ecdh_shared_secret


def nums_internal_key(offset: PrivateKey) -> PublicKey:
    return PublicKey.combine_keys([NUTROOT_NUMS, offset.public_key])


def _blind_key(key: PublicKey, ephemeral: PrivateKey, slot: int) -> PublicKey:
    scalar = derive_blinding_scalar(ecdh_shared_secret(key, ephemeral), slot)
    return key.add(scalar.to_bytes(32, "big"))


def _key_variants(keys: Sequence[PrivateKey]) -> list[PrivateKey]:
    variants: dict[bytes, PrivateKey] = {}
    for key in keys:
        variants[key.public_key.format()] = key
        negated = PrivateKey(
            (SECP256K1_N - int.from_bytes(key.secret, "big")).to_bytes(32, "big")
        )
        variants[negated.public_key.format()] = negated
    return list(variants.values())


def create_nutroot_output(
    internal_key: PublicKey,
    tree: Sequence[bytes] = (),
    *,
    bearer_key: Optional[PrivateKey] = None,
    ephemeral_key: Optional[PrivateKey] = None,
    blind_keys: Collection[bytes] = (),
    nums_offset: Optional[PrivateKey] = None,
    aggregated: bool = False,
) -> tuple[str, SpendInfo]:
    """Construct a bearer or receiver-keyed output, with its complete spend info.

    The caller allocates a fresh internal key or NUMS offset and, for a
    receiver-keyed output, a fresh ephemeral key for each output.
    """
    if bearer_key is not None and ephemeral_key is not None:
        raise ValueError("A bearer output cannot carry an ephemeral")
    if aggregated and bearer_key is not None:
        raise ValueError("An aggregated internal key does not carry a bearer scalar")
    if (
        bearer_key is not None
        and bearer_key.public_key.format() != internal_key.format()
    ):
        raise ValueError("Bearer key does not match the internal key")
    leaves = [parse_nutroot_leaf(leaf) for leaf in tree]
    leaf_count = sum(len(leaf.keys) for leaf in leaves)
    if leaf_count > 255:
        raise ValueError("Nutroot leaf keys exceed the slot map")
    listed = {key.format() for leaf in leaves for key in leaf.keys}
    if not set(blind_keys) <= listed:
        raise ValueError("Blind-me key is absent from the tree")
    if blind_keys and ephemeral_key is None:
        raise ValueError("Blinded leaf keys need an ephemeral")
    if nums_offset is not None:
        if not leaves or bearer_key is not None:
            raise ValueError("NUMS output needs leaves and has no bearer key")
        internal_key = nums_internal_key(nums_offset)
        if ephemeral_key is not None and not blind_keys:
            raise ValueError("NUMS ephemeral must blind at least one leaf key")
    elif ephemeral_key is not None:
        internal_key = _blind_key(internal_key, ephemeral_key, 0)

    slot = 1
    transmitted: list[bytes] = []
    for original, leaf in zip(tree, leaves):
        keys = []
        for key in leaf.keys:
            if key.format() in blind_keys:
                if ephemeral_key is None:
                    raise ValueError("Missing blinding ephemeral")
                key = _blind_key(key, ephemeral_key, slot)
            keys.append(key)
            slot += 1
        serialized = serialize_nutroot_leaf(replace(leaf, keys=keys))
        if not blind_keys and serialized != original:
            raise ValueError("Condition leaf is not canonical")
        transmitted.append(serialized)
    root = (
        nutroot_merkle_root([nutroot_leaf_hash(leaf) for leaf in transmitted])
        if transmitted
        else None
    )
    secret = (
        nutroot_tweak_pubkey(internal_key, root)
        if root is not None or aggregated
        else internal_key
    )
    return secret.format().hex(), SpendInfo(
        k=bearer_key.secret.hex() if bearer_key else None,
        E=ephemeral_key.public_key.format().hex() if ephemeral_key else None,
        K=internal_key.format().hex(),
        tree=[leaf.hex() for leaf in transmitted] if transmitted else None,
        u=nums_offset.secret.hex() if nums_offset else None,
    )


def create_requested_nutroot_output(
    request: NutrootOption,
    *,
    ephemeral_key: Optional[PrivateKey] = None,
    nums_offset: Optional[PrivateKey] = None,
) -> tuple[str, SpendInfo]:
    """Reproduce a NUT-18 tree, changing only its tagged key occurrences."""
    internal = PublicKey(bytes.fromhex(request.k))
    is_nums = internal.format() == NUTROOT_NUMS.format()
    if is_nums:
        nums_offset = nums_offset or PrivateKey()
    elif nums_offset is not None:
        raise ValueError("NUMS offset on a non-NUMS request")
    if not is_nums or request.b:
        ephemeral_key = ephemeral_key or PrivateKey()
    elif ephemeral_key is not None:
        raise ValueError("Request blinds no keys")
    return create_nutroot_output(
        internal,
        [bytes.fromhex(leaf) for leaf in request.l or []],
        ephemeral_key=ephemeral_key,
        blind_keys=[bytes.fromhex(key) for key in request.b or []],
        nums_offset=nums_offset,
    )


@dataclass
class NutrootOwnership:
    internal_key: PublicKey
    leaves: list[NutrootLeaf]
    key_path: Optional[PrivateKey]
    leaf_keys: dict[bytes, PrivateKey]
    receiver_key: Optional[bytes]
    static_keys: set[bytes]
    blinded_leaf_keys: dict[bytes, set[bytes]]


def nutroot_spendable(
    ownership: NutrootOwnership,
    preimages: Mapping[bytes, bytes],
    *,
    now: Optional[float] = None,
    allow_pending_conditions: bool = False,
) -> bool:
    if ownership.key_path is not None:
        return True
    for leaf in ownership.leaves:
        if leaf.type == "commit":
            continue
        if sum(key.format() in ownership.leaf_keys for key in leaf.keys) < leaf.n:
            continue
        if not allow_pending_conditions:
            if leaf.type == "after" and (
                leaf.time is None
                or (now if now is not None else time.time()) < leaf.time
            ):
                continue
            if leaf.type == "hashlock":
                preimage = preimages.get(leaf.hash or b"")
                if (
                    preimage is None
                    or len(preimage) != 32
                    or hashlib.sha256(preimage).digest() != leaf.hash
                ):
                    continue
        return True
    return False


def _matches_secret(internal: PublicKey, root: Optional[bytes], secret: bytes) -> bool:
    if root is not None:
        return nutroot_tweak_pubkey(internal, root).format() == secret
    return (
        internal.format() == secret or nutroot_tweak_pubkey(internal).format() == secret
    )


def resolve_nutroot_ownership(
    proof: Proof,
    private_keys: Sequence[PrivateKey] = (),
    *,
    seed_key: Optional[PrivateKey] = None,
    leaf_keys: Sequence[PrivateKey] = (),
) -> NutrootOwnership:
    """Reconstruct the exact compressed secret and discover the keys held.

    A disclosed tree's order is irrelevant to both reconstruction and recovery
    of leaf keys; receiver-keyed candidates are matched by value.
    """
    secret = bytes.fromhex(proof.secret)
    PublicKey(secret)
    info = proof.spend_info
    raw_tree = [bytes.fromhex(leaf) for leaf in (info.tree if info else None) or []]
    leaves = [parse_nutroot_leaf(leaf) for leaf in raw_tree]
    root = (
        nutroot_merkle_root([nutroot_leaf_hash(leaf) for leaf in raw_tree])
        if raw_tree
        else None
    )
    variants = _key_variants([*private_keys, *([seed_key] if seed_key else [])])
    internal_private: Optional[PrivateKey] = None
    internal: Optional[PublicKey] = None
    receiver_key: Optional[bytes] = None
    if info is not None and info.k is not None:
        internal_private = PrivateKey(bytes.fromhex(info.k))
        internal = internal_private.public_key
    elif info is not None and info.E is not None and info.u is None:
        ephemeral = PublicKey(bytes.fromhex(info.E))
        for key in variants:
            tweak = derive_blinding_scalar(ecdh_shared_secret(ephemeral, key), 0)
            candidate = key.add(tweak.to_bytes(32, "big"))
            if _matches_secret(candidate.public_key, root, secret):
                internal_private = candidate
                internal = candidate.public_key
                receiver_key = key.public_key.format()
                break
    if internal is None and info is not None and info.K is not None:
        internal = PublicKey(bytes.fromhex(info.K))
    if internal is None:
        for key in variants:
            if _matches_secret(key.public_key, root, secret):
                internal_private, internal = key, key.public_key
                break
    if internal is None:
        raise ValueError("Spend info has no usable internal key source")
    if (
        info is not None
        and info.K is not None
        and internal.format().hex() != info.K.lower()
    ):
        raise ValueError("Disclosed internal key differs from the derived key")
    if not _matches_secret(internal, root, secret):
        raise ValueError("Spend info does not reconstruct the secret")
    if info is not None and info.u is not None:
        if (
            nums_internal_key(PrivateKey(bytes.fromhex(info.u))).format()
            != internal.format()
        ):
            raise ValueError("Invalid NUMS offset")
    elif internal_private is None:
        internal_private = next(
            (key for key in variants if key.public_key.format() == internal.format()),
            None,
        )
    key_path = internal_private
    if key_path is not None and internal.format() != secret:
        key_path = nutroot_tweak_seckey(key_path, root)
    listed = {key.format() for leaf in leaves for key in leaf.keys}
    slots = sum(len(leaf.keys) for leaf in leaves)
    if slots > 255:
        raise ValueError("Nutroot leaf keys exceed the slot map")
    held = {
        key.public_key.format(): key for key in _key_variants([*variants, *leaf_keys])
    }
    blinded_leaf_keys: dict[bytes, set[bytes]] = {}
    if info is not None and info.E is not None:
        ephemeral = PublicKey(bytes.fromhex(info.E))
        for key in variants:
            blinded_leaf_keys[key.public_key.format()] = set()
            shared = ecdh_shared_secret(ephemeral, key)
            for slot in range(1, slots + 1):
                candidate = key.add(
                    derive_blinding_scalar(shared, slot).to_bytes(32, "big")
                )
                if candidate.public_key.format() in listed:
                    held[candidate.public_key.format()] = candidate
                    blinded_leaf_keys[key.public_key.format()].add(
                        candidate.public_key.format()
                    )
    return NutrootOwnership(
        internal,
        leaves,
        key_path,
        {key: held[key] for key in listed if key in held},
        receiver_key,
        {key.public_key.format() for key in variants},
        blinded_leaf_keys,
    )


def validate_requested_nutroot_output(
    proof: Proof, request: NutrootOption, ownership: NutrootOwnership
) -> None:
    """Verify the request's key source and exact multiset of requested leaves."""
    info = proof.spend_info
    if info is None or info.k is not None:
        raise ValueError("Nutroot requests require receiver-keyed spend info")
    is_nums = bytes.fromhex(request.k) == NUTROOT_NUMS.format()
    if (info.E is not None) != (not is_nums or bool(request.b)):
        raise ValueError("Ephemeral presence differs from the payment request")
    if is_nums:
        if info.u is None:
            raise ValueError("NUMS request needs its offset")
    elif ownership.receiver_key != bytes.fromhex(request.k):
        raise ValueError("Receiver does not own the requested internal key")
    requested = [bytes.fromhex(leaf) for leaf in request.l or []]
    received = [bytes.fromhex(leaf) for leaf in info.tree or []]
    blind = {bytes.fromhex(key) for key in request.b or []}

    # Pair leaves by their complete non-key fields and all verbatim keys. The
    # remaining substituted keys are checked by their owners during recovery.
    def matches(wanted: bytes, actual: bytes) -> bool:
        a, b = parse_nutroot_leaf(wanted), parse_nutroot_leaf(actual)
        if len(a.keys) != len(b.keys):
            return False
        for left, right in zip(a.keys, b.keys):
            if left.format() not in blind and left.format() != right.format():
                return False
            if left.format() in blind and left.format() in ownership.static_keys:
                if right.format() not in ownership.blinded_leaf_keys.get(
                    left.format(), set()
                ):
                    return False
        return serialize_nutroot_leaf(replace(b, keys=a.keys)) == wanted

    if len(requested) != len(received):
        raise ValueError("Payment tree differs from the request")

    # Match the multiset without depending on leaf order or repeatedly parsing
    # the same pair when several requested leaves are identical.
    edges = [
        [index for index, actual in enumerate(received) if matches(wanted, actual)]
        for wanted in requested
    ]
    assigned: dict[int, int] = {}

    def assign(wanted: int, visited: set[int]) -> bool:
        for actual in edges[wanted]:
            if actual in visited:
                continue
            visited.add(actual)
            if actual not in assigned or assign(assigned[actual], visited):
                assigned[actual] = wanted
                return True
        return False

    if not all(assign(index, set()) for index in range(len(requested))):
        raise ValueError("Payment tree differs from the request")


def create_nutroot_witness(
    proof: Proof,
    digest: bytes,
    ownership: NutrootOwnership,
    *,
    preimages: Mapping[bytes, bytes] = {},
    now: Optional[float] = None,
    acceptance_policy: Optional[Callable[[NutrootLeaf], bool]] = None,
) -> str:
    for leaf in ownership.leaves:
        if acceptance_policy is not None and not acceptance_policy(leaf):
            raise ValueError("Condition tree is outside the wallet acceptance policy")
    if ownership.key_path is not None:
        return json.dumps(
            {"signatures": [ownership.key_path.sign_schnorr(digest).hex()]}
        )
    raw_tree = [
        bytes.fromhex(leaf)
        for leaf in (proof.spend_info.tree if proof.spend_info else None) or []
    ]
    hashes = [nutroot_leaf_hash(leaf) for leaf in raw_tree]
    for index, leaf in enumerate(ownership.leaves):
        if leaf.type == "commit":
            continue
        if leaf.type == "after" and (
            leaf.time is None or (now if now is not None else time.time()) < leaf.time
        ):
            continue
        preimage = preimages.get(leaf.hash or b"") if leaf.type == "hashlock" else None
        if leaf.type == "hashlock" and (
            preimage is None
            or len(preimage) != 32
            or hashlib.sha256(preimage).digest() != leaf.hash
        ):
            continue
        keys = [
            ownership.leaf_keys[key.format()]
            for key in leaf.keys
            if key.format() in ownership.leaf_keys
        ]
        if len(keys) < leaf.n:
            continue
        witness = NutrootWitness.model_validate(
            {
                "leaf": raw_tree[index].hex(),
                "control": {
                    "K": ownership.internal_key.format().hex(),
                    "path": [item.hex() for item in nutroot_merkle_path(hashes, index)],
                },
                "signatures": [
                    key.sign_schnorr(digest).hex() for key in keys[: leaf.n]
                ],
                **({"preimage": preimage.hex()} if preimage is not None else {}),
            }
        )
        verify_script_path_spend(
            PublicKey(bytes.fromhex(proof.secret)), digest, witness, now=now
        )
        return witness.model_dump_json(by_alias=True, exclude_none=True)
    raise ValueError("Wallet cannot satisfy any Nutroot spend path")
