import asyncio
import base64
import hashlib
import json
from pathlib import Path

import cbor2
import pyblst
import pytest
from coincurve import PublicKeyXOnly

from cashu.core.base import (
    BlindedSignature,
    NutrootOption,
    Proof,
    SpendInfo,
    TokenV3,
    TokenV3Token,
    TokenV4,
    TokenV4Proof,
    TokenV4Token,
    WalletKeyset,
)
from cashu.core.crypto import bls_dhke
from cashu.core.crypto.bls import PrivateKey as BlsPrivateKey
from cashu.core.crypto.bls import PublicKey as BlsPublicKey
from cashu.core.crypto.nutroot import (
    NUTROOT_NUMS,
    NutrootLeaf,
    NutrootWitness,
    nutroot_tweak_pubkey,
    serialize_nutroot_leaf,
    verify_script_path_spend,
)
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.nutroot import (
    create_nutroot_output,
    create_nutroot_witness,
    create_requested_nutroot_output,
    resolve_nutroot_ownership,
    validate_requested_nutroot_output,
)
from cashu.mint.db.read import _pending_proof_state
from cashu.wallet import migrations
from cashu.wallet.crud import (
    allocate_quote_counter,
    bump_secret_derivation,
    get_proofs,
    set_secret_derivation,
    store_proof,
)
from cashu.wallet.wallet import Wallet

KID = "02" + "ab" * 32


def key(value):
    return PrivateKey(value.to_bytes(32, "big"))


def leaf(kind="threshold", keys=None, **kwargs):
    return serialize_nutroot_leaf(
        NutrootLeaf(
            type=kind, n=kwargs.pop("n", 1), keys=keys or [key(3).public_key], **kwargs
        )
    )


def proof(secret, info=None):
    return Proof(id=KID, amount=1, secret=secret, C="aa" * 48, spend_info=info)


@pytest.mark.parametrize(
    "group,identity", [("G1", pyblst.BlstP1Element()), ("G2", pyblst.BlstP2Element())]
)
def test_bls_point_validation(group, identity):
    with pytest.raises(ValueError):
        BlsPublicKey(identity.compress(), group=group)
    with pytest.raises(ValueError):
        BlsPublicKey(b"\x00" * (48 if group == "G1" else 96), group=group)


def test_v3_derivation_rejects_a_short_seed_and_invalid_mint_identity():
    wallet = Wallet.__new__(Wallet)
    wallet.seed = bytes(32)
    with pytest.raises(ValueError, match="64-byte"):
        wallet.derive_v3_secret_key(0, KID)
    wallet.seed = bytes(64)
    with pytest.raises(ValueError):
        wallet.derive_v3_quote_lock_key(0, "00" * 33)


def test_bls_proofs_verify_without_dleq_in_mixed_wallet_batches():
    mint_key = BlsPrivateKey(scalar=19)
    secret = key(3).public_key.format().hex()
    C = bls_dhke.hash_to_curve(bytes.fromhex(secret)) * mint_key
    wallet = Wallet.__new__(Wallet)
    wallet.keysets = {
        KID: WalletKeyset(id=KID, public_keys={1: mint_key.public_key}, unit="sat")
    }
    legacy = Proof(
        id="00" + "cd" * 7,
        amount=1,
        secret="legacy",
        C=key(4).public_key.format().hex(),
    )
    wallet.keysets[legacy.id] = WalletKeyset(
        id=legacy.id, public_keys={1: key(5).public_key}, unit="sat"
    )
    valid = proof(secret)
    valid.C = C.format().hex()
    wallet.verify_proofs_dleq([legacy, valid])
    valid.C = (C * 2).format().hex()
    with pytest.raises(Exception, match="pairing verification invalid"):
        wallet.verify_proofs_dleq([legacy, valid])


def test_locked_bearer_key_path_is_tweaked_and_matches_the_secret():
    k = key(7)
    secret, info = create_nutroot_output(k.public_key, [leaf()], bearer_key=k)
    p = proof(secret, info)
    wallet = Wallet.__new__(Wallet)
    signing = wallet._resolve_v3_secret_key(p)
    assert signing is not None
    assert signing.public_key.format().hex() == secret
    digest = hashlib.sha256(b"transaction").digest()
    witness = json.loads(
        create_nutroot_witness(p, digest, resolve_nutroot_ownership(p))
    )
    assert PublicKeyXOnly(bytes.fromhex(secret)[1:]).verify(
        bytes.fromhex(witness["signatures"][0]), digest
    )


def test_scriptless_aggregated_keys_always_carry_the_empty_tweak():
    internal = key(59).public_key
    secret, info = create_nutroot_output(internal, aggregated=True)
    assert secret == nutroot_tweak_pubkey(internal).format().hex()
    assert secret != internal.format().hex()
    assert info.k is None and info.tree is None


def test_receiver_keyed_tree_recovers_leaf_keys_by_value_after_permutation():
    owner, refund = key(7), key(11)
    requested = NutrootOption(
        k=owner.public_key.format().hex(),
        l=[
            leaf("after", [refund.public_key], time=0).hex(),
            leaf(keys=[owner.public_key]).hex(),
        ],
        b=[owner.public_key.format().hex(), refund.public_key.format().hex()],
    )
    secret, info = create_requested_nutroot_output(requested, ephemeral_key=key(13))
    p = proof(secret, info)
    ownership = resolve_nutroot_ownership(p, [owner, refund])
    assert ownership.key_path is not None
    assert len(ownership.leaf_keys) == 2
    validate_requested_nutroot_output(p, requested, ownership)
    info.tree.reverse()
    permuted = resolve_nutroot_ownership(p, [owner, refund])
    assert set(permuted.leaf_keys) == set(ownership.leaf_keys)
    validate_requested_nutroot_output(p, requested, permuted)


@pytest.mark.parametrize("blinded", [False, True])
def test_nums_threshold_output_is_spent_through_its_leaves(blinded):
    alice, bob = key(17), key(23)
    requested = NutrootOption(
        k=NUTROOT_NUMS.format().hex(),
        l=[leaf(keys=[alice.public_key, bob.public_key], n=2).hex()],
        b=[bob.public_key.format().hex()] if blinded else None,
    )
    secret, info = create_requested_nutroot_output(
        requested, nums_offset=key(29), ephemeral_key=key(31) if blinded else None
    )
    assert (info.E is not None) == blinded
    p = proof(secret, info)
    ownership = resolve_nutroot_ownership(p, [alice, bob])
    assert ownership.key_path is None
    validate_requested_nutroot_output(p, requested, ownership)
    digest = hashlib.sha256(b"script transaction").digest()
    witness = create_nutroot_witness(p, digest, ownership)
    verify_script_path_spend(
        PublicKey(bytes.fromhex(secret)),
        digest,
        NutrootWitness.model_validate_json(witness),
    )


def test_request_rejects_an_added_leaf_and_a_mismatching_internal_key():
    alice = key(37)
    requested = NutrootOption(k=alice.public_key.format().hex(), l=[leaf().hex()])
    secret, info = create_requested_nutroot_output(requested)
    p = proof(secret, info)
    info.K = key(41).public_key.format().hex()
    with pytest.raises(ValueError, match="Disclosed internal key"):
        resolve_nutroot_ownership(p, [alice])
    added = requested.model_copy(
        update={"l": [*requested.l, leaf("after", time=0).hex()]}
    )
    secret, info = create_requested_nutroot_output(added)
    p = proof(secret, info)
    ownership = resolve_nutroot_ownership(p, [alice])
    with pytest.raises(ValueError, match="tree differs"):
        validate_requested_nutroot_output(p, requested, ownership)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"k": key(3).secret.hex(), "E": key(5).public_key.format().hex()},
        {"K": key(3).public_key.format().hex(), "tree": []},
        {"tree": [leaf().hex()]},
        {"K": key(3).public_key.format().hex(), "u": key(5).secret.hex()},
    ],
)
def test_malformed_spend_info_is_rejected(kwargs):
    with pytest.raises(ValueError):
        SpendInfo(**kwargs)


def test_token_conversions_preserve_spend_info_and_remove_witnesses():
    secret, info = create_nutroot_output(
        key(43).public_key, [leaf()], bearer_key=key(43)
    )
    p = proof(secret, info)
    p.witness = '{"signatures":["' + "00" * 64 + '"]}'
    token = TokenV4(
        m="https://mint.test",
        u="sat",
        t=[TokenV4Token(i=bytes.fromhex(KID), p=[TokenV4Proof.from_proof(p)])],
    )
    v3 = token.to_tokenv3()
    decoded = TokenV3.deserialize(v3.serialize())
    assert decoded.proofs[0].spend_info == info
    assert decoded.proofs[0].witness is None
    roundtrip = TokenV4.from_tokenv3(decoded)
    assert roundtrip.proofs[0].spend_info == info
    hostile = TokenV3Token(proofs=[p], mint="https://mint.test")
    assert hostile.proofs[0].witness is None
    assert p.witness is not None


def test_v3_wire_models_omit_dleq_entirely():
    p = proof(key(43).public_key.format().hex())
    signature = BlindedSignature(id=KID, amount=1, C_=p.C)
    for model in (p, signature):
        assert "dleq" not in model.model_dump()
        assert "dleq" not in json.loads(model.model_dump_json())
    legacy = signature.model_copy(update={"id": "00" + "ab" * 7})
    assert "dleq" in legacy.model_dump()


def test_v4_decode_reserialize_strips_a_v3_witness_without_accessing_proofs():
    p = proof(key(43).public_key.format().hex())
    raw = {
        "m": "https://mint.test",
        "u": "sat",
        "t": [
            {
                "i": bytes.fromhex(KID),
                "p": [{"a": 1, "s": p.secret, "c": bytes.fromhex(p.C), "w": "stale"}],
            }
        ],
    }
    encoded = "cashuB" + base64.urlsafe_b64encode(cbor2.dumps(raw)).decode().rstrip("=")
    token = TokenV4.deserialize(encoded)
    assert token.t[0].p[0].w is None
    assert "w" not in token.serialize_to_dict()["t"][0]["p"][0]


@pytest.mark.asyncio
async def test_wallet_database_preserves_complete_spend_info(tmp_path):
    db = Database("wallet", str(tmp_path))
    await migrate_databases(db, migrations)
    secret, info = create_requested_nutroot_output(
        NutrootOption(k=key(47).public_key.format().hex(), l=[leaf().hex()])
    )
    info = SpendInfo.model_validate(
        {**info.model_dump(), "future": {"hint": b"\x00\xff"}}
    )
    token = TokenV4(
        m="https://mint.test",
        u="sat",
        t=[
            TokenV4Token(
                i=bytes.fromhex(KID), p=[TokenV4Proof.from_proof(proof(secret, info))]
            )
        ],
    )
    assert TokenV4.deserialize(token.serialize()).proofs[0].spend_info == info
    await store_proof(proof(secret, info), db)
    restored = await get_proofs(db=db)
    assert len(restored) == 1
    assert restored[0].spend_info == info
    await db.engine.dispose()


@pytest.mark.asyncio
async def test_v3_wallet_counters_preserve_the_full_u64_range(tmp_path):
    db = Database("wallet", str(tmp_path))
    try:
        await migrate_databases(db, migrations)
        await set_secret_derivation(db, KID, 2**64 - 2)
        assert await bump_secret_derivation(db, KID) == 2**64 - 2
        assert await bump_secret_derivation(db, KID) == 2**64 - 1
        with pytest.raises(ValueError, match="u64"):
            await bump_secret_derivation(db, KID)
        identity = key(3).public_key.format().hex()
        counters = await asyncio.gather(
            *(allocate_quote_counter(db, identity) for _ in range(8))
        )
        assert sorted(counters) == list(range(8))
    finally:
        await db.engine.dispose()


def test_pending_spends_return_original_key_and_script_witnesses():
    vectors = json.loads(
        Path(__file__).with_name("nutroot_v3_vectors.json").read_text()
    )
    p = proof(key(3).public_key.format().hex())
    for name in ("key_path", "script_path"):
        vector = vectors["nut07_commitments"][name]
        p.witness = vector["witness"]
        p.digest = vector["input_digest"]
        state = _pending_proof_state(p.Y, p)
        assert state.commitment is None
        assert state.witness == p.witness
        assert state.input_digest == p.digest
        assert "commitment" not in state.model_dump()
