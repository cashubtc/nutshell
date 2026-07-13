import datetime
import hashlib
from types import SimpleNamespace

import httpx
import pytest
import respx
from coincurve import PrivateKey, PublicKeyXOnly
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cashu.core.base import PolReceipt, WalletKeyset
from cashu.core.crypto import b_dhke
from cashu.core.crypto.b_dhke import hash_to_curve
from cashu.core.settings import settings
from cashu.mint import app as app_module
from cashu.mint import middleware as middleware_module
from cashu.mint import router as router_module
from cashu.mint.pol import (
    MerkleMountainRangeSum,
    build_trees_for_keyset_at_timestamp,
    generate_output_receipt,
    generate_spent_receipt,
    get_global_digest_for_epoch,
    get_target_epoch,
    submit_to_ots,
    upgrade_pending_ots_receipts,
)
from cashu.wallet.wallet import Wallet

BASE_URL = "http://localhost:3337"
ITEMS = [
    "02b1a03e1b10a23429fa221087e53f19001b97ad89498a44b93b3f23a851121df4",
    "02c3a50646bc1a1fef3da21973b064eb6897de58231c5f3e2730bf18361592394a",
    "03c0029b38423f03b6d203a55e2d6778035740e40dd3d888301b3b47aede737b6f",
]


def _build_router_app() -> FastAPI:
    app = FastAPI()
    middleware_module.add_middlewares(app)
    app.middleware("http")(app_module.catch_exceptions)
    app.include_router(router_module.router)
    return app


def _tree(items=ITEMS, values=(100, 250, 500)):
    return MerkleMountainRangeSum(
        [
            (hashlib.sha256(bytes.fromhex(item)).digest(), value)
            for item, value in zip(items, values)
        ]
    )


def test_sum_mmr_computation_matches_spec_vector():
    tree = _tree()
    root_hash, root_sum = tree.root

    assert tree.size == 3
    assert (
        root_hash.hex()
        == "2518b42edfff24ecc53c8897d1860783d1d26c41d61c378fe612cddeed877040"
    )
    assert root_sum == 850
    sibling_path, peaks = tree.get_proof(0)
    assert sibling_path == [
        {
            "hash": "aa80cd1d9ae985f212fd6c41cdf4c8747c92d787e9d8fd45e5d7e3f85941937f",
            "sum": 250,
            "is_left": False,
        }
    ]
    assert peaks == [
        {
            "hash": "90e8e647a08f35b5b24653ab52e5d27a2deddb05d1e54d5d21777ef02036b29f",
            "sum": 350,
        },
        {
            "hash": "95b7ec67b1f85ca98781f08fc4613559820b99f178707b29c8ebb4577aca5f40",
            "sum": 500,
        },
    ]


def test_sum_mmr_empty_root_and_uint64_overflow():
    assert MerkleMountainRangeSum([]).root == (hashlib.sha256(b"").digest(), 0)
    with pytest.raises(OverflowError):
        MerkleMountainRangeSum([(hashlib.sha256(b"a").digest(), 2**64)])
    leaves = [
        (hashlib.sha256(b"a").digest(), 2**64 - 1),
        (hashlib.sha256(b"b").digest(), 1),
    ]
    with pytest.raises(OverflowError):
        MerkleMountainRangeSum(leaves)


@respx.mock
@pytest.mark.asyncio
async def test_submit_to_ots_success_and_failover():
    digest = hashlib.sha256(b"hello").digest()
    alice = respx.post("https://alice.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(500)
    )
    bob = respx.post("https://bob.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(200, content=b"BOB_OTS_RECEIPT")
    )

    assert await submit_to_ots(digest) == b"BOB_OTS_RECEIPT"
    assert alice.called
    assert bob.called


@respx.mock
@pytest.mark.asyncio
async def test_mint_upgrades_and_republishes_pending_ots_receipts():
    pending = b"pending\x00\x06receipt"
    upgraded = pending + b"-anchored"
    respx.post("https://alice.btc.calendar.opentimestamps.org/upgrade").mock(
        return_value=httpx.Response(200, content=upgraded)
    )
    updates = []

    async def fetchall(query, values=None):
        return [{"epoch_index": 7, "ots_receipt": pending.hex()}]

    async def execute(query, values=None):
        updates.append(values)

    ledger = SimpleNamespace(
        db=SimpleNamespace(
            fetchall=fetchall,
            execute=execute,
            table_with_schema=lambda table: table,
        )
    )
    await upgrade_pending_ots_receipts(ledger)
    assert updates == [{"ots_receipt": upgraded.hex(), "epoch_index": 7}]


@pytest.mark.asyncio
async def test_pol_receipts_are_domain_separated():
    async def fetchone(query, values=None):
        return None

    amount_key = PrivateKey(hashlib.sha256(b"amount-key").digest())
    ledger = SimpleNamespace(
        db=SimpleNamespace(
            fetchone=fetchone,
            table_with_schema=lambda table: table,
        ),
        keysets={"test_keyset": SimpleNamespace(private_keys={100: amount_key})},
    )

    assert await get_target_epoch(ledger) == 1
    issued = await generate_output_receipt(ledger, "test_keyset", 100, ITEMS[0])
    spent = await generate_spent_receipt(ledger, "test_keyset", 100, ITEMS[0])
    pubkey = PublicKeyXOnly(amount_key.public_key.format()[1:])
    issued_message = f"Cashu_PoL_Receipt_Issued:{ITEMS[0]}:1".encode()
    spent_message = f"Cashu_PoL_Receipt_Spent:{ITEMS[0]}:1".encode()

    assert pubkey.verify(
        bytes.fromhex(issued.signature), hashlib.sha256(issued_message).digest()
    )
    assert pubkey.verify(
        bytes.fromhex(spent.signature), hashlib.sha256(spent_message).digest()
    )
    assert not pubkey.verify(
        bytes.fromhex(issued.signature), hashlib.sha256(spent_message).digest()
    )


def test_published_receipt_signature_vectors():
    pubkey = PublicKeyXOnly(
        bytes.fromhex(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
    )
    vectors = [
        (
            f"Cashu_PoL_Receipt_Issued:{ITEMS[0]}:12",
            "31ef4e45aec5da42a7622bfbc6a8d0f9e07b562aa69092b6a2b7ea3a9b8ec92f"
            "88f4d510d488f55b00c2ea1bed0bb1f499c55eda275ffee9e0df60bf941a71b2",
        ),
        (
            f"Cashu_PoL_Receipt_Spent:{ITEMS[1]}:12",
            "28b635335642ac4693f4eefb068500b5360c89df907537ad4f1baa25b5de48e30"
            "fb7a00f2e6a12ea864f5fbe0c0e5a8fd2c15ada088938eba55c339e215904df",
        ),
    ]
    for message, signature in vectors:
        assert pubkey.verify(
            bytes.fromhex(signature), hashlib.sha256(message.encode()).digest()
        )


@pytest.mark.asyncio
async def test_global_digest_commits_to_mmr_sizes_and_normalized_keysets():
    rows = [
        {
            "keyset_id": "00BB",
            "issued_mmr_size": 2,
            "root_issued_hash": "11" * 32,
            "spent_mmr_size": 1,
            "root_spent_hash": "22" * 32,
            "previous_global_digest": "33" * 32,
        },
        {
            "keyset_id": "00AA",
            "issued_mmr_size": 4,
            "root_issued_hash": "44" * 32,
            "spent_mmr_size": 3,
            "root_spent_hash": "55" * 32,
            "previous_global_digest": "33" * 32,
        },
    ]

    async def fetchall(query, values=None):
        return rows

    ledger = SimpleNamespace(
        db=SimpleNamespace(
            fetchall=fetchall,
            table_with_schema=lambda table: table,
        )
    )
    commitment = bytes.fromhex("33" * 32)
    for row in reversed(rows):
        commitment += (
            row["keyset_id"].lower().encode()
            + row["issued_mmr_size"].to_bytes(8, "big")
            + bytes.fromhex(row["root_issued_hash"])
            + row["spent_mmr_size"].to_bytes(8, "big")
            + bytes.fromhex(row["root_spent_hash"])
        )
    assert (
        await get_global_digest_for_epoch(ledger, 1)
        == hashlib.sha256(commitment).digest()
    )


@pytest.mark.asyncio
async def test_build_sum_mmrs_uses_sequential_database_order(monkeypatch):
    now = datetime.datetime.now(datetime.timezone.utc)
    y_hex = hash_to_curve(b"secret").format().hex()

    async def fetchall(query, values=None):
        if "promises" in query:
            assert "pol_sequence ASC" in query
            return [
                {"amount": 100, "b_": ITEMS[0], "created": now},
                {"amount": 250, "b_": ITEMS[1], "created": now},
            ]
        assert "pol_sequence ASC" in query
        return [
            {
                "amount": 100,
                "secret": "secret",
                "y": y_hex,
                "created": now,
            }
        ]

    ledger = SimpleNamespace(
        db=SimpleNamespace(
            fetchall=fetchall,
            table_with_schema=lambda table: table,
        )
    )
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", False)
    issued, spent = await build_trees_for_keyset_at_timestamp(ledger, "keyset")

    assert issued.size == 2
    assert issued.find_leaf(hashlib.sha256(bytes.fromhex(ITEMS[1])).digest()) == 1
    assert spent.size == 1


def test_pol_endpoints_return_current_sum_mmr_schema(monkeypatch):
    keyset_id = "009a6154b71113b7"
    timestamp = datetime.datetime.now(datetime.timezone.utc)
    issued_tree = _tree(ITEMS[:2], (100, 250))
    y_hex = hash_to_curve(b"secret").format().hex()
    spent_tree = _tree([y_hex], (100,))
    issued_hash, issued_sum = issued_tree.root
    spent_hash, spent_sum = spent_tree.root
    signing_key = PrivateKey(hashlib.sha256(b"mint").digest())

    async def fetchone(query, values=None):
        if "pol_epochs" not in query:
            return None
        return {
            "keyset_id": keyset_id,
            "epoch_index": 1,
            "timestamp": timestamp,
            "previous_global_digest": "00" * 32,
            "issued_mmr_size": issued_tree.size,
            "root_issued_hash": issued_hash.hex(),
            "root_issued_sum": issued_sum,
            "spent_mmr_size": spent_tree.size,
            "root_spent_hash": spent_hash.hex(),
            "root_spent_sum": spent_sum,
            "outstanding_balance": issued_sum - spent_sum,
            "ots_receipt": "010203",
            "signature": "mock_sig",
        }

    ledger = SimpleNamespace(
        seed="mint",
        pubkey=signing_key.public_key,
        keysets={keyset_id: SimpleNamespace(final_expiry=None, private_keys={})},
        db=SimpleNamespace(
            fetchone=fetchone,
            table_with_schema=lambda table: table,
        ),
    )
    monkeypatch.setattr(router_module, "ledger", ledger)
    monkeypatch.setattr(
        router_module,
        "build_trees_for_keyset_at_timestamp",
        pytest.importorskip("unittest.mock").AsyncMock(
            return_value=(issued_tree, spent_tree)
        ),
    )
    client = TestClient(_build_router_app())

    manifest = client.get(f"/v1/pol/{keyset_id}/manifest").json()
    assert manifest["issued_mmr_size"] == 2
    assert manifest["issued_mmr_root_hash"] == issued_hash.hex()
    assert "root_issued" not in manifest

    issued = client.post(
        f"/v1/pol/{keyset_id}/proofs/issued",
        json={"blinded_messages": [ITEMS[0]]},
    )
    assert issued.status_code == 200
    proof = issued.json()["proofs"][0]
    assert proof["leaf_index"] == 0
    assert proof["sibling_path"][0]["is_left"] is False
    assert proof["peaks"][0]["hash"] == issued_hash.hex()
    assert "is_left" not in proof["peaks"][0]

    spent = client.post(f"/v1/pol/{keyset_id}/proofs/spent", json={"ys": [y_hex]})
    assert spent.status_code == 200
    assert spent.json()["proofs"][0]["leaf_index"] == 0


@pytest.mark.asyncio
@respx.mock
async def test_wallet_verifies_sum_mmr_inclusion_and_receipt(monkeypatch):
    keyset_id = "009a6154b71113b7"
    secret = "secret_1"
    r_bytes = b"\x01" * 32
    blinded, _ = b_dhke.step1_alice(secret, PrivateKey(r_bytes))
    b_hex = blinded.format().hex()
    issued_tree = _tree([b_hex], (100,))
    issued_hash, issued_sum = issued_tree.root
    empty_hash, _ = MerkleMountainRangeSum([]).root
    amount_key = PrivateKey(hashlib.sha256(b"amount-key").digest())
    receipt_message = f"Cashu_PoL_Receipt_Issued:{b_hex}:1".encode()
    receipt = PolReceipt(
        target_epoch=1,
        signature=amount_key.sign_schnorr(
            hashlib.sha256(receipt_message).digest()
        ).hex(),
    )
    proof = SimpleNamespace(
        id=keyset_id,
        amount=100,
        secret=secret,
        C="02" + "00" * 32,
        derivation_path="HMAC-SHA256:test:0",
        dleq=None,
        pol_receipt=receipt,
    )

    async def load_proofs(reload=True):
        return None

    async def deterministic_secret(counter, kid):
        return secret.encode(), r_bytes, "HMAC-SHA256:test:0"

    async def fetchone(query, values=None):
        return {"counter": 0}

    async def ots(receipt_hex, manifest_timestamp=None):
        return "OTS Attestation: Confirmed"

    wallet = SimpleNamespace(
        url=BASE_URL,
        proofs=[proof],
        load_proofs=load_proofs,
        generate_determinstic_secret=deterministic_secret,
        db=SimpleNamespace(
            fetchone=fetchone,
            table_with_schema=lambda table: table,
        ),
        keysets={
            keyset_id: WalletKeyset(
                id=keyset_id,
                unit="sat",
                public_keys={100: amount_key.public_key},
            )
        },
        mint_info=SimpleNamespace(pubkey=amount_key.public_key.format().hex()),
        _verify_ots_anchoring=ots,
    )
    wallet._verify_pol_receipt = lambda p, item, leaf_type=None: (
        Wallet._verify_pol_receipt(wallet, p, item, leaf_type)
    )
    monkeypatch.setattr(
        "cashu.wallet.wallet.get_proofs",
        pytest.importorskip("unittest.mock").AsyncMock(return_value=[]),
    )

    timestamp = "2026-06-11T12:00:00Z"
    manifest = {
        "keyset_id": keyset_id,
        "epoch_index": 1,
        "timestamp": timestamp,
        "previous_global_digest": "00" * 32,
        "signing_pubkey": amount_key.public_key.format()[1:].hex(),
        "issued_mmr_size": 1,
        "issued_mmr_root_hash": issued_hash.hex(),
        "issued_mmr_root_sum": issued_sum,
        "spent_mmr_size": 0,
        "spent_mmr_root_hash": empty_hash.hex(),
        "spent_mmr_root_sum": 0,
        "outstanding_balance": 100,
        "ots_receipt": "010203",
        "mint_signature": "mock_sig",
    }
    respx.get(f"{BASE_URL}/v1/pol/{keyset_id}/manifest").mock(
        return_value=httpx.Response(200, json=manifest)
    )
    sibling_path, peaks = issued_tree.get_proof(0)
    respx.post(f"{BASE_URL}/v1/pol/{keyset_id}/proofs/issued").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": b_hex,
                        "leaf_index": 0,
                        "value": 100,
                        "sibling_path": sibling_path,
                        "peaks": peaks,
                    }
                ]
            },
        )
    )

    success, challenges, skipped, errors, status = await Wallet.verify_solvency(
        wallet, keyset_id
    )
    assert success
    assert challenges == []
    assert (skipped, errors) == (0, 0)
    assert "sum-MMR proofs verified" in status


def test_published_manifest_message_and_key_vector():
    message = (
        "009a6154b71113b7:1:2026-06-11T12:00:00Z:"
        + "00" * 32
        + ":3:2518b42edfff24ecc53c8897d1860783d1d26c41d61c378fe612cddeed877040"
        ":850:0:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ":0:850"
    )
    assert hashlib.sha256(message.encode()).hexdigest() == (
        "faaafafdc99bf27b8ba4d9b52d7ed5cd29d61c4a19ff65f8d4aaf49f6b964480"
    )
    private_key = PrivateKey(
        bytes.fromhex(
            "371b3102088ee8fa21744920b996fa717417631271730ad34269646465998245"
        )
    )
    assert private_key.public_key.format().hex() == (
        "02f3dd0e40dd3d888301b3b47aede737b6f9451ab451dfc05a1ae023ab4235b4dd"
    )
    digest = hashlib.sha256(message.encode()).digest()
    signature = private_key.sign_schnorr(
        digest,
        bytes.fromhex(
            "b777e0270e6f6bd9302268a253ffda221ce9257a6e13349e198169745c45d72e"
        ),
    )
    pubkey = PublicKeyXOnly(private_key.public_key.format()[1:])
    assert pubkey.verify(
        signature,
        digest,
    )
