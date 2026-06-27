import datetime
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest
import respx
from click.testing import CliRunner
from coincurve import PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cashu.core.base import PolReceipt
from cashu.core.crypto import b_dhke
from cashu.core.crypto.b_dhke import hash_to_curve
from cashu.core.settings import settings
from cashu.mint import app as app_module
from cashu.mint import middleware as middleware_module
from cashu.mint import router as router_module
from cashu.mint.pol import (
    SparseMerkleSumTree,
    generate_output_receipt,
    generate_spent_receipt,
    get_target_epoch,
    submit_to_ots,
)
from cashu.wallet.cli.cli import pol as pol_group
from cashu.wallet.wallet import Wallet

BASE_URL = "http://localhost:3337"


def _build_router_app() -> FastAPI:
    app = FastAPI()
    middleware_module.add_middlewares(app)
    app.middleware("http")(app_module.catch_exceptions)
    app.include_router(router_module.router)
    return app


def test_sparse_merkle_sum_tree_computation():
    leaves = {}
    items = ["blinded_msg_1", "blinded_msg_2"]
    values = [100, 250]

    for item, val in zip(items, values):
        h = hashlib.sha256(item.encode("utf-8")).digest()
        idx_int = int.from_bytes(h, "big")
        leaves[idx_int] = (h, val)

    tree = SparseMerkleSumTree(leaves)
    root_hash, root_sum = tree.root

    assert root_sum == 350
    assert len(root_hash) == 32

    h1_hex = hashlib.sha256(items[0].encode("utf-8")).hexdigest()
    idx1_int = int.from_bytes(bytes.fromhex(h1_hex), "big")

    compact_mask, proof1 = tree.get_proof(idx1_int)
    assert len(proof1) < 256

    mask_int = int(compact_mask, 16)
    sibling_iter = iter(proof1)
    reconstructed_siblings = []
    for d in range(256):
        bit = (mask_int >> d) & 1
        if bit == 1:
            reconstructed_siblings.append(next(sibling_iter))
        else:
            def_hash, def_sum = tree.default_nodes[d]
            reconstructed_siblings.append({"hash": def_hash.hex(), "sum": def_sum})

    current_hash = bytes.fromhex(h1_hex)
    current_sum = values[0]
    for d in range(256):
        sib = reconstructed_siblings[d]
        sib_hash = bytes.fromhex(sib["hash"])
        sib_sum = sib["sum"]

        bit = (idx1_int >> d) & 1
        parent_sum = current_sum + sib_sum

        if bit == 0:
            left_hash = current_hash
            left_sum = current_sum
            right_hash = sib_hash
            right_sum = sib_sum
        else:
            left_hash = sib_hash
            left_sum = sib_sum
            right_hash = current_hash
            right_sum = current_sum

        current_hash = hashlib.sha256(
            left_hash
            + right_hash
            + left_sum.to_bytes(8, "big")
            + right_sum.to_bytes(8, "big")
        ).digest()
        current_sum = parent_sum

    assert current_hash == root_hash
    assert current_sum == root_sum


@respx.mock
@pytest.mark.asyncio
async def test_submit_to_ots_success_and_failover():
    digest = hashlib.sha256(b"hello").digest()

    alice_route = respx.post(
        "https://alice.btc.calendar.opentimestamps.org/digest"
    ).mock(return_value=httpx.Response(200, content=b"ALICE_OTS_RECEIPT"))
    bob_route = respx.post("https://bob.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(200, content=b"BOB_OTS_RECEIPT")
    )

    res = await submit_to_ots(digest)
    assert res == b"ALICE_OTS_RECEIPT"
    assert alice_route.called

    alice_route.reset()
    bob_route.reset()

    respx.post("https://alice.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(500)
    )
    res = await submit_to_ots(digest)
    assert res == b"BOB_OTS_RECEIPT"
    assert bob_route.called


@pytest.mark.asyncio
async def test_pol_receipt_generation(monkeypatch):
    async def mock_fetchone(q, v=None):
        return None

    async def mock_fetchall(q, v=None):
        return []

    async def mock_execute(q, v=None):
        return None

    mock_ledger = SimpleNamespace(
        seed="test_mint_pol_private_key_seed",
        pubkey=PrivateKey(
            hashlib.sha256(b"test_mint_pol_private_key_seed").digest()
        ).public_key,
        db=SimpleNamespace(
            fetchone=mock_fetchone,
            fetchall=mock_fetchall,
            execute=mock_execute,
            table_with_schema=lambda t: t,
        ),
        keysets={
            "test_keyset": SimpleNamespace(
                private_keys={
                    100: PrivateKey(hashlib.sha256(b"fallback_pol_seed_test_keyset_100").digest()),
                    50: PrivateKey(hashlib.sha256(b"fallback_pol_seed_test_keyset_50").digest()),
                }
            )
        },
    )

    # 1. Test target epoch index default
    epoch = await get_target_epoch(mock_ledger)
    assert epoch == 1

    # 2. Test generate_output_receipt for individual output
    receipt_out = await generate_output_receipt(
        mock_ledger, keyset_id="test_keyset", amount=100, b_hex="02b1a03e1b10a23429fa221087e53f19001b97ad89498a44b93b3f23a851121df4"
    )
    assert receipt_out.target_epoch == 1
    assert receipt_out.signature is not None
    assert isinstance(receipt_out.signature, str)
    assert len(receipt_out.signature) == 128  # 64 bytes hex-encoded

    from coincurve import PublicKeyXOnly
    priv_bytes_out = hashlib.sha256(
        b"fallback_pol_seed_test_keyset_100"
    ).digest()
    pub_key_out = PrivateKey(priv_bytes_out).public_key
    pub_key_xonly_out = PublicKeyXOnly(pub_key_out.format()[1:])
    msg_out = "02b1a03e1b10a23429fa221087e53f19001b97ad89498a44b93b3f23a851121df4:1".encode("utf-8")
    assert pub_key_xonly_out.verify(
        bytes.fromhex(receipt_out.signature),
        hashlib.sha256(msg_out).digest(),
    )

    # 3. Test generate_spent_receipt for individual spent input
    receipt_in = await generate_spent_receipt(
        mock_ledger, keyset_id="test_keyset", amount=50, y_hex="02c3a50646bc1a1fef3da21973b064eb6897de58231c5f3e2730bf18361592394a"
    )
    assert receipt_in.target_epoch == 1
    assert receipt_in.signature is not None
    assert isinstance(receipt_in.signature, str)
    assert len(receipt_in.signature) == 128  # 64 bytes hex-encoded

    priv_bytes_in = hashlib.sha256(
        b"fallback_pol_seed_test_keyset_50"
    ).digest()
    pub_key_in = PrivateKey(priv_bytes_in).public_key
    pub_key_xonly_in = PublicKeyXOnly(pub_key_in.format()[1:])
    msg_in = "02c3a50646bc1a1fef3da21973b064eb6897de58231c5f3e2730bf18361592394a:1".encode("utf-8")
    assert pub_key_xonly_in.verify(
        bytes.fromhex(receipt_in.signature),
        hashlib.sha256(msg_in).digest(),
    )


@respx.mock
def test_pol_endpoints_and_mock_ledger(monkeypatch):
    keyset_id = "test_keyset_pol"
    mock_keyset = SimpleNamespace(
        id=keyset_id,
        active=False,
        private_keys={},
        final_expiry=None,
    )

    y1 = hash_to_curve(b"secret_1").format().hex()
    y2 = hash_to_curve(b"secret_2").format().hex()

    epoch_timestamp = datetime.datetime.now(datetime.timezone.utc)

    async def mock_fetchall(query, values=None):
        if "promises" in query:
            return [
                {"amount": 100, "b_": "02b1a03e1b10a23429fa221087e53f19001b97ad89498a44b93b3f23a851121df4", "created": epoch_timestamp},
                {"amount": 200, "b_": "02c3a50646bc1a1fef3da21973b064eb6897de58231c5f3e2730bf18361592394a", "created": epoch_timestamp},
            ]
        elif "proofs_used" in query:
            return [
                {
                    "amount": 50,
                    "secret": "secret_1",
                    "y": y1,
                    "created": epoch_timestamp,
                },
                {
                    "amount": 150,
                    "secret": "secret_2",
                    "y": y2,
                    "created": epoch_timestamp,
                },
            ]
        return []

    async def mock_fetchone(query, values=None):
        if "pol_epochs" in query:
            return {
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": epoch_timestamp,
                "root_issued_hash": hashlib.sha256(b"issued").hexdigest(),
                "root_issued_sum": 300,
                "root_spent_hash": hashlib.sha256(b"spent").hexdigest(),
                "root_spent_sum": 200,
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "signature": "mock_sig",
            }
        return None

    mock_db = SimpleNamespace(
        fetchall=mock_fetchall,
        fetchone=mock_fetchone,
        execute=lambda q, v=None: None,
        table_with_schema=lambda t: t,
    )

    mock_ledger = SimpleNamespace(
        keysets={keyset_id: mock_keyset},
        db=mock_db,
        seed="test_mint_pol_private_key_seed",
        pubkey=PrivateKey(
            hashlib.sha256(b"test_mint_pol_private_key_seed").digest()
        ).public_key,
    )

    monkeypatch.setattr(router_module, "ledger", mock_ledger)

    respx.post("https://alice.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(200, content=b"ALICE_OTS_RECEIPT")
    )

    app = _build_router_app()
    client = TestClient(app)

    # Test GET /v1/pol/{keyset_id}/manifest
    resp_manifest = client.get(f"/v1/pol/{keyset_id}/manifest")
    assert resp_manifest.status_code == 200
    manifest_data = resp_manifest.json()
    assert manifest_data["epoch_index"] == 1
    assert manifest_data["outstanding_balance"] == 100

    # Test POST /v1/pol/{keyset_id}/proofs/issued
    resp = client.post(
        f"/v1/pol/{keyset_id}/proofs/issued",
        json={"blinded_messages": ["02b1a03e1b10a23429fa221087e53f19001b97ad89498a44b93b3f23a851121df4", "03c0029b38423f03b6d203a55e2d6778035740e40dd3d888301b3b47aede737b6f"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "proofs" in data
    assert len(data["proofs"]) == 2

    # Check item 1 (active leaf, value 100)
    item1 = data["proofs"][0]
    assert item1["item"] == "02b1a03e1b10a23429fa221087e53f19001b97ad89498a44b93b3f23a851121df4"
    assert item1["value"] == 100
    assert len(item1["siblings"]) < 256

    # Check item 2 (non-existent, value 0)
    item2 = data["proofs"][1]
    assert item2["item"] == "03c0029b38423f03b6d203a55e2d6778035740e40dd3d888301b3b47aede737b6f"
    assert item2["value"] == 0
    assert len(item2["siblings"]) < 256

    # Test POST /v1/pol/{keyset_id}/proofs/spent
    resp_spent = client.post(
        f"/v1/pol/{keyset_id}/proofs/spent", json={"ys": [y1, "00" * 33]}
    )
    assert resp_spent.status_code == 200
    spent_data = resp_spent.json()
    assert len(spent_data["proofs"]) == 2
    assert spent_data["proofs"][0]["item"] == y1
    assert spent_data["proofs"][0]["value"] == 50
    assert spent_data["proofs"][0]["compact_mask"] is not None
    assert spent_data["proofs"][1]["item"] == "00" * 33
    assert spent_data["proofs"][1]["value"] == 0


@respx.mock
def test_pol_audit_challenge_missing_and_invalid_proofs(monkeypatch):
    keyset_id = "test_keyset_pol"
    mock_keyset = SimpleNamespace(
        id=keyset_id,
        active=False,
        private_keys={},
        final_expiry=None,
    )

    async def mock_fetchall(query, values=None):
        return []

    async def mock_fetchone(query, values=None):
        if "pol_epochs" in query:
            return {
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": datetime.datetime.now(datetime.timezone.utc),
                "root_issued_hash": "00" * 32,
                "root_spent_hash": "00" * 32,
                "root_issued_sum": 300,
                "root_spent_sum": 200,
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "signature": "mock_sig",
            }
        return None

    mock_db = SimpleNamespace(
        fetchall=mock_fetchall,
        fetchone=mock_fetchone,
        execute=lambda q, v=None: None,
        table_with_schema=lambda t: t,
    )

    mock_ledger = SimpleNamespace(
        keysets={keyset_id: mock_keyset},
        db=mock_db,
        seed="test_mint_pol_private_key_seed",
        pubkey=PrivateKey(
            hashlib.sha256(b"test_mint_pol_private_key_seed").digest()
        ).public_key,
    )

    monkeypatch.setattr(router_module, "ledger", mock_ledger)

    respx.post("https://alice.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(200, content=b"ALICE_OTS_RECEIPT")
    )

    app = _build_router_app()
    TestClient(app)

    secret_str = "secret_1"
    r_priv = PrivateKey(b"\x01" * 32)
    B_, _ = b_dhke.step1_alice(secret_str, r_priv)
    expected_b_hex = B_.format().hex()
    expected_y_hex = hash_to_curve(secret_str.encode("utf-8")).format().hex()

    respx.get("http://localhost:3337/v1/pol/test_keyset_pol/manifest").mock(
        return_value=httpx.Response(
            200,
            json={
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "signing_pubkey": "00" * 33,
                "root_issued": {"hash": "00" * 32, "sum": 300},
                "root_spent": {"hash": "00" * 32, "sum": 200},
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "mint_signature": "mock_sig",
            },
        )
    )

    respx.post("http://localhost:3337/v1/pol/test_keyset_pol/proofs/spent").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_y_hex,
                        "index": "00" * 32,
                        "value": 100,  # Fails verification path as unspent proof must have value 0
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    respx.post("http://localhost:3337/v1/pol/test_keyset_pol/proofs/issued").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_b_hex,
                        "index": "00" * 32,
                        "value": 100,
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    async def mock_load_proofs(reload=True):
        return None

    async def mock_generate_determinstic_secret(counter, keyset_id):
        return (b"secret_1", b"\x01" * 32, "HMAC-SHA256:test_keyset_pol:42")

    mock_wallet = SimpleNamespace(
        url="http://localhost:3337",
        load_proofs=mock_load_proofs,
        db=mock_db,
        proofs=[
            SimpleNamespace(
                id=keyset_id,
                amount=100,
                secret="secret_1",
                C="C_hex_1",
                derivation_path="HMAC-SHA256:test_keyset_pol:42",
                dleq=None,
                pol_receipt=None,
            )
        ],
        generate_determinstic_secret=mock_generate_determinstic_secret,
    )
    # Bind the verify_solvency method dynamically to our mock wallet object
    mock_wallet.verify_solvency = lambda k, e=None: Wallet.verify_solvency(
        mock_wallet, k, e
    )
    mock_wallet._verify_ots_anchoring = lambda o: Wallet._verify_ots_anchoring(
        mock_wallet, o
    )
    mock_wallet._verify_pol_receipt = lambda p, b_or_y: True

    obj_ctx = {
        "HOST": "http://localhost:3337",
        "WALLET_NAME": "test_wallet",
        "WALLET": mock_wallet,
    }

    runner = CliRunner()
    result = runner.invoke(pol_group, ["audit", keyset_id], obj=obj_ctx)

    assert result.exception is None
    assert "CRYPTOGRAPHIC FRAUD CHALLENGE" in result.output
    assert "spent_non_inclusion" in result.output
    assert "issued_inclusion_path" in result.output


@respx.mock
def test_pol_audit_challenge_with_receipts(monkeypatch):
    keyset_id = "test_keyset_pol"
    mock_keyset = SimpleNamespace(
        id=keyset_id,
        active=False,
        private_keys={},
        final_expiry=None,
    )

    async def mock_fetchone(query, values=None):
        if "pol_epochs" in query:
            return {
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": datetime.datetime.now(datetime.timezone.utc),
                "root_issued_hash": "00" * 32,
                "root_spent_hash": "00" * 32,
                "root_issued_sum": 300,
                "root_spent_sum": 200,
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "signature": "mock_sig",
            }
        return None

    mock_db = SimpleNamespace(
        fetchall=lambda q, v=None: [],
        fetchone=mock_fetchone,
        execute=lambda q, v=None: None,
        table_with_schema=lambda t: t,
    )

    monkeypatch.setattr(
        router_module,
        "ledger",
        SimpleNamespace(keysets={keyset_id: mock_keyset}, db=mock_db),
    )

    secret_str = "secret_1"
    r_priv = PrivateKey(b"\x01" * 32)
    B_, _ = b_dhke.step1_alice(secret_str, r_priv)
    expected_b_hex = B_.format().hex()
    expected_y_hex = hash_to_curve(secret_str.encode("utf-8")).format().hex()

    respx.get("http://localhost:3337/v1/pol/test_keyset_pol/manifest").mock(
        return_value=httpx.Response(
            200,
            json={
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "signing_pubkey": "00" * 33,
                "root_issued": {"hash": "00" * 32, "sum": 300},
                "root_spent": {"hash": "00" * 32, "sum": 200},
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "mint_signature": "mock_sig",
            },
        )
    )

    respx.post("http://localhost:3337/v1/pol/test_keyset_pol/proofs/spent").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_y_hex,
                        "index": "00" * 32,
                        "value": 100,  # Fails non-inclusion verification
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    respx.post("http://localhost:3337/v1/pol/test_keyset_pol/proofs/issued").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_b_hex,
                        "index": "00" * 32,
                        "value": 100,
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    mock_receipt = PolReceipt(target_epoch=1, signature="mock_receipt_sig")

    async def mock_load_proofs(reload=True):
        return None

    async def mock_generate_determinstic_secret(counter, keyset_id):
        return (b"secret_1", b"\x01" * 32, "HMAC-SHA256:test_keyset_pol:42")

    mock_wallet = SimpleNamespace(
        url="http://localhost:3337",
        load_proofs=mock_load_proofs,
        db=mock_db,
        proofs=[
            SimpleNamespace(
                id=keyset_id,
                amount=100,
                secret="secret_1",
                C="C_hex_1",
                derivation_path="HMAC-SHA256:test_keyset_pol:42",
                pol_receipt=mock_receipt,
                dleq=None,
            )
        ],
        generate_determinstic_secret=mock_generate_determinstic_secret,
    )
    # Bind the verify_solvency method dynamically to our mock wallet object
    mock_wallet.verify_solvency = lambda k, e=None: Wallet.verify_solvency(
        mock_wallet, k, e
    )
    mock_wallet._verify_ots_anchoring = lambda o: Wallet._verify_ots_anchoring(
        mock_wallet, o
    )
    mock_wallet._verify_pol_receipt = lambda p, b_or_y: True

    obj_ctx = {
        "HOST": "http://localhost:3337",
        "WALLET_NAME": "test_wallet",
        "WALLET": mock_wallet,
    }

    runner = CliRunner()
    result = runner.invoke(pol_group, ["audit", keyset_id], obj=obj_ctx)

    assert result.exception is None
    assert "mock_receipt_sig" in result.output
    assert "target_epoch" in result.output


@pytest.mark.asyncio
async def test_build_trees_caching(monkeypatch):
    from cashu.core.settings import settings
    from cashu.mint.pol import _FALLBACK_MEM_CACHE, build_trees_for_keyset_at_timestamp

    # Ensure fallback cache is cleared for this test
    _FALLBACK_MEM_CACHE.clear()

    # 1. Test In-Memory Fallback Cache (Redis disabled)
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", False)

    db_calls = 0

    async def mock_fetchall(query, params=None):
        nonlocal db_calls
        db_calls += 1
        if "promises" in query:
            return [{"amount": 100, "b_": "02b1a03e1b10a23429fa221087e53f19001b97ad89498a44b93b3f23a851121df4", "created": "2026-06-13 12:00:00"}]
        return []

    mock_ledger = SimpleNamespace(
        db=SimpleNamespace(fetchall=mock_fetchall, table_with_schema=lambda t: t)
    )

    # First call with epoch_index -> Cache Miss
    t1_issued, t1_spent = await build_trees_for_keyset_at_timestamp(
        mock_ledger, "cache_keyset", epoch_index=5
    )
    assert db_calls == 2  # one for promises, one for proofs
    assert "cache_keyset:5" in _FALLBACK_MEM_CACHE

    # Second call with epoch_index -> Cache Hit
    t2_issued, t2_spent = await build_trees_for_keyset_at_timestamp(
        mock_ledger, "cache_keyset", epoch_index=5
    )
    assert db_calls == 2  # No extra db calls!
    assert t1_issued is t2_issued
    assert t1_spent is t2_spent

    # 2. Test Redis Cache (Redis enabled)
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", True)

    redis_get_calls = 0
    redis_set_calls = 0
    redis_store = {}

    class MockRedis:
        async def get(self, key):
            nonlocal redis_get_calls
            redis_get_calls += 1
            return redis_store.get(key)

        async def set(self, name, value, ex=None):
            nonlocal redis_set_calls
            redis_set_calls += 1
            redis_store[name] = value
            return True

    mock_redis_wrapper = SimpleNamespace(initialized=True, redis=MockRedis())

    monkeypatch.setattr("cashu.mint.pol.redis", mock_redis_wrapper)

    # First call with Redis -> Cache Miss, should fetch from DB and write to Redis
    db_calls = 0
    r1_issued, r1_spent = await build_trees_for_keyset_at_timestamp(
        mock_ledger, "redis_keyset", epoch_index=10
    )
    assert db_calls == 2
    assert redis_get_calls == 2  # attempted get for issued and spent
    assert redis_set_calls == 2  # wrote issued and spent to Redis

    # Second call with Redis -> Cache Hit, should get from Redis and NOT call DB
    db_calls = 0
    r2_issued, r2_spent = await build_trees_for_keyset_at_timestamp(
        mock_ledger, "redis_keyset", epoch_index=10
    )
    assert db_calls == 0  # No DB calls!
    assert redis_get_calls == 4  # called get again
    assert redis_set_calls == 2  # no new sets

    # Verify the values reconstructed from Redis match
    assert r1_issued.root == r2_issued.root
    assert r1_spent.root == r2_spent.root


@pytest.mark.asyncio
async def test_pol_forget_probability_debug_feature(monkeypatch):
    from cashu.core.settings import settings
    from cashu.mint.pol import _FALLBACK_MEM_CACHE, build_trees_for_keyset_at_timestamp

    # Ensure fallback cache is cleared for this test
    _FALLBACK_MEM_CACHE.clear()

    # Disable Redis cache to avoid caching interference
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", False)

    # 1. Test with forget probability = 1.0 (always forget)
    monkeypatch.setattr(settings, "mint_pol_forget_probability", 1.0)

    async def mock_fetchall(query, params=None):
        if "promises" in query:
            return [{"amount": 100, "b_": "02b1a03e1b10a23429fa221087e53f19001b97ad89498a44b93b3f23a851121df4", "created": "2026-06-13 12:00:00"}]
        if "proofs_used" in query:
            return [{"amount": 50, "secret": "secret_1", "y": "02c3a50646bc1a1fef3da21973b064eb6897de58231c5f3e2730bf18361592394a", "created": "2026-06-13 12:00:00"}]
        return []

    mock_ledger = SimpleNamespace(
        db=SimpleNamespace(fetchall=mock_fetchall, table_with_schema=lambda t: t)
    )

    t_issued_forgot, t_spent_forgot = await build_trees_for_keyset_at_timestamp(
        mock_ledger, "forget_keyset", epoch_index=20
    )

    # Both trees should have 0 active leaves because all were forgotten
    assert len(t_issued_forgot.tree_levels[0]) == 0
    assert len(t_spent_forgot.tree_levels[0]) == 0

    # 2. Test with forget probability = 0.0 (never forget)
    _FALLBACK_MEM_CACHE.clear()
    monkeypatch.setattr(settings, "mint_pol_forget_probability", 0.0)

    t_issued_kept, t_spent_kept = await build_trees_for_keyset_at_timestamp(
        mock_ledger, "forget_keyset", epoch_index=20
    )

    # Both trees should have 1 active leaf because none were forgotten
    assert len(t_issued_kept.tree_levels[0]) == 1
    assert len(t_spent_kept.tree_levels[0]) == 1


@pytest.mark.asyncio
async def test_pol_cheat_value_probability_debug_feature(monkeypatch):
    from cashu.core.settings import settings
    from cashu.mint.pol import _FALLBACK_MEM_CACHE, build_trees_for_keyset_at_timestamp

    # Ensure fallback cache is cleared for this test
    _FALLBACK_MEM_CACHE.clear()

    # Disable Redis cache to avoid caching interference
    monkeypatch.setattr(settings, "mint_redis_cache_enabled", False)

    # 1. Test with cheat probability = 1.0 (always cheat)
    monkeypatch.setattr(settings, "mint_pol_cheat_value_probability", 1.0)
    monkeypatch.setattr(settings, "mint_pol_forget_probability", 0.0)

    async def mock_fetchall(query, params=None):
        if "promises" in query:
            return [{"amount": 100, "b_": "02b1a03e1b10a23429fa221087e53f19001b97ad89498a44b93b3f23a851121df4", "created": "2026-06-13 12:00:00"}]
        if "proofs_used" in query:
            return [{"amount": 50, "secret": "secret_1", "y": "02c3a50646bc1a1fef3da21973b064eb6897de58231c5f3e2730bf18361592394a", "created": "2026-06-13 12:00:00"}]
        return []

    mock_ledger = SimpleNamespace(
        db=SimpleNamespace(fetchall=mock_fetchall, table_with_schema=lambda t: t)
    )

    t_issued_cheat, t_spent_cheat = await build_trees_for_keyset_at_timestamp(
        mock_ledger, "cheat_keyset", epoch_index=30
    )

    # Both trees should have 1 active leaf, but their amounts must be changed (different from 100 and 50)
    issued_val = list(t_issued_cheat.tree_levels[0].values())[0][1]
    spent_val = list(t_spent_cheat.tree_levels[0].values())[0][1]

    assert issued_val != 100
    assert spent_val != 50

    # 2. Test with cheat probability = 0.0 (never cheat)
    _FALLBACK_MEM_CACHE.clear()
    monkeypatch.setattr(settings, "mint_pol_cheat_value_probability", 0.0)

    t_issued_normal, t_spent_normal = await build_trees_for_keyset_at_timestamp(
        mock_ledger, "cheat_keyset", epoch_index=30
    )

    issued_val_normal = list(t_issued_normal.tree_levels[0].values())[0][1]
    spent_val_normal = list(t_spent_normal.tree_levels[0].values())[0][1]

    assert issued_val_normal == 100
    assert spent_val_normal == 50


@respx.mock
def test_pol_wallet_audit_detects_value_cheating(monkeypatch):
    keyset_id = "test_keyset_pol_cheat"
    mock_keyset = SimpleNamespace(
        id=keyset_id,
        active=False,
        private_keys={},
        final_expiry=None,
    )

    async def mock_fetchone(query, values=None):
        if "pol_epochs" in query:
            return {
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": datetime.datetime.now(datetime.timezone.utc),
                "root_issued_hash": "00" * 32,
                "root_spent_hash": "00" * 32,
                "root_issued_sum": 300,
                "root_spent_sum": 200,
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "signature": "mock_sig",
            }
        return None

    mock_db = SimpleNamespace(
        fetchall=lambda q, v=None: [],
        fetchone=mock_fetchone,
        execute=lambda q, v=None: None,
        table_with_schema=lambda t: t,
    )

    monkeypatch.setattr(
        router_module,
        "ledger",
        SimpleNamespace(keysets={keyset_id: mock_keyset}, db=mock_db),
    )

    secret_unspent = "secret_unspent"
    secret_spent = "secret_spent"
    r_priv = PrivateKey(b"\x01" * 32)
    B_unspent, _ = b_dhke.step1_alice(secret_unspent, r_priv)
    B_spent, _ = b_dhke.step1_alice(secret_spent, r_priv)
    
    expected_b_unspent_hex = B_unspent.format().hex()
    expected_b_spent_hex = B_spent.format().hex()
    
    expected_y_unspent_hex = hash_to_curve(secret_unspent.encode("utf-8")).format().hex()
    expected_y_spent_hex = hash_to_curve(secret_spent.encode("utf-8")).format().hex()

    respx.get(f"http://localhost:3337/v1/pol/{keyset_id}/manifest").mock(
        return_value=httpx.Response(
            200,
            json={
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "signing_pubkey": "00" * 33,
                "root_issued": {"hash": "00" * 32, "sum": 300},
                "root_spent": {"hash": "00" * 32, "sum": 200},
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "mint_signature": "mock_sig",
            },
        )
    )

    # 1. Test Spent Tree Cheat Detection (spent_inclusion_value)
    # First query asks for [expected_y_unspent_hex] -> returns value 0 (unspent)
    respx.post(f"http://localhost:3337/v1/pol/{keyset_id}/proofs/spent", json={"ys": [expected_y_unspent_hex]}).mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_y_unspent_hex,
                        "index": "00" * 32,
                        "value": 0,
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    # Second query asks for [expected_y_spent_hex] -> returns value 42 (Cheat!)
    respx.post(f"http://localhost:3337/v1/pol/{keyset_id}/proofs/spent", json={"ys": [expected_y_spent_hex]}).mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_y_spent_hex,
                        "index": "00" * 32,
                        "value": 42,  # Cheat!
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    # Issued Tree returns valid values for both (100)
    respx.post(f"http://localhost:3337/v1/pol/{keyset_id}/proofs/issued").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_b_unspent_hex,
                        "index": "00" * 32,
                        "value": 100,
                        "compact_mask": "0x0",
                        "siblings": [],
                    },
                    {
                        "item": expected_b_spent_hex,
                        "index": "00" * 32,
                        "value": 100,
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    mock_receipt = PolReceipt(target_epoch=1, signature="mock_receipt_sig")

    async def mock_load_proofs(reload=True):
        return None

    async def mock_generate_determinstic_secret(counter, keyset_id):
        if counter == 10:
            return (b"secret_unspent", b"\x01" * 32, f"HMAC-SHA256:{keyset_id}:10")
        if counter == 20:
            return (b"secret_spent", b"\x01" * 32, f"HMAC-SHA256:{keyset_id}:20")
        return (b"secret_other", b"\x01" * 32, f"HMAC-SHA256:{keyset_id}:{counter}")

    mock_wallet = SimpleNamespace(
        url="http://localhost:3337",
        load_proofs=mock_load_proofs,
        db=mock_db,
        proofs=[
            SimpleNamespace(
                id=keyset_id,
                amount=100,
                secret="secret_unspent",
                C="C_hex_unspent",
                derivation_path=f"HMAC-SHA256:{keyset_id}:10",
                pol_receipt=mock_receipt,
                dleq=None,
            )
        ],
        generate_determinstic_secret=mock_generate_determinstic_secret,
    )

    # We mock the db.fetchall inside audit to return 1 spent proof
    async def mock_fetchall_spent(query, values=None):
        return [
            {
                "amount": 100,
                "C": "C_hex_spent",
                "secret": "secret_spent",
                "id": keyset_id,
                "derivation_path": f"HMAC-SHA256:{keyset_id}:20",
                "pol_receipt": json.dumps(mock_receipt.model_dump()),
            }
        ]
    mock_db.fetchall = mock_fetchall_spent

    mock_wallet.verify_solvency = lambda k, e=None: Wallet.verify_solvency(
        mock_wallet, k, e
    )
    mock_wallet._verify_ots_anchoring = lambda o: Wallet._verify_ots_anchoring(
        mock_wallet, o
    )
    mock_wallet._verify_pol_receipt = lambda p, b_or_y: True

    obj_ctx = {
        "HOST": "http://localhost:3337",
        "WALLET_NAME": "test_wallet",
        "WALLET": mock_wallet,
    }

    runner = CliRunner()
    result = runner.invoke(pol_group, ["audit", keyset_id], obj=obj_ctx)

    assert result.exception is None
    assert "spent_inclusion_value" in result.output
    assert "Falsely registered spent amount as 42" in result.output

    # 2. Test Issued Tree Cheat Detection (issued_inclusion_value)
    # The spent proof matches value 100, but the issued promise returns value 42 instead of 100
    respx.post(f"http://localhost:3337/v1/pol/{keyset_id}/proofs/spent", json={"ys": [expected_y_spent_hex]}).mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_y_spent_hex,
                        "index": "00" * 32,
                        "value": 100,  # Valid Spent Tree value
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    respx.post(f"http://localhost:3337/v1/pol/{keyset_id}/proofs/issued").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_b_unspent_hex,
                        "index": "00" * 32,
                        "value": 42,  # Cheat!
                        "compact_mask": "0x0",
                        "siblings": [],
                    },
                    {
                        "item": expected_b_spent_hex,
                        "index": "00" * 32,
                        "value": 100,
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    result2 = runner.invoke(pol_group, ["audit", keyset_id], obj=obj_ctx)

    assert result2.exception is None
    assert "issued_inclusion_value" in result2.output
    assert "Falsely registered issued amount as 42" in result2.output


def test_pol_endpoints_rate_limiting(monkeypatch):
    keyset_id = "test_keyset_pol"
    mock_keyset = SimpleNamespace(
        id=keyset_id,
        active=False,
        private_keys={},
        final_expiry=None,
    )
    epoch_timestamp = datetime.datetime.now(datetime.timezone.utc)

    async def mock_fetchone(query, values=None):
        if "pol_epochs" in query:
            return {
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": epoch_timestamp,
                "root_issued_hash": hashlib.sha256(b"issued").hexdigest(),
                "root_issued_sum": 300,
                "root_spent_hash": hashlib.sha256(b"spent").hexdigest(),
                "root_spent_sum": 200,
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "signature": "mock_sig",
            }
        return None

    mock_db = SimpleNamespace(
        fetchone=mock_fetchone,
        execute=lambda q, v=None: None,
        table_with_schema=lambda t: t,
    )
    mock_ledger = SimpleNamespace(
        keysets={keyset_id: mock_keyset},
        db=mock_db,
        seed="test_mint_pol_private_key_seed",
        pubkey=PrivateKey(
            hashlib.sha256(b"test_mint_pol_private_key_seed").digest()
        ).public_key,
    )
    monkeypatch.setattr(router_module, "ledger", mock_ledger)

    # Set rate limits
    monkeypatch.setattr(settings, "mint_rate_limit", True)
    monkeypatch.setattr(settings, "mint_rate_limit_proxy_trust", True)

    hits = 0
    original_hit = router_module.limiter._limiter.hit
    def mock_hit(*args, **kwargs):
        nonlocal hits
        hits += 1
        if hits > 2:
            return False
        return original_hit(*args, **kwargs)
    monkeypatch.setattr(router_module.limiter._limiter, "hit", mock_hit)

    app = _build_router_app()
    client = TestClient(app)

    headers = {"CF-Connecting-IP": "203.0.113.10"}

    # Request 1 -> 200
    resp = client.get(f"/v1/pol/{keyset_id}/manifest", headers=headers)
    assert resp.status_code == 200

    # Request 2 -> 200
    resp = client.get(f"/v1/pol/{keyset_id}/manifest", headers=headers)
    assert resp.status_code == 200

    # Request 3 -> 429
    resp = client.get(f"/v1/pol/{keyset_id}/manifest", headers=headers)
    assert resp.status_code == 429


@pytest.mark.asyncio
@respx.mock
async def test_pol_endpoints_signature_verification_failure(monkeypatch):
    keyset_id = "test_keyset_pol"
    epoch_timestamp = datetime.datetime.now(datetime.timezone.utc)

    from coincurve import PrivateKey as CoincurvePrivateKey
    private_key_obj = CoincurvePrivateKey()
    public_key_obj = private_key_obj.public_key

    from cashu.core.base import WalletKeyset as RealWalletKeyset
    mock_keyset = RealWalletKeyset(
        id=keyset_id,
        public_keys={100: public_key_obj},
        unit="sat"
    )

    async def mock_fetchone(query, values=None):
        if "pol_epochs" in query:
            return {
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": epoch_timestamp,
                "root_issued_hash": "00" * 32,
                "root_spent_hash": "00" * 32,
                "root_issued_sum": 300,
                "root_spent_sum": 200,
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "signature": "mock_sig",
            }
        return None

    mock_db = SimpleNamespace(
        fetchone=mock_fetchone,
        execute=lambda q, v=None: None,
        table_with_schema=lambda t: t,
    )

    async def mock_load_proofs(reload=True):
        return None

    async def mock_generate_determinstic_secret(counter, kid):
        return (b"secret_1", b"\x01" * 32, "HMAC-SHA256:test_keyset_pol:42")

    mock_wallet = SimpleNamespace(
        url="http://localhost:3337",
        load_proofs=mock_load_proofs,
        db=mock_db,
        keysets={keyset_id: mock_keyset},
        proofs=[
            SimpleNamespace(
                id=keyset_id,
                amount=100,
                secret="secret_1",
                C="C_hex_1",
                derivation_path="HMAC-SHA256:test_keyset_pol:42",
                pol_receipt=PolReceipt(target_epoch=1, signature="bad_signature"),
                dleq=None,
            )
        ],
        generate_determinstic_secret=mock_generate_determinstic_secret,
    )

    async def mock_verify_ots_anchoring(o):
        return "OTS Attestation: Confirmed"

    mock_wallet.verify_solvency = lambda k, e=None: Wallet.verify_solvency(
        mock_wallet, k, e
    )
    mock_wallet._verify_ots_anchoring = mock_verify_ots_anchoring
    mock_wallet._verify_pol_receipt = lambda p, b_or_y: Wallet._verify_pol_receipt(
        mock_wallet, p, b_or_y
    )

    respx.get("http://localhost:3337/v1/pol/test_keyset_pol/manifest").mock(
        return_value=httpx.Response(
            200,
            json={
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": epoch_timestamp.isoformat(),
                "signing_pubkey": "00" * 33,
                "root_issued": {"hash": "00" * 32, "sum": 300},
                "root_spent": {"hash": "00" * 32, "sum": 200},
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "mint_signature": "mock_sig",
            },
        )
    )

    respx.post("http://localhost:3337/v1/pol/test_keyset_pol/proofs/spent").mock(
        return_value=httpx.Response(
            200,
            json={"proofs": []},
        )
    )

    from cashu.core.crypto.secp import PrivateKey as SecpPrivateKey
    B_, _ = b_dhke.step1_alice("secret_1", SecpPrivateKey(b"\x01" * 32))
    expected_b_hex = B_.format().hex()

    respx.post("http://localhost:3337/v1/pol/test_keyset_pol/proofs/issued").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_b_hex,
                        "index": "00" * 32,
                        "value": 100,
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    success, challenges, skipped_no_path, skipped_error, status_msg = await mock_wallet.verify_solvency(keyset_id)

    assert success is False
    assert len(challenges) == 1
    assert challenges[0]["item_type"] == "issued_receipt_signature_invalid"
    assert "Invalid signature on issued pol_receipt" in challenges[0]["error"]


@pytest.mark.asyncio
@respx.mock
async def test_pol_manifest_schnorr_signature_verification_success_and_failure(monkeypatch):
    from coincurve import PrivateKey


    keyset_id = "test_keyset_pol"
    epoch_timestamp = datetime.datetime.now(datetime.timezone.utc)
    timestamp_str = epoch_timestamp.isoformat()

    # Create dummy keys for signing
    priv_bytes = hashlib.sha256(b"manifest_test_key_seed").digest()
    priv_key = PrivateKey(priv_bytes)
    pub_key_hex = priv_key.public_key.format().hex()

    # 1. Build the valid manifest data
    keyset_id = "test_keyset_pol"
    epoch_index = 1
    root_issued_hash = "00" * 32
    root_issued_sum = 300
    root_spent_hash = "00" * 32
    root_spent_sum = 200
    outstanding_balance = 100
    ots_receipt = "010203"

    msg = f"{keyset_id}:{epoch_index}:{timestamp_str}:{root_issued_hash}:{root_issued_sum}:{root_spent_hash}:{root_spent_sum}:{outstanding_balance}:{ots_receipt}"
    valid_sig = priv_key.sign_schnorr(hashlib.sha256(msg.encode("utf-8")).digest()).hex()

    # Mock wallet setup
    from cashu.core.base import WalletKeyset as RealWalletKeyset
    mock_keyset = RealWalletKeyset(
        id=keyset_id,
        public_keys={100: priv_key.public_key},
        unit="sat"
    )

    async def mock_fetchone(query, values=None):
        return None

    mock_db = SimpleNamespace(
        fetchall=lambda q, v=None: [],
        fetchone=mock_fetchone,
        execute=lambda q, v=None: None,
        table_with_schema=lambda t: t,
    )

    async def mock_load_proofs(reload=True):
        return None

    async def mock_generate_determinstic_secret(counter, kid):
        return (b"secret_1", b"\x01" * 32, "HMAC-SHA256:test_keyset_pol:42")

    mock_wallet = SimpleNamespace(
        url="http://localhost:3337",
        load_proofs=mock_load_proofs,
        db=mock_db,
        keysets={keyset_id: mock_keyset},
        proofs=[
            SimpleNamespace(
                id=keyset_id,
                amount=100,
                secret="secret_1",
                C="C_hex_1",
                derivation_path="HMAC-SHA256:test_keyset_pol:42",
                pol_receipt=PolReceipt(target_epoch=1, signature="bad_signature"),
                dleq=None,
            )
        ],
        generate_determinstic_secret=mock_generate_determinstic_secret,
    )

    async def mock_verify_ots_anchoring(o):
        return "OTS Attestation: Confirmed"

    mock_wallet.verify_solvency = lambda k, e=None: Wallet.verify_solvency(
        mock_wallet, k, e
    )
    mock_wallet._verify_ots_anchoring = mock_verify_ots_anchoring
    mock_wallet._verify_pol_receipt = lambda p, b_or_y: True

    # Mock responses
    respx.post("http://localhost:3337/v1/pol/test_keyset_pol/proofs/spent").mock(
        return_value=httpx.Response(200, json={"proofs": []})
    )

    from cashu.core.crypto.secp import PrivateKey as SecpPrivateKey
    B_, _ = b_dhke.step1_alice("secret_1", SecpPrivateKey(b"\x01" * 32))
    expected_b_hex = B_.format().hex()

    respx.post("http://localhost:3337/v1/pol/test_keyset_pol/proofs/issued").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_b_hex,
                        "index": "00" * 32,
                        "value": 100,
                        "compact_mask": "0x0",
                        "siblings": [],
                    }
                ]
            },
        )
    )

    # Mock A: Return VALID manifest signature
    respx.get("http://localhost:3337/v1/pol/test_keyset_pol/manifest").mock(
        return_value=httpx.Response(
            200,
            json={
                "keyset_id": keyset_id,
                "epoch_index": epoch_index,
                "timestamp": timestamp_str,
                "signing_pubkey": pub_key_hex,
                "root_issued": {"hash": root_issued_hash, "sum": root_issued_sum},
                "root_spent": {"hash": root_spent_hash, "sum": root_spent_sum},
                "outstanding_balance": outstanding_balance,
                "ots_receipt": ots_receipt,
                "mint_signature": valid_sig,
            },
        )
    )

    # Should run with signature verified (fails only on the bad signature on individual receipt, NOT manifest signature!)
    success, challenges, skipped_no_path, skipped_error, status_msg = await mock_wallet.verify_solvency(keyset_id)
    assert "Manifest signature verification failed" not in status_msg

    # Mock B: Return INVALID manifest signature
    respx.get("http://localhost:3337/v1/pol/test_keyset_pol/manifest").mock(
        return_value=httpx.Response(
            200,
            json={
                "keyset_id": keyset_id,
                "epoch_index": epoch_index,
                "timestamp": timestamp_str,
                "signing_pubkey": pub_key_hex,
                "root_issued": {"hash": root_issued_hash, "sum": root_issued_sum},
                "root_spent": {"hash": root_spent_hash, "sum": root_spent_sum},
                "outstanding_balance": outstanding_balance,
                "ots_receipt": ots_receipt,
                "mint_signature": "00" * 64, # Bad signature
            },
        )
    )

    success2, challenges2, skipped_no_path2, skipped_error2, status_msg2 = await mock_wallet.verify_solvency(keyset_id)
    assert success2 is False
    assert "Manifest signature verification failed" in status_msg2





