import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from cashu.core.models import (
    BlindedMessage,
    Proof,
)
from cashu.mint.app import app
from tests.helpers import is_deprecated_api_only

# Apply skip marker to all tests in this module if deprecated API is NOT enabled
pytestmark = pytest.mark.skipif(not is_deprecated_api_only, reason="Deprecated API not enabled")

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

# Define strategies
def hex_string(min_len=66, max_len=66):
    return st.text(alphabet="0123456789abcdef", min_size=min_len, max_size=max_len)

def valid_unit():
    return st.sampled_from(["sat", "usd", "eur", "msat"])

def public_key():
    return st.builds(lambda a, b: a + b, st.just("02"), hex_string(64, 64))

def keyset_id():
    return st.builds(lambda a, b: a + b, st.just("00"), hex_string(14, 14))

def url_safe_text(min_len=1, max_len=20):
    # Generates text that is safe for URLs (no control chars, no slashes, no #, no ?)
    return st.text(alphabet=st.characters(blacklist_categories=("Cc", "Cs", "Zl", "Zp", "Cn")), min_size=min_len, max_size=max_len).filter(lambda x: "/" not in x and "\\" not in x and "#" not in x and "?" not in x)

# Strategy for BlindedMessage
blinded_message_strategy = st.builds(
    BlindedMessage,
    amount=st.integers(min_value=1),
    id=st.one_of(keyset_id(), hex_string(16, 16)),
    B_=st.one_of(hex_string(), public_key()),
    C_=st.one_of(st.none(), public_key(), hex_string())
)

# Strategy for Proof
proof_strategy = st.builds(
    Proof,
    id=st.one_of(keyset_id(), hex_string(16, 16)),
    amount=st.integers(min_value=1),
    secret=st.text(min_size=1, max_size=64),
    C=st.one_of(hex_string(), public_key()),
    Y=st.one_of(public_key(), hex_string())
)

# Fuzzers for Deprecated API

# GET /mint
@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(amount=st.integers())
def test_fuzz_deprecated_mint_get(client, amount):
    response = client.get(f"/mint?amount={amount}")
    # Expecting either success or valid error codes
    assert response.status_code in [200, 400, 404, 422, 503]

# POST /mint
@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    outputs=st.lists(blinded_message_strategy, min_size=1, max_size=10),
    hash=st.one_of(st.none(), st.text(min_size=1, max_size=64))
)
def test_fuzz_deprecated_mint_post(client, outputs, hash):
    outputs_json = [o.model_dump() for o in outputs]
    payload = {"outputs": outputs_json}
    params = {}
    if hash:
        params["hash"] = hash
    
    response = client.post("/mint", json=payload, params=params)
    assert response.status_code in [400, 404, 422, 503]

# POST /melt
@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    pr=st.text(min_size=1, max_size=500),
    proofs=st.lists(proof_strategy, min_size=1, max_size=10),
    outputs=st.one_of(st.none(), st.lists(blinded_message_strategy, min_size=1, max_size=5))
)
def test_fuzz_deprecated_melt(client, pr, proofs, outputs):
    inputs_json = [p.model_dump(exclude={'dleq', 'witness'}) for p in proofs]
    outputs_json = [o.model_dump() for o in outputs] if outputs else None
    
    payload = {
        "pr": pr,
        "proofs": inputs_json,
        "outputs": outputs_json
    }
    response = client.post("/melt", json=payload)
    assert response.status_code in [400, 404, 422, 503]

# POST /check
@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    proofs=st.lists(proof_strategy, min_size=1, max_size=10)
)
def test_fuzz_deprecated_check(client, proofs):
    inputs_json = [p.model_dump(exclude={'dleq', 'witness'}) for p in proofs]
    payload = {"proofs": inputs_json}
    
    response = client.post("/check", json=payload)
    if response.status_code == 200:
        data = response.json()
        # For random proofs (unknown to mint), they are considered UNSPENT
        # So spendable should be True, pending should be False
        assert len(data["spendable"]) == len(proofs)
        assert len(data["pending"]) == len(proofs)
        assert all(data["spendable"])
        assert not any(data["pending"])
    else:
        assert response.status_code in [400, 404, 422, 503]

# POST /split
@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    proofs=st.lists(proof_strategy, min_size=1, max_size=10),
    outputs=st.lists(blinded_message_strategy, min_size=1, max_size=10),
    amount=st.one_of(st.none(), st.integers(min_value=1))
)
def test_fuzz_deprecated_split(client, proofs, outputs, amount):
    inputs_json = [p.model_dump(exclude={'dleq', 'witness'}) for p in proofs]
    outputs_json = [o.model_dump() for o in outputs]
    
    payload = {
        "proofs": inputs_json,
        "outputs": outputs_json
    }
    if amount is not None:
        payload["amount"] = amount

    response = client.post("/split", json=payload)
    assert response.status_code in [400, 404, 422, 503]

# POST /restore
@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    outputs=st.lists(blinded_message_strategy, min_size=1, max_size=20)
)
def test_fuzz_deprecated_restore(client, outputs):
    outputs_json = [o.model_dump() for o in outputs]
    payload = {"outputs": outputs_json}
    
    response = client.post("/restore", json=payload)
    if response.status_code == 200:
        data = response.json()
        assert data["outputs"] == []
        assert data["signatures"] == []
    else:
        assert response.status_code in [400, 404, 422, 503]
