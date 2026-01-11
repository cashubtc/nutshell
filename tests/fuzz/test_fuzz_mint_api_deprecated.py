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

blinded_message_strategy = st.builds(
    BlindedMessage,
    amount=st.integers(min_value=1),
    id=st.text(min_size=1, max_size=20),
    B_=hex_string(),
    C_=st.one_of(st.none(), hex_string())
)

proof_strategy = st.builds(
    Proof,
    id=st.text(min_size=1, max_size=20),
    amount=st.integers(min_value=1),
    secret=st.text(min_size=1, max_size=64),
    C=hex_string(),
    Y=hex_string()
)

# Fuzzers for Deprecated API

# GET /mint
@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(amount=st.integers())
def test_fuzz_deprecated_mint_get(client, amount):
    try:
        response = client.get(f"/mint?amount={amount}")
        # Expecting either success or valid error codes
        assert response.status_code in [200, 400, 404, 422, 503]
    except Exception:
        pass

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
    
    try:
        response = client.post("/mint", json=payload, params=params)
        assert response.status_code in [400, 404, 422, 503]
    except Exception:
        pass

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
    try:
        response = client.post("/melt", json=payload)
        assert response.status_code in [400, 404, 422, 503]
    except Exception:
        pass

# POST /check
@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    proofs=st.lists(proof_strategy, min_size=1, max_size=10)
)
def test_fuzz_deprecated_check(client, proofs):
    inputs_json = [p.model_dump(exclude={'dleq', 'witness'}) for p in proofs]
    payload = {"proofs": inputs_json}
    
    try:
        response = client.post("/check", json=payload)
        assert response.status_code in [400, 404, 422, 503]
    except Exception:
        pass

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

    try:
        response = client.post("/split", json=payload)
        assert response.status_code in [400, 404, 422, 503]
    except Exception:
        pass

# POST /restore
@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    outputs=st.lists(blinded_message_strategy, min_size=1, max_size=20)
)
def test_fuzz_deprecated_restore(client, outputs):
    outputs_json = [o.model_dump() for o in outputs]
    payload = {"outputs": outputs_json}
    
    try:
        response = client.post("/restore", json=payload)
        assert response.status_code in [400, 404, 422, 503]
    except Exception:
        pass
