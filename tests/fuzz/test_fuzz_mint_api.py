
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

ALLOWED_STATUS_CODES = [400, 404, 405, 422, 503]

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
    # Generates text that is safe for URLs (no control chars, no slashes)
    return st.text(alphabet=st.characters(blacklist_categories=("Cc", "Cs", "Zl", "Zp", "Cn")), min_size=min_len, max_size=max_len).filter(lambda x: "/" not in x and "\\" not in x)

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

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

# Apply skip marker to all tests in this module if deprecated API is enabled
pytestmark = pytest.mark.skipif(is_deprecated_api_only, reason="Deprecated API enabled")

# Fuzzers

@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    unit=valid_unit(),
    amount=st.integers(min_value=1, max_value=1000000),
    description=st.text(max_size=100),
    pubkey=st.one_of(st.none(), public_key(), hex_string())
)
def test_fuzz_mint_quote(client, unit, amount, description, pubkey):
    payload = {
        "unit": unit,
        "amount": amount,
        "description": description,
        "pubkey": pubkey
    }
    response = client.post("/v1/mint/quote/bolt11", json=payload)
    assert response.status_code in ALLOWED_STATUS_CODES + [200]

@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    quote=st.text(min_size=1, max_size=50),
    outputs=st.lists(blinded_message_strategy, min_size=1, max_size=10),
    signature=st.one_of(st.none(), hex_string(132, 132))
)
def test_fuzz_mint(client, quote, outputs, signature):
    outputs_json = [o.model_dump() for o in outputs]
    payload = {
        "quote": quote,
        "outputs": outputs_json,
        "signature": signature
    }
    response = client.post("/v1/mint/bolt11", json=payload)
    assert response.status_code in ALLOWED_STATUS_CODES

@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    unit=valid_unit(),
    request=st.text(min_size=10, max_size=500), # Bolt11 invoice simulation
    options=st.none()
)
def test_fuzz_melt_quote(client, unit, request, options):
    payload = {
        "unit": unit,
        "request": request,
        "options": options
    }
    response = client.post("/v1/melt/quote/bolt11", json=payload)
    assert response.status_code in ALLOWED_STATUS_CODES

@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    quote=st.text(min_size=1, max_size=50),
    inputs=st.lists(proof_strategy, min_size=1, max_size=10),
    outputs=st.one_of(st.none(), st.lists(blinded_message_strategy, min_size=1, max_size=5))
)
def test_fuzz_melt(client, quote, inputs, outputs):
    inputs_json = [i.model_dump(exclude={'dleq', 'witness'}) for i in inputs]
    outputs_json = [o.model_dump() for o in outputs] if outputs else None
    
    payload = {
        "quote": quote,
        "inputs": inputs_json,
        "outputs": outputs_json
    }
    response = client.post("/v1/melt/bolt11", json=payload)
    assert response.status_code in ALLOWED_STATUS_CODES

@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    inputs=st.lists(proof_strategy, min_size=1, max_size=10),
    outputs=st.lists(blinded_message_strategy, min_size=1, max_size=10)
)
def test_fuzz_swap(client, inputs, outputs):
    inputs_json = [i.model_dump() for i in inputs]
    outputs_json = [o.model_dump() for o in outputs]
    payload = {
        "inputs": inputs_json,
        "outputs": outputs_json
    }
    response = client.post("/v1/swap", json=payload)
    assert response.status_code in ALLOWED_STATUS_CODES

@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    Ys=st.lists(st.one_of(hex_string(), public_key()), min_size=1, max_size=20)
)
def test_fuzz_checkstate(client, Ys):
    payload = {
        "Ys": Ys
    }
    response = client.post("/v1/checkstate", json=payload)
    assert response.status_code in ALLOWED_STATUS_CODES

@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(
    outputs=st.lists(blinded_message_strategy, min_size=1, max_size=20)
)
def test_fuzz_restore(client, outputs):
    outputs_json = [o.model_dump() for o in outputs]
    payload = {
        "outputs": outputs_json
    }
    response = client.post("/v1/restore", json=payload)
    assert response.status_code in ALLOWED_STATUS_CODES

# GET Endpoints - using url_safe_text and try/except

@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(keyset_id=url_safe_text())
def test_fuzz_keys_keyset_id(client, keyset_id):
    response = client.get(f"/v1/keys/{keyset_id}")
    assert response.status_code in ALLOWED_STATUS_CODES

@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(quote=url_safe_text(max_len=50))
def test_fuzz_mint_quote_get(client, quote):
    response = client.get(f"/v1/mint/quote/bolt11/{quote}")
    assert response.status_code in ALLOWED_STATUS_CODES

@hypothesis_settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(quote=url_safe_text(max_len=50))
def test_fuzz_melt_quote_get(client, quote):
    response = client.get(f"/v1/melt/quote/bolt11/{quote}")
    assert response.status_code in ALLOWED_STATUS_CODES
