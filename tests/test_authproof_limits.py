import base64
import json
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from cashu.core.base import AuthProof
from cashu.core.constants import MAX_KEYSET_ID_LEN, MAX_PUBKEY_LEN
from cashu.core.settings import settings

POINT = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def test_auth_token_rejects_length_before_decoding(monkeypatch):
    decoded = Mock(side_effect=AssertionError("overlong token must not be decoded"))
    monkeypatch.setattr("cashu.core.base.base64.urlsafe_b64decode", decoded)
    token = AuthProof.prefix + "a" * AuthProof.max_token_length()

    with pytest.raises(ValueError, match="token too long"):
        AuthProof.from_base64(token)

    decoded.assert_not_called()


@pytest.mark.parametrize(
    "field,limit", [("id", MAX_KEYSET_ID_LEN), ("C", MAX_PUBKEY_LEN)]
)
def test_auth_token_rejects_long_nested_fields(field, limit):
    payload = {"id": "00deadbeefdeadbe", "C": POINT, "secret": "secret"}
    payload[field] = "a" * (limit + 1)
    token = (
        AuthProof.prefix
        + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    )

    with pytest.raises(ValidationError) as exc:
        AuthProof.from_base64(token)

    assert exc.value.errors(include_input=False)[0]["loc"] == (field,)


def test_auth_token_rejects_long_secret_before_proof_conversion(monkeypatch):
    payload = {
        "id": "00deadbeefdeadbe",
        "C": POINT,
        "secret": "x" * (settings.mint_max_secret_length + 1),
    }
    token = (
        AuthProof.prefix
        + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    )
    hashed = Mock(side_effect=AssertionError("rejected secret must not be hashed"))
    monkeypatch.setattr("cashu.core.base.hash_to_curve", hashed)

    with pytest.raises(ValidationError) as exc:
        AuthProof.from_base64(token).to_proof()

    assert exc.value.errors(include_input=False)[0]["loc"] == ("secret",)
    hashed.assert_not_called()


@pytest.mark.parametrize("secret_character", ["a", "é", "😀", '"', "\\"])
@pytest.mark.parametrize("padded", [False, True])
def test_auth_token_limit_accepts_maximum_valid_fields(secret_character, padded):
    proof = AuthProof(
        id="01" + "11" * 32,
        C=POINT,
        secret=secret_character * settings.mint_max_secret_length,
    )
    token = proof.to_base64()
    if padded:
        token += "=" * (-len(token[len(AuthProof.prefix) :]) % 4)

    assert len(token) <= AuthProof.max_token_length()
    assert AuthProof.from_base64(token) == proof
