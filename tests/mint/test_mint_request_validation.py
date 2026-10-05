from typing import Annotated
from unittest.mock import Mock

import pytest
from pydantic import BeforeValidator, TypeAdapter, ValidationError

from cashu.core.base import Proof
from cashu.core.models import PostMeltRequest, PostSwapRequest
from cashu.core.settings import settings
from cashu.mint.validation import validate_input_secret_lengths

POINT = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


@pytest.mark.parametrize(
    "model,fields", [(PostSwapRequest, {}), (PostMeltRequest, {"quote": "quote"})]
)
@pytest.mark.parametrize("input_kind", ["dict", "proof", "constructed_proof", "bytes"])
def test_mint_request_rejects_long_secret_before_hashing(
    monkeypatch, model, fields, input_kind
):
    proof = {
        "id": "00deadbeefdeadbe",
        "amount": 1,
        "C": POINT,
        "secret": "x" * (settings.mint_max_secret_length + 1),
    }
    if input_kind == "proof":
        value = Proof(**proof)
    elif input_kind == "constructed_proof":
        value = Proof.model_construct(**proof)
    elif input_kind == "bytes":
        value = {**proof, "secret": proof["secret"].encode()}
    else:
        value = proof
    hashed = Mock(side_effect=AssertionError("rejected secret must not be hashed"))
    monkeypatch.setattr("cashu.core.base.hash_to_curve", hashed)
    adapter = TypeAdapter(Annotated[model, BeforeValidator(validate_input_secret_lengths)])

    with pytest.raises(ValidationError) as exc:
        adapter.validate_python({**fields, "inputs": [value], "outputs": []})

    assert exc.value.errors(include_input=False)[0]["loc"] == ("inputs", 0, "secret")
    assert exc.value.errors(include_input=False)[0]["type"] == "string_too_long"
    hashed.assert_not_called()


@pytest.mark.parametrize(
    "model,fields", [(PostSwapRequest, {}), (PostMeltRequest, {"quote": "quote"})]
)
@pytest.mark.parametrize("secret_character", ["a", "😀"])
@pytest.mark.parametrize("as_bytes", [False, True])
def test_mint_request_secret_limit_accepts_boundary(
    model, fields, secret_character, as_bytes
):
    secret = secret_character * settings.mint_max_secret_length
    proof = {
        "id": "00deadbeefdeadbe",
        "amount": 1,
        "C": POINT,
        "secret": secret.encode() if as_bytes else secret,
    }
    adapter = TypeAdapter(Annotated[model, BeforeValidator(validate_input_secret_lengths)])
    request = adapter.validate_python({**fields, "inputs": [proof], "outputs": []})

    assert type(request.inputs[0]) is Proof
    assert request.inputs[0].secret == secret
    assert request.inputs[0].Y == Proof(**proof).Y


def test_mint_request_reports_all_long_secrets_before_hashing(monkeypatch):
    valid = {"secret": "valid"}
    invalid = {"secret": "x" * (settings.mint_max_secret_length + 1)}
    hashed = Mock(side_effect=AssertionError("rejected request must not hash any proof"))
    monkeypatch.setattr("cashu.core.base.hash_to_curve", hashed)
    adapter = TypeAdapter(
        Annotated[PostSwapRequest, BeforeValidator(validate_input_secret_lengths)]
    )

    with pytest.raises(ValidationError) as exc:
        adapter.validate_python({"inputs": [invalid, valid, invalid], "outputs": []})

    assert [error["loc"] for error in exc.value.errors(include_input=False)] == [
        ("inputs", 0, "secret"),
        ("inputs", 2, "secret"),
    ]
    hashed.assert_not_called()


@pytest.mark.parametrize(
    "body,location",
    [
        ([], ()),
        ({"inputs": None, "outputs": []}, ("inputs",)),
        ({"inputs": "invalid", "outputs": []}, ("inputs",)),
        ({"inputs": [None], "outputs": []}, ("inputs", 0)),
        ({"inputs": [{"secret": None}], "outputs": []}, ("inputs", 0, "secret")),
        ({"inputs": [{"secret": 123}], "outputs": []}, ("inputs", 0, "secret")),
    ],
)
def test_mint_request_preserves_structural_validation_errors(body, location):
    adapter = TypeAdapter(
        Annotated[PostSwapRequest, BeforeValidator(validate_input_secret_lengths)]
    )

    with pytest.raises(ValidationError) as exc:
        adapter.validate_python(body)

    assert exc.value.errors(include_input=False)[0]["loc"] == location
