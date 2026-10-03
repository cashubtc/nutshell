from copy import deepcopy
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from cashu.core.base import BlindedMessage, BlindedSignature, Proof
from cashu.core.constants import MAX_PUBKEY_LEN, MAX_QUOTE_ID_LEN, MAX_SIG_LEN
from cashu.core.json_rpc.base import (
    JSONRPCNotficationParams,
    JSONRPCSubscribeParams,
    JSONRPCUnsubscribeParams,
    JSONRRPCSubscribeResponse,
)
from cashu.core.models import (
    PostAuthBlindMintRequest,
    PostMeltRequest,
    PostMintBatchRequest,
    PostMintRequest,
    PostRestoreRequest,
    PostRestoreResponse,
    PostSwapRequest,
)
from cashu.core.models.proof import ProofInput
from cashu.core.settings import settings

POINT = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
OUTPUT = {"id": "00deadbeefdeadbe", "amount": 1, "B_": POINT}
SIGNATURE = {
    "id": "00deadbeefdeadbe",
    "amount": 1,
    "C_": POINT,
    "dleq": {"e": "11" * 32, "s": "22" * 32},
}


@pytest.mark.parametrize(
    "model,fields",
    [
        (PostMintBatchRequest, {"quotes": ["unpaid-quote"]}),
        (PostSwapRequest, {"inputs": []}),
        (PostMintRequest, {"quote": "unpaid-quote"}),
        (PostMeltRequest, {"quote": "unpaid-quote", "inputs": []}),
        (PostAuthBlindMintRequest, {}),
        (PostRestoreRequest, {}),
    ],
)
@pytest.mark.parametrize("field", ["id", "B_", "C_"])
@pytest.mark.parametrize("length", [MAX_PUBKEY_LEN + 1, 2_000_002])
def test_requests_reject_oversized_blinded_message(model, fields, field, length):
    output = {**OUTPUT, field: "a" * length}

    with pytest.raises(ValidationError) as exc:
        model.model_validate({**fields, "outputs": [output]})

    assert exc.value.errors(include_input=False)[0]["loc"] == ("outputs", 0, field)


@pytest.mark.parametrize(
    "keyset_id", ["a+/BCDefgh12", "00deadbeefdeadbe", "01" + "11" * 32]
)
def test_blinded_models_accept_supported_keyset_ids_and_points(keyset_id):
    output = BlindedMessage(**{**OUTPUT, "id": keyset_id, "C_": POINT})
    signature = BlindedSignature(**{**SIGNATURE, "id": keyset_id})

    assert output.id == signature.id == keyset_id
    assert output.B_ == output.C_ == signature.C_ == POINT
    assert BlindedMessage(**OUTPUT).C_ is None


@pytest.mark.parametrize(
    "path,limit",
    [(("id",), 66), (("C_",), 66), (("dleq", "e"), 64), (("dleq", "s"), 64)],
)
@pytest.mark.parametrize("extra", [1, 2_000_000])
def test_restore_rejects_oversized_signature_fields(path, limit, extra):
    signature = deepcopy(SIGNATURE)
    target = signature
    for field in path[:-1]:
        target = target[field]
    target[path[-1]] = "a" * (limit + extra)

    with pytest.raises(ValidationError) as exc:
        PostRestoreResponse.model_validate(
            {"outputs": [OUTPUT], "signatures": [signature]}
        )

    assert exc.value.errors(include_input=False)[0]["loc"] == ("signatures", 0, *path)


@pytest.mark.parametrize("field,item", [("outputs", OUTPUT), ("signatures", SIGNATURE)])
def test_restore_response_bounds_arrays(field, item):
    limit = settings.mint_max_request_length
    assert (
        len(getattr(PostRestoreResponse.model_validate({field: [item] * limit}), field))
        == limit
    )

    with pytest.raises(ValidationError) as exc:
        PostRestoreResponse.model_validate({field: [item] * (limit + 1)})

    assert exc.value.errors(include_input=False)[0]["loc"] == (field,)
    assert exc.value.errors(include_input=False)[0]["type"] == "too_long"


def test_restore_response_accepts_empty_and_valid_responses():
    empty = PostRestoreResponse()
    restored = PostRestoreResponse.model_validate(
        {"outputs": [OUTPUT], "signatures": [SIGNATURE]}
    )

    assert empty.outputs == empty.signatures == []
    assert restored.outputs[0].B_ == restored.signatures[0].C_ == POINT
    assert restored.signatures[0].dleq.e == SIGNATURE["dleq"]["e"]
    assert restored.signatures[0].dleq.s == SIGNATURE["dleq"]["s"]


@pytest.mark.parametrize("length", [MAX_SIG_LEN + 1, 2_000_000])
def test_batch_mint_rejects_long_quote_signatures(length):
    with pytest.raises(ValidationError) as exc:
        PostMintBatchRequest(quotes=["quote"], outputs=[], signatures=["a" * length])

    assert exc.value.errors(include_input=False)[0]["loc"] == ("signatures", 0)


@pytest.mark.parametrize("signatures", [None, [], [None], ["a" * MAX_SIG_LEN, None]])
def test_batch_mint_preserves_optional_quote_signatures(signatures):
    request = PostMintBatchRequest(quotes=["quote"], outputs=[], signatures=signatures)
    assert request.signatures == signatures


@pytest.mark.parametrize(
    "model,fields", [(PostSwapRequest, {}), (PostMeltRequest, {"quote": "quote"})]
)
@pytest.mark.parametrize("input_kind", ["dict", "proof", "request_proof", "bytes"])
def test_request_rejects_long_secret_before_hashing(
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
    elif input_kind == "request_proof":
        value = ProofInput.model_construct(**proof)
    elif input_kind == "bytes":
        value = {**proof, "secret": proof["secret"].encode()}
    else:
        value = proof
    hashed = Mock(side_effect=AssertionError("rejected secret must not be hashed"))
    monkeypatch.setattr("cashu.core.base.hash_to_curve", hashed)

    with pytest.raises(ValidationError) as exc:
        model.model_validate({**fields, "inputs": [value], "outputs": []})

    assert exc.value.errors(include_input=False)[0]["loc"] == ("inputs", 0, "secret")
    assert exc.value.errors(include_input=False)[0]["type"] == "string_too_long"
    hashed.assert_not_called()


@pytest.mark.parametrize(
    "model,fields", [(PostSwapRequest, {}), (PostMeltRequest, {"quote": "quote"})]
)
@pytest.mark.parametrize("secret_character", ["a", "😀"])
def test_request_secret_limit_accepts_boundary(model, fields, secret_character):
    proof = {
        "id": "00deadbeefdeadbe",
        "amount": 1,
        "C": POINT,
        "secret": secret_character * settings.mint_max_secret_length,
    }
    request = model.model_validate({**fields, "inputs": [proof], "outputs": []})
    assert request.inputs[0].secret == proof["secret"]
    assert request.inputs[0].Y == Proof(**proof).Y


@pytest.mark.parametrize(
    "model,fields", [(PostSwapRequest, {}), (PostMeltRequest, {"quote": "quote"})]
)
def test_request_preserves_existing_wallet_proof(monkeypatch, model, fields):
    proof = Proof(
        id="00deadbeefdeadbe",
        amount=1,
        C=POINT,
        secret="secret",
        dleq={"e": "11" * 32, "s": "22" * 32, "r": "33" * 32},
        witness='{"signatures":[]}',
        p2pk_e=POINT,
        reserved=True,
        send_id="send-id",
        time_created=123,
        time_reserved="456",
        derivation_path="m/0'/0'/0'",
        mint_id="mint-id",
        melt_id="melt-id",
    )
    hashed = Mock(side_effect=AssertionError("existing proof must not be rehashed"))
    monkeypatch.setattr("cashu.core.base.hash_to_curve", hashed)

    request = model.model_validate({**fields, "inputs": [proof], "outputs": []})

    assert request.inputs[0].model_dump() == proof.model_dump()
    hashed.assert_not_called()


@pytest.mark.parametrize(
    "model,fields",
    [
        (JSONRPCSubscribeParams, {"kind": "proof_state", "filters": [POINT]}),
        (JSONRPCUnsubscribeParams, {}),
        (JSONRPCNotficationParams, {"payload": {}}),
        (JSONRRPCSubscribeResponse, {"status": "OK"}),
    ],
)
def test_subscription_id_lengths_are_consistent(model, fields):
    assert model(subId="s" * MAX_QUOTE_ID_LEN, **fields).subId == "s" * MAX_QUOTE_ID_LEN
    with pytest.raises(ValidationError) as exc:
        model(subId="s" * (MAX_QUOTE_ID_LEN + 1), **fields)
    assert exc.value.errors(include_input=False)[0]["loc"] == ("subId",)
