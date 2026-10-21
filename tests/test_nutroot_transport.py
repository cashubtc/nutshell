import copy
import hashlib
import json
from pathlib import Path

import pytest

from cashu.core.base import NutrootOption, PaymentRequest, ProofState, TokenV4
from cashu.core.crypto.nutroot import (
    NUTROOT_NUMS,
    NutrootLeaf,
    serialize_nutroot_leaf,
    tlv_record,
)
from cashu.core.crypto.secp import PrivateKey
from cashu.core.crypto.transcript import (
    TransactionShape,
    TranscriptQuote,
    build_transaction_transcript,
    parse_transaction_transcript,
)
from cashu.core.nutroot import create_requested_nutroot_output
from cashu.core.nuts import nut18, nut26
from cashu.core.nuts.nut10_transport import SigningPackage, SpendReceipt

VECTORS = json.loads(
    Path(__file__).with_name("nutroot_wallet_vectors.json").read_text()
)


def test_payment_request_wire_vectors():
    request = PaymentRequest.model_validate(VECTORS["request"])
    assert nut26.serialize(request) == VECTORS["request_creqb"]
    assert nut26.deserialize(VECTORS["request_creqb"]) == request
    nums_request = PaymentRequest.model_validate(VECTORS["nums_request"])
    assert nut18.deserialize(VECTORS["nums_request_creqA"]) == nums_request
    assert nut18.serialize(nums_request) == VECTORS["nums_request_creqA"].rstrip("=")


@pytest.mark.parametrize("blind,offset,index", [(True, 7, 0), (False, 9, 1)])
def test_nums_output_matches_independent_spec_vectors(blind, offset, index):
    request = PaymentRequest.model_validate(VECTORS["nums_request"]).nutroot
    if not blind:
        request = request.model_copy(update={"b": None})
    secret, info = create_requested_nutroot_output(
        request,
        ephemeral_key=PrivateKey((5).to_bytes(32, "big")) if blind else None,
        nums_offset=PrivateKey(offset.to_bytes(32, "big")),
    )
    expected = VECTORS["nums_outputs"][index]
    assert secret == expected["secret"]
    assert info.model_dump(exclude_none=True) == expected["spend_info"]


def test_signing_package_signs_and_merges_the_spec_transaction():
    package = SigningPackage.model_validate(VECTORS["signing_package"])
    package.contexts()
    decoded = SigningPackage.deserialize(package.serialize())
    assert decoded == package
    signed = decoded.sign([PrivateKey((3).to_bytes(32, "big"))])
    assert len(signed.spends[0].signatures) == 1
    witnesses = package.merge(
        [signed], expected_transcript=bytes.fromhex(package.transcript)
    )
    assert len(json.loads(witnesses[0])["signatures"]) == 1
    assert package.spends[0].signatures == []


@pytest.mark.parametrize("change", ["input", "secret", "leaf", "partial_signature"])
def test_signer_rejects_a_misidentified_or_invalid_spend(change):
    data = copy.deepcopy(VECTORS["signing_package"])
    spend = data["spends"][0]
    if change == "input":
        spend["input"] = 1
    elif change == "secret":
        spend["secret"] = PrivateKey((5).to_bytes(32, "big")).public_key.format().hex()
    elif change == "leaf":
        spend["leaf"] = "00ff"
    else:
        spend["signatures"] = ["00" * 64]
    with pytest.raises(Exception):
        SigningPackage.model_validate(data).sign([PrivateKey((3).to_bytes(32, "big"))])


def test_package_merge_requires_the_original_transaction():
    package = SigningPackage.model_validate(VECTORS["signing_package"])
    signed = package.sign([PrivateKey((3).to_bytes(32, "big"))])
    with pytest.raises(ValueError, match="different transaction"):
        package.merge([signed], expected_transcript=b"another transaction")


def test_quote_signing_package_keeps_hashlock_preimage_with_the_creator():
    key = PrivateKey((3).to_bytes(32, "big"))
    preimage = b"\x07" * 32
    leaf = serialize_nutroot_leaf(
        NutrootLeaf(
            type="hashlock",
            n=1,
            keys=[key.public_key],
            hash=hashlib.sha256(preimage).digest(),
        )
    )
    secret, info = create_requested_nutroot_output(
        NutrootOption(k=NUTROOT_NUMS.format().hex(), l=[leaf.hex()])
    )
    transcript = build_transaction_transcript(
        TransactionShape(
            mint_quote_inputs=[
                TranscriptQuote(
                    amount=8,
                    quote_id="mint-quote",
                    pubkey=bytes.fromhex(secret),
                    issued=4,
                )
            ],
            melt_quote_outputs=[TranscriptQuote(amount=8, quote_id="melt-quote")],
        )
    )
    package = SigningPackage.model_validate(
        {
            "transcript": transcript.hex(),
            "spends": [
                {
                    "input": 0,
                    "secret": secret,
                    "leaf": leaf.hex(),
                    "control": {"K": info.K, "path": []},
                }
            ],
        }
    )
    signed = package.sign([key])
    assert "preimage" not in signed.model_dump_json()
    with pytest.raises(ValueError, match="preimage"):
        package.merge([signed], expected_transcript=transcript)
    witness = package.merge(
        [signed], expected_transcript=transcript, preimages={0: preimage}
    )
    assert json.loads(witness[0])["preimage"] == preimage.hex()


def test_receipt_opens_the_spec_commitment_and_roundtrips():
    receipt = SpendReceipt.model_validate(VECTORS["receipt"])
    commitments = {entry.Y: entry.commitment for entry in receipt.receipts}
    receipt.verify(commitments)
    decoded = SpendReceipt.deserialize(receipt.serialize())
    assert decoded == receipt
    decoded.verify(commitments)
    with pytest.raises(ValueError, match="mint's spend commitment"):
        receipt.verify({receipt.receipts[0].Y: "00" * 32})


def test_receipt_verifies_against_unhashed_status_evidence():
    receipt = SpendReceipt.model_validate(VECTORS["receipt"])
    states = [
        ProofState(Y=entry.Y, state="SPENT", witness=entry.witness, input_digest=entry.input_digest)
        for entry in receipt.receipts
    ]
    receipt.verify_states(states)
    states[0].witness += " "
    with pytest.raises(ValueError, match="mint's spend commitment"):
        receipt.verify_states(states)
    states[0].state = states[0].state.pending
    with pytest.raises(ValueError, match="SPENT"):
        receipt.verify_states(states)


@pytest.mark.parametrize("change", ["witness", "digest", "proof", "transcript"])
def test_receipt_rejects_modified_evidence(change):
    receipt = SpendReceipt.model_validate(VECTORS["receipt"])
    commitments = {entry.Y: entry.commitment for entry in receipt.receipts}
    entry = receipt.receipts[0]
    if change == "witness":
        entry.witness += " "
    elif change == "digest":
        entry.input_digest = "00" * 32
    elif change == "proof":
        entry.Y = "00" * 48
    else:
        entry.transcript += tlv_record(0x23, b"").hex()
    with pytest.raises(ValueError):
        receipt.verify(commitments)


def test_receipt_creation_retains_the_exact_witness():
    vector = SpendReceipt.model_validate(VECTORS["receipt"])
    token = TokenV4.deserialize(vector.token)
    proof = token.proofs[0]
    proof.id = vector.receipts[0].keyset_id
    proof.witness = vector.receipts[0].witness
    receipt = SpendReceipt.create(
        token, bytes.fromhex(vector.receipts[0].transcript), [proof]
    )
    assert receipt.receipts[0] == vector.receipts[0]
    receipt.verify({entry.Y: entry.commitment for entry in vector.receipts})


def test_transaction_parser_refuses_containers_outside_the_scoped_specs():
    raw = bytes.fromhex(VECTORS["signing_package"]["transcript"])
    for container_type in (0x23, 0xF1, 0xFF):
        with pytest.raises(ValueError, match="container"):
            parse_transaction_transcript(raw + tlv_record(container_type, b""))
