import secrets

import pytest

from cashu.core.base import BlindedMessage, Proof
from cashu.core.errors import (
    TransactionMaxInputsExceededError,
    TransactionMaxOutputsExceededError,
    WitnessTooLongError,
)
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from tests.helpers import assert_err


@pytest.mark.asyncio
async def test_max_inputs_exceeded(ledger: Ledger, monkeypatch):
    monkeypatch.setattr(settings, "mint_max_inputs", 1)
    p1 = Proof.from_dict(
        {
            "amount": 8,
            "secret": "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            "C": "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904",
            "id": "009a1f293253e41e",
        }
    )
    p2 = Proof.from_dict(
        {
            "amount": 8,
            "secret": "77798aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2926",
            "C": "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904",
            "id": "009a1f293253e41e",
        }
    )

    await assert_err(
        ledger.verify_inputs_and_outputs(proofs=[p1, p2], outputs=None),
        TransactionMaxInputsExceededError(),
    )


@pytest.mark.asyncio
async def test_max_outputs_exceeded(ledger: Ledger, monkeypatch):
    monkeypatch.setattr(settings, "mint_max_outputs", 1)
    kid = next(iter(ledger.keysets.keys()))
    outputs = [
        BlindedMessage(id=kid, amount=8, B_="02" + "00" * 32),
        BlindedMessage(id=kid, amount=8, B_="02" + "11" * 32),
    ]

    await assert_err(
        ledger._verify_outputs(outputs),
        TransactionMaxOutputsExceededError(),
    )


@pytest.mark.asyncio
async def test_restore_max_outputs_exceeded(ledger: Ledger, monkeypatch):
    monkeypatch.setattr(settings, "mint_max_outputs", 1)
    kid = next(iter(ledger.keysets.keys()))
    outputs = [
        BlindedMessage(id=kid, amount=8, B_="02" + "00" * 32),
        BlindedMessage(id=kid, amount=8, B_="02" + "11" * 32),
    ]

    await assert_err(
        ledger.restore(outputs),
        TransactionMaxOutputsExceededError(),
    )


@pytest.mark.asyncio
async def test_witness_too_long(ledger: Ledger):
    proof = Proof.from_dict(
        {
            "amount": 8,
            "secret": "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            "C": "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904",
            "id": "009a1f293253e41e",
            "witness": secrets.token_hex(5000),
        }
    )

    await assert_err(
        ledger.verify_inputs_and_outputs(proofs=[proof], outputs=[]),
        WitnessTooLongError(),
    )


@pytest.mark.asyncio
async def test_witness_without_spending_condition(ledger: Ledger):
    proof = Proof.from_dict(
        {
            "amount": 8,
            "secret": "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            "C": "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904",
            "id": "009a1f293253e41e",
            "witness": secrets.token_hex(50),
        }
    )

    try:
        ledger._verify_input_spending_conditions(proof)
    except Exception as exc:
        error_message: str = str(exc.args[0])
        expected_error = "witness data not allowed without a spending condition"
        if expected_error not in error_message:
            raise Exception(f"Expected error: {expected_error}, got: {error_message}")
        return

    raise Exception(
        "Expected error: witness data not allowed without a spending condition, got no error"
    )
