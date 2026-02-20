import secrets

import pytest

from cashu.core.base import Proof
from cashu.core.errors import WitnessTooLongError
from cashu.mint.ledger import Ledger
from tests.helpers import assert_err


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
