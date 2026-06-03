import math
from types import SimpleNamespace

import pytest

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Method, Proof, Unit
from cashu.lightning.base import PaymentResponse, PaymentResult, PaymentStatus
from cashu.mint.ledger import Ledger


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("unit", "fee_reserve", "expected_fee_limit_msat"),
    [
        (Unit.sat, 2, 2_000),
        (Unit.msat, 2_000, 2_000),
    ],
)
async def test_melt_converts_fee_reserve_to_msat_for_backend_fee_limit(
    unit: Unit, fee_reserve: int, expected_fee_limit_msat: int
):
    melt_quote = MeltQuote(
        quote="q1",
        method=Method.bolt11.name,
        request="lnbc1fake",
        checking_id="checking-1",
        unit=unit.name,
        amount=10_000,
        fee_reserve=fee_reserve,
        state=MeltQuoteState.unpaid,
    )
    captured = {}

    async def get_melt_quote(quote_id: str) -> MeltQuote:
        assert quote_id == melt_quote.quote
        return melt_quote

    async def verify_inputs_and_outputs(proofs):
        return None

    async def verify_and_set_melt_quote_pending(quote, proofs, keysets):
        quote.state = MeltQuoteState.pending
        return quote

    async def melt_mint_settle_internally(quote, proofs):
        return quote

    async def pay_invoice(quote: MeltQuote, fee_limit_msat: int) -> PaymentResponse:
        captured["fee_limit_msat"] = fee_limit_msat
        return PaymentResponse(
            result=PaymentResult.SETTLED,
            checking_id=quote.checking_id,
            fee=Amount(Unit.msat, 0),
            preimage="00" * 32,
        )

    async def set_melt_quote_paid_and_invalidate_proofs(**kwargs):
        return kwargs["quote"]

    ledger = SimpleNamespace(
        disable_melt=False,
        get_melt_quote=get_melt_quote,
        _verify_and_get_unit_method=lambda unit_name, method_name: (
            unit,
            Method.bolt11,
        ),
        _verify_proofs_unit=lambda proofs, expected_unit: None,
        _verify_sigall_spending_conditions=lambda proofs, outputs, message: None,
        get_fees_for_proofs=lambda proofs: 0,
        verify_inputs_and_outputs=verify_inputs_and_outputs,
        db_write=SimpleNamespace(
            verify_and_set_melt_quote_pending=verify_and_set_melt_quote_pending,
            set_melt_quote_paid_and_invalidate_proofs=(
                set_melt_quote_paid_and_invalidate_proofs
            ),
        ),
        melt_mint_settle_internally=melt_mint_settle_internally,
        backends={
            Method.bolt11: {
                unit: SimpleNamespace(pay_invoice=pay_invoice),
            },
        },
        keysets={},
    )
    proof = Proof(
        id="keyset-id",
        amount=melt_quote.amount + melt_quote.fee_reserve,
        secret=f"proof-{unit.name}",
        C="00",
    )

    await Ledger.melt(ledger, proofs=[proof], quote=melt_quote.quote)  # type: ignore[arg-type]  # type: ignore[arg-type]  # type: ignore[arg-type]

    assert captured["fee_limit_msat"] == expected_fee_limit_msat


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fee_msat", "expected_fee_paid_sat"),
    [
        (1000, 1),
        (1001, 2),
        (1500, 2),
        (1999, 2),
        (2001, 3),
    ],
)
async def test_pending_melt_resolution_fee_paid_rounds_up(
    fee_msat: int, expected_fee_paid_sat: int
):
    melt_quote = MeltQuote(
        quote="q-pending-fee-round",
        method=Method.bolt11.name,
        request="lnbc1fake",
        checking_id="checking-pending",
        unit=Unit.sat.name,
        amount=100,
        fee_reserve=10,
        state=MeltQuoteState.pending,
    )

    async def crud_get_melt_quote(quote_id: str, db=None):
        return melt_quote

    async def crud_get_mint_quote(request: str, db=None):
        return None

    async def crud_get_pending_proofs_for_quote(quote_id: str, db=None):
        return []

    async def crud_get_blinded_messages_melt_id(melt_id: str, db=None):
        return None

    async def set_melt_quote_paid_and_invalidate_proofs(**kwargs):
        return kwargs["quote"]

    async def get_payment_status(checking_id: str) -> PaymentStatus:
        return PaymentStatus(
            result=PaymentResult.SETTLED,
            fee=Amount(Unit.msat, fee_msat),
            preimage="aa" * 32,
        )

    ledger = SimpleNamespace(
        crud=SimpleNamespace(
            get_melt_quote=crud_get_melt_quote,
            get_mint_quote=crud_get_mint_quote,
            get_pending_proofs_for_quote=crud_get_pending_proofs_for_quote,
            get_blinded_messages_melt_id=crud_get_blinded_messages_melt_id,
        ),
        db=None,
        _verify_and_get_unit_method=lambda unit_name, method_name: (
            Unit.sat,
            Method.bolt11,
        ),
        get_fees_for_proofs=lambda proofs: 0,
        db_write=SimpleNamespace(
            set_melt_quote_paid_and_invalidate_proofs=(
                set_melt_quote_paid_and_invalidate_proofs
            ),
        ),
        backends={
            Method.bolt11: {
                Unit.sat: SimpleNamespace(get_payment_status=get_payment_status),
            },
        },
        keysets={},
    )

    result = await Ledger.get_melt_quote(ledger, quote_id=melt_quote.quote)  # type: ignore[arg-type]  # type: ignore[arg-type]  # type: ignore[arg-type]

    assert result.state == MeltQuoteState.paid
    assert result.fee_paid == expected_fee_paid_sat
    assert result.fee_paid == math.ceil(fee_msat / 1000)
