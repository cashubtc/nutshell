from unittest.mock import AsyncMock

import pytest

from cashu.core.base import (
    Amount,
    MeltQuote,
    MeltQuoteState,
    MintQuote,
    MintQuoteState,
    Unit,
)
from cashu.core.errors import TransactionError
from cashu.core.models import (
    PostMeltQuoteResponse,
    PostMintQuoteRequest,
    PostMintQuoteResponse,
)
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult, PaymentStatus
from cashu.mint.db.write import DbWriteHelper
from cashu.mint.ledger import Ledger
from cashu.payment import payment_method_registry
from cashu.payment.registry import PaymentMethodRegistry


def test_builtin_bolt11_payment_method_is_registered():
    assert payment_method_registry.get("bolt11").method == "bolt11"


@pytest.mark.parametrize("method", ["", "BOLT11", "has space", "../bolt11"])
def test_payment_method_names_are_safe_route_segments(method: str):
    with pytest.raises(ValueError):
        PaymentMethodRegistry.validate_method(method)


def test_mint_quote_response_only_exposes_method_data():
    quote = MintQuote(
        quote="quote-id",
        method="testpay",
        request="case-sensitive-request",
        checking_id="secret-checking-id",
        unit="sat",
        amount=10,
        state=MintQuoteState.paid,
        created_time=123,
        method_data={"payment_url": "https://example.test/pay"},
    )

    response = PostMintQuoteResponse.from_mint_quote(quote).model_dump()

    assert response["payment_url"] == "https://example.test/pay"
    assert "checking_id" not in response
    assert "created_time" not in response
    assert "state_val" not in response


def test_melt_quote_response_only_exposes_method_data():
    quote = MeltQuote(
        quote="quote-id",
        method="testpay",
        request="case-sensitive-request",
        checking_id="secret-checking-id",
        unit="sat",
        amount=10,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
        created_time=123,
        method_data={"destination": "merchant-123"},
    )

    response = PostMeltQuoteResponse.from_melt_quote(quote).model_dump()

    assert response["destination"] == "merchant-123"
    assert "checking_id" not in response
    assert "created_time" not in response


def test_partial_mint_quote_issuance_transition():
    quote = MintQuote(
        quote="quote-id",
        method="testpay",
        request="payment-request",
        checking_id="checking-id",
        unit="sat",
        amount=10,
        state=MintQuoteState.pending,
        amount_paid=10,
        amount_issued=0,
        updated_at=100,
    )

    DbWriteHelper._apply_mint_quote_issuance(quote, 4)
    assert quote.amount_issued == 4
    assert quote.state == MintQuoteState.paid
    assert quote.updated_at > 100
    assert quote.issued_time is None

    DbWriteHelper._apply_mint_quote_issuance(quote, 6)
    assert quote.amount_issued == 10
    assert quote.state == MintQuoteState.issued
    assert quote.issued_time is not None


def test_mint_quote_issuance_rejects_amount_above_paid_balance():
    quote = MintQuote(
        quote="quote-id",
        method="testpay",
        request="payment-request",
        checking_id="checking-id",
        unit="sat",
        amount=10,
        state=MintQuoteState.pending,
        amount_paid=10,
        amount_issued=8,
    )

    with pytest.raises(TransactionError, match="exceeds paid quote balance"):
        DbWriteHelper._apply_mint_quote_issuance(quote, 3)


def test_mint_quote_rollback_preserves_cumulative_accounting():
    quote = MintQuote(
        quote="quote-id",
        method="testpay",
        request="payment-request",
        checking_id="checking-id",
        unit="sat",
        amount=10,
        state=MintQuoteState.pending,
        amount_paid=100,
        amount_issued=40,
    )

    DbWriteHelper._restore_mint_quote_state(quote, MintQuoteState.paid)

    assert quote.state == MintQuoteState.paid
    assert quote.amount_paid == 100
    assert quote.amount_issued == 40


def test_legacy_mint_quote_accounting_is_initialized_from_state():
    quote = MintQuote(
        quote="quote-id",
        method="bolt11",
        request="payment-request",
        checking_id="checking-id",
        unit="sat",
        amount=10,
        state=MintQuoteState.paid,
        amount_paid=None,
        amount_issued=None,
    )

    DbWriteHelper._ensure_mint_quote_accounting(quote)

    assert quote.amount_paid == 10
    assert quote.amount_issued == 0


@pytest.mark.asyncio
async def test_reusable_mint_quote_observes_payments_after_full_issuance(
    fake_backend_settings, ledger: Ledger, monkeypatch: pytest.MonkeyPatch
):
    plugin = payment_method_registry.get("bolt11")
    monkeypatch.setattr(plugin, "allows_partial_mint", True)
    get_status = AsyncMock(
        return_value=PaymentStatus(
            result=PaymentResult.SETTLED,
            amount_paid=Amount(Unit.sat, 20),
        )
    )
    monkeypatch.setattr(plugin, "get_incoming_payment_status", get_status)

    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=10, unit="sat"))
    quote.amount_paid = 10
    quote.amount_issued = 10
    quote.state_val = MintQuoteState.issued
    await ledger.crud.update_mint_quote(quote=quote, db=ledger.db)

    refreshed = await ledger.get_mint_quote(quote.quote, force_backend_check=True)

    assert refreshed.state == MintQuoteState.paid
    assert refreshed.amount_paid == 20
    assert refreshed.amount_issued == 10


@pytest.mark.asyncio
async def test_batch_issuance_applies_each_quote_delta(
    fake_backend_settings, ledger: Ledger
):
    quotes = [
        MintQuote(
            quote=f"quote-{i}",
            method="bolt11",
            request=f"request-{i}",
            checking_id=f"checking-{i}",
            unit="sat",
            amount=100,
            state=MintQuoteState.paid,
            amount_paid=paid,
            amount_issued=issued,
        )
        for i, (paid, issued) in enumerate([(100, 40), (80, 20)])
    ]
    for quote in quotes:
        await ledger.crud.store_mint_quote(quote=quote, db=ledger.db)

    await ledger.db_write._set_mint_quotes_pending([q.quote for q in quotes])
    updated = await ledger.db_write._unset_mint_quotes_pending(
        [q.quote for q in quotes],
        MintQuoteState.issued,
        issued_amounts=[30, 60],
    )

    assert [(q.amount_paid, q.amount_issued, q.state) for q in updated] == [
        (100, 70, MintQuoteState.paid),
        (80, 80, MintQuoteState.issued),
    ]


@pytest.fixture
def fake_backend_settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "mint_backend_bolt11_sat", "FakeWallet")
    monkeypatch.setattr(settings, "mint_backend_bolt11_usd", "FakeWallet")
