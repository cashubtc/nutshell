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
    PostMeltQuoteRequest,
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


def test_common_mint_quote_request_allows_method_specific_amount():
    request = PostMintQuoteRequest.model_validate({"unit": "sat", "account": "alice"})

    assert request.amount is None
    assert request.model_extra == {"account": "alice"}


def test_common_melt_quote_request_has_typed_optional_amount():
    request = PostMeltQuoteRequest.model_validate(
        {"unit": "sat", "request": "bc1qexample", "amount": 10}
    )

    assert request.amount == 10
    assert "amount" not in (request.model_extra or {})


def test_bolt11_mint_quote_still_requires_amount():
    plugin = payment_method_registry.get("bolt11")

    with pytest.raises(ValueError, match="require an amount"):
        plugin.validate_mint_quote_request({"unit": "sat"})


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


def test_mint_quote_method_data_cannot_override_common_fields():
    quote = MintQuote(
        quote="authoritative-id",
        method="testpay",
        request="request",
        checking_id="checking-id",
        unit="sat",
        amount=10,
        state=MintQuoteState.unpaid,
        method_data={"quote": "processor-id", "state": "PAID", "merchant": "bob"},
    )

    response = PostMintQuoteResponse.from_mint_quote(quote).model_dump()
    assert response["quote"] == "authoritative-id"
    assert response["state"] == "UNPAID"
    assert response["merchant"] == "bob"


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


def test_melt_quote_method_data_cannot_override_common_fields():
    quote = MeltQuote(
        quote="authoritative-id",
        method="testpay",
        request="request",
        checking_id="checking-id",
        unit="sat",
        amount=10,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
        method_data={"quote": "processor-id", "state": "PAID", "merchant": "bob"},
    )

    response = PostMeltQuoteResponse.from_melt_quote(quote).model_dump()
    assert response["quote"] == "authoritative-id"
    assert response["state"] == "UNPAID"
    assert response["merchant"] == "bob"


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


@pytest.mark.asyncio
async def test_mint_quote_rejects_underpaid_balance_before_pending(
    fake_backend_settings, ledger: Ledger
):
    quote = MintQuote(
        quote="underpaid-quote",
        method="bolt11",
        request="payment-request",
        checking_id="checking-id",
        unit="sat",
        amount=64,
        state=MintQuoteState.paid,
        amount_paid=1,
        amount_issued=0,
    )
    await ledger.crud.store_mint_quote(quote=quote, db=ledger.db)

    with pytest.raises(TransactionError, match="exceeds paid quote balance"):
        await ledger.db_write._set_mint_quote_pending(quote.quote, issued_amount=64)

    stored = await ledger.crud.get_mint_quote(quote_id=quote.quote, db=ledger.db)
    assert stored is not None
    assert stored.state == MintQuoteState.paid
    assert stored.amount_paid == 1
    assert stored.amount_issued == 0


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
async def test_non_reusable_mint_quote_stays_unpaid_after_partial_payment(
    fake_backend_settings, ledger: Ledger, monkeypatch: pytest.MonkeyPatch
):
    plugin = payment_method_registry.get("bolt11")
    monkeypatch.setattr(plugin, "allows_partial_mint", False)
    monkeypatch.setattr(
        plugin,
        "get_incoming_payment_status",
        AsyncMock(
            return_value=PaymentStatus(
                result=PaymentResult.PENDING,
                amount_paid=Amount(Unit.sat, 1),
            )
        ),
    )

    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=64, unit="sat"))
    refreshed = await ledger.get_mint_quote(quote.quote, force_backend_check=True)

    assert refreshed.state == MintQuoteState.unpaid
    assert refreshed.amount_paid == 1
    assert refreshed.amount_issued == 0


@pytest.mark.asyncio
async def test_shared_processor_event_routes_to_quote_method(
    fake_backend_settings, ledger: Ledger, monkeypatch: pytest.MonkeyPatch
):
    quote = MintQuote(
        quote="mint-quote",
        method="bolt11",
        request="payment-request",
        checking_id='{"type":7,"id":"processor-quote"}',
        unit="sat",
        amount=10,
        state=MintQuoteState.unpaid,
    )
    await ledger.crud.store_mint_quote(quote=quote, db=ledger.db)
    refresh = AsyncMock(return_value=quote)
    monkeypatch.setattr(ledger, "get_mint_quote", refresh)

    # The on-chain listener consumed a BOLT11 event from their shared endpoint.
    await ledger.invoice_callback_dispatcher(
        quote.checking_id, method="onchain", unit=Unit.sat
    )

    refresh.assert_awaited_once_with(quote.quote, force_backend_check=True)


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
