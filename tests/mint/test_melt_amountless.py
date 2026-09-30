from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from cashu.core.base import Amount, Method, Unit
from cashu.core.errors import (
    AmountlessInvoiceNotSupportedError,
    AmountMismatchError,
    TransactionError,
)
from cashu.core.models import PostMeltQuoteRequest
from cashu.lightning.base import PaymentQuoteResponse
from tests.mint.test_mint_invoice_amount import invoice_response


@pytest.mark.parametrize("amount", [0, -1, 1.5, True, "1000"])
def test_amountless_amount_must_be_positive_integer(amount):
    with pytest.raises(ValidationError):
        PostMeltQuoteRequest(
            unit="sat",
            request="unused",
            options={"amountless": {"amount_msat": amount}},
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invoice_amount,options,message",
    [
        (None, None, "requires options.amountless.amount_msat"),
        (None, {"mpp": {"amount": 1000}}, "requires options.amountless.amount_msat"),
        (1000, {"amountless": {"amount_msat": 1000}}, "requires an amountless invoice"),
        (
            None,
            {"amountless": {"amount_msat": 1000}, "mpp": {"amount": 1000}},
            "mutually exclusive",
        ),
    ],
)
async def test_invalid_amountless_quote_never_reaches_backend(
    ledger, monkeypatch, invoice_amount, options, message
):
    backend = ledger.backends[Method.bolt11][Unit.sat]
    get_quote = AsyncMock()
    monkeypatch.setattr(backend, "get_payment_quote", get_quote)
    with pytest.raises(TransactionError, match=message):
        await ledger.melt_quote(
            PostMeltQuoteRequest(
                unit="sat",
                request=invoice_response(invoice_amount).payment_request,
                options=options,
            )
        )
    get_quote.assert_not_awaited()


@pytest.mark.asyncio
async def test_amountless_support_is_backend_specific(ledger, monkeypatch):
    backend = ledger.backends[Method.bolt11][Unit.sat]
    monkeypatch.setattr(backend, "supports_amountless", False)
    method = next(m for m in ledger.mint_info.nuts[5]["methods"] if m.unit == "sat")
    assert method.options.amountless is False
    assert not ledger.mint_info.supports_amountless("bolt11", Unit.sat)
    request = PostMeltQuoteRequest(
        unit="sat",
        request=invoice_response(None).payment_request,
        options={"amountless": {"amount_msat": 1001}},
    )
    with pytest.raises(AmountlessInvoiceNotSupportedError):
        await ledger.melt_quote(request)


@pytest.mark.asyncio
@pytest.mark.parametrize("amount", [1, 2, 3])
async def test_amountless_quote_checks_rounded_amount(ledger, monkeypatch, amount):
    backend = ledger.backends[Method.bolt11][Unit.sat]
    monkeypatch.setattr(backend, "supports_amountless", True)
    request = PostMeltQuoteRequest(
        unit="sat",
        request=invoice_response(None).payment_request,
        options={"amountless": {"amount_msat": 1001}},
    )
    monkeypatch.setattr(
        backend,
        "get_payment_quote",
        AsyncMock(
            return_value=PaymentQuoteResponse(
                checking_id="test",
                amount=Amount(Unit.sat, amount),
                fee=Amount(Unit.sat, 2),
            )
        ),
    )
    if amount != 2:
        with pytest.raises(AmountMismatchError):
            await ledger.melt_quote(request)
    else:
        response = await ledger.melt_quote(request)
        stored = await ledger.crud.get_melt_quote(quote_id=response.quote, db=ledger.db)
        assert stored.amount == 2
        assert stored.amount_msat == 1001
        assert stored.amount_option_type == "nut-23"
        assert stored.request == request.request


@pytest.mark.asyncio
async def test_amountless_migration_preserves_existing_quotes(tmp_path):
    from cashu.core.base import MeltQuote, MeltQuoteState
    from cashu.core.db import Database
    from cashu.core.migrations import migrate_databases
    from cashu.mint import migrations
    from cashu.mint.crud import LedgerCrudSqlite

    db = Database("mint", str(tmp_path))
    crud = LedgerCrudSqlite()
    try:
        await migrate_databases(db, migrations)
        quote = MeltQuote(
            quote="legacy",
            method="bolt11",
            request="legacy-request",
            checking_id="legacy-hash",
            unit="sat",
            amount=17,
            fee_reserve=2,
            state=MeltQuoteState.unpaid,
        )
        await crud.store_melt_quote(quote=quote, db=db)
        # Reconstruct the preceding schema with an existing quote.
        await db.execute("ALTER TABLE melt_quotes DROP COLUMN amount_msat")
        await db.execute("ALTER TABLE melt_quotes DROP COLUMN amount_option_type")
        await migrations.m040_add_amount_msat_to_melt_quotes(db)
        legacy = await crud.get_melt_quote(quote_id="legacy", db=db)
        assert legacy is not None
        assert legacy.amount_msat is None
        assert legacy.amount_option_type is None
        assert legacy.amount == 17
        assert legacy.unpaid
        quote.quote = "amountless"
        quote.amount_msat = 16_001
        quote.amount_option_type = "nut-23"
        await crud.store_melt_quote(quote=quote, db=db)
        restored = await crud.get_melt_quote(quote_id=quote.quote, db=db)
        assert restored is not None
        assert restored.amount_msat == 16_001
        assert restored.amount_option_type == "nut-23"
    finally:
        await db.engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("unit,expected", [(Unit.sat, 17), (Unit.usd, 2)])
async def test_amountless_payment_keeps_msat_across_quote_conversion(
    ledger, monkeypatch, unit, expected
):
    from cashu.lightning.fake import FakeWallet

    backend = FakeWallet(unit)
    monkeypatch.setitem(ledger.backends[Method.bolt11], unit, backend)
    request = PostMeltQuoteRequest(
        unit=unit.name,
        request=invoice_response(None).payment_request,
        options={"amountless": {"amount_msat": 16_001}},
    )
    response = await ledger.melt_quote(request)
    assert response.amount == expected
    stored = await ledger.crud.get_melt_quote(quote_id=response.quote, db=ledger.db)
    assert stored.amount_msat == 16_001
    paid = []
    monkeypatch.setattr(
        backend,
        "update_balance",
        lambda invoice, incoming: paid.append(invoice.amount_msat),
    )
    result = await backend.pay_invoice(stored, 2000)
    assert result.settled
    assert paid == [16_001]
