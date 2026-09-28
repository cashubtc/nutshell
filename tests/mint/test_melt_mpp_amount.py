from unittest.mock import AsyncMock

import pytest

from cashu.core.base import Amount, Method, Unit
from cashu.core.errors import AmountMismatchError, TransactionError
from cashu.core.models import (
    PostMeltQuoteRequest,
    PostMeltRequestOptionMpp,
    PostMeltRequestOptions,
)
from cashu.lightning.base import PaymentQuoteResponse
from tests.mint.test_mint_invoice_amount import invoice_response


@pytest.mark.asyncio
@pytest.mark.parametrize("unit,expected", [(Unit.sat, 17), (Unit.msat, 16_001)])
async def test_mpp_quote_persists_exact_amount_and_type(
    ledger, monkeypatch, unit, expected
):
    if unit == Unit.msat:
        await ledger.activate_keyset(derivation_path="m/0'/1'/0'")
    backend = ledger.backends[Method.bolt11][Unit.sat]
    monkeypatch.setattr(backend, "supports_mpp", True)
    monkeypatch.setitem(ledger.backends[Method.bolt11], unit, backend)
    monkeypatch.setattr(
        backend,
        "get_payment_quote",
        AsyncMock(
            return_value=PaymentQuoteResponse(
                checking_id="test",
                amount=Amount(unit, expected),
                fee=Amount(unit, 2),
            )
        ),
    )
    request = PostMeltQuoteRequest(
        unit=unit.name,
        request=str(invoice_response(17_000).payment_request),
        options=PostMeltRequestOptions(mpp=PostMeltRequestOptionMpp(amount=16_001)),
    )
    response = await ledger.melt_quote(request)
    stored = await ledger.crud.get_melt_quote(quote_id=response.quote, db=ledger.db)
    assert stored is not None
    assert stored.amount == expected
    assert stored.amount_msat == 16_001
    assert stored.amount_option_type == "nut-15"
    assert stored.request == request.request


@pytest.mark.asyncio
async def test_mpp_rejects_wrong_rounded_quote_amount(ledger, monkeypatch):
    backend = ledger.backends[Method.bolt11][Unit.sat]
    monkeypatch.setattr(backend, "supports_mpp", True)
    monkeypatch.setattr(
        backend,
        "get_payment_quote",
        AsyncMock(
            return_value=PaymentQuoteResponse(
                checking_id="test",
                amount=Amount(Unit.sat, 16),
                fee=Amount(Unit.sat, 2),
            )
        ),
    )
    with pytest.raises(AmountMismatchError):
        await ledger.melt_quote(
            PostMeltQuoteRequest(
                unit="sat",
                request=str(invoice_response(17_000).payment_request),
                options=PostMeltRequestOptions(
                    mpp=PostMeltRequestOptionMpp(amount=16_001)
                ),
            )
        )


@pytest.mark.asyncio
async def test_mpp_cannot_exceed_invoice(ledger):
    with pytest.raises(TransactionError, match="mpp amount exceeds invoice amount"):
        await ledger.melt_quote(
            PostMeltQuoteRequest(
                unit="sat",
                request=str(invoice_response(16_000).payment_request),
                options=PostMeltRequestOptions(
                    mpp=PostMeltRequestOptionMpp(amount=16_001)
                ),
            )
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unit,amount,invoice_msat,expected",
    [
        ("sat", 16, 17_000, 16_000),
        ("msat", 16_001, 17_000, 16_001),
        ("sat", 17, 16_001, None),
        ("msat", 16_001, 16_001, None),
    ],
)
async def test_migration_marks_legacy_mpp_without_changing_full_quotes(
    tmp_path, unit, amount, invoice_msat, expected
):
    from cashu.core.base import MeltQuote, MeltQuoteState
    from cashu.core.db import Database
    from cashu.core.migrations import migrate_databases
    from cashu.mint import migrations
    from cashu.mint.crud import LedgerCrudSqlite

    db = Database("mint", str(tmp_path))
    crud = LedgerCrudSqlite()
    try:
        await migrate_databases(db, migrations)
        invoice = invoice_response(invoice_msat)
        assert invoice.payment_request and invoice.checking_id
        quote = MeltQuote(
            quote="legacy",
            method="bolt11",
            request=invoice.payment_request,
            checking_id=invoice.checking_id,
            unit=unit,
            amount=amount,
            fee_reserve=2,
            state=MeltQuoteState.unpaid,
        )
        await crud.store_melt_quote(quote=quote, db=db)
        await db.execute("ALTER TABLE melt_quotes DROP COLUMN amount_msat")
        await db.execute("ALTER TABLE melt_quotes DROP COLUMN amount_option_type")
        await migrations.m040_add_amount_msat_to_melt_quotes(db)
        stored = await crud.get_melt_quote(quote_id=quote.quote, db=db)
        assert stored is not None
        assert stored.amount == amount
        assert stored.amount_msat == expected
        assert stored.amount_option_type == ("nut-15" if expected is not None else None)
        assert stored.unpaid
    finally:
        await db.engine.dispose()
