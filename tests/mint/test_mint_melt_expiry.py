import time
from unittest.mock import AsyncMock, Mock

import bolt11
import pytest

from cashu.core.base import Amount, Method, MintQuote, MintQuoteState, Unit
from cashu.core.errors import QuoteExpiredError
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import (
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    PaymentStatusResult,
)
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet
from cashu.mint.ledger import Ledger
from tests.helpers import get_fake_invoice, is_regtest
from tests.mint.invoice_amount_helpers import make_outputs, unblind_promises

pytestmark = [pytest.mark.asyncio, pytest.mark.skipif(is_regtest, reason="fake wallet")]


async def issue_proofs(ledger: Ledger):
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    await ledger.get_mint_quote(quote.quote)
    outputs, secrets = make_outputs(ledger, 8, Unit.sat)
    promises = await ledger.mint(quote_id=quote.quote, outputs=outputs)
    return unblind_promises(ledger, promises, secrets)


@pytest.mark.parametrize("internal", [False, True], ids=["external", "internal"])
async def test_ledger_uses_backend_validation_for_opaque_requests(
    ledger: Ledger, monkeypatch, internal
):
    proofs = await issue_proofs(ledger)
    request = "opaque-payment-request"
    now = int(time.time())
    expiry = now + 60
    if internal:
        await ledger.crud.store_mint_quote(
            db=ledger.db,
            quote=MintQuote(
                quote="opaque-mint-quote",
                method=Method.bolt11.name,
                request=request,
                checking_id="opaque-payment",
                unit="sat",
                amount=2,
                state=MintQuoteState.unpaid,
                created_time=now,
                expiry=expiry,
            ),
        )
    backend = ledger.backends[Method.bolt11][Unit.sat]
    validate = Mock(return_value=expiry)
    get_payment_quote = AsyncMock(
        return_value=PaymentQuoteResponse(
            checking_id="opaque-payment",
            amount=Amount(Unit.sat, 2),
            fee=Amount(Unit.sat, 1),
        )
    )
    payment = AsyncMock(return_value=PaymentResponse(result=PaymentResult.SETTLED))
    monkeypatch.setattr(backend, "validate_payment_request", validate)
    monkeypatch.setattr(backend, "get_payment_quote", get_payment_quote)
    monkeypatch.setattr(backend, "pay_invoice", payment)

    quote = await ledger.melt_quote(PostMeltQuoteRequest(unit="sat", request=request))
    assert quote.request == request
    assert quote.expiry == expiry

    response = await ledger.melt(proofs=proofs, quote=quote.quote)

    assert response.state == "PAID"
    validate.assert_called_once_with(request)
    assert all(
        state.spent
        for state in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
    )
    if internal:
        get_payment_quote.assert_not_awaited()
        payment.assert_not_awaited()
    else:
        get_payment_quote.assert_awaited_once()
        payment.assert_awaited_once()


@pytest.mark.parametrize("internal", [False, True], ids=["external", "internal"])
@pytest.mark.parametrize(
    "request_ttl, quote_ttl, expected_ttl",
    [
        (60, None, 60),
        (60, 30, 30),
        (60, 7200, 60),
        (3600, None, 3600),
        (None, None, None),
        (None, 30, 30),
    ],
)
async def test_melt_quote_stores_backend_expiry(
    ledger: Ledger, monkeypatch, internal, request_ttl, quote_ttl, expected_ttl
):
    if internal:
        mint_quote = await ledger.mint_quote(PostMintQuoteRequest(amount=2, unit="sat"))
        request = mint_quote.request
    else:
        request = get_fake_invoice(2)
    now = int(time.time())
    monkeypatch.setattr("cashu.mint.ledger.time.time", lambda: now)
    monkeypatch.setattr(settings, "melt_quote_ttl", quote_ttl)
    backend = ledger.backends[Method.bolt11][Unit.sat]
    validate = Mock(return_value=None if request_ttl is None else now + request_ttl)
    monkeypatch.setattr(backend, "validate_payment_request", validate)

    quote = await ledger.melt_quote(PostMeltQuoteRequest(unit="sat", request=request))

    validate.assert_called_once_with(request)
    expected_expiry = None if expected_ttl is None else now + expected_ttl
    assert quote.expiry == expected_expiry
    stored = await ledger.get_melt_quote(quote.quote)
    assert stored.expiry == expected_expiry


@pytest.mark.parametrize("internal", [False, True], ids=["external", "internal"])
async def test_expired_invoice_is_rejected_before_quoting(
    ledger: Ledger, monkeypatch, internal
):
    if internal:
        mint_quote = await ledger.mint_quote(PostMintQuoteRequest(amount=2, unit="sat"))
        request = mint_quote.request
    else:
        request = get_fake_invoice(2)
    expired_at = bolt11.decode(request).expiry_time + 1
    monkeypatch.setattr("cashu.mint.ledger.time.time", lambda: expired_at)
    backend = ledger.backends[Method.bolt11][Unit.sat]
    get_payment_quote = AsyncMock()
    create_internal_quote = Mock(wraps=ledger.create_internal_melt_quote)
    store_quote = AsyncMock(wraps=ledger.db_write._store_melt_quote)
    monkeypatch.setattr(backend, "get_payment_quote", get_payment_quote)
    monkeypatch.setattr(ledger, "create_internal_melt_quote", create_internal_quote)
    monkeypatch.setattr(ledger.db_write, "_store_melt_quote", store_quote)

    with pytest.raises(QuoteExpiredError, match="invoice expired"):
        await ledger.melt_quote(PostMeltQuoteRequest(unit="sat", request=request))

    get_payment_quote.assert_not_awaited()
    create_internal_quote.assert_not_called()
    store_quote.assert_not_awaited()


@pytest.mark.parametrize("prefer_async", [False, True], ids=["sync", "async"])
async def test_expired_melt_quote_does_not_lock_proofs(
    ledger: Ledger, monkeypatch, prefer_async
):
    proofs = await issue_proofs(ledger)
    now = int(time.time())
    monkeypatch.setattr(settings, "melt_quote_ttl", 60)
    quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=get_fake_invoice(2, date=now))
    )
    outputs, _ = make_outputs(ledger, 1, Unit.sat)
    backend = ledger.backends[Method.bolt11][Unit.sat]
    payment = AsyncMock(return_value=PaymentResponse(result=PaymentResult.PENDING))
    set_pending = AsyncMock(wraps=ledger.db_write.verify_and_set_melt_quote_pending)
    monkeypatch.setattr(backend, "pay_invoice", payment)
    monkeypatch.setattr(
        ledger.db_write, "verify_and_set_melt_quote_pending", set_pending
    )
    monkeypatch.setattr("cashu.mint.ledger.time.time", lambda: now + 120)

    melt = ledger.async_melt if prefer_async else ledger.melt
    with pytest.raises(QuoteExpiredError, match="quote expired"):
        await melt(proofs=proofs, quote=quote.quote, outputs=outputs)

    payment.assert_not_awaited()
    set_pending.assert_not_awaited()
    assert (await ledger.get_melt_quote(quote.quote)).unpaid
    assert all(
        s.unspent for s in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
    )
    assert (
        await ledger.crud.get_blinded_messages_melt_id(
            db=ledger.db, melt_id=quote.quote
        )
        == []
    )


@pytest.mark.parametrize(
    "backend_cls", [LndRestWallet, LndRPCWallet], ids=["rest", "grpc"]
)
@pytest.mark.parametrize("prepared", [False, True], ids=["before-lock", "after-lock"])
@pytest.mark.parametrize("expiry", [60, None], ids=["explicit", "bolt11-default"])
async def test_expired_invoice_does_not_strand_proofs(
    ledger: Ledger, monkeypatch, backend_cls, prepared, expiry
):
    proofs = await issue_proofs(ledger)
    now = int(time.time())
    monkeypatch.setattr(settings, "melt_quote_ttl", 7200)
    quote = await ledger.melt_quote(
        PostMeltQuoteRequest(
            unit="sat", request=get_fake_invoice(2, date=now, expiry=expiry)
        )
    )
    invoice_expiry = now + (3600 if expiry is None else expiry)
    assert quote.expiry == invoice_expiry
    outputs, _ = make_outputs(ledger, 1, Unit.sat)
    balance_before, _ = await ledger.crud.get_balance(
        db=ledger.db, keyset=ledger.keyset
    )
    pending = None
    if prepared:
        pending = await ledger._prepare_melt(
            proofs=proofs, quote=quote.quote, outputs=outputs
        )
        assert pending.pending
        assert all(
            s.pending
            for s in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
        )

    backend = object.__new__(backend_cls)
    backend.unit = Unit.sat
    backend.supports_mpp = True
    backend.endpoint = "lnd.test"
    backend.combined_creds = None
    backend.client = Mock()
    payment = AsyncMock(wraps=backend.pay_invoice)
    monkeypatch.setattr(backend, "pay_invoice", payment)
    status = AsyncMock(return_value=PaymentStatus(result=PaymentStatusResult.NOT_FOUND))
    monkeypatch.setattr(backend, "get_payment_status", status)
    validate = Mock(
        side_effect=AssertionError("payment must use the stored quote expiry")
    )
    monkeypatch.setattr(backend, "validate_payment_request", validate)
    monkeypatch.setattr(ledger, "backends", {Method.bolt11: {Unit.sat: backend}})
    channel = Mock(side_effect=AssertionError("must not contact LND"))
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.grpc.aio.secure_channel", channel
    )
    monkeypatch.setattr("cashu.mint.ledger.time.time", lambda: invoice_expiry + 1)

    with pytest.raises(QuoteExpiredError, match="quote expired"):
        if pending is not None:
            await ledger._execute_melt_payment(pending, proofs, outputs)
        else:
            await ledger.melt(proofs=proofs, quote=quote.quote, outputs=outputs)

    payment.assert_not_awaited()
    status.assert_not_awaited()
    validate.assert_not_called()
    channel.assert_not_called()
    assert backend.client.mock_calls == []
    assert (await ledger.get_melt_quote(quote.quote)).unpaid
    assert all(
        s.unspent for s in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
    )
    assert (
        await ledger.crud.get_blinded_messages_melt_id(
            db=ledger.db, melt_id=quote.quote
        )
        == []
    )
    balance_after, _ = await ledger.crud.get_balance(db=ledger.db, keyset=ledger.keyset)
    assert balance_after == balance_before


async def test_internal_melt_expiring_after_preparation_releases_proofs(
    ledger: Ledger, monkeypatch
):
    proofs = await issue_proofs(ledger)
    mint_quote = await ledger.mint_quote(PostMintQuoteRequest(amount=2, unit="sat"))
    monkeypatch.setattr(settings, "melt_quote_ttl", 60)
    quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=mint_quote.request)
    )
    outputs, _ = make_outputs(ledger, 1, Unit.sat)
    balance_before, _ = await ledger.crud.get_balance(
        db=ledger.db, keyset=ledger.keyset
    )
    pending = await ledger._prepare_melt(
        proofs=proofs, quote=quote.quote, outputs=outputs
    )
    assert quote.expiry is not None
    expired_at = quote.expiry + 1
    monkeypatch.setattr("cashu.mint.ledger.time.time", lambda: expired_at)

    with pytest.raises(QuoteExpiredError, match="quote expired"):
        await ledger._execute_melt_payment(pending, proofs, outputs)

    assert (await ledger.get_melt_quote(quote.quote)).unpaid
    stored_mint_quote = await ledger.crud.get_mint_quote(
        quote_id=mint_quote.quote, db=ledger.db
    )
    assert stored_mint_quote is not None and stored_mint_quote.unpaid
    assert all(
        state.unspent
        for state in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
    )
    assert (
        await ledger.crud.get_blinded_messages_melt_id(
            db=ledger.db, melt_id=quote.quote
        )
        == []
    )
    balance_after, _ = await ledger.crud.get_balance(db=ledger.db, keyset=ledger.keyset)
    assert balance_after == balance_before


@pytest.mark.parametrize(
    "result", [PaymentStatusResult.NOT_FOUND, PaymentStatusResult.SETTLED]
)
async def test_expired_pending_quote_still_uses_backend_status(
    ledger: Ledger, monkeypatch, result
):
    proofs = await issue_proofs(ledger)
    now = int(time.time())
    monkeypatch.setattr(settings, "melt_quote_ttl", 60)
    quote = await ledger.melt_quote(
        PostMeltQuoteRequest(
            unit="sat", request=get_fake_invoice(2, date=now, expiry=60)
        )
    )
    await ledger._prepare_melt(proofs=proofs, quote=quote.quote)
    backend = ledger.backends[Method.bolt11][Unit.sat]
    status = AsyncMock(return_value=PaymentStatus(result=result))
    monkeypatch.setattr(backend, "get_payment_status", status)
    monkeypatch.setattr("cashu.mint.ledger.time.time", lambda: now + 120)

    resolved = await ledger.get_melt_quote(quote.quote)

    status.assert_awaited_once()
    states = await ledger.db_read.get_proofs_states([p.Y for p in proofs])
    if result == PaymentStatusResult.SETTLED:
        assert resolved.paid
        assert all(state.spent for state in states)
    else:
        assert resolved.pending
        assert all(state.pending for state in states)
